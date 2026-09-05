/// BBS+ credential scheme for within-epoch unlinkable trust presentations.
///
/// # Design
///
/// The Ed25519-based anonymous credential scheme (credential.rs) provides
/// epoch-level unlinkability: a peer gets a new pseudonym each epoch, but
/// within an epoch, all presentations share the same `holder_tag`. BBS+
/// signatures provide per-presentation unlinkability: each proof of
/// credential possession is cryptographically unlinkable to any other,
/// even within the same epoch.
///
/// # BBS+ overview
///
/// BBS+ is a pairing-based multi-message signature scheme:
///
/// - **Issuer** has keypair `(sk, pk)` where `pk = sk * G2`
/// - **Sign**: given messages `m1..mL`, compute signature `(A, e, s)` where
///   `A = (1/(sk+e)) * (g1 + s*h0 + sum(mi*hi))`
/// - **Prove**: holder creates a zero-knowledge proof of knowledge of the
///   signature without revealing it (selective disclosure of attributes)
/// - **Verify**: verifier checks the proof against the issuer's public key
///
/// # Attributes
///
/// A BBS+ credential encodes these as signed messages:
/// - `m0`: link secret (held privately, never disclosed — prevents transfer)
/// - `m1`: tier (Observed=1, Verified=2, Endorsed=3)
/// - `m2`: capabilities bitfield
/// - `m3`: epoch
/// - `m4`: issuer-assigned nonce (revocation handle)
///
/// # Privacy properties vs Ed25519 scheme
///
/// | Property | Ed25519 | BBS+ |
/// |---|---|---|
/// | Cross-epoch unlinkability | Yes | Yes |
/// | Within-epoch unlinkability | No (same holder_tag) | Yes (each proof is unique) |
/// | Selective disclosure | No (all-or-nothing) | Yes (reveal tier, hide epoch) |
/// | Non-transferability | Via ephemeral key | Via link secret in proof |
/// | Proof size | ~160 bytes | ~400 bytes |
/// | Verification cost | ~1 EdDSA verify | ~2 pairings |
///
/// # Implementation notes
///
/// Uses BLS12-381 curve. The implementation is self-contained using the
/// `bls12_381` crate for group operations, avoiding external BBS+ libraries
/// that may have unstable APIs.
///
/// # BROKEN — do not use for trust decisions
///
/// This scheme is forgeable in two independent ways, both demonstrated by
/// forgery tests at the bottom of this file:
///
/// 1. `generators()` returns base-point multiples of publicly derivable
///    scalars rather than hash-to-curve outputs, so the discrete logs BBS+
///    unforgeability depends on being unknown are public. One issued
///    credential is enough to mint any attribute set without the issuer key.
/// 2. The verifier's pairing check and its Schnorr check are never related to
///    each other, so the proved messages are not bound to the signature.
///    Observing one proof — they travel in descriptors — is enough to mint
///    proofs for arbitrary attributes with no credential at all.
///
/// `descriptor.bbs_tier()` is consequently NOT read into `AdmissionSignals`.
/// See `docs/adr/006-bbs-plus-known-breaks.md` for the analysis, the
/// containment currently in place, and the conditions for re-enabling.
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use ff::Field;
use serde::{Deserialize, Serialize};

use super::credential::CredentialTier;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Number of messages in a BBS+ credential.
const NUM_MESSAGES: usize = 5;

/// Domain separator for BBS+ hash-to-scalar.
const DOMAIN_BBS_H2S: &[u8] = b"miasma-bbs-h2s-v1";

/// Domain separator for proof challenge.
const DOMAIN_BBS_CHALLENGE: &[u8] = b"miasma-bbs-challenge-v1";

// ─── Generators ─────────────────────────────────────────────────────────────

/// Number of generators needed: g1 + h0 (blinding) + h1..hN (messages).
const TOTAL_GENERATORS: usize = NUM_MESSAGES + 2;

/// Deterministic generators for BBS+ (g1, h0, h1..h4).
///
/// # BROKEN — these are not independent generators
///
/// This computes `G1::generator() * hash_to_scalar(..)`, i.e. a scalar multiple
/// of the base point. It does **not** hash to the curve, so each generator's
/// discrete log with respect to the base point is publicly computable, and the
/// unknown-discrete-log assumption BBS+ unforgeability rests on does not hold.
/// The doc comment here previously claimed "hashing domain-separated indices to
/// G1", which is what hid this: the description was of hash-to-curve, the code
/// was a scalar multiplication.
///
/// The fix is RFC 9380 hash-to-curve (`bls12_381` provides SSWU behind its
/// `experimental` feature) under a fixed DST. That changes every generator and
/// therefore invalidates existing credentials, so it is a wire-format break.
/// See `docs/adr/006-bbs-plus-known-breaks.md`.
fn generators() -> Vec<G1Projective> {
    let mut gens = Vec::with_capacity(TOTAL_GENERATORS);
    for i in 0..TOTAL_GENERATORS {
        let mut input = Vec::new();
        input.extend_from_slice(b"miasma-bbs-gen-v1-");
        input.extend_from_slice(&(i as u32).to_le_bytes());
        let hash = blake3::hash(&input);
        let scalar = hash_to_scalar(hash.as_bytes());
        gens.push(G1Projective::generator() * scalar);
    }
    gens
}

/// Hash arbitrary bytes to a BLS12-381 scalar.
fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = blake3::hash(&[DOMAIN_BBS_H2S, data].concat());
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(hash.as_bytes());
    // Hash again for the upper 32 bytes to get uniform distribution.
    let hash2 = blake3::hash(&[DOMAIN_BBS_H2S, hash.as_bytes()].concat());
    wide[32..].copy_from_slice(hash2.as_bytes());
    Scalar::from_bytes_wide(&wide)
}

// ─── BBS+ Issuer Key ───────────────────────────────────────────────────────

/// BBS+ issuer keypair.
#[derive(Clone)]
pub struct BbsIssuerKey {
    /// Secret key scalar.
    sk: Scalar,
    /// Public key in G2.
    pub pk: G2Projective,
}

impl BbsIssuerKey {
    /// Generate a new issuer keypair from seed bytes.
    pub fn from_seed(seed: &[u8]) -> Self {
        let sk = hash_to_scalar(seed);
        let pk = G2Projective::generator() * sk;
        Self { sk, pk }
    }

    /// Generate a random issuer keypair.
    pub fn generate() -> Self {
        let sk = Scalar::random(&mut rand::thread_rng());
        let pk = G2Projective::generator() * sk;
        Self { sk, pk }
    }

    /// Public key bytes (compressed G2 point).
    pub fn pk_bytes(&self) -> [u8; 96] {
        G2Affine::from(self.pk).to_compressed()
    }
}

// ─── BBS+ Signature ─────────────────────────────────────────────────────────

/// A BBS+ signature over a vector of messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsSignature {
    /// Point A in G1 (compressed, 48 bytes).
    pub a: Vec<u8>,
    /// Scalar e (32 bytes).
    pub e: Vec<u8>,
    /// Scalar s (blinding factor, 32 bytes).
    pub s: Vec<u8>,
}

impl BbsSignature {
    /// Sign messages `m[0..NUM_MESSAGES]` with the issuer key.
    ///
    /// Computes: `A = (1/(sk+e)) * (g1 + s*h0 + sum(mi*hi))`
    pub fn sign(issuer: &BbsIssuerKey, messages: &[Scalar; NUM_MESSAGES]) -> Self {
        let gv = generators();
        // Resample e until sk+e != 0. This is not a security-relevant fallback
        // (e is freshly random and never attacker-controlled at signing time),
        // but a signature computed with `inv` silently replaced by `Scalar::one()`
        // would satisfy neither the intended equation `A = B/(sk+e)` nor produce
        // a diagnosable error -- it would just be a signature that fails to
        // verify later, for a reason invisible at the call site. Resampling
        // keeps `sign` total (always produces a genuine signature) instead of
        // ever emitting a value computed under a substituted, wrong scalar.
        // Practically this loop runs exactly once: `sk+e==0` occurs with
        // probability ~1/2^255 for a random Scalar e over BLS12-381's scalar field.
        let mut e = Scalar::random(&mut rand::thread_rng());
        while bool::from((issuer.sk + e).invert().is_none()) {
            e = Scalar::random(&mut rand::thread_rng());
        }
        let s = Scalar::random(&mut rand::thread_rng());

        // B = g1 + s*h0 + m[0]*h[1] + ... + m[4]*h[5]
        // where gv[0]=g1, gv[1]=h0, gv[2..7]=h1..h5
        let mut bpt = gv[0]; // g1
        bpt += gv[1] * s; // s * h0
        for i in 0..NUM_MESSAGES {
            bpt += gv[i + 2] * messages[i]; // mi * hi
        }

        // A = B * (1/(sk + e)). Guaranteed to succeed: the loop above already
        // ensures sk+e is invertible.
        let inv = (issuer.sk + e).invert().unwrap();
        let a = bpt * inv;

        Self {
            a: G1Affine::from(a).to_compressed().to_vec(),
            e: e.to_bytes()[..32].to_vec(),
            s: s.to_bytes()[..32].to_vec(),
        }
    }
}

// ─── BBS+ Credential ────────────────────────────────────────────────────────

/// Attributes encoded in a BBS+ credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsCredentialAttributes {
    /// Link secret (private, never disclosed).
    pub link_secret: [u8; 32],
    /// Trust tier.
    pub tier: CredentialTier,
    /// Capabilities bitfield.
    pub capabilities: u8,
    /// Epoch of issuance.
    pub epoch: u64,
    /// Issuer-assigned nonce (revocation handle).
    pub nonce: u64,
}

impl BbsCredentialAttributes {
    /// Convert attributes to scalar messages for BBS+ signing.
    fn to_messages(&self) -> [Scalar; NUM_MESSAGES] {
        [
            hash_to_scalar(&self.link_secret),
            Scalar::from(self.tier as u64),
            Scalar::from(self.capabilities as u64),
            Scalar::from(self.epoch),
            Scalar::from(self.nonce),
        ]
    }
}

/// A BBS+ credential: attributes + signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsCredential {
    pub attributes: BbsCredentialAttributes,
    pub signature: BbsSignature,
    /// Issuer public key (compressed G2, 96 bytes).
    pub issuer_pk: Vec<u8>,
}

// ─── BBS+ Proof (selective disclosure) ──────────────────────────────────────

/// A zero-knowledge proof of BBS+ credential possession.
///
/// This proof reveals selected attributes while hiding others. The link
/// secret (m0) is always hidden, ensuring non-transferability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsProof {
    /// Randomised signature point A' (compressed G1, 48 bytes).
    pub a_prime: Vec<u8>,
    /// Blinded A point: A_bar = r1 * A' * e (compressed G1, 48 bytes).
    pub a_bar: Vec<u8>,
    /// Commitment B = g1 + s*h0 + sum(mi*hi) (compressed G1, 48 bytes).
    pub b_point: Vec<u8>,
    /// Challenge scalar (32 bytes).
    pub challenge: Vec<u8>,
    /// Response for blinding factor s (32 bytes).
    pub response_s: Vec<u8>,
    /// Response scalars for hidden attributes (32 bytes each).
    pub responses: Vec<Vec<u8>>,
    /// Disclosed attribute indices and values.
    pub disclosed: Vec<(usize, u64)>,
    /// Proof domain (binds to verifier context).
    pub domain: Vec<u8>,
}

/// Which attributes to disclose in a BBS+ proof.
#[derive(Debug, Clone)]
pub struct DisclosurePolicy {
    /// Indices of attributes to reveal (0=link_secret, 1=tier, 2=caps, 3=epoch, 4=nonce).
    /// Link secret (index 0) should NEVER be disclosed.
    pub reveal: Vec<usize>,
}

impl Default for DisclosurePolicy {
    fn default() -> Self {
        // Default: reveal tier only, hide everything else.
        Self { reveal: vec![1] }
    }
}

impl DisclosurePolicy {
    /// Reveal tier and capabilities.
    pub fn tier_and_caps() -> Self {
        Self { reveal: vec![1, 2] }
    }

    /// Reveal nothing (pure proof of credential possession).
    pub fn reveal_nothing() -> Self {
        Self { reveal: vec![] }
    }
}

// ─── BBS+ Issuer ────────────────────────────────────────────────────────────

/// Issues BBS+ credentials.
pub struct BbsIssuer {
    key: BbsIssuerKey,
}

impl BbsIssuer {
    pub fn new(key: BbsIssuerKey) -> Self {
        Self { key }
    }

    /// Issue a credential for the given attributes.
    pub fn issue(&self, attributes: BbsCredentialAttributes) -> BbsCredential {
        let messages = attributes.to_messages();
        let signature = BbsSignature::sign(&self.key, &messages);
        BbsCredential {
            attributes,
            signature,
            issuer_pk: self.key.pk_bytes().to_vec(),
        }
    }

    /// Public key bytes.
    pub fn pk_bytes(&self) -> [u8; 96] {
        self.key.pk_bytes()
    }
}

// ─── BBS+ Holder (proof generation) ─────────────────────────────────────────

/// Generate a BBS+ proof of credential possession with selective disclosure.
pub fn bbs_create_proof(
    credential: &BbsCredential,
    policy: &DisclosurePolicy,
    context: &[u8],
) -> BbsProof {
    let messages = credential.attributes.to_messages();
    let s_scalar = deserialize_scalar(&credential.signature.s);

    let hidden: Vec<usize> = (0..NUM_MESSAGES)
        .filter(|i| !policy.reveal.contains(i))
        .collect();

    let disclosed: Vec<(usize, u64)> = policy
        .reveal
        .iter()
        .map(|&i| {
            let val = match i {
                1 => credential.attributes.tier as u64,
                2 => credential.attributes.capabilities as u64,
                3 => credential.attributes.epoch,
                4 => credential.attributes.nonce,
                _ => 0u64,
            };
            (i, val)
        })
        .collect();

    let gv = generators();

    // Compute B = g1 + s*h0 + sum(mi*hi)
    let mut b_point = gv[0]; // g1
    b_point += gv[1] * s_scalar; // s * h0
    for i in 0..NUM_MESSAGES {
        b_point += gv[i + 2] * messages[i];
    }

    // Randomise the signature: A' = r1 * A
    let r1 = Scalar::random(&mut rand::thread_rng());
    let a_point = deserialize_g1(&credential.signature.a);
    let a_prime = a_point * r1;

    // A_bar = r1 * B - e * A'
    // This satisfies e(A', W) = e(A_bar, G2) because A_bar = A' * sk
    // (proof: A_bar = r1*B - e*r1*A = r1*(B - e*A) = r1*A*(sk+e-e) = r1*A*sk = A'*sk)
    let e_scalar = deserialize_scalar(&credential.signature.e);
    let a_bar = b_point * r1 - a_prime * e_scalar;

    // Commitment phase: random blindings for s and hidden attributes.
    let blind_s = Scalar::random(&mut rand::thread_rng());
    let blindings: Vec<Scalar> = hidden
        .iter()
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect();

    // t = blind_s * h0 + sum_hidden(blinding_j * h_j)
    let mut t = gv[1] * blind_s;
    for (j, &idx) in hidden.iter().enumerate() {
        t += gv[idx + 2] * blindings[j];
    }

    // Challenge: hash(A', A_bar, B, t, context).
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&G1Affine::from(a_prime).to_compressed());
    challenge_input.extend_from_slice(&G1Affine::from(a_bar).to_compressed());
    challenge_input.extend_from_slice(&G1Affine::from(b_point).to_compressed());
    challenge_input.extend_from_slice(&G1Affine::from(t).to_compressed());
    challenge_input.extend_from_slice(context);
    let challenge = hash_to_scalar(&[DOMAIN_BBS_CHALLENGE, &challenge_input].concat());

    // Response for s: resp_s = blind_s + challenge * s
    let resp_s = blind_s + challenge * s_scalar;

    // Responses for hidden: response_j = blinding_j + challenge * message_hidden_j
    let responses: Vec<Vec<u8>> = hidden
        .iter()
        .enumerate()
        .map(|(j, &idx)| {
            let resp = blindings[j] + challenge * messages[idx];
            resp.to_bytes()[..32].to_vec()
        })
        .collect();

    BbsProof {
        a_prime: G1Affine::from(a_prime).to_compressed().to_vec(),
        a_bar: G1Affine::from(a_bar).to_compressed().to_vec(),
        b_point: G1Affine::from(b_point).to_compressed().to_vec(),
        challenge: challenge.to_bytes()[..32].to_vec(),
        response_s: resp_s.to_bytes()[..32].to_vec(),
        responses,
        disclosed,
        domain: context.to_vec(),
    }
}

/// Parse a G1 point from compressed bytes for proof verification (no fallback).
fn parse_g1_proof(bytes: &[u8]) -> Result<G1Projective, BbsError> {
    if bytes.len() != 48 {
        return Err(BbsError::InvalidProof);
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(bytes);
    let opt = G1Affine::from_compressed(&arr);
    if bool::from(opt.is_some()) {
        Ok(G1Projective::from(opt.unwrap()))
    } else {
        Err(BbsError::InvalidProof)
    }
}

/// Parse a scalar response from a BBS+ proof (no fallback).
///
/// Mirrors `parse_g1_proof`'s strictness: `Scalar::from_bytes` rejects any
/// byte string that is not the canonical little-endian encoding of a value
/// strictly less than the field modulus. Unlike `deserialize_scalar` (used
/// only for locally-held, previously-accepted credential fields), a proof's
/// responses arrive from an untrusted peer at verification time and a
/// malformed encoding must be rejected outright, not silently reinterpreted
/// as `hash_to_scalar(bytes)`. Silently substituting a fallback value on a
/// parse failure is exactly the pattern behind VULN-001/VULN-002
/// (docs/adr/005-anonymous-trust-descriptors.md) applied to a different
/// field type; this function exists so the verifier never does that again.
fn parse_scalar_proof(bytes: &[u8]) -> Result<Scalar, BbsError> {
    if bytes.len() != 32 {
        return Err(BbsError::InvalidProof);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let opt = Scalar::from_bytes(&arr);
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        Err(BbsError::InvalidProof)
    }
}

/// Deserialize a G1 point from compressed bytes, with fallback.
fn deserialize_g1(bytes: &[u8]) -> G1Projective {
    if bytes.len() == 48 {
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        let opt = G1Affine::from_compressed(&arr);
        if bool::from(opt.is_some()) {
            return G1Projective::from(opt.unwrap());
        }
    }
    G1Projective::generator()
}

/// Deserialize a scalar from bytes, with fallback to hash.
fn deserialize_scalar(bytes: &[u8]) -> Scalar {
    if bytes.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        let opt = Scalar::from_bytes(&arr);
        if bool::from(opt.is_some()) {
            return opt.unwrap();
        }
    }
    hash_to_scalar(bytes)
}

// ─── BBS+ Verifier ──────────────────────────────────────────────────────────

/// Verify a BBS+ proof against an issuer public key.
///
/// Returns the disclosed attributes if the proof is valid.
pub fn bbs_verify_proof(
    proof: &BbsProof,
    issuer_pk_bytes: &[u8; 96],
    context: &[u8],
) -> Result<Vec<(usize, u64)>, BbsError> {
    // Parse issuer public key.
    let pk_affine = G2Affine::from_compressed(issuer_pk_bytes);
    if bool::from(pk_affine.is_none()) {
        return Err(BbsError::InvalidIssuerKey);
    }
    let pk = pk_affine.unwrap();

    // Parse proof points.
    if proof.a_prime.len() != 48
        || proof.a_bar.len() != 48
        || proof.b_point.len() != 48
        || proof.challenge.len() < 32
        || proof.response_s.len() < 32
    {
        return Err(BbsError::InvalidProof);
    }

    let a_prime = parse_g1_proof(&proof.a_prime)?;
    let a_bar = parse_g1_proof(&proof.a_bar)?;
    let b_point = parse_g1_proof(&proof.b_point)?;

    // Parse challenge.
    let mut c_arr = [0u8; 32];
    c_arr.copy_from_slice(&proof.challenge[..32]);
    let c_opt = Scalar::from_bytes(&c_arr);
    let challenge = if bool::from(c_opt.is_some()) {
        c_opt.unwrap()
    } else {
        return Err(BbsError::InvalidProof);
    };

    // Parse response for s (strict: a malformed/non-canonical encoding must
    // fail verification outright, not be silently reinterpreted).
    let resp_s = parse_scalar_proof(&proof.response_s)?;

    // Determine hidden indices.
    let disclosed_indices: Vec<usize> = proof.disclosed.iter().map(|&(i, _)| i).collect();
    let hidden: Vec<usize> = (0..NUM_MESSAGES)
        .filter(|i| !disclosed_indices.contains(i))
        .collect();

    if proof.responses.len() != hidden.len() {
        return Err(BbsError::InvalidProof);
    }

    let gv = generators();

    // Recompute t from responses, B, and challenge.
    // t = resp_s * h0 + sum_hidden(resp_j * h_j) - c * (B - g1 - sum_disclosed(val * h_disc))
    let mut b_disclosed = gv[0]; // g1
    for &(idx, val) in &proof.disclosed {
        b_disclosed += gv[idx + 2] * Scalar::from(val);
    }

    let mut t_recomputed = gv[1] * resp_s; // resp_s * h0
    for (j, &idx) in hidden.iter().enumerate() {
        let resp = parse_scalar_proof(&proof.responses[j])?;
        t_recomputed += gv[idx + 2] * resp;
    }
    t_recomputed -= (b_point - b_disclosed) * challenge;

    // Recompute challenge.
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&G1Affine::from(a_prime).to_compressed());
    challenge_input.extend_from_slice(&G1Affine::from(a_bar).to_compressed());
    challenge_input.extend_from_slice(&G1Affine::from(b_point).to_compressed());
    challenge_input.extend_from_slice(&G1Affine::from(t_recomputed).to_compressed());
    challenge_input.extend_from_slice(context);
    let challenge_recomputed = hash_to_scalar(&[DOMAIN_BBS_CHALLENGE, &challenge_input].concat());

    if challenge != challenge_recomputed {
        return Err(BbsError::ProofVerificationFailed);
    }

    // ── Pairing check: issuer binding ──────────────────────────────────
    //
    // Verify e(A', W) == e(A_bar, G2).
    //
    // A_bar was computed as r1*B - e*A', which equals A'*sk when the
    // signature is valid. This pairing check proves the credential was
    // signed by the issuer with public key W, binding the Schnorr proof
    // (message knowledge) to the issuer's identity.

    // Reject trivial proof: A' must not be the identity point.
    if bool::from(G1Affine::from(a_prime).is_identity()) {
        return Err(BbsError::InvalidProof);
    }

    // e(A', W) == e(A_bar, G2)  ⟺  e(A', W) * e(-A_bar, G2) == 1
    let neg_a_bar = -a_bar;
    let pairing_result = multi_miller_loop(&[
        (&G1Affine::from(a_prime), &G2Prepared::from(pk)),
        (
            &G1Affine::from(neg_a_bar),
            &G2Prepared::from(G2Affine::generator()),
        ),
    ])
    .final_exponentiation();

    use bls12_381::Gt;
    if pairing_result != Gt::identity() {
        return Err(BbsError::IssuerBindingFailed);
    }

    Ok(proof.disclosed.clone())
}

// ─── BBS+ Errors ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BbsError {
    InvalidIssuerKey,
    InvalidProof,
    ProofVerificationFailed,
    /// Pairing check failed: credential was not signed by the claimed issuer.
    IssuerBindingFailed,
    LinkSecretDisclosed,
}

impl std::fmt::Display for BbsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BbsError::InvalidIssuerKey => write!(f, "invalid BBS+ issuer public key"),
            BbsError::InvalidProof => write!(f, "invalid BBS+ proof structure"),
            BbsError::ProofVerificationFailed => write!(f, "BBS+ proof verification failed"),
            BbsError::IssuerBindingFailed => write!(f, "BBS+ pairing check failed: wrong issuer"),
            BbsError::LinkSecretDisclosed => write!(f, "link secret must not be disclosed"),
        }
    }
}

// ─── Link Secret ────────────────────────────────────────────────────────────

/// Generate a new random link secret.
pub fn generate_link_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

// ─── BBS+ Credential Wallet ──────────────────────────────────────────────

/// Maximum BBS+ credentials stored per wallet (prevents flooding).
const MAX_BBS_CREDENTIALS: usize = 100;

/// Stores BBS+ credentials held by this node.
///
/// Unlike the Ed25519 wallet, BBS+ credentials don't require a matching
/// ephemeral identity — the link secret is the binding factor, not a public key.
pub struct BbsCredentialWallet {
    /// This node's persistent link secret (survives epoch rotation).
    link_secret: [u8; 32],
    /// Credentials keyed by (issuer_pk_bytes_prefix, epoch).
    /// We use the first 32 bytes of the 96-byte issuer pk as key prefix.
    credentials: std::collections::HashMap<([u8; 32], u64), BbsCredential>,
}

impl BbsCredentialWallet {
    /// Create a new wallet with a fresh link secret.
    pub fn new() -> Self {
        Self {
            link_secret: generate_link_secret(),
            credentials: std::collections::HashMap::new(),
        }
    }

    /// This wallet's link secret (needed when requesting BBS+ credentials).
    pub fn link_secret(&self) -> [u8; 32] {
        self.link_secret
    }

    /// Store a BBS+ credential after verification.
    pub fn store(&mut self, credential: BbsCredential) {
        let mut pk_prefix = [0u8; 32];
        pk_prefix.copy_from_slice(&credential.issuer_pk[..32.min(credential.issuer_pk.len())]);
        let key = (pk_prefix, credential.attributes.epoch);
        self.credentials.insert(key, credential);

        // Enforce capacity: evict oldest-epoch entries.
        while self.credentials.len() > MAX_BBS_CREDENTIALS {
            if let Some(oldest_key) = self
                .credentials
                .iter()
                .min_by_key(|(_, c)| c.attributes.epoch)
                .map(|(k, _)| *k)
            {
                self.credentials.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    /// Get the best (highest-tier) BBS+ credential from any issuer.
    pub fn best_credential(&self) -> Option<&BbsCredential> {
        self.credentials.values().max_by_key(|c| c.attributes.tier)
    }

    /// Create a proof from the best available BBS+ credential.
    pub fn present(&self, policy: &DisclosurePolicy, context: &[u8]) -> Option<BbsProof> {
        let cred = self.best_credential()?;
        Some(bbs_create_proof(cred, policy, context))
    }

    /// Number of stored credentials.
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    /// Prune credentials from epochs older than the given minimum.
    pub fn prune_before_epoch(&mut self, min_epoch: u64) {
        self.credentials.retain(|&(_, epoch), _| epoch >= min_epoch);
    }
}

/// Registry of known BBS+ issuer public keys (G2 points, 96 bytes each).
pub struct BbsIssuerRegistry {
    /// Known issuer G2 public keys (compressed, 96 bytes).
    issuers: Vec<[u8; 96]>,
}

impl Default for BbsIssuerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BbsIssuerRegistry {
    pub fn new() -> Self {
        Self {
            issuers: Vec::new(),
        }
    }

    /// Register a BBS+ issuer public key.
    pub fn add_issuer(&mut self, pk_bytes: [u8; 96]) {
        if !self.issuers.contains(&pk_bytes) {
            self.issuers.push(pk_bytes);
        }
    }

    /// Check whether a given issuer pk is known.
    pub fn is_known(&self, pk_bytes: &[u8; 96]) -> bool {
        self.issuers.contains(pk_bytes)
    }

    /// Number of known BBS+ issuers.
    pub fn len(&self) -> usize {
        self.issuers.len()
    }

    /// List all known issuer public keys.
    pub fn issuer_list(&self) -> &[[u8; 96]] {
        &self.issuers
    }
}

// ─── Trait boundary ─────────────────────────────────────────────────────────

/// Abstraction over credential schemes (Ed25519-based vs BBS+).
///
/// This trait allows the rest of the stack to work with either credential
/// scheme through a common interface.
pub trait CredentialScheme: Send + Sync {
    /// Name of the scheme (for diagnostics).
    fn name(&self) -> &str;

    /// Whether this scheme provides within-epoch unlinkability.
    fn within_epoch_unlinkable(&self) -> bool;

    /// Whether this scheme supports selective disclosure.
    fn selective_disclosure(&self) -> bool;
}

/// Marker for the Ed25519-based scheme.
pub struct Ed25519Scheme;

impl CredentialScheme for Ed25519Scheme {
    fn name(&self) -> &str {
        "ed25519-ephemeral"
    }
    fn within_epoch_unlinkable(&self) -> bool {
        false
    }
    fn selective_disclosure(&self) -> bool {
        false
    }
}

/// Marker for the BBS+ scheme.
pub struct BbsPlusScheme;

impl CredentialScheme for BbsPlusScheme {
    fn name(&self) -> &str {
        "bbs-plus"
    }
    fn within_epoch_unlinkable(&self) -> bool {
        true
    }
    fn selective_disclosure(&self) -> bool {
        true
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attributes() -> BbsCredentialAttributes {
        BbsCredentialAttributes {
            link_secret: generate_link_secret(),
            tier: CredentialTier::Verified,
            capabilities: 0x07, // store + relay + route
            epoch: 1000,
            nonce: 42,
        }
    }

    // ── Adversarial: forgery attempts ───────────────────────────────────
    //
    // Every other test in this module has an honest prover build a proof and
    // then damages it. That only ever exercises the implementation against
    // itself. These two build a proof the way an attacker would -- from the
    // values an attacker can actually obtain -- and are the only tests here
    // that can fail for a reason of *construction* rather than of encoding.

    /// Recompute each generator's discrete log with respect to the G1 base
    /// point, using only public values.
    ///
    /// `generators()` documents itself as "hashing domain-separated indices to
    /// G1", but computes `G1::generator() * hash_to_scalar(..)` instead. That
    /// is a scalar multiple of the base point, not a hash-to-curve, so every
    /// `t_i` below is computable by anyone.
    fn public_generator_dlogs() -> Vec<Scalar> {
        (0..TOTAL_GENERATORS)
            .map(|i| {
                let mut input = Vec::new();
                input.extend_from_slice(b"miasma-bbs-gen-v1-");
                input.extend_from_slice(&(i as u32).to_le_bytes());
                hash_to_scalar(blake3::hash(&input).as_bytes())
            })
            .collect()
    }

    /// BBS+ unforgeability requires the generators to have unknown discrete-log
    /// relationships. They do not, so one issued credential is enough to mint a
    /// signature over attributes the issuer never saw -- without the issuer key.
    #[test]
    fn known_generator_dlogs_allow_attribute_forgery_without_the_issuer_key() {
        let issuer_key = BbsIssuerKey::generate();
        let gv = generators();
        let t = public_generator_dlogs();

        // The generators really are base-point multiples of publicly derivable
        // scalars. If this ever stops holding, the forgery below stops working.
        for i in 0..TOTAL_GENERATORS {
            assert_eq!(
                G1Affine::from(gv[i]),
                G1Affine::from(G1Projective::generator() * t[i]),
                "generator {i} is a known multiple of the base point"
            );
        }

        // A legitimately issued, lowest-privilege credential.
        let honest = BbsCredentialAttributes {
            tier: CredentialTier::Observed,
            capabilities: 0x01,
            ..test_attributes()
        };
        let honest_messages = honest.to_messages();
        let sig = BbsSignature::sign(&issuer_key, &honest_messages);
        let s = deserialize_scalar(&sig.s);
        let e = deserialize_scalar(&sig.e);

        // Because h_i = t_i * g, the whole commitment collapses to one scalar:
        //   B = g * (t0 + s*t1 + sum(m_i * t_{i+2}))
        let aggregate = |m: &[Scalar; NUM_MESSAGES], s: Scalar| {
            let mut acc = t[0] + s * t[1];
            for i in 0..NUM_MESSAGES {
                acc += m[i] * t[i + 2];
            }
            acc
        };

        // Attributes the issuer never signed: top tier, every capability, and
        // a link secret of the attacker's own choosing (so the credential is
        // freely transferable, which the link secret is supposed to prevent).
        let forged_attrs = BbsCredentialAttributes {
            link_secret: [0x9u8; 32],
            tier: CredentialTier::Endorsed,
            capabilities: 0xFF,
            epoch: honest.epoch,
            nonce: honest.nonce,
        };
        let forged_messages = forged_attrs.to_messages();

        // Solve for the blinding factor that keeps the aggregate unchanged.
        let mut wanted = aggregate(&honest_messages, s) - t[0];
        for i in 0..NUM_MESSAGES {
            wanted -= forged_messages[i] * t[i + 2];
        }
        let s_forged = wanted * t[1].invert().unwrap();

        // (A, e, s_forged) satisfies the real BBS+ verification equation
        //   e(A, pk + e*G2) == e(B', G2)
        // for the *forged* message vector. Nothing was re-signed.
        let a = deserialize_g1(&sig.a);
        let mut b_forged = gv[0] + gv[1] * s_forged;
        for i in 0..NUM_MESSAGES {
            b_forged += gv[i + 2] * forged_messages[i];
        }
        let pairing = multi_miller_loop(&[
            (
                &G1Affine::from(a),
                &G2Prepared::from(G2Affine::from(
                    issuer_key.pk + G2Projective::generator() * e,
                )),
            ),
            (
                &G1Affine::from(-b_forged),
                &G2Prepared::from(G2Affine::generator()),
            ),
        ])
        .final_exponentiation();
        assert_eq!(
            pairing,
            bls12_381::Gt::identity(),
            "forged signature satisfies the BBS+ signature equation"
        );

        // And it survives the real prove/verify path end to end.
        let forged_credential = BbsCredential {
            attributes: forged_attrs,
            signature: BbsSignature {
                a: sig.a.clone(),
                e: sig.e.clone(),
                s: s_forged.to_bytes()[..32].to_vec(),
            },
            issuer_pk: issuer_key.pk_bytes().to_vec(),
        };
        let proof = bbs_create_proof(&forged_credential, &DisclosurePolicy::default(), b"ctx");
        let disclosed = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), b"ctx")
            .expect("verifier accepts the forged credential");
        assert_eq!(disclosed, vec![(1, CredentialTier::Endorsed as u64)]);
    }

    /// The verifier runs two independent checks: a Schnorr proof over the
    /// prover-supplied commitment `b_point`, and a pairing check over
    /// `a_prime`/`a_bar`. Nothing ties the two together, so the messages proved
    /// are never bound to the signature. Observing one proof -- they travel in
    /// descriptors -- is enough to mint proofs for arbitrary attributes.
    #[test]
    fn pairing_check_is_not_bound_to_the_message_commitment() {
        let issuer_key = BbsIssuerKey::generate();
        let issuer_pk = issuer_key.pk_bytes();
        let context = b"admission-ctx";

        // A victim publishes an ordinary proof.
        let victim = BbsCredentialAttributes {
            tier: CredentialTier::Observed,
            capabilities: 0x01,
            ..test_attributes()
        };
        let victim_cred = BbsCredential {
            attributes: victim.clone(),
            signature: BbsSignature::sign(&issuer_key, &victim.to_messages()),
            issuer_pk: issuer_pk.to_vec(),
        };
        let observed = bbs_create_proof(&victim_cred, &DisclosurePolicy::default(), context);

        // ── attacker: holds no credential and no issuer key, only `observed`.
        //
        // e(A', W) == e(A_bar, G2) is preserved under scaling both points by
        // the same r, so a fresh-looking pair is free.
        let r = Scalar::random(&mut rand::thread_rng());
        let a_prime = parse_g1_proof(&observed.a_prime).unwrap() * r;
        let a_bar = parse_g1_proof(&observed.a_bar).unwrap() * r;

        // Build a commitment over whatever attributes we want. We know all of
        // its openings because we chose them, so the Schnorr half is honest.
        let gv = generators();
        let forged_attrs = BbsCredentialAttributes {
            link_secret: [0x5u8; 32],
            tier: CredentialTier::Endorsed,
            capabilities: 0xFF,
            epoch: 7777,
            nonce: 1,
        };
        let m = forged_attrs.to_messages();
        let s = Scalar::random(&mut rand::thread_rng());
        let mut b_point = gv[0] + gv[1] * s;
        for i in 0..NUM_MESSAGES {
            b_point += gv[i + 2] * m[i];
        }

        let hidden: Vec<usize> = (0..NUM_MESSAGES).filter(|i| *i != 1).collect();
        let blind_s = Scalar::random(&mut rand::thread_rng());
        let blindings: Vec<Scalar> = hidden
            .iter()
            .map(|_| Scalar::random(&mut rand::thread_rng()))
            .collect();
        let mut t_commit = gv[1] * blind_s;
        for (j, &idx) in hidden.iter().enumerate() {
            t_commit += gv[idx + 2] * blindings[j];
        }

        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(&G1Affine::from(a_prime).to_compressed());
        challenge_input.extend_from_slice(&G1Affine::from(a_bar).to_compressed());
        challenge_input.extend_from_slice(&G1Affine::from(b_point).to_compressed());
        challenge_input.extend_from_slice(&G1Affine::from(t_commit).to_compressed());
        challenge_input.extend_from_slice(context);
        let challenge = hash_to_scalar(&[DOMAIN_BBS_CHALLENGE, &challenge_input].concat());

        let forged = BbsProof {
            a_prime: G1Affine::from(a_prime).to_compressed().to_vec(),
            a_bar: G1Affine::from(a_bar).to_compressed().to_vec(),
            b_point: G1Affine::from(b_point).to_compressed().to_vec(),
            challenge: challenge.to_bytes()[..32].to_vec(),
            response_s: (blind_s + challenge * s).to_bytes()[..32].to_vec(),
            responses: hidden
                .iter()
                .enumerate()
                .map(|(j, &idx)| (blindings[j] + challenge * m[idx]).to_bytes()[..32].to_vec())
                .collect(),
            disclosed: vec![(1, CredentialTier::Endorsed as u64)],
            domain: context.to_vec(),
        };

        let disclosed = bbs_verify_proof(&forged, &issuer_pk, context)
            .expect("verifier accepts a proof minted from an observed one");
        assert_eq!(disclosed, vec![(1, CredentialTier::Endorsed as u64)]);
    }

    #[test]
    fn bbs_issue_and_create_proof() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let attrs = test_attributes();
        let credential = issuer.issue(attrs);

        // Create proof revealing tier only.
        let policy = DisclosurePolicy::default(); // reveal tier
        let context = b"test-verifier-challenge";
        let proof = bbs_create_proof(&credential, &policy, context);

        assert_eq!(proof.disclosed.len(), 1);
        assert_eq!(proof.disclosed[0], (1, CredentialTier::Verified as u64));
        assert_eq!(proof.responses.len(), 4); // 4 hidden attributes
    }

    #[test]
    fn bbs_proof_verifies() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let attrs = test_attributes();
        let credential = issuer.issue(attrs);

        let policy = DisclosurePolicy::default();
        let context = b"verification-context";
        let proof = bbs_create_proof(&credential, &policy, context);

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), context);
        assert!(result.is_ok());
        let disclosed = result.unwrap();
        assert_eq!(disclosed.len(), 1);
        assert_eq!(disclosed[0].1, CredentialTier::Verified as u64);
    }

    #[test]
    fn bbs_wrong_context_fails() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::default();
        let proof = bbs_create_proof(&credential, &policy, b"context-A");

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), b"context-B");
        assert!(result.is_err());
    }

    /// A non-canonical scalar encoding (all-0xff bytes, >= the BLS12-381
    /// scalar field modulus) must be rejected outright by the verifier, not
    /// silently reinterpreted via `hash_to_scalar`. Regression test for the
    /// fallback that `parse_scalar_proof` replaced -- see its doc comment.
    #[test]
    fn bbs_malformed_response_s_rejected() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::default();
        let context = b"malformed-scalar-ctx";
        let mut proof = bbs_create_proof(&credential, &policy, context);

        proof.response_s = vec![0xffu8; 32]; // non-canonical: >= field modulus

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), context);
        assert_eq!(result, Err(BbsError::InvalidProof));
    }

    /// Same as above, but for a hidden-message response rather than `response_s`.
    #[test]
    fn bbs_malformed_hidden_response_rejected() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::default();
        let context = b"malformed-response-ctx";
        let mut proof = bbs_create_proof(&credential, &policy, context);

        assert!(!proof.responses.is_empty());
        proof.responses[0] = vec![0xffu8; 32]; // non-canonical: >= field modulus

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), context);
        assert_eq!(result, Err(BbsError::InvalidProof));
    }

    /// A response of the wrong length must also be rejected outright.
    #[test]
    fn bbs_wrong_length_response_rejected() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::default();
        let context = b"wrong-length-ctx";
        let mut proof = bbs_create_proof(&credential, &policy, context);

        proof.response_s = vec![0x01u8; 16]; // too short

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), context);
        assert_eq!(result, Err(BbsError::InvalidProof));
    }

    #[test]
    fn bbs_selective_disclosure_tier_and_caps() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::tier_and_caps();
        let context = b"selective-ctx";
        let proof = bbs_create_proof(&credential, &policy, context);

        assert_eq!(proof.disclosed.len(), 2);
        assert_eq!(proof.responses.len(), 3); // 3 hidden

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), context);
        assert!(result.is_ok());
        let disclosed = result.unwrap();
        assert!(disclosed
            .iter()
            .any(|&(i, v)| i == 1 && v == CredentialTier::Verified as u64));
        assert!(disclosed.iter().any(|&(i, v)| i == 2 && v == 0x07));
    }

    #[test]
    fn bbs_reveal_nothing() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::reveal_nothing();
        let context = b"nothing-ctx";
        let proof = bbs_create_proof(&credential, &policy, context);

        assert_eq!(proof.disclosed.len(), 0);
        assert_eq!(proof.responses.len(), 5); // all hidden

        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), context);
        assert!(result.is_ok());
    }

    #[test]
    fn bbs_two_proofs_unlinkable() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::default();
        let proof1 = bbs_create_proof(&credential, &policy, b"ctx-1");
        let proof2 = bbs_create_proof(&credential, &policy, b"ctx-2");

        // A' is randomised each time → different values.
        assert_ne!(proof1.a_prime, proof2.a_prime);
        // Challenge is different.
        assert_ne!(proof1.challenge, proof2.challenge);
        // Responses are different.
        assert_ne!(proof1.responses, proof2.responses);

        // Both verify independently.
        assert!(bbs_verify_proof(&proof1, &issuer_key.pk_bytes(), b"ctx-1").is_ok());
        assert!(bbs_verify_proof(&proof2, &issuer_key.pk_bytes(), b"ctx-2").is_ok());
    }

    #[test]
    fn bbs_wrong_issuer_key_fails() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let wrong_key = BbsIssuerKey::from_seed(b"wrong-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key);
        let credential = issuer.issue(test_attributes());

        let policy = DisclosurePolicy::default();
        let context = b"wrong-key-ctx";
        let proof = bbs_create_proof(&credential, &policy, context);

        // Verification with the wrong key must fail: pairing check
        // e(A', W) != e(A_bar, G2) when W is the wrong issuer key.
        let result = bbs_verify_proof(&proof, &wrong_key.pk_bytes(), context);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BbsError::IssuerBindingFailed);
    }

    #[test]
    fn bbs_credential_serde_roundtrip() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key);
        let credential = issuer.issue(test_attributes());

        let bytes = bincode::serialize(&credential).unwrap();
        let deserialized: BbsCredential = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.attributes.tier, CredentialTier::Verified);
        assert_eq!(deserialized.attributes.capabilities, 0x07);
        assert_eq!(deserialized.issuer_pk, credential.issuer_pk);
    }

    #[test]
    fn bbs_proof_serde_roundtrip() {
        let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
        let issuer = BbsIssuer::new(issuer_key);
        let credential = issuer.issue(test_attributes());

        let proof = bbs_create_proof(&credential, &DisclosurePolicy::default(), b"ctx");
        let bytes = bincode::serialize(&proof).unwrap();
        let deserialized: BbsProof = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.a_prime, proof.a_prime);
        assert_eq!(deserialized.challenge, proof.challenge);
    }

    #[test]
    fn bbs_scheme_trait_properties() {
        let ed = Ed25519Scheme;
        assert!(!ed.within_epoch_unlinkable());
        assert!(!ed.selective_disclosure());
        assert_eq!(ed.name(), "ed25519-ephemeral");

        let bbs = BbsPlusScheme;
        assert!(bbs.within_epoch_unlinkable());
        assert!(bbs.selective_disclosure());
        assert_eq!(bbs.name(), "bbs-plus");
    }

    #[test]
    fn bbs_endorsed_tier_credential() {
        let issuer_key = BbsIssuerKey::from_seed(b"endorsed-issuer");
        let issuer = BbsIssuer::new(issuer_key.clone());
        let attrs = BbsCredentialAttributes {
            link_secret: generate_link_secret(),
            tier: CredentialTier::Endorsed,
            capabilities: 0x0F,
            epoch: 2000,
            nonce: 99,
        };
        let credential = issuer.issue(attrs);

        let policy = DisclosurePolicy::tier_and_caps();
        let proof = bbs_create_proof(&credential, &policy, b"endorsed-ctx");
        let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), b"endorsed-ctx");
        assert!(result.is_ok());
        let disclosed = result.unwrap();
        assert!(disclosed
            .iter()
            .any(|&(i, v)| i == 1 && v == CredentialTier::Endorsed as u64));
    }

    #[test]
    fn link_secret_generation_unique() {
        let s1 = generate_link_secret();
        let s2 = generate_link_secret();
        assert_ne!(s1, s2);
    }
}
