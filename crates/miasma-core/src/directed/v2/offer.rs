//! Prekey offer: the recipient's signed response that supplies `r_eph`.
//!
//! The offer is signed over a domain-separated BLAKE3 digest of its canonical
//! bytes (§3.3). The sender checks the offer against the request it sent and
//! the contact it holds (§3.4) before building an invite.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Domain-separation label for the offer signature digest.
const OFFER_LABEL: &str = "miasma directed v2 prekey offer";
/// Domain-separation label for the sharing-key binding digest (§3.2).
const BINDING_LABEL: &str = "miasma sharing key binding v1";

/// The fields an offer signs over, in canonical order.
///
/// Integers are little-endian. `requester` is length-prefixed with a u16 so the
/// variable-length PeerId cannot shift the following fields.
pub struct OfferFields<'a> {
    /// Suite selector.
    pub suite: u8,
    /// Offer identifier.
    pub offer_id: &'a [u8; 16],
    /// Request identifier echoed from the request.
    pub request_id: &'a [u8; 16],
    /// Requester PeerId bytes.
    pub requester: &'a [u8],
    /// Recipient's Ed25519 identity public key.
    pub recipient_identity: &'a [u8; 32],
    /// Recipient's X25519 sharing key.
    pub recipient_sharing: &'a [u8; 32],
    /// Signature binding the sharing key to the identity.
    pub recipient_binding: &'a [u8; 64],
    /// Recipient ephemeral public key.
    pub recipient_ephemeral: &'a [u8; 32],
    /// Advertised lifetime in seconds.
    pub ttl_secs: u32,
}

impl OfferFields<'_> {
    /// Build the canonical byte string the offer signature covers.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(1 + 16 + 16 + 2 + self.requester.len() + 32 + 32 + 64 + 32 + 4);
        v.push(self.suite);
        v.extend_from_slice(self.offer_id);
        v.extend_from_slice(self.request_id);
        v.extend_from_slice(&(self.requester.len() as u16).to_le_bytes());
        v.extend_from_slice(self.requester);
        v.extend_from_slice(self.recipient_identity);
        v.extend_from_slice(self.recipient_sharing);
        v.extend_from_slice(self.recipient_binding);
        v.extend_from_slice(self.recipient_ephemeral);
        v.extend_from_slice(&self.ttl_secs.to_le_bytes());
        v
    }

    /// The digest the offer signature is computed over.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(OFFER_LABEL);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }
}

/// Sign an offer with the recipient's identity key.
pub fn sign_offer(recipient_sk: &SigningKey, fields: &OfferFields<'_>) -> [u8; 64] {
    recipient_sk.sign(&fields.digest()).to_bytes()
}

/// Verify that `sig` is the recipient identity's signature over `fields`.
pub fn verify_offer_signature(fields: &OfferFields<'_>, sig: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(fields.recipient_identity) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    vk.verify_strict(&fields.digest(), &Signature::from_bytes(sig))
        .is_ok()
}

/// Recompute the §3.2 sharing-key binding digest (kept local to this module).
fn binding_digest(identity_pub: &[u8; 32], sharing_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(BINDING_LABEL);
    h.update(identity_pub);
    h.update(sharing_pub);
    *h.finalize().as_bytes()
}

fn verify_binding(identity_pub: &[u8; 32], sharing_pub: &[u8; 32], sig: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(identity_pub) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    vk.verify_strict(
        &binding_digest(identity_pub, sharing_pub),
        &Signature::from_bytes(sig),
    )
    .is_ok()
}

/// Why a sender rejected an offer (maps to the error codes in `wire::codes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferReject {
    /// The suite was not in the set the sender requested.
    UnsupportedSuite,
    /// The request id or requester did not match the sender's request.
    PeerMismatch,
    /// The recipient identity did not match the contact PeerId.
    IdentityMismatch,
    /// The recipient binding did not verify.
    BadBinding,
    /// The sharing key did not match the contact.
    KeyMismatch,
    /// The offer signature did not verify.
    BadSignature,
}

/// What the sender knows before it asked for an offer.
pub struct SenderExpectation<'a> {
    /// Suites the sender offered in its request.
    pub requested_suites: &'a [u8],
    /// The request id the sender sent.
    pub request_id: &'a [u8; 16],
    /// The sender's own PeerId bytes (the offer must echo these as requester).
    pub own_requester: &'a [u8],
    /// PeerId bytes derived from the contact and from the connection; both must
    /// match `recipient_identity`'s PeerId. The caller supplies the already
    /// agreed-upon PeerId bytes to compare against.
    pub contact_peer_id: &'a [u8],
    /// The sharing key the contact string carries (`msk:`).
    pub contact_sharing: &'a [u8; 32],
    /// PeerId bytes derived from `recipient_identity` by the caller.
    pub recipient_identity_peer_id: &'a [u8],
}

/// Run the sender-side checks of §3.4 (items 1-7 that are pure).
///
/// PeerId derivation from an Ed25519 key is done by the caller and passed in as
/// `recipient_identity_peer_id`; this function compares byte strings so it stays
/// free of the networking types.
pub fn check_offer(
    fields: &OfferFields<'_>,
    sig: &[u8; 64],
    expect: &SenderExpectation<'_>,
) -> Result<(), OfferReject> {
    // 1. suite is one the sender offered.
    if !expect.requested_suites.contains(&fields.suite) {
        return Err(OfferReject::UnsupportedSuite);
    }
    // 2. request_id and requester echo the sender's request.
    if fields.request_id != expect.request_id || fields.requester != expect.own_requester {
        return Err(OfferReject::PeerMismatch);
    }
    // 3. recipient_identity's PeerId matches the contact and the connection.
    if expect.recipient_identity_peer_id != expect.contact_peer_id {
        return Err(OfferReject::IdentityMismatch);
    }
    // 4. recipient_binding is correct for (recipient_identity, recipient_sharing).
    if !verify_binding(
        fields.recipient_identity,
        fields.recipient_sharing,
        fields.recipient_binding,
    ) {
        return Err(OfferReject::BadBinding);
    }
    // 5. recipient_sharing matches the contact's msk: key.
    if fields.recipient_sharing != expect.contact_sharing {
        return Err(OfferReject::KeyMismatch);
    }
    // 6. the offer signature is correct.
    if !verify_offer_signature(fields, sig) {
        return Err(OfferReject::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Setup {
        sk: SigningKey,
        offer_id: [u8; 16],
        request_id: [u8; 16],
        requester: Vec<u8>,
        recipient_identity: [u8; 32],
        recipient_sharing: [u8; 32],
        recipient_binding: [u8; 64],
        recipient_ephemeral: [u8; 32],
        ttl_secs: u32,
    }

    fn setup() -> Setup {
        let sk = SigningKey::from_bytes(&rand::random());
        let recipient_identity = sk.verifying_key().to_bytes();
        let recipient_sharing: [u8; 32] = rand::random();
        // Build a correct binding over (identity, sharing).
        let recipient_binding = sk
            .sign(&binding_digest(&recipient_identity, &recipient_sharing))
            .to_bytes();
        Setup {
            sk,
            offer_id: rand::random(),
            request_id: rand::random(),
            requester: rand::random::<[u8; 38]>().to_vec(),
            recipient_identity,
            recipient_sharing,
            recipient_binding,
            recipient_ephemeral: rand::random(),
            ttl_secs: rand::random(),
        }
    }

    impl Setup {
        fn fields(&self) -> OfferFields<'_> {
            OfferFields {
                suite: 2,
                offer_id: &self.offer_id,
                request_id: &self.request_id,
                requester: &self.requester,
                recipient_identity: &self.recipient_identity,
                recipient_sharing: &self.recipient_sharing,
                recipient_binding: &self.recipient_binding,
                recipient_ephemeral: &self.recipient_ephemeral,
                ttl_secs: self.ttl_secs,
            }
        }
    }

    #[test]
    fn an_offer_signed_by_the_recipient_verifies() {
        let s = setup();
        let f = s.fields();
        let sig = sign_offer(&s.sk, &f);
        assert!(verify_offer_signature(&f, &sig));
    }

    #[test]
    fn flipping_a_field_breaks_the_offer_signature() {
        let s = setup();
        let f = s.fields();
        let sig = sign_offer(&s.sk, &f);
        let mut eph = s.recipient_ephemeral;
        eph[0] ^= 0x01;
        let tampered = OfferFields {
            recipient_ephemeral: &eph,
            ..f
        };
        assert!(!verify_offer_signature(&tampered, &sig));
    }

    fn expectation<'a>(s: &'a Setup, suites: &'a [u8]) -> SenderExpectation<'a> {
        SenderExpectation {
            requested_suites: suites,
            request_id: &s.request_id,
            own_requester: &s.requester,
            contact_peer_id: &s.requester, // reuse a stable byte string as the agreed PeerId
            contact_sharing: &s.recipient_sharing,
            recipient_identity_peer_id: &s.requester,
        }
    }

    #[test]
    fn a_correct_offer_passes_the_sender_checks() {
        let s = setup();
        let f = s.fields();
        let sig = sign_offer(&s.sk, &f);
        let suites = [2u8];
        assert_eq!(check_offer(&f, &sig, &expectation(&s, &suites)), Ok(()));
    }

    #[test]
    fn a_sharing_key_that_differs_from_the_contact_is_key_mismatch() {
        let s = setup();
        let f = s.fields();
        let sig = sign_offer(&s.sk, &f);
        let suites = [2u8];
        let other: [u8; 32] = rand::random();
        let mut exp = expectation(&s, &suites);
        exp.contact_sharing = &other;
        assert_eq!(check_offer(&f, &sig, &exp), Err(OfferReject::KeyMismatch));
    }

    #[test]
    fn a_suite_not_requested_is_unsupported() {
        let s = setup();
        let f = s.fields();
        let sig = sign_offer(&s.sk, &f);
        let suites = [9u8];
        assert_eq!(
            check_offer(&f, &sig, &expectation(&s, &suites)),
            Err(OfferReject::UnsupportedSuite)
        );
    }

    #[test]
    fn a_tampered_signature_is_bad_signature() {
        let s = setup();
        let f = s.fields();
        let mut sig = sign_offer(&s.sk, &f);
        sig[0] ^= 0x01;
        let suites = [2u8];
        assert_eq!(
            check_offer(&f, &sig, &expectation(&s, &suites)),
            Err(OfferReject::BadSignature)
        );
    }

    #[test]
    fn a_wrong_request_id_is_peer_mismatch() {
        let s = setup();
        let f = s.fields();
        let sig = sign_offer(&s.sk, &f);
        let suites = [2u8];
        let other_req: [u8; 16] = rand::random();
        let mut exp = expectation(&s, &suites);
        exp.request_id = &other_req;
        assert_eq!(check_offer(&f, &sig, &exp), Err(OfferReject::PeerMismatch));
    }
}
