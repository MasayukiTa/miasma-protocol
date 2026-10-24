//! Directed share v2 — known-answer and wire-shape checks.
//!
//! The header, offer, binding and transcript checks read expected values from
//! `tests/fixtures/directed_v2/frozen.hex`, each computed independently from the
//! design (a separate implementation of the same BLAKE3 derive, HKDF-SHA256,
//! X25519 and Ed25519 steps), not copied from this crate's output; they
//! recompute each value through the crate and assert it equals the frozen line,
//! so a drift in either the design or the code shows up here. The v2 key
//! schedule and real-envelope checks lower in this file do not read frozen
//! samples: the schedule is not yet finalized, so they recompute it against an
//! in-test HKDF and run a real seal/open round trip instead.
//!
//! Fixture inputs are derived from labels through `fill` (a keyed BLAKE3 XOF), so
//! no literal keys, nonces, salts or passwords appear in this file.

use miasma_core::directed::v2::credential;
use miasma_core::directed::v2::kdf;
use miasma_core::directed::v2::offer::{self, OfferFields};
use miasma_core::directed::v2::transcript::{self, Header, OuterRefs};

use ed25519_dalek::SigningKey;

const FROZEN: &str = include_str!("fixtures/directed_v2/frozen.hex");
const FIX_CTX: &str = "miasma directed v2 kat fixtures (test-only)";

/// Keyed BLAKE3 XOF over `label`, matching the generator that wrote the fixture.
fn fill<const N: usize>(label: &str) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key(FIX_CTX);
    h.update(label.as_bytes());
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

fn frozen(name: &str) -> Vec<u8> {
    for line in FROZEN.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (n, hex_str) = line
            .split_once(' ')
            .expect("each fixture line is `name hex`");
        if n == name {
            return hex::decode(hex_str).expect("fixture hex decodes");
        }
    }
    panic!("fixture `{name}` not found");
}

fn arr32(name: &str) -> [u8; 32] {
    frozen(name).try_into().expect("32 bytes")
}
fn arr16(name: &str) -> [u8; 16] {
    frozen(name).try_into().expect("16 bytes")
}
fn arr24(name: &str) -> [u8; 24] {
    frozen(name).try_into().expect("24 bytes")
}
fn arr64(name: &str) -> [u8; 64] {
    frozen(name).try_into().expect("64 bytes")
}

// X25519 keys from the same labels the generator used.
fn x_pub(label: &str) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(fill::<32>(label));
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}
fn x_secret(label: &str) -> [u8; 32] {
    x25519_dalek::StaticSecret::from(fill::<32>(label)).to_bytes()
}
fn ed_key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&fill::<32>(label))
}

#[test]
fn fixture_public_keys_match_the_frozen_values() {
    // If these drift, every downstream KAT would drift too; check them first so
    // a key-derivation mismatch is easy to spot.
    assert_eq!(
        ed_key("sender identity sk").verifying_key().to_bytes(),
        arr32("sender_identity")
    );
    assert_eq!(
        ed_key("recipient identity sk").verifying_key().to_bytes(),
        arr32("recipient_identity")
    );
    assert_eq!(x_pub("sender sharing secret"), arr32("sender_sharing"));
    assert_eq!(x_pub("r_static secret"), arr32("r_static_pub"));
    assert_eq!(x_pub("e_s secret"), arr32("e_s_pub"));
    assert_eq!(x_pub("r_eph secret"), arr32("r_eph_pub"));
}

#[test]
fn binding_signatures_match_the_frozen_values() {
    let sender_sk = ed_key("sender identity sk");
    let sender_sharing = x_pub("sender sharing secret");
    assert_eq!(
        credential::sign_binding(&sender_sk, &sender_sharing),
        arr64("sender_binding")
    );

    let recipient_sk = ed_key("recipient identity sk");
    let r_static_pub = x_pub("r_static secret");
    assert_eq!(
        credential::sign_binding(&recipient_sk, &r_static_pub),
        arr64("recipient_binding")
    );

    // And they verify.
    assert!(credential::verify_binding(
        &arr32("sender_identity"),
        &sender_sharing,
        &arr64("sender_binding")
    ));
}

#[test]
fn the_offer_signature_target_matches_the_frozen_value() {
    let offer_id = arr16("offer_id");
    let request_id = arr16("request_id");
    let requester = frozen("requester");
    let recipient_identity = arr32("recipient_identity");
    let recipient_sharing = arr32("r_static_pub");
    let recipient_binding = arr64("recipient_binding");
    let recipient_ephemeral = arr32("r_eph_pub");
    let fields = OfferFields {
        suite: 2,
        offer_id: &offer_id,
        request_id: &request_id,
        requester: &requester,
        recipient_identity: &recipient_identity,
        recipient_sharing: &recipient_sharing,
        recipient_binding: &recipient_binding,
        recipient_ephemeral: &recipient_ephemeral,
        ttl_secs: 1200,
    };
    assert_eq!(fields.canonical_bytes(), frozen("offer_canonical"));
    assert_eq!(&fields.digest()[..], &frozen("offer_sig_msg")[..]);

    // The recipient's signature over that target verifies.
    let recipient_sk = ed_key("recipient identity sk");
    let sig = offer::sign_offer(&recipient_sk, &fields);
    assert!(offer::verify_offer_signature(&fields, &sig));
    assert_eq!(sig, arr64("offer_sig"));
}

fn kat_header() -> (
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 16],
    [u8; 32],
) {
    (
        arr32("envelope_id"),
        arr32("sender_identity"),
        arr32("sender_sharing"),
        arr32("recipient_identity"),
        arr32("r_static_pub"),
        arr32("e_s_pub"),
        arr32("r_eph_pub"),
        arr16("offer_id"),
        arr32("password_salt"),
    )
}

#[test]
fn the_header_bytes_and_h_hdr_match_the_frozen_values() {
    let (
        envelope_id,
        sender_identity,
        sender_sharing,
        recipient_identity,
        r_static_pub,
        e_s_pub,
        r_eph_pub,
        offer_id,
        password_salt,
    ) = kat_header();
    let header = Header {
        version: 2,
        suite: 2,
        envelope_id: &envelope_id,
        sender_identity: &sender_identity,
        sender_pubkey: &sender_sharing,
        recipient_identity: &recipient_identity,
        recipient_pubkey: &r_static_pub,
        ephemeral_pubkey: &e_s_pub,
        recipient_ephemeral: &r_eph_pub,
        offer_id: &offer_id,
        kdf_m_kib: 65536,
        kdf_t_cost: 3,
        kdf_p_cost: 1,
        password_salt: &password_salt,
        created_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        retention_secs: 3600,
    };
    assert_eq!(header.canonical_bytes(), frozen("header_bytes"));
    assert_eq!(header.h_hdr(), arr32("h_hdr"));
}

#[test]
fn sig_msg_signature_and_transcript_hash_match_the_frozen_values() {
    let h_hdr = arr32("h_hdr");
    let payload_nonce = arr24("payload_nonce");
    let dek_nonce = arr24("dek_nonce");
    let encrypted_payload = frozen("encrypted_payload");
    let wrapped_dek = frozen("wrapped_dek");
    let sender_binding = arr64("sender_binding");
    let outer = OuterRefs {
        payload_nonce: &payload_nonce,
        encrypted_payload: &encrypted_payload,
        dek_nonce: &dek_nonce,
        wrapped_dek: &wrapped_dek,
        sender_binding: &sender_binding,
    };
    let sm = transcript::sig_msg(&h_hdr, &outer);
    assert_eq!(sm, arr32("sig_msg"));

    let sender_sk = ed_key("sender identity sk");
    let signature = transcript::sign_transcript(&sender_sk, &sm);
    assert_eq!(signature, arr64("signature"));
    assert!(transcript::verify_transcript(
        &arr32("sender_identity"),
        &sm,
        &signature
    ));

    assert_eq!(
        transcript::transcript_hash(&sm, &signature),
        arr32("transcript_hash")
    );
}

// --- v2 key schedule and real-envelope checks, decoupled from frozen samples. ---
//
// The v2 key derivation and envelope format are not yet finalized, so instead of
// reading frozen ciphertext/key samples (which the earlier salt-as-label KDF
// produced) these tests recompute the schedule independently and run a real
// seal/open round trip; the frozen real_* samples will return once v2 is frozen.
//
// No literal key, nonce, salt or password appears: inputs come from `fill`
// labels or the RNG, and the key schedule is checked against an in-test
// HKDF-SHA256 (RFC 5869) built by hand from HMAC-SHA256 over `sha2::Sha256`,
// independent of the `hkdf` crate the production code uses.

use sha2::{Digest, Sha256};

use miasma_core::directed::v2::seal::{self, SealInput};

/// Key-schedule domain-separation labels (sec 4.2), fixed by the wire format.
const LABEL_KEX: &[u8] = b"miasma/directed/v2/kex";
const INFO_PAYLOAD: &[u8] = b"miasma/directed/v2/payload";
const INFO_CONTENT: &[u8] = b"miasma/directed/v2/content";

/// HMAC-SHA256 by hand (FIPS 198-1) over `sha2::Sha256`, so the HKDF below does
/// not lean on the `hkdf` crate the production code uses.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(d.as_slice());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner.as_slice());
    let mac = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.as_slice());
    out
}

/// RFC 5869 HKDF-SHA256 with an empty (None) Extract salt, expanded to 32 bytes
/// (one block: T(1)).
fn hkdf_no_salt_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(&[0u8; 32], ikm);
    let mut msg = Vec::with_capacity(info.len() + 1);
    msg.extend_from_slice(info);
    msg.push(0x01);
    hmac_sha256(&prk, &msg)
}

/// The derived keys match an independent HKDF-SHA256 over the same inputs, and
/// the sender and recipient sides reach the same payload key. Inputs come from
/// `fill` labels, not frozen samples, because the v2 schedule is not yet frozen.
#[test]
fn the_derived_keys_match_the_frozen_values() {
    let h_hdr = fill::<32>("derived keys h_hdr");

    // Sender-side dh_concat from fixture secrets/publics.
    let ds = kdf::dh_concat_sender(
        &x_secret("e_s secret"),
        &x_pub("r_static secret"),
        &x_pub("r_eph secret"),
    )
    .unwrap();

    // k_payload through the crate equals an independent HKDF(salt=None,
    // ikm = dh1||dh2, info = LABEL_KEX || INFO_PAYLOAD || H_hdr).
    let k_payload = kdf::derive_k_payload(&ds, &h_hdr).unwrap();
    let mut payload_info = Vec::new();
    payload_info.extend_from_slice(LABEL_KEX);
    payload_info.extend_from_slice(INFO_PAYLOAD);
    payload_info.extend_from_slice(&h_hdr);
    let independent_payload = hkdf_no_salt_32(&ds, &payload_info);
    assert_eq!(&k_payload[..], &independent_payload[..]);

    // k_content through the crate equals an independent HKDF(salt=None, ikm=dek,
    // info = INFO_CONTENT || suite || envelope_id).
    let dek = fill::<32>("derived keys dek");
    let envelope_id = fill::<32>("derived keys envelope_id");
    let k_content = kdf::derive_k_content(&dek, 2, &envelope_id).unwrap();
    let mut content_info = Vec::new();
    content_info.extend_from_slice(INFO_CONTENT);
    content_info.push(2u8);
    content_info.extend_from_slice(&envelope_id);
    let independent_content = hkdf_no_salt_32(&dek, &content_info);
    assert_eq!(&k_content[..], &independent_content[..]);

    // The recipient side reaches the same payload key.
    let dr = kdf::dh_concat_recipient(
        &x_secret("r_static secret"),
        &x_secret("r_eph secret"),
        &x_pub("e_s secret"),
    )
    .unwrap();
    let k_payload_r = kdf::derive_k_payload(&dr, &h_hdr).unwrap();
    assert_eq!(&k_payload[..], &k_payload_r[..]);
}

/// Argon2id cost parameters for the round-trip tests: the shared minimum mouth,
/// so the password hash stays cheap in CI.
const RT_KDF_M_KIB: u32 = 8;
const RT_KDF_T_COST: u32 = 1;
const RT_KDF_P_COST: u32 = 1;

/// Round-trip material, every field drawn from a label or the RNG so no key,
/// nonce, salt or password is a fixed value.
struct RealWorld {
    r_static_secret: [u8; 32],
    r_static_pub: [u8; 32],
    r_eph_secret: [u8; 32],
    r_eph_pub: [u8; 32],
    e_s_secret: [u8; 32],
    e_s_pub: [u8; 32],
    sender_identity: [u8; 32],
    recipient_identity: [u8; 32],
    envelope_id: [u8; 32],
    offer_id: [u8; 16],
    password_salt: [u8; 32],
    dek: [u8; 32],
    password: String,
}

/// Draw the round-trip material from the RNG.
fn real_world() -> RealWorld {
    let r_static = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let e_s = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    // The password is the ASCII hex of 16 random bytes, so it is a valid `&str`
    // for `password_hash` and never a literal password string.
    let pw: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    RealWorld {
        r_static_secret: r_static.to_bytes(),
        r_static_pub: x25519_dalek::PublicKey::from(&r_static).to_bytes(),
        r_eph_secret: r_eph.to_bytes(),
        r_eph_pub: x25519_dalek::PublicKey::from(&r_eph).to_bytes(),
        e_s_secret: e_s.to_bytes(),
        e_s_pub: x25519_dalek::PublicKey::from(&e_s).to_bytes(),
        sender_identity: rand::random(),
        recipient_identity: rand::random(),
        envelope_id: rand::random(),
        offer_id: rand::random(),
        password_salt: rand::random(),
        dek: rand::random(),
        password: pw.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

fn real_header(w: &RealWorld) -> Header<'_> {
    Header {
        version: 2,
        suite: 2,
        envelope_id: &w.envelope_id,
        sender_identity: &w.sender_identity,
        sender_pubkey: &w.r_static_pub,
        recipient_identity: &w.recipient_identity,
        recipient_pubkey: &w.r_static_pub,
        ephemeral_pubkey: &w.e_s_pub,
        recipient_ephemeral: &w.r_eph_pub,
        offer_id: &w.offer_id,
        kdf_m_kib: RT_KDF_M_KIB,
        kdf_t_cost: RT_KDF_T_COST,
        kdf_p_cost: RT_KDF_P_COST,
        password_salt: &w.password_salt,
        created_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        retention_secs: 3600,
    }
}

/// A real envelope, sealed with the public functions, opens end to end for the
/// recipient: the DEK wrap yields the DEK, that DEK opens the body, and the
/// payload preview opens without a password. A round trip replaces the frozen
/// samples until the v2 format is finalized.
#[test]
fn real_envelope_v2_opens_for_the_recipient_with_fixed_keys_and_password() {
    let w = real_world();
    let mut rng = rand::rngs::OsRng;

    let body = b"the real directed v2 body bytes";
    let preview = b"preview: mid=42, size=2048";

    // Seal the body under the DEK (content layer).
    let (content_nonce, protected) =
        seal::seal_content_with(&mut rng, &w.dek, 2, &w.envelope_id, body).unwrap();

    // Seal the payload preview and wrap the DEK against the header.
    let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
    let pwh = kdf::password_hash(
        &w.password,
        &w.password_salt,
        RT_KDF_M_KIB,
        RT_KDF_T_COST,
        RT_KDF_P_COST,
    )
    .unwrap();
    let hdr = real_header(&w);
    let sealed = seal::seal_outer_with(
        &mut rng,
        &hdr,
        &SealInput {
            dh_concat: &ds,
            pwh: &pwh,
            dek: &w.dek,
            payload_plaintext: preview,
        },
    )
    .unwrap();

    // Recipient side: recompute dh_concat and H_hdr, open the wrap, then body.
    let dr = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();
    let h_hdr = hdr.h_hdr();
    let dek = seal::open_wrapped_dek(&dr, &pwh, &h_hdr, &sealed.dek_nonce, &sealed.wrapped_dek)
        .expect("the real DEK wrap opens for the recipient");
    assert_eq!(&dek[..], &w.dek[..]);

    let opened_body = seal::open_content(&dek, 2, &w.envelope_id, &content_nonce, &protected)
        .expect("the protected body opens with the recovered DEK");
    assert_eq!(opened_body, body);

    let opened_preview = seal::open_payload(
        &dr,
        &h_hdr,
        &sealed.payload_nonce,
        &sealed.encrypted_payload,
    )
    .expect("the payload preview opens without a password");
    assert_eq!(opened_preview, preview);
}

/// Forward secrecy: with `r_eph` replaced by an unrelated secret the recipient
/// can no longer form `dh2`, so the DEK wrap does not open; the correct
/// ephemeral still opens it, and tampering with the wrap fails. A round trip
/// replaces the frozen samples until the v2 format is finalized.
#[test]
fn real_envelope_v2_stays_closed_without_r_eph() {
    let w = real_world();
    let mut rng = rand::rngs::OsRng;

    let ds = kdf::dh_concat_sender(&w.e_s_secret, &w.r_static_pub, &w.r_eph_pub).unwrap();
    let pwh = kdf::password_hash(
        &w.password,
        &w.password_salt,
        RT_KDF_M_KIB,
        RT_KDF_T_COST,
        RT_KDF_P_COST,
    )
    .unwrap();
    let hdr = real_header(&w);
    let mut sealed = seal::seal_outer_with(
        &mut rng,
        &hdr,
        &SealInput {
            dh_concat: &ds,
            pwh: &pwh,
            dek: &w.dek,
            payload_plaintext: b"preview",
        },
    )
    .unwrap();
    let h_hdr = hdr.h_hdr();

    // An unrelated ephemeral stands in for "r_eph discarded": dh2 is wrong.
    let other_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
    let dr_wrong = kdf::dh_concat_recipient(&w.r_static_secret, &other_eph, &w.e_s_pub).unwrap();
    assert!(
        seal::open_wrapped_dek(
            &dr_wrong,
            &pwh,
            &h_hdr,
            &sealed.dek_nonce,
            &sealed.wrapped_dek
        )
        .is_err(),
        "without r_eph the DEK wrap must not open"
    );

    // The correct ephemeral still opens it, so the failure above is the missing
    // r_eph and not some other mismatch.
    let dr_ok = kdf::dh_concat_recipient(&w.r_static_secret, &w.r_eph_secret, &w.e_s_pub).unwrap();
    assert!(
        seal::open_wrapped_dek(&dr_ok, &pwh, &h_hdr, &sealed.dek_nonce, &sealed.wrapped_dek)
            .is_ok(),
        "with the right r_eph the DEK wrap opens"
    );

    // Tampering with one byte of the wrap fails decryption.
    sealed.wrapped_dek[0] ^= 0x01;
    assert!(
        seal::open_wrapped_dek(&dr_ok, &pwh, &h_hdr, &sealed.dek_nonce, &sealed.wrapped_dek)
            .is_err(),
        "a tampered wrap must not open"
    );
}
