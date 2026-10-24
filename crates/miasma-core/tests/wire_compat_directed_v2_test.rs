//! Directed share v2 — known-answer and wire-shape checks.
//!
//! Every expected value in `tests/fixtures/directed_v2/frozen.hex` was computed
//! independently from the design (a separate implementation of the same BLAKE3
//! derive, HKDF-SHA256, X25519 and Ed25519 steps), not copied from this crate's
//! output. The tests below recompute each value through the crate and assert it
//! equals the frozen line, so a drift in either the design or the code shows up
//! here.
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

#[test]
fn the_derived_keys_match_the_frozen_values() {
    // Sender-side dh_concat from the fixture secrets/publics.
    let ds = kdf::dh_concat_sender(
        &x_secret("e_s secret"),
        &arr32("r_static_pub"),
        &arr32("r_eph_pub"),
    )
    .unwrap();
    let h_hdr = arr32("h_hdr");
    let k_payload = kdf::derive_k_payload(&ds, &h_hdr).unwrap();
    assert_eq!(&k_payload[..], &frozen("k_payload")[..]);

    let dek = arr32("dek");
    let k_content = kdf::derive_k_content(&dek, 2, &arr32("envelope_id")).unwrap();
    assert_eq!(&k_content[..], &frozen("k_content")[..]);

    // Recipient-side dh_concat reaches the same payload key.
    let dr = kdf::dh_concat_recipient(
        &x_secret("r_static secret"),
        &x_secret("r_eph secret"),
        &arr32("e_s_pub"),
    )
    .unwrap();
    let k_payload_r = kdf::derive_k_payload(&dr, &h_hdr).unwrap();
    assert_eq!(&k_payload[..], &k_payload_r[..]);
}

// --- Real-envelope integration KAT and forward secrecy (§8.2, §8.3). ---
//
// The `real_*_v2` fixtures below were produced independently from the design
// (a separate X25519 + HKDF-SHA256 + Argon2id + XChaCha20-Poly1305 run), then
// frozen. These tests walk the recipient path
// `kdf::dh_concat_recipient` -> `seal::open_wrapped_dek` ->
// `seal::open_content` / `seal::open_payload` and assert the frozen bytes open
// to the expected plaintext. No literal key, nonce, salt or password appears:
// every secret comes from a `fill` label, and `pwh` is derived through
// `kdf::password_hash`.
//
// The reused `h_hdr` fixture carries kdf params m=65536, t=3, p=1, so the
// password hash below uses the same costs; the wrap AAD binds that same
// `h_hdr`.

use miasma_core::directed::v2::seal;

/// Argon2id cost parameters baked into the frozen `h_hdr` (§4.3).
const REAL_KDF_M_KIB: u32 = 65536;
const REAL_KDF_T_COST: u32 = 3;
const REAL_KDF_P_COST: u32 = 1;

/// Plaintexts the real fixtures encrypt, pinned here so a drift shows up.
const REAL_MID_PLAINTEXT: &[u8] = b"preview: mid=42, size=2048";
const REAL_BODY_PLAINTEXT: &[u8] = b"the real directed v2 body bytes";

/// The password for the real fixtures, derived from a label (never a literal):
/// the generator used the hex encoding of a 16-byte `fill` output.
fn real_password() -> String {
    hex::encode(fill::<16>("real password v2"))
}

/// Derive `pwh` for the real fixtures through the crate, as a sender would.
fn real_pwh() -> [u8; 32] {
    let salt = arr32("real_password_salt_v2");
    let pwh = kdf::password_hash(
        &real_password(),
        &salt,
        REAL_KDF_M_KIB,
        REAL_KDF_T_COST,
        REAL_KDF_P_COST,
    )
    .expect("password_hash within bounds");
    *pwh
}

/// Recipient-side `dh1 ‖ dh2` built from the frozen kex material.
fn real_dr() -> [u8; 64] {
    let dr = kdf::dh_concat_recipient(
        &x_secret("r_static secret"),
        &x_secret("r_eph secret"),
        &arr32("e_s_pub"),
    )
    .expect("recipient dh_concat");
    *dr
}

/// The real envelope opens end to end for the recipient: the DEK wrap yields the
/// frozen DEK, that DEK opens the protected body, and the payload preview opens
/// without a password. This pins "`real_envelope_v2` opens with fixed keys and
/// password" (§8.3).
#[test]
fn real_envelope_v2_opens_for_the_recipient_with_fixed_keys_and_password() {
    let dr = real_dr();
    let pwh = real_pwh();
    let h_hdr = arr32("h_hdr");

    // Open the DEK wrap and recover the frozen DEK.
    let dek = seal::open_wrapped_dek(
        &dr,
        &pwh,
        &h_hdr,
        &arr24("real_dek_nonce_v2"),
        &frozen("real_wrapped_dek_v2"),
    )
    .expect("the real DEK wrap opens for the recipient");
    assert_eq!(&dek[..], &arr32("real_dek_v2")[..]);

    // The recovered DEK opens the protected body (content layer).
    let body = seal::open_content(
        &dek,
        2,
        &arr32("envelope_id"),
        &arr24("real_content_nonce_v2"),
        &frozen("real_protected_v2"),
    )
    .expect("the protected body opens with the recovered DEK");
    assert_eq!(body, REAL_BODY_PLAINTEXT);

    // The preview opens from the key-exchange secret alone (no password).
    let preview = seal::open_payload(
        &dr,
        &h_hdr,
        &arr24("real_payload_nonce_v2"),
        &frozen("real_mid_v2"),
    )
    .expect("the payload preview opens without a password");
    assert_eq!(preview, REAL_MID_PLAINTEXT);
}

/// Forward secrecy: with `r_eph` replaced by an unrelated secret the recipient
/// can no longer form `dh2`, so the wrap key is wrong and the DEK wrap does not
/// open. This pins "`r_eph` を渡さないと開かない" (§8.3).
#[test]
fn real_envelope_v2_stays_closed_without_r_eph() {
    let pwh = real_pwh();
    let h_hdr = arr32("h_hdr");

    // An unrelated ephemeral secret stands in for "r_eph discarded".
    let other_eph = x_secret("unrelated ephemeral for forward secrecy");
    let dr_wrong =
        kdf::dh_concat_recipient(&x_secret("r_static secret"), &other_eph, &arr32("e_s_pub"))
            .expect("recipient dh_concat with the wrong ephemeral still computes");

    assert!(
        seal::open_wrapped_dek(
            &dr_wrong,
            &pwh,
            &h_hdr,
            &arr24("real_dek_nonce_v2"),
            &frozen("real_wrapped_dek_v2"),
        )
        .is_err(),
        "without r_eph the DEK wrap must not open"
    );

    // Sanity: the correct ephemeral still opens it, so the failure above is due
    // to the missing r_eph and not to some other mismatch.
    let dr_ok = real_dr();
    assert!(
        seal::open_wrapped_dek(
            &dr_ok,
            &pwh,
            &h_hdr,
            &arr24("real_dek_nonce_v2"),
            &frozen("real_wrapped_dek_v2"),
        )
        .is_ok(),
        "with the right r_eph the DEK wrap opens"
    );
}
