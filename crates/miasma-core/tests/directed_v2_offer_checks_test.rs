//! Directed share v2 — sender-side offer checks (§3.4, §8.3).
//!
//! `offer::check_offer` runs the pure sender checks in order: suite, request
//! echo, recipient-identity PeerId, sharing-key binding, sharing-key match, and
//! finally the offer signature. These integration tests change one offer field
//! (or one piece of the sender's expectation) at a time and assert the matching
//! `OfferReject`. The §8.3 case singled out here is that a `recipient_sharing`
//! that differs from the contact returns `KeyMismatch`.
//!
//! No literal keys, nonces or salts appear below: identity keys come from
//! `SigningKey::from_bytes(&rand::random())`, every other secret-shaped value is
//! `rand::random()`, and each binding is produced by signing it correctly with
//! `credential::sign_binding`.

use miasma_core::directed::v2::credential;
use miasma_core::directed::v2::offer::{
    check_offer, sign_offer, OfferFields, OfferReject, SenderExpectation,
};

use ed25519_dalek::SigningKey;

/// Everything a correct offer and a matching sender expectation are built from.
///
/// Byte strings used as PeerIds (`requester`) are random; the sender
/// expectation compares them by value, which is all `check_offer` does.
struct Fixture {
    recipient_sk: SigningKey,
    offer_id: [u8; 16],
    request_id: [u8; 16],
    requester: Vec<u8>,
    recipient_identity: [u8; 32],
    recipient_sharing: [u8; 32],
    recipient_binding: [u8; 64],
    recipient_ephemeral: [u8; 32],
    ttl_secs: u32,
}

fn fixture() -> Fixture {
    let recipient_sk = SigningKey::from_bytes(&rand::random());
    let recipient_identity = recipient_sk.verifying_key().to_bytes();
    let recipient_sharing: [u8; 32] = rand::random();
    // A correct binding over (identity, sharing) via the public credential API.
    let recipient_binding = credential::sign_binding(&recipient_sk, &recipient_sharing);
    Fixture {
        recipient_sk,
        offer_id: rand::random(),
        request_id: rand::random(),
        // PeerId-shaped bytes; the exact length does not matter to the checks.
        requester: rand::random::<[u8; 38]>().to_vec(),
        recipient_identity,
        recipient_sharing,
        recipient_binding,
        recipient_ephemeral: rand::random(),
        ttl_secs: rand::random(),
    }
}

impl Fixture {
    /// The offer fields exactly as the recipient would send them.
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

    /// A sender expectation that accepts the fields above.
    ///
    /// A single random byte string stands in for the agreed PeerId: both the
    /// contact and the identity-derived PeerId equal it, so check 3 passes.
    fn expectation<'a>(&'a self, suites: &'a [u8]) -> SenderExpectation<'a> {
        SenderExpectation {
            requested_suites: suites,
            request_id: &self.request_id,
            own_requester: &self.requester,
            contact_peer_id: &self.requester,
            contact_sharing: &self.recipient_sharing,
            recipient_identity_peer_id: &self.requester,
        }
    }
}

#[test]
fn a_correct_offer_passes_every_sender_check() {
    let fx = fixture();
    let f = fx.fields();
    let sig = sign_offer(&fx.recipient_sk, &f);
    let suites = [2u8];
    assert_eq!(check_offer(&f, &sig, &fx.expectation(&suites)), Ok(()));
}

#[test]
fn a_suite_the_sender_did_not_request_is_unsupported_suite() {
    let fx = fixture();
    let f = fx.fields();
    let sig = sign_offer(&fx.recipient_sk, &f);
    // The offer advertises suite 2; the sender only asked for suite 9.
    let suites = [9u8];
    assert_eq!(
        check_offer(&f, &sig, &fx.expectation(&suites)),
        Err(OfferReject::UnsupportedSuite)
    );
}

#[test]
fn a_request_id_that_does_not_echo_the_request_is_peer_mismatch() {
    let fx = fixture();
    // Change the offer's request_id; sign over the changed fields so the
    // signature is valid and the request echo is the first thing that fails.
    let other_request_id: [u8; 16] = rand::random();
    let tampered = OfferFields {
        request_id: &other_request_id,
        ..fx.fields()
    };
    let sig = sign_offer(&fx.recipient_sk, &tampered);
    let suites = [2u8];
    assert_eq!(
        check_offer(&tampered, &sig, &fx.expectation(&suites)),
        Err(OfferReject::PeerMismatch)
    );
}

#[test]
fn a_requester_that_does_not_echo_the_request_is_peer_mismatch() {
    let fx = fixture();
    let other_requester = rand::random::<[u8; 38]>().to_vec();
    let tampered = OfferFields {
        requester: &other_requester,
        ..fx.fields()
    };
    let sig = sign_offer(&fx.recipient_sk, &tampered);
    let suites = [2u8];
    assert_eq!(
        check_offer(&tampered, &sig, &fx.expectation(&suites)),
        Err(OfferReject::PeerMismatch)
    );
}

#[test]
fn a_recipient_identity_peer_id_that_differs_from_the_contact_is_identity_mismatch() {
    let fx = fixture();
    let f = fx.fields();
    let sig = sign_offer(&fx.recipient_sk, &f);
    let suites = [2u8];
    // The identity-derived PeerId the caller computed does not equal the
    // contact's PeerId, so check 3 fails before binding or signature.
    let other_peer_id = rand::random::<[u8; 38]>().to_vec();
    let mut exp = fx.expectation(&suites);
    exp.recipient_identity_peer_id = &other_peer_id;
    assert_eq!(
        check_offer(&f, &sig, &exp),
        Err(OfferReject::IdentityMismatch)
    );
}

#[test]
fn a_recipient_binding_that_does_not_verify_is_bad_binding() {
    let fx = fixture();
    // Flip one byte of the otherwise-correct binding so it no longer verifies.
    let mut bad_binding = fx.recipient_binding;
    bad_binding[0] ^= 0x01;
    let tampered = OfferFields {
        recipient_binding: &bad_binding,
        ..fx.fields()
    };
    // Sign over the changed fields so the signature itself is valid and the
    // binding is the first check that fails.
    let sig = sign_offer(&fx.recipient_sk, &tampered);
    let suites = [2u8];
    assert_eq!(
        check_offer(&tampered, &sig, &fx.expectation(&suites)),
        Err(OfferReject::BadBinding)
    );
}

#[test]
fn a_sharing_key_that_differs_from_the_contact_is_key_mismatch() {
    let fx = fixture();
    // The recipient advertises a different sharing key, correctly bound to its
    // identity, but the contact the sender holds carries the original key.
    let other_sharing: [u8; 32] = rand::random();
    let other_binding = credential::sign_binding(&fx.recipient_sk, &other_sharing);
    let tampered = OfferFields {
        recipient_sharing: &other_sharing,
        recipient_binding: &other_binding,
        ..fx.fields()
    };
    let sig = sign_offer(&fx.recipient_sk, &tampered);
    let suites = [2u8];
    // expectation.contact_sharing stays the original fx.recipient_sharing.
    assert_eq!(
        check_offer(&tampered, &sig, &fx.expectation(&suites)),
        Err(OfferReject::KeyMismatch)
    );
}

#[test]
fn a_recipient_ephemeral_change_breaks_the_offer_signature() {
    let fx = fixture();
    let f = fx.fields();
    // Sign over the original fields, then present a changed ephemeral. This
    // field is not inspected by an earlier check, so the signature is where the
    // tamper is caught.
    let sig = sign_offer(&fx.recipient_sk, &f);
    let mut eph = fx.recipient_ephemeral;
    eph[0] ^= 0x01;
    let tampered = OfferFields {
        recipient_ephemeral: &eph,
        ..f
    };
    let suites = [2u8];
    assert_eq!(
        check_offer(&tampered, &sig, &fx.expectation(&suites)),
        Err(OfferReject::BadSignature)
    );
}

#[test]
fn a_ttl_change_breaks_the_offer_signature() {
    let fx = fixture();
    let f = fx.fields();
    let sig = sign_offer(&fx.recipient_sk, &f);
    // ttl_secs is advisory and not inspected by an earlier check, so a change
    // after signing is caught by the signature.
    let tampered = OfferFields {
        ttl_secs: fx.ttl_secs.wrapping_add(1),
        ..f
    };
    let suites = [2u8];
    assert_eq!(
        check_offer(&tampered, &sig, &fx.expectation(&suites)),
        Err(OfferReject::BadSignature)
    );
}

#[test]
fn a_tampered_signature_is_bad_signature() {
    let fx = fixture();
    let f = fx.fields();
    let mut sig = sign_offer(&fx.recipient_sk, &f);
    sig[0] ^= 0x01;
    let suites = [2u8];
    assert_eq!(
        check_offer(&f, &sig, &fx.expectation(&suites)),
        Err(OfferReject::BadSignature)
    );
}
