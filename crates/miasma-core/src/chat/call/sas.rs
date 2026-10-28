//! Derivation of the call short authentication string's raw bits.

use sha2::{Digest, Sha256};

use super::super::crypto::label;

/// Derive 64 SAS bits, independent of the order of the two identities.
///
/// `confirm_tag` is the `confirm_initiator` tag fixed at both ends: the
/// initiator uses its own `confirmation()`, and the responder uses
/// `expected_peer_confirmation()`. Presentation as digits or words and their
/// grouping is the UI's job. The 64 bits meet the requirement of at least
/// about 60 bits.
pub fn sas_bits(
    id_a: &[u8; 32],
    id_b: &[u8; 32],
    confirm_tag: &[u8; 32],
    call_id: &[u8; 16],
    caller_nonce: &[u8; 16],
    callee_nonce: &[u8; 16],
    offer_hash: &[u8; 32],
) -> [u8; 8] {
    let (first, second) = if id_a <= id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut hash = Sha256::new();
    hash.update(label::CALL_SAS);
    hash.update(first);
    hash.update(second);
    hash.update(confirm_tag);
    hash.update(call_id);
    hash.update(caller_nonce);
    hash.update(callee_nonce);
    hash.update(offer_hash);
    let digest = hash.finalize();
    let mut bits = [0u8; 8];
    bits.copy_from_slice(&digest[..8]);
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_order_does_not_matter() {
        let a = [1; 32];
        let b = [2; 32];
        let tag = [3; 32];
        let call = [4; 16];
        let caller = [5; 16];
        let callee = [6; 16];
        let offer = [7; 32];
        assert!(
            sas_bits(&a, &b, &tag, &call, &caller, &callee, &offer)
                == sas_bits(&b, &a, &tag, &call, &caller, &callee, &offer)
        );
    }

    #[test]
    fn every_input_group_affects_output() {
        let mut a = [1; 32];
        let mut b = [2; 32];
        let mut tag = [3; 32];
        let mut call = [4; 16];
        let mut caller = [5; 16];
        let mut callee = [6; 16];
        let mut offer = [7; 32];
        let baseline = sas_bits(&a, &b, &tag, &call, &caller, &callee, &offer);
        macro_rules! check_group {
            ($field:ident) => {{
                $field[0] ^= 1;
                assert!(baseline != sas_bits(&a, &b, &tag, &call, &caller, &callee, &offer));
                $field[0] ^= 1;
            }};
        }
        check_group!(a);
        check_group!(b);
        check_group!(tag);
        check_group!(call);
        check_group!(caller);
        check_group!(callee);
        check_group!(offer);
        // The macro restores each byte; read the last one so that restore is not a dead store.
        assert!(offer == [7; 32]);
    }

    #[test]
    fn matches_independent_construction() {
        let a = [9; 32];
        let b = [1; 32];
        let tag = [3; 32];
        let call = [4; 16];
        let caller = [5; 16];
        let callee = [6; 16];
        let offer = [7; 32];
        let mut input = Vec::new();
        input.extend_from_slice(b"miasma/call/v1/sas");
        input.extend_from_slice(&b);
        input.extend_from_slice(&a);
        input.extend_from_slice(&tag);
        input.extend_from_slice(&call);
        input.extend_from_slice(&caller);
        input.extend_from_slice(&callee);
        input.extend_from_slice(&offer);
        let digest = Sha256::digest(&input);
        let mut expected = [0; 8];
        expected.copy_from_slice(&digest[..8]);
        assert!(sas_bits(&a, &b, &tag, &call, &caller, &callee, &offer) == expected);
    }

    #[test]
    fn random_input_pairs_produce_distinct_eight_byte_outputs() {
        for _ in 0..100 {
            let a: [u8; 32] = rand::random();
            let b: [u8; 32] = rand::random();
            let tag: [u8; 32] = rand::random();
            let call: [u8; 16] = rand::random();
            let caller: [u8; 16] = rand::random();
            let callee: [u8; 16] = rand::random();
            let offer: [u8; 32] = rand::random();
            let mut other_offer = offer;
            other_offer[0] ^= 1;
            let first = sas_bits(&a, &b, &tag, &call, &caller, &callee, &offer);
            let second = sas_bits(&a, &b, &tag, &call, &caller, &callee, &other_offer);
            assert!(first.len() == 8);
            assert!(first != second);
        }
    }
}
