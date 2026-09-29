//! Protected, resumable large-file transfer.
//!
//! See `docs/tasks/protected-resumable-transfer-plan.md` for the design and the
//! phase plan. This module is deliberately self-contained so that the shared
//! daemon/IPC/CLI files only need a variant and a dispatch call to use it.
//!
//! * [`protection`] — password as an encryption factor (Argon2id → HKDF).
//! * [`manifest`] — the per-piece index that travels with the DHT record.
//! * [`receive`] — the verified, resumable receive engine.
//! * [`progress`] — live status of a transfer.
//! * [`journal`] — the small file that lets a stopped transfer resume.

pub mod bench;
pub mod jobs;
pub mod journal;
pub mod manifest;
pub mod network;
pub mod progress;
pub mod protection;
pub mod publish;
pub mod publish_journal;
pub mod receive;

pub use manifest::{
    decode_record_value, encode_record_value, PieceId, SegmentEntry, TransferManifest,
};
pub use progress::{Phase, TransferKind, TransferProgress, TransferState, TransferStatus};
pub use protection::{PasswordProtection, Protection, UnlockedKey};
pub use receive::{run_receive, PieceSource, ReceiveOutcome, ReceiveSpec, RetryConfig};

#[cfg(test)]
mod receive_tests;

#[cfg(test)]
mod tests {
    //! End-to-end checks of the primitives together: a password-protected
    //! segment round trip with the manifest built from the real shares.
    use super::*;
    use crate::{
        crypto::hash::ContentId,
        dissolution::segment::{dissolve_segment_with, retrieve_segment, retrieve_segment_with},
        dissolution::SegmentMeta,
        pipeline::DissolutionParams,
        MiasmaError,
    };

    fn params(k: usize, n: usize) -> DissolutionParams {
        DissolutionParams {
            data_shards: k,
            total_shards: n,
        }
    }

    fn meta(len: usize, index: u32, n: usize) -> SegmentMeta {
        SegmentMeta {
            index,
            offset_bytes: 0,
            plaintext_len: len as u32,
            share_count: n as u16,
        }
    }

    const PLAIN: &[u8] = b"the quick brown fox jumps over the lazy dog, repeatedly and at length";

    #[test]
    fn a_protected_segment_round_trips_with_the_right_password() {
        let p = params(4, 6);
        let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
        let pw = protection::random_test_password();
        let (prot, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, Some(&key)).unwrap();

        let unlocked = prot.unlock(&pw).unwrap();
        let out = retrieve_segment_with(&mid, &shares, &m, p, Some(&unlocked)).unwrap();
        assert_eq!(out, PLAIN);
    }

    #[test]
    fn a_protected_segment_is_unreadable_with_the_mid_and_every_shard_but_no_password() {
        let p = params(4, 6);
        let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
        let pw = protection::random_test_password();
        let (_, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, Some(&key)).unwrap();

        // The plain retrieval path: MID + all shards, no password.
        let err = retrieve_segment(&mid, &shares, &m, p).unwrap_err();
        assert!(matches!(err, MiasmaError::Decryption(_)), "got {err:?}");
    }

    #[test]
    fn a_key_from_a_different_password_does_not_decrypt() {
        let p = params(4, 6);
        let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
        let right_pw = protection::random_test_password();
        let wrong_pw = protection::random_test_password();
        let (_, key) = PasswordProtection::create_with_cost(&right_pw, 64, 1, 1).unwrap();
        let (_, wrong) = PasswordProtection::create_with_cost(&wrong_pw, 64, 1, 1).unwrap();
        let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, Some(&key)).unwrap();
        assert!(retrieve_segment_with(&mid, &shares, &m, p, Some(&wrong)).is_err());
    }

    #[test]
    fn a_protected_segment_cannot_be_replayed_as_another_segment_index() {
        // Same key, same shares, claimed to be segment 1: the HKDF info binds the
        // index, so the derived AES key differs and decryption fails.
        let p = params(4, 6);
        let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
        let pw = protection::random_test_password();
        let (_, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        let (_, mut shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, Some(&key)).unwrap();
        for s in &mut shares {
            s.segment_index = 1;
        }
        let replay = meta(PLAIN.len(), 1, 6);
        assert!(retrieve_segment_with(&mid, &shares, &replay, p, Some(&key)).is_err());
    }

    #[test]
    fn an_unprotected_segment_is_unchanged_by_this_work() {
        // `password_key == None` must be exactly the pre-existing behaviour.
        let p = params(4, 6);
        let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
        let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, None).unwrap();
        assert_eq!(retrieve_segment(&mid, &shares, &m, p).unwrap(), PLAIN);
        assert_eq!(
            retrieve_segment_with(&mid, &shares, &m, p, None).unwrap(),
            PLAIN
        );
        // ...and giving it a password that was never used breaks it, as it should.
        let pw = protection::random_test_password();
        let (_, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        assert!(retrieve_segment_with(&mid, &shares, &m, p, Some(&key)).is_err());
    }

    #[test]
    fn redundancy_presets_all_round_trip_including_no_parity() {
        // (k, n): 1.0x, 1.1x, 1.2x, 1.5x, 2.0x of a k=10 split.
        for (k, n) in [(10, 10), (10, 11), (10, 12), (10, 15), (10, 20)] {
            let p = params(k, n);
            let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
            let pw = protection::random_test_password();
            let (prot, key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
            let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, Some(&key)).unwrap();
            assert_eq!(shares.len(), n, "k={k} n={n}");

            let unlocked = prot.unlock(&pw).unwrap();
            let out = retrieve_segment_with(&mid, &shares, &m, p, Some(&unlocked)).unwrap();
            assert_eq!(out, PLAIN, "k={k} n={n}");
        }
    }

    #[test]
    fn loss_tolerance_is_exactly_n_minus_k() {
        for (k, n) in [(10, 10), (10, 11), (10, 12), (10, 15), (10, 20)] {
            let p = params(k, n);
            let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
            let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, None).unwrap();

            // Losing n-k shards is survivable: keep the *last* k (all parity
            // first where there is any) so recovery, not the fast path, runs.
            let keep: Vec<_> = shares[n - k..].to_vec();
            assert_eq!(
                retrieve_segment(&mid, &keep, &m, p).unwrap(),
                PLAIN,
                "k={k} n={n}: losing n-k must be survivable"
            );

            // Losing one more must fail cleanly, not panic or return junk.
            let too_few: Vec<_> = shares[n - k + 1..].to_vec();
            assert!(
                matches!(
                    retrieve_segment(&mid, &too_few, &m, p),
                    Err(MiasmaError::InsufficientShares { .. })
                ),
                "k={k} n={n}: losing n-k+1 must be InsufficientShares"
            );
        }
    }

    #[test]
    fn no_parity_split_needs_every_shard() {
        let p = params(10, 10);
        let mid = ContentId::compute(PLAIN, &p.to_param_bytes());
        let (m, shares) = dissolve_segment_with(PLAIN, &mid, 0, 0, p, None).unwrap();
        assert_eq!(shares.len(), 10);
        // Shuffled order is fine; a missing shard is not.
        let mut all = shares.clone();
        all.reverse();
        assert_eq!(retrieve_segment(&mid, &all, &m, p).unwrap(), PLAIN);
        assert!(retrieve_segment(&mid, &shares[..9], &m, p).is_err());
    }
}
