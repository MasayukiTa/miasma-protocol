//! Regression tests for the hosted-share findings of the 2026-09 adversarial
//! review (C-03 cross-publisher replacement, C-08 one peer squatting the whole
//! hosted quota). Each test drives the real `LocalShareStore` and asserts that
//! the attack now FAILS.
//!
//! Principals are the authenticated peer ids the network layer passes to the
//! store; here they are random strings generated at run time.

use miasma_core::{
    pipeline::{dissolve, DissolutionParams},
    share::ShareVerification,
    store::{HostedPutError, HostedRefusal},
    LocalShareStore, MiasmaShare,
};

fn principal() -> String {
    format!("peer-{:032x}", rand::random::<u128>())
}

fn one_shard() -> DissolutionParams {
    DissolutionParams {
        data_shards: 1,
        total_shards: 1,
    }
}

/// A share that passes `self_consistent` and claims the same public routing
/// tuple as `victim` but is not derived from the victim's content.
fn forged_same_tuple(victim: &MiasmaShare) -> MiasmaShare {
    let mut forged = victim.clone();
    forged.shard_data[0] ^= 0x5a;
    forged.shard_hash = *blake3::hash(&forged.shard_data).as_bytes();
    forged.key_share[0] ^= 0xa5;
    assert!(ShareVerification::self_consistent(&forged));
    forged
}

fn refusal(r: Result<String, HostedPutError>) -> HostedRefusal {
    match r {
        Err(HostedPutError::Refused(reason)) => reason,
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

fn victim_share() -> MiasmaShare {
    let (_mid, shares) = dissolve(
        format!("victim content {}", rand::random::<u64>()).as_bytes(),
        DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        },
    )
    .unwrap();
    shares[0].clone()
}

#[test]
fn a_different_principal_cannot_replace_or_evict_a_hosted_share() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(10);
    let publisher = principal();
    let attacker = principal();

    let genuine = victim_share();
    let genuine_addr = store.put_hosted_by(&genuine, &publisher).unwrap();
    let used_before = store.used_hosted_bytes();

    let forged = forged_same_tuple(&genuine);
    let reason = refusal(store.put_hosted_by(&forged, &attacker));
    assert_eq!(reason, HostedRefusal::NotOwner);

    // Not evicted, not replaced, not stored.
    let served = store.get_untouched(&genuine_addr).unwrap();
    assert_eq!(served.shard_hash, genuine.shard_hash);
    assert_eq!(
        store.find_piece(
            &genuine.mid_prefix,
            genuine.segment_index,
            genuine.slot_index
        ),
        Some(genuine_addr.clone())
    );
    assert_eq!(store.used_hosted_bytes(), used_before);
    let forged_addr = LocalShareStore::address_of(&forged).unwrap();
    assert!(store.get_untouched(&forged_addr).is_err());
}

#[test]
fn an_unknown_principal_neither_replaces_nor_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(10);
    let publisher = principal();

    let genuine = victim_share();
    let addr = store.put_hosted_by(&genuine, &publisher).unwrap();
    // A push without a principal (the legacy entry point) cannot take a slot
    // that a known principal holds ...
    let forged = forged_same_tuple(&genuine);
    assert!(store.put_hosted(&forged).is_err());
    assert!(store.get_untouched(&addr).is_ok());

    // ... and an entry of unknown owner cannot be claimed by a known one.
    let other = victim_share();
    let legacy_addr = store.put_hosted(&other).unwrap();
    let claim = forged_same_tuple(&other);
    assert_eq!(
        refusal(store.put_hosted_by(&claim, &publisher)),
        HostedRefusal::NotOwner
    );
    assert!(store.get_untouched(&legacy_addr).is_ok());
}

#[test]
fn the_same_principal_can_republish_a_newer_generation() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(10);
    let publisher = principal();

    let first = victim_share();
    let first_addr = store.put_hosted_by(&first, &publisher).unwrap();
    let used_one = store.used_hosted_bytes();

    let second = forged_same_tuple(&first); // same tuple, different bytes
    let second_addr = store.put_hosted_by(&second, &publisher).unwrap();
    assert_ne!(first_addr, second_addr);

    assert!(store.get_untouched(&first_addr).is_err());
    assert_eq!(
        store.find_piece(&first.mid_prefix, first.segment_index, first.slot_index),
        Some(second_addr.clone())
    );
    assert_eq!(
        store.get_untouched(&second_addr).unwrap().shard_hash,
        second.shard_hash
    );
    // The old generation's bytes were released, not added to.
    assert_eq!(store.used_hosted_bytes(), used_one);

    // Re-pushing identical bytes is idempotent.
    assert_eq!(
        store.put_hosted_by(&second, &publisher).unwrap(),
        second_addr
    );
}

#[test]
fn pushing_identical_bytes_does_not_transfer_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(10);
    let owner = principal();
    let copycat = principal();

    let genuine = victim_share();
    let addr = store.put_hosted_by(&genuine, &owner).unwrap();
    assert_eq!(store.put_hosted_by(&genuine, &copycat).unwrap(), addr);

    // The copycat did not become the owner: it still cannot replace, the owner still can.
    let newer = forged_same_tuple(&genuine);
    assert_eq!(
        refusal(store.put_hosted_by(&newer, &copycat)),
        HostedRefusal::NotOwner
    );
    store.put_hosted_by(&newer, &owner).unwrap();
}

#[test]
fn one_principal_is_stopped_at_its_budget_while_another_can_still_store() {
    let dir = tempfile::tempdir().unwrap();
    let quota_mb = 64u64;
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(quota_mb);
    let budget = store.hosted_principal_budget_bytes();
    let quota = store.hosted_quota_bytes();
    assert!(budget < quota, "the budget must leave room for others");

    let squatter = principal();
    let mut accepted = 0u32;
    let last_refusal = loop {
        let payload = vec![(accepted & 0xff) as u8; 1024 * 1024];
        let (_mid, mut shares) = dissolve(&payload, one_shard()).unwrap();
        shares[0].segment_index = accepted;
        match store.put_hosted_by(&shares[0], &squatter) {
            Ok(_) => accepted += 1,
            Err(e) => break refusal(Err(e)),
        }
        assert!(accepted < 200, "the budget did not stop the squatter");
    };
    assert_eq!(last_refusal, HostedRefusal::PrincipalBudgetExceeded);
    assert!(accepted > 0);
    assert!(store.used_hosted_bytes() <= budget);
    assert!(store.used_hosted_bytes() < quota);

    // A different principal is unaffected.
    let (_mid, victim) = dissolve(&vec![0xEEu8; 1024 * 1024], one_shard()).unwrap();
    store
        .put_hosted_by(&victim[0], &principal())
        .expect("another principal can still store");
}

#[test]
fn unknown_owners_share_one_budget_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(64);
    let budget = store.hosted_principal_budget_bytes();

    let mut accepted = 0u32;
    loop {
        let (_mid, mut shares) =
            dissolve(&vec![(accepted & 0xff) as u8; 1024 * 1024], one_shard()).unwrap();
        shares[0].segment_index = accepted;
        match store.put_hosted(&shares[0]) {
            Ok(_) => accepted += 1,
            Err(_) => break,
        }
        assert!(accepted < 200);
    }
    assert!(store.used_hosted_bytes() <= budget);
    assert!(store.used_hosted_bytes() < store.hosted_quota_bytes());
}

#[test]
fn a_small_quota_stays_usable_by_one_principal() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(2);
    // The floor is min(quota, 16 MiB): a small quota is not divided down to nothing.
    assert_eq!(
        store.hosted_principal_budget_bytes(),
        store.hosted_quota_bytes()
    );
    store.put_hosted_by(&victim_share(), &principal()).unwrap();
}

#[test]
fn the_default_hosted_quota_still_refuses_everything() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100).unwrap();
    assert_eq!(store.hosted_quota_bytes(), 0);
    assert_eq!(
        refusal(store.put_hosted_by(&victim_share(), &principal())),
        HostedRefusal::QuotaExceeded
    );
}

#[test]
fn an_index_written_before_principals_existed_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let genuine = victim_share();
    let addr;
    {
        let store = LocalShareStore::open(dir.path(), 100)
            .unwrap()
            .with_hosted_quota_mb(10);
        addr = store.put_hosted_by(&genuine, &principal()).unwrap();
    }

    // Rewrite the index the way an older build wrote it: no principal field.
    let index_path = dir.path().join("store_index.json");
    let mut index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&index_path).unwrap()).unwrap();
    let mut stripped = 0;
    for entry in index.as_object_mut().unwrap().values_mut() {
        if entry
            .as_object_mut()
            .unwrap()
            .remove("hosted_principal")
            .is_some()
        {
            stripped += 1;
        }
    }
    assert_eq!(stripped, 1);
    std::fs::write(&index_path, serde_json::to_string(&index).unwrap()).unwrap();

    let store = LocalShareStore::open(dir.path(), 100)
        .unwrap()
        .with_hosted_quota_mb(10);
    assert!(
        store.used_hosted_bytes() > 0,
        "the legacy entry must still be indexed"
    );
    assert_eq!(
        store.find_piece(
            &genuine.mid_prefix,
            genuine.segment_index,
            genuine.slot_index
        ),
        Some(addr.clone())
    );
    assert_eq!(
        store.get_untouched(&addr).unwrap().shard_hash,
        genuine.shard_hash
    );

    // Its owner is unknown: nobody can replace it by claiming the tuple.
    let forged = forged_same_tuple(&genuine);
    assert_eq!(
        refusal(store.put_hosted_by(&forged, &principal())),
        HostedRefusal::NotOwner
    );
    assert!(store.get_untouched(&addr).is_ok());
}
