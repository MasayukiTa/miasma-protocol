//! End-to-end autonomous piece repair on a local multi-node network.
//!
//! A publishes content with k=2, n=3 so that three hosts (B, C, D) each hold one
//! slot. One host is killed. A's maintenance pass must notice, replicate the
//! slot to the spare node E, and rewrite the record without changing k, n or the
//! MID. The proof that the repair is real, not bookkeeping: A and a second host
//! are then shut down as well, leaving exactly one original host plus E, and a
//! fresh node still retrieves the content (k=2 needs both).

use std::{sync::Arc, time::Duration};

use miasma_core::{
    daemon::maintenance_exec::{CoordinatorBackend, MemoryRecordSource, RecordSource},
    network::coordinator::PublishOptions,
    network::types::DhtRecord,
    repair::{
        check_record_update, EvidenceConfig, MaintenanceClock, MaintenanceConfig, MaintenanceCore,
        PieceMaintenanceConfig, SystemClock,
    },
    ContentId, DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaNode, Multiaddr,
    NodeType,
};

async fn spawn_node(
    key_byte: u8,
    hosted_quota_mb: u64,
) -> (MiasmaCoordinator, Arc<LocalShareStore>) {
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Arc::new(
        LocalShareStore::open(&dir, 100)
            .unwrap()
            .with_hosted_quota_mb(hosted_quota_mb),
    );
    let key = [key_byte; 32];
    let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    let listen_addr_str = addrs[0].to_string();
    let coord = MiasmaCoordinator::start(node, store.clone(), vec![listen_addr_str]).await;
    (coord, store)
}

async fn join(joiner: &MiasmaCoordinator, seed: &MiasmaCoordinator) {
    let seed_addr: Multiaddr = seed.listen_addrs()[0].parse().unwrap();
    let seed_id = *seed.peer_id();
    let joiner_id = *joiner.peer_id();
    joiner.add_bootstrap_peer(seed_id, seed_addr).await.unwrap();
    joiner.bootstrap_dht().await.unwrap();
    joiner
        .wait_until_peer_connected(seed_id, Duration::from_secs(10))
        .await
        .unwrap();
    seed.wait_until_peer_connected(joiner_id, Duration::from_secs(10))
        .await
        .unwrap();
}

fn holder_of(record: &DhtRecord, slot: u16) -> Vec<u8> {
    let held: Vec<_> = record
        .locations
        .iter()
        .filter(|l| l.shard_index == slot)
        .collect();
    assert_eq!(held.len(), 1, "slot {slot} must have exactly one location");
    held[0].peer_id_bytes.clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn killed_holder_is_replaced_and_content_survives_without_the_publisher() {
    let result = tokio::time::timeout(Duration::from_secs(150), async {
        let (coord_a, store_a) = spawn_node(0xA7, 0).await;
        let (coord_b, store_b) = spawn_node(0xB7, 50).await;
        let (coord_c, store_c) = spawn_node(0xC7, 50).await;
        let (coord_d, store_d) = spawn_node(0xD7, 50).await;
        let (coord_e, store_e) = spawn_node(0xE7, 50).await;

        for host in [&coord_b, &coord_c, &coord_d, &coord_e] {
            join(host, &coord_a).await;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;

        let params = DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        };
        let content = b"autonomous repair: a lost replica is recreated, k/n and MID untouched";
        let report = coord_a
            .dissolve_and_publish_with_options(content, params, PublishOptions::strict(params))
            .await
            .expect("publish");
        let mid = report.mid;
        assert_eq!(
            report.remote_distinct_shards_per_segment,
            vec![3],
            "precondition: every slot sits on a different remote host"
        );

        let before = coord_a
            .dht_handle()
            .get_record(*mid.as_bytes())
            .await
            .unwrap()
            .expect("record published");
        assert_eq!(before.locations.len(), 3);

        // Which coordinator holds which slot.
        // Four hosts, three slots: placement is randomised, so find out which
        // host is the spare that holds nothing.
        let all = [&coord_b, &coord_c, &coord_d, &coord_e];
        let stores = [&store_b, &store_c, &store_d, &store_e];
        let owner_of = |slot: u16| -> usize {
            let bytes = holder_of(&before, slot);
            all.iter()
                .position(|c| c.peer_id().to_bytes() == bytes)
                .expect("holder is one of the four hosts")
        };
        let (dead_idx, second_idx, survivor_idx) = (owner_of(0), owner_of(1), owner_of(2));
        let spare_idx = (0..all.len())
            .find(|i| ![dead_idx, second_idx, survivor_idx].contains(i))
            .expect("one host holds no slot");
        let spare = all[spare_idx];
        let store_spare = stores[spare_idx];
        assert_eq!(store_spare.used_hosted_bytes(), 0, "the spare starts empty");

        // ── The holder of slot 0 dies. ──────────────────────────────────────
        all[dead_idx].shutdown().await;

        // ── A's maintenance pass. ───────────────────────────────────────────
        let coord_a = Arc::new(coord_a);
        let source = Arc::new(MemoryRecordSource::new(vec![before.clone()]));
        let backend = CoordinatorBackend::new(
            coord_a.clone(),
            store_a.clone(),
            source.clone() as Arc<dyn RecordSource>,
        );
        let cfg = MaintenanceConfig {
            planner: PieceMaintenanceConfig {
                target_replicas_per_slot: 1,
                prefer_distinct_failure_domains: false,
                ..PieceMaintenanceConfig::default()
            },
            evidence: EvidenceConfig {
                max_failures: 1,
                ..EvidenceConfig::default()
            },
            ..MaintenanceConfig::default()
        };
        let clock = SystemClock;
        let mut core = MaintenanceCore::new(cfg, clock.now_secs());
        let tick = core.tick(&backend, clock.now_secs()).await;
        assert_eq!(
            tick.repaired, 1,
            "one slot replica must be repaired: {tick:?}"
        );
        assert_eq!(tick.records_committed, 1, "{tick:?}");
        assert_eq!(tick.invariant_violations, 0);

        // ── Invariants of the rewritten record. ─────────────────────────────
        let after = source.records().pop().expect("record kept");
        check_record_update(&before, &after).expect("legal maintenance rewrite");
        assert_eq!(after.mid_digest, *mid.as_bytes(), "MID unchanged");
        assert_eq!(
            (after.data_shards, after.total_shards),
            (2, 3),
            "k/n unchanged"
        );
        assert_eq!(
            after.locations.len(),
            3,
            "slots preserved, none added or lost"
        );
        assert_eq!(holder_of(&after, 0), spare.peer_id().to_bytes());
        assert_eq!(holder_of(&after, 1), holder_of(&before, 1));
        assert_eq!(holder_of(&after, 2), holder_of(&before, 2));
        assert!(
            after.published_at > before.published_at,
            "the rewritten record must supersede the old one"
        );
        assert!(
            store_spare.used_hosted_bytes() > 0,
            "the spare must now physically hold the pushed share"
        );
        assert_eq!(ContentId::from_digest(after.mid_digest), mid);

        // ── Proof of real durability: one original host + the spare remain. ─
        coord_a.shutdown().await;
        all[second_idx].shutdown().await;
        let survivor = all[survivor_idx];

        let (coord_f, _sf) = spawn_node(0xF7, 0).await;
        for seed in [survivor, spare] {
            let addr: Multiaddr = seed.listen_addrs()[0].parse().unwrap();
            coord_f
                .add_bootstrap_peer(*seed.peer_id(), addr)
                .await
                .unwrap();
        }
        coord_f.bootstrap_dht().await.unwrap();
        for seed in [survivor, spare] {
            coord_f
                .wait_until_peer_connected(*seed.peer_id(), Duration::from_secs(10))
                .await
                .unwrap();
        }
        let recovered = coord_f
            .retrieve_from_network(&mid, params)
            .await
            .expect("retrieval needs the repaired replica on the spare (k=2, two hosts left)");
        assert_eq!(recovered.as_slice(), content as &[u8]);

        for c in [survivor, spare, &coord_f] {
            c.shutdown().await;
        }
    })
    .await;

    result.expect("piece maintenance end-to-end test timed out (150s)");
}
