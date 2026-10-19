//! Piece maintenance across a daemon restart, on a local multi-node network.
//!
//! The node's DHT store is in memory only, and the replication queue does not
//! announce a record it already marked `Replicated`. A maintenance pass after a
//! restart therefore finds no local copy of its own record. These tests pin the
//! behaviour that matters then:
//!
//! * the rewritten record is committed (and persisted in the queue) anyway;
//! * a later pass after another restart does not push the same share again;
//! * a record that is not this node's own costs no traffic at all.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use miasma_core::{
    daemon::{
        maintenance_exec::{
            CoordinatorBackend, MemoryRecordSource, QueueRecordSource, RecordSource,
        },
        replication::{PendingReplication, ReplicationQueue},
    },
    network::coordinator::PublishOptions,
    network::types::DhtRecord,
    repair::{
        EvidenceConfig, MaintenanceClock, MaintenanceConfig, MaintenanceCore,
        PieceMaintenanceConfig, SystemClock,
    },
    DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaNode, Multiaddr, NodeType,
};

fn new_store(hosted_quota_mb: u64) -> Arc<LocalShareStore> {
    let dir = tempfile::tempdir().unwrap().keep();
    Arc::new(
        LocalShareStore::open(&dir, 100)
            .unwrap()
            .with_hosted_quota_mb(hosted_quota_mb),
    )
}

async fn spawn_node_with(key_byte: u8, store: Arc<LocalShareStore>) -> MiasmaCoordinator {
    let key = [key_byte; 32];
    let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    let listen_addr_str = addrs[0].to_string();
    MiasmaCoordinator::start(node, store, vec![listen_addr_str]).await
}

async fn spawn_node(
    key_byte: u8,
    hosted_quota_mb: u64,
) -> (MiasmaCoordinator, Arc<LocalShareStore>) {
    let store = new_store(hosted_quota_mb);
    (spawn_node_with(key_byte, store.clone()).await, store)
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

fn config() -> MaintenanceConfig {
    MaintenanceConfig {
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
    }
}

const PARAMS: DissolutionParams = DissolutionParams {
    data_shards: 2,
    total_shards: 3,
};

#[tokio::test(flavor = "multi_thread")]
async fn repair_after_a_restart_is_committed_and_not_repeated_by_the_next_restart() {
    let result = tokio::time::timeout(Duration::from_secs(240), async {
        let (coord_a, store_a) = spawn_node(0xA8, 0).await;
        let (coord_b, _sb) = spawn_node(0xB8, 50).await;
        let (coord_c, _sc) = spawn_node(0xC8, 50).await;
        let (coord_d, _sd) = spawn_node(0xD8, 50).await;
        let (coord_e, _se) = spawn_node(0xE8, 50).await;
        for host in [&coord_b, &coord_c, &coord_d, &coord_e] {
            join(host, &coord_a).await;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;

        let content = b"a repair that survives two restarts is committed exactly once";
        let report = coord_a
            .dissolve_and_publish_with_options(content, PARAMS, PublishOptions::strict(PARAMS))
            .await
            .expect("publish");
        let digest = *report.mid.as_bytes();
        assert_eq!(report.remote_distinct_shards_per_segment, vec![3]);
        let before = coord_a
            .dht_handle()
            .get_record(digest)
            .await
            .unwrap()
            .expect("record published");

        // The steady state of a published item: announced and acknowledged.
        let queue_dir = tempfile::tempdir().unwrap();
        {
            let mut q = ReplicationQueue::load_or_create(queue_dir.path()).unwrap();
            q.push(PendingReplication::new(report.mid.to_string(), before.clone()))
                .unwrap();
            q.mark_replicated(&digest).unwrap();
        }

        let all = [&coord_b, &coord_c, &coord_d, &coord_e];
        let owner_of = |slot: u16| -> usize {
            let bytes = holder_of(&before, slot);
            all.iter()
                .position(|c| c.peer_id().to_bytes() == bytes)
                .expect("holder is one of the four hosts")
        };
        let (dead_idx, second_idx, third_idx) = (owner_of(0), owner_of(1), owner_of(2));
        let spare_idx = (0..all.len())
            .find(|i| ![dead_idx, second_idx, third_idx].contains(i))
            .expect("one host holds no slot");
        let live: Vec<&MiasmaCoordinator> = (0..all.len())
            .filter(|i| *i != dead_idx)
            .map(|i| all[i])
            .collect();
        all[dead_idx].shutdown().await;

        // ── Restart 1: the daemon comes back with an empty DHT store. ───────
        coord_a.shutdown().await;
        drop(coord_a);
        let coord_a1 = Arc::new(spawn_node_with(0xA8, store_a.clone()).await);
        for host in &live {
            join(&coord_a1, host).await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            coord_a1
                .dht_handle()
                .local_record_value(digest)
                .await
                .is_none(),
            "precondition: nothing refilled the restarted node's DHT store"
        );

        let clock = SystemClock;
        let tick1 = {
            let queue = Arc::new(Mutex::new(
                ReplicationQueue::load_or_create(queue_dir.path()).unwrap(),
            ));
            let backend = CoordinatorBackend::new(
                coord_a1.clone(),
                store_a.clone(),
                Arc::new(QueueRecordSource(queue)) as Arc<dyn RecordSource>,
            );
            let mut core = MaintenanceCore::new(config(), clock.now_secs());
            core.tick(&backend, clock.now_secs()).await
        };

        // ── Restart 2: again an empty DHT store and a fresh executor. ───────
        coord_a1.shutdown().await;
        drop(coord_a1);
        let coord_a2 = Arc::new(spawn_node_with(0xA8, store_a.clone()).await);
        for host in &live {
            join(&coord_a2, host).await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let (tick2, persisted) = {
            let queue = Arc::new(Mutex::new(
                ReplicationQueue::load_or_create(queue_dir.path()).unwrap(),
            ));
            let persisted = queue
                .lock()
                .unwrap()
                .get(&digest)
                .map(|i| i.record.clone())
                .expect("item kept");
            let backend = CoordinatorBackend::new(
                coord_a2.clone(),
                store_a.clone(),
                Arc::new(QueueRecordSource(queue)) as Arc<dyn RecordSource>,
            );
            let mut core = MaintenanceCore::new(config(), clock.now_secs());
            (core.tick(&backend, clock.now_secs()).await, persisted)
        };

        let spare_bytes = all[spare_idx].peer_id().to_bytes();
        let committed = tick1.repaired == 1
            && tick1.records_committed == 1
            && tick1.commit_failures == 0
            && persisted.locations.len() == 3
            && persisted
                .locations
                .iter()
                .any(|l| l.shard_index == 0 && l.peer_id_bytes == spare_bytes)
            && persisted.published_at > before.published_at;
        let not_repeated = tick2.repaired == 0 && tick2.failed == 0 && tick2.commit_failures == 0;
        assert!(
            committed && not_repeated,
            "committed={committed} not_repeated={not_repeated}\n tick1={tick1:?}\n tick2={tick2:?}\n \
             persisted locations={:?}",
            persisted
                .locations
                .iter()
                .map(|l| (l.shard_index, l.peer_id_bytes.len()))
                .collect::<Vec<_>>()
        );

        coord_a2.shutdown().await;
        for c in live {
            c.shutdown().await;
        }
    })
    .await;
    result.expect("restart maintenance test timed out (240s)");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_signed_by_another_node_costs_no_probe_and_no_push() {
    let result = tokio::time::timeout(Duration::from_secs(240), async {
        // P publishes; M (the maintainer) merely holds P's record as a DHT node.
        let (coord_m, store_m) = spawn_node(0xA9, 0).await;
        let (coord_p, _sp) = spawn_node(0xB9, 0).await;
        let hosts = [
            spawn_node(0xC9, 50).await,
            spawn_node(0xD9, 50).await,
            spawn_node(0xE9, 50).await,
            spawn_node(0xF9, 50).await,
        ];
        join(&coord_p, &coord_m).await;
        for (h, _) in &hosts {
            join(h, &coord_m).await;
            join(h, &coord_p).await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let report = coord_p
            .dissolve_and_publish_with_options(
                b"someone else's content",
                PARAMS,
                PublishOptions::strict(PARAMS),
            )
            .await
            .expect("publish");
        let digest = *report.mid.as_bytes();
        let foreign = coord_p
            .dht_handle()
            .get_record(digest)
            .await
            .unwrap()
            .expect("record published");

        // M must hold P's signed record locally.
        let mut held = false;
        for _ in 0..60 {
            if coord_m
                .dht_handle()
                .local_record_value(digest)
                .await
                .is_some()
            {
                held = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(held, "precondition: M stores P's record");

        // Placement is random and the maintainer M can be a holder itself, so
        // pick a holder that is one of the plain hosts.
        let dead = hosts
            .iter()
            .find(|(h, _)| {
                foreign
                    .locations
                    .iter()
                    .any(|l| l.peer_id_bytes == h.peer_id().to_bytes())
            })
            .expect("at least one holder is one of the hosts");
        dead.0.shutdown().await;

        let coord_m = Arc::new(coord_m);
        let backend = CoordinatorBackend::new(
            coord_m.clone(),
            store_m.clone(),
            Arc::new(MemoryRecordSource::new(vec![foreign.clone()])) as Arc<dyn RecordSource>,
        );
        let clock = SystemClock;
        let mut core = MaintenanceCore::new(config(), clock.now_secs());
        let tick = core.tick(&backend, clock.now_secs()).await;

        assert!(
            tick.repaired == 0 && tick.failed == 0 && tick.commit_failures == 0,
            "a record this node did not publish must not be touched: {tick:?}"
        );
        assert_eq!(tick.probes, 0, "{tick:?}");

        coord_m.shutdown().await;
        coord_p.shutdown().await;
        for (h, _) in &hosts {
            h.shutdown().await;
        }
    })
    .await;
    result.expect("foreign record maintenance test timed out (240s)");
}
