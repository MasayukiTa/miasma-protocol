//! Content published with the streaming file path is kept up like any other
//! publish: its record is in the persistent replication queue, so autonomous
//! piece maintenance repairs a lost replica of it, and still does so after the
//! daemon restarted.
//!
//! A daemon publishes a password-protected file through the transfer job
//! interface (the streaming path) on a local network of four hosts. The
//! daemon stops, the holder of one slot dies, and a restarted node (same key,
//! same store, empty in-memory DHT store) runs one maintenance pass over the
//! queue the daemon left behind. One slot must be repaired; k, n, the MID and
//! the protection recorded in the manifest must be unchanged; a second restart
//! must not repeat the repair.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use miasma_core::{
    daemon::{
        ipc::{daemon_request, ControlRequest, ControlResponse},
        maintenance_exec::{CoordinatorBackend, QueueRecordSource, RecordSource},
        replication::ReplicationQueue,
        DaemonServer,
    },
    network::types::DhtRecord,
    repair::{
        check_record_update, EvidenceConfig, MaintenanceClock, MaintenanceConfig, MaintenanceCore,
        PieceMaintenanceConfig, SystemClock,
    },
    transfer::{open_signed_record, TransferState, TransferStatus},
    ContentId, LocalShareStore, MiasmaCoordinator, MiasmaNode, Multiaddr, NodeType,
};

fn new_hosted_store(hosted_quota_mb: u64) -> Arc<LocalShareStore> {
    let dir = tempfile::tempdir().unwrap().keep();
    Arc::new(
        LocalShareStore::open(&dir, 100)
            .unwrap()
            .with_hosted_quota_mb(hosted_quota_mb),
    )
}

async fn spawn_node_with(key: [u8; 32], store: Arc<LocalShareStore>) -> MiasmaCoordinator {
    let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    MiasmaCoordinator::start(node, store, vec![addrs[0].to_string()]).await
}

async fn join(joiner: &MiasmaCoordinator, seed: &MiasmaCoordinator) {
    let seed_addr: Multiaddr = seed.listen_addrs()[0].parse().unwrap();
    joiner
        .add_bootstrap_peer(*seed.peer_id(), seed_addr)
        .await
        .unwrap();
    joiner.bootstrap_dht().await.unwrap();
    joiner
        .wait_until_peer_connected(*seed.peer_id(), Duration::from_secs(10))
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

async fn wait_until_finished(dir: &std::path::Path, id: &str) -> TransferStatus {
    loop {
        let s = match daemon_request(dir, ControlRequest::TransferStatus { id: id.into() })
            .await
            .unwrap()
        {
            ControlResponse::TransferStatus(s) => s,
            other => panic!("unexpected: {other:?}"),
        };
        if s.state != TransferState::Running {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_publish_is_repaired_by_maintenance_and_survives_restarts() {
    let result = tokio::time::timeout(Duration::from_secs(300), async {
        // ── The publisher is a real daemon; four plain hosts around it. ─────
        let daemon_dir = tempfile::tempdir().unwrap().keep();
        let store_a = Arc::new(LocalShareStore::open(&daemon_dir, 100).unwrap());
        let master: [u8; 32] = std::fs::read(daemon_dir.join("master.key"))
            .unwrap()
            .try_into()
            .unwrap();
        let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let server = DaemonServer::start(node, store_a.clone(), daemon_dir.clone())
            .await
            .unwrap();
        let a_peer = *server.peer_id();
        let a_addr: Multiaddr = server.listen_addrs()[0].parse().unwrap();
        let queue = server.queue();
        let shutdown = server.shutdown_handle();
        let run = tokio::spawn(server.run());

        let mut hosts = Vec::new();
        for key in [0xB6u8, 0xC6, 0xD6, 0xE6] {
            hosts.push(spawn_node_with([key; 32], new_hosted_store(50)).await);
        }
        for host in &hosts {
            host.add_bootstrap_peer(a_peer, a_addr.clone())
                .await
                .unwrap();
            host.bootstrap_dht().await.unwrap();
            host.wait_until_peer_connected(a_peer, Duration::from_secs(10))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // ── Publish through the streaming transfer job. ─────────────────────
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("payload.bin");
        let body: Vec<u8> = (0..50_000u32)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        std::fs::write(&src, &body).unwrap();
        let password = format!("pw-1{:032x}", rand::random::<u128>());
        let id = match daemon_request(
            &daemon_dir,
            ControlRequest::TransferStartPublish {
                file_path: src.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
                password: Some(password),
                restart: false,
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        let finished = wait_until_finished(&daemon_dir, &id).await;
        assert_eq!(finished.state, TransferState::Complete, "{finished:?}");
        let mid = ContentId::from_str(&finished.mid).unwrap();
        let digest = *mid.as_bytes();

        // ── The record must be in the persistent replication queue. ─────────
        let before = queue
            .lock()
            .unwrap()
            .get(&digest)
            .map(|item| item.record.clone())
            .expect("a streamed publish must register its record in the replication queue");
        assert_eq!((before.data_shards, before.total_shards), (2, 3));
        assert_eq!(before.locations.len(), 3);

        let owner_of = |slot: u16| -> usize {
            let bytes = holder_of(&before, slot);
            hosts
                .iter()
                .position(|c| c.peer_id().to_bytes() == bytes)
                .expect("precondition: every slot sits on one of the four remote hosts")
        };
        let (dead_idx, second_idx, third_idx) = (owner_of(0), owner_of(1), owner_of(2));
        let spare_idx = (0..hosts.len())
            .find(|i| ![dead_idx, second_idx, third_idx].contains(i))
            .expect("one host holds no slot");

        // ── The daemon stops; its queue stays on disk. ──────────────────────
        shutdown.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("daemon did not stop")
            .unwrap()
            .expect("daemon exited with an error");
        drop(queue);

        // ── One holder dies; the node restarts with an empty DHT store. ─────
        hosts[dead_idx].shutdown().await;
        let live: Vec<&MiasmaCoordinator> = (0..hosts.len())
            .filter(|i| *i != dead_idx)
            .map(|i| &hosts[i])
            .collect();

        let coord_a1 = Arc::new(spawn_node_with(master, store_a.clone()).await);
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
        let queue1 = Arc::new(Mutex::new(
            ReplicationQueue::load_or_create(&daemon_dir).unwrap(),
        ));
        let tick1 = {
            let backend = CoordinatorBackend::new(
                coord_a1.clone(),
                store_a.clone(),
                Arc::new(QueueRecordSource(queue1.clone())) as Arc<dyn RecordSource>,
            );
            let mut core = MaintenanceCore::new(config(), clock.now_secs());
            core.tick(&backend, clock.now_secs()).await
        };
        assert_eq!(
            tick1.repaired, 1,
            "one slot replica must be repaired: {tick1:?}"
        );
        assert_eq!(tick1.records_committed, 1, "{tick1:?}");
        assert_eq!(tick1.commit_failures, 0, "{tick1:?}");
        assert_eq!(tick1.invariant_violations, 0, "{tick1:?}");

        // ── Invariants of the rewritten record. ─────────────────────────────
        let after = queue1
            .lock()
            .unwrap()
            .get(&digest)
            .map(|item| item.record.clone())
            .expect("item kept");
        check_record_update(&before, &after).expect("legal maintenance rewrite");
        assert_eq!(after.mid_digest, digest, "MID unchanged");
        assert_eq!(
            (after.data_shards, after.total_shards),
            (2, 3),
            "k/n unchanged"
        );
        assert_eq!(after.locations.len(), 3);
        assert_eq!(holder_of(&after, 0), hosts[spare_idx].peer_id().to_bytes());
        assert_eq!(holder_of(&after, 1), holder_of(&before, 1));
        assert_eq!(holder_of(&after, 2), holder_of(&before, 2));
        assert!(after.published_at > before.published_at);

        // The rewritten record was announced with its manifest: still the
        // protected transfer it was.
        let own_key = coord_a1.dht_handle().publisher_key().expect("signing key");
        let envelope = coord_a1
            .dht_handle()
            .local_record_value(digest)
            .await
            .expect("the repaired record is announced");
        let opened = open_signed_record(&digest, &envelope, Some(&own_key)).unwrap();
        let manifest = opened
            .manifest
            .expect("the repaired record must keep its transfer manifest");
        assert_eq!(manifest.mid, digest);
        assert!(
            manifest.protection.is_password(),
            "a protected transfer must stay protected"
        );

        // ── Second restart: the repair is not repeated. ─────────────────────
        coord_a1.shutdown().await;
        drop(coord_a1);
        drop(queue1);
        let coord_a2 = Arc::new(spawn_node_with(master, store_a.clone()).await);
        for host in &live {
            join(&coord_a2, host).await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let queue2 = Arc::new(Mutex::new(
            ReplicationQueue::load_or_create(&daemon_dir).unwrap(),
        ));
        let tick2 = {
            let backend = CoordinatorBackend::new(
                coord_a2.clone(),
                store_a.clone(),
                Arc::new(QueueRecordSource(queue2)) as Arc<dyn RecordSource>,
            );
            let mut core = MaintenanceCore::new(config(), clock.now_secs());
            core.tick(&backend, clock.now_secs()).await
        };
        assert!(
            tick2.repaired == 0 && tick2.failed == 0 && tick2.commit_failures == 0,
            "the next restart must not repeat the repair: {tick2:?}"
        );

        coord_a2.shutdown().await;
        for host in live {
            host.shutdown().await;
        }
    })
    .await;
    result.expect("streamed publish upkeep test timed out (300s)");
}
