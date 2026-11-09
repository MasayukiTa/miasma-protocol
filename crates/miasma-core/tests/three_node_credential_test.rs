use std::{sync::Arc, time::Duration};

use miasma_core::{
    network::node::StoreResponse,
    pipeline::{dissolve, DissolutionParams},
    LocalShareStore, MiasmaCoordinator, MiasmaNode, Multiaddr, NodeType,
};
use tempfile::TempDir;

async fn node() -> (MiasmaCoordinator, Arc<LocalShareStore>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    miasma_core::state_crypto::provision_master_key(dir.path()).unwrap();
    let store = Arc::new(
        LocalShareStore::open(dir.path(), 100)
            .unwrap()
            .with_hosted_quota_mb(50),
    );
    let key: [u8; 32] = rand::random();
    let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/udp/0/quic-v1").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
    (coord, store, dir)
}

async fn dial(from: &MiasmaCoordinator, to: &MiasmaCoordinator) {
    let addr: Multiaddr = to.listen_addrs()[0].parse().unwrap();
    from.add_bootstrap_peer(*to.peer_id(), addr).await.unwrap();
}

async fn run_case(simultaneous: bool, duplicate: bool) {
    let (s, _ss, _sd) = node().await;
    let (r, _rs, _rd) = node().await;
    let (h, hs, _hd) = node().await;
    assert_ne!(s.listen_addrs()[0], r.listen_addrs()[0]);
    assert_ne!(s.listen_addrs()[0], h.listen_addrs()[0]);
    assert_ne!(r.listen_addrs()[0], h.listen_addrs()[0]);
    dial(&s, &h).await;
    if simultaneous {
        tokio::join!(dial(&r, &h), dial(&h, &r));
    } else {
        dial(&r, &h).await;
    }
    if duplicate {
        tokio::join!(dial(&s, &h), dial(&r, &h));
    }
    let h_id = *h.peer_id();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let sc = s
                .dht_handle()
                .select_storage_candidates(vec![])
                .await
                .unwrap();
            let rc = r
                .dht_handle()
                .select_storage_candidates(vec![])
                .await
                .unwrap();
            let s_stats = s.credential_stats().await.unwrap();
            let r_stats = r.credential_stats().await.unwrap();
            let h_stats = h.credential_stats().await.unwrap();
            if sc.contains(&h_id)
                && rc.contains(&h_id)
                && s_stats.held_credentials >= 1
                && r_stats.held_credentials >= 1
                && h_stats.known_issuers >= 3
                && h_stats.held_credentials >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("H must be a verified storage candidate for both S and R");
    let (_, shares) = dissolve(
        format!("three node storage {}", rand::random::<u64>()).as_bytes(),
        DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        },
    )
    .unwrap();
    let share = shares[0].clone();
    let response = s
        .dht_handle()
        .store_share_on_peer(h_id, share.clone())
        .await
        .unwrap();
    let address = match response {
        StoreResponse::Accepted { address, .. } => address,
        other => panic!("H rejected S's share: {other:?}"),
    };
    assert_eq!(
        hs.get_untouched(&address).unwrap().shard_hash,
        share.shard_hash
    );
    s.shutdown().await;
    r.shutdown().await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn three_nodes_verify_and_store() {
    run_case(false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn three_nodes_with_simultaneous_dials() {
    run_case(true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn three_nodes_with_duplicate_dials() {
    run_case(true, true).await;
}
