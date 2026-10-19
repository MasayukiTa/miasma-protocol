//! A `Required` anonymity policy must hold on the paths that really fetch
//! pieces: the receive engine's piece source (built by the coordinator from its
//! policy) and the retrieval source used by the relay paths. No direct
//! transport is touched, and when nothing is permitted the fetch fails instead
//! of downgrading. Default policies keep the whole fallback chain.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use miasma_core::{
    network::types::ShardLocation, transfer::PieceSource, AnonymityPolicy, ContentId,
    DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaNode, MiasmaShare, NodeType,
    PayloadTransport, PayloadTransportError, PayloadTransportKind,
};

/// A transport that always has the piece and counts every call.
#[derive(Clone)]
struct Counting {
    kind: PayloadTransportKind,
    calls: Arc<AtomicU64>,
}

impl Counting {
    fn new(kind: PayloadTransportKind) -> Self {
        Self {
            kind,
            calls: Arc::new(AtomicU64::new(0)),
        }
    }
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl PayloadTransport for Counting {
    fn kind(&self) -> PayloadTransportKind {
        self.kind
    }
    async fn fetch_share(
        &self,
        _peer_addr: &str,
        _mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(MiasmaShare {
            version: 1,
            mid_prefix: [0; 8],
            segment_index,
            slot_index,
            shard_data: vec![0xAA; 16],
            key_share: vec![0xBB; 32],
            shard_hash: [0; 32],
            nonce: [0; 12],
            original_len: 16,
            timestamp: 0,
        }))
    }
}

fn some_mid() -> ContentId {
    let params = DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    };
    ContentId::compute(b"anonymity-required-test", &params.to_param_bytes())
}

fn holder(addr: &str) -> ShardLocation {
    ShardLocation {
        peer_id_bytes: vec![0; 38],
        shard_index: 0,
        segment_index: 0,
        addrs: vec![addr.to_string()],
    }
}

/// A real coordinator (its own libp2p transport stays in the chain, but is a
/// direct one) with the given extra transports appended.
async fn coordinator(
    extra: Vec<Box<dyn PayloadTransport>>,
) -> (MiasmaCoordinator, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
    let key: [u8; 32] = rand::random();
    let node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let coord = MiasmaCoordinator::start_with_transports(
        node,
        store,
        vec!["/ip4/127.0.0.1/tcp/0".into()],
        extra,
    )
    .await;
    (coord, dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_receive_engine_never_uses_a_direct_transport_under_a_required_policy() {
    let tcp = Counting::new(PayloadTransportKind::TcpDirect);
    let wss = Counting::new(PayloadTransportKind::WssTunnel);
    let relay = Counting::new(PayloadTransportKind::RelayHop);
    let (mut coord, _dir) = coordinator(vec![
        Box::new(tcp.clone()),
        Box::new(wss.clone()),
        Box::new(relay.clone()),
    ])
    .await;
    coord.set_anonymity_policy(AnonymityPolicy::Required { min_hops: 1 });

    let source = coord.piece_source();
    for slot in 0..4u16 {
        let got = source
            .fetch_piece(&some_mid(), 0, slot, &holder("203.0.113.9:4001"))
            .await
            .expect("a permitted transport is configured");
        assert_eq!(got.expect("the relay has the piece").slot_index, slot);
    }
    assert_eq!(tcp.calls(), 0, "a direct transport was used");
    assert_eq!(wss.calls(), 0, "a direct transport was used");
    assert_eq!(
        relay.calls(),
        4,
        "the permitted transport carried the fetches"
    );
    coord.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_only_direct_transports_a_required_receive_fails_and_touches_none() {
    let tcp = Counting::new(PayloadTransportKind::TcpDirect);
    let (mut coord, _dir) = coordinator(vec![Box::new(tcp.clone())]).await;
    coord.set_anonymity_policy(AnonymityPolicy::Required { min_hops: 1 });

    let err = coord
        .piece_source()
        .fetch_piece(&some_mid(), 0, 0, &holder("203.0.113.9:4001"))
        .await
        .expect_err("nothing may carry the request");
    assert!(err.to_string().contains("forbids"), "{err}");
    assert_eq!(tcp.calls(), 0, "a direct transport was used");
    coord.shutdown().await;
}
