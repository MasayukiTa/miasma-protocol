//! The retrieval source used by the relay paths honours a `Required` anonymity
//! policy: no direct transport is touched, a relay-circuit address may use the
//! libp2p transport, and default policies keep the whole fallback chain.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use miasma_core::{
    network::types::{DhtRecord, ShardLocation},
    AnonymityPolicy, BypassOnionDhtExecutor, ContentId, DissolutionParams, FallbackShareSource,
    MiasmaShare, OnionAwareDhtExecutor, PayloadTransport, PayloadTransportError,
    PayloadTransportKind, PayloadTransportSelector, ShareSource,
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

async fn source_with(
    transports: Vec<Box<dyn PayloadTransport>>,
    addr: &str,
    policy: AnonymityPolicy,
) -> (FallbackShareSource<BypassOnionDhtExecutor>, Vec<String>) {
    let params = DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    };
    let mid = ContentId::compute(b"anonymity-relay-source-test", &params.to_param_bytes());
    let dht = BypassOnionDhtExecutor::new();
    dht.put(DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: 2,
        total_shards: 3,
        version: 1,
        locations: vec![ShardLocation {
            peer_id_bytes: vec![0; 38],
            shard_index: 0,
            segment_index: 0,
            addrs: vec![addr.to_string()],
        }],
        published_at: 0,
    })
    .await
    .unwrap();
    let selector = Arc::new(PayloadTransportSelector::new(transports));
    let source = FallbackShareSource::new(dht, selector).with_policy(policy);
    let candidates = source.list_candidates(&mid).await;
    assert_eq!(candidates.len(), 1);
    (source, candidates)
}

#[tokio::test]
async fn the_retrieval_source_of_the_relay_paths_honours_a_required_policy() {
    let libp2p = Counting::new(PayloadTransportKind::DirectLibp2p);
    let tcp = Counting::new(PayloadTransportKind::TcpDirect);
    let (source, candidates) = source_with(
        vec![Box::new(libp2p.clone()), Box::new(tcp.clone())],
        "203.0.113.9:4001",
        AnonymityPolicy::Required { min_hops: 1 },
    )
    .await;
    let err = source.fetch(&candidates[0]).await.unwrap_err();
    assert!(err.to_string().contains("forbids"), "{err}");
    assert_eq!((libp2p.calls(), tcp.calls()), (0, 0));
}

#[tokio::test]
async fn a_relay_circuit_address_may_use_libp2p_but_still_no_other_direct_transport() {
    let libp2p = Counting::new(PayloadTransportKind::DirectLibp2p);
    let tcp = Counting::new(PayloadTransportKind::TcpDirect);
    let (source, candidates) = source_with(
        vec![Box::new(tcp.clone()), Box::new(libp2p.clone())],
        "/ip4/198.51.100.7/tcp/4001/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWDest",
        AnonymityPolicy::Required { min_hops: 1 },
    )
    .await;
    let got = source.fetch(&candidates[0]).await.unwrap();
    assert!(got.is_some());
    assert_eq!(libp2p.calls(), 1);
    assert_eq!(tcp.calls(), 0);
}

#[tokio::test]
async fn default_policies_keep_the_whole_fallback_chain() {
    for policy in [AnonymityPolicy::Direct, AnonymityPolicy::Opportunistic] {
        let tcp = Counting::new(PayloadTransportKind::TcpDirect);
        let (source, candidates) =
            source_with(vec![Box::new(tcp.clone())], "203.0.113.9:4001", policy).await;
        assert!(source.fetch(&candidates[0]).await.unwrap().is_some());
        assert_eq!(tcp.calls(), 1, "{policy}");
    }
}
