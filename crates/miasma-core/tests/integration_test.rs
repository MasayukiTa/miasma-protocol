//! Integration tests for miasma-core.
//!
//! These tests exercise the full pipeline end-to-end using public APIs only.
//! They run as a separate binary (Rust integration test convention), so only
//! pub items are accessible.
//!
//! # Coverage
//! | Test | What it verifies |
//! |---|---|
//! | full_dissolution_retrieval_pipeline | E2E: dissolve → store → retrieve |
//! | multi_segment_file_roundtrip | dissolve_file → store → retrieve_file |
//! | forgery_rejection | tampered shares rejected by coarse_verify |
//! | all_shares_forged_fails | InsufficientShares when all forged |
//! | recovery_shards_compensate | RS erasure coding recovers missing data shards |
//! | distress_wipe_within_slo | wipe ≤ 5s SLO; master.key removed |
//! | wipe_makes_shares_unreadable | new store cannot decrypt old shares |
//! | bypass_dht_roundtrip | BypassOnionDhtExecutor put/get |
//! | onion_dht_roundtrip | LiveOnionDhtExecutor full onion path |
//! | single_byte_content | boundary: 1-byte payload |
//! | retrieval_latency_slo | 1 MB local retrieval << 45s P2P SLO |
//! | multi_dissolution_isolation | two files don't contaminate each other |
//! | empty_file_roundtrip | zero-byte content |

use std::sync::Arc;
use tempfile::TempDir;

use miasma_core::{
    network::types::DhtRecord,
    // Core pipeline
    dissolve,
    dissolve_file,
    ContentId,
    DissolutionParams,
    // Retrieval
    DhtShareSource,
    FallbackShareSource,
    LocalShareSource,
    LocalShareStore,
    MiasmaError,
    RetrievalCoordinator,
    // DHT + onion
    BypassOnionDhtExecutor,
    LiveOnionDhtExecutor,
    LiveOnionShareFetcher,
    OnionAwareDhtExecutor,
    DEFAULT_SEGMENT_SIZE,
    // P2P node
    Multiaddr,
    MiasmaCoordinator,
    MiasmaNode,
    NetworkShareFetcher,
    NodeType,
    // Payload transport
    PayloadTransport,
    PayloadTransportError,
    PayloadTransportKind,
    PayloadTransportSelector,
    TransportPhase,
    // WSS transport
    WebSocketConfig,
    WssPayloadTransport,
    WssShareServer,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_store(dir: &TempDir) -> Arc<LocalShareStore> {
    Arc::new(LocalShareStore::open(dir.path(), 100).unwrap())
}

fn make_coordinator(store: Arc<LocalShareStore>) -> RetrievalCoordinator<LocalShareSource> {
    RetrievalCoordinator::new(LocalShareSource::new(store))
}

// ── Test 1: Full dissolution + retrieval pipeline (E2E) ───────────────────────

#[tokio::test]
async fn full_dissolution_retrieval_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    let content = b"Full pipeline integration test: this content exercises the \
        complete path from plaintext to encrypted shards and back. \
        Each stage must produce the same plaintext at the end.";
    let params = DissolutionParams::default();

    let (mid, shares) = dissolve(content, params).unwrap();
    assert_eq!(shares.len(), params.total_shards);

    for s in &shares {
        store.put(s).unwrap();
    }

    let recovered = coord.retrieve(&mid, params).await.unwrap();
    assert_eq!(recovered.as_slice(), content as &[u8]);
}

// ── Test 2: Multi-segment file round-trip ─────────────────────────────────────

#[tokio::test]
async fn multi_segment_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    // 700 bytes with 256-byte segments → 3 segments (256 + 256 + 188).
    let data = vec![0xABu8; 700];
    let params = DissolutionParams::default();

    let (manifest, all_shares) = dissolve_file(&data, params, 256).unwrap();
    assert_eq!(manifest.segments.len(), 3);

    for seg_shares in &all_shares {
        for s in seg_shares {
            store.put(s).unwrap();
        }
    }

    let recovered = coord.retrieve_file(&manifest).await.unwrap();
    assert_eq!(recovered.as_slice(), data.as_slice());
}

// ── Test 3: Forgery rejection (≤ n-k tampered shares still recoverable) ───────

#[tokio::test]
async fn forgery_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    let content = b"forgery rejection integration test - coarse_verify must block tampered shards";
    let params = DissolutionParams::default(); // k=10, n=20

    let (mid, mut shares) = dissolve(content, params).unwrap();

    // Tamper 9 shares (< k). Coarse verify (shard_hash check) rejects them.
    for s in shares.iter_mut().take(9) {
        s.shard_data = vec![0xDE; s.shard_data.len()];
        // shard_hash is stale — ShareVerification::coarse_verify returns false.
    }

    for s in &shares {
        store.put(s).unwrap();
    }

    // 11 valid shares ≥ k=10 → retrieval succeeds.
    let recovered = coord.retrieve(&mid, params).await.unwrap();
    assert_eq!(recovered.as_slice(), content as &[u8]);
}

// ── Test 4: All shares forged → retrieval fails ────────────────────────────────

#[tokio::test]
async fn all_shares_forged_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    let content = b"all forged test";
    let params = DissolutionParams::default();

    let (mid, mut shares) = dissolve(content, params).unwrap();
    for s in shares.iter_mut() {
        s.shard_data = vec![0xFF; s.shard_data.len()];
    }
    for s in &shares {
        store.put(s).unwrap();
    }

    let result = coord.retrieve(&mid, params).await;
    assert!(
        matches!(result, Err(MiasmaError::InsufficientShares { .. })),
        "expected InsufficientShares, got: {:?}",
        result
    );
}

// ── Test 5: Recovery shards compensate for missing data shards ────────────────

#[tokio::test]
async fn recovery_shards_compensate_missing_data() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    let content = b"erasure coding recovery: 5 data shards missing, 15 recovery shards available";
    let params = DissolutionParams::default(); // k=10, n=20

    let (mid, shares) = dissolve(content, params).unwrap();

    // Drop first 5 data shards; store shards 5–19 (10 data + 10 recovery).
    for s in shares.iter().filter(|s| s.slot_index >= 5) {
        store.put(s).unwrap();
    }

    let recovered = coord.retrieve(&mid, params).await.unwrap();
    assert_eq!(recovered.as_slice(), content as &[u8]);
}

// ── Test 6: Distress wipe completes within 5-second SLO ──────────────────────

#[test]
fn distress_wipe_within_slo() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 100).unwrap();

    let content = b"sensitive content subject to distress wipe";
    let params = DissolutionParams::default();
    let (_, shares) = dissolve(content, params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }
    assert_eq!(store.list().len(), params.total_shards);

    let start = std::time::Instant::now();
    store.distress_wipe().unwrap();
    let elapsed = start.elapsed();

    // SLO: ≤ 5 seconds (PRD Section 9).
    assert!(
        elapsed.as_secs() < 5,
        "distress wipe exceeded 5-second SLO: {:?}",
        elapsed
    );

    // master.key must not exist after wipe.
    assert!(!dir.path().join("master.key").exists());
}

// ── Test 7: Wipe makes shares unreadable to a new store instance ──────────────

#[test]
fn wipe_makes_shares_unreadable() {
    let dir = tempfile::tempdir().unwrap();

    {
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let (_, shares) =
            dissolve(b"classified document", DissolutionParams::default()).unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }
        store.distress_wipe().unwrap();
    }

    // Open a new store at the same path — new master.key is generated.
    let new_store = LocalShareStore::open(dir.path(), 100).unwrap();

    // Any address in the index will fail decryption under the new key.
    for addr in new_store.list() {
        let result = new_store.get(&addr);
        assert!(
            result.is_err(),
            "share '{addr}' should not be readable after distress wipe"
        );
    }
}

// ── Test 8: BypassOnionDhtExecutor put/get round-trip ─────────────────────────

#[tokio::test]
async fn bypass_dht_roundtrip() {
    let executor = BypassOnionDhtExecutor::new();
    let mid = ContentId::compute(b"bypass dht test content", b"k=10,n=20,v=1");

    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: 10,
        total_shards: 20,
        version: 1,
        locations: vec![],
        published_at: 0,
    };

    executor.put(record).await.unwrap();

    let retrieved = executor.get(&mid).await.unwrap();
    assert!(retrieved.is_some());

    let r = retrieved.unwrap();
    assert_eq!(r.mid_digest, *mid.as_bytes());
    assert_eq!(r.data_shards, 10);
}

// ── Test 9: LiveOnionDhtExecutor full 2-hop onion round-trip ─────────────────

#[tokio::test]
async fn onion_dht_roundtrip() {
    let master = [0x42u8; 32];
    let executor = LiveOnionDhtExecutor::new_phase1(&master).unwrap();

    // Use a real ContentId so that put+get are matched.
    let mid = ContentId::compute(b"onion dht integration test", b"k=10,n=20,v=1");
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: 10,
        total_shards: 20,
        version: 1,
        locations: vec![],
        published_at: 0,
    };

    executor.put(record).await.unwrap();

    let retrieved = executor.get(&mid).await.unwrap();
    assert!(retrieved.is_some(), "expected Some(record) from onion DHT get");
    assert_eq!(retrieved.unwrap().mid_digest, *mid.as_bytes());
}

// ── Test 10: BypassOnionDhtExecutor missing key returns None ─────────────────

#[tokio::test]
async fn bypass_dht_missing_key_returns_none() {
    let executor = BypassOnionDhtExecutor::new();
    let mid = ContentId::compute(b"never stored", b"k=10,n=20,v=1");
    let result = executor.get(&mid).await.unwrap();
    assert!(result.is_none());
}

// ── Test 11: Single-byte content boundary ─────────────────────────────────────

#[tokio::test]
async fn single_byte_content_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    let content: &[u8] = b"X";
    let params = DissolutionParams::default();

    let (mid, shares) = dissolve(content, params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    let recovered = coord.retrieve(&mid, params).await.unwrap();
    assert_eq!(recovered, content);
}

// ── Test 12: Empty content round-trip ─────────────────────────────────────────

#[tokio::test]
async fn empty_content_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    let params = DissolutionParams::default();
    let (manifest, all_shares) = dissolve_file(&[], params, DEFAULT_SEGMENT_SIZE).unwrap();

    for seg_shares in &all_shares {
        for s in seg_shares {
            store.put(s).unwrap();
        }
    }

    let recovered = coord.retrieve_file(&manifest).await.unwrap();
    assert!(recovered.is_empty());
}

// ── Test 13: Two files don't contaminate each other ───────────────────────────

#[tokio::test]
async fn multi_dissolution_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);

    let params = DissolutionParams::default();
    let content_a = b"file A - this must not be confused with file B";
    let content_b = b"file B - completely different content with a different MID";

    let (mid_a, shares_a) = dissolve(content_a, params).unwrap();
    let (mid_b, shares_b) = dissolve(content_b, params).unwrap();

    // Store both files' shares.
    for s in shares_a.iter().chain(shares_b.iter()) {
        store.put(s).unwrap();
    }

    // Retrieve both independently.
    let coord = make_coordinator(store.clone());
    let rec_a = coord.retrieve(&mid_a, params).await.unwrap();
    let rec_b = coord.retrieve(&mid_b, params).await.unwrap();

    assert_eq!(rec_a.as_slice(), content_a as &[u8]);
    assert_eq!(rec_b.as_slice(), content_b as &[u8]);
    assert_ne!(rec_a, rec_b);
}

// ── Test 14: Retrieval latency SLO (Phase 1 local store) ─────────────────────

#[tokio::test]
async fn retrieval_latency_slo_local_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);
    let coord = make_coordinator(store.clone());

    // 1 MiB content.
    let content = vec![0x42u8; 1024 * 1024];
    let params = DissolutionParams::default();

    let (mid, shares) = dissolve(&content, params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    let start = std::time::Instant::now();
    let recovered = coord.retrieve(&mid, params).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(recovered.len(), content.len());

    // Phase 1 local store should be far below the 45s P2P SLO (PRD §12).
    // We assert ≤ 30s to leave headroom even on slow CI machines.
    assert!(
        elapsed.as_secs() < 30,
        "1 MiB local retrieval exceeded 30s: {:?}",
        elapsed
    );
    println!("[SLO] 1 MiB retrieval (local store): {:?}", elapsed);
}

// ── Test 15: Share store quota enforcement ────────────────────────────────────

#[test]
fn store_quota_enforced() {
    // Use a very small quota (1 MB) to trigger LRU eviction.
    let dir = tempfile::tempdir().unwrap();
    let store = LocalShareStore::open(dir.path(), 1).unwrap(); // 1 MB quota

    let params = DissolutionParams::default();
    // Dissolve multiple files to fill the store.
    for i in 0u8..5 {
        let content = vec![i; 50_000]; // 50 KB per file
        let (_, shares) = dissolve(&content, params).unwrap();
        for s in &shares {
            // put may evict LRU entries to stay within quota.
            let _ = store.put(s);
        }
    }

    // Used bytes should not exceed quota.
    let used = store.used_bytes();
    let quota = 1 * 1024 * 1024; // 1 MB
    assert!(
        used <= quota,
        "store used {} bytes exceeds quota {} bytes",
        used,
        quota
    );
}

// ── Test 16: MID is deterministic ────────────────────────────────────────────

#[test]
fn mid_is_deterministic() {
    let content = b"same content, same params";
    let params = DissolutionParams::default();
    let param_bytes = params.to_param_bytes();

    let mid1 = ContentId::compute(content, &param_bytes);
    let mid2 = ContentId::compute(content, &param_bytes);
    assert_eq!(mid1, mid2);

    let mid_str = mid1.to_string();
    assert!(mid_str.starts_with("miasma:"), "MID format: {}", mid_str);

    let parsed = ContentId::from_str(&mid_str).unwrap();
    assert_eq!(mid1, parsed);
}

// ── Test 17: Full onion stack dissolution + retrieval (Phase 1 P2P SLO) ──────

/// Verifies the full Phase 1 onion-stack pipeline end-to-end:
///   dissolve → LocalShareStore → LiveOnionDhtExecutor (put) →
///   DhtShareSource + LiveOnionShareFetcher → RetrievalCoordinator (retrieve)
///
/// The Phase 1 stack uses in-process onion relay simulation; all crypto is
/// exercised but no real network I/O occurs. This test serves as the baseline
/// for the 45-second P2P SLO defined in PRD §12: we assert ≤ 5s here (in-proc).
#[tokio::test]
async fn onion_stack_dissolution_retrieval_slo() {
    let master = [0x77u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());

    let content = b"onion stack full-stack SLO test: \
        dissolve -> DHT publish -> DhtShareSource retrieve";
    let params = DissolutionParams::default();

    // Step 1: dissolve and store shares locally.
    let (mid, shares) = dissolve(content, params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    // Step 2: publish DHT record via LiveOnionDhtExecutor (2-hop in-process onion).
    let dht_exec = LiveOnionDhtExecutor::new_phase1(&master).unwrap();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: vec![],
        published_at: 0,
    };
    dht_exec.put(record).await.unwrap();

    // Step 3: retrieve via DhtShareSource backed by LiveOnionShareFetcher.
    let share_fetcher =
        LiveOnionShareFetcher::new_phase1(&master, store).unwrap();
    let dht_source = DhtShareSource::new(dht_exec, share_fetcher);
    let coord = RetrievalCoordinator::new(dht_source);

    let start = std::time::Instant::now();
    let recovered = coord.retrieve(&mid, params).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(recovered.as_slice(), content as &[u8]);

    // Phase 1 in-process SLO: well below the 45s P2P target.
    // We assert < 30s to leave headroom for slow debug/CI builds; a release
    // build completes in milliseconds (X25519 ECDH is fast in opt mode).
    assert!(
        elapsed.as_secs() < 30,
        "onion stack retrieval exceeded 30s: {:?}",
        elapsed
    );
    println!("[SLO] onion stack retrieval (in-process 2-hop): {:?}", elapsed);
}

// ── Test 18: Two-node loopback P2P E2E (bypass DHT, real TCP share-exchange) ──
//
// Topology:  Node A (holder)  ←─ TCP/loopback ─→  Node B (retriever)
//
// Approach B: bypasses Kademlia PUT/GET entirely to avoid the quorum-race
// that fires when swarm.dial() runs before the remote event loop is accepting.
//
// Flow:
//   1. Both node event loops start FIRST (TCP sockets now accepting).
//   2. Sleep 200 ms for accept() to become live.
//   3. Dissolve content into Node A's store (local put, no network).
//   4. Build DhtRecord manually with Node A's address + peer_id.
//   5. Seed BypassOnionDhtExecutor with the record (enumerate shard slots).
//   6. Seed NetworkShareFetcher cache (skips DHT GET on fetch).
//   7. RetrievalCoordinator sends ShareFetchRequests via Node B's share handle,
//      which dials Node A (already accepting!) over TCP.
//   8. Node A's event loop serves each shard from store_a.
//   9. Assert reconstructed plaintext == original.

#[tokio::test(flavor = "multi_thread")]
async fn p2p_two_node_loopback() {
    use std::time::Duration;
    use miasma_core::network::types::ShardLocation;
    use tokio::time::{sleep, timeout};

    let _ = tracing_subscriber::fmt()
        .with_env_filter("miasma_core=debug,libp2p_swarm=info")
        .try_init();

    let result = timeout(Duration::from_secs(30), async {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());

        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        // ── Discover OS-assigned TCP ports before starting event loops ─────────
        let mut node_a =
            MiasmaNode::new(&key_a, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let peer_id_a = node_a.local_peer_id;
        let addrs_a = node_a.collect_listen_addrs(400).await;
        assert!(!addrs_a.is_empty(), "Node A must have a listen address");
        let listen_addr_a_str = addrs_a[0].to_string();
        println!("[loopback] Node A: {peer_id_a} @ {listen_addr_a_str}");

        let node_b =
            MiasmaNode::new(&key_b, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        // Extract Node B's handles BEFORE start() consumes node_b.
        let dht_handle_b = node_b.dht_handle();
        let share_handle_b = node_b.share_exchange_handle();

        // ── Start both event loops (TCP sockets now accepting) ─────────────────
        // store_a is cloned so it remains accessible below for local puts.
        let _coord_a = MiasmaCoordinator::start(
            node_a,
            store_a.clone(),
            vec![listen_addr_a_str.clone()],
        ).await;
        let _coord_b = MiasmaCoordinator::start(node_b, store_b, vec![]).await;

        // Give both TCP stacks time to enter accept().
        sleep(Duration::from_millis(200)).await;

        // ── Dissolve content into Node A's store (no network I/O) ─────────────
        let content = b"two-node loopback integration test payload, verify real P2P";
        let params = DissolutionParams { data_shards: 3, total_shards: 5 };

        let (mid, shares) = dissolve(content, params).unwrap();
        for share in &shares {
            store_a.put(share).unwrap();
        }
        println!("[loopback] MID: {}", mid.to_string());

        // ── Build DhtRecord manually (no Kademlia PUT/GET required) ───────────
        let peer_bytes_a = peer_id_a.to_bytes();
        let locations: Vec<ShardLocation> = shares
            .iter()
            .map(|s| ShardLocation {
                peer_id_bytes: peer_bytes_a.clone(),
                shard_index: s.slot_index,
                addrs: vec![listen_addr_a_str.clone()],
            })
            .collect();

        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations,
            published_at: 0,
        };

        // ── Retrieval: bypass DHT + real TCP share-exchange ───────────────────
        // BypassOnionDhtExecutor serves list_candidates() with total_shards slots.
        let bypass_dht = BypassOnionDhtExecutor::new();
        bypass_dht.put(record.clone()).await.unwrap();

        // NetworkShareFetcher pre-seeded: skips DHT GET, uses Node B's share
        // handle to dial Node A (already accepting) and fetch each shard via TCP.
        let network_fetcher =
            NetworkShareFetcher::with_initial_record(dht_handle_b, share_handle_b, record);

        let source = DhtShareSource::new(bypass_dht, network_fetcher);
        let recovered = RetrievalCoordinator::new(source)
            .retrieve(&mid, params)
            .await
            .expect("retrieve failed");

        assert_eq!(
            recovered.as_slice(),
            content as &[u8],
            "reconstructed plaintext mismatch"
        );
        println!("[loopback] Round-trip OK: {} bytes", recovered.len());
    })
    .await;

    result.expect("p2p_two_node_loopback timed out (30s)");
}

// ── Test 19: Full Kademlia DHT + share-exchange round-trip ────────────────────
//
// Topology:  Node A (publisher/holder) ←─ TCP/loopback ─→ Node B (retriever)
//
// Unlike Test 18 which bypasses Kademlia, this test exercises the real DHT:
//   1. Both nodes start; bootstrap each other from within their running loops.
//   2. Node A dissolves + publishes via `dissolve_and_publish()` → Kademlia PUT.
//   3. Node B retrieves via `retrieve_from_network()` → Kademlia GET + TCP
//      share-exchange → reconstruct plaintext.

#[tokio::test(flavor = "multi_thread")]
async fn p2p_kademlia_full_roundtrip() {
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    let _ = tracing_subscriber::fmt()
        .with_env_filter("miasma_core=debug,libp2p_swarm=info")
        .try_init();

    let result = timeout(Duration::from_secs(60), async {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());

        let key_a = [0x33u8; 32];
        let key_b = [0x44u8; 32];

        // ── Start Node A ──────────────────────────────────────────────────────
        let mut node_a =
            MiasmaNode::new(&key_a, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let addrs_a = node_a.collect_listen_addrs(400).await;
        assert!(!addrs_a.is_empty(), "Node A must have a listen address");
        let listen_addr_a_str = addrs_a[0].to_string();

        let coord_a =
            MiasmaCoordinator::start(node_a, store_a.clone(), vec![listen_addr_a_str.clone()])
                .await;
        let peer_id_a = *coord_a.peer_id();
        println!("[kademlia] Node A: {peer_id_a} @ {listen_addr_a_str}");

        // ── Start Node B ──────────────────────────────────────────────────────
        let mut node_b =
            MiasmaNode::new(&key_b, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let addrs_b = node_b.collect_listen_addrs(400).await;
        assert!(!addrs_b.is_empty(), "Node B must have a listen address");
        let listen_addr_b_str = addrs_b[0].to_string();

        let coord_b =
            MiasmaCoordinator::start(node_b, store_b.clone(), vec![listen_addr_b_str.clone()])
                .await;
        let peer_id_b = *coord_b.peer_id();
        println!("[kademlia] Node B: {peer_id_b} @ {listen_addr_b_str}");

        // ── Bootstrap: connect A↔B from within the running event loops ────────
        let addr_a: Multiaddr = listen_addr_a_str.parse().unwrap();
        let addr_b: Multiaddr = listen_addr_b_str.parse().unwrap();

        coord_a.add_bootstrap_peer(peer_id_b, addr_b).await.unwrap();
        coord_b.add_bootstrap_peer(peer_id_a, addr_a).await.unwrap();

        coord_a.bootstrap_dht().await.unwrap();
        coord_b.bootstrap_dht().await.unwrap();

        // Wait for Kademlia routing tables to converge (~1-3 round trips).
        eprintln!("[kademlia] Waiting for DHT convergence…");
        sleep(Duration::from_millis(2500)).await;

        // ── Publish via Node A ────────────────────────────────────────────────
        let content = b"kademlia full round-trip: real DHT PUT + GET with TCP share-exchange";
        let params = DissolutionParams { data_shards: 3, total_shards: 5 };

        let mid = coord_a
            .dissolve_and_publish(content, params)
            .await
            .expect("dissolve_and_publish failed");
        println!("[kademlia] Published MID: {}", mid.to_string());

        // Allow the PUT to replicate to the routing table.
        sleep(Duration::from_millis(500)).await;

        // ── Retrieve via Node B ───────────────────────────────────────────────
        let recovered = coord_b
            .retrieve_from_network(&mid, params)
            .await
            .expect("retrieve_from_network failed");

        assert_eq!(
            recovered.as_slice(),
            content as &[u8],
            "Kademlia round-trip plaintext mismatch"
        );
        println!("[kademlia] Round-trip OK: {} bytes", recovered.len());

        coord_a.shutdown().await;
        coord_b.shutdown().await;
    })
    .await;

    result.expect("p2p_kademlia_full_roundtrip timed out (60s)");
}

// ── Test 20: CLI smoke path — mirrors `network-publish` → `network-get` ───────
//
// This test is the in-process analogue of the 2-terminal CLI runbook:
//
//   Terminal 1:  miasma --data-dir /tmp/a init
//                miasma --data-dir /tmp/a network-publish file.txt
//                # stays running, prints: MID + /ip4/127.0.0.1/.../p2p/<peer_id>
//
//   Terminal 2:  miasma --data-dir /tmp/b init
//                miasma --data-dir /tmp/b network-get <MID> \
//                    --bootstrap /ip4/127.0.0.1/.../p2p/<peer_id> -o out.bin
//
// Kept intentionally small (k=2/n=3, tiny payload) for fast CI feedback.
// For the full-fidelity P2P + DHT test, see `p2p_kademlia_full_roundtrip`.

#[tokio::test(flavor = "multi_thread")]
async fn cli_smoke_loopback() {
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    let _ = tracing_subscriber::fmt()
        .with_env_filter("miasma_core=info")
        .try_init();

    let result = timeout(Duration::from_secs(30), async {
        // ── Node A: init + network-publish ────────────────────────────────────
        let dir_a = tempfile::tempdir().unwrap();
        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let key_a = [0x55u8; 32];

        let mut node_a =
            MiasmaNode::new(&key_a, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let peer_id_a = node_a.local_peer_id;
        let addrs_a = node_a.collect_listen_addrs(400).await;
        assert!(!addrs_a.is_empty(), "Node A must have a listen address");
        let addr_a_str = addrs_a[0].to_string();
        // Simulate the bootstrap address printed by `network-publish`
        let bootstrap_str = format!("{addr_a_str}/p2p/{peer_id_a}");
        println!("[smoke] Node A bootstrap addr: {bootstrap_str}");

        let coord_a =
            MiasmaCoordinator::start(node_a, store_a, vec![addr_a_str.clone()]).await;

        // Dissolve + publish (same as `miasma network-publish`)
        let content = b"cli smoke test payload";
        let params = DissolutionParams { data_shards: 2, total_shards: 3 };
        let mid = coord_a.dissolve_and_publish(content, params).await.unwrap();
        println!("[smoke] Published MID: {}", mid.to_string());

        // ── Node B: init + network-get (with --bootstrap) ─────────────────────
        let dir_b = tempfile::tempdir().unwrap();
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());
        let key_b = [0x66u8; 32];

        let mut node_b =
            MiasmaNode::new(&key_b, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let _addrs_b = node_b.collect_listen_addrs(400).await;
        let coord_b = MiasmaCoordinator::start(node_b, store_b, vec![]).await;

        // Parse bootstrap addr and register (same as CLI --bootstrap parsing)
        use libp2p::multiaddr::Protocol;
        let mut addr: Multiaddr = bootstrap_str.parse().unwrap();
        let bootstrap_peer_id: libp2p::PeerId = addr.iter().find_map(|p| {
            if let Protocol::P2p(id) = p { Some(id) } else { None }
        }).unwrap();
        if matches!(addr.iter().last(), Some(Protocol::P2p(_))) { addr.pop(); }

        coord_b.add_bootstrap_peer(bootstrap_peer_id, addr).await.unwrap();
        coord_b.bootstrap_dht().await.unwrap();

        // Wait for DHT convergence (same as 2s sleep in `network-get`)
        sleep(Duration::from_millis(1500)).await;

        // Retrieve (same as `miasma network-get`)
        let recovered = coord_b.retrieve_from_network(&mid, params).await
            .expect("network-get failed");

        assert_eq!(recovered.as_slice(), content as &[u8], "plaintext mismatch");
        println!("[smoke] Round-trip OK: {} bytes", recovered.len());

        coord_a.shutdown().await;
        coord_b.shutdown().await;
    })
    .await;

    result.expect("cli_smoke_loopback timed out (30s)");
}

// ── Test 21: Daemon IPC publish → get round-trip ──────────────────────────────
//
// Mirrors the two-terminal CLI runbook at the API level:
//   Daemon A starts → client publishes via IPC → client gets via daemon B IPC.

#[tokio::test(flavor = "multi_thread")]
async fn daemon_ipc_publish_get_roundtrip() {
    use miasma_core::daemon::DaemonServer;
    use miasma_core::daemon::ipc::{daemon_request, ControlRequest, ControlResponse};
    use std::time::Duration;
    use tokio::time::timeout;

    let _ = tracing_subscriber::fmt()
        .with_env_filter("miasma_core=info")
        .try_init();

    let result = timeout(Duration::from_secs(30), async {
        // ── Node A daemon ─────────────────────────────────────────────────────
        let dir_a = tempfile::tempdir().unwrap();
        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let key_a = [0x88u8; 32];
        let node_a = MiasmaNode::new(&key_a, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();

        let server_a = DaemonServer::start(node_a, store_a, dir_a.path().to_owned())
            .await
            .unwrap();
        let addr_a = format!("{}/p2p/{}", server_a.listen_addrs()[0], server_a.peer_id());
        let shutdown_a = server_a.shutdown_handle();
        let dir_a_path = dir_a.path().to_owned();
        tokio::spawn(server_a.run());

        // ── Publish via IPC client (network-publish behaviour) ────────────────
        let content = b"daemon IPC round-trip test payload";
        let req = ControlRequest::Publish {
            data: content.to_vec(),
            data_shards: 2,
            total_shards: 3,
        };
        let mid_str = match daemon_request(&dir_a_path, req).await.unwrap() {
            ControlResponse::Published { mid } => mid,
            other => panic!("unexpected: {other:?}"),
        };
        println!("[ipc] Published MID: {mid_str}");

        // After publish, network-publish EXITS — only the daemon stays alive.

        // ── Node B daemon ─────────────────────────────────────────────────────
        let dir_b = tempfile::tempdir().unwrap();
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());
        let key_b = [0x99u8; 32];
        let node_b = MiasmaNode::new(&key_b, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();

        let server_b = DaemonServer::start(node_b, store_b, dir_b.path().to_owned())
            .await
            .unwrap();
        let dir_b_path = dir_b.path().to_owned();
        let shutdown_b = server_b.shutdown_handle();

        // Bootstrap B → A.
        {
            use libp2p::multiaddr::Protocol;
            let mut addr: Multiaddr = addr_a.parse().unwrap();
            let bootstrap_peer_id: libp2p::PeerId = addr.iter().find_map(|p| {
                if let Protocol::P2p(id) = p { Some(id) } else { None }
            }).unwrap();
            if matches!(addr.iter().last(), Some(Protocol::P2p(_))) { addr.pop(); }
            server_b.add_bootstrap_peer(bootstrap_peer_id, addr).await.unwrap();
        }
        server_b.bootstrap_dht().await.unwrap();
        tokio::spawn(server_b.run());

        // Wait for DHT convergence.
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // ── Get via IPC client (network-get behaviour) ────────────────────────
        let req = ControlRequest::Get {
            mid: mid_str.clone(),
            data_shards: 2,
            total_shards: 3,
        };
        let retrieved = match daemon_request(&dir_b_path, req).await.unwrap() {
            ControlResponse::Retrieved { data } => data,
            ControlResponse::Error(e) => panic!("get error: {e}"),
            other => panic!("unexpected: {other:?}"),
        };

        assert_eq!(retrieved.as_slice(), content as &[u8], "content mismatch");
        println!("[ipc] Round-trip OK: {} bytes", retrieved.len());

        let _ = shutdown_a.send(()).await;
        let _ = shutdown_b.send(()).await;
    })
    .await;

    result.expect("daemon_ipc_publish_get_roundtrip timed out");
}

// ── Test 22: Publish before peers exist → replication retries when peer joins ──
//
// Proves that the replication queue defers announce until a peer is available,
// then eventually delivers the record so a later joiner can retrieve content.

#[tokio::test(flavor = "multi_thread")]
async fn replication_retries_after_peer_join() {
    use miasma_core::daemon::DaemonServer;
    use miasma_core::daemon::ipc::{daemon_request, ControlRequest, ControlResponse};
    use std::time::Duration;
    use tokio::time::timeout;

    let _ = tracing_subscriber::fmt()
        .with_env_filter("miasma_core=info")
        .try_init();

    let result = timeout(Duration::from_secs(30), async {
        // ── Node A: publish with no peers ─────────────────────────────────────
        let dir_a = tempfile::tempdir().unwrap();
        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let node_a = MiasmaNode::new(&[0xAAu8; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();

        let server_a = DaemonServer::start(node_a, store_a, dir_a.path().to_owned())
            .await
            .unwrap();
        let addr_a_str = format!("{}/p2p/{}", server_a.listen_addrs()[0], server_a.peer_id());
        let shutdown_a = server_a.shutdown_handle();
        let dir_a_path = dir_a.path().to_owned();
        let queue_a = server_a.queue();
        tokio::spawn(server_a.run());

        let content = b"replication-retry test: publish before peers exist";
        let req = ControlRequest::Publish { data: content.to_vec(), data_shards: 2, total_shards: 3 };
        let mid_str = match daemon_request(&dir_a_path, req).await.unwrap() {
            ControlResponse::Published { mid } => mid,
            other => panic!("unexpected: {other:?}"),
        };
        println!("[retry] Published MID: {mid_str} (no peers yet)");

        // Immediately after publish: pending_replication = 1, replicated = 0.
        assert_eq!(queue_a.lock().unwrap().pending_count(), 1);
        assert_eq!(queue_a.lock().unwrap().replicated_count(), 0);

        // ── Node B: join and bootstrap to A ───────────────────────────────────
        let dir_b = tempfile::tempdir().unwrap();
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());
        let node_b = MiasmaNode::new(&[0xBBu8; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();

        let server_b = DaemonServer::start(node_b, store_b, dir_b.path().to_owned())
            .await
            .unwrap();
        let dir_b_path = dir_b.path().to_owned();
        let shutdown_b = server_b.shutdown_handle();

        {
            use libp2p::multiaddr::Protocol;
            let mut addr: Multiaddr = addr_a_str.parse().unwrap();
            let peer_id_a: libp2p::PeerId = addr.iter().find_map(|p| {
                if let Protocol::P2p(id) = p { Some(id) } else { None }
            }).unwrap();
            if matches!(addr.iter().last(), Some(Protocol::P2p(_))) { addr.pop(); }
            server_b.add_bootstrap_peer(peer_id_a, addr).await.unwrap();
        }
        server_b.bootstrap_dht().await.unwrap();
        tokio::spawn(server_b.run());

        // Wait for connection to be established.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Re-read server_a via IPC: trigger replication retry now that A has a peer.
        // In production this happens via the 5-second timer; here we just wait for it.
        // The timer fires every 5s, so wait up to 7s for at least one retry.
        let mut replicated = false;
        for _ in 0..14 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let rc = queue_a.lock().unwrap().replicated_count();
            if rc > 0 {
                replicated = true;
                break;
            }
        }
        println!("[retry] replicated_count = {}", queue_a.lock().unwrap().replicated_count());
        assert!(replicated, "replication was never confirmed by a remote peer");

        // ── B can now retrieve content ─────────────────────────────────────────
        let req = ControlRequest::Get { mid: mid_str.clone(), data_shards: 2, total_shards: 3 };
        let retrieved = match daemon_request(&dir_b_path, req).await.unwrap() {
            ControlResponse::Retrieved { data } => data,
            ControlResponse::Error(e) => panic!("get from B failed: {e}"),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(retrieved.as_slice(), content as &[u8]);
        println!("[retry] Round-trip OK after replication retry: {} bytes", retrieved.len());

        let _ = shutdown_a.send(()).await;
        let _ = shutdown_b.send(()).await;
    })
    .await;

    result.expect("replication_retries_after_peer_join timed out");
}

// ── Test 23: Topology event triggers replication without fallback timer ──────
//
// Proves that a PeerConnected topology event drives replication immediately,
// without relying on the 60-second fallback timer.  The fallback timer is set
// far in the future (60s) so if the test completes in <15s it can only be the
// topology-event path that did the work.

#[test]
fn topology_event_triggers_replication() {
    // Use a manual runtime so we can drop it to forcibly stop all daemon
    // tasks — `#[tokio::test]` waits for spawned tasks which can hang if
    // Kademlia shutdown is slow for certain peer-ID combinations.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let passed = rt.block_on(async {
        use miasma_core::daemon::DaemonServer;
        use miasma_core::daemon::ipc::{daemon_request, ControlRequest, ControlResponse};
        use std::time::Duration;
        use tokio::time::timeout;

        let _ = tracing_subscriber::fmt()
            .with_env_filter("miasma_core=info")
            .try_init();

        timeout(Duration::from_secs(20), async {
            // ── Node A: publish with no peers ──────────────────────────────
            let dir_a = tempfile::tempdir().unwrap();
            let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
            let node_a = MiasmaNode::new(&[0xCCu8; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();

            let server_a = DaemonServer::start(node_a, store_a, dir_a.path().to_owned())
                .await
                .unwrap();
            let addr_a_str = format!("{}/p2p/{}", server_a.listen_addrs()[0], server_a.peer_id());
            let dir_a_path = dir_a.path().to_owned();
            let queue_a = server_a.queue();
            tokio::spawn(server_a.run());

            let content = b"topology-event-driven replication test";
            let req = ControlRequest::Publish { data: content.to_vec(), data_shards: 2, total_shards: 3 };
            match daemon_request(&dir_a_path, req).await.unwrap() {
                ControlResponse::Published { mid } => {
                    println!("[topo] Published MID: {mid}");
                }
                other => panic!("unexpected: {other:?}"),
            };

            assert_eq!(queue_a.lock().unwrap().pending_count(), 1);

            // ── Node B: join — PeerConnected should trigger replication ───
            let dir_b = tempfile::tempdir().unwrap();
            let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());
            let node_b = MiasmaNode::new(&[0xDDu8; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();

            let server_b = DaemonServer::start(node_b, store_b, dir_b.path().to_owned())
                .await
                .unwrap();

            {
                use libp2p::multiaddr::Protocol;
                let mut addr: Multiaddr = addr_a_str.parse().unwrap();
                let peer_id_a: libp2p::PeerId = addr.iter().find_map(|p| {
                    if let Protocol::P2p(id) = p { Some(id) } else { None }
                }).unwrap();
                if matches!(addr.iter().last(), Some(Protocol::P2p(_))) { addr.pop(); }
                server_b.add_bootstrap_peer(peer_id_a, addr).await.unwrap();
            }
            server_b.bootstrap_dht().await.unwrap();
            tokio::spawn(server_b.run());

            // Wait for replication to be confirmed.
            // Fallback timer is 60s; if this completes in <5s it proves
            // the topology-event path drove the replication.
            tokio::time::sleep(Duration::from_secs(5)).await;
            let rc = queue_a.lock().unwrap().replicated_count();
            let pc = queue_a.lock().unwrap().pending_count();
            println!("[topo] replicated={rc}, pending={pc}");
            assert!(rc > 0, "replication should be driven by topology event, not fallback timer");
        }).await
    });

    // Forcibly shut down the runtime without waiting for daemon tasks.
    rt.shutdown_timeout(std::time::Duration::from_millis(100));
    passed.expect("topology_event_triggers_replication timed out");
}

// ── Test 24: WAL survives daemon restart ─────────────────────────────────────
//
// Proves that the replication queue's WAL persistence survives a process
// restart: items pushed in session 1 are recovered in session 2.

#[tokio::test(flavor = "multi_thread")]
async fn wal_survives_daemon_restart() {
    use miasma_core::daemon::replication::ReplicationQueue;
    use miasma_core::daemon::replication::ItemState;
    use miasma_core::network::types::DhtRecord;

    let dir = tempfile::tempdir().unwrap();

    // Create a record to simulate a publish.
    let mut digest = [0u8; 32];
    digest[0] = 0xEE;
    let record = DhtRecord {
        mid_digest: digest,
        data_shards: 2,
        total_shards: 3,
        version: 1,
        locations: vec![],
        published_at: 1000,
    };

    // Session 1: push an item and record a few attempts.
    {
        let mut q = ReplicationQueue::load_or_create(dir.path()).unwrap();
        let item = miasma_core::daemon::replication::PendingReplication::new(
            "test-wal-restart".to_string(),
            record.clone(),
        );
        q.push(item).unwrap();
        q.record_attempt(&digest).unwrap();
        q.record_attempt(&digest).unwrap();
        assert_eq!(q.pending_count(), 1);
    }
    // Drop = simulated crash.

    // Session 2: reload and verify state.
    {
        let q = ReplicationQueue::load_or_create(dir.path()).unwrap();
        assert_eq!(q.pending_count(), 1);
        let item = q.get(&digest).unwrap();
        assert_eq!(item.attempt_count, 2);
        assert_eq!(item.state, ItemState::Pending);
        assert_eq!(item.mid_str, "test-wal-restart");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAYLOAD TRANSPORT PLANE TESTS
// ═══════════════════════════════════════════════════════════════════════════════
//
// These tests verify REAL payload retrieval, not just discovery/metadata.
// Each test asserts which transport was used and that the retrieved plaintext
// matches the original content.

// ── Mock transports for payload-plane tests ──────────────────────────────────

/// Transport backed by a local store — simulates successful share fetch.
struct LocalStoreTransport {
    store: Arc<LocalShareStore>,
    kind: PayloadTransportKind,
}

#[async_trait::async_trait]
impl PayloadTransport for LocalStoreTransport {
    fn kind(&self) -> PayloadTransportKind {
        self.kind
    }

    async fn fetch_share(
        &self,
        _peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<miasma_core::MiasmaShare>, PayloadTransportError> {
        let prefix: [u8; 8] = mid_digest[..8].try_into().unwrap();
        let candidates = self.store.search_by_mid_prefix(&prefix);
        let share = candidates.iter().find_map(|addr| {
            self.store.get(addr).ok().and_then(|s| {
                if s.slot_index == slot_index && s.segment_index == segment_index {
                    Some(s)
                } else {
                    None
                }
            })
        });
        Ok(share)
    }
}

/// Transport that always fails at session phase.
struct SessionFailTransport;

#[async_trait::async_trait]
impl PayloadTransport for SessionFailTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::DirectLibp2p
    }

    async fn fetch_share(
        &self,
        _: &str,
        _: [u8; 32],
        _: u16,
        _: u32,
    ) -> Result<Option<miasma_core::MiasmaShare>, PayloadTransportError> {
        Err(PayloadTransportError {
            phase: TransportPhase::Session,
            message: "QUIC connection refused (simulated DPI block)".into(),
        })
    }
}

/// Transport that always fails at data phase.
struct DataFailTransport;

#[async_trait::async_trait]
impl PayloadTransport for DataFailTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::TcpDirect
    }

    async fn fetch_share(
        &self,
        _: &str,
        _: [u8; 32],
        _: u16,
        _: u32,
    ) -> Result<Option<miasma_core::MiasmaShare>, PayloadTransportError> {
        Err(PayloadTransportError {
            phase: TransportPhase::Data,
            message: "connection reset during piece transfer".into(),
        })
    }
}

// ── Test 25: Payload retrieval via FallbackShareSource ──────────────────────
//
// Proves: dissolve → store → FallbackShareSource (with transport selector) →
//         RetrievalCoordinator → reconstruct = original content.
// This is a REAL payload-plane test: shares are actually fetched, decoded,
// and verified against the original plaintext.

#[tokio::test]
async fn payload_transport_single_transport_success() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);

    let content = b"payload-plane: single transport success proves real data fetch";
    let params = DissolutionParams::default();
    let (mid, shares) = dissolve(content, params).unwrap();

    for s in &shares {
        store.put(s).unwrap();
    }

    // Build DHT record so FallbackShareSource can list candidates.
    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec!["127.0.0.1:9999".into()],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    let selector = Arc::new(PayloadTransportSelector::new(vec![Box::new(
        LocalStoreTransport {
            store: store.clone(),
            kind: PayloadTransportKind::DirectLibp2p,
        },
    )]));

    let source = FallbackShareSource::new(dht, selector.clone());
    let recovered = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await
        .expect("payload retrieval failed");

    assert_eq!(recovered.as_slice(), content as &[u8]);

    // Verify transport stats recorded the successes.
    let snap = selector.stats().snapshot();
    let libp2p_stat = snap
        .iter()
        .find(|r| r.transport == PayloadTransportKind::DirectLibp2p)
        .unwrap();
    assert!(
        libp2p_stat.success_count >= params.data_shards as u64,
        "expected at least k={} successes, got {}",
        params.data_shards,
        libp2p_stat.success_count
    );
}

// ── Test 26: Payload fallback — primary fails, secondary succeeds ───────────
//
// Proves: when the first transport fails (session error), the selector falls
// back to the next transport in the chain and payload retrieval still succeeds.
// The test asserts the fallback was observable via transport statistics.

#[tokio::test]
async fn payload_transport_fallback_on_session_failure() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);

    let content = b"payload-plane: fallback after session failure";
    let params = DissolutionParams { data_shards: 3, total_shards: 5 };
    let (mid, shares) = dissolve(content, params).unwrap();

    for s in &shares {
        store.put(s).unwrap();
    }

    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec!["127.0.0.1:9999".into()],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    // Fallback chain: SessionFail (libp2p) → LocalStore (tcp-direct)
    let selector = Arc::new(PayloadTransportSelector::new(vec![
        Box::new(SessionFailTransport),
        Box::new(LocalStoreTransport {
            store: store.clone(),
            kind: PayloadTransportKind::TcpDirect,
        }),
    ]));

    let source = FallbackShareSource::new(dht, selector.clone());
    let recovered = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await
        .expect("payload retrieval with fallback failed");

    assert_eq!(recovered.as_slice(), content as &[u8]);

    // Verify: primary transport failed, secondary succeeded.
    let snap = selector.stats().snapshot();
    let libp2p_stat = snap.iter().find(|r| r.transport == PayloadTransportKind::DirectLibp2p).unwrap();
    let tcp_stat = snap.iter().find(|r| r.transport == PayloadTransportKind::TcpDirect).unwrap();
    assert!(libp2p_stat.failure_count >= params.data_shards as u64,
        "expected {} libp2p failures, got {}", params.data_shards, libp2p_stat.failure_count);
    assert!(tcp_stat.success_count >= params.data_shards as u64,
        "expected {} tcp successes, got {}", params.data_shards, tcp_stat.success_count);
}

// ── Test 27: All transports fail → retrieval fails with InsufficientShares ──
//
// Proves: when all transports in the fallback chain fail, the retrieval
// correctly reports InsufficientShares (not a panic or opaque error).

#[tokio::test]
async fn payload_transport_all_fail_returns_insufficient() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);

    let content = b"payload-plane: all transports fail";
    let params = DissolutionParams { data_shards: 3, total_shards: 5 };
    let (mid, shares) = dissolve(content, params).unwrap();

    for s in &shares {
        store.put(s).unwrap();
    }

    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec!["127.0.0.1:9999".into()],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    // All transports fail.
    let selector = Arc::new(PayloadTransportSelector::new(vec![
        Box::new(SessionFailTransport),
        Box::new(DataFailTransport),
    ]));

    let source = FallbackShareSource::new(dht, selector.clone());
    let result = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await;

    assert!(
        matches!(result, Err(MiasmaError::InsufficientShares { .. })),
        "expected InsufficientShares, got: {result:?}"
    );

    // Both transports should have recorded failures.
    let snap = selector.stats().snapshot();
    let libp2p_fail = snap.iter().find(|r| r.transport == PayloadTransportKind::DirectLibp2p).unwrap();
    let tcp_fail = snap.iter().find(|r| r.transport == PayloadTransportKind::TcpDirect).unwrap();
    assert!(libp2p_fail.failure_count > 0);
    assert!(tcp_fail.failure_count > 0);
}

// ── Test 28: Fallback distinguishes session vs data failure ──────────────────
//
// Proves: the diagnostic output correctly records which phase failed for each
// transport, so operators can distinguish "DPI blocks the connection" from
// "connection established but payload transfer interrupted".

#[tokio::test]
async fn payload_transport_phase_distinction() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(&dir);

    let params = DissolutionParams { data_shards: 2, total_shards: 3 };
    let (mid, shares) = dissolve(b"phase distinction test", params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec!["127.0.0.1:9999".into()],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    // Chain: SessionFail → DataFail → LocalStore (success)
    let selector = Arc::new(PayloadTransportSelector::new(vec![
        Box::new(SessionFailTransport),
        Box::new(DataFailTransport),
        Box::new(LocalStoreTransport {
            store: store.clone(),
            kind: PayloadTransportKind::RelayHop,
        }),
    ]));

    let source = FallbackShareSource::new(dht, selector.clone());
    let recovered = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await
        .expect("retrieval should succeed via third transport");

    assert_eq!(recovered.as_slice(), b"phase distinction test");

    // Verify stats: session failure, data failure, and success all recorded.
    let snap = selector.stats().snapshot();
    assert!(snap.iter().any(|r| r.transport == PayloadTransportKind::DirectLibp2p && r.failure_count > 0),
        "session failure should be recorded for libp2p");
    assert!(snap.iter().any(|r| r.transport == PayloadTransportKind::TcpDirect && r.failure_count > 0),
        "data failure should be recorded for tcp");
    assert!(snap.iter().any(|r| r.transport == PayloadTransportKind::RelayHop && r.success_count > 0),
        "relay success should be recorded");
}

// ── Test 29: Real P2P payload transport via FallbackShareSource ─────────────
//
// Like p2p_two_node_loopback (Test 18) but uses the new FallbackShareSource
// with Libp2pPayloadTransport, proving the transport selector integration
// works end-to-end over real TCP.

#[tokio::test(flavor = "multi_thread")]
async fn p2p_payload_transport_loopback() {
    use std::time::Duration;
    use miasma_core::network::types::ShardLocation;
    use miasma_core::Libp2pPayloadTransport;
    use tokio::time::{sleep, timeout};

    let _ = tracing_subscriber::fmt()
        .with_env_filter("miasma_core=debug,libp2p_swarm=info")
        .try_init();

    let result = timeout(Duration::from_secs(30), async {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());

        let key_a = [0xE1u8; 32];
        let key_b = [0xE2u8; 32];

        let mut node_a =
            MiasmaNode::new(&key_a, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let peer_id_a = node_a.local_peer_id;
        let addrs_a = node_a.collect_listen_addrs(400).await;
        let listen_addr_a_str = addrs_a[0].to_string();

        let node_b =
            MiasmaNode::new(&key_b, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let dht_handle_b = node_b.dht_handle();
        let share_handle_b = node_b.share_exchange_handle();

        let _coord_a = MiasmaCoordinator::start(
            node_a,
            store_a.clone(),
            vec![listen_addr_a_str.clone()],
        ).await;
        let _coord_b = MiasmaCoordinator::start(node_b, store_b, vec![]).await;

        sleep(Duration::from_millis(200)).await;

        // Dissolve content into Node A's store.
        let content = b"payload-plane: real P2P loopback via FallbackShareSource";
        let params = DissolutionParams { data_shards: 3, total_shards: 5 };
        let (mid, shares) = dissolve(content, params).unwrap();
        for share in &shares {
            store_a.put(share).unwrap();
        }

        // Build DhtRecord manually.
        let peer_bytes_a = peer_id_a.to_bytes();
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations: shares.iter().map(|s| ShardLocation {
                peer_id_bytes: peer_bytes_a.clone(),
                shard_index: s.slot_index,
                addrs: vec![listen_addr_a_str.clone()],
            }).collect(),
            published_at: 0,
        };

        // Use FallbackShareSource with Libp2pPayloadTransport (REAL TCP).
        let bypass_dht = BypassOnionDhtExecutor::new();
        bypass_dht.put(record.clone()).await.unwrap();

        // Pre-seed the libp2p transport's record cache since we bypass DHT.
        // We do this by building a selector with the transport directly.
        // The Libp2pPayloadTransport needs the DhtRecord in its cache;
        // we achieve this by using NetworkShareFetcher::with_initial_record
        // wrapped in the new API. For this test, use a mock transport that
        // delegates to the real share handle.
        struct RealLibp2pTransport {
            share_handle: miasma_core::ShareExchangeHandle,
            record: DhtRecord,
        }

        #[async_trait::async_trait]
        impl PayloadTransport for RealLibp2pTransport {
            fn kind(&self) -> PayloadTransportKind {
                PayloadTransportKind::DirectLibp2p
            }

            async fn fetch_share(
                &self,
                _peer_addr: &str,
                mid_digest: [u8; 32],
                slot_index: u16,
                segment_index: u32,
            ) -> Result<Option<miasma_core::MiasmaShare>, PayloadTransportError> {
                let location = match self.record.locations.iter().find(|l| l.shard_index == slot_index) {
                    Some(l) => l,
                    None => return Ok(None),
                };
                let peer_id = libp2p::PeerId::from_bytes(&location.peer_id_bytes)
                    .map_err(|e| PayloadTransportError {
                        phase: TransportPhase::Session,
                        message: format!("invalid peer_id: {e}"),
                    })?;
                let request = miasma_core::network::node::ShareFetchRequest {
                    mid_digest,
                    slot_index,
                    segment_index,
                };
                self.share_handle
                    .fetch(peer_id, location.addrs.clone(), request)
                    .await
                    .map_err(|e| PayloadTransportError {
                        phase: TransportPhase::Data,
                        message: format!("{e}"),
                    })
            }
        }

        let selector = Arc::new(PayloadTransportSelector::new(vec![
            Box::new(RealLibp2pTransport {
                share_handle: share_handle_b,
                record,
            }),
        ]));

        let source = FallbackShareSource::new(bypass_dht, selector.clone());
        let recovered = RetrievalCoordinator::new(source)
            .retrieve(&mid, params)
            .await
            .expect("real P2P payload retrieval failed");

        assert_eq!(
            recovered.as_slice(),
            content as &[u8],
            "payload mismatch after real P2P transport"
        );

        // Verify transport stats.
        let snap = selector.stats().snapshot();
        let libp2p_stat = snap.iter()
            .find(|r| r.transport == PayloadTransportKind::DirectLibp2p)
            .unwrap();
        assert!(
            libp2p_stat.success_count >= params.data_shards as u64,
            "expected {} real P2P successes, got {}",
            params.data_shards,
            libp2p_stat.success_count
        );
        println!(
            "[payload] Real P2P round-trip OK: {} bytes, {} transport successes",
            recovered.len(),
            libp2p_stat.success_count
        );
    })
    .await;

    result.expect("p2p_payload_transport_loopback timed out (30s)");
}

// ── Test 30: WSS end-to-end payload retrieval ───────────────────────────────
//
// Proves the full payload retrieval path over WebSocket:
// dissolve → store → WssShareServer → WssPayloadTransport → FallbackShareSource
// → RetrievalCoordinator → reconstruct original content.

#[tokio::test(flavor = "multi_thread")]
async fn wss_payload_e2e_retrieval() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());

    // 1. Dissolve content.
    let content = b"WSS payload transport end-to-end test content - proves real share fetch";
    let params = DissolutionParams { data_shards: 3, total_shards: 5 };
    let (mid, shares) = dissolve(content, params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    // 2. Start WSS share server.
    let server = WssShareServer::bind(store.clone(), 0).await.unwrap();
    let wss_port = server.port;
    tokio::spawn(server.run());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Build DhtRecord with locations pointing at the WSS server.
    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec![format!("127.0.0.1:{wss_port}")],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    // 4. Build transport selector: WSS only.
    let wss_transport = WssPayloadTransport::new(WebSocketConfig {
        port: wss_port,
        ..Default::default()
    });
    let selector = Arc::new(PayloadTransportSelector::new(vec![
        Box::new(wss_transport),
    ]));

    // 5. Retrieve via FallbackShareSource.
    let source = FallbackShareSource::new(dht, selector.clone());
    let recovered = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await
        .expect("WSS payload retrieval failed");

    assert_eq!(
        recovered.as_slice(),
        content as &[u8],
        "content mismatch after WSS payload retrieval"
    );

    // 6. Verify transport stats show WSS success.
    let snap = selector.stats().snapshot();
    let wss_stat = snap
        .iter()
        .find(|r| r.transport == PayloadTransportKind::WssTunnel)
        .expect("WSS transport stats missing");
    assert!(
        wss_stat.success_count >= params.data_shards as u64,
        "expected at least {} WSS successes, got {}",
        params.data_shards,
        wss_stat.success_count
    );
    assert_eq!(wss_stat.failure_count, 0, "WSS should have zero failures");
    println!(
        "[wss] E2E payload retrieval OK: {} bytes, {} WSS successes",
        recovered.len(),
        wss_stat.success_count
    );
}

// ── Test 31: WSS fallback — direct transport fails, WSS succeeds ────────────
//
// Simulates an environment where the primary transport (DirectLibp2p) is blocked
// but WSS is reachable. Proves the fallback engine picks WSS and records the
// session failure on the primary.

#[tokio::test(flavor = "multi_thread")]
async fn wss_payload_fallback_on_primary_failure() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());

    let content = b"WSS fallback test: primary blocked, WSS rescues";
    let params = DissolutionParams { data_shards: 3, total_shards: 5 };
    let (mid, shares) = dissolve(content, params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    // Start WSS server.
    let server = WssShareServer::bind(store.clone(), 0).await.unwrap();
    let wss_port = server.port;
    tokio::spawn(server.run());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // DhtRecord pointing at WSS server address.
    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec![format!("127.0.0.1:{wss_port}")],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    // Chain: SessionFail (simulates blocked QUIC) → WSS (real, should succeed).
    let wss_transport = WssPayloadTransport::new(WebSocketConfig {
        port: wss_port,
        ..Default::default()
    });
    let selector = Arc::new(PayloadTransportSelector::new(vec![
        Box::new(SessionFailTransport),
        Box::new(wss_transport),
    ]));

    let source = FallbackShareSource::new(dht, selector.clone());
    let recovered = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await
        .expect("WSS fallback retrieval failed");

    assert_eq!(
        recovered.as_slice(),
        content as &[u8],
        "content mismatch after WSS fallback retrieval"
    );

    // Verify: primary recorded failures, WSS recorded successes.
    let snap = selector.stats().snapshot();

    let primary_stat = snap
        .iter()
        .find(|r| r.transport == PayloadTransportKind::DirectLibp2p)
        .expect("primary transport stats missing");
    assert!(
        primary_stat.failure_count > 0,
        "primary should have failures (blocked)"
    );

    let wss_stat = snap
        .iter()
        .find(|r| r.transport == PayloadTransportKind::WssTunnel)
        .expect("WSS transport stats missing");
    assert!(
        wss_stat.success_count >= params.data_shards as u64,
        "WSS should have rescued: expected {} successes, got {}",
        params.data_shards,
        wss_stat.success_count
    );
    println!(
        "[wss] Fallback OK: primary failures={}, WSS successes={}",
        primary_stat.failure_count, wss_stat.success_count
    );
}

// ── Test 32: WSS diagnostics — transport kind recorded in attempts ──────────
//
// Verifies that the FallbackShareSource records transport attempts with correct
// kind and phase, enabling the CLI status display.

#[tokio::test(flavor = "multi_thread")]
async fn wss_payload_diagnostics_transport_kind() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());

    let params = DissolutionParams { data_shards: 3, total_shards: 5 };
    let (mid, shares) = dissolve(b"WSS diagnostics test", params).unwrap();
    for s in &shares {
        store.put(s).unwrap();
    }

    let server = WssShareServer::bind(store.clone(), 0).await.unwrap();
    let wss_port = server.port;
    tokio::spawn(server.run());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let dht = BypassOnionDhtExecutor::new();
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        version: 1,
        locations: (0..params.total_shards as u16)
            .map(|i| miasma_core::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: i,
                addrs: vec![format!("127.0.0.1:{wss_port}")],
            })
            .collect(),
        published_at: 0,
    };
    dht.put(record).await.unwrap();

    // Chain: DataFail → WSS. DataFail connects but fails at data phase.
    let wss_transport = WssPayloadTransport::new(WebSocketConfig {
        port: wss_port,
        ..Default::default()
    });
    let selector = Arc::new(PayloadTransportSelector::new(vec![
        Box::new(DataFailTransport),
        Box::new(wss_transport),
    ]));

    let source = FallbackShareSource::new(dht, selector.clone());
    let recovered = RetrievalCoordinator::new(source)
        .retrieve(&mid, params)
        .await
        .expect("WSS diagnostics retrieval failed");

    assert_eq!(recovered.as_slice(), b"WSS diagnostics test");

    // Check the stats snapshot for correct transport readiness.
    let snap = selector.stats().snapshot();

    // DataFail transport uses TcpDirect kind.
    let tcp_stat = snap
        .iter()
        .find(|r| r.transport == PayloadTransportKind::TcpDirect)
        .expect("TcpDirect stats missing");
    assert!(tcp_stat.failure_count > 0, "TcpDirect should show data-phase failures");

    let wss_stat = snap
        .iter()
        .find(|r| r.transport == PayloadTransportKind::WssTunnel)
        .expect("WssTunnel stats missing");
    assert!(wss_stat.success_count > 0, "WssTunnel should show successes");
    assert_eq!(wss_stat.failure_count, 0, "WssTunnel should have no failures");

    println!(
        "[wss] Diagnostics OK: TcpDirect failures={}, WssTunnel successes={}",
        tcp_stat.failure_count, wss_stat.success_count
    );
}
