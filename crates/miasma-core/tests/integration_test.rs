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
    LocalShareSource,
    LocalShareStore,
    MiasmaError,
    RetrievalCoordinator,
    // DHT
    BypassOnionDhtExecutor,
    LiveOnionDhtExecutor,
    OnionAwareDhtExecutor,
    DEFAULT_SEGMENT_SIZE,
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
