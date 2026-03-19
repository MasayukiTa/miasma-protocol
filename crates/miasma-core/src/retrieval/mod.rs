/// Content retrieval pipeline — Task 6.
///
/// # Retrieval flow
/// ```text
/// RetrievalCoordinator::retrieve(mid, params)
///   ├─ ShareSource::list_candidates(mid.prefix())
///   │    Phase 1: LocalShareSource → LocalShareStore::search_by_mid_prefix()
///   │    Phase 2: DhtShareSource → DHT record lookup + onion-routed peer fetch
///   ├─ shuffle(candidates)           ← random order, prevents timing correlation
///   ├─ for each addr (shuffled):
///   │    fetch(addr) → MiasmaShare
///   │    coarse_verify(share, mid)   ← reject forgeries before K_enc available
///   │    stop when k valid shares collected
///   └─ pipeline::retrieve(mid, valid_shares, params)
///        RS decode → SSS combine → AES-256-GCM decrypt → BLAKE3 verify
///
/// RetrievalCoordinator::retrieve_file(manifest)
///   └─ collect_segment_from_candidates() per segment → dissolution::retrieve_file()
/// ```
///
/// # Security properties (Task 6 checklist)
/// - **偽造Share検出と拒否**: `ShareVerification::coarse_verify` rejects shares
///   with mismatched `mid_prefix` or `shard_hash` before K_enc is available.
///   Full MAC verification (BLAKE3 of plaintext vs MID) runs after reconstruction.
/// - **平文コンテンツのディスク書き込み禁止**: `retrieve()` and `retrieve_file()`
///   return `Vec<u8>`. The plaintext never touches disk — the caller is responsible
///   for deciding persistence (Phase 1 scope: in-memory only, ≤1 GB).
/// - **ランダム順収集**: `shuffle()` before fetching ensures a passive observer
///   cannot correlate request timing to shard indices.
/// - **k個受信で停止**: Collection loop breaks immediately once k valid shares
///   are found, minimising information exposure.
pub mod coordinator;
pub mod dht_source;
pub mod source;
pub mod streaming;
pub mod transport_source;

pub use coordinator::RetrievalCoordinator;
pub use dht_source::DhtShareSource;
pub use source::{LocalShareSource, ShareSource};
pub use streaming::StreamingRetrievalCoordinator;
pub use transport_source::FallbackShareSource;
