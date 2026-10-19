//! Daemon wiring for autonomous piece maintenance.
//!
//! The decision logic lives in [`crate::repair`]; this file connects it to a
//! running node:
//!
//! * [`CoordinatorBackend`] implements [`MaintenanceBackend`] over the node's
//!   DHT handle, share-exchange handle and local share store: holder probes are
//!   ordinary share fetches verified against the piece, replicas travel over
//!   the same share-push path publishing uses, and the updated record is
//!   re-announced with its transfer manifest preserved.
//! * [`start`] launches the loop with the daemon and returns a
//!   [`MaintenanceTask`] the daemon stops on shutdown.
//! * [`cancel_for`] stops the loop for a data directory immediately; the
//!   distress-wipe path calls it before any key material is erased.
//!
//! Only records this node itself published are maintained: the replacement
//! record must be signed by the same key as the original.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use async_trait::async_trait;
use libp2p::PeerId;
use tokio::sync::watch;
use tracing::{debug, warn};

use super::replication::ReplicationQueue;
use crate::{
    crypto::hash::ContentId,
    network::{
        coordinator::MiasmaCoordinator,
        node::{ShareFetchRequest, StoreResponse},
        types::{DhtRecord, ShardLocation},
    },
    repair::{
        executor::{
            spawn_executor, ExecutorHandle, MaintenanceBackend, MaintenanceConfig, ProbeResult,
        },
        failure_domain_for_addrs, Candidate, ProbeOutcome, SystemClock,
    },
    share::{MiasmaShare, ShareVerification},
    store::LocalShareStore,
};

/// How long one holder probe or source fetch may take.
const REMOTE_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

// ─── Record source ───────────────────────────────────────────────────────────

/// Where the maintained records come from and where updated ones are kept.
pub trait RecordSource: Send + Sync {
    /// Every record this node is responsible for.
    fn records(&self) -> Vec<DhtRecord>;
    /// Store the updated record for its MID.
    fn replace(&self, record: DhtRecord);

    /// The record kept for `mid_digest`, if any.
    fn find(&self, mid_digest: &[u8; 32]) -> Option<DhtRecord> {
        self.records()
            .into_iter()
            .find(|r| &r.mid_digest == mid_digest)
    }

    /// Keep a rewritten record whose announce is not confirmed yet, so that it
    /// survives a restart and is announced again. Defaults to [`replace`](Self::replace).
    fn stage(&self, record: DhtRecord) {
        self.replace(record);
    }
}

/// The daemon's replication queue as a record source. Replacing a record keeps
/// the item's replication state untouched, so maintenance never schedules a
/// manifest-less re-announce of its own.
pub struct QueueRecordSource(pub Arc<Mutex<ReplicationQueue>>);

impl RecordSource for QueueRecordSource {
    fn records(&self) -> Vec<DhtRecord> {
        match self.0.lock() {
            Ok(q) => q.all_items().map(|i| i.record.clone()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn replace(&self, record: DhtRecord) {
        if let Ok(mut q) = self.0.lock() {
            if let Err(e) = q.update_record(record) {
                warn!("maintenance: could not persist updated record: {e}");
            }
        }
    }

    fn find(&self, mid_digest: &[u8; 32]) -> Option<DhtRecord> {
        self.0
            .lock()
            .ok()?
            .get(mid_digest)
            .map(|i| i.record.clone())
    }

    fn stage(&self, record: DhtRecord) {
        if let Ok(mut q) = self.0.lock() {
            if let Err(e) = q.update_record_and_requeue(record) {
                warn!("maintenance: could not persist staged record: {e}");
            }
        }
    }
}

/// In-memory record source for embedders and tests.
#[derive(Default)]
pub struct MemoryRecordSource(Mutex<Vec<DhtRecord>>);

impl MemoryRecordSource {
    pub fn new(records: Vec<DhtRecord>) -> Self {
        Self(Mutex::new(records))
    }
}

impl RecordSource for MemoryRecordSource {
    fn records(&self) -> Vec<DhtRecord> {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn replace(&self, record: DhtRecord) {
        if let Ok(mut g) = self.0.lock() {
            match g.iter_mut().find(|r| r.mid_digest == record.mid_digest) {
                Some(slot) => *slot = record,
                None => g.push(record),
            }
        }
    }
}

// ─── Backend over the live node ──────────────────────────────────────────────

pub struct CoordinatorBackend {
    coord: Arc<MiasmaCoordinator>,
    store: Arc<LocalShareStore>,
    source: Arc<dyn RecordSource>,
    metered: Arc<AtomicBool>,
}

impl CoordinatorBackend {
    pub fn new(
        coord: Arc<MiasmaCoordinator>,
        store: Arc<LocalShareStore>,
        source: Arc<dyn RecordSource>,
    ) -> Self {
        Self {
            coord,
            store,
            source,
            metered: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Flag a metered link: while set, maintenance does no background traffic.
    pub fn metered_flag(&self) -> Arc<AtomicBool> {
        self.metered.clone()
    }

    /// The node's own verified copy of a piece, if it keeps one.
    fn local_copy(&self, mid: &ContentId, segment: u32, slot: u16) -> Option<MiasmaShare> {
        let address = self.store.find_piece(&mid.prefix(), segment, slot)?;
        let share = self.store.get_untouched(&address).ok()?;
        piece_matches(&share, mid, segment, slot).then_some(share)
    }

    /// The record this node published for `mid`, with its manifest, if any.
    ///
    /// The DHT store of the running node is in memory only: after a restart it
    /// is empty until something announces the record again, and a record that
    /// is already `Replicated` is not announced again. The record source (the
    /// replication queue, persisted and written only by this node's own
    /// publishes) is therefore the fallback; its records carry no manifest,
    /// because they are announced without one.
    ///
    /// A record in the local DHT store must be signed by this node's own key;
    /// without a signing key nothing can be called "own", so nothing is.
    async fn own_record(
        &self,
        mid: [u8; 32],
    ) -> Result<(DhtRecord, Option<crate::transfer::TransferManifest>), String> {
        let dht = self.coord.dht_handle();
        let own_key = dht
            .publisher_key()
            .ok_or("no record-signing key; cannot tell which records are this node's own")?;
        match dht.local_record_value(mid).await {
            Some(envelope) => {
                let found = crate::transfer::open_signed_record(&mid, &envelope, Some(&own_key))
                    .map_err(|e| format!("current record unusable: {e:?}"))?;
                Ok((found.record, found.manifest))
            }
            None => self
                .source
                .find(&mid)
                .map(|record| (record, None))
                .ok_or_else(|| "own record not found; refusing to rewrite it".to_string()),
        }
    }

    async fn fetch_from(
        &self,
        location: &ShardLocation,
        mid_digest: [u8; 32],
    ) -> Result<Option<MiasmaShare>, ()> {
        let peer = PeerId::from_bytes(&location.peer_id_bytes).map_err(|_| ())?;
        let request = ShareFetchRequest {
            mid_digest,
            slot_index: location.shard_index,
            segment_index: location.segment_index,
        };
        let fetch = self
            .coord
            .share_exchange_handle()
            .fetch(peer, location.addrs.clone(), request);
        match tokio::time::timeout(REMOTE_FETCH_TIMEOUT, fetch).await {
            Ok(Ok(share)) => Ok(share),
            _ => Err(()),
        }
    }
}

/// Is `share` exactly the piece `(mid, segment, slot)`, with an intact hash?
fn piece_matches(share: &MiasmaShare, mid: &ContentId, segment: u32, slot: u16) -> bool {
    share.slot_index == slot
        && share.segment_index == segment
        && ShareVerification::coarse_verify(share, mid)
}

fn share_bytes(share: &MiasmaShare) -> u64 {
    (share.shard_data.len() + share.key_share.len()) as u64
}

#[async_trait]
impl MaintenanceBackend for CoordinatorBackend {
    async fn tracked_records(&self) -> Vec<DhtRecord> {
        self.source.records()
    }

    async fn probe(&self, location: &ShardLocation, mid_digest: &[u8; 32]) -> ProbeResult {
        let mid = ContentId::from_digest(*mid_digest);
        let (segment, slot) = (location.segment_index, location.shard_index);
        let reference = self.local_copy(&mid, segment, slot);

        // A location that names this very node is checked against the store.
        if location.peer_id_bytes == self.coord.local_peer_bytes() {
            let outcome = if reference.is_some() {
                ProbeOutcome::Verified
            } else {
                ProbeOutcome::Unverifiable
            };
            return ProbeResult { outcome, bytes: 0 };
        }

        match self.fetch_from(location, *mid_digest).await {
            Err(()) => ProbeResult {
                outcome: ProbeOutcome::Unreachable,
                bytes: 0,
            },
            Ok(None) => ProbeResult {
                outcome: ProbeOutcome::Unverifiable,
                bytes: 0,
            },
            Ok(Some(share)) => {
                // With a local reference, every field that decides usability
                // (key share, nonce, length) must match, not only the hash.
                let genuine = piece_matches(&share, &mid, segment, slot)
                    && reference
                        .as_ref()
                        .is_none_or(|r| r.piece_commitment(&mid) == share.piece_commitment(&mid));
                ProbeResult {
                    outcome: if genuine {
                        ProbeOutcome::Verified
                    } else {
                        ProbeOutcome::Unverifiable
                    },
                    bytes: share_bytes(&share),
                }
            }
        }
    }

    async fn source_share(
        &self,
        record: &DhtRecord,
        segment: u32,
        slot: u16,
        live_holders: &[ShardLocation],
    ) -> Option<MiasmaShare> {
        let mid = ContentId::from_digest(record.mid_digest);
        if let Some(local) = self.local_copy(&mid, segment, slot) {
            return Some(local);
        }
        let own = self.coord.local_peer_bytes();
        for holder in live_holders.iter().filter(|h| h.peer_id_bytes != own) {
            if let Ok(Some(share)) = self.fetch_from(holder, record.mid_digest).await {
                if piece_matches(&share, &mid, segment, slot) {
                    return Some(share);
                }
            }
        }
        None
    }

    async fn candidates(&self, exclude: &[String]) -> Vec<Candidate> {
        let exclude_ids: Vec<PeerId> = exclude
            .iter()
            .filter_map(|s| PeerId::from_str(s).ok())
            .collect();
        let dht = self.coord.dht_handle();
        let Ok(ranked) = dht.select_storage_candidates(exclude_ids).await else {
            return Vec::new();
        };
        let addrs: HashMap<PeerId, Vec<String>> = dht
            .connected_peers()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(p, a)| (p, a.iter().map(|m| m.to_string()).collect()))
            .collect();
        ranked
            .into_iter()
            .map(|peer| Candidate {
                failure_domain: addrs.get(&peer).and_then(|a| failure_domain_for_addrs(a)),
                peer_id: peer.to_string(),
            })
            .collect()
    }

    async fn push(
        &self,
        candidate: &Candidate,
        share: &MiasmaShare,
    ) -> Result<ShardLocation, String> {
        let peer = PeerId::from_str(&candidate.peer_id).map_err(|e| e.to_string())?;
        match self
            .coord
            .dht_handle()
            .store_share_on_peer(peer, share.clone())
            .await
            .map_err(|e| e.to_string())?
        {
            StoreResponse::Accepted {
                advertised_addrs, ..
            } => Ok(ShardLocation {
                peer_id_bytes: peer.to_bytes(),
                shard_index: share.slot_index,
                segment_index: share.segment_index,
                addrs: advertised_addrs,
            }),
            StoreResponse::Rejected(reason) => Err(format!("holder rejected the share: {reason}")),
        }
    }

    async fn verify_record(&self, record: &DhtRecord) -> Result<(), String> {
        let (current, _) = self.own_record(record.mid_digest).await?;
        if current.data_shards != record.data_shards || current.total_shards != record.total_shards
        {
            return Err("k/n differ from the published record".into());
        }
        Ok(())
    }

    async fn stage_record(&self, updated: &DhtRecord) -> Result<(), String> {
        let (_, manifest) = self.own_record(updated.mid_digest).await?;
        if manifest.is_some() {
            // A queued re-announce would carry no manifest: only keep the
            // record; the commit announces it with the manifest.
            self.source.replace(updated.clone());
        } else {
            self.source.stage(updated.clone());
        }
        Ok(())
    }

    async fn commit_record(&self, updated: DhtRecord) -> Result<(), String> {
        let mid = updated.mid_digest;
        // The manifest of the current record must travel with the new one:
        // re-announcing without it would turn a protected transfer into a
        // legacy one. If the record cannot be read, refuse instead of guessing.
        let (current, manifest) = self.own_record(mid).await?;
        if current.data_shards != updated.data_shards
            || current.total_shards != updated.total_shards
        {
            return Err("refusing to change k/n of a published record".into());
        }

        self.coord
            .dht_handle()
            .put_with_manifest(updated.clone(), manifest.as_ref())
            .await
            .map_err(|e| e.to_string())?;
        self.source.replace(updated);
        Ok(())
    }

    async fn link_allows_background(&self) -> bool {
        !self.metered.load(Ordering::Relaxed)
    }
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

type CancelRegistry = Mutex<HashMap<PathBuf, watch::Sender<bool>>>;

fn registry() -> &'static CancelRegistry {
    static REGISTRY: OnceLock<CancelRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The running maintenance loop of one daemon.
pub struct MaintenanceTask {
    handle: ExecutorHandle,
    data_dir: PathBuf,
}

impl MaintenanceTask {
    /// Stop the loop (cancelling a pass in flight) and wait for it to end.
    pub async fn stop(self) {
        if let Ok(mut r) = registry().lock() {
            r.remove(&self.data_dir);
        }
        self.handle.stop().await;
    }
}

/// Stop the maintenance loop of the daemon using `data_dir`, if any. Safe to
/// call from any thread, repeatedly, and when no loop is running.
pub fn cancel_for(data_dir: &Path) {
    if let Ok(r) = registry().lock() {
        if let Some(tx) = r.get(data_dir) {
            let _ = tx.send(true);
            debug!("maintenance cancelled");
        }
    }
}

/// Start autonomous maintenance for a running daemon.
pub fn start(
    coord: Arc<MiasmaCoordinator>,
    store: Arc<LocalShareStore>,
    queue: Arc<Mutex<ReplicationQueue>>,
    data_dir: &Path,
) -> MaintenanceTask {
    let backend = Arc::new(CoordinatorBackend::new(
        coord,
        store,
        Arc::new(QueueRecordSource(queue)),
    ));
    let handle = spawn_executor(backend, MaintenanceConfig::default(), Arc::new(SystemClock));
    if let Ok(mut r) = registry().lock() {
        r.insert(data_dir.to_path_buf(), handle.cancel_signal());
    }
    MaintenanceTask {
        handle,
        data_dir: data_dir.to_path_buf(),
    }
}
