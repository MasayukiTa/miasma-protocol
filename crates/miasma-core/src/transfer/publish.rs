//! The send engine: a file publish that reports progress and can be resumed.
//!
//! This is the streaming publish (read a segment, encrypt + Reed-Solomon + Shamir
//! it, store it, offer it to peers) with three additions:
//!
//! * progress you can read while it runs;
//! * a journal, so a publish that was stopped — cancel, crash, out of disk —
//!   continues from the last finished segment instead of starting over;
//! * cancellation at a safe point.
//!
//! With no journal directory it behaves exactly as the old blocking publish did,
//! and `MiasmaCoordinator::dissolve_and_publish_file*` now delegate here.
//!
//! What a resume trusts: nothing it has not checked. The source file must have
//! the same length and modification time; every already-finished segment is
//! re-read and compared with its recorded hash; and its pieces must still be in
//! the local store. The first segment that fails any check, and everything after
//! it, is done again.

use std::{
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, UNIX_EPOCH},
};

use zeroize::Zeroizing;

use super::{
    manifest::{SegmentEntry, TransferManifest},
    progress::{Phase, TransferProgress, TransferState},
    protection::{PasswordProtection, Protection, UnlockedKey},
    publish_journal::{
        publish_journal_path, PublishHeader, PublishJournal, PublishSegmentRecord,
        PUBLISH_JOURNAL_VERSION,
    },
};
use crate::{
    crypto::hash::ContentId,
    dissolution::{segment::dissolve_segment_with, DEFAULT_SEGMENT_SIZE},
    network::{
        coordinator::{estimated_local_share_storage_bytes, max_segment_size_for},
        types::{DhtRecord, ShardLocation},
        MiasmaCoordinator, PublishOptions, PublishReport,
    },
    pipeline::DissolutionParams,
    MiasmaError,
};

pub struct PublishSpec {
    pub file_path: PathBuf,
    pub params: DissolutionParams,
    pub options: PublishOptions,
    pub password: Option<Zeroizing<String>>,
    /// Where the journal lives. `None` disables journalling (and so resume).
    pub journal_dir: Option<PathBuf>,
    /// Ignore any journal and start again from the beginning.
    pub restart: bool,
}

#[derive(Debug)]
pub enum PublishOutcome {
    Complete(PublishReport),
    /// Stopped with the journal kept; running the same publish resumes it.
    Paused {
        next_segment: u32,
        reason: String,
    },
    Cancelled {
        next_segment: u32,
    },
}

/// What a verified journal hands the resumed run.
struct Resumed {
    header: PublishHeader,
    records: Vec<PublishSegmentRecord>,
    key: Option<Arc<UnlockedKey>>,
}

fn mtime_parts(meta: &std::fs::Metadata) -> (u64, u32) {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or((0, 0), |d| (d.as_secs(), d.subsec_nanos()))
}

impl MiasmaCoordinator {
    /// Publish a file, with progress, cancellation and (given a journal
    /// directory) resume. See the module documentation.
    pub async fn publish_file_job(
        &self,
        spec: PublishSpec,
        progress: Option<Arc<TransferProgress>>,
    ) -> Result<PublishOutcome, MiasmaError> {
        let progress = progress
            .unwrap_or_else(|| TransferProgress::for_send(spec.file_path.to_string_lossy()));
        let journal = spec
            .journal_dir
            .as_ref()
            .map(|d| publish_journal_path(d, &spec.file_path));

        let result = self.run_publish(spec, &progress).await;
        let journal_kept = journal.as_ref().is_some_and(|p| p.exists());
        match &result {
            Ok(PublishOutcome::Complete(_)) => {
                progress.set_state(TransferState::Complete, None, false)
            }
            Ok(PublishOutcome::Paused { reason, .. }) => {
                progress.set_state(TransferState::Paused, Some(reason.clone()), journal_kept)
            }
            Ok(PublishOutcome::Cancelled { .. }) => {
                progress.set_state(TransferState::Cancelled, None, journal_kept)
            }
            Err(e) => progress.set_state(TransferState::Failed, Some(e.to_string()), journal_kept),
        }
        result
    }

    async fn run_publish(
        &self,
        spec: PublishSpec,
        progress: &Arc<TransferProgress>,
    ) -> Result<PublishOutcome, MiasmaError> {
        let PublishSpec {
            file_path,
            params,
            options,
            password,
            journal_dir,
            restart,
        } = spec;

        if password.as_ref().is_some_and(|p| p.is_empty()) {
            return Err(MiasmaError::InvalidManifest(
                "an empty password would protect nothing; refusing".into(),
            ));
        }
        progress.set_name(file_path.to_string_lossy());
        progress.set_phase(Phase::Preparing);

        let file = std::fs::File::open(&file_path)?;
        let meta = file.metadata()?;
        let file_len = meta.len();
        let (mtime_secs, mtime_nanos) = mtime_parts(&meta);

        // A streaming publish still needs durable storage for the n generated
        // shares. Refuse before doing any work if this file cannot fit in the
        // owned-share budget; otherwise LRU eviction could delete earlier
        // segments of the same publish and still leave a normal-looking record.
        let required_bytes = estimated_local_share_storage_bytes(file_len, params)?;
        let quota_bytes = self.share_store().owned_quota_bytes();
        if required_bytes > quota_bytes {
            return Err(MiasmaError::Storage(format!(
                "file publish requires approximately {} MiB of owned-share quota for k={}, n={} redundancy, but storage.quota_mb provides {} MiB; increase storage.quota_mb before publishing this file",
                required_bytes.div_ceil(1024 * 1024),
                params.data_shards,
                params.total_shards,
                quota_bytes / (1024 * 1024)
            )));
        }

        // Clamp against the share-exchange wire cap for small data_shards counts.
        let segment_size = DEFAULT_SEGMENT_SIZE.min(max_segment_size_for(params.data_shards));
        let segment_count: u32 = if file_len == 0 {
            1
        } else {
            file_len.div_ceil(segment_size as u64) as u32
        };
        progress.set_totals(segment_count, file_len);

        let journal_path = journal_dir
            .as_ref()
            .map(|d| publish_journal_path(d, &file_path));
        let path_string = file_path.to_string_lossy().into_owned();

        // ── Resume, if there is a journal we can trust. ─────────────────────
        let mut resumed: Option<Resumed> = None;
        if let (Some(jp), false) = (&journal_path, restart) {
            if let Some(journal) = PublishJournal::load(jp) {
                let h = &journal.header;
                let same_job = h.path == path_string
                    && h.file_len == file_len
                    && h.mtime_secs == mtime_secs
                    && h.mtime_nanos == mtime_nanos
                    && h.data_shards == params.data_shards as u8
                    && h.total_shards == params.total_shards as u8
                    && h.segment_size == segment_size as u32
                    && h.protection.is_password() == password.is_some();
                if same_job {
                    resumed = self
                        .verify_resume(
                            journal,
                            jp,
                            &file_path,
                            password.as_ref().map(|p| p.as_str()),
                            progress,
                        )
                        .await?;
                }
            }
        }

        // ── The MID, the protection and the journal header. ─────────────────
        let (mid, protection, key) = match &resumed {
            Some(r) => (
                ContentId::from_str(&r.header.mid)?,
                r.header.protection.clone(),
                r.key.clone(),
            ),
            None => {
                // A new protected transfer needs a password that meets the
                // policy; refuse now, before hashing the whole file. (A
                // resumed publish keeps the protection it already has.)
                if let Some(pw) = password.as_ref() {
                    super::password_policy::check(pw.as_str())
                        .map_err(MiasmaError::WeakPassword)?;
                }
                progress.set_phase(Phase::Hashing);
                let Some(mid) = hash_file(&file_path, params, file_len, progress.clone()).await?
                else {
                    return Ok(PublishOutcome::Cancelled { next_segment: 0 });
                };
                let (protection, key) = match password.as_ref().map(|p| p.as_str()) {
                    None => (Protection::None, None),
                    Some(pw) => {
                        let pw = Zeroizing::new(pw.to_owned());
                        let (prot, key) = tokio::task::spawn_blocking(move || {
                            PasswordProtection::create(pw.as_str())
                        })
                        .await
                        .map_err(|e| {
                            MiasmaError::Encryption(format!("password KDF task: {e}"))
                        })??;
                        (Protection::Password(prot), Some(Arc::new(key)))
                    }
                };
                let header = PublishHeader {
                    version: PUBLISH_JOURNAL_VERSION,
                    path: path_string.clone(),
                    file_len,
                    mtime_secs,
                    mtime_nanos,
                    data_shards: params.data_shards as u8,
                    total_shards: params.total_shards as u8,
                    segment_size: segment_size as u32,
                    mid: mid.to_string(),
                    protection: protection.clone(),
                    started_at: super::journal::now_secs(),
                };
                if let Some(jp) = &journal_path {
                    PublishJournal::create(jp, &header)?;
                }
                (mid, protection, key)
            }
        };
        progress.set_mid(mid.to_string());

        // ── Rebuild what the finished segments contributed. ─────────────────
        let mut manifest =
            TransferManifest::new(&mid, params, segment_size as u32, file_len, protection);
        let mut all_locations: Vec<ShardLocation> = Vec::new();
        let mut remote_distinct_per_segment: Vec<usize> = Vec::new();
        let mut start_segment: u32 = 0;
        let mut offset: u64 = 0;
        if let Some(r) = &resumed {
            for rec in &r.records {
                manifest.push_segment(rec.entry.clone())?;
                all_locations.extend(self.locations_for_segment(rec, params));
                remote_distinct_per_segment.push(rec.remote.len());
                offset += rec.entry.plaintext_len as u64;
                start_segment += 1;
            }
        }
        // Also resets the byte counter that hashing/verifying used for its own progress.
        progress.set_resumed(start_segment, offset);

        // ── The publish loop. ───────────────────────────────────────────────
        progress.set_phase(Phase::Transferring);
        let mut reader = std::io::BufReader::new(std::fs::File::open(&file_path)?);
        reader.seek(SeekFrom::Start(offset))?;
        let mut segment_buf = vec![0u8; segment_size];

        for seg in start_segment..segment_count {
            if progress.is_cancelled() {
                return Ok(PublishOutcome::Cancelled { next_segment: seg });
            }

            let expected = (file_len - offset).min(segment_size as u64) as usize;
            let mut filled = 0;
            while filled < expected {
                let n = reader.read(&mut segment_buf[filled..expected])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled != expected {
                return Err(MiasmaError::InvalidManifest(format!(
                    "source file changed while publishing: segment {seg} expected {expected} bytes, read {filled}"
                )));
            }
            let chunk = &segment_buf[..filled];

            let dissolve_started = Instant::now();
            let (_meta, shares) =
                dissolve_segment_with(chunk, &mid, seg, offset, params, key.as_deref())?;
            manifest.push_segment(SegmentEntry::from_dissolved(seg, &mid, chunk, &shares)?)?;
            let dissolve_time = dissolve_started.elapsed();
            let entry = manifest.segments[seg as usize].clone();

            let push_started = Instant::now();
            let stored = self.store_locally_and_distribute(shares, params).await;
            let (mut locations, remote_distinct) = match stored {
                Ok(v) => v,
                // Out of disk or similar: keep the journal; resuming after the
                // condition clears is the point.
                Err(MiasmaError::Io(e)) => {
                    return Ok(PublishOutcome::Paused {
                        next_segment: seg,
                        reason: format!("cannot store segment {seg}: {e}"),
                    })
                }
                Err(MiasmaError::Storage(m)) => {
                    return Ok(PublishOutcome::Paused {
                        next_segment: seg,
                        reason: format!("cannot store segment {seg}: {m}"),
                    })
                }
                Err(e) => return Err(e),
            };
            let push_time = push_started.elapsed();
            if remote_distinct < options.min_remote_distinct_shards {
                return Err(MiasmaError::InsufficientShares {
                    need: options.min_remote_distinct_shards,
                    got: remote_distinct,
                });
            }

            // Journal only what cannot be rebuilt: pieces another peer holds.
            if let Some(jp) = &journal_path {
                let me = self.local_peer_bytes();
                let remote: Vec<ShardLocation> = locations
                    .iter()
                    .filter(|l| l.peer_id_bytes != me)
                    .cloned()
                    .collect();
                PublishJournal::append(jp, &PublishSegmentRecord { entry, remote })?;
            }

            all_locations.append(&mut locations);
            remote_distinct_per_segment.push(remote_distinct);
            offset += filled as u64;

            progress.on_segment_done(filled as u64, push_time, dissolve_time, Duration::ZERO);
        }

        // ── Announce. ───────────────────────────────────────────────────────
        progress.set_phase(Phase::Finalizing);
        // The manifest must describe exactly the bytes that were dissolved.
        manifest.validate().map_err(|e| {
            MiasmaError::InvalidManifest(format!(
                "source file changed while publishing, or manifest inconsistent: {e}"
            ))
        })?;
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations: all_locations,
            published_at: std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        self.dht_handle()
            .put_with_manifest(record, Some(&manifest))
            .await?;
        if let Some(jp) = &journal_path {
            PublishJournal::remove(jp);
        }

        tracing::info!(
            "Published {} ({file_len} bytes, {segment_count} segments) via streaming dissolution",
            mid.to_string()
        );
        Ok(PublishOutcome::Complete(PublishReport {
            mid,
            remote_distinct_shards_per_segment: remote_distinct_per_segment,
        }))
    }

    /// Locations for one already-finished segment: the pieces another peer
    /// accepted keep the address that peer announced; every other slot is a local
    /// copy announced at *this* daemon's current addresses.
    fn locations_for_segment(
        &self,
        rec: &PublishSegmentRecord,
        params: DissolutionParams,
    ) -> Vec<ShardLocation> {
        let me = self.local_peer_bytes();
        let addrs = self.local_announce_addrs();
        (0..params.total_shards as u16)
            .map(|slot| {
                rec.remote
                    .iter()
                    .find(|l| l.shard_index == slot)
                    .cloned()
                    .unwrap_or_else(|| ShardLocation {
                        peer_id_bytes: me.clone(),
                        shard_index: slot,
                        segment_index: rec.entry.index,
                        addrs: addrs.clone(),
                    })
            })
            .collect()
    }

    /// Check a journal against reality; return the part of it that is still good.
    async fn verify_resume(
        &self,
        journal: PublishJournal,
        journal_path: &std::path::Path,
        file_path: &std::path::Path,
        password: Option<&str>,
        progress: &Arc<TransferProgress>,
    ) -> Result<Option<Resumed>, MiasmaError> {
        // The password comes first: a wrong one must fail before any work.
        let key = match (&journal.header.protection, password) {
            (Protection::Password(prot), Some(pw)) => {
                let prot = prot.clone();
                let pw = Zeroizing::new(pw.to_owned());
                let unlocked = tokio::task::spawn_blocking(move || prot.unlock(pw.as_str()))
                    .await
                    .map_err(|e| MiasmaError::Decryption(format!("password KDF task: {e}")))??;
                Some(Arc::new(unlocked))
            }
            (Protection::Password(_), None) => return Err(MiasmaError::PasswordRequired),
            _ => None,
        };

        progress.set_phase(Phase::Verifying);
        let mid = ContentId::from_str(&journal.header.mid)?;
        let prefix = mid.prefix();
        let n = journal.header.total_shards;
        let seg_size = journal.header.segment_size as u64;
        let records = journal.segments.clone();
        let store = self.share_store().clone();
        let path = file_path.to_path_buf();
        let prog = progress.clone();

        let good = tokio::task::spawn_blocking(move || -> Result<usize, MiasmaError> {
            let mut f = std::fs::File::open(&path)?;
            let mut buf = vec![0u8; seg_size as usize];
            let mut verified_bytes = 0u64;
            for (i, rec) in records.iter().enumerate() {
                let len = rec.entry.plaintext_len as usize;
                f.seek(SeekFrom::Start(i as u64 * seg_size))?;
                if f.read_exact(&mut buf[..len]).is_err() {
                    return Ok(i);
                }
                if *blake3::hash(&buf[..len]).as_bytes() != rec.entry.plain_hash {
                    return Ok(i);
                }
                // Every share of the segment was stored locally when it was made.
                let all_present = (0..n as u16)
                    .all(|slot| store.find_piece(&prefix, rec.entry.index, slot).is_some());
                if !all_present {
                    return Ok(i);
                }
                verified_bytes += len as u64;
                prog.set_verified_bytes(verified_bytes);
            }
            Ok(records.len())
        })
        .await
        .map_err(|e| MiasmaError::Storage(format!("verify task: {e}")))??;

        if good < journal.segments.len() {
            journal.truncate_to(journal_path, good)?;
        }
        Ok(Some(Resumed {
            header: journal.header,
            records: journal.segments.into_iter().take(good).collect(),
            key,
        }))
    }
}

/// The MID of the file at `path`, read once, reporting progress. Same value as
/// `ContentId::compute_from_reader`: the content bytes, then the parameters.
async fn hash_file(
    path: &std::path::Path,
    params: DissolutionParams,
    file_len: u64,
    progress: Arc<TransferProgress>,
) -> Result<Option<ContentId>, MiasmaError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<Option<ContentId>, MiasmaError> {
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut done = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            done += n as u64;
            progress.set_verified_bytes(done.min(file_len));
            if progress.is_cancelled() {
                return Ok(None);
            }
        }
        hasher.update(&params.to_param_bytes());
        Ok(Some(ContentId::from_digest(*hasher.finalize().as_bytes())))
    })
    .await
    .map_err(|e| MiasmaError::Storage(format!("hash task: {e}")))?
}
