//! The receive engine: verified, resumable, observable.
//!
//! Given a record and (ideally) its manifest, it fetches each segment's pieces,
//! checks every piece against the manifest's ID *as it arrives*, reassembles and
//! decrypts the segment, checks the segment against its hash, appends it to
//! `<output>.part`, and records progress in a journal. Anything that stops it
//! part-way — a dead holder, a crash, a cancel — leaves the partial file and the
//! journal, and running the same transfer again continues from the last verified
//! segment.
//!
//! The engine is generic over [`PieceSource`] so it runs unchanged against the
//! real network transport and against a fault-injecting source in tests.
//!
//! What it guarantees, and what it does not:
//! * The final file is only ever renamed into place after the whole-file MID
//!   matches. A partial file is never visible under the output name.
//! * A piece that does not match the manifest is refused and the next holder is
//!   tried; it never reaches the decoder.
//! * A wrong password is refused **before any piece is fetched**.
//! * A record with no manifest (published before manifests existed) still
//!   transfers, with resume, but without per-piece or per-segment verification;
//!   only the final MID check protects it. A password with such a record is an
//!   error, because there is nothing to protect it with.

use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use zeroize::Zeroizing;

use super::{
    journal::{journal_path, now_secs, part_path_for, ReceiveJournal, JOURNAL_VERSION},
    manifest::{sanitize_file_name, SegmentEntry, TransferManifest, MAX_SEGMENT_SIZE},
    progress::{Phase, TransferProgress, TransferState},
    protection::{Protection, UnlockedKey},
    share_id::{ShareId, ShareMismatch},
};
use crate::{
    crypto::hash::ContentId,
    dissolution::{segment::retrieve_segment_with, SegmentMeta},
    network::types::{DhtRecord, ShardLocation, MAX_SEGMENTS},
    pipeline::DissolutionParams,
    share::{MiasmaShare, ShareVerification},
    MiasmaError,
};

/// Where pieces come from. `Ok(None)` means "this holder does not have it right
/// now"; the engine simply tries the next one.
#[async_trait]
pub trait PieceSource: Send + Sync {
    async fn fetch_piece(
        &self,
        mid: &ContentId,
        segment: u32,
        slot: u16,
        holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError>;
}

/// How stubbornly a segment is retried before the transfer is paused.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    pub max_attempts_per_segment: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_segment: 5,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(15),
        }
    }
}

impl RetryConfig {
    /// Backoff before retry number `attempt` (1-based): base, doubled each time, capped.
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let factor = 1u32 << attempt.saturating_sub(1).min(16);
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }
}

pub struct ReceiveSpec {
    pub mid: ContentId,
    pub record: DhtRecord,
    /// `None` for a record published before manifests existed.
    pub manifest: Option<TransferManifest>,
    pub password: Option<Zeroizing<String>>,
    pub output_path: PathBuf,
    /// Directory the journal lives in (usually `<data_dir>/transfers`).
    pub journal_dir: PathBuf,
    /// Discard any partial transfer and start over.
    pub restart: bool,
    pub retry: RetryConfig,
    /// The share ID the person supplied, if any. When set, the record's signer,
    /// the manifest's publisher, the protection state and the MID must all match
    /// it before a single piece is fetched (see [`ShareId::check_record`]).
    pub expect: Option<ShareId>,
    /// The key that verifiably signed the record envelope, when the caller knows
    /// it (both network paths do). Must equal the manifest's `publisher`.
    pub record_signer: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Complete {
        bytes: u64,
    },
    /// Stopped with the partial file and journal kept. Run again to resume.
    Paused {
        next_segment: u32,
        reason: String,
    },
    Cancelled {
        next_segment: u32,
    },
}

/// Run a receive to completion, a pause, or a cancel, keeping `progress` current.
pub async fn run_receive<S: PieceSource + ?Sized>(
    source: &S,
    spec: ReceiveSpec,
    progress: Arc<TransferProgress>,
) -> Result<ReceiveOutcome, MiasmaError> {
    let result = run_inner(source, spec, &progress).await;
    match &result {
        Ok(ReceiveOutcome::Complete { .. }) => {
            progress.set_state(TransferState::Complete, None, false)
        }
        Ok(ReceiveOutcome::Paused { reason, .. }) => {
            progress.set_state(TransferState::Paused, Some(reason.clone()), true)
        }
        Ok(ReceiveOutcome::Cancelled { .. }) => {
            progress.set_state(TransferState::Cancelled, None, true)
        }
        Err(e) => progress.set_state(TransferState::Failed, Some(e.to_string()), false),
    }
    result
}

async fn run_inner<S: PieceSource + ?Sized>(
    source: &S,
    spec: ReceiveSpec,
    progress: &Arc<TransferProgress>,
) -> Result<ReceiveOutcome, MiasmaError> {
    let ReceiveSpec {
        mid,
        record,
        manifest,
        password,
        output_path,
        journal_dir,
        restart,
        retry,
        expect,
        record_signer,
    } = spec;

    progress.set_phase(Phase::Preparing);

    // A folder or an unwritable place is a mistake the person can fix now; do not
    // discover it after the pieces have been fetched.
    check_output_target(&output_path)?;

    // ── 1. The record, the manifest and the parameters must agree. ──────────
    if record.mid_digest != *mid.as_bytes() {
        return Err(MiasmaError::InvalidMid(
            "the record is not for the requested MID".into(),
        ));
    }
    // The record comes from the network. Nothing in it may size an allocation or
    // a loop until it has been bounded (C-02).
    record.validate()?;
    // Who published it, before the manifest is trusted for anything: with a
    // share ID the record must be signed by exactly the ID's publisher, carry a
    // manifest that names that publisher, and agree on protection and MID (C-01,
    // C-06). Without one, the record is accepted unauthenticated.
    if let Some(id) = &expect {
        if id.mid_bytes() != mid.as_bytes() {
            return Err(MiasmaError::ShareMismatch(ShareMismatch::MidMismatch));
        }
        id.check_record(
            &record.mid_digest,
            record_signer.as_ref(),
            manifest.as_ref(),
        )
        .map_err(MiasmaError::ShareMismatch)?;
        progress.set_publisher_authenticated(true);
    } else if let (Some(m), Some(signer)) = (&manifest, &record_signer) {
        if &m.publisher != signer {
            return Err(MiasmaError::InvalidManifest(
                "the manifest names a different publisher than the one that signed the record"
                    .into(),
            ));
        }
    }
    let params = match &manifest {
        Some(m) => {
            m.validate()?;
            if m.mid != record.mid_digest {
                return Err(MiasmaError::InvalidManifest(
                    "manifest MID does not match the record".into(),
                ));
            }
            if m.data_shards != record.data_shards || m.total_shards != record.total_shards {
                return Err(MiasmaError::InvalidManifest(
                    "manifest shard counts do not match the record".into(),
                ));
            }
            m.params()
        }
        None => DissolutionParams {
            data_shards: record.data_shards as usize,
            total_shards: record.total_shards as usize,
        },
    };
    let k = params.data_shards;

    // ── 2. The password, before any piece is fetched. ───────────────────────
    let key: Option<Arc<UnlockedKey>> = match (manifest.as_ref().map(|m| &m.protection), password) {
        (Some(Protection::Password(prot)), Some(pw)) => {
            let prot = prot.clone();
            let unlocked = tokio::task::spawn_blocking(move || prot.unlock(pw.as_str()))
                .await
                .map_err(|e| MiasmaError::Decryption(format!("password KDF task: {e}")))??;
            Some(Arc::new(unlocked))
        }
        (Some(Protection::Password(_)), None) => return Err(MiasmaError::PasswordRequired),
        (_, Some(_)) => {
            return Err(MiasmaError::InvalidManifest(
                "a password was supplied but this transfer is not password-protected; \
                 refusing to ignore it"
                    .into(),
            ))
        }
        (_, None) => None,
    };

    // ── 3. Candidates per segment, data shards first (no RS reconstruction). ─
    let segment_count: u32 = match &manifest {
        Some(m) => m.segments.len() as u32,
        // `record.validate()` bounded every index below MAX_SEGMENTS, so this
        // cannot overflow or ask for an absurd table; the checks stay so that
        // remains true if that ever changes.
        None => record
            .locations
            .iter()
            .map(|l| l.segment_index)
            .max()
            .map_or(Some(1), |m| m.checked_add(1))
            .filter(|&c| c <= MAX_SEGMENTS)
            .ok_or_else(|| {
                MiasmaError::InvalidManifest("invalid record: segment table too large".into())
            })?,
    };
    let total_bytes = manifest.as_ref().map_or(0, |m| m.total_bytes);
    progress.set_totals(segment_count, total_bytes);

    let mut candidates: Vec<Vec<(u16, ShardLocation)>> = vec![Vec::new(); segment_count as usize];
    for loc in &record.locations {
        if let Some(bucket) = candidates.get_mut(loc.segment_index as usize) {
            bucket.push((loc.shard_index, loc.clone()));
        }
    }
    for bucket in &mut candidates {
        bucket.sort_by_key(|(slot, _)| *slot);
    }

    // ── 4. Fresh start or resume. ───────────────────────────────────────────
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| io_context("cannot create the folder", parent, &e))?;
        }
    }
    let part_path = part_path_for(&output_path);
    let jpath = journal_path(&journal_dir, &mid);
    let manifest_hash = manifest
        .as_ref()
        .map(|m| m.manifest_hash().map(hex::encode))
        .transpose()?;

    let mut hasher = blake3::Hasher::new();
    let mut next_segment: u32 = 0;
    let mut bytes_done: u64 = 0;
    let mut started_at = now_secs();

    let prior = if restart {
        None
    } else {
        ReceiveJournal::load(&jpath).filter(|j| {
            j.mid == mid.to_string()
                && j.output_path == output_path.to_string_lossy()
                && j.data_shards == params.data_shards as u8
                && j.total_shards == params.total_shards as u8
                && j.segment_count == segment_count
                && j.total_bytes == total_bytes
                && j.manifest_hash == manifest_hash
                && part_path.exists()
        })
    };

    if let Some(j) = prior {
        progress.set_phase(Phase::Verifying);
        let pp = part_path.clone();
        let m = manifest.clone();
        let prog = progress.clone();
        let (seg, bytes, h) = tokio::task::spawn_blocking(move || {
            verify_prefix(&pp, m.as_ref(), j.next_segment, j.bytes_done, &prog)
        })
        .await
        .map_err(|e| MiasmaError::Storage(format!("verify task: {e}")))??;
        started_at = j.started_at;
        next_segment = seg;
        bytes_done = bytes;
        hasher = h;
        // Drop anything after the last verified byte (a crash between the write
        // and the journal update leaves a tail).
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&part_path)
            .map_err(|e| io_context("cannot open the partial file", &part_path, &e))?;
        f.set_len(bytes_done)
            .map_err(|e| io_context("cannot trim the partial file", &part_path, &e))?;
    } else {
        // Fresh: never inherit a stale partial file.
        let _ = std::fs::remove_file(&part_path);
        ReceiveJournal::remove(&jpath);
    }
    progress.set_resumed(next_segment, bytes_done);

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&part_path)
        .await
        .map_err(|e| io_context("cannot create the partial file", &part_path, &e))?;
    file.seek(SeekFrom::Start(bytes_done)).await?;

    let mut journal = ReceiveJournal {
        version: JOURNAL_VERSION,
        mid: mid.to_string(),
        output_path: output_path.to_string_lossy().into_owned(),
        part_path: part_path.to_string_lossy().into_owned(),
        data_shards: params.data_shards as u8,
        total_shards: params.total_shards as u8,
        segment_count,
        total_bytes,
        manifest_hash,
        next_segment,
        bytes_done,
        started_at,
        updated_at: now_secs(),
        last_error: None,
    };
    journal.save(&jpath)?;

    progress.set_phase(Phase::Transferring);

    // ── 5. The transfer loop. ───────────────────────────────────────────────
    // Pieces that verified but then failed to decode; never reused in this run.
    let mut suspects: HashSet<(u32, u16, Vec<u8>)> = HashSet::new();
    for seg in next_segment..segment_count {
        if progress.is_cancelled() {
            journal.save(&jpath)?;
            return Ok(ReceiveOutcome::Cancelled { next_segment: seg });
        }

        let entry = manifest.as_ref().map(|m| &m.segments[seg as usize]);

        // Collect k verified pieces, retrying the whole segment with backoff.
        // Verified pieces are kept across attempts.
        let fetch_started = Instant::now();
        let mut attempt: u32 = 0;
        let mut pool: Vec<PooledPiece> = Vec::new();
        loop {
            match fill_pool(
                source,
                &mid,
                seg,
                &candidates[seg as usize],
                k,
                manifest.as_ref(),
                progress,
                &suspects,
                &mut pool,
            )
            .await
            {
                Ok(()) => break,
                Err(MiasmaError::InsufficientShares { need, got }) => {
                    attempt += 1;
                    if progress.is_cancelled() {
                        journal.save(&jpath)?;
                        return Ok(ReceiveOutcome::Cancelled { next_segment: seg });
                    }
                    if attempt >= retry.max_attempts_per_segment {
                        let reason = format!(
                            "segment {seg}: only {got} of {need} valid pieces after {attempt} attempts"
                        );
                        journal.last_error = Some(reason.clone());
                        journal.updated_at = now_secs();
                        journal.save(&jpath)?;
                        return Ok(ReceiveOutcome::Paused {
                            next_segment: seg,
                            reason,
                        });
                    }
                    progress.segment_retry();
                    tokio::time::sleep(retry.delay_for(attempt)).await;
                }
                Err(e) => return Err(e),
            }
        }
        let fetch_time = fetch_started.elapsed();

        // Reassemble and decrypt off the async threads. If the first k verified
        // pieces still do not decode (only possible without a manifest, or from
        // a lying publisher), try other pieces before giving up.
        let decode_started = Instant::now();
        let ctx = SegmentCtx {
            mid: &mid,
            seg,
            candidates: &candidates[seg as usize],
            k,
            params,
            key: key.as_ref(),
            entry,
            manifest: manifest.as_ref(),
        };
        let plaintext =
            decode_with_fallback(source, &ctx, progress, &mut suspects, &mut pool).await?;
        let decode_time = decode_started.elapsed();

        // Append, make it durable, then journal it.
        let write_started = Instant::now();
        let write = async {
            file.write_all(&plaintext).await?;
            file.sync_data().await
        }
        .await;
        if let Err(e) = write {
            // Out of disk or similar: keep everything; resuming after the
            // condition clears is the whole point.
            let reason = format!("cannot write {}: {e}", part_path.display());
            journal.last_error = Some(reason.clone());
            let _ = journal.save(&jpath);
            return Ok(ReceiveOutcome::Paused {
                next_segment: seg,
                reason,
            });
        }
        hasher.update(&plaintext);
        bytes_done += plaintext.len() as u64;
        journal.next_segment = seg + 1;
        journal.bytes_done = bytes_done;
        journal.updated_at = now_secs();
        journal.last_error = None;
        journal.save(&jpath)?;
        let write_time = write_started.elapsed();

        progress.on_segment_done(plaintext.len() as u64, fetch_time, decode_time, write_time);
    }

    // ── 6. Only a file whose MID matches is ever named as the output. ───────
    progress.set_phase(Phase::Finalizing);
    hasher.update(&params.to_param_bytes());
    let actual = ContentId::from_digest(*hasher.finalize().as_bytes());
    if actual != mid {
        drop(file);
        let _ = std::fs::remove_file(&part_path);
        ReceiveJournal::remove(&jpath);
        return Err(MiasmaError::HashMismatch);
    }
    file.sync_all().await?;
    drop(file);
    std::fs::rename(&part_path, &output_path).map_err(|e| {
        io_context(
            "cannot move the finished file into place at",
            &output_path,
            &e,
        )
    })?;
    ReceiveJournal::remove(&jpath);
    Ok(ReceiveOutcome::Complete { bytes: bytes_done })
}

/// An I/O failure with the path and the OS error kind in the message, so a
/// report from another machine (a macOS permission prompt, a read-only volume)
/// says what was refused and where.
fn io_context(what: &str, path: &Path, e: &std::io::Error) -> MiasmaError {
    MiasmaError::Storage(format!("{what} {}: {:?}: {e}", path.display(), e.kind()))
}

/// Where a receive into `chosen` writes: `chosen` itself, unless it is an
/// existing folder, in which case the file goes inside it under the name the
/// transfer carries. The name is untrusted manifest text and is sanitised again
/// here; an existing file is never overwritten. The engine itself stays strict
/// ([`check_output_target`] refuses a folder); this is the layer above it.
pub fn resolve_output_target(
    chosen: &Path,
    manifest: Option<&TransferManifest>,
) -> Result<PathBuf, MiasmaError> {
    if !chosen.is_dir() {
        return Ok(chosen.to_path_buf());
    }
    let name = manifest
        .and_then(|m| m.name.as_deref())
        .and_then(sanitize_file_name);
    let Some(name) = name else {
        return Err(MiasmaError::Storage(format!(
            "the output path {} is a folder and this transfer does not carry a file name: \
             give a file name inside it (for example {})",
            chosen.display(),
            chosen.join("received.bin").display()
        )));
    };
    let target = chosen.join(&name);
    // `symlink_metadata`: a dangling link at that name is taken too.
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(MiasmaError::Storage(format!(
            "{} already exists; refusing to overwrite it (choose another folder or a file \
             name)",
            target.display()
        )));
    }
    Ok(target)
}

/// Check, before any network work, that `output` can be written: it must not be
/// an existing folder, its folder must exist (or be creatable) and be writable.
/// Answers with a message that names the path and the OS error.
///
/// It leaves nothing behind except a newly created parent folder, which the
/// receive would create anyway.
pub fn check_output_target(output: &Path) -> Result<(), MiasmaError> {
    if output.is_dir() {
        return Err(MiasmaError::Storage(format!(
            "the output path {} is a folder, not a file: give a file name inside it \
             (for example {})",
            output.display(),
            output.join("received.bin").display()
        )));
    }
    if output.file_name().is_none() {
        return Err(MiasmaError::Storage(format!(
            "the output path {} has no file name",
            output.display()
        )));
    }
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        if parent.exists() && !parent.is_dir() {
            return Err(MiasmaError::Storage(format!(
                "cannot save to {}: {} is not a folder",
                output.display(),
                parent.display()
            )));
        }
        std::fs::create_dir_all(parent)
            .map_err(|e| io_context("cannot create the folder", parent, &e))?;
    }
    // Writability: open the `.part` file the way the receive will, without
    // truncating one that is already there, and remove it again if it is ours.
    let part = part_path_for(output);
    let existed = part.exists();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part)
        .map_err(|e| io_context("cannot write to", &part, &e))?;
    if !existed {
        let _ = std::fs::remove_file(&part);
    }
    Ok(())
}

/// A piece that passed verification, with the holder it came from.
struct PooledPiece {
    share: MiasmaShare,
    peer: Vec<u8>,
}

/// Verified pieces fetched beyond `k` when the first `k` fail to decode.
const RECOVERY_EXTRA_PIECES: usize = 4;
/// Decode attempts per segment (the first plus piece swaps) before giving up.
const MAX_DECODE_ATTEMPTS: usize = 16;

/// Everything `decode_with_fallback` needs to know about one segment.
struct SegmentCtx<'a> {
    mid: &'a ContentId,
    seg: u32,
    candidates: &'a [(u16, ShardLocation)],
    k: usize,
    params: DissolutionParams,
    key: Option<&'a Arc<UnlockedKey>>,
    entry: Option<&'a SegmentEntry>,
    manifest: Option<&'a TransferManifest>,
}

/// Top `pool` up to `want` verified pieces, refusing any that do not match the
/// manifest. Slots already in the pool and pieces previously found suspect are
/// skipped; a rejected piece leaves the slot open for the next holder listed.
#[allow(clippy::too_many_arguments)]
async fn fill_pool<S: PieceSource + ?Sized>(
    source: &S,
    mid: &ContentId,
    seg: u32,
    candidates: &[(u16, ShardLocation)],
    want: usize,
    manifest: Option<&TransferManifest>,
    progress: &Arc<TransferProgress>,
    suspects: &HashSet<(u32, u16, Vec<u8>)>,
    pool: &mut Vec<PooledPiece>,
) -> Result<(), MiasmaError> {
    for (slot, holder) in candidates {
        if pool.len() >= want || progress.is_cancelled() {
            break;
        }
        if pool.iter().any(|p| p.share.slot_index == *slot)
            || suspects.contains(&(seg, *slot, holder.peer_id_bytes.clone()))
        {
            continue;
        }
        let fetched = match source.fetch_piece(mid, seg, *slot, holder).await {
            Ok(Some(share)) => share,
            // Not there, or the holder failed: try the next one.
            Ok(None) | Err(_) => continue,
        };
        if piece_is_acceptable(&fetched, mid, seg, *slot, manifest) {
            progress.piece_fetched();
            pool.push(PooledPiece {
                share: fetched,
                peer: holder.peer_id_bytes.clone(),
            });
        } else {
            progress.piece_rejected();
        }
    }
    if pool.len() < want {
        return Err(MiasmaError::InsufficientShares {
            need: want,
            got: pool.len(),
        });
    }
    Ok(())
}

/// A decode failure that a different set of pieces could cure.
fn is_recoverable(e: &MiasmaError) -> bool {
    matches!(
        e,
        MiasmaError::Decryption(_)
            | MiasmaError::ReedSolomon(_)
            | MiasmaError::Sss(_)
            | MiasmaError::InvalidManifest(_)
    )
}

/// Decode one combination of pieces and check it against the manifest, off the
/// async threads.
async fn decode_once(
    ctx: &SegmentCtx<'_>,
    pieces: Vec<MiasmaShare>,
) -> Result<Vec<u8>, MiasmaError> {
    let plaintext_len = match ctx.entry {
        Some(e) => e.plaintext_len,
        // No manifest: the most common `original_len` among the pieces.
        None => most_common_len(&pieces),
    };
    let meta = SegmentMeta {
        index: ctx.seg,
        offset_bytes: 0,
        plaintext_len,
        share_count: ctx.params.total_shards as u16,
    };
    let mid = ctx.mid.clone();
    let key = ctx.key.cloned();
    let params = ctx.params;
    let expected = ctx.entry.map(|e| (e.plaintext_len, e.plain_hash));
    let seg = ctx.seg;
    tokio::task::spawn_blocking(move || {
        let plaintext = retrieve_segment_with(&mid, &pieces, &meta, params, key.as_deref())?;
        if let Some((len, hash)) = expected {
            if plaintext.len() != len as usize || *blake3::hash(&plaintext).as_bytes() != hash {
                return Err(MiasmaError::InvalidManifest(format!(
                    "segment {seg} does not match its manifest hash; the manifest and the \
                     pieces disagree"
                )));
            }
        }
        Ok(plaintext)
    })
    .await
    .map_err(|e| MiasmaError::Decryption(format!("decode task: {e}")))?
}

fn most_common_len(pieces: &[MiasmaShare]) -> u32 {
    let mut best = (0usize, pieces.first().map_or(0, |p| p.original_len));
    for p in pieces {
        let n = pieces
            .iter()
            .filter(|q| q.original_len == p.original_len)
            .count();
        if n > best.0 {
            best = (n, p.original_len);
        }
    }
    best.1
}

/// Decode the segment from the pool. If the first `k` pieces fail in a way other
/// pieces could cure, fetch a few spares and retry with one piece swapped at a
/// time (bounded by [`MAX_DECODE_ATTEMPTS`]). The piece swapped out of the
/// combination that finally decodes is recorded as suspect and is not reused in
/// this run. If nothing works, the first error is returned.
async fn decode_with_fallback<S: PieceSource + ?Sized>(
    source: &S,
    ctx: &SegmentCtx<'_>,
    progress: &Arc<TransferProgress>,
    suspects: &mut HashSet<(u32, u16, Vec<u8>)>,
    pool: &mut Vec<PooledPiece>,
) -> Result<Vec<u8>, MiasmaError> {
    let k = ctx.k;
    pool.sort_by_key(|p| p.share.slot_index);
    let pick = |pool: &[PooledPiece], idx: &[usize]| -> Vec<MiasmaShare> {
        idx.iter().map(|&i| pool[i].share.clone()).collect()
    };

    let base: Vec<usize> = (0..k).collect();
    let first_err = match decode_once(ctx, pick(pool, &base)).await {
        Ok(pt) => return Ok(pt),
        Err(e) if is_recoverable(&e) => e,
        Err(e) => return Err(e),
    };

    // Spare pieces from other slots/holders. Falling short is not an error here:
    // whatever could be fetched is tried.
    let _ = fill_pool(
        source,
        ctx.mid,
        ctx.seg,
        ctx.candidates,
        k + RECOVERY_EXTRA_PIECES,
        ctx.manifest,
        progress,
        suspects,
        pool,
    )
    .await;

    let mut attempts = 1usize;
    for spare in k..pool.len() {
        for out in 0..k {
            if attempts >= MAX_DECODE_ATTEMPTS || progress.is_cancelled() {
                return Err(first_err);
            }
            attempts += 1;
            let mut idx = base.clone();
            idx[out] = spare;
            match decode_once(ctx, pick(pool, &idx)).await {
                Ok(pt) => {
                    let bad = &pool[out];
                    suspects.insert((ctx.seg, bad.share.slot_index, bad.peer.clone()));
                    progress.piece_rejected();
                    return Ok(pt);
                }
                Err(e) if is_recoverable(&e) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Err(first_err)
}

fn piece_is_acceptable(
    share: &MiasmaShare,
    mid: &ContentId,
    seg: u32,
    slot: u16,
    manifest: Option<&TransferManifest>,
) -> bool {
    if share.segment_index != seg
        || share.slot_index != slot
        || !ShareVerification::coarse_verify(share, mid)
    {
        return false;
    }
    match manifest {
        // The piece must be exactly the one the index lists for this slot: the
        // commitment covers key_share, nonce and original_len too, so a piece
        // whose ciphertext is right but whose key material was flipped is
        // refused here and a spare holder is used instead.
        Some(m) => m
            .expected_piece(seg, slot)
            .is_some_and(|expected| ShareVerification::verify_piece(share, mid, expected)),
        // No manifest, nothing to compare against; at least keep an unchecked
        // length from sizing the decode buffer.
        None => share.original_len <= MAX_SEGMENT_SIZE,
    }
}

/// Re-read an existing partial file and confirm what it holds.
///
/// With a manifest, each segment is checked against its `plain_hash`, so the
/// first damaged or missing segment is found exactly. Without one only the byte
/// count can be checked, and a short file restarts from the beginning.
///
/// Returns the count of trustworthy segments, their byte length, and a hasher
/// that has consumed exactly those bytes.
fn verify_prefix(
    part: &Path,
    manifest: Option<&TransferManifest>,
    journal_next: u32,
    journal_bytes: u64,
    progress: &TransferProgress,
) -> Result<(u32, u64, blake3::Hasher), MiasmaError> {
    let mut f = std::fs::File::open(part)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut bytes: u64 = 0;

    let Some(m) = manifest else {
        // No per-segment hashes: trust the journal's byte count if the file has
        // at least that many bytes, otherwise start over.
        if f.metadata()?.len() < journal_bytes {
            return Ok((0, 0, blake3::Hasher::new()));
        }
        let mut left = journal_bytes;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            f.read_exact(&mut buf[..want])?;
            hasher.update(&buf[..want]);
            left -= want as u64;
            bytes += want as u64;
            progress.set_verified_bytes(bytes);
        }
        return Ok((journal_next, journal_bytes, hasher));
    };

    let mut good = 0u32;
    for seg in 0..journal_next {
        let entry = &m.segments[seg as usize];
        let before = hasher.clone();
        let mut seg_hasher = blake3::Hasher::new();
        let mut left = entry.plaintext_len as u64;
        let mut ok = true;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            match f.read_exact(&mut buf[..want]) {
                Ok(()) => {
                    seg_hasher.update(&buf[..want]);
                    hasher.update(&buf[..want]);
                    left -= want as u64;
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok || *seg_hasher.finalize().as_bytes() != entry.plain_hash {
            // Everything from here on is not trusted: rewind to before this segment.
            return Ok((good, bytes, before));
        }
        bytes += entry.plaintext_len as u64;
        good += 1;
        progress.set_verified_bytes(bytes);
    }
    // Position is irrelevant to the caller (it reopens and seeks), but leave the
    // handle tidy.
    let _ = f.seek(SeekFrom::Start(bytes));
    Ok((good, bytes, hasher))
}
