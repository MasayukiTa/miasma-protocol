/// Local encrypted Share store — Task 7.
///
/// # Design decisions (Task 7 checklist)
///
/// | Decision | Choice | Rationale |
/// |---|---|---|
/// | 暗号アルゴリズム | XChaCha20-Poly1305 | 192-bit nonce → random nonce per file は安全。AES-GCM (96-bit) と差別化。|
/// | 鍵保管 | `{data_dir}/master.key` (平文バイナリ、OSのファイル権限で保護) | Phase 1 デスクトップ向け。Phase 2 で Android Keystore / iOS Keychain 対応予定。|
/// | 暗号化粒度 | ファイル単位 (1 Share = 1 暗号化ファイル) | シンプル。LRU eviction もファイル削除で完結。|
/// | distress wipe 整合 | master.key 削除 → 全Share瞬時に不可読 ✅ | key_deletion = unreadable の設計を満たす (§Section 9)。|
/// | アドレス方式 | `BLAKE3(serialized_share)` の hex 文字列 | 内容アドレス指定でデdup が自然に発生。|
///
/// # Directory layout
/// ```text
/// {data_dir}/
///   master.key          ← 32-byte random master key (delete this to wipe all shares)
///   shares/
///     {blake3_hex}.ms   ← XChaCha20-Poly1305 encrypted MiasmaShare (nonce prepended)
///   store_index.json    ← LRU index {address → {size_bytes, last_accessed_secs}}
/// ```
use std::{
    collections::HashMap,
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{share::MiasmaShare, MiasmaError};

const NONCE_LEN: usize = 24; // XChaCha20 nonce
const MASTER_KEY_FILE: &str = "master.key";
const SHARES_DIR: &str = "shares";
const INDEX_FILE: &str = "store_index.json";
const SHARE_EXT: &str = ".ms";

/// Share of the hosted quota one principal may hold, in percent.
///
/// The hosted budget is one pool; without a per-principal limit a single
/// admitted peer can fill all of it and deny every later publisher. A quarter
/// means at least four distinct principals must cooperate to exhaust the pool,
/// while a single publisher can still park a meaningful amount of data.
pub const HOSTED_PRINCIPAL_SHARE_PERCENT: u64 = 25;

/// Lower bound of the per-principal hosted budget, applied as
/// `min(hosted quota, HOSTED_PRINCIPAL_FLOOR_BYTES)`.
///
/// A percentage alone makes a small quota unusable (25% of 20 MiB is 5 MiB,
/// less than one 4 MiB-segment publish of a few pieces). 16 MiB lets one
/// publisher place a full segment set on a small node, and the `min` with the
/// quota keeps the budget from ever exceeding the pool itself.
pub const HOSTED_PRINCIPAL_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

/// Why [`LocalShareStore::put_hosted_by`] refused a share. Reaches the pusher
/// as a `StoreRejectReason`, so its `PushState` can tell a standing refusal
/// (budget) from a per-piece one (ownership).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedRefusal {
    /// The global hosted budget is full.
    QuotaExceeded,
    /// The pushing principal already holds its share of the hosted budget.
    PrincipalBudgetExceeded,
    /// A different principal holds this `(mid_prefix, segment, slot)`.
    NotOwner,
}

impl std::fmt::Display for HostedRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuotaExceeded => write!(f, "hosted share storage quota exceeded"),
            Self::PrincipalBudgetExceeded => {
                write!(f, "per-principal hosted share budget exceeded")
            }
            Self::NotOwner => write!(f, "hosted piece is held by another principal"),
        }
    }
}

/// Error of [`LocalShareStore::put_hosted_by`].
#[derive(Debug)]
pub enum HostedPutError {
    /// The store declined the share for a policy reason.
    Refused(HostedRefusal),
    /// I/O, crypto or serialization failure.
    Store(MiasmaError),
}

impl From<HostedRefusal> for HostedPutError {
    fn from(r: HostedRefusal) -> Self {
        Self::Refused(r)
    }
}

impl From<MiasmaError> for HostedPutError {
    fn from(e: MiasmaError) -> Self {
        Self::Store(e)
    }
}

impl From<HostedPutError> for MiasmaError {
    fn from(e: HostedPutError) -> Self {
        match e {
            HostedPutError::Refused(r) => MiasmaError::Storage(r.to_string()),
            HostedPutError::Store(e) => e,
        }
    }
}

impl std::fmt::Display for HostedPutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => r.fmt(f),
            Self::Store(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for HostedPutError {}

// ─── LRU index ───────────────────────────────────────────────────────────────

/// Who a stored share belongs to.
///
/// Phase 2.1: a node can now hold shares on behalf of a remote publisher
/// (`Hosted`, via an inbound `/miasma/share-store/1.0.0` request) in addition
/// to shares it produced by dissolving its own content (`Owned`). The two
/// must never share one quota/eviction policy -- a peer this node is merely
/// helping distribute content for must never be able to evict this node's
/// own shares (or another publisher's already-hosted shares) just by pushing
/// enough junk. `#[serde(default)]` on the field that carries this so every
/// pre-2.1 `store_index.json` entry (with no `origin` at all) deserializes as
/// `Owned` -- the only kind that existed before this phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum ShareOrigin {
    #[default]
    Owned,
    Hosted,
}

/// Identifies the logical "slot" a hosted share occupies: the same
/// `(mid_prefix, segment_index, slot_index)` triple that
/// `redistribute_segment` (best-effort repair) or a second dissolution of
/// identical content can independently regenerate with different bytes
/// (fresh key, fresh RS/SSS output) and a different content address. Content
/// addressing (`BLAKE3(bincode(share))`) means those generations would
/// otherwise coexist forever instead of the newer one replacing the older --
/// see the "hosted put replaces same-tuple entry" logic in `put_hosted_by`.
///
/// The tuple is public and carries no identity, so it is *not* ownership: a
/// replacement is only allowed for the principal that stored the old entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct HostedTuple {
    mid_prefix: [u8; 8],
    segment_index: u32,
    slot_index: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    size_bytes: u64,
    last_accessed_secs: u64,
    #[serde(default)]
    origin: ShareOrigin,
    /// Set only for `Hosted` entries (including ones stored before this field
    /// existed, which get `None` and are simply never replaced by tuple --
    /// they age out via normal hosted-quota pressure instead).
    #[serde(default)]
    hosted_tuple: Option<HostedTuple>,
    /// Which piece this share is, for *every* entry (owned or hosted): the same
    /// `(mid_prefix, segment, slot)` triple as `hosted_tuple`.
    ///
    /// It exists so a piece can be found by index lookup instead of by
    /// decrypting stored shares one after another to read their headers, which
    /// is what serving a fetch request used to do -- O(shares in the store)
    /// full decryptions per request. `None` for entries written before this
    /// field existed; `find_piece` fills those in lazily, once.
    #[serde(default)]
    piece: Option<PieceKey>,
    /// For `Hosted` entries: the authenticated principal (the transport-level
    /// peer id) that pushed the share. `None` means unknown -- entries written
    /// before this field existed, or pushed through [`LocalShareStore::put_hosted`]
    /// without a principal. An unknown owner never matches anyone, so its entry
    /// is neither replaced nor claimed by a later push; its bytes are accounted
    /// to one shared "unknown" bucket.
    #[serde(default)]
    hosted_principal: Option<String>,
}

/// See [`IndexEntry::piece`]. Same shape as [`HostedTuple`].
type PieceKey = HostedTuple;

impl PieceKey {
    fn of(share: &MiasmaShare) -> Self {
        Self {
            mid_prefix: share.mid_prefix,
            segment_index: share.segment_index,
            slot_index: share.slot_index,
        }
    }
}

type StoreIndex = HashMap<String, IndexEntry>;

/// A parsed copy of the index plus the file stamp it was read at. Lets
/// read-only lookups skip re-parsing a multi-megabyte JSON file per request.
struct CachedIndex {
    stamp: Option<(SystemTime, u64)>,
    index: std::sync::Arc<StoreIndex>,
}

fn index_stamp(data_dir: &Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(data_dir.join(INDEX_FILE)).ok()?;
    Some((m.modified().ok()?, m.len()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_index(data_dir: &Path) -> StoreIndex {
    let path = data_dir.join(INDEX_FILE);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_index(data_dir: &Path, index: &StoreIndex) -> Result<(), MiasmaError> {
    let path = data_dir.join(INDEX_FILE);
    let raw =
        serde_json::to_string(index).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
    atomic_write(&path, raw.as_bytes())
}

/// Write to a temp file then rename — atomic on POSIX, best-effort on Windows.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ─── Master key management ────────────────────────────────────────────────────

/// Load or create the master key at `{data_dir}/master.key`.
///
/// The master key is used to derive per-file XChaCha20-Poly1305 keys via HKDF.
/// Deleting this file instantly renders all stored shares unreadable (distress wipe).
fn load_or_create_master_key(data_dir: &Path) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let key_path = data_dir.join(MASTER_KEY_FILE);
    if key_path.exists() {
        let bytes = Zeroizing::new(std::fs::read(&key_path)?);
        if bytes.len() != 32 {
            return Err(MiasmaError::KeyDerivation(
                "master.key has wrong length".into(),
            ));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&bytes);
        if arr.iter().all(|byte| *byte == 0) {
            return Err(MiasmaError::KeyDerivation(
                "master.key is erased/all-zero; refusing known key material".into(),
            ));
        }
        Ok(arr)
    } else {
        let mut arr = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut OsRng, arr.as_mut());
        std::fs::create_dir_all(data_dir)?;

        // Write the key via atomic_write_restricted: the file is created
        // with a restrictive DACL/mode from the start (Win32 CreateFileW
        // with SECURITY_ATTRIBUTES on Windows, open() with 0o600 on Unix).
        // At no point does the key exist on disk with permissive permissions.
        crate::secure_file::atomic_write_restricted(&key_path, arr.as_ref()).map_err(|e| {
            MiasmaError::KeyDerivation(format!(
                "failed to write master.key with restricted permissions: {e}"
            ))
        })?;

        Ok(arr)
    }
}

/// Derive a per-file XChaCha20-Poly1305 key from the master key and the share address.
///
/// `key = HKDF-SHA256(ikm = master_key, info = "miasma-store-v1:" || address_hex)`
fn derive_file_key(
    master_key: &[u8; 32],
    address: &str,
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let info = format!("miasma-store-v1:{address}");
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

// ─── Encryption / decryption ──────────────────────────────────────────────────

fn encrypt_share(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, MiasmaError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| MiasmaError::Encryption(e.to_string()))?;
    // Prepend nonce to ciphertext: [nonce (24 bytes) || ct || tag (16 bytes)]
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_share(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, MiasmaError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(MiasmaError::Decryption("blob too short".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| MiasmaError::Decryption(e.to_string()))
}

// ─── Startup hygiene ─────────────────────────────────────────────────────────

/// Remove orphaned `.tmp` files left by interrupted atomic writes.
fn cleanup_tmp_files(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                tracing::debug!(path = %path.display(), "removing orphaned .tmp file");
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Count `.ms` share files in the shares directory.
fn count_share_files(shares_dir: &Path) -> usize {
    std::fs::read_dir(shares_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|s| s == "ms")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Rebuild `store_index.json` from share files on disk.
///
/// For each `.ms` file in `shares/`, records its size and current timestamp.
/// The content address is derived from the file stem (filename without `.ms`).
fn rebuild_index(data_dir: &Path, shares_dir: &Path) {
    let mut index = StoreIndex::new();
    let now = now_secs();
    if let Ok(entries) = std::fs::read_dir(shares_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ms") {
                continue;
            }
            let address = match path.file_stem().and_then(|s| s.to_str()) {
                Some(a) => a.to_string(),
                None => continue,
            };
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            index.insert(
                address,
                IndexEntry {
                    size_bytes: size,
                    last_accessed_secs: now,
                    // Rebuild has no way to recover which shares were hosted
                    // on behalf of a remote publisher vs. produced locally --
                    // `Owned` is the safe default (worst case, a formerly-
                    // hosted share becomes eligible for owned-quota LRU
                    // eviction sooner than ideal; never a security issue).
                    origin: ShareOrigin::Owned,
                    hosted_tuple: None,
                    // Filled in lazily by `find_piece`.
                    piece: None,
                    hosted_principal: None,
                },
            );
        }
    }
    if !index.is_empty() {
        let _ = save_index(data_dir, &index);
        tracing::info!(entries = index.len(), "store index rebuilt from disk");
    }
}

// ─── LocalShareStore ─────────────────────────────────────────────────────────

/// Encrypted local share store.
///
/// Thread-safety: safe to share as `Arc<LocalShareStore>` across concurrent
/// callers -- `write_lock` serializes every index read-modify-write sequence
/// (`put`/`put_hosted`/`delete`/`evict_if_needed`) into one critical section
/// each, which is what actually matters here (the on-disk index is the only
/// mutable shared state; individual share files are written once, under a
/// content-derived name, and never mutated in place). Before Phase 2.1 this
/// was documented as "not thread-safe, wrap in `Arc<Mutex<_>>`" -- true at the
/// time because there was only ever one caller (local dissolution); Phase
/// 2.1 added a second writer (inbound network `Store` requests), which is
/// exactly the case that comment was warning about.
pub struct LocalShareStore {
    data_dir: PathBuf,
    shares_dir: PathBuf,
    /// In-memory master key. `None` means distress wipe has completed for this
    /// process. Key-dependent operations hold this lock until completion so a
    /// completed wipe cannot race with an in-flight decrypt/write.
    master_key: std::sync::Mutex<Option<Zeroizing<[u8; 32]>>>,
    /// Quota in bytes for `Owned` shares (produced by this node's own
    /// dissolutions).
    quota_bytes: u64,
    /// Quota in bytes for `Hosted` shares (accepted on behalf of a remote
    /// publisher via inbound `/miasma/share-store/1.0.0`). Separate from
    /// `quota_bytes` so a peer this node is merely helping distribute
    /// content for can never evict this node's own shares, or another
    /// publisher's already-hosted shares, just by pushing enough shares of
    /// its own -- see `put_hosted`'s reject-rather-than-evict behaviour.
    /// Zero by default (a node must opt in via `with_hosted_quota_mb` to
    /// accept any pushed shares at all).
    hosted_quota_bytes: u64,
    /// Serializes every index read-modify-write sequence across all mutating
    /// methods, so two concurrent writers (e.g. a local dissolve and an
    /// inbound network `Store` request) can never interleave and corrupt or
    /// silently drop an update to `store_index.json`.
    write_lock: std::sync::Mutex<()>,
    /// Parsed index for read-only piece lookups; see [`CachedIndex`].
    index_cache: std::sync::Mutex<Option<CachedIndex>>,
}

impl LocalShareStore {
    /// Open (or create) the store under `data_dir`.
    ///
    /// Performs startup hygiene:
    /// 1. Creates `shares/` directory if missing.
    /// 2. Loads or creates `master.key`.
    /// 3. Cleans up orphaned `.tmp` files from prior interrupted writes.
    /// 4. Rebuilds `store_index.json` from disk if missing or corrupt.
    pub fn open(data_dir: &Path, quota_mb: u64) -> Result<Self, MiasmaError> {
        let shares_dir = data_dir.join(SHARES_DIR);
        std::fs::create_dir_all(&shares_dir)?;
        let master_key = load_or_create_master_key(data_dir)?;

        // Cleanup orphaned .tmp files from interrupted atomic writes.
        cleanup_tmp_files(data_dir);
        cleanup_tmp_files(&shares_dir);

        // If store_index.json is missing or corrupt, rebuild from share files.
        let index = load_index(data_dir);
        if index.is_empty() && shares_dir.exists() {
            let on_disk = count_share_files(&shares_dir);
            if on_disk > 0 {
                tracing::info!(
                    orphaned_shares = on_disk,
                    "store_index.json empty/corrupt — rebuilding from share files"
                );
                rebuild_index(data_dir, &shares_dir);
            }
        }

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            shares_dir,
            master_key: std::sync::Mutex::new(Some(master_key)),
            quota_bytes: quota_mb * 1024 * 1024,
            hosted_quota_bytes: 0,
            write_lock: std::sync::Mutex::new(()),
            index_cache: std::sync::Mutex::new(None),
        })
    }

    /// Opt this store in to accepting inbound-hosted shares (from
    /// `/miasma/share-store/1.0.0`), with their own byte budget separate
    /// from the owned-share quota. Call before wrapping in `Arc` --
    /// `Arc::new(LocalShareStore::open(dir, quota_mb)?.with_hosted_quota_mb(50))`.
    ///
    /// A store that never calls this has `hosted_quota_bytes == 0`, so
    /// `put_hosted` always rejects -- a node must opt in to hosting other
    /// publishers' shares, not have it happen implicitly.
    pub fn with_hosted_quota_mb(mut self, hosted_quota_mb: u64) -> Self {
        self.hosted_quota_bytes = hosted_quota_mb.saturating_mul(1024 * 1024);
        self
    }

    /// Open the store the way a daemon does: owned quota from
    /// `storage.quota_mb`, hosted quota from `storage.hosted_quota_mb`
    /// (default `0`, i.e. every pushed share is refused). This is the single
    /// place the configuration reaches the store, so a test can drive it with
    /// a parsed `config.toml`.
    pub fn open_configured(
        data_dir: &Path,
        storage: &crate::config::StorageConfig,
    ) -> Result<Self, MiasmaError> {
        Ok(Self::open(data_dir, storage.quota_mb)?.with_hosted_quota_mb(storage.hosted_quota_mb))
    }

    /// Configured hosted-share budget in bytes (`0` = refuse all pushed shares).
    pub fn hosted_quota_bytes(&self) -> u64 {
        self.hosted_quota_bytes
    }

    fn lock_master_key(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<Zeroizing<[u8; 32]>>>, MiasmaError> {
        self.master_key
            .lock()
            .map_err(|_| MiasmaError::Storage("master key lock poisoned".into()))
    }

    fn live_master_key(guard: &Option<Zeroizing<[u8; 32]>>) -> Result<&[u8; 32], MiasmaError> {
        guard
            .as_ref()
            .map(|key| &**key)
            .ok_or_else(|| MiasmaError::Storage("store has been distress-wiped".into()))
    }

    /// Content-address of a share: `BLAKE3(bincode(share))` as lowercase hex.
    pub fn address_of(share: &MiasmaShare) -> Result<String, MiasmaError> {
        let bytes = share.to_bytes()?;
        Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    /// Store a share this node produced itself (owned quota). Returns its
    /// content address.
    ///
    /// If the address already exists (idempotent re-store), updates last_accessed.
    /// If quota is exceeded, evicts LRU entries (owned entries only) until
    /// space is available.
    pub fn put(&self, share: &MiasmaShare) -> Result<String, MiasmaError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| MiasmaError::Storage("store write lock poisoned".into()))?;
        let master_guard = self.lock_master_key()?;
        let master_key = Self::live_master_key(&master_guard)?;
        let address = Self::address_of(share)?;
        let file_path = self.share_path(&address);

        // Serialize share to plaintext bytes.
        let plaintext = share.to_bytes()?;
        let size = plaintext.len() as u64;

        // Ensure quota.
        self.evict_if_needed_locked(size, &address)?;

        // Derive per-file key and encrypt.
        let file_key = derive_file_key(master_key, &address)?;
        let blob = encrypt_share(&file_key, &plaintext)?;

        atomic_write(&file_path, &blob)?;

        // Update index.
        let mut index = load_index(&self.data_dir);
        index.insert(
            address.clone(),
            IndexEntry {
                size_bytes: blob.len() as u64,
                last_accessed_secs: now_secs(),
                origin: ShareOrigin::Owned,
                hosted_tuple: None,
                piece: Some(PieceKey::of(share)),
                hosted_principal: None,
            },
        );
        save_index(&self.data_dir, &index)?;

        Ok(address)
    }

    /// Store a share on behalf of a remote publisher whose identity is not
    /// known (hosted quota). Returns its content address.
    ///
    /// The share is recorded with an *unknown* principal: it is accounted to
    /// the shared "unknown" bucket and can neither be replaced by, nor replace,
    /// any other entry with the same `(mid_prefix, segment_index, slot_index)`
    /// tuple. Network code must use [`put_hosted_by`](Self::put_hosted_by) with
    /// the authenticated peer id instead.
    pub fn put_hosted(&self, share: &MiasmaShare) -> Result<String, MiasmaError> {
        self.put_hosted_inner(share, None)
            .map_err(MiasmaError::from)
    }

    /// Store a share pushed by the authenticated principal `principal` (the
    /// transport-level peer id of the sender). Returns its content address.
    ///
    /// Unlike `put`, this **never evicts** owned shares or hosted shares of
    /// other principals to make room. Refusals are typed ([`HostedRefusal`]):
    ///
    /// * [`HostedRefusal::NotOwner`] -- another principal (or an unknown one)
    ///   already holds this `(mid_prefix, segment_index, slot_index)` tuple.
    ///   The tuple is public and carries no identity, so it cannot express
    ///   ownership; only the principal that stored an entry may replace it.
    /// * [`HostedRefusal::QuotaExceeded`] -- the global hosted budget is full.
    /// * [`HostedRefusal::PrincipalBudgetExceeded`] -- this principal already
    ///   holds its fraction of the hosted budget
    ///   ([`hosted_principal_budget_bytes`](Self::hosted_principal_budget_bytes)).
    ///
    /// A share whose bytes are already stored is acknowledged without touching
    /// the entry, so a second principal pushing identical bytes can neither
    /// take over nor evict the first one's copy.
    ///
    /// A newer generation of the same tuple pushed by the *same* principal (a
    /// republish, or `redistribute_segment`'s repair path) replaces the older
    /// one rather than coexisting ambiguously -- see `HostedTuple`.
    pub fn put_hosted_by(
        &self,
        share: &MiasmaShare,
        principal: &str,
    ) -> Result<String, HostedPutError> {
        self.put_hosted_inner(share, Some(principal))
    }

    fn put_hosted_inner(
        &self,
        share: &MiasmaShare,
        principal: Option<&str>,
    ) -> Result<String, HostedPutError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| MiasmaError::Storage("store write lock poisoned".into()))?;
        let master_guard = self.lock_master_key()?;
        let master_key = Self::live_master_key(&master_guard)?;
        let address = Self::address_of(share)?;
        let file_path = self.share_path(&address);

        let plaintext = share.to_bytes()?;
        let size = plaintext.len() as u64;

        let mut index = load_index(&self.data_dir);
        if index.contains_key(&address) {
            // Identical bytes are already stored: idempotent. Never change the
            // recorded owner or origin of an existing entry.
            return Ok(address);
        }

        let tuple = HostedTuple {
            mid_prefix: share.mid_prefix,
            segment_index: share.segment_index,
            slot_index: share.slot_index,
        };
        // An unknown principal (`None`) never owns anything.
        let owned_by_caller =
            |e: &IndexEntry| principal.is_some() && e.hosted_principal.as_deref() == principal;
        let conflicting: Vec<(String, u64, bool)> = index
            .iter()
            .filter(|(_, e)| e.origin == ShareOrigin::Hosted && e.hosted_tuple == Some(tuple))
            .map(|(addr, e)| (addr.clone(), e.size_bytes, owned_by_caller(e)))
            .collect();
        if conflicting.iter().any(|(_, _, mine)| !mine) {
            return Err(HostedRefusal::NotOwner.into());
        }
        let freed: u64 = conflicting.iter().map(|(_, sz, _)| *sz).sum();

        let hosted_total: u64 = index
            .values()
            .filter(|e| e.origin == ShareOrigin::Hosted)
            .map(|e| e.size_bytes)
            .sum();
        if hosted_total.saturating_sub(freed) + size > self.hosted_quota_bytes {
            return Err(HostedRefusal::QuotaExceeded.into());
        }
        // `None` matches `None`: unknown/legacy entries share one bucket.
        let held_by_principal: u64 = index
            .values()
            .filter(|e| {
                e.origin == ShareOrigin::Hosted && e.hosted_principal.as_deref() == principal
            })
            .map(|e| e.size_bytes)
            .sum();
        if held_by_principal.saturating_sub(freed) + size > self.hosted_principal_budget_bytes() {
            return Err(HostedRefusal::PrincipalBudgetExceeded.into());
        }

        // Replace the caller's own older generation of this tuple.
        for (old_addr, _, _) in &conflicting {
            let _ = std::fs::remove_file(self.share_path(old_addr));
            index.remove(old_addr);
        }

        let file_key = derive_file_key(master_key, &address)?;
        let blob = encrypt_share(&file_key, &plaintext)?;
        atomic_write(&file_path, &blob)?;

        index.insert(
            address.clone(),
            IndexEntry {
                size_bytes: blob.len() as u64,
                last_accessed_secs: now_secs(),
                origin: ShareOrigin::Hosted,
                hosted_tuple: Some(tuple),
                piece: Some(PieceKey::of(share)),
                hosted_principal: principal.map(str::to_owned),
            },
        );
        save_index(&self.data_dir, &index)?;

        Ok(address)
    }

    /// The most hosted bytes one principal (one pushing peer; all unknown
    /// owners together) may hold: see [`HOSTED_PRINCIPAL_SHARE_PERCENT`] and
    /// [`HOSTED_PRINCIPAL_FLOOR_BYTES`].
    pub fn hosted_principal_budget_bytes(&self) -> u64 {
        let fraction = self
            .hosted_quota_bytes
            .saturating_mul(HOSTED_PRINCIPAL_SHARE_PERCENT)
            / 100;
        fraction.max(self.hosted_quota_bytes.min(HOSTED_PRINCIPAL_FLOOR_BYTES))
    }

    /// Current total size of `Hosted`-origin share blobs in bytes.
    pub fn used_hosted_bytes(&self) -> u64 {
        load_index(&self.data_dir)
            .values()
            .filter(|e| e.origin == ShareOrigin::Hosted)
            .map(|e| e.size_bytes)
            .sum()
    }

    /// Retrieve a share by its content address.
    pub fn get(&self, address: &str) -> Result<MiasmaShare, MiasmaError> {
        let share = self.get_untouched(address)?;

        // Update last_accessed.
        let mut index = load_index(&self.data_dir);
        if let Some(entry) = index.get_mut(address) {
            entry.last_accessed_secs = now_secs();
            let _ = save_index(&self.data_dir, &index);
        }

        Ok(share)
    }

    /// As [`get`](Self::get) but without recording the access.
    ///
    /// `get` re-reads and rewrites the whole index file on every call to bump
    /// `last_accessed`. That is right for LRU bookkeeping and wrong for a hot
    /// read path (serving a fetch request), where it is O(index size) extra
    /// work per share and turns every read into a write.
    pub fn get_untouched(&self, address: &str) -> Result<MiasmaShare, MiasmaError> {
        let master_guard = self.lock_master_key()?;
        let master_key = Self::live_master_key(&master_guard)?;
        let file_path = self.share_path(address);
        let blob = std::fs::read(&file_path)?;

        let file_key = derive_file_key(master_key, address)?;
        let plaintext = decrypt_share(&file_key, &blob)?;
        MiasmaShare::from_bytes(&plaintext)
    }

    /// The parsed index, re-read only when the file has changed.
    fn index_snapshot(&self) -> std::sync::Arc<StoreIndex> {
        let stamp = index_stamp(&self.data_dir);
        let mut cache = self.index_cache.lock().unwrap();
        if let (Some(c), Some(_)) = (cache.as_ref(), stamp) {
            if c.stamp == stamp {
                return c.index.clone();
            }
        }
        let index = std::sync::Arc::new(load_index(&self.data_dir));
        *cache = Some(CachedIndex {
            stamp,
            index: index.clone(),
        });
        index
    }

    /// The address of the share for exactly `(mid_prefix, segment, slot)`, found
    /// through the index with **no decryption**.
    ///
    /// This replaces `search_by_mid_prefix` + `get` on the fetch-serving path,
    /// which decrypted every share in the store to read its header: one fetch
    /// request cost O(shares stored) full decryptions and index rewrites. For a
    /// 100 GiB publish that is 32,000 shares, ~200 GiB of decryption per
    /// request.
    ///
    /// If several generations of the same piece exist (the same content
    /// published twice gets a fresh key each time) the most recently written one
    /// is returned. Entries written before piece keys existed are identified by
    /// decrypting them once; the answer is recorded so it is never repeated.
    pub fn find_piece(
        &self,
        mid_prefix: &[u8; 8],
        segment_index: u32,
        slot_index: u16,
    ) -> Option<String> {
        let want = PieceKey {
            mid_prefix: *mid_prefix,
            segment_index,
            slot_index,
        };
        let pick = |index: &StoreIndex| {
            index
                .iter()
                .filter(|(_, e)| e.piece == Some(want))
                .max_by_key(|(_, e)| e.last_accessed_secs)
                .map(|(addr, _)| addr.clone())
        };

        if let Some(addr) = pick(&self.index_snapshot()) {
            return Some(addr);
        }

        // Not in the cached view: the cache may simply be stale, so look once at
        // the file itself before concluding the piece is not here.
        let fresh = load_index(&self.data_dir);
        if let Some(addr) = pick(&fresh) {
            return Some(addr);
        }
        if fresh.values().all(|e| e.piece.is_some()) {
            return None;
        }
        self.backfill_pieces(&want)
    }

    /// One-time migration for entries with no piece key: decrypt each, record its
    /// key in the index, and return the address matching `want`, if any.
    fn backfill_pieces(&self, want: &PieceKey) -> Option<String> {
        let _guard = self.write_lock.lock().ok()?;
        let mut index = load_index(&self.data_dir);
        let unknown: Vec<String> = index
            .iter()
            .filter(|(_, e)| e.piece.is_none())
            .map(|(a, _)| a.clone())
            .collect();
        let mut found: Option<(String, u64)> = None;
        let mut changed = false;
        for addr in unknown {
            let Ok(share) = self.get_untouched(&addr) else {
                continue;
            };
            let key = PieceKey::of(&share);
            if let Some(e) = index.get_mut(&addr) {
                e.piece = Some(key);
                changed = true;
                if key == *want
                    && found
                        .as_ref()
                        .is_none_or(|(_, t)| e.last_accessed_secs >= *t)
                {
                    found = Some((addr.clone(), e.last_accessed_secs));
                }
            }
        }
        if changed {
            let _ = save_index(&self.data_dir, &index);
        }
        found.map(|(a, _)| a)
    }

    /// Check if a share with the given address exists.
    pub fn contains(&self, address: &str) -> bool {
        self.share_path(address).exists()
    }

    /// List all stored share addresses.
    pub fn list(&self) -> Vec<String> {
        load_index(&self.data_dir).into_keys().collect()
    }

    /// Delete a specific share by address.
    pub fn delete(&self, address: &str) -> Result<(), MiasmaError> {
        let _guard = self.write_lock.lock().unwrap();
        let _ = std::fs::remove_file(self.share_path(address));
        let mut index = load_index(&self.data_dir);
        index.remove(address);
        save_index(&self.data_dir, &index)
    }

    /// **Distress wipe**: delete the master key, making all stored shares
    /// immediately and permanently unreadable.
    ///
    /// Completes in O(1) — just one file deletion. Satisfies the ≤5s SLO.
    /// The share files remain on disk but cannot be decrypted without the key.
    ///
    /// Returns `Ok(())` on success.
    pub fn distress_wipe(&self) -> Result<(), MiasmaError> {
        // Serialize against writers. Readers serialize on the master-key lock;
        // waiting for it here guarantees no pre-wipe decrypt remains in flight
        // when this method returns.
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| MiasmaError::Storage("store write lock poisoned".into()))?;
        let mut master_guard = self.lock_master_key()?;

        // Dropping `Zeroizing` immediately erases the in-process key. Even if
        // disk cleanup fails, this store instance remains fail-closed.
        *master_guard = None;

        let mut cleanup_errors = Vec::new();
        let key_path = self.data_dir.join(MASTER_KEY_FILE);
        if key_path.exists() {
            let zeros = vec![0u8; 32];
            if let Err(e) = atomic_write(&key_path, &zeros) {
                cleanup_errors.push(format!("erase master.key: {e}"));
            } else if let Err(e) = std::fs::remove_file(&key_path) {
                cleanup_errors.push(format!("remove erased master.key: {e}"));
            }
        }

        // Scrub persisted transport secrets from config.toml so they do not
        // survive a wipe. A parse/save failure is wipe failure, never advisory.
        let config_path = self.data_dir.join("config.toml");
        if config_path.exists() {
            match crate::config::NodeConfig::load(&self.data_dir) {
                Ok(mut config) => {
                    if config.has_persisted_secrets() {
                        if let Err(e) = config.scrub_credentials(&self.data_dir) {
                            cleanup_errors.push(format!("scrub transport secrets: {e}"));
                        }
                    }
                }
                Err(e) => {
                    cleanup_errors.push(format!("load config for proxy credential scrub: {e}"))
                }
            }
        }

        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(MiasmaError::Storage(format!(
                "distress wipe incomplete: {}",
                cleanup_errors.join("; ")
            )))
        }
    }

    /// Return addresses of all shares whose `mid_prefix` matches `prefix`.
    ///
    /// Decrypts each stored share to check the prefix. In Phase 1 the store
    /// is small so this is acceptable; Phase 2 will cache the prefix index.
    pub fn search_by_mid_prefix(&self, prefix: &[u8; 8]) -> Vec<String> {
        self.list()
            .into_iter()
            .filter(|addr| {
                self.get(addr)
                    .map(|s| s.mid_prefix == *prefix)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Current total size of all stored share blobs in bytes.
    pub fn used_bytes(&self) -> u64 {
        load_index(&self.data_dir)
            .values()
            .map(|e| e.size_bytes)
            .sum()
    }

    /// Configured byte budget for locally-owned shares.
    ///
    /// Large streaming publishes use this for a preflight check so a file
    /// cannot silently evict its own earlier segments while it is still being
    /// published.
    pub fn owned_quota_bytes(&self) -> u64 {
        self.quota_bytes
    }

    /// Current byte usage by locally-owned shares only.
    pub fn used_owned_bytes(&self) -> u64 {
        load_index(&self.data_dir)
            .values()
            .filter(|entry| entry.origin == ShareOrigin::Owned)
            .map(|entry| entry.size_bytes)
            .sum()
    }

    // ── private helpers ────────────────────────────────────────────────────

    fn share_path(&self, address: &str) -> PathBuf {
        self.shares_dir.join(format!("{}{}", address, SHARE_EXT))
    }

    /// Evict LRU *owned* entries until `needed_bytes` fit within the owned
    /// quota. Never evicts `skip_address` (the entry being written) or any
    /// `Hosted` entry -- a local dissolve running low on owned-quota space
    /// must never free room by deleting shares this node is hosting on
    /// behalf of a remote publisher. Caller must already hold `write_lock`.
    fn evict_if_needed_locked(
        &self,
        needed_bytes: u64,
        skip_address: &str,
    ) -> Result<(), MiasmaError> {
        let mut index = load_index(&self.data_dir);
        let current: u64 = index
            .values()
            .filter(|e| e.origin == ShareOrigin::Owned)
            .map(|e| e.size_bytes)
            .sum();

        if current + needed_bytes <= self.quota_bytes {
            return Ok(());
        }

        // Sort by last_accessed ascending (oldest first). Hosted entries are
        // never eviction candidates here.
        let mut entries: Vec<(String, u64, u64)> = index
            .iter()
            .filter(|(addr, e)| addr.as_str() != skip_address && e.origin == ShareOrigin::Owned)
            .map(|(addr, e)| (addr.clone(), e.size_bytes, e.last_accessed_secs))
            .collect();
        entries.sort_by_key(|(_, _, t)| *t);

        let mut freed = 0u64;
        for (addr, size, _) in entries {
            if current + needed_bytes - freed <= self.quota_bytes {
                break;
            }
            let _ = std::fs::remove_file(self.share_path(&addr));
            index.remove(&addr);
            freed += size;
            tracing::debug!("evicted share {} ({} bytes)", addr, size);
        }

        save_index(&self.data_dir, &index)
    }
}

// ─── ShareSink implementation ─────────────────────────────────────────────────

/// Implement `ShareSink` so `LocalShareStore` can be used directly with
/// `ShareDistributor` (Task 5 distribution protocol).
#[async_trait::async_trait]
impl crate::dissolution::ShareSink for LocalShareStore {
    /// Just the storage address -- a local store has no peer/network
    /// placement metadata to report (see `network::NetworkShareSink` for the
    /// receipt type that does).
    type Receipt = String;

    async fn store(&self, share: MiasmaShare) -> Result<String, crate::MiasmaError> {
        self.put(&share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::ContentId;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dummy_share(idx: u16) -> MiasmaShare {
        let mid = ContentId::compute(b"test content", b"k=10,n=20,v=1");
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        MiasmaShare::new(
            &mid,
            0, // segment_index
            idx,
            vec![idx as u8; 64],
            vec![0xAA; 32],
            rand::random::<[u8; 12]>(),
            100,
            ts,
        )
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(0);
        let addr = store.put(&share).unwrap();
        let recovered = store.get(&addr).unwrap();
        assert_eq!(share.slot_index, recovered.slot_index);
        assert_eq!(share.shard_hash, recovered.shard_hash);
    }

    #[test]
    fn idempotent_put() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(1);
        let a1 = store.put(&share).unwrap();
        let a2 = store.put(&share).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn wrong_key_decrypt_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store1 = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(2);
        let addr = store1.put(&share).unwrap();

        // Delete master key and create a different one.
        store1.distress_wipe().unwrap();
        // Re-open store — new master key generated.
        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        // Should fail to decrypt (different key).
        assert!(store2.get(&addr).is_err());
    }

    #[test]
    fn distress_wipe_reports_config_scrub_failure_but_stays_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(24);
        let addr = store.put(&share).unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[transport\nproxy_password = \"still-secret\"",
        )
        .unwrap();

        let err = store.distress_wipe().unwrap_err();
        assert!(err.to_string().contains("distress wipe incomplete"));
        assert!(!dir.path().join(MASTER_KEY_FILE).exists());
        assert!(store.get(&addr).is_err(), "store must remain fail-closed");
    }

    #[test]
    fn distress_wipe_removes_master_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(22);
        let addr = store.put(&share).unwrap();
        assert!(store.get(&addr).is_ok());

        store.distress_wipe().unwrap();
        assert!(!dir.path().join(MASTER_KEY_FILE).exists());
        assert!(
            store.get(&addr).is_err(),
            "same process must not decrypt after wipe"
        );
        assert!(
            store.put(&dummy_share(23)).is_err(),
            "same process must not write after wipe"
        );
    }

    #[test]
    fn lru_eviction_respects_quota() {
        let dir = tempfile::tempdir().unwrap();
        // Very small quota: 1 MiB
        let store = LocalShareStore::open(dir.path(), 1).unwrap();

        // Store many shares until eviction kicks in.
        let mut addrs = vec![];
        for i in 0..30u16 {
            let share = dummy_share(i);
            let addr = store.put(&share).unwrap();
            addrs.push(addr);
        }
        assert!(store.used_bytes() <= 1024 * 1024 + 4096 /* slack */);
    }

    #[test]
    fn list_contains_stored_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let s0 = dummy_share(0);
        let s1 = dummy_share(1);
        let a0 = store.put(&s0).unwrap();
        let a1 = store.put(&s1).unwrap();
        let list = store.list();
        assert!(list.contains(&a0));
        assert!(list.contains(&a1));
    }

    // ── Crash recovery tests ────────────────────────────────────────────────

    #[test]
    fn corrupted_index_falls_back_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(10);
        let addr = store.put(&share).unwrap();
        drop(store);

        // Corrupt the index file.
        std::fs::write(dir.path().join(INDEX_FILE), b"{{not json!").unwrap();

        // Re-open: should rebuild from share files on disk.
        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        let list = store2.list();
        assert!(
            list.contains(&addr),
            "index should be rebuilt from share files"
        );
        // Share should still be readable.
        let recovered = store2.get(&addr).unwrap();
        assert_eq!(recovered.slot_index, 10);
    }

    #[test]
    fn missing_index_rebuilt_from_share_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let s0 = dummy_share(20);
        let s1 = dummy_share(21);
        let a0 = store.put(&s0).unwrap();
        let a1 = store.put(&s1).unwrap();
        drop(store);

        // Delete the index file entirely.
        let _ = std::fs::remove_file(dir.path().join(INDEX_FILE));

        // Re-open: should rebuild from share files.
        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        let list = store2.list();
        assert!(list.contains(&a0));
        assert!(list.contains(&a1));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn orphaned_tmp_files_cleaned_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        drop(store);

        // Create orphaned .tmp files simulating interrupted writes.
        let tmp1 = dir.path().join("store_index.tmp");
        let tmp2 = dir.path().join(SHARES_DIR).join("deadbeef.tmp");
        std::fs::write(&tmp1, b"partial write").unwrap();
        std::fs::write(&tmp2, b"partial share").unwrap();
        assert!(tmp1.exists());
        assert!(tmp2.exists());

        // Re-open: .tmp files should be cleaned up.
        let _store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        assert!(!tmp1.exists(), "data_dir .tmp should be removed");
        assert!(!tmp2.exists(), "shares_dir .tmp should be removed");
    }

    #[test]
    fn master_key_wrong_length_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        // Write a 16-byte key (wrong length — should be 32).
        std::fs::write(dir.path().join(MASTER_KEY_FILE), [0xFFu8; 16]).unwrap();

        let result = LocalShareStore::open(dir.path(), 100);
        assert!(result.is_err(), "wrong-length master.key should fail");
        let err_msg = result.err().map(|e| format!("{e}")).unwrap_or_default();
        assert!(
            err_msg.contains("wrong length"),
            "error should mention wrong length: {err_msg}"
        );
    }

    #[test]
    fn master_key_empty_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        // Write an empty file.
        std::fs::write(dir.path().join(MASTER_KEY_FILE), []).unwrap();

        let result = LocalShareStore::open(dir.path(), 100);
        assert!(result.is_err(), "empty master.key should fail");
    }

    #[test]
    fn shares_dir_deleted_recreated_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        drop(store);

        // Delete shares directory.
        std::fs::remove_dir_all(dir.path().join(SHARES_DIR)).unwrap();

        // Re-open: shares dir should be recreated.
        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(30);
        let addr = store2.put(&share).unwrap();
        let recovered = store2.get(&addr).unwrap();
        assert_eq!(recovered.slot_index, 30);
    }

    #[test]
    fn partial_share_write_does_not_corrupt_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(40);
        let addr = store.put(&share).unwrap();
        drop(store);

        // Simulate a crash that left a .tmp file but the actual .ms is fine.
        let orphan = dir.path().join(SHARES_DIR).join(format!("{addr}.tmp"));
        std::fs::write(&orphan, b"interrupted write data").unwrap();

        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        assert!(!orphan.exists(), ".tmp should be cleaned up");
        // Original share should still be readable.
        let recovered = store2.get(&addr).unwrap();
        assert_eq!(recovered.slot_index, 40);
    }

    #[test]
    fn truncated_share_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let share = dummy_share(50);
        let addr = store.put(&share).unwrap();
        drop(store);

        // Truncate the share file (simulate disk corruption).
        let share_path = dir
            .path()
            .join(SHARES_DIR)
            .join(format!("{addr}{SHARE_EXT}"));
        std::fs::write(&share_path, [0u8; 10]).unwrap();

        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        let result = store2.get(&addr);
        assert!(result.is_err(), "truncated share should fail to decrypt");
    }

    #[test]
    fn multiple_shares_survive_index_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let mut addrs = vec![];
        for i in 60..65u16 {
            addrs.push(store.put(&dummy_share(i)).unwrap());
        }
        drop(store);

        // Corrupt index.
        std::fs::write(dir.path().join(INDEX_FILE), b"garbage").unwrap();

        // Rebuild: all 5 shares should reappear.
        let store2 = LocalShareStore::open(dir.path(), 100).unwrap();
        let list = store2.list();
        assert_eq!(list.len(), 5, "all 5 shares should be in rebuilt index");
        for addr in &addrs {
            assert!(list.contains(addr));
        }
    }

    #[test]
    fn index_and_shares_dir_both_missing_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        // Only create master.key — no shares dir, no index.
        std::fs::create_dir_all(dir.path()).unwrap();
        let key = [0xABu8; 32];
        crate::secure_file::atomic_write_restricted(&dir.path().join(MASTER_KEY_FILE), &key)
            .unwrap();

        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        assert!(store.list().is_empty());
        // Should be able to write a share.
        let addr = store.put(&dummy_share(70)).unwrap();
        assert_eq!(store.list().len(), 1);
        assert!(store.list().contains(&addr));
    }

    // ── find_piece: index lookup instead of decrypting the whole store ───────

    fn piece(seg: u32, slot: u16, payload: u8) -> MiasmaShare {
        let mid = ContentId::compute(b"piece lookup", b"k=10,n=20,v=1");
        MiasmaShare::new(
            &mid,
            seg,
            slot,
            vec![payload; 64],
            vec![0xAA; 32],
            rand::random::<[u8; 12]>(),
            100,
            1,
        )
    }

    fn prefix() -> [u8; 8] {
        ContentId::compute(b"piece lookup", b"k=10,n=20,v=1").prefix()
    }

    fn index_json(dir: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join(INDEX_FILE)).unwrap()).unwrap()
    }

    fn write_index_json(dir: &Path, v: &serde_json::Value) {
        std::fs::write(dir.join(INDEX_FILE), serde_json::to_string(v).unwrap()).unwrap();
    }

    #[test]
    fn find_piece_locates_each_share_by_its_tuple() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let a = store.put(&piece(0, 0, 1)).unwrap();
        let b = store.put(&piece(0, 1, 2)).unwrap();
        let c = store.put(&piece(1, 0, 3)).unwrap();

        assert_eq!(store.find_piece(&prefix(), 0, 0), Some(a));
        assert_eq!(store.find_piece(&prefix(), 0, 1), Some(b));
        assert_eq!(store.find_piece(&prefix(), 1, 0), Some(c.clone()));
        // Segment and slot are not interchangeable.
        assert_eq!(store.find_piece(&prefix(), 0, 2), None);
        assert_eq!(store.find_piece(&prefix(), 2, 0), None);
        // Nor is a different MID.
        assert_eq!(store.find_piece(&[9u8; 8], 1, 0), None);

        let got = store.get_untouched(&c).unwrap();
        assert_eq!((got.segment_index, got.slot_index), (1, 0));
    }

    #[test]
    fn a_lookup_neither_decrypts_other_shares_nor_writes_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let mut target = String::new();
        for slot in 0..20u16 {
            let addr = store.put(&piece(0, slot, slot as u8)).unwrap();
            if slot == 7 {
                target = addr;
            }
        }
        // Destroy every other share file: the old scan decrypted all of them and
        // would have choked. An index lookup must not need them at all.
        for addr in store.list() {
            if addr != target {
                std::fs::write(
                    dir.path()
                        .join(SHARES_DIR)
                        .join(format!("{addr}{SHARE_EXT}")),
                    b"x",
                )
                .unwrap();
            }
        }
        let before = std::fs::read(dir.path().join(INDEX_FILE)).unwrap();
        for _ in 0..50 {
            let addr = store.find_piece(&prefix(), 0, 7).expect("must be found");
            assert_eq!(addr, target);
            assert_eq!(store.get_untouched(&addr).unwrap().slot_index, 7);
        }
        let after = std::fs::read(dir.path().join(INDEX_FILE)).unwrap();
        assert_eq!(before, after, "serving reads must not rewrite the index");
    }

    #[test]
    fn get_untouched_leaves_last_accessed_alone_but_get_still_updates_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let addr = store.put(&piece(0, 0, 1)).unwrap();

        // Age the entry so a touch is visible.
        let mut v = index_json(dir.path());
        v[&addr]["last_accessed_secs"] = serde_json::json!(5);
        write_index_json(dir.path(), &v);

        store.get_untouched(&addr).unwrap();
        assert_eq!(index_json(dir.path())[&addr]["last_accessed_secs"], 5);

        store.get(&addr).unwrap();
        assert!(
            index_json(dir.path())[&addr]["last_accessed_secs"]
                .as_u64()
                .unwrap()
                > 5
        );
    }

    #[test]
    fn find_piece_prefers_the_newest_generation() {
        // The same content published twice gets a fresh key each time, so the same
        // (mid, segment, slot) can be stored under two addresses.
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let old = store.put(&piece(0, 0, 1)).unwrap();
        let new = store.put(&piece(0, 0, 2)).unwrap();
        assert_ne!(old, new);

        let mut v = index_json(dir.path());
        v[&old]["last_accessed_secs"] = serde_json::json!(100);
        v[&new]["last_accessed_secs"] = serde_json::json!(200);
        write_index_json(dir.path(), &v);

        let fresh = LocalShareStore::open(dir.path(), 100).unwrap();
        assert_eq!(fresh.find_piece(&prefix(), 0, 0), Some(new));
    }

    #[test]
    fn entries_from_before_piece_keys_are_found_and_recorded_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        let a = store.put(&piece(0, 0, 1)).unwrap();
        let b = store.put(&piece(3, 5, 2)).unwrap();

        // Rewrite the index the way an older version would have: no `piece`.
        let mut v = index_json(dir.path());
        for addr in [&a, &b] {
            v[addr].as_object_mut().unwrap().remove("piece");
        }
        write_index_json(dir.path(), &v);
        assert!(index_json(dir.path())[&a].get("piece").is_none());

        let fresh = LocalShareStore::open(dir.path(), 100).unwrap();
        assert_eq!(fresh.find_piece(&prefix(), 3, 5), Some(b.clone()));
        // The answer was recorded for *both* legacy entries, not just the match.
        let after = index_json(dir.path());
        assert!(
            !after[&a]["piece"].is_null(),
            "legacy entry a was backfilled"
        );
        assert!(
            !after[&b]["piece"].is_null(),
            "legacy entry b was backfilled"
        );
        assert_eq!(fresh.find_piece(&prefix(), 0, 0), Some(a));
    }

    #[test]
    fn find_piece_survives_a_reopen_and_sees_another_instances_writes() {
        let dir = tempfile::tempdir().unwrap();
        let first = LocalShareStore::open(dir.path(), 100).unwrap();
        let a = first.put(&piece(0, 0, 1)).unwrap();
        assert_eq!(first.find_piece(&prefix(), 0, 0), Some(a));

        // A second handle on the same directory writes a new piece; the first
        // handle's cached view must not hide it.
        let second = LocalShareStore::open(dir.path(), 100).unwrap();
        let b = second.put(&piece(4, 4, 9)).unwrap();
        assert_eq!(first.find_piece(&prefix(), 4, 4), Some(b));
    }

    #[test]
    fn hosted_shares_are_findable_too() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100)
            .unwrap()
            .with_hosted_quota_mb(10);
        let addr = store.put_hosted(&piece(2, 3, 7)).unwrap();
        assert_eq!(store.find_piece(&prefix(), 2, 3), Some(addr));
    }

    /// Measurement, not a correctness test: how the cost of one `put` grows with
    /// the number of shares already stored. Every `put` re-reads and rewrites the
    /// whole JSON index, so this should grow linearly with the store size (and a
    /// whole publish quadratically). Run with:
    /// `cargo test -p miasma-core --lib -- --ignored --nocapture measure_put_cost`
    #[test]
    #[ignore]
    fn measure_put_cost_growth() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100_000).unwrap();
        let mut n = 0u32;
        let mut last = std::time::Instant::now();
        for checkpoint in [250u32, 500, 1000, 2000, 4000] {
            let batch_start = n;
            let t = std::time::Instant::now();
            while n < checkpoint {
                store
                    .put(&piece(n / 20, (n % 20) as u16, (n % 251) as u8))
                    .unwrap();
                n += 1;
            }
            let per_put = t.elapsed().as_secs_f64() * 1e3 / (n - batch_start) as f64;
            let idx = std::fs::metadata(dir.path().join(INDEX_FILE))
                .unwrap()
                .len();
            println!(
                "[measure] shares {:>5}: avg {:>7.2} ms/put over the last {:>4}, index file {:>6.2} MB",
                n,
                per_put,
                n - batch_start,
                idx as f64 / 1e6
            );
            last = std::time::Instant::now();
        }
        let _ = last;
    }
}
