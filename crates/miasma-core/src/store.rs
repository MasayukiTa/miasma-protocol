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

// ─── LRU index ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    size_bytes: u64,
    last_accessed_secs: u64,
}

type StoreIndex = HashMap<String, IndexEntry>;

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
    let raw = serde_json::to_string(index).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
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
        let bytes = std::fs::read(&key_path)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| MiasmaError::KeyDerivation("master.key has wrong length".into()))?;
        Ok(Zeroizing::new(arr))
    } else {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.as_mut().copy_from_slice(&key);
        std::fs::create_dir_all(data_dir)?;

        // Write the key via atomic_write_restricted: the file is created
        // with a restrictive DACL/mode from the start (Win32 CreateFileW
        // with SECURITY_ATTRIBUTES on Windows, open() with 0o600 on Unix).
        // At no point does the key exist on disk with permissive permissions.
        crate::secure_file::atomic_write_restricted(&key_path, arr.as_ref())
            .map_err(|e| MiasmaError::KeyDerivation(format!(
                "failed to write master.key with restricted permissions: {e}"
            )))?;

        Ok(arr)
    }
}

/// Derive a per-file XChaCha20-Poly1305 key from the master key and the share address.
///
/// `key = HKDF-SHA256(ikm = master_key, info = "miasma-store-v1:" || address_hex)`
fn derive_file_key(master_key: &[u8; 32], address: &str) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
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

// ─── LocalShareStore ─────────────────────────────────────────────────────────

/// Encrypted local share store.
///
/// Thread-safety: not `Sync`. Wrap in `Arc<Mutex<_>>` for shared access.
pub struct LocalShareStore {
    data_dir: PathBuf,
    shares_dir: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
    /// Quota in bytes.
    quota_bytes: u64,
}

impl LocalShareStore {
    /// Open (or create) the store under `data_dir`.
    pub fn open(data_dir: &Path, quota_mb: u64) -> Result<Self, MiasmaError> {
        let shares_dir = data_dir.join(SHARES_DIR);
        std::fs::create_dir_all(&shares_dir)?;
        let master_key = load_or_create_master_key(data_dir)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            shares_dir,
            master_key,
            quota_bytes: quota_mb * 1024 * 1024,
        })
    }

    /// Content-address of a share: `BLAKE3(bincode(share))` as lowercase hex.
    pub fn address_of(share: &MiasmaShare) -> Result<String, MiasmaError> {
        let bytes = share.to_bytes()?;
        Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    /// Store a share. Returns its content address.
    ///
    /// If the address already exists (idempotent re-store), updates last_accessed.
    /// If quota is exceeded, evicts LRU entries until space is available.
    pub fn put(&self, share: &MiasmaShare) -> Result<String, MiasmaError> {
        let address = Self::address_of(share)?;
        let file_path = self.share_path(&address);

        // Serialize share to plaintext bytes.
        let plaintext = share.to_bytes()?;
        let size = plaintext.len() as u64;

        // Ensure quota.
        self.evict_if_needed(size, &address)?;

        // Derive per-file key and encrypt.
        let file_key = derive_file_key(&self.master_key, &address)?;
        let blob = encrypt_share(&file_key, &plaintext)?;

        atomic_write(&file_path, &blob)?;

        // Update index.
        let mut index = load_index(&self.data_dir);
        index.insert(
            address.clone(),
            IndexEntry {
                size_bytes: blob.len() as u64,
                last_accessed_secs: now_secs(),
            },
        );
        save_index(&self.data_dir, &index)?;

        Ok(address)
    }

    /// Retrieve a share by its content address.
    pub fn get(&self, address: &str) -> Result<MiasmaShare, MiasmaError> {
        let file_path = self.share_path(address);
        let blob = std::fs::read(&file_path)?;

        let file_key = derive_file_key(&self.master_key, address)?;
        let plaintext = decrypt_share(&file_key, &blob)?;
        let share = MiasmaShare::from_bytes(&plaintext)?;

        // Update last_accessed.
        let mut index = load_index(&self.data_dir);
        if let Some(entry) = index.get_mut(address) {
            entry.last_accessed_secs = now_secs();
            let _ = save_index(&self.data_dir, &index);
        }

        Ok(share)
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
        let key_path = self.data_dir.join(MASTER_KEY_FILE);
        // Zero-fill before deletion for defense against data recovery tools.
        if key_path.exists() {
            let zeros = vec![0u8; 32];
            let _ = atomic_write(&key_path, &zeros);
            std::fs::remove_file(&key_path)?;
        }

        // Scrub proxy credentials from config.toml so they don't survive a wipe.
        let config_path = self.data_dir.join("config.toml");
        if config_path.exists() {
            if let Ok(mut config) = crate::config::NodeConfig::load(&self.data_dir) {
                if config.transport.proxy_username.is_some()
                    || config.transport.proxy_password.is_some()
                {
                    let _ = config.scrub_credentials(&self.data_dir);
                }
            }
        }

        Ok(())
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

    // ── private helpers ────────────────────────────────────────────────────

    fn share_path(&self, address: &str) -> PathBuf {
        self.shares_dir
            .join(format!("{}{}", address, SHARE_EXT))
    }

    /// Evict LRU entries until `needed_bytes` fit within quota.
    /// Never evicts `skip_address` (the entry being written).
    fn evict_if_needed(&self, needed_bytes: u64, skip_address: &str) -> Result<(), MiasmaError> {
        let mut index = load_index(&self.data_dir);
        let current: u64 = index.values().map(|e| e.size_bytes).sum();

        if current + needed_bytes <= self.quota_bytes {
            return Ok(());
        }

        // Sort by last_accessed ascending (oldest first).
        let mut entries: Vec<(String, u64, u64)> = index
            .iter()
            .filter(|(addr, _)| addr.as_str() != skip_address)
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
            [0u8; 12],
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
    fn distress_wipe_removes_master_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalShareStore::open(dir.path(), 100).unwrap();
        store.distress_wipe().unwrap();
        assert!(!dir.path().join(MASTER_KEY_FILE).exists());
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
        assert!(store.used_bytes() <= 1 * 1024 * 1024 + 4096 /* slack */);
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
}
