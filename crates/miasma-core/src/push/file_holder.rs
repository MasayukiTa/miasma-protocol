//! A disk-backed custody store sized for deposited files.
//!
//! The chat custody store ([`crate::chat::mailbox::holder::MemoryCustody`]) is
//! held entirely in RAM and hard-capped at a few megabytes: it is meant for
//! single sealed messages, not files. An offline *file* deposit can be far
//! larger than the RAM an idle node should hold, so files are kept by a
//! separate store that writes each item to disk and never holds more than one
//! item in memory at a time.
//!
//! It implements the very same [`CustodyStore`] verbs as the chat store, so the
//! existing [`crate::chat::mailbox::client::MailboxClient`] and the
//! [`crate::push::deposit`] file deposit/fetch work against it unchanged. What a
//! holder keeps is ciphertext only (the deposit module seals every chunk and
//! the manifest under a key derived from the two identities); this store never
//! looks inside an item.
//!
//! Everything is bounded:
//!
//! * a size limit per item, a limit on items and bytes in total, and a budget
//!   of items and bytes per depositor (so one contact cannot use it all);
//! * every item expires after a fixed time and is dropped by the next call
//!   that touches the store, or by [`CustodyStore::sweep`];
//! * only contacts the holder trusts may deposit, list, fetch or delete;
//! * with the switch off (the default) every deposit is refused.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use crate::chat::mailbox::holder::{CustodyError, CustodyStats, CustodyStore, DepositOutcome};
use crate::chat::mailbox::ids::{ItemId, RecipientTag};
use crate::config::PushConfig;

/// Ceilings the settings cannot raise. A file holder may hold a large file, but
/// not without bound: the total is capped so a single depositor cannot fill the
/// disk, and an item is capped at one sealed deposit chunk plus a small margin
/// (the deposit module never puts more than [`crate::push::deposit::CHUNK_PLAINTEXT`]
/// of plaintext in one item).
pub const HARD_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const HARD_MAX_ITEMS: usize = 1 << 20;
pub const HARD_MAX_TTL_MS: u64 = 30 * 86_400_000;
/// Largest item a file holder accepts: one sealed chunk is 16 KiB of plaintext
/// plus a 16-byte tag; 64 KiB leaves ample room and still rejects anything that
/// is not a deposit chunk or manifest.
pub const HARD_MAX_ITEM_BYTES: usize = 64 * 1024;
/// Items returned by one listing (the same cap the chat store uses).
pub const MAX_LIST: usize = 64;

/// What a file holder will keep, from `[push]` in the settings. Only the switch
/// and the sizes come from settings; the hard ceilings above still apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCustodyLimits {
    /// Off by default: a holder that is off refuses every deposit.
    pub enabled: bool,
    pub max_item_bytes: usize,
    pub max_total_bytes: u64,
    pub max_items: usize,
    pub max_items_per_depositor: usize,
    pub max_bytes_per_depositor: u64,
    /// How long an item is kept.
    pub ttl_ms: u64,
}

impl Default for FileCustodyLimits {
    fn default() -> Self {
        Self {
            enabled: false,
            max_item_bytes: HARD_MAX_ITEM_BYTES,
            // Enough for one 64 MiB file (the slice target) from one depositor,
            // with room for a second alongside it.
            max_total_bytes: 256 * 1024 * 1024,
            max_items: 1 << 16,
            max_items_per_depositor: 1 << 14,
            max_bytes_per_depositor: 128 * 1024 * 1024,
            ttl_ms: 14 * 86_400_000,
        }
    }
}

impl FileCustodyLimits {
    /// The limits for `[push]`: the switch and the quota come from the settings,
    /// then the hard ceilings are applied.
    pub fn from_config(c: &PushConfig) -> Self {
        Self {
            enabled: c.file_custody_enabled,
            max_total_bytes: c.file_custody_total_bytes,
            max_bytes_per_depositor: c.file_custody_per_depositor_bytes,
            ttl_ms: c.file_custody_ttl_ms,
            ..Self::default()
        }
        .clamped()
    }

    fn clamped(mut self) -> Self {
        self.max_item_bytes = self.max_item_bytes.min(HARD_MAX_ITEM_BYTES);
        self.max_total_bytes = self.max_total_bytes.min(HARD_MAX_TOTAL_BYTES);
        self.max_items = self.max_items.min(HARD_MAX_ITEMS);
        self.max_bytes_per_depositor = self.max_bytes_per_depositor.min(HARD_MAX_TOTAL_BYTES);
        self.ttl_ms = self.ttl_ms.min(HARD_MAX_TTL_MS);
        self
    }
}

struct Meta {
    from: [u8; 32],
    len: u64,
    expires_ms: u64,
    order: u64,
    /// The file on disk holding the ciphertext for this item.
    path: PathBuf,
}

struct Inner {
    items: HashMap<(RecipientTag, ItemId), Meta>,
    bytes: u64,
    per_depositor: HashMap<[u8; 32], (usize, u64)>,
    next_order: u64,
}

impl Inner {
    fn remove(&mut self, key: &(RecipientTag, ItemId)) -> bool {
        let Some(m) = self.items.remove(key) else {
            return false;
        };
        self.bytes = self.bytes.saturating_sub(m.len);
        if let Some(d) = self.per_depositor.get_mut(&m.from) {
            d.0 = d.0.saturating_sub(1);
            d.1 = d.1.saturating_sub(m.len);
            if d.0 == 0 {
                self.per_depositor.remove(&m.from);
            }
        }
        // A failed unlink only leaves the bytes on disk until the dir is wiped.
        let _ = fs::remove_file(&m.path);
        true
    }

    fn sweep(&mut self, now_ms: u64) -> usize {
        let gone: Vec<_> = self
            .items
            .iter()
            .filter(|(_, m)| m.expires_ms <= now_ms)
            .map(|(k, _)| *k)
            .collect();
        for k in &gone {
            self.remove(k);
        }
        gone.len()
    }
}

/// A custody store that keeps each item as a file under one directory. The
/// directory is the caller's to place (and to wipe on shutdown); nothing here
/// survives a wipe of it.
pub struct DiskFileCustody {
    limits: FileCustodyLimits,
    dir: PathBuf,
    trusted: Mutex<HashSet<[u8; 32]>>,
    inner: Mutex<Inner>,
}

impl DiskFileCustody {
    /// Create a store that writes items under `dir` (created if missing).
    pub fn new(limits: FileCustodyLimits, dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            limits: limits.clamped(),
            dir,
            trusted: Mutex::new(HashSet::new()),
            inner: Mutex::new(Inner {
                items: HashMap::new(),
                bytes: 0,
                per_depositor: HashMap::new(),
                next_order: 0,
            }),
        })
    }

    pub fn limits(&self) -> &FileCustodyLimits {
        &self.limits
    }

    /// Let the contact `id` use this holder.
    pub fn trust(&self, id: [u8; 32]) {
        self.trusted.lock().unwrap().insert(id);
    }

    /// Stop serving `id` and drop what it deposited.
    pub fn revoke(&self, id: &[u8; 32]) {
        self.trusted.lock().unwrap().remove(id);
        let mut g = self.inner.lock().unwrap();
        let keys: Vec<_> = g
            .items
            .iter()
            .filter(|(_, m)| &m.from == id)
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            g.remove(&k);
        }
    }

    fn check(&self, who: &[u8; 32]) -> Result<(), CustodyError> {
        if !self.limits.enabled {
            return Err(CustodyError::Disabled);
        }
        if !self.trusted.lock().unwrap().contains(who) {
            return Err(CustodyError::NotTrusted);
        }
        Ok(())
    }

    fn item_path(&self, order: u64) -> PathBuf {
        self.dir.join(format!("item-{order:020}.bin"))
    }
}

impl CustodyStore for DiskFileCustody {
    fn trust(&self, id: [u8; 32]) {
        DiskFileCustody::trust(self, id);
    }

    fn deposit(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, CustodyError> {
        self.check(who)?;
        if blob.is_empty() || blob.len() > self.limits.max_item_bytes {
            return Err(CustodyError::TooBig);
        }
        let mut g = self.inner.lock().unwrap();
        g.sweep(now_ms);
        let key = (tag, item);
        if g.items.contains_key(&key) {
            return Ok(DepositOutcome::Duplicate);
        }
        let blen = blob.len() as u64;
        let (n, b) = g.per_depositor.get(who).copied().unwrap_or((0, 0));
        if n + 1 > self.limits.max_items_per_depositor
            || b + blen > self.limits.max_bytes_per_depositor
        {
            return Err(CustodyError::DepositorBudget);
        }
        if g.items.len() + 1 > self.limits.max_items || g.bytes + blen > self.limits.max_total_bytes
        {
            return Err(CustodyError::Full);
        }
        let order = g.next_order;
        let path = self.item_path(order);
        // Write the ciphertext to its own file before recording the item, so a
        // listed item always has its bytes on disk.
        {
            let mut f = fs::File::create(&path).map_err(|_| CustodyError::Full)?;
            if f.write_all(blob).and_then(|_| f.flush()).is_err() {
                let _ = fs::remove_file(&path);
                return Err(CustodyError::Full);
            }
        }
        g.next_order += 1;
        g.bytes += blen;
        let e = g.per_depositor.entry(*who).or_insert((0, 0));
        e.0 += 1;
        e.1 += blen;
        g.items.insert(
            key,
            Meta {
                from: *who,
                len: blen,
                expires_ms: now_ms.saturating_add(self.limits.ttl_ms),
                order,
                path,
            },
        );
        Ok(DepositOutcome::Stored)
    }

    fn list(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, CustodyError> {
        self.check(who)?;
        let mut g = self.inner.lock().unwrap();
        g.sweep(now_ms);
        let mut v: Vec<(u64, ItemId)> = g
            .items
            .iter()
            .filter(|((t, _), _)| *t == tag)
            .map(|((_, i), m)| (m.order, *i))
            .collect();
        v.sort();
        Ok(v.into_iter().take(MAX_LIST).map(|(_, i)| i).collect())
    }

    fn fetch(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, CustodyError> {
        self.check(who)?;
        let mut g = self.inner.lock().unwrap();
        g.sweep(now_ms);
        let Some(m) = g.items.get(&(tag, item)) else {
            return Ok(None);
        };
        let mut buf = Vec::with_capacity(m.len as usize);
        // One item at a time: the holder reads a single item into memory, never
        // the whole file.
        match fs::File::open(&m.path).and_then(|mut f| f.read_to_end(&mut buf)) {
            Ok(_) => Ok(Some(buf)),
            // The record exists but its bytes are gone (a wiped dir); treat it
            // as not held rather than as an error.
            Err(_) => Ok(None),
        }
    }

    fn delete(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, CustodyError> {
        self.check(who)?;
        Ok(self.inner.lock().unwrap().remove(&(tag, item)))
    }

    fn sweep(&self, now_ms: u64) -> usize {
        self.inner.lock().unwrap().sweep(now_ms)
    }

    fn stats(&self) -> CustodyStats {
        let g = self.inner.lock().unwrap();
        CustodyStats {
            items: g.items.len(),
            bytes: g.bytes as usize,
        }
    }
}
