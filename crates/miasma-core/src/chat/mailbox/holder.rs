//! The custody store: sealed envelopes held for contacts who are offline.
//!
//! [`MemoryCustody`] keeps everything in memory; [`DiskCustody`] wraps it and
//! also seals a snapshot to disk so a holder that restarts does not lose what
//! it was keeping. Either way the store is bounded:
//!
//! * a size limit per item, a limit on items and bytes in total, and a budget
//!   of items and bytes per depositor (so one contact cannot use it all);
//! * every item expires after a fixed time and is dropped by the next call
//!   that touches the store;
//! * unknown peers can deposit within tighter quotas; other verbs require trust;
//! * with the switch off (the default) every deposit is refused.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use super::ids::{ItemId, RecipientTag};
use crate::{chat::proto::MAX_FRAME_BODY, config::ChatConfig};

/// Ceilings that the settings cannot raise: together they keep the store
/// within the memory the idle chat state is allowed.
pub const HARD_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const HARD_MAX_ITEMS: usize = 1024;
pub const HARD_MAX_TTL_MS: u64 = 30 * 86_400_000;
/// Items returned by one listing.
pub const MAX_LIST: usize = 64;
/// Largest item: a sealed envelope and the ID of its sender in front.
pub const MAX_ITEM_BYTES: usize = MAX_FRAME_BODY + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyLimits {
    /// Off by default: a holder that is off refuses every deposit.
    pub enabled: bool,
    pub max_item_bytes: usize,
    pub max_total_bytes: usize,
    pub max_items: usize,
    pub max_items_per_depositor: usize,
    pub max_bytes_per_depositor: usize,
    /// How long an item is kept.
    pub ttl_ms: u64,
}

impl Default for CustodyLimits {
    fn default() -> Self {
        Self {
            enabled: false,
            max_item_bytes: MAX_ITEM_BYTES,
            max_total_bytes: 2 * 1024 * 1024,
            max_items: 256,
            max_items_per_depositor: 64,
            max_bytes_per_depositor: 512 * 1024,
            ttl_ms: 14 * 86_400_000,
        }
    }
}

impl CustodyLimits {
    /// The limits for `[chat]`: the switch, the total byte and item
    /// ceilings, and the time-to-live (days) all come from the settings and
    /// are then clamped to the hard ceilings.
    pub fn from_config(c: &ChatConfig) -> Self {
        Self {
            enabled: c.custody_enabled,
            max_total_bytes: c.custody_max_total_bytes,
            max_items: c.custody_max_items,
            ttl_ms: c.custody_ttl_days.saturating_mul(86_400_000),
            ..Self::default()
        }
        .clamped()
    }

    fn clamped(mut self) -> Self {
        self.max_item_bytes = self.max_item_bytes.min(MAX_ITEM_BYTES);
        self.max_total_bytes = self.max_total_bytes.min(HARD_MAX_TOTAL_BYTES);
        self.max_items = self.max_items.min(HARD_MAX_ITEMS);
        self.ttl_ms = self.ttl_ms.min(HARD_MAX_TTL_MS);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositOutcome {
    Stored,
    /// Already held; nothing changed (the expiry is not extended).
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    #[error("holding is switched off")]
    Disabled,
    #[error("not a contact this holder trusts")]
    NotTrusted,
    #[error("item is empty or too large")]
    TooBig,
    #[error("the store is full")]
    Full,
    #[error("this depositor has used its share")]
    DepositorBudget,
    /// The caller sent custody requests faster than the per-contact rate
    /// allows. A trusted contact that hammers list/fetch/delete/deposit is
    /// told to slow down rather than being let through unchecked.
    #[error("too many custody requests; slow down")]
    RateLimited,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CustodyStats {
    pub items: usize,
    pub bytes: usize,
}

/// What a holder offers. `who` is the authenticated ID of the caller (the
/// transport proves it); every call checks it again.
pub trait CustodyStore: Send + Sync {
    /// Let the contact `id` use this holder. Called again for a caller on each
    /// request, so a contact added after start is served without a restart.
    fn trust(&self, id: [u8; 32]);
    /// Remove contact privileges without dropping existing deposits.
    fn untrust(&self, id: &[u8; 32]);

    fn deposit(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, CustodyError>;

    /// Items waiting for `tag`, oldest first, at most [`MAX_LIST`].
    fn list(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, CustodyError>;

    fn fetch(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, CustodyError>;

    /// Remove an item (the recipient has it). True when something was held.
    fn delete(&self, who: &[u8; 32], tag: RecipientTag, item: ItemId)
        -> Result<bool, CustodyError>;

    /// Drop every expired item; returns how many.
    fn sweep(&self, now_ms: u64) -> usize;

    fn stats(&self) -> CustodyStats;
}

struct Held {
    from: [u8; 32],
    blob: Vec<u8>,
    expires_ms: u64,
    order: u64,
}

struct Inner {
    items: HashMap<(RecipientTag, ItemId), Held>,
    bytes: usize,
    per_depositor: HashMap<[u8; 32], (usize, usize)>,
    next_order: u64,
}

impl Inner {
    fn remove(&mut self, key: &(RecipientTag, ItemId)) -> bool {
        let Some(h) = self.items.remove(key) else {
            return false;
        };
        self.bytes = self.bytes.saturating_sub(h.blob.len());
        if let Some(d) = self.per_depositor.get_mut(&h.from) {
            d.0 = d.0.saturating_sub(1);
            d.1 = d.1.saturating_sub(h.blob.len());
            if d.0 == 0 {
                self.per_depositor.remove(&h.from);
            }
        }
        true
    }

    fn sweep(&mut self, now_ms: u64) -> usize {
        let gone: Vec<_> = self
            .items
            .iter()
            .filter(|(_, h)| h.expires_ms <= now_ms)
            .map(|(k, _)| *k)
            .collect();
        for k in &gone {
            self.remove(k);
        }
        gone.len()
    }
}

/// The in-memory store. Contents are lost when the process ends.
pub struct MemoryCustody {
    limits: CustodyLimits,
    trusted: Mutex<HashSet<[u8; 32]>>,
    inner: Mutex<Inner>,
}

impl MemoryCustody {
    // Tags derive from public endpoint IDs; possession is not authentication.
    fn is_recipient(who: &[u8; 32], tag: RecipientTag) -> bool {
        tag == RecipientTag::for_recipient(who)
            || tag == RecipientTag::for_group_recipient(who)
            || tag == RecipientTag::for_directed_recipient(who)
    }

    pub fn new(limits: CustodyLimits) -> Self {
        Self {
            limits: limits.clamped(),
            trusted: Mutex::new(HashSet::new()),
            inner: Mutex::new(Inner {
                items: HashMap::new(),
                bytes: 0,
                per_depositor: HashMap::new(),
                next_order: 0,
            }),
        }
    }

    pub fn limits(&self) -> &CustodyLimits {
        &self.limits
    }

    /// Stop serving `id` and drop what it deposited.
    pub fn revoke(&self, id: &[u8; 32]) {
        self.trusted.lock().unwrap().remove(id);
        let mut g = self.inner.lock().unwrap();
        let keys: Vec<_> = g
            .items
            .iter()
            .filter(|(_, h)| &h.from == id)
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

    /// Serialise every held item (not the trust set, which the service
    /// re-establishes from the contact list) into a flat buffer that
    /// [`Self::restore`] reads back. Order is by `order` so the oldest item
    /// keeps its place after a restart.
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        let g = self.inner.lock().unwrap();
        let mut items: Vec<(&(RecipientTag, ItemId), &Held)> = g.items.iter().collect();
        items.sort_by_key(|(_, h)| h.order);
        let mut out = Vec::with_capacity(5 + items.len() * (16 + 16 + 32 + 8 + 4));
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for ((tag, item), h) in items {
            out.extend_from_slice(&tag.0);
            out.extend_from_slice(&item.0);
            out.extend_from_slice(&h.from);
            out.extend_from_slice(&h.expires_ms.to_be_bytes());
            out.extend_from_slice(&(h.blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&h.blob);
        }
        out
    }

    /// Replace the held items with those encoded in `buf` by [`Self::snapshot`].
    /// Items already expired at `now_ms`, or that would breach a current limit,
    /// are dropped silently: a snapshot never raises a ceiling. A malformed
    /// buffer leaves the store empty. The trust set is untouched.
    pub(crate) fn restore(&self, buf: &[u8], now_ms: u64) {
        let mut g = self.inner.lock().unwrap();
        *g = Inner {
            items: HashMap::new(),
            bytes: 0,
            per_depositor: HashMap::new(),
            next_order: 0,
        };
        let Some((&ver, mut rest)) = buf.split_first() else {
            return;
        };
        if ver != SNAPSHOT_VERSION || rest.len() < 4 {
            return;
        }
        let count = u32::from_be_bytes(rest[..4].try_into().expect("len")) as usize;
        rest = &rest[4..];
        for _ in 0..count {
            if rest.len() < 16 + 16 + 32 + 8 + 4 {
                break;
            }
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&rest[..16]);
            let mut item = [0u8; 16];
            item.copy_from_slice(&rest[16..32]);
            let mut from = [0u8; 32];
            from.copy_from_slice(&rest[32..64]);
            let expires_ms = u64::from_be_bytes(rest[64..72].try_into().expect("len"));
            let blen = u32::from_be_bytes(rest[72..76].try_into().expect("len")) as usize;
            rest = &rest[76..];
            if rest.len() < blen {
                break;
            }
            let blob = rest[..blen].to_vec();
            rest = &rest[blen..];
            // Honour the current limits and skip anything already expired, so a
            // snapshot made under looser settings cannot push the store over a
            // tightened ceiling after a restart.
            if expires_ms <= now_ms || blob.is_empty() || blob.len() > self.limits.max_item_bytes {
                continue;
            }
            let (n, b) = g.per_depositor.get(&from).copied().unwrap_or((0, 0));
            if n + 1 > self.limits.max_items_per_depositor
                || b + blob.len() > self.limits.max_bytes_per_depositor
                || g.items.len() + 1 > self.limits.max_items
                || g.bytes + blob.len() > self.limits.max_total_bytes
            {
                continue;
            }
            let order = g.next_order;
            g.next_order += 1;
            g.bytes += blob.len();
            let e = g.per_depositor.entry(from).or_insert((0, 0));
            e.0 += 1;
            e.1 += blob.len();
            g.items.insert(
                (RecipientTag(tag), ItemId(item)),
                Held {
                    from,
                    blob,
                    expires_ms,
                    order,
                },
            );
        }
    }
}

/// Version byte of the custody snapshot written to disk.
const SNAPSHOT_VERSION: u8 = 1;

impl CustodyStore for MemoryCustody {
    fn trust(&self, id: [u8; 32]) {
        self.trusted.lock().unwrap().insert(id);
    }

    fn untrust(&self, id: &[u8; 32]) {
        self.trusted.lock().unwrap().remove(id);
    }

    fn deposit(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, CustodyError> {
        if !self.limits.enabled {
            return Err(CustodyError::Disabled);
        }
        let trusted = self.trusted.lock().unwrap().clone();
        let known = trusted.contains(who);
        if blob.is_empty() || blob.len() > self.limits.max_item_bytes {
            return Err(CustodyError::TooBig);
        }
        let mut g = self.inner.lock().unwrap();
        g.sweep(now_ms);
        let key = (tag, item);
        if let Some(held) = g.items.get(&key) {
            // A repeated identical deposit (same key and blob) is a duplicate
            // regardless of who re-sends it, and never counts against a quota;
            // only a key collision carrying a different blob is refused.
            if held.blob != blob {
                return Err(CustodyError::Full);
            }
            let order = g.next_order;
            g.next_order += 1;
            g.items.get_mut(&key).unwrap().order = order;
            return Ok(DepositOutcome::Duplicate);
        }
        let (n, b) = g.per_depositor.get(who).copied().unwrap_or((0, 0));
        if n + 1 > self.limits.max_items_per_depositor
            || b + blob.len() > self.limits.max_bytes_per_depositor
            // Sixteen items prevent a single unknown peer from exhausting item
            // slots on its own. The per-identity cap alone is not enough: an
            // attacker can mint many free endpoint identities, each staying
            // under its own quota, and fill the store between them (Sybil).
            || (!known && n + 1 > 16)
            // One eighth caps a single unknown peer's bytes; the class-wide cap
            // below is what actually bounds the Sybil case.
            || (!known && b + blob.len() > self.limits.max_total_bytes / 8)
        {
            return Err(CustodyError::DepositorBudget);
        }
        // Class-wide cap for the whole unknown (non-contact) depositor set.
        // Per-identity quotas do not bound a Sybil flood of many cheap
        // identities, so all unknown depositors TOGETHER may hold at most one
        // quarter of the item count and one quarter of the bytes of the store.
        // The remaining three quarters are a guaranteed reserve for contacts:
        // the unknown class can never take the last quarter, so a contact can
        // always deposit even when strangers have flooded their share.
        if !known {
            let trusted_now = self.trusted.lock().unwrap().clone();
            let (unknown_items, unknown_bytes) = g
                .per_depositor
                .iter()
                .filter(|(from, _)| !trusted_now.contains(*from))
                .fold((0usize, 0usize), |(ni, nb), (_, (i, by))| (ni + i, nb + by));
            // One quarter of the item count: strangers in total may not hold
            // more than a quarter of the slots (many free identities each below
            // their own 16-item quota would otherwise fill every slot).
            if unknown_items + 1 > self.limits.max_items / 4
                // One quarter of the bytes: the same cap on total bytes, so a
                // Sybil cannot starve contacts out of the byte budget either.
                || unknown_bytes + blob.len() > self.limits.max_total_bytes / 4
            {
                return Err(CustodyError::DepositorBudget);
            }
        }
        if !known && n == 0 {
            let mut recent = HashMap::new();
            for held in g.items.values().filter(|h| !trusted.contains(&h.from)) {
                let order = recent.entry(held.from).or_insert(held.order);
                *order = (*order).max(held.order);
            }
            // Cap identities at 256 to bound unknown-depositor bookkeeping.
            if recent.len() >= 256 {
                if let Some((&oldest, _)) = recent.iter().min_by_key(|(_, order)| *order) {
                    let keys: Vec<_> = g
                        .items
                        .iter()
                        .filter(|(_, h)| h.from == oldest)
                        .map(|(k, _)| *k)
                        .collect();
                    for key in keys {
                        g.remove(&key);
                    }
                }
            }
        }
        if g.items.len() + 1 > self.limits.max_items
            || g.bytes + blob.len() > self.limits.max_total_bytes
        {
            return Err(CustodyError::Full);
        }
        let order = g.next_order;
        g.next_order += 1;
        g.bytes += blob.len();
        let e = g.per_depositor.entry(*who).or_insert((0, 0));
        e.0 += 1;
        e.1 += blob.len();
        g.items.insert(
            key,
            Held {
                from: *who,
                blob: blob.to_vec(),
                expires_ms: now_ms.saturating_add(self.limits.ttl_ms),
                order,
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
        if !Self::is_recipient(who, tag) {
            return Err(CustodyError::NotTrusted);
        }
        let mut g = self.inner.lock().unwrap();
        g.sweep(now_ms);
        let mut v: Vec<(u64, ItemId)> = g
            .items
            .iter()
            .filter(|((t, _), _)| *t == tag)
            .map(|((_, i), h)| (h.order, *i))
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
        match g.items.get(&(tag, item)) {
            Some(h) if h.from != *who && !Self::is_recipient(who, tag) => {
                Err(CustodyError::NotTrusted)
            }
            held => Ok(held.map(|h| h.blob.clone())),
        }
    }

    fn delete(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, CustodyError> {
        self.check(who)?;
        let mut g = self.inner.lock().unwrap();
        let key = (tag, item);
        if let Some(h) = g.items.get(&key) {
            if h.from != *who && !Self::is_recipient(who, tag) {
                return Err(CustodyError::NotTrusted);
            }
        }
        Ok(g.remove(&key))
    }

    fn sweep(&self, now_ms: u64) -> usize {
        self.inner.lock().unwrap().sweep(now_ms)
    }

    fn stats(&self) -> CustodyStats {
        let g = self.inner.lock().unwrap();
        CustodyStats {
            items: g.items.len(),
            bytes: g.bytes,
        }
    }
}

/// A [`CustodyStore`] that keeps its held items in an encrypted document on
/// disk, so a holder that restarts still has what it was keeping for an
/// offline contact. It wraps a [`MemoryCustody`] for all the bookkeeping and
/// writes a fresh snapshot after every change.
///
/// The snapshot is sealed with [`Label::ChatCustody`], exactly like the other
/// chat state; a holder learns nothing from the file it would not already learn
/// by holding the items in memory. `privacy.stealth_mode` governs logs, not
/// chat state (see `ChatConfig::history_save`), so custody is sealed to disk
/// alongside the outbox and session state, exactly like the rest of chat.
pub struct DiskCustody {
    mem: MemoryCustody,
    keys: std::sync::Arc<crate::state_crypto::StateKeys>,
    path: std::path::PathBuf,
    /// Set after a write failed: the store keeps working in memory and stops
    /// touching the file for the rest of the run, so a full or read-only disk
    /// never turns custody into an error path.
    off: std::sync::atomic::AtomicBool,
}

impl DiskCustody {
    /// Open the store at `path`, loading any snapshot found there. A snapshot
    /// that cannot be read (wrong key, damaged, truncated) is ignored and the
    /// store starts empty; the file is replaced on the next write.
    pub fn open(
        limits: CustodyLimits,
        keys: std::sync::Arc<crate::state_crypto::StateKeys>,
        path: std::path::PathBuf,
        now_ms: u64,
    ) -> Self {
        let mem = MemoryCustody::new(limits);
        if path.exists() {
            if let Ok(plain) = crate::state_crypto::doc::read_document(
                &keys,
                crate::state_crypto::Label::ChatCustody,
                &path,
            ) {
                mem.restore(&plain, now_ms);
            }
        }
        Self {
            mem,
            keys,
            path,
            off: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn limits(&self) -> &CustodyLimits {
        self.mem.limits()
    }

    /// Stop serving `id`, drop what it deposited, and write the smaller store.
    pub fn revoke(&self, id: &[u8; 32]) {
        self.mem.revoke(id);
        self.persist();
    }

    /// Write the current items to disk, unless writing was turned off after an
    /// earlier failure.
    fn persist(&self) {
        if self.off.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let snap = self.mem.snapshot();
        if crate::state_crypto::doc::write_document(
            &self.keys,
            crate::state_crypto::Label::ChatCustody,
            &self.path,
            &snap,
        )
        .is_err()
        {
            // Keep serving from memory; leave the file alone for the rest of
            // the run so one bad write does not repeat on every call.
            self.off.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl CustodyStore for DiskCustody {
    fn trust(&self, id: [u8; 32]) {
        self.mem.trust(id);
    }

    fn untrust(&self, id: &[u8; 32]) {
        self.mem.untrust(id);
    }

    fn deposit(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, CustodyError> {
        let out = self.mem.deposit(who, tag, item, blob, now_ms)?;
        // Duplicate deposits also update the depositor's recency.
        self.persist();
        Ok(out)
    }

    fn list(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, CustodyError> {
        let before = self.mem.stats().items;
        let out = self.mem.list(who, tag, now_ms)?;
        // The listing swept: if it dropped anything, persist the smaller store.
        if self.mem.stats().items != before {
            self.persist();
        }
        Ok(out)
    }

    fn fetch(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, CustodyError> {
        let before = self.mem.stats().items;
        let out = self.mem.fetch(who, tag, item, now_ms)?;
        if self.mem.stats().items != before {
            self.persist();
        }
        Ok(out)
    }

    fn delete(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, CustodyError> {
        let removed = self.mem.delete(who, tag, item)?;
        if removed {
            self.persist();
        }
        Ok(removed)
    }

    fn sweep(&self, now_ms: u64) -> usize {
        let n = self.mem.sweep(now_ms);
        if n > 0 {
            self.persist();
        }
        n
    }

    fn stats(&self) -> CustodyStats {
        self.mem.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];
    const STRANGER: [u8; 32] = [9; 32];

    fn on() -> CustodyLimits {
        CustodyLimits {
            enabled: true,
            ..CustodyLimits::default()
        }
    }

    fn store(l: CustodyLimits) -> MemoryCustody {
        let s = MemoryCustody::new(l);
        s.trust(A);
        s.trust(B);
        s
    }

    fn tag() -> RecipientTag {
        RecipientTag::for_recipient(&B)
    }

    fn id(n: u8) -> ItemId {
        ItemId([n; 16])
    }

    #[test]
    fn holding_can_be_disabled() {
        assert!(!CustodyLimits::default().enabled);
        assert!(CustodyLimits::from_config(&ChatConfig::default()).enabled);
        let s = store(CustodyLimits::default());
        assert_eq!(
            s.deposit(&A, tag(), id(1), b"x", 0),
            Err(CustodyError::Disabled)
        );
        assert_eq!(s.stats(), CustodyStats::default());
        let mut cfg = ChatConfig::default();
        cfg.custody_enabled = false;
        assert!(!CustodyLimits::from_config(&cfg).enabled);
    }

    #[test]
    fn limits_come_from_config_and_are_clamped() {
        // Ordinary values pass through from the settings.
        let mut cfg = ChatConfig::default();
        cfg.custody_max_total_bytes = 1024;
        cfg.custody_max_items = 7;
        cfg.custody_ttl_days = 3;
        let l = CustodyLimits::from_config(&cfg);
        assert_eq!(l.max_total_bytes, 1024);
        assert_eq!(l.max_items, 7);
        assert_eq!(l.ttl_ms, 3 * 86_400_000);

        // Values past the hard ceilings are clamped down.
        let mut big = ChatConfig::default();
        big.custody_max_total_bytes = usize::MAX;
        big.custody_max_items = usize::MAX;
        big.custody_ttl_days = u64::MAX / 86_400_000 + 1000;
        let c = CustodyLimits::from_config(&big);
        assert_eq!(c.max_total_bytes, HARD_MAX_TOTAL_BYTES);
        assert_eq!(c.max_items, HARD_MAX_ITEMS);
        assert_eq!(c.ttl_ms, HARD_MAX_TTL_MS);
    }

    #[test]
    fn unknown_peers_may_only_deposit() {
        let s = store(on());
        assert_eq!(
            s.deposit(&STRANGER, tag(), id(2), b"x", 0),
            Ok(DepositOutcome::Stored)
        );
        s.deposit(&A, tag(), id(1), b"x", 0).unwrap();
        assert_eq!(s.list(&STRANGER, tag(), 0), Err(CustodyError::NotTrusted));
        assert_eq!(
            s.fetch(&STRANGER, tag(), id(1), 0),
            Err(CustodyError::NotTrusted)
        );
        assert_eq!(
            s.delete(&STRANGER, tag(), id(1)),
            Err(CustodyError::NotTrusted)
        );
        // Revoking drops what the contact deposited.
        s.revoke(&A);
        s.sweep(u64::MAX);
        assert_eq!(s.stats(), CustodyStats::default());
    }

    #[test]
    fn unknown_depositors_evict_the_least_recently_used() {
        let s = MemoryCustody::new(on());
        let recipient: [u8; 32] = rand::random();
        s.trust(recipient);
        let tag = RecipientTag::for_recipient(&recipient);
        let mut entries = Vec::new();
        for _ in 0..256 {
            let sender: [u8; 32] = rand::random();
            let item = ItemId(rand::random());
            s.deposit(&sender, tag, item, b"x", 0).unwrap();
            entries.push((sender, item));
        }
        s.deposit(&entries[0].0, tag, entries[0].1, b"x", 0)
            .unwrap();
        let newcomer: [u8; 32] = rand::random();
        s.deposit(&newcomer, tag, ItemId(rand::random()), b"x", 0)
            .unwrap();
        assert!(s.fetch(&recipient, tag, entries[0].1, 0).unwrap().is_some());
        assert!(s.fetch(&recipient, tag, entries[1].1, 0).unwrap().is_none());
    }

    #[test]
    fn other_contacts_cannot_access_items() {
        let s = store(on());
        let other: [u8; 32] = rand::random();
        let recipient: [u8; 32] = rand::random();
        let tag = RecipientTag::for_recipient(&recipient);
        let item = ItemId(rand::random());
        s.trust(other);
        s.trust(recipient);
        s.deposit(&A, tag, item, b"sealed", 0).unwrap();
        assert_eq!(s.list(&other, tag, 0), Err(CustodyError::NotTrusted));
        assert_eq!(s.fetch(&other, tag, item, 0), Err(CustodyError::NotTrusted));
        assert_eq!(s.delete(&other, tag, item), Err(CustodyError::NotTrusted));
        assert_eq!(s.list(&recipient, tag, 0).unwrap(), vec![item]);
        assert_eq!(
            s.fetch(&recipient, tag, item, 0).unwrap(),
            Some(b"sealed".to_vec())
        );
        assert!(s.delete(&recipient, tag, item).unwrap());
    }

    #[test]
    fn item_size_is_limited() {
        let s = store(on());
        assert_eq!(
            s.deposit(&A, tag(), id(1), b"", 0),
            Err(CustodyError::TooBig)
        );
        let big = vec![0u8; MAX_ITEM_BYTES + 1];
        assert_eq!(
            s.deposit(&A, tag(), id(1), &big, 0),
            Err(CustodyError::TooBig)
        );
        let max = vec![0u8; MAX_ITEM_BYTES];
        assert_eq!(
            s.deposit(&A, tag(), id(1), &max, 0),
            Ok(DepositOutcome::Stored)
        );
    }

    #[test]
    fn totals_and_per_depositor_shares_are_limited() {
        let s = store(CustodyLimits {
            max_items: 5,
            max_items_per_depositor: 3,
            max_total_bytes: 100,
            max_bytes_per_depositor: 100,
            ..on()
        });
        for n in 1..=3 {
            s.deposit(&A, tag(), id(n), &[0; 10], 0).unwrap();
        }
        assert_eq!(
            s.deposit(&A, tag(), id(4), &[0; 10], 0),
            Err(CustodyError::DepositorBudget)
        );
        // Another contact still has its own share, up to the total.
        s.deposit(&B, tag(), id(5), &[0; 10], 0).unwrap();
        s.deposit(&B, tag(), id(6), &[0; 10], 0).unwrap();
        assert_eq!(
            s.deposit(&B, tag(), id(7), &[0; 10], 0),
            Err(CustodyError::Full)
        );
        assert_eq!(
            s.stats(),
            CustodyStats {
                items: 5,
                bytes: 50
            }
        );
        // Bytes are limited too.
        let t = store(CustodyLimits {
            max_total_bytes: 25,
            ..on()
        });
        t.deposit(&A, tag(), id(1), &[0; 20], 0).unwrap();
        assert_eq!(
            t.deposit(&A, tag(), id(2), &[0; 10], 0),
            Err(CustodyError::Full)
        );
        // Deleting frees the room.
        assert!(t.delete(&A, tag(), id(1)).unwrap());
        t.deposit(&A, tag(), id(2), &[0; 10], 0).unwrap();
    }

    // F-002: the per-identity quota does not bound a Sybil flood -- an attacker
    // mints many free endpoint IDs, each staying under its own 16-item quota,
    // and fills the store between them. A class-wide cap holds the whole
    // unknown (non-contact) depositor set to a quarter of the store, keeping
    // three quarters reserved for real contacts.
    #[test]
    fn the_unknown_class_is_capped_regardless_of_identity_count() {
        // max_items 8 -> the unknown class may hold at most 8 / 4 = 2 items,
        // well under the per-identity cap of 16, so the class cap is what binds.
        let s = store(CustodyLimits {
            max_items: 8,
            max_total_bytes: 8_000,
            max_bytes_per_depositor: 8_000,
            ..on()
        });
        let recipient: [u8; 32] = rand::random();
        s.trust(recipient);
        let tag = RecipientTag::for_recipient(&recipient);
        // Two different strangers each deposit one item: both fit the quarter.
        let s1: [u8; 32] = [100; 32];
        let s2: [u8; 32] = [101; 32];
        assert_eq!(
            s.deposit(&s1, tag, id(1), b"x", 0),
            Ok(DepositOutcome::Stored)
        );
        assert_eq!(
            s.deposit(&s2, tag, id(2), b"x", 0),
            Ok(DepositOutcome::Stored)
        );
        // A third fresh identity -- still under its own per-identity quota --
        // is refused because the unknown class has used its quarter share.
        let s3: [u8; 32] = [102; 32];
        assert_eq!(
            s.deposit(&s3, tag, id(3), b"x", 0),
            Err(CustodyError::DepositorBudget)
        );
        // A real contact is unaffected: the other three quarters are reserved,
        // so it still deposits even with the unknown class at its cap.
        assert_eq!(
            s.deposit(&A, tag, id(4), b"x", 0),
            Ok(DepositOutcome::Stored)
        );
        // Once a stranger's item is gone, the class has room for one more.
        assert!(s.delete(&recipient, tag, id(1)).unwrap());
        let s4: [u8; 32] = [103; 32];
        assert_eq!(
            s.deposit(&s4, tag, id(5), b"x", 0),
            Ok(DepositOutcome::Stored)
        );
    }

    // F-002 (bytes): the class-wide cap also bounds total bytes, so a Sybil
    // cannot starve contacts out of the byte budget with many small identities.
    #[test]
    fn the_unknown_class_byte_share_is_capped() {
        // max_total_bytes 400 -> unknown class may hold at most 100 bytes.
        let s = store(CustodyLimits {
            max_items: 256,
            max_total_bytes: 400,
            max_bytes_per_depositor: 400,
            ..on()
        });
        let recipient: [u8; 32] = rand::random();
        s.trust(recipient);
        let tag = RecipientTag::for_recipient(&recipient);
        let s1: [u8; 32] = [110; 32];
        let s2: [u8; 32] = [111; 32];
        s.deposit(&s1, tag, id(1), &[0; 60], 0).unwrap();
        // 60 + 60 = 120 > 100: the second stranger is over the class byte cap
        // even though it is a fresh identity under its own per-depositor budget.
        assert_eq!(
            s.deposit(&s2, tag, id(2), &[0; 60], 0),
            Err(CustodyError::DepositorBudget)
        );
        // A contact may still use the reserved remainder of the byte budget.
        s.deposit(&A, tag, id(3), &[0; 200], 0).unwrap();
    }

    #[test]
    fn settings_cannot_raise_the_hard_ceilings() {
        let s = MemoryCustody::new(CustodyLimits {
            max_total_bytes: usize::MAX,
            max_items: usize::MAX,
            ttl_ms: u64::MAX,
            max_item_bytes: usize::MAX,
            ..on()
        });
        assert_eq!(s.limits().max_total_bytes, HARD_MAX_TOTAL_BYTES);
        assert_eq!(s.limits().max_items, HARD_MAX_ITEMS);
        assert_eq!(s.limits().ttl_ms, HARD_MAX_TTL_MS);
        assert_eq!(s.limits().max_item_bytes, MAX_ITEM_BYTES);
    }

    #[test]
    fn items_expire() {
        let s = store(CustodyLimits {
            ttl_ms: 1000,
            ..on()
        });
        s.deposit(&A, tag(), id(1), b"old", 0).unwrap();
        s.deposit(&A, tag(), id(2), b"new", 900).unwrap();
        assert_eq!(s.list(&B, tag(), 999).unwrap(), vec![id(1), id(2)]);
        // At the expiry time the first is gone; the second still there.
        assert_eq!(s.list(&B, tag(), 1000).unwrap(), vec![id(2)]);
        assert_eq!(s.fetch(&B, tag(), id(1), 1000).unwrap(), None);
        assert_eq!(
            s.fetch(&B, tag(), id(2), 1000).unwrap(),
            Some(b"new".to_vec())
        );
        assert_eq!(s.sweep(1900), 1);
        assert_eq!(s.stats(), CustodyStats::default());
        // Expired room is usable again by the next deposit.
        let t = store(CustodyLimits {
            ttl_ms: 10,
            max_items: 1,
            ..on()
        });
        t.deposit(&A, tag(), id(1), b"x", 0).unwrap();
        assert_eq!(
            t.deposit(&A, tag(), id(2), b"x", 5),
            Err(CustodyError::Full)
        );
        assert_eq!(
            t.deposit(&A, tag(), id(2), b"x", 10),
            Ok(DepositOutcome::Stored)
        );
    }

    #[test]
    fn the_same_item_twice_is_held_once_and_not_extended() {
        let s = store(CustodyLimits {
            ttl_ms: 100,
            ..on()
        });
        assert_eq!(
            s.deposit(&A, tag(), id(1), b"x", 0),
            Ok(DepositOutcome::Stored)
        );
        assert_eq!(
            s.deposit(&B, tag(), id(1), b"x", 90),
            Ok(DepositOutcome::Duplicate)
        );
        assert_eq!(s.stats().items, 1);
        assert_eq!(s.fetch(&A, tag(), id(1), 100).unwrap(), None);
    }

    #[test]
    fn items_for_other_recipients_are_not_listed() {
        let s = store(on());
        s.deposit(&A, tag(), id(1), b"x", 0).unwrap();
        s.deposit(&A, RecipientTag([8; 16]), id(2), b"y", 0)
            .unwrap();
        assert_eq!(s.list(&B, tag(), 0).unwrap(), vec![id(1)]);
        assert_eq!(s.fetch(&B, tag(), id(2), 0).unwrap(), None);
    }

    #[test]
    fn a_listing_is_capped() {
        let s = store(CustodyLimits {
            max_items_per_depositor: 200,
            ..on()
        });
        for n in 0..(MAX_LIST as u8 + 10) {
            s.deposit(&A, tag(), id(n), &[1], 0).unwrap();
        }
        let l = s.list(&B, tag(), 0).unwrap();
        assert_eq!(l.len(), MAX_LIST);
        assert_eq!(l[0], id(0));
    }
}

#[cfg(test)]
mod disk_tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    use crate::state_crypto::StateKeys;

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];

    fn tag() -> RecipientTag {
        RecipientTag::for_recipient(&B)
    }
    fn id(n: u8) -> ItemId {
        ItemId([n; 16])
    }
    fn on() -> CustodyLimits {
        CustodyLimits {
            enabled: true,
            ..CustodyLimits::default()
        }
    }
    fn keys(master: u8) -> Arc<StateKeys> {
        Arc::new(StateKeys::from_master_key(&[master; 32]).unwrap())
    }

    #[test]
    fn other_contact_is_denied() {
        let dir = tempdir().unwrap();
        let key: [u8; 32] = rand::random();
        let s = DiskCustody::open(
            on(),
            Arc::new(StateKeys::from_master_key(&key).unwrap()),
            dir.path().join("custody"),
            0,
        );
        let depositor: [u8; 32] = rand::random();
        let recipient: [u8; 32] = rand::random();
        let other: [u8; 32] = rand::random();
        let tag = RecipientTag::for_recipient(&recipient);
        let item = ItemId(rand::random());
        s.trust(depositor);
        s.trust(other);
        s.deposit(&depositor, tag, item, b"sealed", 0).unwrap();
        assert_eq!(s.list(&other, tag, 0), Err(CustodyError::NotTrusted));
        assert_eq!(s.fetch(&other, tag, item, 0), Err(CustodyError::NotTrusted));
        assert_eq!(s.delete(&other, tag, item), Err(CustodyError::NotTrusted));
    }

    // A holder that restarts still has what it was keeping for an offline
    // contact: deposit, drop the store, re-open the same file, and the sealed
    // item is read back and served.
    #[test]
    fn survives_a_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("custody.doc");
        let k = keys(7);
        {
            let s = DiskCustody::open(on(), k.clone(), path.clone(), 0);
            s.trust(A);
            s.trust(B);
            s.deposit(&A, tag(), id(1), b"sealed", 0).unwrap();
            assert_eq!(s.stats().items, 1);
        }
        assert!(path.exists(), "a snapshot is written on deposit");
        let s = DiskCustody::open(on(), k, path, 0);
        // Trust is re-seeded from the contact list after a restart, exactly as
        // the service does; the held item is already back.
        s.trust(B);
        assert_eq!(s.stats().items, 1);
        assert_eq!(s.list(&B, tag(), 0).unwrap(), vec![id(1)]);
        assert_eq!(
            s.fetch(&B, tag(), id(1), 0).unwrap(),
            Some(b"sealed".to_vec())
        );
    }

    // The file is sealed: a store opened with a different master key cannot read
    // it and starts empty rather than leaking or erroring.
    #[test]
    fn a_wrong_key_starts_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("custody.doc");
        {
            let s = DiskCustody::open(on(), keys(7), path.clone(), 0);
            s.trust(A);
            s.deposit(&A, tag(), id(1), b"sealed", 0).unwrap();
        }
        let s = DiskCustody::open(on(), keys(8), path, 0);
        s.trust(B);
        assert_eq!(s.stats().items, 0);
        assert_eq!(s.list(&B, tag(), 0).unwrap(), Vec::<ItemId>::new());
    }

    // A snapshot taken under looser settings cannot push the store past a
    // ceiling that was tightened before the restart.
    #[test]
    fn a_tightened_ceiling_drops_items_on_restore() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("custody.doc");
        let k = keys(7);
        {
            let s = DiskCustody::open(on(), k.clone(), path.clone(), 0);
            s.trust(A);
            for n in 1..=4 {
                s.deposit(&A, tag(), id(n), &[0u8; 10], 0).unwrap();
            }
            assert_eq!(s.stats().items, 4);
        }
        let tight = CustodyLimits {
            max_items: 2,
            ..on()
        };
        let s = DiskCustody::open(tight, k, path, 0);
        s.trust(A);
        assert_eq!(s.stats().items, 2, "restore honours the current ceiling");
    }

    // Items already expired at restore time are not read back.
    #[test]
    fn an_expired_item_is_not_restored() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("custody.doc");
        let k = keys(7);
        {
            let s = DiskCustody::open(
                CustodyLimits {
                    ttl_ms: 1000,
                    ..on()
                },
                k.clone(),
                path.clone(),
                0,
            );
            s.trust(A);
            s.deposit(&A, tag(), id(1), b"x", 0).unwrap();
        }
        // Re-open after the item's expiry: it is swept on restore.
        let s = DiskCustody::open(
            CustodyLimits {
                ttl_ms: 1000,
                ..on()
            },
            k,
            path,
            2000,
        );
        s.trust(A);
        assert_eq!(s.stats().items, 0);
    }

    // Revoking a contact drops what it deposited and the smaller store is
    // written, so the dropped item is gone after a restart too.
    #[test]
    fn a_revoke_persists_across_a_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("custody.doc");
        let k = keys(7);
        {
            let s = DiskCustody::open(on(), k.clone(), path.clone(), 0);
            s.trust(A);
            s.deposit(&A, tag(), id(1), b"x", 0).unwrap();
            s.revoke(&A);
            assert_eq!(s.stats().items, 0);
        }
        let s = DiskCustody::open(on(), k, path, 0);
        s.trust(A);
        assert_eq!(s.stats().items, 0);
    }
}
