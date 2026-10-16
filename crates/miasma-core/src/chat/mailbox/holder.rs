//! The custody store: sealed envelopes held for contacts who are offline.
//!
//! Everything is bounded and nothing is written to disk:
//!
//! * a size limit per item, a limit on items and bytes in total, and a budget
//!   of items and bytes per depositor (so one contact cannot use it all);
//! * every item expires after a fixed time and is dropped by the next call
//!   that touches the store;
//! * only contacts the holder trusts may deposit, list, fetch or delete;
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
    /// The limits for `[chat]`: only the switch comes from the settings.
    pub fn from_config(c: &ChatConfig) -> Self {
        Self {
            enabled: c.custody_enabled,
            ..Self::default()
        }
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CustodyStats {
    pub items: usize,
    pub bytes: usize,
}

/// What a holder offers. `who` is the authenticated ID of the caller (the
/// transport proves it); every call checks it again.
pub trait CustodyStore: Send + Sync {
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
    fn delete(
        &self,
        who: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, CustodyError>;

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
}

impl CustodyStore for MemoryCustody {
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
        let (n, b) = g.per_depositor.get(who).copied().unwrap_or((0, 0));
        if n + 1 > self.limits.max_items_per_depositor
            || b + blob.len() > self.limits.max_bytes_per_depositor
        {
            return Err(CustodyError::DepositorBudget);
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
        Ok(g.items.get(&(tag, item)).map(|h| h.blob.clone()))
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
            bytes: g.bytes,
        }
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
        RecipientTag([7; 16])
    }

    fn id(n: u8) -> ItemId {
        ItemId([n; 16])
    }

    #[test]
    fn holding_is_off_by_default() {
        assert!(!CustodyLimits::default().enabled);
        assert!(!CustodyLimits::from_config(&ChatConfig::default()).enabled);
        let s = store(CustodyLimits::default());
        assert_eq!(
            s.deposit(&A, tag(), id(1), b"x", 0),
            Err(CustodyError::Disabled)
        );
        assert_eq!(s.stats(), CustodyStats::default());
        let mut cfg = ChatConfig::default();
        cfg.custody_enabled = true;
        assert!(CustodyLimits::from_config(&cfg).enabled);
    }

    #[test]
    fn only_trusted_contacts_may_use_it() {
        let s = store(on());
        assert_eq!(
            s.deposit(&STRANGER, tag(), id(1), b"x", 0),
            Err(CustodyError::NotTrusted)
        );
        s.deposit(&A, tag(), id(1), b"x", 0).unwrap();
        assert_eq!(
            s.list(&STRANGER, tag(), 0),
            Err(CustodyError::NotTrusted)
        );
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
        assert_eq!(s.stats(), CustodyStats::default());
    }

    #[test]
    fn item_size_is_limited() {
        let s = store(on());
        assert_eq!(s.deposit(&A, tag(), id(1), b"", 0), Err(CustodyError::TooBig));
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
        assert_eq!(s.stats(), CustodyStats { items: 5, bytes: 50 });
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
        let s = store(CustodyLimits { ttl_ms: 1000, ..on() });
        s.deposit(&A, tag(), id(1), b"old", 0).unwrap();
        s.deposit(&A, tag(), id(2), b"new", 900).unwrap();
        assert_eq!(s.list(&B, tag(), 999).unwrap(), vec![id(1), id(2)]);
        // At the expiry time the first is gone; the second still there.
        assert_eq!(s.list(&B, tag(), 1000).unwrap(), vec![id(2)]);
        assert_eq!(s.fetch(&B, tag(), id(1), 1000).unwrap(), None);
        assert_eq!(s.fetch(&B, tag(), id(2), 1000).unwrap(), Some(b"new".to_vec()));
        assert_eq!(s.sweep(1900), 1);
        assert_eq!(s.stats(), CustodyStats::default());
        // Expired room is usable again by the next deposit.
        let t = store(CustodyLimits {
            ttl_ms: 10,
            max_items: 1,
            ..on()
        });
        t.deposit(&A, tag(), id(1), b"x", 0).unwrap();
        assert_eq!(t.deposit(&A, tag(), id(2), b"x", 5), Err(CustodyError::Full));
        assert_eq!(t.deposit(&A, tag(), id(2), b"x", 10), Ok(DepositOutcome::Stored));
    }

    #[test]
    fn the_same_item_twice_is_held_once_and_not_extended() {
        let s = store(CustodyLimits { ttl_ms: 100, ..on() });
        assert_eq!(s.deposit(&A, tag(), id(1), b"x", 0), Ok(DepositOutcome::Stored));
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
        s.deposit(&A, RecipientTag([8; 16]), id(2), b"y", 0).unwrap();
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
