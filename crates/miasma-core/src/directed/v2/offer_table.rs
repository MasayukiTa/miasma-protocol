//! In-memory table of pending prekey offers, keyed by requester PeerId and
//! offer identifier (§2.3).
//!
//! An offer is held only in memory, expires after a fixed lifetime, and can be
//! taken out at most once. The table never reads the clock itself: every
//! operation receives `now` as an argument so tests can drive it with virtual
//! time. `now` is an unsigned count in the caller's own unit (the tests use
//! seconds); only differences against the stored creation time are compared.

use libp2p::PeerId;
use std::collections::HashMap;

/// Offer lifetime, in the same unit as the `now` argument (§2.3: 20 seconds).
/// An offer is valid up to and including this age; strictly older is expired.
pub const OFFER_TTL: u64 = 20;

/// Upper bound on unused offers held for a single PeerId (§2.3: 100).
pub const MAX_OFFERS_PER_PEER: usize = 100;

/// The offer identifier type, matching `offer::OfferFields::offer_id`.
pub type OfferId = [u8; 16];

/// Why an insert was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferTableError {
    /// The PeerId already holds [`MAX_OFFERS_PER_PEER`] unused offers.
    TooManyForPeer,
}

/// One stored offer and the time it was created.
struct Entry<V> {
    offer: V,
    created: u64,
}

impl<V> Entry<V> {
    /// Whether this entry is still within its lifetime at `now`.
    ///
    /// Uses a saturating difference so a `now` earlier than `created` (a clock
    /// that moved backwards) reads as age zero rather than wrapping.
    fn is_live(&self, now: u64) -> bool {
        now.saturating_sub(self.created) <= OFFER_TTL
    }
}

/// A table of pending offers looked up by `(PeerId, OfferId)`.
///
/// `V` is the stored offer payload; the table is agnostic to its shape.
pub struct OfferTable<V> {
    by_peer: HashMap<PeerId, HashMap<OfferId, Entry<V>>>,
}

impl<V> Default for OfferTable<V> {
    fn default() -> Self {
        Self {
            by_peer: HashMap::new(),
        }
    }
}

impl<V> OfferTable<V> {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an offer for `peer` under `id`, created at `now`.
    ///
    /// Expired entries for `peer` are dropped first so a stale backlog does not
    /// block a fresh offer. If `peer` then still holds [`MAX_OFFERS_PER_PEER`]
    /// live offers, the insert is rejected with [`OfferTableError::TooManyForPeer`]
    /// and the table is left unchanged. Re-inserting the same `id` replaces the
    /// existing entry and does not count towards the limit.
    pub fn insert(
        &mut self,
        peer: PeerId,
        id: OfferId,
        offer: V,
        now: u64,
    ) -> Result<(), OfferTableError> {
        let slot = self.by_peer.entry(peer).or_default();
        slot.retain(|_, e| e.is_live(now));
        if !slot.contains_key(&id) && slot.len() >= MAX_OFFERS_PER_PEER {
            // Drop the peer's map if we created it empty above and are rejecting,
            // so a rejected insert leaves no observable trace.
            if slot.is_empty() {
                self.by_peer.remove(&peer);
            }
            return Err(OfferTableError::TooManyForPeer);
        }
        slot.insert(
            id,
            Entry {
                offer,
                created: now,
            },
        );
        Ok(())
    }

    /// Take the offer for `(peer, id)` if it exists and is still live at `now`.
    ///
    /// The entry is removed whether or not it was live, so an offer can be taken
    /// at most once and an expired one is not returned. Returns `None` when the
    /// entry is absent or expired.
    pub fn take(&mut self, peer: &PeerId, id: &OfferId, now: u64) -> Option<V> {
        let slot = self.by_peer.get_mut(peer)?;
        let entry = slot.remove(id)?;
        if slot.is_empty() {
            self.by_peer.remove(peer);
        }
        if entry.is_live(now) {
            Some(entry.offer)
        } else {
            None
        }
    }

    /// Remove every expired offer across all peers, measured against `now`.
    pub fn sweep(&mut self, now: u64) {
        self.by_peer.retain(|_, slot| {
            slot.retain(|_, e| e.is_live(now));
            !slot.is_empty()
        });
    }

    /// Number of live offers held for `peer` at `now`.
    ///
    /// Expired entries that have not yet been swept are not counted.
    pub fn len_for_peer(&self, peer: &PeerId, now: u64) -> usize {
        self.by_peer
            .get(peer)
            .map(|slot| slot.values().filter(|e| e.is_live(now)).count())
            .unwrap_or(0)
    }

    /// Whether a fresh offer (one with an id not already held) could be inserted
    /// for `peer` at `now` without exceeding [`MAX_OFFERS_PER_PEER`].
    ///
    /// This counts only live entries, matching [`Self::insert`], which drops
    /// expired entries before it checks the limit. A caller can use this to
    /// decline a request before doing expensive per-offer work, so a peer that
    /// is already at the limit is turned away without that work. It is a
    /// read-only check and leaves the table unchanged.
    pub fn has_capacity_for_new(&self, peer: &PeerId, now: u64) -> bool {
        self.len_for_peer(peer, now) < MAX_OFFERS_PER_PEER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct offer value per test, so the payload type is exercised without
    /// depending on the real offer shape.
    fn offer(tag: u32) -> Vec<u8> {
        tag.to_le_bytes().to_vec()
    }

    /// A fresh random offer id.
    fn id() -> OfferId {
        rand::random()
    }

    #[test]
    fn an_offer_is_live_at_exactly_the_ttl_boundary_and_expired_one_unit_later() {
        let mut t: OfferTable<Vec<u8>> = OfferTable::new();
        let peer = PeerId::random();
        let oid = id();
        t.insert(peer, oid, offer(1), 100).unwrap();

        // Created at 100: still live at 100 + OFFER_TTL (the boundary).
        assert_eq!(t.take(&peer, &oid, 100 + OFFER_TTL), Some(offer(1)));

        // One unit past the boundary: expired, returns None.
        t.insert(peer, oid, offer(2), 100).unwrap();
        assert_eq!(t.take(&peer, &oid, 100 + OFFER_TTL + 1), None);
    }

    #[test]
    fn the_hundredth_offer_is_accepted_and_the_hundred_first_is_rejected() {
        let mut t: OfferTable<Vec<u8>> = OfferTable::new();
        let peer = PeerId::random();
        let now = 0;

        // 100 distinct offers fit.
        let mut ids = Vec::with_capacity(MAX_OFFERS_PER_PEER);
        for i in 0..MAX_OFFERS_PER_PEER {
            let oid = id();
            ids.push(oid);
            assert_eq!(t.insert(peer, oid, offer(i as u32), now), Ok(()));
        }
        assert_eq!(t.len_for_peer(&peer, now), MAX_OFFERS_PER_PEER);

        // The 101st distinct offer is rejected.
        assert_eq!(
            t.insert(peer, id(), offer(9999), now),
            Err(OfferTableError::TooManyForPeer)
        );
        assert_eq!(t.len_for_peer(&peer, now), MAX_OFFERS_PER_PEER);

        // Replacing an existing id is still allowed at the limit.
        assert_eq!(t.insert(peer, ids[0], offer(1234), now), Ok(()));
    }

    #[test]
    fn an_offer_can_be_taken_only_once() {
        let mut t: OfferTable<Vec<u8>> = OfferTable::new();
        let peer = PeerId::random();
        let oid = id();
        t.insert(peer, oid, offer(7), 0).unwrap();

        assert_eq!(t.take(&peer, &oid, 0), Some(offer(7)));
        // The second take finds nothing.
        assert_eq!(t.take(&peer, &oid, 0), None);
    }

    #[test]
    fn each_peer_has_an_independent_quota() {
        let mut t: OfferTable<Vec<u8>> = OfferTable::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let now = 0;

        // Fill peer A to the limit.
        for i in 0..MAX_OFFERS_PER_PEER {
            t.insert(peer_a, id(), offer(i as u32), now).unwrap();
        }
        assert_eq!(
            t.insert(peer_a, id(), offer(0), now),
            Err(OfferTableError::TooManyForPeer)
        );

        // peer B is unaffected: its own slot is empty and accepts offers.
        let b_id = id();
        assert_eq!(t.insert(peer_b, b_id, offer(42), now), Ok(()));
        assert_eq!(t.len_for_peer(&peer_b, now), 1);
        assert_eq!(t.take(&peer_b, &b_id, now), Some(offer(42)));
    }

    #[test]
    fn sweep_drops_expired_offers_and_the_count_falls() {
        let mut t: OfferTable<Vec<u8>> = OfferTable::new();
        let peer = PeerId::random();

        // Two offers created at different times.
        let old = id();
        let fresh = id();
        t.insert(peer, old, offer(1), 0).unwrap();
        t.insert(peer, fresh, offer(2), 15).unwrap();
        assert_eq!(t.len_for_peer(&peer, 15), 2);

        // At now = 25 the first (age 25) is expired, the second (age 10) is live.
        t.sweep(25);
        assert_eq!(t.len_for_peer(&peer, 25), 1);
        assert_eq!(t.take(&peer, &old, 25), None);
        assert_eq!(t.take(&peer, &fresh, 25), Some(offer(2)));

        // Sweeping the last live offer away empties the peer entirely.
        t.insert(peer, id(), offer(3), 100).unwrap();
        t.sweep(1_000);
        assert_eq!(t.len_for_peer(&peer, 1_000), 0);
    }
}
