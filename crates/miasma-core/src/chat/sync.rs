//! Catching up after a pause: what the sender still holds for a contact is
//! compared with what the contact has already applied, by message ID, so a
//! message whose acknowledgement was lost is not sent again.
//!
//! The three steps are plain functions on the engine, so they run the same in
//! the service and in the tests:
//!
//! 1. [`request_for`]: the oldest waiting messages for the contact (bounded).
//! 2. [`answer`]: at the other end, which of them it has applied already.
//! 3. [`apply_reply`]: the sender records those as delivered.
//!
//! Each side runs step 1 for its own queue when it connects, so both
//! directions converge. Nothing here is trusted beyond the contact's own
//! message numbers: the answer can only close messages the sender itself named,
//! and a wrong answer costs the sender its own messages only.

use super::{
    engine::ChatCore,
    outbox::OutKind,
    proto::{SyncItem, MAX_SYNC_ITEMS},
};

/// The oldest waiting messages for `peer`, at most [`MAX_SYNC_ITEMS`].
pub fn request_for(core: &ChatCore, peer: &[u8; 32]) -> Vec<SyncItem> {
    core.outbox
        .pending_for(peer)
        .into_iter()
        // Read receipts carry no message number of their own to compare.
        .filter(|e| e.kind == OutKind::Text)
        .take(MAX_SYNC_ITEMS)
        .map(|e| SyncItem {
            id: e.id,
            seq: e.seq,
            len: e.text.len().min(u16::MAX as usize) as u16,
        })
        .collect()
}

/// The IDs among `items` (sent by `peer`) that this side has applied already.
/// A message longer than this side accepts is not counted: the sender sends
/// it so that it gets the proper refusal.
pub fn answer(core: &ChatCore, peer: &[u8; 32], items: &[SyncItem]) -> Vec<[u8; 16]> {
    let max_text = core.max_text();
    items
        .iter()
        .take(MAX_SYNC_ITEMS)
        .filter(|it| it.seq != 0 && usize::from(it.len) <= max_text)
        .filter(|it| core.store.peek_peer(peer, |st| !st.is_new_seq(it.seq)))
        .map(|it| it.id)
        .collect()
}

/// Record as delivered the messages of `asked` that `have` lists. Returns the
/// number closed. IDs that were not asked about, or are gone already, change
/// nothing.
pub fn apply_reply(
    core: &ChatCore,
    peer: &[u8; 32],
    asked: &[SyncItem],
    have: &[[u8; 16]],
    now: u64,
) -> usize {
    let mut closed = 0;
    for id in have {
        if !asked.iter().any(|a| &a.id == id) {
            continue;
        }
        let waiting = core.outbox.get(id).is_some_and(|e| &e.peer == peer);
        if waiting {
            core.mark_delivered(id, now);
            if core.outbox.get(id).is_none() {
                closed += 1;
            }
        }
    }
    closed
}
