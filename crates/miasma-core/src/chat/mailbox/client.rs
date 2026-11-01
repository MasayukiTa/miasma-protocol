//! The side that uses holders: deposit a copy of a sealed envelope with some
//! trusted contacts, and collect what is waiting for us from them.
//!
//! How the bytes reach a holder is the [`MailboxTransport`]; this module only
//! decides what to ask for and keeps the counts bounded. The transport used
//! over the chat channel is [`super::transport`]; the tests build their own.

use std::collections::HashSet;

use super::{
    holder::{CustodyError, DepositOutcome},
    ids::{ItemId, RecipientTag},
};

/// Items taken from holders in one collection.
pub const MAX_COLLECT: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailboxError {
    /// The holder could not be reached.
    #[error("holder unreachable")]
    Unreachable,
    /// The holder answered with a refusal.
    #[error("holder refused: {0}")]
    Refused(CustodyError),
}

/// One request/answer exchange with a holder. `holder` is the endpoint ID of
/// the contact asked.
pub trait MailboxTransport {
    fn deposit(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, MailboxError>;

    fn list(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, MailboxError>;

    fn fetch(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, MailboxError>;

    fn delete(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, MailboxError>;
}

/// What a deposit round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DepositReport {
    /// Holders that now hold a copy.
    pub held_by: Vec<[u8; 32]>,
    /// Holders that could not take it, and why.
    pub failed: Vec<([u8; 32], MailboxError)>,
}

/// What a collection did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectReport {
    /// Distinct items handed to the receiver.
    pub offered: usize,
    /// Items the receiver took (new or already known) and that were removed
    /// from the holders.
    pub taken: usize,
    /// Copies of an item already seen from another holder in this round.
    pub repeated: usize,
    /// Holders that could not be asked.
    pub unreachable: usize,
}

pub struct MailboxClient<T: MailboxTransport> {
    transport: T,
    /// How many holders get a copy.
    copies: usize,
}

impl<T: MailboxTransport> MailboxClient<T> {
    pub fn new(transport: T, copies: usize) -> Self {
        Self {
            transport,
            copies: copies.clamp(1, 8),
        }
    }

    /// Put a copy of the sealed envelope `wire` (from `sender`, for
    /// `recipient`) with up to `copies` of `holders`, in the order given,
    /// stopping once enough hold it. The sender's ID goes in front of the
    /// envelope inside the item: the recipient needs it to open the envelope
    /// and checks it by opening (a wrong one does not open anything).
    pub fn deposit(
        &self,
        holders: &[[u8; 32]],
        sender: &[u8; 32],
        recipient: &[u8; 32],
        item: ItemId,
        wire: &[u8],
        now_ms: u64,
    ) -> DepositReport {
        let tag = RecipientTag::for_recipient(recipient);
        let mut blob = Vec::with_capacity(32 + wire.len());
        blob.extend_from_slice(sender);
        blob.extend_from_slice(wire);
        let blob = blob.as_slice();
        let mut rep = DepositReport::default();
        for h in holders {
            if h == recipient {
                continue;
            }
            if rep.held_by.len() >= self.copies {
                break;
            }
            match self.transport.deposit(h, tag, item, blob, now_ms) {
                Ok(_) => rep.held_by.push(*h),
                Err(e) => rep.failed.push((*h, e)),
            }
        }
        rep
    }

    /// Ask every holder for what waits for `me`. Each distinct item is given
    /// to `take` once as (sender, sealed envelope); when `take` returns true
    /// (applied, or already known) the item is removed from the holders that
    /// have it.
    pub fn collect(
        &self,
        holders: &[[u8; 32]],
        me: &[u8; 32],
        now_ms: u64,
        mut take: impl FnMut(&[u8; 32], &[u8]) -> bool,
    ) -> CollectReport {
        let tag = RecipientTag::for_recipient(me);
        let mut rep = CollectReport::default();
        let mut seen: HashSet<ItemId> = HashSet::new();
        let mut taken_ids: HashSet<ItemId> = HashSet::new();
        // (holder, item) pairs whose item was taken, to remove afterwards.
        let mut to_delete: Vec<([u8; 32], ItemId)> = Vec::new();
        for h in holders {
            if h == me {
                continue;
            }
            let ids = match self.transport.list(h, tag, now_ms) {
                Ok(v) => v,
                Err(_) => {
                    rep.unreachable += 1;
                    continue;
                }
            };
            for id in ids {
                if !seen.insert(id) {
                    rep.repeated += 1;
                    if taken_ids.contains(&id) {
                        to_delete.push((*h, id));
                    }
                    continue;
                }
                if seen.len() > MAX_COLLECT {
                    break;
                }
                let blob = match self.transport.fetch(h, tag, id, now_ms) {
                    Ok(Some(b)) => b,
                    Ok(None) => continue,
                    Err(_) => {
                        rep.unreachable += 1;
                        break;
                    }
                };
                let Some((sender, wire)) = blob
                    .split_first_chunk::<32>()
                    .filter(|(_, w)| !w.is_empty())
                else {
                    continue;
                };
                rep.offered += 1;
                if take(sender, wire) {
                    rep.taken += 1;
                    taken_ids.insert(id);
                    to_delete.push((*h, id));
                }
            }
        }
        for (h, id) in to_delete {
            // A failed removal only leaves the copy to expire.
            let _ = self.transport.delete(&h, tag, id);
        }
        rep
    }
}
