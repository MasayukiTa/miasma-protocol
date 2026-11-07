//! Names used by the custody store: who a held item is for and which item it
//! is.

use crate::chat::crypto::Envelope;

const TAG_CONTEXT: &str = "miasma chat custody recipient tag v1";
/// Group hand-over items are kept under a tag of their own so the recipient
/// collects and applies them through the group path, never as a private
/// message (ADR-012 step 5).
const GROUP_TAG_CONTEXT: &str = "miasma chat custody group recipient tag v1";
/// Directed-share invites are kept under a tag of their own so an offline
/// recipient collects them through the directed path, never mixed with a
/// private chat message or a group hand-over.
const DIRECTED_TAG_CONTEXT: &str = "miasma directed invite custody recipient tag v1";

/// The short name of a recipient under which items for it are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecipientTag(pub [u8; 16]);

impl RecipientTag {
    /// The tag of the contact with endpoint ID `recipient`.
    pub fn for_recipient(recipient: &[u8; 32]) -> Self {
        let k = blake3::derive_key(TAG_CONTEXT, recipient);
        let mut t = [0u8; 16];
        t.copy_from_slice(&k[..16]);
        Self(t)
    }

    /// The tag under which group hand-over items for `recipient` are kept,
    /// distinct from [`Self::for_recipient`] so they never mix with private
    /// messages in a holder (ADR-012 step 5).
    pub fn for_group_recipient(recipient: &[u8; 32]) -> Self {
        let k = blake3::derive_key(GROUP_TAG_CONTEXT, recipient);
        let mut t = [0u8; 16];
        t.copy_from_slice(&k[..16]);
        Self(t)
    }

    /// The tag under which a directed-share invite for `recipient` is kept,
    /// distinct from the private and group tags so an offline recipient
    /// collects it through the directed path only.
    pub fn for_directed_recipient(recipient: &[u8; 32]) -> Self {
        let k = blake3::derive_key(DIRECTED_TAG_CONTEXT, recipient);
        let mut t = [0u8; 16];
        t.copy_from_slice(&k[..16]);
        Self(t)
    }
}

/// One held item: the ID of the sealed envelope in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId(pub [u8; 16]);

/// The item ID of a sealed envelope, or `None` when the bytes are not one.
pub fn item_id_of(wire: &[u8]) -> Option<ItemId> {
    Envelope::decode(wire).ok().map(|e| ItemId(e.id))
}

/// The item ID of a directed-share invite, taken from the random 32-byte
/// envelope id. Two different invites keep different ids because the
/// envelope id is generated at random per envelope.
pub fn item_id_for_directed(envelope_id: &[u8; 32]) -> ItemId {
    let mut t = [0u8; 16];
    t.copy_from_slice(&envelope_id[..16]);
    ItemId(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_stable_and_differ_per_recipient() {
        let a = RecipientTag::for_recipient(&[1; 32]);
        assert_eq!(a, RecipientTag::for_recipient(&[1; 32]));
        assert_ne!(a, RecipientTag::for_recipient(&[2; 32]));
    }

    #[test]
    fn group_tags_are_stable_and_differ_from_private() {
        let g = RecipientTag::for_group_recipient(&[1; 32]);
        assert_eq!(g, RecipientTag::for_group_recipient(&[1; 32]));
        assert_ne!(g, RecipientTag::for_group_recipient(&[2; 32]));
        // A group item and a private item for the same contact never share a
        // tag, so the recipient never applies one on the other's path.
        assert_ne!(g, RecipientTag::for_recipient(&[1; 32]));
    }

    #[test]
    fn junk_has_no_item_id() {
        assert!(item_id_of(&[]).is_none());
        assert!(item_id_of(&[7; 40]).is_none());
    }

    #[test]
    fn directed_tags_are_stable_and_differ_from_private_and_group() {
        let d = RecipientTag::for_directed_recipient(&[1; 32]);
        assert_eq!(d, RecipientTag::for_directed_recipient(&[1; 32]));
        assert_ne!(d, RecipientTag::for_directed_recipient(&[2; 32]));
        // A directed invite never shares a tag with a private message or a
        // group hand-over for the same recipient, so the collect paths stay
        // separate.
        assert_ne!(d, RecipientTag::for_recipient(&[1; 32]));
        assert_ne!(d, RecipientTag::for_group_recipient(&[1; 32]));
    }

    #[test]
    fn directed_item_id_is_the_first_16_bytes_of_the_envelope_id() {
        let mut eid = [0u8; 32];
        for (i, b) in eid.iter_mut().enumerate() {
            *b = i as u8;
        }
        let item = item_id_for_directed(&eid);
        assert_eq!(item.0, eid[..16]);
        // A different envelope id gives a different item id.
        let other = item_id_for_directed(&[9u8; 32]);
        assert_ne!(item, other);
    }
}
