//! Names used by the custody store: who a held item is for and which item it
//! is.

use crate::chat::crypto::Envelope;

const TAG_CONTEXT: &str = "miasma chat custody recipient tag v1";

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
}

/// One held item: the ID of the sealed envelope in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId(pub [u8; 16]);

/// The item ID of a sealed envelope, or `None` when the bytes are not one.
pub fn item_id_of(wire: &[u8]) -> Option<ItemId> {
    Envelope::decode(wire).ok().map(|e| ItemId(e.id))
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
    fn junk_has_no_item_id() {
        assert!(item_id_of(&[]).is_none());
        assert!(item_id_of(&[7; 40]).is_none());
    }
}
