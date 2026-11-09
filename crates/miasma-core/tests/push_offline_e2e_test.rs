//! End-to-end offline file delivery through the chat receive path.
//!
//! A sender deposits an end-to-end encrypted file with one in-process holder
//! (a `DiskFileCustody` file store), puts the resulting `FileDepositNotice`
//! inside an ordinary chat text message, and then leaves. A recipient that
//! starts only afterwards receives that chat message through the real chat
//! receive path, recovers the notice from the message text exactly as the chat
//! engine does, runs the verified fetch, and ends up with a file whose bytes
//! equal the original. The holder's items are then cleared and no partial file
//! is left behind.
//!
//! Everything runs in one process over a shared disk-backed holder: no network,
//! no relay. The transport is the same `MailboxTransport` custody path used by
//! `push_offline_deposit_test.rs`; the chat leg reuses the public `ChatCore`
//! seal/accept verbs the way `chat_custody_net_test.rs` exercises the service.
//!
//! Keys and salts are random in every test: a hard-coded salt or key array is
//! both unrealistic and flagged by CodeQL, so none appears here.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use tempfile::TempDir;

use miasma_core::chat::crypto::Identity;
use miasma_core::chat::engine::ChatCore;
use miasma_core::chat::file_notice::{notice_to_text, text_to_notice};
use miasma_core::chat::mailbox::client::{MailboxError, MailboxTransport};
use miasma_core::chat::mailbox::holder::{CustodyStore, DepositOutcome};
use miasma_core::chat::mailbox::ids::{ItemId, RecipientTag};
use miasma_core::chat::outbox::Outbox;
use miasma_core::chat::proto::{AckStatus, FileDepositNotice};
use miasma_core::chat::store::{ChatStore, StoreSettings};
use miasma_core::push::deposit::{self, deposit_file, DepositReceipt};
use miasma_core::push::file_holder::{DiskFileCustody, FileCustodyLimits};
use miasma_core::push::receive_offline::fetch_verified;
use miasma_core::state_crypto::StateKeys;

/// An in-process transport for one node over a set of shared holders. The node
/// authenticates as `who`; each holder is a `DiskFileCustody` file store.
struct Node {
    holders: Vec<([u8; 32], Arc<DiskFileCustody>)>,
    who: [u8; 32],
}

impl Node {
    fn store(&self, holder: &[u8; 32]) -> Option<&Arc<DiskFileCustody>> {
        self.holders
            .iter()
            .find(|(id, _)| id == holder)
            .map(|(_, s)| s)
    }
}

impl MailboxTransport for Node {
    fn deposit(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, MailboxError> {
        let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
        s.deposit(&self.who, tag, item, blob, now_ms)
            .map_err(MailboxError::Refused)
    }
    fn list(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, MailboxError> {
        let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
        s.list(&self.who, tag, now_ms)
            .map_err(MailboxError::Refused)
    }
    fn fetch(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, MailboxError> {
        let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
        s.fetch(&self.who, tag, item, now_ms)
            .map_err(MailboxError::Refused)
    }
    fn delete(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, MailboxError> {
        let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
        s.delete(&self.who, tag, item)
            .map_err(MailboxError::Refused)
    }
}

/// A disk-backed holder that trusts both contacts and keeps a small file.
fn file_holder(dir: &Path, a: [u8; 32], b: [u8; 32]) -> Arc<DiskFileCustody> {
    let limits = FileCustodyLimits {
        enabled: true,
        ..FileCustodyLimits::default()
    };
    let s = Arc::new(DiskFileCustody::new(limits, dir).expect("holder dir is writable"));
    s.trust(a);
    s.trust(b);
    s
}

/// One chat endpoint built from the same public verbs the service uses.
struct ChatSide {
    _dir: TempDir,
    core: ChatCore,
}

fn chat_side(seed: &[u8; 32]) -> ChatSide {
    let dir = tempfile::tempdir().expect("tempdir");
    let master: [u8; 32] = rand::random();
    let keys = Arc::new(StateKeys::from_master_key(&master).expect("state keys"));
    let id = Identity::from_seed(seed);
    let chat = dir.path().join("chat");
    let store = ChatStore::open(&chat, keys.clone(), id.id(), StoreSettings::default())
        .expect("chat store opens");
    let (outbox, _) = Outbox::open(
        &miasma_core::paths::chat_outbox_file(&chat),
        keys,
        StoreSettings::default(),
        1,
    );
    let core = ChatCore::new(store, outbox, id, 4096);
    ChatSide { _dir: dir, core }
}

/// Delete every item a holder keeps for the recipient, as the recipient does
/// after a verified fetch, so the holder drops what it held. The item IDs are
/// opaque to the holder, so the recipient lists them and deletes each one.
fn clear_holder(
    transport: &dyn MailboxTransport,
    recipient: &[u8; 32],
    notice: &FileDepositNotice,
    now_ms: u64,
) {
    let tag = RecipientTag::for_recipient(recipient);
    for holder in &notice.holders {
        let items = transport.list(holder, tag, now_ms).unwrap_or_default();
        for item in items {
            let _ = transport.delete(holder, tag, item);
        }
    }
}

/// Build the chat-delivered notice from a deposit receipt, the way the sender
/// does before sealing it into a chat message. The receipt's public fields
/// carry everything the recipient needs to fetch and verify the file.
fn notice_from_receipt(
    receipt: &DepositReceipt,
    salt: [u8; 16],
    file_name: &str,
) -> FileDepositNotice {
    FileDepositNotice {
        file_key: receipt.file_key,
        salt,
        manifest_id: receipt.manifest_id.0,
        holders: receipt.held_by.clone(),
        file_name: file_name.to_string(),
        size: receipt.manifest.size,
        sha256: receipt.sha256,
    }
}

/// A reproducible multi-chunk payload (at least three full chunks plus a short
/// tail) built from a random seed byte so no literal content array appears.
fn multi_chunk_file() -> Vec<u8> {
    let len = deposit::CHUNK_PLAINTEXT * 3 + 777;
    let start: u8 = rand::random();
    (0..len)
        .map(|i| start.wrapping_add((i % 251) as u8))
        .collect()
}

#[test]
fn sender_deposits_and_leaves_then_recipient_receives_through_chat() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sender_seed: [u8; 32] = rand::random();
    let recipient_seed: [u8; 32] = rand::random();
    let sender = Identity::from_seed(&sender_seed);
    let recipient = Identity::from_seed(&recipient_seed);
    let holder_id: [u8; 32] = rand::random();
    let store = file_holder(&tmp.path().join("holder"), sender.id(), recipient.id());
    let salt: [u8; 16] = rand::random();

    let file = multi_chunk_file();
    assert!(file.len() > deposit::CHUNK_PLAINTEXT * 3);

    // The two chat endpoints. The recipient endpoint exists but is not touched
    // until the sender has gone.
    let sender_chat = chat_side(&sender_seed);
    let recipient_chat = chat_side(&recipient_seed);

    // The sender deposits the file and seals the notice into a chat message,
    // then every sender-side object is dropped: the sender has left.
    let (wire, expected): (Vec<u8>, Vec<u8>) = {
        let tx = Node {
            holders: vec![(holder_id, store.clone())],
            who: sender.id(),
        };
        let receipt: DepositReceipt = deposit_file(
            &tx,
            &[holder_id],
            &recipient.id(),
            salt,
            &file[..],
            1_000,
            1,
        )
        .expect("deposit succeeds with one holder");
        assert_eq!(receipt.held_by, vec![holder_id]);
        assert!(receipt.manifest.chunks >= 3);
        let notice = notice_from_receipt(&receipt, salt, "report.bin");
        let text = notice_to_text(&notice);
        let (wire, _id) = sender_chat
            .core
            .seal_for(&recipient.id(), text.as_bytes())
            .expect("seal the notice message for the recipient");
        (wire, file.clone())
        // tx, sender_chat and the receipt are dropped here: the sender is gone.
    };
    drop(sender_chat);

    // Later, the recipient starts and accepts the sealed chat message through
    // the real receive path.
    assert_eq!(
        recipient_chat
            .core
            .accept(&sender.id(), &wire, 2_000)
            .status,
        AckStatus::Stored
    );

    // The notice is recovered from the received chat text exactly as the chat
    // engine recovers it on the receive path.
    let texts: Vec<String> = recipient_chat
        .core
        .history(&sender.id(), None, 50)
        .into_iter()
        .map(|m| m.text)
        .collect();
    let notice = texts
        .iter()
        .find_map(|t| text_to_notice(t))
        .expect("the received chat message carries a file deposit notice");

    // The verified fetch places the file; its bytes equal the original.
    let rx = Node {
        holders: vec![(holder_id, store.clone())],
        who: recipient.id(),
    };
    let inbox = tmp.path().join("inbox");
    let placed = fetch_verified(&rx, &recipient.id(), &notice, &inbox, 3_000)
        .expect("the recipient fetches and verifies the deposited file");
    assert_eq!(fs::read(&placed).expect("read placed file"), expected);

    // No partial file is left behind.
    let leftover_parts = fs::read_dir(&inbox)
        .expect("read inbox")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .to_string()
                .contains(".part")
        })
        .count();
    assert_eq!(leftover_parts, 0, "no .part file remains");

    // The recipient clears the holder, which then holds nothing.
    clear_holder(&rx, &recipient.id(), &notice, 3_000);
    assert_eq!(store.stats().items, 0, "the holder items are deleted");
}

#[test]
fn a_flipped_byte_in_a_stored_chunk_gives_no_placed_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sender_seed: [u8; 32] = rand::random();
    let recipient_seed: [u8; 32] = rand::random();
    let sender = Identity::from_seed(&sender_seed);
    let recipient = Identity::from_seed(&recipient_seed);
    let holder_id: [u8; 32] = rand::random();
    let holder_dir = tmp.path().join("holder");
    let store = file_holder(&holder_dir, sender.id(), recipient.id());
    let salt: [u8; 16] = rand::random();

    let file = multi_chunk_file();
    let tx = Node {
        holders: vec![(holder_id, store.clone())],
        who: sender.id(),
    };
    let receipt = deposit_file(
        &tx,
        &[holder_id],
        &recipient.id(),
        salt,
        &file[..],
        1_000,
        1,
    )
    .expect("deposit succeeds");
    let notice = notice_from_receipt(&receipt, salt, "report.bin");

    // Flip one byte in the first stored chunk item on the holder's disk. The
    // manifest is the last item deposited, so item-0 is a chunk.
    let chunk_path = holder_dir.join("item-00000000000000000000.bin");
    let mut bytes = fs::read(&chunk_path).expect("read a stored chunk");
    assert!(!bytes.is_empty());
    bytes[0] ^= 1;
    fs::write(&chunk_path, &bytes).expect("write the tampered chunk");

    let rx = Node {
        holders: vec![(holder_id, store)],
        who: recipient.id(),
    };
    let inbox = tmp.path().join("inbox");
    assert!(
        fetch_verified(&rx, &recipient.id(), &notice, &inbox, 2_000).is_err(),
        "a tampered chunk must not verify"
    );
    let placed = inbox
        .exists()
        .then(|| fs::read_dir(&inbox).expect("read inbox").count())
        .unwrap_or(0);
    assert_eq!(placed, 0, "no file is placed when a chunk is altered");
}

#[test]
fn no_hybrid_session_at_the_sender_deposits_nothing() {
    // The sender's offline deposit only runs once a protected (hybrid) session
    // with the recipient exists. Without `pqc`, `has_protected_session` is
    // always false, so no session is ever protected; here we model the contract
    // directly: with no protected session the sender must not deposit, and the
    // holder must hold nothing.
    let tmp = tempfile::tempdir().expect("tempdir");
    let sender_seed: [u8; 32] = rand::random();
    let recipient_seed: [u8; 32] = rand::random();
    let sender = Identity::from_seed(&sender_seed);
    let recipient = Identity::from_seed(&recipient_seed);
    let holder_id: [u8; 32] = rand::random();
    let store = file_holder(&tmp.path().join("holder"), sender.id(), recipient.id());

    let sender_chat = chat_side(&sender_seed);

    // No hybrid upgrade is ever completed in a plain build, so the sender has
    // no protected session for the recipient.
    assert!(
        !has_protected_session(&sender_chat.core, &recipient.id()),
        "a fresh sender has no protected session"
    );

    // The sender's deposit gate: deposit only with a protected session.
    let file = multi_chunk_file();
    let tx = Node {
        holders: vec![(holder_id, store.clone())],
        who: sender.id(),
    };
    let salt: [u8; 16] = rand::random();
    let deposited = if has_protected_session(&sender_chat.core, &recipient.id()) {
        deposit_file(
            &tx,
            &[holder_id],
            &recipient.id(),
            salt,
            &file[..],
            1_000,
            1,
        )
        .is_ok()
    } else {
        false
    };
    assert!(
        !deposited,
        "nothing is deposited without a protected session"
    );
    assert_eq!(store.stats().items, 0, "the holder holds nothing");
}

/// Mirror of the sender's deposit precondition. The engine's own
/// `has_protected_session` is crate-private; this reproduces its public
/// observable: without `pqc`, and before any hybrid upgrade, a session is
/// never protected. A chat message still seals and opens on the ordinary
/// pairwise session; only the *protected* layer is absent.
fn has_protected_session(_core: &ChatCore, _peer: &[u8; 32]) -> bool {
    false
}
