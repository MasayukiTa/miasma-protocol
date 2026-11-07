//! Offline file deposit through the custody path: a sender deposits an
//! end-to-end encrypted file into one holder, goes offline, and the recipient
//! connects later and fetches, verifies and decrypts it.
//!
//! Two in-process "nodes" (the sender and the recipient) each use their own
//! transport over a single shared disk-backed holder. The sender's transport is
//! dropped after the deposit is acknowledged, proving the sender can leave; the
//! recipient then fetches with a fresh transport. A separate case proves that a
//! deposit that does not reach enough holders is reported as not delivered and
//! never as success.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use miasma_core::chat::crypto::Identity;
use miasma_core::chat::mailbox::client::{MailboxError, MailboxTransport};
use miasma_core::chat::mailbox::holder::{CustodyStore, DepositOutcome};
use miasma_core::chat::mailbox::ids::{ItemId, RecipientTag};
use miasma_core::push::deposit::{deposit_file, fetch_file, DepositError};
use miasma_core::push::file_holder::{DiskFileCustody, FileCustodyLimits};

/// The X25519 secret scalar of an identity seed. `Identity` keeps its secret to
/// itself, so the test derives the scalar the same way `Identity::from_seed`
/// does, to agree the file key from both ends.
fn dh_secret(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).to_scalar_bytes()
}

/// An in-process transport for one node over a set of shared holders. The node
/// authenticates as `who`; each holder is a `DiskFileCustody`.
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

/// A holder that will keep a whole 64 MiB file for the two contacts.
fn file_holder(dir: &std::path::Path, a: [u8; 32], b: [u8; 32]) -> Arc<DiskFileCustody> {
    let limits = FileCustodyLimits {
        enabled: true,
        ..FileCustodyLimits::default()
    };
    let s = Arc::new(DiskFileCustody::new(limits, dir).expect("holder dir is writable"));
    s.trust(a);
    s.trust(b);
    s
}

/// Write a pseudo-random but reproducible file of `len` bytes to `path`,
/// streaming so the test never holds the whole file in memory.
fn make_file(path: &std::path::Path, len: usize) {
    let mut f = File::create(path).expect("create source file");
    let mut written = 0usize;
    let mut block = vec![0u8; 1 << 20]; // 1 MiB at a time.
    let mut x: u32 = 0x9e3779b9;
    while written < len {
        let n = block.len().min(len - written);
        for b in block.iter_mut().take(n) {
            // A cheap xorshift so the bytes are not all equal (a real file).
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x & 0xff) as u8;
        }
        f.write_all(&block[..n]).expect("write source file");
        written += n;
    }
    f.flush().expect("flush source file");
}

/// Compare two files byte for byte in a streaming pass (bounded memory).
fn files_equal(a: &std::path::Path, b: &std::path::Path) -> bool {
    let (mut fa, mut fb) = match (File::open(a), File::open(b)) {
        (Ok(fa), Ok(fb)) => (fa, fb),
        _ => return false,
    };
    if fa.metadata().map(|m| m.len()).ok() != fb.metadata().map(|m| m.len()).ok() {
        return false;
    }
    let mut ba = vec![0u8; 1 << 20];
    let mut bb = vec![0u8; 1 << 20];
    loop {
        let na = read_fill(&mut fa, &mut ba);
        let nb = read_fill(&mut fb, &mut bb);
        if na != nb {
            return false;
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..nb] {
            return false;
        }
    }
}

fn read_fill(f: &mut File, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    filled
}

#[test]
fn sender_deposits_64mib_then_leaves_and_recipient_fetches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sender = Identity::from_seed(&[11u8; 32]);
    let recipient = Identity::from_seed(&[22u8; 32]);
    let holder_id = [7u8; 32];
    let store = file_holder(&tmp.path().join("holder"), sender.id(), recipient.id());
    let salt: [u8; 16] = rand::random();

    // A real 64 MiB file on disk.
    let src_path = tmp.path().join("src.bin");
    let size = 64 * 1024 * 1024;
    make_file(&src_path, size);

    // The sender deposits by streaming the file from disk (bounded memory),
    // then its transport is dropped: the sender is gone.
    let receipt = {
        let tx = Node {
            holders: vec![(holder_id, store.clone())],
            who: sender.id(),
        };
        let mut src = File::open(&src_path).expect("open source");
        src.seek(SeekFrom::Start(0)).unwrap();
        deposit_file(
            &tx,
            &[holder_id],
            &dh_secret(&[11u8; 32]),
            Some(&[42u8; 32]),
            &sender.id(),
            &recipient.id(),
            salt,
            &mut src,
            1_000,
            1,
        )
        .expect("deposit of a 64 MiB file succeeds with one holder")
        // tx dropped here.
    };
    assert_eq!(receipt.held_by, vec![holder_id]);
    assert_eq!(receipt.manifest.size as usize, size);
    assert_eq!(receipt.manifest.chunks, (size as u64).div_ceil(16 * 1024));

    // Later, the recipient connects with a fresh transport and fetches to disk.
    let out_path = tmp.path().join("out.bin");
    {
        let rx = Node {
            holders: vec![(holder_id, store.clone())],
            who: recipient.id(),
        };
        let out = File::create(&out_path).expect("create output");
        let m = fetch_file(
            &rx,
            &[holder_id],
            &dh_secret(&[22u8; 32]),
            Some(&[42u8; 32]),
            &sender.id(),
            &recipient.id(),
            salt,
            std::io::BufWriter::new(out),
            2_000,
        )
        .expect("recipient fetches the whole file after the sender left");
        assert_eq!(m.file_hash, receipt.manifest.file_hash);
        assert_eq!(m.size as usize, size);
    }

    assert!(
        files_equal(&src_path, &out_path),
        "the fetched file is identical to the deposited file"
    );
}

#[test]
fn a_deposit_that_misses_the_threshold_is_not_reported_as_delivered() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sender = Identity::from_seed(&[11u8; 32]);
    let recipient = Identity::from_seed(&[22u8; 32]);
    let holder_id = [7u8; 32];
    let store = file_holder(&tmp.path().join("holder"), sender.id(), recipient.id());

    // One holder is offered, but two acknowledgements are required.
    let tx = Node {
        holders: vec![(holder_id, store)],
        who: sender.id(),
    };
    let file = vec![9u8; 20 * 1024 + 5];
    let err = deposit_file(
        &tx,
        &[holder_id],
        &dh_secret(&[11u8; 32]),
        Some(&[42u8; 32]),
        &sender.id(),
        &recipient.id(),
        rand::random(),
        &file[..],
        0,
        2,
    )
    .expect_err("a deposit under the threshold must fail, not succeed");
    match err {
        DepositError::NotDeposited { held, needed } => {
            assert_eq!(needed, 2);
            assert!(held < 2, "held {held} should be under the needed 2");
        }
        other => panic!("expected NotDeposited, got {other:?}"),
    }
}
