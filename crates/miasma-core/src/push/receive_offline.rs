//! Verified, bounded-memory reconstruction of an offline file deposit.

use std::{
    collections::HashSet,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use sha2::{Digest, Sha256};

use super::{
    deposit::{self, DepositError},
    service::place_without_overwrite,
};
use crate::chat::{mailbox::client::MailboxTransport, proto::FileDepositNotice};

#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error("invalid deposit notice")]
    InvalidNotice,
    #[error("deposit fetch failed: {0}")]
    Fetch(#[from] DepositError),
    #[error("file does not match the notice")]
    Mismatch,
    #[error("file operation failed: {0}")]
    Io(#[from] std::io::Error),
}

struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Fetch a single notice into `dir`, verifying its size and SHA-256 before
/// placing it. The caller must authenticate and authorize the sender, dedupe
/// notices, and run this blocking operation off the async runtime.
pub fn fetch_verified(
    transport: &dyn MailboxTransport,
    recipient: &[u8; 32],
    notice: &FileDepositNotice,
    dir: &Path,
    now_ms: u64,
) -> Result<PathBuf, ReceiveError> {
    if deposit::manifest_id(&notice.salt).0 != notice.manifest_id {
        return Err(ReceiveError::InvalidNotice);
    }
    let name = crate::transfer::manifest::sanitize_file_name(&notice.file_name)
        .ok_or(ReceiveError::InvalidNotice)?;
    fs::create_dir_all(dir)?;
    let part = Partial(dir.join(format!(
        ".offline-{}.part",
        hex::encode(rand::random::<[u8; 16]>())
    )));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&part.0)?;
    let manifest = deposit::fetch_file(
        transport,
        &notice.holders,
        &notice.file_key,
        recipient,
        notice.salt,
        &mut file,
        now_ms,
    )?;
    if manifest.size != notice.size || file.metadata()?.len() != notice.size {
        return Err(ReceiveError::Mismatch);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    if hash.finalize().as_slice() != notice.sha256 {
        return Err(ReceiveError::Mismatch);
    }
    drop(file);
    Ok(place_without_overwrite(&part.0, dir, &name)?)
}

static FETCHED: OnceLock<Mutex<HashSet<[u8; 16]>>> = OnceLock::new();

/// Run a verified fetch away from the async receive loop. Duplicate manifest IDs
/// are ignored for the lifetime of this process, including failed attempts.
pub fn spawn_fetch(
    transport: std::sync::Arc<dyn MailboxTransport + Send + Sync>,
    recipient: [u8; 32],
    notice: FileDepositNotice,
    dir: PathBuf,
    now_ms: u64,
) -> Option<tokio::task::JoinHandle<Result<PathBuf, ReceiveError>>> {
    if !FETCHED
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(notice.manifest_id)
    {
        return None;
    }
    Some(tokio::spawn(async move {
        tokio::task::spawn_blocking(move || {
            fetch_verified(transport.as_ref(), &recipient, &notice, &dir, now_ms)
        })
        .await
        .unwrap_or_else(|e| Err(ReceiveError::Io(std::io::Error::other(e))))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::mailbox::{
        client::MailboxError,
        holder::DepositOutcome,
        ids::{ItemId, RecipientTag},
    };
    use std::sync::Arc;

    struct UnusedTransport;
    impl MailboxTransport for UnusedTransport {
        fn deposit(
            &self,
            _: &[u8; 32],
            _: RecipientTag,
            _: ItemId,
            _: &[u8],
            _: u64,
        ) -> Result<DepositOutcome, MailboxError> {
            unreachable!()
        }
        fn list(&self, _: &[u8; 32], _: RecipientTag, _: u64) -> Result<Vec<ItemId>, MailboxError> {
            unreachable!()
        }
        fn fetch(
            &self,
            _: &[u8; 32],
            _: RecipientTag,
            _: ItemId,
            _: u64,
        ) -> Result<Option<Vec<u8>>, MailboxError> {
            unreachable!()
        }
        fn delete(&self, _: &[u8; 32], _: RecipientTag, _: ItemId) -> Result<bool, MailboxError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn duplicate_is_ignored_while_running_and_after_completion() {
        let notice = FileDepositNotice {
            file_key: [0; 32],
            salt: [0; 16],
            manifest_id: [255; 16],
            holders: vec![],
            file_name: "test".into(),
            size: 0,
            sha256: [0; 32],
        };
        let call = || {
            spawn_fetch(
                Arc::new(UnusedTransport),
                [0; 32],
                notice.clone(),
                PathBuf::new(),
                0,
            )
        };
        let first = call().expect("first fetch starts");
        assert!(call().is_none());
        assert!(matches!(
            first.await.unwrap(),
            Err(ReceiveError::InvalidNotice)
        ));
        assert!(call().is_none());
    }
}
