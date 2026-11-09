//! Verified, bounded-memory reconstruction of an offline file deposit.

use std::{
    collections::HashSet,
    fs,
    io::{Read, Seek, SeekFrom, Write},
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
    #[error("file was already received")]
    AlreadyReceived,
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
static DONE_LOCK: Mutex<()> = Mutex::new(());

fn is_done(dir: &Path, id: &[u8; 16]) -> std::io::Result<bool> {
    let _guard = DONE_LOCK.lock().unwrap();
    match fs::read_to_string(dir.join(".offline-done")) {
        Ok(contents) => Ok(contents.lines().any(|line| line == hex::encode(id))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn mark_done(dir: &Path, id: &[u8; 16]) -> std::io::Result<()> {
    let _guard = DONE_LOCK.lock().unwrap();
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(".offline-done"))?;
    writeln!(file, "{}", hex::encode(id))?;
    file.sync_all()
}

/// Run a verified fetch away from the async receive loop. Duplicate manifest IDs
/// are ignored while an attempt is running.
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
        let id = notice.manifest_id;
        let started = tokio::time::Instant::now();
        let policy = super::retry::RetryPolicy {
            window: Some(std::time::Duration::from_secs(7 * 86400)),
            ..Default::default()
        };
        let mut failures = 0u32;
        let result = loop {
            let transport = transport.clone();
            let notice = notice.clone();
            let dir = dir.clone();
            let current_ms =
                now_ms.saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
            let result = tokio::task::spawn_blocking(move || {
                if is_done(&dir, &notice.manifest_id)? {
                    return Err(ReceiveError::AlreadyReceived);
                }
                let path =
                    fetch_verified(transport.as_ref(), &recipient, &notice, &dir, current_ms)?;
                mark_done(&dir, &notice.manifest_id)?;
                let tag = crate::chat::mailbox::ids::RecipientTag::for_recipient(&recipient);
                let chunks = notice.size / deposit::CHUNK_PLAINTEXT as u64
                    + u64::from(notice.size % deposit::CHUNK_PLAINTEXT as u64 != 0);
                for holder in &notice.holders {
                    for item in std::iter::once(deposit::manifest_id(&notice.salt))
                        .chain((0..chunks).map(|index| deposit::chunk_id(index, &notice.salt)))
                    {
                        if let Err(e) = transport.delete(holder, tag, item) {
                            tracing::warn!("offline custody delete failed: {e}");
                        }
                    }
                }
                Ok(path)
            })
            .await
            .unwrap_or_else(|e| Err(ReceiveError::Io(std::io::Error::other(e))));
            if !matches!(
                result,
                Err(ReceiveError::Fetch(
                    DepositError::NoManifest | DepositError::MissingChunk
                ))
            ) || policy.exhausted(started.elapsed())
            {
                break result;
            }
            failures = failures.saturating_add(1);
            let remaining =
                std::time::Duration::from_secs(7 * 86400).saturating_sub(started.elapsed());
            tokio::time::sleep(policy.delay(failures, rand::random()).min(remaining)).await;
            if policy.exhausted(started.elapsed()) {
                break result;
            }
        };
        FETCHED.get().unwrap().lock().unwrap().remove(&id);
        result
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
        assert!(call().is_some());
    }
}
