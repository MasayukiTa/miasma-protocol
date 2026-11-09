//! Receive a network share announced by a trusted contact.

use super::{
    service::{place_without_overwrite, PushService},
    store::Contact,
};
use crate::{
    chat::proto::NetworkFileNotice,
    daemon::ipc::{daemon_request, ControlRequest, ControlResponse},
    transfer::progress::TransferState,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static DONE_LOCK: Mutex<()> = Mutex::new(());
const DONE: &str = ".network-receive-done";

#[derive(Debug, thiserror::Error)]
enum ReceiveError {
    #[error("already received")]
    AlreadyReceived,
    #[error("invalid notice")]
    InvalidNotice,
    #[error("network content unavailable")]
    Unavailable,
    #[error("transfer failed")]
    Failed,
    #[error("file does not match notice")]
    Mismatch,
    #[error("file operation failed")]
    Io(#[from] std::io::Error),
}

struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(crate::transfer::journal::part_path_for(&self.0));
    }
}

fn done(dir: &Path, id: &str, mark: bool) -> Result<bool, ReceiveError> {
    let _lock = DONE_LOCK.lock().unwrap();
    let key = hex::encode(Sha256::digest(id.as_bytes()));
    let path = dir.join(DONE);
    let found = match fs::read_to_string(&path) {
        Ok(s) => s.lines().any(|line| line == key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    if mark && !found {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{key}")?;
        f.sync_all()?;
    }
    Ok(found)
}

#[async_trait::async_trait]
trait Source: Send + Sync {
    async fn fetch(&self, notice: &NetworkFileNotice, path: &Path) -> Result<(), ReceiveError>;
}

struct DaemonSource(PathBuf);
#[async_trait::async_trait]
impl Source for DaemonSource {
    async fn fetch(&self, notice: &NetworkFileNotice, path: &Path) -> Result<(), ReceiveError> {
        let response = daemon_request(
            &self.0,
            ControlRequest::TransferStartReceive {
                mid: notice.share_id.clone(),
                output_path: path.to_string_lossy().into_owned(),
                password: Some(notice.password.clone()),
                restart: true,
                via: vec![],
                via_ca_pem: None,
            },
        )
        .await
        .map_err(|_| ReceiveError::Unavailable)?;
        let ControlResponse::TransferStarted { id } = response else {
            return Err(ReceiveError::Failed);
        };
        loop {
            let response =
                daemon_request(&self.0, ControlRequest::TransferStatus { id: id.clone() })
                    .await
                    .map_err(|_| ReceiveError::Unavailable)?;
            let ControlResponse::TransferStatus(status) = response else {
                return Err(ReceiveError::Unavailable);
            };
            // A concurrent CLI receive can own this MID. Never consume its output.
            if Path::new(&status.name) != path {
                return Err(ReceiveError::Unavailable);
            }
            match status.state {
                TransferState::Running => tokio::time::sleep(Duration::from_secs(1)).await,
                TransferState::Complete => return Ok(()),
                TransferState::Paused => return Err(ReceiveError::Unavailable),
                TransferState::Failed
                    if status
                        .last_error
                        .as_deref()
                        .is_some_and(|e| e.contains("wrong password")) =>
                {
                    return Err(ReceiveError::Failed)
                }
                TransferState::Failed => return Err(ReceiveError::Unavailable),
                TransferState::Cancelled => return Err(ReceiveError::Failed),
            }
        }
    }
}

async fn receive_once(
    source: &dyn Source,
    notice: &NetworkFileNotice,
    dir: &Path,
) -> Result<PathBuf, ReceiveError> {
    let name = crate::transfer::manifest::sanitize_file_name(&notice.file_name)
        .ok_or(ReceiveError::InvalidNotice)?;
    fs::create_dir_all(dir)?;
    if done(dir, &notice.share_id, false)? {
        return Err(ReceiveError::AlreadyReceived);
    }
    let part = Partial(dir.join(format!(
        ".network-{}.part",
        hex::encode(rand::random::<[u8; 16]>())
    )));
    source.fetch(notice, &part.0).await?;
    let mut file = fs::File::open(&part.0)?;
    if file.metadata()?.len() != notice.size {
        return Err(ReceiveError::Mismatch);
    }
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
    let path = place_without_overwrite(&part.0, dir, &name)?;
    done(dir, &notice.share_id, true)?;
    Ok(path)
}

pub fn spawn_receive(service: Arc<PushService>, contact: Contact, notice: NetworkFileNotice) {
    let id = notice.share_id.clone();
    if !ACTIVE
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(id.clone())
    {
        return;
    }
    tokio::spawn(async move {
        let source = DaemonSource(service.data_dir().to_path_buf());
        let dir = service.contact_dir(&contact.label);
        let policy = super::retry::RetryPolicy {
            window: Some(Duration::from_secs(7 * 86400)),
            ..Default::default()
        };
        let started = tokio::time::Instant::now();
        let mut failures = 0u32;
        loop {
            match receive_once(&source, &notice, &dir).await {
                Ok(path) => {
                    service.record_offline_receive(&contact, &notice.file_name, notice.size, &path);
                    break;
                }
                Err(ReceiveError::Unavailable) if !policy.exhausted(started.elapsed()) => {
                    failures = failures.saturating_add(1);
                    let remaining =
                        Duration::from_secs(7 * 86400).saturating_sub(started.elapsed());
                    tokio::time::sleep(policy.delay(failures, rand::random()).min(remaining)).await;
                    if policy.exhausted(started.elapsed()) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        ACTIVE.get().unwrap().lock().unwrap().remove(&id);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSource {
        bytes: Vec<u8>,
        password: String,
    }

    #[async_trait::async_trait]
    impl Source for FakeSource {
        async fn fetch(&self, notice: &NetworkFileNotice, path: &Path) -> Result<(), ReceiveError> {
            if notice.password != self.password {
                return Err(ReceiveError::Failed);
            }
            fs::write(path, &self.bytes)?;
            Ok(())
        }
    }

    fn fixture() -> (FakeSource, NetworkFileNotice) {
        let bytes = rand::random::<[u8; 32]>().to_vec();
        let password = hex::encode(rand::random::<[u8; 32]>());
        let notice = NetworkFileNotice {
            share_id: hex::encode(rand::random::<[u8; 32]>()),
            password: password.clone(),
            file_name: "example.bin".into(),
            size: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        };
        (FakeSource { bytes, password }, notice)
    }

    #[tokio::test]
    async fn verifies_places_and_deduplicates() {
        let (source, notice) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = receive_once(&source, &notice, dir.path()).await.unwrap();
        assert_eq!(fs::read(path).unwrap(), source.bytes);
        assert!(matches!(
            receive_once(&source, &notice, dir.path()).await,
            Err(ReceiveError::AlreadyReceived)
        ));
    }

    #[tokio::test]
    async fn refuses_tampering_and_wrong_password() {
        let (mut source, mut notice) = fixture();
        let dir = tempfile::tempdir().unwrap();
        source.bytes[0] ^= 1;
        assert!(matches!(
            receive_once(&source, &notice, dir.path()).await,
            Err(ReceiveError::Mismatch)
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        notice.password = hex::encode(rand::random::<[u8; 32]>());
        assert!(matches!(
            receive_once(&source, &notice, dir.path()).await,
            Err(ReceiveError::Failed)
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
