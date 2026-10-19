//! Getting a RAM-only receive from a front end to the node.
//!
//! [`receive_stream`](super::receive_stream::receive_stream) needs a record, a
//! manifest and a piece source. The node that owns those registers itself here
//! as a [`StreamHost`], once per data directory; a front end that only knows the
//! data directory (the UniFFI layer) then finds it with [`host_for`]. Tests
//! register a host that serves pieces from memory.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::{
    progress::{Phase, TransferProgress, TransferState},
    receive::RetryConfig,
    receive_stream::{receive_stream, SegmentSink, StreamOutcome, StreamSpec},
    share_id::TransferId,
};
use crate::{network::MiasmaCoordinator, MiasmaError};

/// Something that can run a RAM-only receive for a share ID or MID.
#[async_trait]
pub trait StreamHost: Send + Sync {
    async fn receive_stream_id(
        &self,
        target: &TransferId,
        password: Option<Zeroizing<String>>,
        sink: &mut dyn SegmentSink,
        progress: Arc<TransferProgress>,
    ) -> Result<StreamOutcome, MiasmaError>;
}

#[async_trait]
impl StreamHost for MiasmaCoordinator {
    /// The record and manifest are read from the DHT once, then verified exactly
    /// as [`receive_file_id`](MiasmaCoordinator::receive_file_id) does (share ID
    /// signer, protection state, MID) before a piece is fetched. Nothing is
    /// written to disk.
    async fn receive_stream_id(
        &self,
        target: &TransferId,
        password: Option<Zeroizing<String>>,
        sink: &mut dyn SegmentSink,
        progress: Arc<TransferProgress>,
    ) -> Result<StreamOutcome, MiasmaError> {
        progress.set_phase(Phase::Preparing);
        let mid = target.mid();
        let expect = target.share_id().copied();
        if let Some(id) = &expect {
            progress.set_share_id(Some(id.to_string()));
            progress.set_share_id_checked(true);
        }
        let fetched = match self
            .fetch_verified_record(&mid, expect.as_ref().map(|s| *s.publisher()))
            .await
        {
            Ok(f) => f,
            Err(e) => {
                progress.set_state(TransferState::Failed, Some(e.to_string()), false);
                sink.abort();
                return Err(e);
            }
        };
        let source = self.piece_source();
        let mut spec = StreamSpec::new(mid, fetched.record, fetched.manifest);
        spec.password = password;
        spec.retry = RetryConfig::default();
        spec.expect = expect;
        spec.record_signer = Some(fetched.signer);
        receive_stream(&source, spec, sink, progress).await
    }
}

static HOSTS: OnceLock<Mutex<HashMap<PathBuf, Arc<dyn StreamHost>>>> = OnceLock::new();

fn hosts() -> &'static Mutex<HashMap<PathBuf, Arc<dyn StreamHost>>> {
    HOSTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Make `host` the node that serves RAM-only receives for `data_dir`, replacing
/// any earlier one.
pub fn register_host(data_dir: &Path, host: Arc<dyn StreamHost>) {
    hosts().lock().unwrap().insert(data_dir.to_path_buf(), host);
}

/// Forget the host for `data_dir` (the node is stopping).
pub fn unregister_host(data_dir: &Path) {
    hosts().lock().unwrap().remove(data_dir);
}

/// The host registered for `data_dir`, if any.
pub fn host_for(data_dir: &Path) -> Option<Arc<dyn StreamHost>> {
    hosts().lock().unwrap().get(data_dir).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nop;

    #[async_trait]
    impl StreamHost for Nop {
        async fn receive_stream_id(
            &self,
            _target: &TransferId,
            _password: Option<Zeroizing<String>>,
            _sink: &mut dyn SegmentSink,
            _progress: Arc<TransferProgress>,
        ) -> Result<StreamOutcome, MiasmaError> {
            Ok(StreamOutcome::Complete {
                segments: 0,
                bytes: 0,
            })
        }
    }

    #[test]
    fn a_host_is_found_per_data_directory_until_it_is_removed() {
        let a = Path::new("/stream-host-test/a");
        let b = Path::new("/stream-host-test/b");
        assert!(host_for(a).is_none());
        register_host(a, Arc::new(Nop));
        assert!(host_for(a).is_some());
        assert!(host_for(b).is_none(), "another directory has no host");
        unregister_host(a);
        assert!(host_for(a).is_none());
    }
}
