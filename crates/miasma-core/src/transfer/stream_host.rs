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
    FetchedRecord,
};
use crate::{
    network::MiasmaCoordinator,
    wipe::{WipeGate, WipeInProgress},
    MiasmaError,
};

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
        check_stream_format(&fetched, sink, &progress)?;
        let source = self.piece_source();
        let mut spec = StreamSpec::new(mid, fetched.record, fetched.manifest);
        spec.password = password;
        spec.retry = RetryConfig::default();
        spec.expect = expect;
        spec.record_signer = Some(fetched.signer);
        receive_stream(&source, spec, sink, progress).await
    }
}

fn check_stream_format(
    fetched: &FetchedRecord,
    sink: &mut dyn SegmentSink,
    progress: &TransferProgress,
) -> Result<(), MiasmaError> {
    if fetched.manifest_v4.is_some() {
        let error = MiasmaError::UnsupportedStreamingFormat;
        progress.set_state(TransferState::Failed, Some(error.to_string()), false);
        sink.abort();
        return Err(error);
    }
    Ok(())
}

/// A host whose receives are registered with a [`WipeGate`].
///
/// Every stream that runs through it is an in-flight operation of the gate: a
/// wipe refuses new streams, cancels the running ones (the receive future is
/// dropped, which wipes its segment buffers, and the sink is told to abort) and
/// waits for them to be gone before the key is erased. The daemon registers its
/// node this way, so the UniFFI front end gets the behaviour through
/// [`host_for`] without knowing about the gate.
pub struct GatedHost {
    inner: Arc<dyn StreamHost>,
    gate: Arc<WipeGate>,
}

impl GatedHost {
    pub fn new(inner: Arc<dyn StreamHost>, gate: Arc<WipeGate>) -> Self {
        Self { inner, gate }
    }
}

#[async_trait]
impl StreamHost for GatedHost {
    async fn receive_stream_id(
        &self,
        target: &TransferId,
        password: Option<Zeroizing<String>>,
        sink: &mut dyn SegmentSink,
        progress: Arc<TransferProgress>,
    ) -> Result<StreamOutcome, MiasmaError> {
        let _op = match self.gate.enter() {
            Ok(op) => op,
            Err(refused) => {
                progress.set_state(TransferState::Failed, Some(refused.to_string()), false);
                sink.abort();
                return Err(refused.into());
            }
        };
        let ended = {
            let run = async {
                // Test hold point (off unless a test turns it on).
                self.gate.stall_point().await;
                self.inner
                    .receive_stream_id(target, password, &mut *sink, progress.clone())
                    .await
            };
            tokio::select! {
                biased;
                _ = self.gate.cancelled() => None,
                r = run => Some(r),
            }
        };
        match ended {
            Some(result) => result,
            None => {
                // The receive future is gone (its buffers were wiped on drop);
                // the app must not keep what it already got.
                progress.cancel();
                sink.abort();
                Err(WipeInProgress.into())
            }
        }
    }
}

/// Make `host` the node that serves RAM-only receives for `data_dir`, with
/// every receive registered with `gate` (see [`GatedHost`]).
pub fn register_gated_host(data_dir: &Path, host: Arc<dyn StreamHost>, gate: Arc<WipeGate>) {
    register_host(data_dir, Arc::new(GatedHost::new(host, gate)));
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

    use crate::{ContentId, DissolutionParams};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Probe {
        chunks: Arc<AtomicUsize>,
        aborted: Arc<AtomicBool>,
        completed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl SegmentSink for Probe {
        async fn accept(
            &mut self,
            _index: u32,
            _data: &[u8],
        ) -> Result<(), crate::transfer::SinkError> {
            self.chunks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn complete(&mut self, _total: u64) {
            self.completed.store(true, Ordering::SeqCst);
        }
        fn abort(&mut self) {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }

    /// Delivers a chunk every few milliseconds until it is dropped.
    struct Streamer;

    #[async_trait]
    impl StreamHost for Streamer {
        async fn receive_stream_id(
            &self,
            _target: &TransferId,
            _password: Option<Zeroizing<String>>,
            sink: &mut dyn SegmentSink,
            _progress: Arc<TransferProgress>,
        ) -> Result<StreamOutcome, MiasmaError> {
            let mut i = 0u32;
            loop {
                let _ = sink.accept(i, b"plaintext").await;
                i += 1;
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        }
    }

    fn some_target() -> TransferId {
        let params = DissolutionParams {
            data_shards: 2,
            total_shards: 3,
        };
        TransferId::Mid(ContentId::compute(
            b"stream-host-test",
            &params.to_param_bytes(),
        ))
    }

    #[test]
    fn latest_format_is_refused_before_streaming() {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let mid = some_target().mid();
        let publisher = key.verifying_key().to_bytes();
        let fetched = FetchedRecord {
            record: crate::network::types::DhtRecord {
                mid_digest: *mid.as_bytes(),
                data_shards: 2,
                total_shards: 3,
                version: 1,
                locations: vec![],
                published_at: 1,
            },
            manifest: None,
            manifest_v4: Some(crate::transfer::ManifestV4 {
                version: crate::transfer::MANIFEST_VERSION_V4,
                mid: *mid.as_bytes(),
                publisher,
                name: None,
                data_shards: 2,
                total_shards: 3,
                segment_size: 1024,
                total_bytes: 0,
                protection: crate::transfer::Protection::None,
                segments: vec![],
                suite: crate::format::ObjectSuite::Suite2.id(),
                ext: vec![],
            }),
            signer: publisher,
        };
        let mut sink = Probe::default();
        let error =
            check_stream_format(&fetched, &mut sink, &TransferProgress::new("test")).unwrap_err();
        assert!(matches!(error, MiasmaError::UnsupportedStreamingFormat));
        assert!(error.to_string().contains("normal receive command"));
        assert!(sink.aborted.load(Ordering::SeqCst));
        assert_eq!(sink.chunks.load(Ordering::SeqCst), 0);
        assert!(!sink.completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_wipe_cancels_a_running_stream_aborts_its_sink_and_stops_chunks() {
        let gate = Arc::new(WipeGate::new());
        let host = Arc::new(GatedHost::new(Arc::new(Streamer), gate.clone()));
        let probe = Probe::default();
        let (chunks, aborted, completed) = (
            probe.chunks.clone(),
            probe.aborted.clone(),
            probe.completed.clone(),
        );
        let task = {
            let host = host.clone();
            tokio::spawn(async move {
                let mut probe = probe;
                let target = some_target();
                host.receive_stream_id(&target, None, &mut probe, TransferProgress::new("x"))
                    .await
            })
        };
        while chunks.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(gate.in_flight(), 1, "the stream is a registered operation");

        gate.begin_wipe();
        assert!(gate.drained(std::time::Duration::from_secs(5)).await);
        let at_wipe = chunks.load(Ordering::SeqCst);
        assert!(aborted.load(Ordering::SeqCst), "the sink must be aborted");
        assert!(!completed.load(Ordering::SeqCst));
        let res = task.await.unwrap();
        assert!(res.unwrap_err().to_string().contains("wipe in progress"));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            chunks.load(Ordering::SeqCst),
            at_wipe,
            "no chunk may reach the sink after the wipe drained"
        );

        // A stream started afterwards is refused and its sink aborted.
        let mut late = Probe::default();
        let late_aborted = late.aborted.clone();
        let err = host
            .receive_stream_id(&some_target(), None, &mut late, TransferProgress::new("y"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("wipe in progress"));
        assert!(late_aborted.load(Ordering::SeqCst));
        assert_eq!(late.chunks.load(Ordering::SeqCst), 0);
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
