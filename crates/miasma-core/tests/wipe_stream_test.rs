//! A wipe issued to a real, running daemon while a RAM-only receive is open:
//! the stream is one of the gate's operations, so the wipe cancels it, tells
//! the sink to abort and waits for it before the key is erased. After the wipe
//! returned, no further plaintext reaches the sink.
//!
//! The stream is held at the gate's test hold point (off by default; no request
//! can turn it on) so that it is certainly still open when the wipe arrives.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use miasma_core::daemon::{ipc::daemon_wipe, ipc::ControlResponse, DaemonServer};
use miasma_core::network::types::NodeType;
use miasma_core::transfer::{
    stream_host::host_for, SegmentSink, SinkError, TransferId, TransferProgress,
};
use miasma_core::{network::node::MiasmaNode, ContentId, DissolutionParams, LocalShareStore};

#[derive(Clone, Default)]
struct Probe {
    chunks: Arc<AtomicUsize>,
    aborted: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
}

#[async_trait]
impl SegmentSink for Probe {
    async fn accept(&mut self, _index: u32, _data: &[u8]) -> Result<(), SinkError> {
        self.chunks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn complete(&mut self, _total_bytes: u64) {
        self.completed.store(true, Ordering::SeqCst);
    }
    fn abort(&mut self) {
        self.aborted.store(true, Ordering::SeqCst);
    }
}

async fn wait_for_host(data_dir: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while host_for(data_dir).is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the running daemon never registered its stream host"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn some_target() -> TransferId {
    let params = DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    };
    TransferId::Mid(ContentId::compute(
        b"wipe-stream-test",
        &params.to_param_bytes(),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wipe_cancels_an_open_ram_only_receive_and_aborts_its_sink() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
    let master: [u8; 32] = std::fs::read(dir.path().join("master.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store.clone(), dir.path().to_owned())
        .await
        .unwrap();
    let run = tokio::spawn(server.run());
    let data_dir = dir.path().to_owned();
    wait_for_host(&data_dir).await;
    let gate = store.wipe_gate();

    // The front end finds the node the way the UniFFI layer does.
    let host = host_for(&data_dir).expect("host registered");
    gate.set_stall_for_tests(true);
    let probe = Probe::default();
    let stream = {
        let (host, mut sink) = (host.clone(), probe.clone());
        tokio::spawn(async move {
            host.receive_stream_id(&some_target(), None, &mut sink, TransferProgress::new("t"))
                .await
        })
    };

    // The stream is open and counted by the gate.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while gate.in_flight() < 1 || gate.stalled_for_tests() < 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the RAM-only receive is not registered with the wipe gate: in_flight={}, stalled={}",
            gate.in_flight(),
            gate.stalled_for_tests()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let resp = tokio::time::timeout(Duration::from_secs(30), daemon_wipe(&data_dir))
        .await
        .expect("wipe did not answer in time")
        .unwrap();
    assert!(matches!(resp, ControlResponse::Wiped), "got {resp:?}");

    // Once the wipe returned the stream is already over.
    assert_eq!(gate.in_flight(), 0);
    let res = tokio::time::timeout(Duration::from_secs(5), stream)
        .await
        .expect("the stream did not end after the wipe")
        .unwrap();
    assert!(res
        .expect_err("a stream must not succeed across a wipe")
        .to_string()
        .contains("wipe in progress"));
    assert!(probe.aborted.load(Ordering::SeqCst), "sink.abort expected");
    assert!(!probe.completed.load(Ordering::SeqCst));
    assert_eq!(probe.chunks.load(Ordering::SeqCst), 0);

    // A stream started on the handle that was already cloned is refused.
    let mut late = Probe::default();
    let err = host
        .receive_stream_id(&some_target(), None, &mut late, TransferProgress::new("u"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("wipe in progress"), "{err}");
    assert!(late.aborted.load(Ordering::SeqCst));
    assert_eq!(late.chunks.load(Ordering::SeqCst), 0);

    let exit = tokio::time::timeout(Duration::from_secs(20), run)
        .await
        .expect("daemon did not exit after the wipe");
    exit.unwrap().expect("daemon exited with an error");
}
