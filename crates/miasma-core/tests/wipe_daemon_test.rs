//! A distress wipe issued through the control interface of a real, running
//! daemon: running operations stop, no partial output stays on disk, the root
//! key file is gone, every later store operation fails cleanly and the daemon
//! exits on its own.
//!
//! The operations are held at the gate's test hold points (off by default, no
//! request can turn them on) so that each one is certainly still running when
//! the wipe arrives. This proves the logical erase of the key and the removal
//! of the files the daemon wrote; it says nothing about physical overwriting of
//! earlier storage blocks.

use std::{path::Path, sync::Arc, time::Duration};

use miasma_core::daemon::{
    ipc::{daemon_request, daemon_wipe, ControlRequest, ControlResponse},
    DaemonServer,
};
use miasma_core::network::types::NodeType;
use miasma_core::state_crypto::StateKeys;
use miasma_core::{network::node::MiasmaNode, LocalShareStore};
use tokio::task::JoinHandle;

struct TestDaemon {
    dir: tempfile::TempDir,
    store: Arc<LocalShareStore>,
    run: JoinHandle<anyhow::Result<()>>,
}

async fn start_daemon() -> TestDaemon {
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
    TestDaemon { dir, store, run }
}

fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_under(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn wipe_through_the_control_interface_stops_work_and_leaves_no_output() {
    let d = start_daemon().await;
    let data_dir = d.dir.path().to_owned();
    let gate = d.store.wipe_gate();

    // Something to read back, published before the hold points are switched on.
    let payload = b"plaintext that must not reach the disk after a wipe".to_vec();
    let mid = match daemon_request(
        &data_dir,
        ControlRequest::Publish {
            data: payload,
            data_shards: 2,
            total_shards: 3,
        },
    )
    .await
    .unwrap()
    {
        ControlResponse::Published { mid } => mid,
        other => panic!("publish failed: {other:?}"),
    };
    let share_addrs = d.store.list();
    assert!(!share_addrs.is_empty(), "the publish stored shares");
    assert!(d.store.get(&share_addrs[0]).is_ok());

    // A leftover job file, as a background transfer would leave behind.
    let transfers = miasma_core::paths::transfers_dir(&data_dir);
    std::fs::create_dir_all(&transfers).unwrap();
    std::fs::write(transfers.join("send-leftover.jsonl"), b"journal bytes").unwrap();

    // Files for the operations.
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source.bin");
    std::fs::write(&source, vec![7u8; 64 * 1024]).unwrap();
    let source_job = work.path().join("source-job.bin");
    std::fs::write(&source_job, vec![9u8; 64 * 1024]).unwrap();
    let out = work.path().join("streamed-out.bin");

    gate.set_stall_for_tests(true);

    let get = {
        let (dir, mid, out) = (data_dir.clone(), mid.clone(), out.clone());
        tokio::spawn(async move {
            daemon_request(
                &dir,
                ControlRequest::GetToFile {
                    mid,
                    data_shards: 2,
                    total_shards: 3,
                    output_path: out.to_string_lossy().into_owned(),
                },
            )
            .await
        })
    };
    let publish = {
        let (dir, source) = (data_dir.clone(), source.clone());
        tokio::spawn(async move {
            daemon_request(
                &dir,
                ControlRequest::PublishFile {
                    file_path: source.to_string_lossy().into_owned(),
                    data_shards: 2,
                    total_shards: 3,
                },
            )
            .await
        })
    };
    // The background transfer job answers at once with its id.
    let job_id = match daemon_request(
        &data_dir,
        ControlRequest::TransferStartPublish {
            file_path: source_job.to_string_lossy().into_owned(),
            data_shards: 2,
            total_shards: 3,
            password: None,
            restart: false,
        },
    )
    .await
    .unwrap()
    {
        ControlResponse::TransferStarted { id } => id,
        other => panic!("transfer start failed: {other:?}"),
    };

    // All three are now registered and parked.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while gate.stalled_for_tests() < 3 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "operations did not reach the hold point: stalled={}, in_flight={}, get_done={}, publish_done={}",
            gate.stalled_for_tests(),
            gate.in_flight(),
            get.is_finished(),
            publish.is_finished()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(gate.in_flight(), 3);
    assert!(
        out.exists(),
        "the streamed output exists while the receive is running"
    );
    assert!(d.dir.path().join("master.key").exists());

    // The wipe, through the control interface.
    let resp = tokio::time::timeout(Duration::from_secs(30), daemon_wipe(&data_dir))
        .await
        .expect("wipe did not answer in time")
        .unwrap();
    assert!(matches!(resp, ControlResponse::Wiped), "got {resp:?}");

    // The operations ended without success.
    for (name, task) in [("get", get), ("publish", publish)] {
        let res = tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .unwrap_or_else(|_| panic!("{name} did not end after the wipe"))
            .unwrap();
        match res {
            Ok(ControlResponse::Error(msg)) => {
                assert!(msg.contains("wipe in progress"), "{name}: {msg}")
            }
            // The connection may be closed by the daemon shutting down.
            Err(_) => {}
            Ok(other) => panic!("{name} must not succeed across a wipe: {other:?}"),
        }
    }
    assert_eq!(gate.in_flight(), 0);

    // The background job was stopped and says why.
    let registry = miasma_core::transfer::jobs::registry_for(&data_dir);
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let st = registry.status(&job_id).expect("job is known");
        if st.state == miasma_core::transfer::TransferState::Failed {
            assert!(
                st.last_error
                    .unwrap_or_default()
                    .contains("wipe in progress"),
                "job error"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "job still {:?}",
            st.state
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // No partial plaintext output, no key, no transfer files.
    assert!(!out.exists(), "partial output must be removed");
    assert!(!data_dir.join("master.key").exists(), "master.key is gone");
    assert!(
        files_under(&transfers).is_empty(),
        "transfer files left: {:?}",
        files_under(&transfers)
    );

    // Every later store operation is a clean error, and nothing recreates the key.
    assert!(d.store.get(&share_addrs[0]).is_err());
    assert!(d.store.get_untouched(&share_addrs[0]).is_err());
    assert!(d.store.key_memory_status().is_none());
    assert!(d.store.wipe_gate().enter().is_err());
    assert!(StateKeys::load(&data_dir).is_err());
    assert!(!data_dir.join("master.key").exists());

    // The daemon ends on its own.
    let exit = tokio::time::timeout(Duration::from_secs(20), d.run)
        .await
        .expect("daemon did not exit after the wipe");
    exit.unwrap().expect("daemon exited with an error");

    // A new request finds nobody to talk to.
    assert!(daemon_request(&data_dir, ControlRequest::Status)
        .await
        .is_err());
}
