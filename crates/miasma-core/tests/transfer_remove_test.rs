//! Removing finished transfers from the dashboard, through the daemon's IPC.
//!
//! What must hold: only a finished transfer goes; what it leaves on disk that
//! would bring it back after a restart goes with it; nothing the person owns is
//! deleted (a receive's output file, a send's source file, the shares a send
//! published); and a request without the control token does nothing.
//!
//! Jobs are put into the daemon's registry directly (the daemon and the test
//! share one registry per data directory), so every state can be set up without
//! a network. One test runs a real publish end to end.

use std::{path::Path, sync::Arc, time::Duration};

use miasma_core::{
    daemon::{
        ipc::{daemon_request, read_frame, write_frame, ControlRequest, ControlResponse},
        DaemonServer,
    },
    network::{node::MiasmaNode, types::NodeType},
    transfer::{
        jobs::{registry_for, RemoveRefusal, TransferRegistry},
        journal::{journal_path, part_path_for, ReceiveJournal, JOURNAL_VERSION},
        TransferProgress, TransferState, TransferStatus,
    },
    ContentId, LocalShareStore,
};
use tokio::{net::TcpStream, task::JoinHandle};

struct TestDaemon {
    dir: tempfile::TempDir,
    port: u16,
    store: Arc<LocalShareStore>,
    shutdown: tokio::sync::mpsc::Sender<()>,
    run: JoinHandle<anyhow::Result<()>>,
}

async fn start_daemon() -> TestDaemon {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let master: [u8; 32] = std::fs::read(dir.path().join("master.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store.clone(), dir.path().to_owned())
        .await
        .unwrap();
    let port = server.control_port();
    let shutdown = server.shutdown_handle();
    let run = tokio::spawn(server.run());
    TestDaemon {
        dir,
        port,
        store,
        shutdown,
        run,
    }
}

impl TestDaemon {
    fn registry(&self) -> Arc<TransferRegistry> {
        registry_for(self.dir.path())
    }

    async fn ask(&self, req: ControlRequest) -> ControlResponse {
        daemon_request(self.dir.path(), req).await.unwrap()
    }

    async fn list(&self) -> Vec<TransferStatus> {
        match self.ask(ControlRequest::TransferList).await {
            ControlResponse::TransferList(l) => l,
            other => panic!("unexpected: {other:?}"),
        }
    }

    async fn remove(&self, id: &str, discard_partial: bool) -> ControlResponse {
        self.ask(ControlRequest::TransferRemove {
            id: id.into(),
            discard_partial,
        })
        .await
    }

    async fn stop(self) {
        let _ = self.shutdown.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.run).await;
    }
}

fn mid_of(tag: &str) -> ContentId {
    ContentId::compute(tag.as_bytes(), b"p")
}

/// A receive job in `state`, named after `output`.
fn receive_job(
    d: &TestDaemon,
    mid: &ContentId,
    output: &Path,
    state: TransferState,
    resumable: bool,
) -> String {
    let id = mid.to_string();
    let p = TransferProgress::new(id.clone());
    p.set_name(output.to_string_lossy());
    if state != TransferState::Running {
        p.set_state(state, None, resumable);
    }
    d.registry().insert_for_tests(&id, p);
    id
}

/// The journal and `.part` a stopped receive leaves next to `output`.
fn leave_partial(d: &TestDaemon, mid: &ContentId, output: &Path) {
    let part = part_path_for(output);
    std::fs::write(&part, b"partial bytes").unwrap();
    ReceiveJournal {
        version: JOURNAL_VERSION,
        mid: mid.to_string(),
        output_path: output.to_string_lossy().into_owned(),
        part_path: part.to_string_lossy().into_owned(),
        data_shards: 2,
        total_shards: 3,
        segment_count: 4,
        total_bytes: 4_000,
        manifest_hash: None,
        next_segment: 1,
        bytes_done: 1_000,
        started_at: 1,
        updated_at: 2,
        last_error: None,
        share_id: None,
    }
    .save(&journal_path(&d.registry().journal_dir(), mid))
    .unwrap();
}

fn ids(list: &[TransferStatus]) -> Vec<String> {
    let mut v: Vec<String> = list.iter().map(|s| s.mid.clone()).collect();
    v.sort();
    v
}

fn refused(resp: ControlResponse, want: RemoveRefusal) {
    match resp {
        ControlResponse::TransferRemoveRefused { reason, .. } => assert_eq!(reason, want),
        other => panic!("expected {want:?}, got {other:?}"),
    }
}

fn removed(resp: ControlResponse) -> (u32, u32) {
    match resp {
        ControlResponse::TransferRemoved {
            removed,
            kept_partial,
        } => (removed, kept_partial),
        other => panic!("expected a removal, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_finished_receive_is_removed_and_its_output_file_is_untouched() {
    let d = start_daemon().await;
    let out_dir = tempfile::tempdir().unwrap();
    let output = out_dir.path().join("out.bin");
    std::fs::write(&output, b"the received file").unwrap();
    let mid = mid_of("done");
    let id = receive_job(&d, &mid, &output, TransferState::Complete, false);
    assert_eq!(ids(&d.list().await), vec![id.clone()]);

    assert_eq!(removed(d.remove(&id, false).await), (1, 0));

    assert!(d.list().await.is_empty(), "the row must not come back");
    assert!(matches!(
        d.ask(ControlRequest::TransferStatus { id: id.clone() })
            .await,
        ControlResponse::Error(_)
    ));
    assert_eq!(std::fs::read(&output).unwrap(), b"the received file");
    // A restarted daemon has no live jobs and finds nothing on disk to list.
    let restarted = TransferRegistry::detached_for_tests(d.dir.path());
    assert!(restarted.list().is_empty());
    // Idempotent: the second remove is a clean not-found.
    refused(d.remove(&id, false).await, RemoveRefusal::NotFound);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_id_is_not_found_and_an_id_is_never_a_path() {
    let d = start_daemon().await;
    let victim = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(victim.path(), b"keep me").unwrap();
    for id in [
        "miasma:nope".to_owned(),
        String::new(),
        format!("send:{}", victim.path().display()),
        victim.path().display().to_string(),
        "../../etc/passwd".to_owned(),
    ] {
        refused(d.remove(&id, true).await, RemoveRefusal::NotFound);
    }
    assert_eq!(std::fs::read(victim.path()).unwrap(), b"keep me");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_receive_with_partial_data_is_discarded_only_on_request() {
    let d = start_daemon().await;
    let out_dir = tempfile::tempdir().unwrap();
    let output = out_dir.path().join("big.bin");
    // An unrelated older file at the output path must never be deleted.
    std::fs::write(&output, b"older file").unwrap();
    let mid = mid_of("cancelled");
    leave_partial(&d, &mid, &output);
    let id = receive_job(&d, &mid, &output, TransferState::Cancelled, true);
    let part = part_path_for(&output);
    let jpath = journal_path(&d.registry().journal_dir(), &mid);

    // Without the explicit discard nothing is lost.
    refused(d.remove(&id, false).await, RemoveRefusal::HasPartialData);
    assert!(part.exists() && jpath.exists());
    assert_eq!(ids(&d.list().await), vec![id.clone()]);

    // With it, the row, the journal and the .part go; the output path stays.
    assert_eq!(removed(d.remove(&id, true).await), (1, 0));
    assert!(!part.exists(), ".part must be deleted");
    assert!(!jpath.exists(), "journal must be deleted");
    assert_eq!(std::fs::read(&output).unwrap(), b"older file");
    assert!(d.list().await.is_empty());
    // After a restart it does not reappear as a paused transfer.
    assert!(TransferRegistry::detached_for_tests(d.dir.path())
        .list()
        .is_empty());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_journal_that_points_elsewhere_never_deletes_a_foreign_file() {
    let d = start_daemon().await;
    let out_dir = tempfile::tempdir().unwrap();
    let output = out_dir.path().join("x.bin");
    let foreign = out_dir.path().join("precious.txt");
    std::fs::write(&foreign, b"precious").unwrap();
    let mid = mid_of("tampered");
    leave_partial(&d, &mid, &output);
    // Point the journal's part_path at a file that is not `<output>.part`.
    let jpath = journal_path(&d.registry().journal_dir(), &mid);
    let mut j = ReceiveJournal::load(&jpath).unwrap();
    j.part_path = foreign.to_string_lossy().into_owned();
    j.save(&jpath).unwrap();
    let id = receive_job(&d, &mid, &output, TransferState::Failed, false);

    assert_eq!(removed(d.remove(&id, true).await), (1, 0));
    assert_eq!(std::fs::read(&foreign).unwrap(), b"precious");
    assert!(!jpath.exists());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn running_and_paused_transfers_are_refused_and_keep_everything() {
    let d = start_daemon().await;
    let out_dir = tempfile::tempdir().unwrap();

    let running = receive_job(
        &d,
        &mid_of("running"),
        &out_dir.path().join("r.bin"),
        TransferState::Running,
        false,
    );
    let paused_out = out_dir.path().join("p.bin");
    let paused_mid = mid_of("paused");
    leave_partial(&d, &paused_mid, &paused_out);
    let paused = receive_job(&d, &paused_mid, &paused_out, TransferState::Paused, true);
    // A paused transfer known only from its journal (an earlier daemon process).
    let orphan_out = out_dir.path().join("o.bin");
    let orphan_mid = mid_of("orphan");
    leave_partial(&d, &orphan_mid, &orphan_out);
    let orphan = orphan_mid.to_string();

    refused(d.remove(&running, true).await, RemoveRefusal::Running);
    refused(d.remove(&paused, true).await, RemoveRefusal::Paused);
    refused(d.remove(&orphan, true).await, RemoveRefusal::Paused);

    assert!(part_path_for(&paused_out).exists());
    assert!(part_path_for(&orphan_out).exists());
    assert!(journal_path(&d.registry().journal_dir(), &paused_mid).exists());
    assert!(journal_path(&d.registry().journal_dir(), &orphan_mid).exists());
    assert_eq!(d.list().await.len(), 3);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_finished_removes_only_finished_transfers_and_never_partial_data() {
    let d = start_daemon().await;
    let out_dir = tempfile::tempdir().unwrap();
    let mk = |tag: &str, state, resumable| {
        let mid = mid_of(tag);
        let out = out_dir.path().join(format!("{tag}.bin"));
        (receive_job(&d, &mid, &out, state, resumable), mid, out)
    };
    let (complete, _, complete_out) = mk("c", TransferState::Complete, false);
    std::fs::write(&complete_out, b"kept").unwrap();
    let (failed, _, _) = mk("f", TransferState::Failed, false);
    let (running, _, _) = mk("r", TransferState::Running, false);
    let (paused, pm, po) = mk("p", TransferState::Paused, true);
    leave_partial(&d, &pm, &po);
    let (cancelled, cm, co) = mk("x", TransferState::Cancelled, true);
    leave_partial(&d, &cm, &co);

    // Two finished rows go; the cancelled one with partial data is kept.
    assert_eq!(
        removed(d.ask(ControlRequest::TransferClearFinished).await),
        (2, 1)
    );
    let mut left = vec![running, paused, cancelled];
    left.sort();
    assert_eq!(ids(&d.list().await), left);
    for gone in [&complete, &failed] {
        assert!(matches!(
            d.ask(ControlRequest::TransferStatus { id: gone.clone() })
                .await,
            ControlResponse::Error(_)
        ));
    }
    assert_eq!(std::fs::read(&complete_out).unwrap(), b"kept");
    assert!(part_path_for(&co).exists() && part_path_for(&po).exists());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_finished_send_is_removed_but_its_source_and_shares_stay() {
    timeout_test(async {
        let d = start_daemon().await;
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("in.bin");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let id = match d
            .ask(ControlRequest::TransferStartPublish {
                file_path: src.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
                password: None,
                restart: false,
            })
            .await
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        loop {
            let s = match d
                .ask(ControlRequest::TransferStatus { id: id.clone() })
                .await
            {
                ControlResponse::TransferStatus(s) => s,
                other => panic!("unexpected: {other:?}"),
            };
            if s.state != TransferState::Running {
                assert_eq!(s.state, TransferState::Complete, "{:?}", s.last_error);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut shares_before = d.store.list();
        shares_before.sort();
        assert!(!shares_before.is_empty(), "the publish stored shares");

        assert_eq!(removed(d.remove(&id, false).await), (1, 0));

        assert!(d.list().await.is_empty());
        assert_eq!(std::fs::read(&src).unwrap(), data, "source file untouched");
        let mut shares_after = d.store.list();
        shares_after.sort();
        assert_eq!(shares_after, shares_before, "published shares untouched");
        assert!(TransferRegistry::detached_for_tests(d.dir.path())
            .list()
            .is_empty());
        d.stop().await;
    })
    .await;
}

async fn timeout_test(f: impl std::future::Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(120), f)
        .await
        .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_remove_without_the_control_token_is_refused_and_changes_nothing() {
    let d = start_daemon().await;
    let out_dir = tempfile::tempdir().unwrap();
    let id = receive_job(
        &d,
        &mid_of("guarded"),
        &out_dir.path().join("g.bin"),
        TransferState::Complete,
        false,
    );
    for req in [
        ControlRequest::TransferRemove {
            id: id.clone(),
            discard_partial: true,
        },
        ControlRequest::TransferClearFinished,
    ] {
        // A bare request as the first frame, with no auth frame before it.
        let mut s = TcpStream::connect(("127.0.0.1", d.port)).await.unwrap();
        if write_frame(&mut s, &req).await.is_ok() {
            match read_frame::<ControlResponse>(&mut s).await {
                Err(_) => {}
                Ok(ControlResponse::Error(e)) => assert!(e.contains("unauthorized"), "{e}"),
                Ok(other) => panic!("served without a token: {other:?}"),
            }
        }
    }
    assert_eq!(ids(&d.list().await), vec![id]);
    d.stop().await;
}

// ─── A folder target: the daemon accepts it, the engine still refuses it ─────

#[tokio::test(flavor = "multi_thread")]
async fn a_receive_into_a_folder_is_accepted_by_the_daemon_and_resolved_by_the_job() {
    // The daemon no longer refuses a folder: the job writes <folder>/<name> once
    // the manifest names the file (see share_id_test for the written file). The
    // engine's own check still refuses a folder (next test), so nothing is
    // created in the folder before the record is known.
    let d = start_daemon().await;
    let folder = tempfile::tempdir().unwrap();
    let mid = mid_of("folder target");
    let resp = d
        .ask(ControlRequest::TransferStartReceive {
            mid: mid.to_string(),
            output_path: folder.path().to_string_lossy().into_owned(),
            password: None,
            restart: false,
            via: vec![],
            via_ca_pem: None,
        })
        .await;
    let id = match resp {
        ControlResponse::TransferStarted { id } => id,
        other => panic!("a folder must be accepted, got {other:?}"),
    };
    assert_eq!(std::fs::read_dir(folder.path()).unwrap().count(), 0);
    let _ = d.ask(ControlRequest::TransferCancel { id }).await;
    d.stop().await;
}

#[test]
fn the_output_target_check_names_the_path_and_leaves_nothing_behind() {
    use miasma_core::transfer::receive::check_output_target;
    let dir = tempfile::tempdir().unwrap();

    // A folder, and a path whose "folder" is really a file.
    let e = check_output_target(dir.path()).unwrap_err().to_string();
    assert!(e.contains("folder") && e.contains(&dir.path().display().to_string()));
    let file = dir.path().join("plain.txt");
    std::fs::write(&file, b"x").unwrap();
    let e = check_output_target(&file.join("out.bin"))
        .unwrap_err()
        .to_string();
    assert!(e.contains("not a folder"), "{e}");

    // A good path: its missing folder is created, and no `.part` is left.
    let good = dir.path().join("new").join("sub").join("got.bin");
    check_output_target(&good).unwrap();
    assert!(good.parent().unwrap().is_dir());
    assert!(!part_path_for(&good).exists());
    // An existing partial file is neither truncated nor deleted.
    std::fs::write(part_path_for(&good), b"keep").unwrap();
    check_output_target(&good).unwrap();
    assert_eq!(std::fs::read(part_path_for(&good)).unwrap(), b"keep");
}
