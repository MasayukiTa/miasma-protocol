//! Phase 3: the receive job as a client sees it — through the daemon's IPC, the
//! way `miasma network-get` uses it. Two real daemons on loopback.

use std::{sync::Arc, time::Duration};

use miasma_core::{
    daemon::{
        ipc::{daemon_request, ControlRequest, ControlResponse},
        DaemonServer,
    },
    transfer::{TransferState, TransferStatus},
    LocalShareStore, MiasmaNode, Multiaddr, NodeType,
};
use tokio::time::timeout;

struct Daemon {
    dir: std::path::PathBuf,
    shutdown: tokio::sync::mpsc::Sender<()>,
    addr: String,
}

async fn start_daemon(key: u8, bootstrap: Option<&str>) -> Daemon {
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Arc::new(LocalShareStore::open(&dir, 1000).unwrap());
    let node = MiasmaNode::new(&[key; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.clone()).await.unwrap();
    let addr = format!("{}/p2p/{}", server.listen_addrs()[0], server.peer_id());
    let shutdown = server.shutdown_handle();

    if let Some(peer) = bootstrap {
        use libp2p::multiaddr::Protocol;
        let mut a: Multiaddr = peer.parse().unwrap();
        let id: libp2p::PeerId = a
            .iter()
            .find_map(|p| {
                if let Protocol::P2p(id) = p {
                    Some(id)
                } else {
                    None
                }
            })
            .unwrap();
        if matches!(a.iter().last(), Some(Protocol::P2p(_))) {
            a.pop();
        }
        server.add_bootstrap_peer(id, a).await.unwrap();
        server.bootstrap_dht().await.unwrap();
    }
    tokio::spawn(server.run());
    Daemon {
        dir,
        shutdown,
        addr,
    }
}

async fn status(d: &Daemon, id: &str) -> TransferStatus {
    match daemon_request(&d.dir, ControlRequest::TransferStatus { id: id.into() })
        .await
        .unwrap()
    {
        ControlResponse::TransferStatus(s) => s,
        other => panic!("unexpected: {other:?}"),
    }
}

async fn wait_until_finished(d: &Daemon, id: &str) -> TransferStatus {
    loop {
        let s = status(d, id).await;
        if s.state != TransferState::Running {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_receive_job_reports_status_completes_and_a_wrong_password_fails_cleanly() {
    timeout(Duration::from_secs(180), async {
        let a = start_daemon(0x51, None).await;

        // A publishes a password-protected file.
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("payload.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 31 % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let mid = match daemon_request(
            &a.dir,
            ControlRequest::PublishFileProtected {
                file_path: src.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
                password: "ipc-secret".into(),
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::Published { mid } => mid,
            other => panic!("unexpected: {other:?}"),
        };

        let b = start_daemon(0x52, Some(&a.addr)).await;
        tokio::time::sleep(Duration::from_millis(2000)).await;

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");

        // ── Wrong password: the job ends Failed, not Running forever ─────────
        let id = match daemon_request(
            &b.dir,
            ControlRequest::TransferStartReceive {
                mid: mid.clone(),
                output_path: out.to_string_lossy().into_owned(),
                password: Some("wrong".into()),
                restart: false,
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(id, mid, "the id is the MID");
        let s = wait_until_finished(&b, &id).await;
        assert_eq!(s.state, TransferState::Failed);
        assert!(
            s.last_error
                .as_deref()
                .unwrap_or("")
                .contains("wrong password"),
            "{:?}",
            s.last_error
        );
        assert!(!out.exists());
        assert_eq!(
            s.pieces_fetched, 0,
            "nothing may be fetched for a wrong password"
        );

        // ── Missing password is a distinct, clear error ─────────────────────
        daemon_request(
            &b.dir,
            ControlRequest::TransferStartReceive {
                mid: mid.clone(),
                output_path: out.to_string_lossy().into_owned(),
                password: None,
                restart: false,
            },
        )
        .await
        .unwrap();
        let s = wait_until_finished(&b, &id).await;
        assert_eq!(s.state, TransferState::Failed);
        assert!(
            s.last_error
                .as_deref()
                .unwrap_or("")
                .contains("password-protected"),
            "{:?}",
            s.last_error
        );

        // ── The right password ───────────────────────────────────────────────
        daemon_request(
            &b.dir,
            ControlRequest::TransferStartReceive {
                mid: mid.clone(),
                output_path: out.to_string_lossy().into_owned(),
                password: Some("ipc-secret".into()),
                restart: false,
            },
        )
        .await
        .unwrap();
        let s = wait_until_finished(&b, &id).await;
        assert_eq!(s.state, TransferState::Complete, "{:?}", s.last_error);
        assert_eq!(s.bytes_done, data.len() as u64);
        assert_eq!(s.bytes_total, data.len() as u64);
        assert_eq!(s.segments_done, s.segments_total);
        assert_eq!(std::fs::read(&out).unwrap(), data);

        // ── It is listed, and an unknown id / a finished job cannot be cancelled ─
        match daemon_request(&b.dir, ControlRequest::TransferList)
            .await
            .unwrap()
        {
            ControlResponse::TransferList(l) => {
                assert!(l
                    .iter()
                    .any(|t| t.mid == mid && t.state == TransferState::Complete));
            }
            other => panic!("unexpected: {other:?}"),
        }
        for id in [mid.as_str(), "miasma:not-a-transfer"] {
            match daemon_request(&b.dir, ControlRequest::TransferCancel { id: id.into() })
                .await
                .unwrap()
            {
                ControlResponse::Error(_) => {}
                other => panic!("cancelling {id} should be refused, got {other:?}"),
            }
        }
        match daemon_request(
            &b.dir,
            ControlRequest::TransferStatus {
                id: "miasma:not-a-transfer".into(),
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::Error(_) => {}
            other => panic!("unexpected: {other:?}"),
        }

        let _ = a.shutdown.send(()).await;
        let _ = b.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}
