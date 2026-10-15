//! `LogsTail` / `LogsSetDiagnostic` / `LogsClear` against a real daemon, and
//! the wire-compatibility of the new variants.

use std::sync::Arc;

use miasma_core::daemon::ipc::{daemon_request, ControlRequest, ControlResponse};
use miasma_core::daemon::DaemonServer;
use miasma_core::logging::{self, Component, InitOptions};
use miasma_core::network::types::NodeType;
use miasma_core::{network::node::MiasmaNode, LocalShareStore, NodeConfig};

#[test]
fn new_variants_round_trip_through_json() {
    let r = ControlRequest::LogsTail {
        max_lines: 50,
        since_seq: Some(7),
    };
    let s = serde_json::to_string(&r).unwrap();
    assert_eq!(s, r#"{"LogsTail":{"max_lines":50,"since_seq":7}}"#);
    let back: ControlRequest = serde_json::from_str(&s).unwrap();
    assert!(matches!(
        back,
        ControlRequest::LogsTail {
            max_lines: 50,
            since_seq: Some(7)
        }
    ));
    // `since_seq` may be absent (older clients of this variant).
    let back: ControlRequest = serde_json::from_str(r#"{"LogsTail":{"max_lines":5}}"#).unwrap();
    assert!(matches!(
        back,
        ControlRequest::LogsTail {
            max_lines: 5,
            since_seq: None
        }
    ));
    for req in [
        ControlRequest::LogsSetDiagnostic { enabled: true },
        ControlRequest::LogsClear,
    ] {
        let s = serde_json::to_string(&req).unwrap();
        let _: ControlRequest = serde_json::from_str(&s).unwrap();
    }

    let resp = ControlResponse::Logs {
        lines: vec!["a".into(), "b".into()],
        next_seq: 9,
        diagnostic: false,
        stealth: true,
        capacity: 2 << 20,
    };
    let s = serde_json::to_string(&resp).unwrap();
    let back: ControlResponse = serde_json::from_str(&s).unwrap();
    match back {
        ControlResponse::Logs {
            lines, next_seq, ..
        } => {
            assert_eq!(lines, ["a", "b"]);
            assert_eq!(next_seq, 9);
        }
        other => panic!("{other:?}"),
    }
    // Optional fields may be missing.
    let back: ControlResponse =
        serde_json::from_str(r#"{"Logs":{"lines":[],"next_seq":0}}"#).unwrap();
    assert!(matches!(back, ControlResponse::Logs { .. }));
    // Debug never prints the lines.
    let shown = format!(
        "{:?}",
        ControlResponse::Logs {
            lines: vec!["private line".into()],
            next_seq: 1,
            diagnostic: false,
            stealth: true,
            capacity: 0
        }
    );
    assert!(!shown.contains("private line"));
}

/// What an older daemon does with the new request: it cannot parse it, so the
/// connection ends without a `Logs` answer (the CLI reports "not supported").
#[test]
fn an_older_daemon_cannot_parse_the_new_requests() {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    enum OldRequest {
        Status,
        Wipe,
    }
    let new = serde_json::to_string(&ControlRequest::LogsClear).unwrap();
    assert!(serde_json::from_str::<OldRequest>(&new).is_err());
    // And the older requests are unchanged for a newer daemon.
    assert!(serde_json::from_str::<ControlRequest>("\"Status\"").is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_daemon_serves_its_memory_buffer() {
    let dir = tempfile::tempdir().unwrap();
    NodeConfig::default().save(dir.path()).unwrap();
    let settings = logging::init(InitOptions {
        component: Component::Daemon,
        data_dir: dir.path(),
        filter_env: "MIASMA_TEST_UNSET_FILTER",
        default_filter: "info",
        process_hardening: false,
    });
    assert!(settings.stealth && !settings.diagnostic_files);

    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
    let master: [u8; 32] = std::fs::read(dir.path().join("master.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.path().to_owned())
        .await
        .unwrap();
    let shutdown = server.shutdown_handle();
    let run = tokio::spawn(server.run());

    tracing::info!("marker line one");
    tracing::info!("marker line two");

    let resp = daemon_request(
        dir.path(),
        ControlRequest::LogsTail {
            max_lines: 1000,
            since_seq: None,
        },
    )
    .await
    .unwrap();
    let (lines, next_seq) = match resp {
        ControlResponse::Logs {
            lines,
            next_seq,
            diagnostic,
            stealth,
            capacity,
        } => {
            assert!(stealth && !diagnostic);
            assert_eq!(capacity, 2 * 1024 * 1024);
            (lines, next_seq)
        }
        other => panic!("{other:?}"),
    };
    assert!(lines.iter().any(|l| l.contains("marker line one")));
    assert!(lines.iter().any(|l| l.contains("marker line two")));

    // Follow: only newer lines.
    tracing::info!("marker line three");
    let resp = daemon_request(
        dir.path(),
        ControlRequest::LogsTail {
            max_lines: 1000,
            since_seq: Some(next_seq),
        },
    )
    .await
    .unwrap();
    match resp {
        ControlResponse::Logs { lines, .. } => {
            assert!(lines.iter().any(|l| l.contains("marker line three")));
            assert!(!lines.iter().any(|l| l.contains("marker line one")));
        }
        other => panic!("{other:?}"),
    }

    // Diagnostic logging on: files appear in the folder, the setting is
    // persisted; off: they are gone.
    let resp = daemon_request(
        dir.path(),
        ControlRequest::LogsSetDiagnostic { enabled: true },
    )
    .await
    .unwrap();
    assert!(matches!(
        resp,
        ControlResponse::Logs {
            diagnostic: true,
            ..
        }
    ));
    tracing::info!("written to the file");
    assert!(
        NodeConfig::load(dir.path())
            .unwrap()
            .privacy
            .diagnostic_logging
    );
    assert!(miasma_core::logging::diag::count_files(dir.path()) >= 1);
    let resp = daemon_request(
        dir.path(),
        ControlRequest::LogsSetDiagnostic { enabled: false },
    )
    .await
    .unwrap();
    assert!(matches!(
        resp,
        ControlResponse::Logs {
            diagnostic: false,
            ..
        }
    ));
    assert_eq!(miasma_core::logging::diag::count_files(dir.path()), 0);
    assert!(
        !NodeConfig::load(dir.path())
            .unwrap()
            .privacy
            .diagnostic_logging
    );

    // Clear empties the buffer.
    let resp = daemon_request(dir.path(), ControlRequest::LogsClear)
        .await
        .unwrap();
    assert!(matches!(resp, ControlResponse::Logs { .. }));
    let resp = daemon_request(
        dir.path(),
        ControlRequest::LogsTail {
            max_lines: 1000,
            since_seq: None,
        },
    )
    .await
    .unwrap();
    match resp {
        ControlResponse::Logs { lines, .. } => {
            assert!(!lines.iter().any(|l| l.contains("marker line")))
        }
        other => panic!("{other:?}"),
    }

    let _ = shutdown.send(()).await;
    let _ = run.await;
}
