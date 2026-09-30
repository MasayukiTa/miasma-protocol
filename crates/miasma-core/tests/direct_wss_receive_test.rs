//! Direct receive over a WebSocket endpoint (`network-get --via`).
//!
//! The sender is a real node with a real `WssShareServer` in front of its store
//! and its DHT record store; the receiver has no libp2p peer and no bootstrap, so
//! the DHT is unusable: everything (record, manifest, every piece) crosses the
//! WebSocket. The receive engine is the production one, not a stand-in.
//!
//! No test carries a fixed secret or a hard-coded key: passwords are generated at
//! run time and the TLS certificates are created here.

use std::{sync::Arc, time::Duration};

use futures::{SinkExt, StreamExt};
use miasma_core::{
    daemon::{
        ipc::{daemon_request, ControlRequest, ControlResponse},
        DaemonServer,
    },
    network::node::ShareFetchResponse,
    transfer::{
        direct::{
            fetch_record_and_manifest_via, receive_file_via, ViaConfig, WsPieceSource,
            MAX_VIA_ENDPOINTS,
        },
        receive::{run_receive, ReceiveSpec, RetryConfig},
        ReceiveOutcome, TransferProgress, TransferState, TransferStatus,
    },
    transport::{
        websocket::{decode_ws_message, encode_ws_message, RecordProvider, WsRequest, WsResponse},
        ws_direct::WsDirectClient,
    },
    ContentId, DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaError, MiasmaNode,
    NodeType, PublishOptions, WssShareServer,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

/// A file one 64 KiB block longer than the largest k=2 segment: exactly two
/// segments without needing a 64 MiB fixture (see `transfer_publish_test`).
const MAX_SEGMENT_K2: usize = (8 * 1024 * 1024 - 4096) * 2;
const TWO_SEGMENT_LEN: usize = MAX_SEGMENT_K2 + 64 * 1024;

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    }
}

/// A fresh random password: no test carries a fixed secret.
fn random_password() -> String {
    // Always satisfies the password policy: a digit, letters and a symbol.
    format!("pw-1{:032x}", rand::random::<u128>())
}

/// Deterministic, non-repeating-looking content so a segment mix-up is visible.
fn content(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn write_payload(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A sender: a node holding its shares and its DHT record locally, with the
/// WebSocket server in front of both. There is deliberately no peer.
struct Sender {
    coord: MiasmaCoordinator,
    store: Arc<LocalShareStore>,
    port: u16,
    _dir: TempDir,
}

impl Sender {
    async fn plain(key: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
        let mut node = MiasmaNode::new(&[key; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let addrs = node.collect_listen_addrs(400).await;
        let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
        let server = WssShareServer::bind(store.clone(), 0)
            .await
            .unwrap()
            .with_record_provider(Arc::new(coord.dht_handle().clone()));
        let port = server.port;
        tokio::spawn(server.run());
        Self {
            coord,
            store,
            port,
            _dir: dir,
        }
    }

    fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }

    async fn publish(&self, bytes: &[u8], password: Option<&str>) -> ContentId {
        let scratch = tempfile::tempdir().unwrap();
        let path = write_payload(&scratch, bytes);
        let report = match password {
            Some(pw) => {
                self.coord
                    .dissolve_and_publish_file_protected(
                        &path,
                        params(),
                        PublishOptions::default(),
                        pw,
                    )
                    .await
            }
            None => {
                self.coord
                    .dissolve_and_publish_file_with_options(
                        &path,
                        params(),
                        PublishOptions::default(),
                    )
                    .await
            }
        }
        .unwrap();
        report.mid
    }
}

fn via(url: &str) -> ViaConfig {
    ViaConfig {
        urls: vec![url.to_owned()],
        ca_pem: None,
    }
}

fn pw(s: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(s.to_owned()))
}

// ─── The whole thing, through the daemon's IPC ──────────────────────────────

struct Daemon {
    dir: TempDir,
    shutdown: tokio::sync::mpsc::Sender<()>,
    wss_port: u16,
}

async fn start_daemon(key: u8) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let node = MiasmaNode::new(&[key; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.path().to_path_buf())
        .await
        .unwrap();
    let wss_port = server.wss_port();
    let shutdown = server.shutdown_handle();
    tokio::spawn(server.run());
    Daemon {
        dir,
        shutdown,
        wss_port,
    }
}

async fn status(d: &Daemon, id: &str) -> TransferStatus {
    match daemon_request(
        d.dir.path(),
        ControlRequest::TransferStatus { id: id.into() },
    )
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

async fn start_receive(
    d: &Daemon,
    mid: &str,
    out: &std::path::Path,
    password: Option<&str>,
    via: Vec<String>,
) -> ControlResponse {
    daemon_request(
        d.dir.path(),
        ControlRequest::TransferStartReceive {
            mid: mid.to_owned(),
            output_path: out.to_string_lossy().into_owned(),
            password: password.map(str::to_owned),
            restart: false,
            via,
            via_ca_pem: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_protected_multi_segment_transfer_is_received_through_a_daemon_with_only_a_via_url() {
    timeout(Duration::from_secs(400), async {
        // Sender daemon: plain WS server on 127.0.0.1, its own record store.
        let a = start_daemon(0x61).await;
        let src_dir = tempfile::tempdir().unwrap();
        let data = content(TWO_SEGMENT_LEN);
        let src = write_payload(&src_dir, &data);
        let password = random_password();
        let mid = match daemon_request(
            a.dir.path(),
            ControlRequest::PublishFileProtected {
                file_path: src.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
                password: password.clone(),
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::Published { mid } => mid,
            other => panic!("unexpected: {other:?}"),
        };
        assert!(a.wss_port != 0);

        // Receiver daemon: no bootstrap, no peer. The DHT cannot help it.
        let b = start_daemon(0x62).await;
        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let url = format!("ws://127.0.0.1:{}", a.wss_port);

        // Wrong password: refused before any piece is fetched.
        let id = match start_receive(&b, &mid, &out, Some(&random_password()), vec![url.clone()])
            .await
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
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
        assert_eq!(
            s.pieces_fetched, 0,
            "nothing may be fetched for a wrong password"
        );
        assert!(!out.exists());

        // No password for a protected transfer: a distinct, clear error.
        start_receive(&b, &mid, &out, None, vec![url.clone()]).await;
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

        // The right password: two segments, byte-identical.
        start_receive(&b, &mid, &out, Some(&password), vec![url.clone()]).await;
        let s = wait_until_finished(&b, &id).await;
        assert_eq!(s.state, TransferState::Complete, "{:?}", s.last_error);
        assert_eq!(s.segments_total, 2);
        assert_eq!(s.segments_done, 2);
        assert_eq!(s.bytes_done, data.len() as u64);
        assert!(std::fs::read(&out).unwrap() == data, "byte-identical");

        let _ = a.shutdown.send(()).await;
        let _ = b.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_via_list_is_refused_by_the_daemon_with_a_clear_message() {
    timeout(Duration::from_secs(60), async {
        let b = start_daemon(0x63).await;
        let out = tempfile::tempdir().unwrap().path().join("x.bin");
        let mid = ContentId::compute(b"x", &params().to_param_bytes()).to_string();

        for bad in [
            vec!["https://example.com".to_owned()],
            vec!["not a url".to_owned()],
            vec!["wss://user:secret@example.com".to_owned()],
            (0..=MAX_VIA_ENDPOINTS)
                .map(|i| format!("wss://h{i}.example.com"))
                .collect(),
        ] {
            match start_receive(&b, &mid, &out, None, bad.clone()).await {
                ControlResponse::Error(e) => {
                    assert!(e.contains("--via") || e.contains("via"), "{e}");
                    assert!(!e.contains("secret"), "credentials must not be echoed: {e}");
                }
                other => panic!("{bad:?} must be refused, got {other:?}"),
            }
        }
        let _ = b.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

#[test]
fn a_request_from_an_older_client_without_via_still_parses() {
    let old = r#"{"TransferStartReceive":{"mid":"miasma:x","output_path":"/o","password":null,"restart":false}}"#;
    match serde_json::from_str::<ControlRequest>(old).unwrap() {
        ControlRequest::TransferStartReceive {
            via, via_ca_pem, ..
        } => {
            assert!(via.is_empty());
            assert!(via_ca_pem.is_none());
        }
        _ => panic!("wrong variant"),
    }
}

// ─── The engine over the wire ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_direct_receive_resumes_after_a_stop_and_finishes_exactly() {
    timeout(Duration::from_secs(400), async {
        let sender = Sender::plain(0x71).await;
        let data = content(TWO_SEGMENT_LEN);
        let password = random_password();
        let mid = sender.publish(&data, Some(&password)).await;

        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("received").join("payload.bin");
        let journals = work.path().join("transfers");
        let cfg = via(&sender.ws_url());

        // Stop as soon as segment 0 is safely on disk.
        let progress = TransferProgress::new(mid.to_string());
        progress.stop_after_segments(1);
        let first = receive_file_via(&cfg, &mid, &out, pw(&password), &journals, false, progress)
            .await
            .unwrap();
        assert_eq!(first, ReceiveOutcome::Cancelled { next_segment: 1 });
        assert!(!out.exists(), "no output name until the file is whole");

        // Run it again: resumes at segment 1, does not fetch segment 0 again.
        let progress = TransferProgress::new(mid.to_string());
        let second = receive_file_via(
            &cfg,
            &mid,
            &out,
            pw(&password),
            &journals,
            false,
            progress.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            second,
            ReceiveOutcome::Complete {
                bytes: TWO_SEGMENT_LEN as u64
            }
        );
        let s = progress.snapshot();
        assert_eq!(s.resumed_from_segment, 1);
        assert_eq!(s.segments_done, 2);
        assert_eq!(s.pieces_rejected, 0);
        assert!(
            std::fs::read(&out).unwrap() == data,
            "byte-identical after resume"
        );
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_mid_is_a_clean_error_not_a_hang() {
    timeout(Duration::from_secs(60), async {
        let sender = Sender::plain(0x72).await;
        let _ = sender.publish(&content(50_000), None).await;

        let unknown = ContentId::compute(b"never published", &params().to_param_bytes());
        let work = tempfile::tempdir().unwrap();
        let progress = TransferProgress::new(unknown.to_string());
        let started = std::time::Instant::now();
        let err = receive_file_via(
            &via(&sender.ws_url()),
            &unknown,
            &work.path().join("out.bin"),
            None,
            &work.path().join("transfers"),
            false,
            progress.clone(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no record"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must not retry an answer"
        );
        assert_eq!(progress.snapshot().state, TransferState::Failed);
        assert!(!work.path().join("out.bin").exists());
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_endpoint_is_reported_not_endless() {
    timeout(Duration::from_secs(120), async {
        // A port nothing listens on.
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let mid = ContentId::compute(b"whatever", &params().to_param_bytes());
        let work = tempfile::tempdir().unwrap();
        let err = receive_file_via(
            &via(&format!("ws://127.0.0.1:{closed}")),
            &mid,
            &work.path().join("out.bin"),
            None,
            &work.path().join("transfers"),
            false,
            TransferProgress::new(mid.to_string()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("cannot reach"), "{err}");
    })
    .await
    .expect("timed out");
}

/// A WebSocket endpoint that relays to `upstream_port` but corrupts the shares of
/// `tamper_slots`: a hostile or broken endpoint between the receiver and a sender.
async fn tampering_relay(upstream_port: u16, tamper_slots: Vec<u16>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream =
        Arc::new(WsDirectClient::new(&format!("ws://127.0.0.1:{upstream_port}"), None).unwrap());
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let upstream = upstream.clone();
            let tamper_slots = tamper_slots.clone();
            tokio::spawn(async move {
                let mut ws = match tokio_tungstenite::accept_async(tcp).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                while let Some(Ok(msg)) = ws.next().await {
                    let Message::Binary(data) = msg else { return };
                    let Ok(req) = decode_ws_message::<WsRequest>(&data, 1024) else {
                        return;
                    };
                    let response = match req {
                        WsRequest::Record { mid_digest } => WsResponse::Record {
                            value: upstream.fetch_record(mid_digest).await.unwrap(),
                        },
                        WsRequest::Share(r) => {
                            let mut share = upstream
                                .fetch_share(r.mid_digest, r.segment_index, r.slot_index)
                                .await
                                .unwrap();
                            if let Some(s) = share.as_mut() {
                                if tamper_slots.contains(&s.slot_index) {
                                    let last = s.shard_data.len() - 1;
                                    s.shard_data[last] ^= 0x01;
                                }
                            }
                            WsResponse::Share(ShareFetchResponse { share })
                        }
                    };
                    let body = encode_ws_message(&response).unwrap();
                    if ws.send(Message::Binary(body)).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_piece_is_rejected_reported_and_replaced_by_a_spare() {
    timeout(Duration::from_secs(120), async {
        let sender = Sender::plain(0x73).await;
        let data = content(300_000);
        let mid = sender.publish(&data, None).await;

        // Slot 0 is corrupted in flight; slots 1 and 2 are good, k = 2.
        let relay = tampering_relay(sender.port, vec![0]).await;
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("out.bin");
        let progress = TransferProgress::new(mid.to_string());
        let outcome = receive_file_via(
            &via(&format!("ws://127.0.0.1:{relay}")),
            &mid,
            &out,
            None,
            &work.path().join("transfers"),
            false,
            progress.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ReceiveOutcome::Complete {
                bytes: data.len() as u64
            }
        );
        let s = progress.snapshot();
        assert!(
            s.pieces_rejected >= 1,
            "the bad piece must be reported: {s:?}"
        );
        assert!(std::fs::read(&out).unwrap() == data);
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn when_every_piece_is_tampered_nothing_is_written_and_the_transfer_pauses() {
    timeout(Duration::from_secs(120), async {
        let sender = Sender::plain(0x74).await;
        let mid = sender.publish(&content(300_000), None).await;
        let relay = tampering_relay(sender.port, vec![0, 1, 2]).await;

        let clients = vec![Arc::new(
            WsDirectClient::new(&format!("ws://127.0.0.1:{relay}"), None).unwrap(),
        )];
        let (record, manifest) = fetch_record_and_manifest_via(&clients, &mid).await.unwrap();
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("out.bin");
        let progress = TransferProgress::new(mid.to_string());
        let outcome = run_receive(
            &WsPieceSource::new(clients),
            ReceiveSpec {
                mid: mid.clone(),
                record,
                manifest,
                password: None,
                output_path: out.clone(),
                journal_dir: work.path().join("transfers"),
                restart: false,
                retry: RetryConfig {
                    max_attempts_per_segment: 2,
                    base_delay: Duration::from_millis(10),
                    max_delay: Duration::from_millis(20),
                },
                expect: None,
                record_signer: None,
            },
            progress.clone(),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, ReceiveOutcome::Paused { .. }),
            "{outcome:?}"
        );
        assert!(
            !out.exists(),
            "a tampered transfer must never appear as a file"
        );
        assert!(progress.snapshot().pieces_rejected >= 2);
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_endpoint_serves_when_the_first_is_dead() {
    timeout(Duration::from_secs(120), async {
        let sender = Sender::plain(0x75).await;
        let data = content(200_000);
        let mid = sender.publish(&data, None).await;
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("out.bin");
        let cfg = ViaConfig {
            urls: vec![format!("ws://127.0.0.1:{dead}"), sender.ws_url()],
            ca_pem: None,
        };
        let outcome = receive_file_via(
            &cfg,
            &mid,
            &out,
            None,
            &work.path().join("transfers"),
            false,
            TransferProgress::new(mid.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ReceiveOutcome::Complete {
                bytes: data.len() as u64
            }
        );
        assert!(std::fs::read(&out).unwrap() == data);
    })
    .await
    .expect("timed out");
}

// ─── wss:// with a certificate that only the test knows ─────────────────────

fn self_signed() -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

#[tokio::test(flavor = "multi_thread")]
async fn wss_with_a_self_signed_certificate_works_with_the_ca_and_is_refused_without() {
    timeout(Duration::from_secs(120), async {
        let sender = Sender::plain(0x76).await;
        let data = content(250_000);
        let mid = sender.publish(&data, None).await;

        // A TLS front for the same store and record store.
        let (cert_pem, key_pem) = self_signed();
        let tls = WssShareServer::bind_tls(
            sender.store.clone(),
            0,
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
        )
        .await
        .unwrap()
        .with_record_provider(Arc::new(sender.coord.dht_handle().clone()));
        let tls_port = tls.port;
        tokio::spawn(tls.run());
        let url = format!("wss://localhost:{tls_port}");

        // With the certificate as an extra CA: the whole file arrives.
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("out.bin");
        let with_ca = ViaConfig {
            urls: vec![url.clone()],
            ca_pem: Some(cert_pem.clone()),
        };
        let outcome = receive_file_via(
            &with_ca,
            &mid,
            &out,
            None,
            &work.path().join("transfers"),
            false,
            TransferProgress::new(mid.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ReceiveOutcome::Complete {
                bytes: data.len() as u64
            }
        );
        assert!(std::fs::read(&out).unwrap() == data);

        // Without it the certificate is not trusted (this process's OS store has
        // never heard of it): refused at once, with a message that says what to do.
        let out2 = work.path().join("out2.bin");
        let progress = TransferProgress::new(mid.to_string());
        let started = std::time::Instant::now();
        let err = receive_file_via(
            &via(&url),
            &mid,
            &out2,
            None,
            &work.path().join("transfers2"),
            false,
            progress.clone(),
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, MiasmaError::Network(_)), "{err:?}");
        assert!(
            msg.contains("certificate") && msg.contains("--ca-cert"),
            "{msg}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a refused certificate is not retried"
        );
        assert_eq!(progress.snapshot().state, TransferState::Failed);
        assert!(!out2.exists());

        // A different CA does not vouch for it either.
        let (other_ca, _) = self_signed();
        let wrong_ca = ViaConfig {
            urls: vec![url],
            ca_pem: Some(other_ca),
        };
        let err = receive_file_via(
            &wrong_ca,
            &mid,
            &work.path().join("out3.bin"),
            None,
            &work.path().join("transfers3"),
            false,
            TransferProgress::new(mid.to_string()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("certificate"), "{err}");
    })
    .await
    .expect("timed out");
}

// ─── Measurement (not a correctness test) ───────────────────────────────────

/// Loopback throughput of the direct path, and what connection reuse buys.
/// `cargo test -p miasma-core --test direct_wss_receive_test -- --ignored --nocapture measure_`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement"]
async fn measure_direct_receive_throughput_on_loopback() {
    let sender = Sender::plain(0x77).await;
    let data = content(TWO_SEGMENT_LEN);
    let mid = sender.publish(&data, None).await;

    // Whole receive.
    let work = tempfile::tempdir().unwrap();
    let progress = TransferProgress::new(mid.to_string());
    let t = std::time::Instant::now();
    receive_file_via(
        &via(&sender.ws_url()),
        &mid,
        &work.path().join("out.bin"),
        None,
        &work.path().join("transfers"),
        false,
        progress.clone(),
    )
    .await
    .unwrap();
    let secs = t.elapsed().as_secs_f64();
    let s = progress.snapshot();
    println!(
        "direct receive: {} bytes in {:.2} s = {:.1} MB/s (fetch {} ms, decode {} ms, write {} ms)",
        data.len(),
        secs,
        data.len() as f64 / secs / 1e6,
        s.fetch_ms,
        s.decode_ms,
        s.write_ms
    );

    // What the sender's store costs per share (read + decrypt at rest), so the
    // wire can be told apart from it.
    let addr = sender.store.list()[0].clone();
    let t = std::time::Instant::now();
    let share = sender.store.get(&addr).unwrap();
    println!(
        "sender store read of one {} byte share: {:.1} ms",
        share.shard_data.len(),
        t.elapsed().as_secs_f64() * 1e3
    );
    let pooled = WsDirectClient::new(&sender.ws_url(), None).unwrap();
    let t = std::time::Instant::now();
    for _ in 0..20 {
        let _ = pooled.fetch_record([9u8; 32]).await.unwrap();
    }
    println!(
        "empty round trip on a pooled connection: {:.2} ms",
        t.elapsed().as_secs_f64() * 1e3 / 20.0
    );

    // The wire alone: an 8 MiB answer (the size of the largest share) with no
    // store or decryption behind it, on a pooled connection vs a new connection
    // each time.
    struct Blob(Vec<u8>);
    #[async_trait::async_trait]
    impl RecordProvider for Blob {
        async fn record_value(&self, _mid: [u8; 32]) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
    }
    let store = sender.store.clone();
    let blob = WssShareServer::bind(store, 0)
        .await
        .unwrap()
        .with_record_provider(Arc::new(Blob(vec![0x5Au8; 8 * 1024 * 1024])));
    let blob_url = format!("ws://127.0.0.1:{}", blob.port);
    tokio::spawn(blob.run());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let n = 10;
    let pooled = WsDirectClient::new(&blob_url, None).unwrap();
    let t = std::time::Instant::now();
    for _ in 0..n {
        pooled.fetch_record([1u8; 32]).await.unwrap().unwrap();
    }
    let pooled_s = t.elapsed().as_secs_f64() / n as f64;
    let t = std::time::Instant::now();
    for _ in 0..n {
        let fresh = WsDirectClient::new(&blob_url, None).unwrap();
        fresh.fetch_record([1u8; 32]).await.unwrap().unwrap();
    }
    let fresh_s = t.elapsed().as_secs_f64() / n as f64;
    println!(
        "8 MiB over the wire: {:.1} ms = {:.0} MB/s pooled; {:.1} ms with a new connection each time",
        pooled_s * 1e3,
        8.0 * 1.048576 / pooled_s,
        fresh_s * 1e3
    );
}
