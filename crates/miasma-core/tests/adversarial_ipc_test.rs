//! Regression tests for the local control channel (adversarial review C-05 /
//! F3 / S-02): the daemon's IPC and HTTP bridge must not serve a peer that
//! merely reaches loopback.
//!
//! Every test runs a real daemon against a throwaway data directory. No test
//! writes a literal password: secrets are drawn from the OS RNG at run time.

use std::{path::Path, sync::Arc, time::Duration};

use miasma_core::daemon::{
    control_auth::{self, TOKEN_FILE},
    ipc::{
        daemon_request, daemon_wipe, read_frame, write_frame, ControlAuth, ControlRequest,
        ControlResponse, PORT_FILE,
    },
    DaemonServer,
};
use miasma_core::network::types::NodeType;
use miasma_core::{network::node::MiasmaNode, LocalShareStore};
use rand::{rngs::OsRng, Rng};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
use zeroize::Zeroize;

struct TestDaemon {
    dir: tempfile::TempDir,
    port: u16,
    http_port: u16,
    shutdown: tokio::sync::mpsc::Sender<()>,
    run: JoinHandle<anyhow::Result<()>>,
}

async fn start_daemon() -> TestDaemon {
    start_daemon_in(tempfile::tempdir().unwrap()).await
}

async fn start_daemon_in(dir: tempfile::TempDir) -> TestDaemon {
    let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
    let master: [u8; 32] = std::fs::read(dir.path().join("master.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.path().to_owned())
        .await
        .unwrap();
    let port = server.control_port();
    let http_port = server.http_bridge_port();
    let shutdown = server.shutdown_handle();
    let run = tokio::spawn(server.run());
    TestDaemon {
        dir,
        port,
        http_port,
        shutdown,
        run,
    }
}

impl TestDaemon {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn master_key_present(&self) -> bool {
        self.path().join("master.key").exists()
    }

    fn token(&self) -> String {
        control_auth::read_token_file(self.path())
            .unwrap()
            .as_str()
            .to_owned()
    }

    async fn stop(self) {
        let _ = self.shutdown.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.run).await;
    }
}

/// What a raw client (no helper, no token unless it passes one) gets back for
/// `frames` written to the control port. `None` means the daemon closed the
/// connection without answering.
async fn raw_exchange(port: u16, first: &impl serde::Serialize) -> Option<ControlResponse> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // The daemon may hang up before or while we write: that is a refusal too.
    if write_frame(&mut s, first).await.is_err() {
        return None;
    }
    read_frame::<ControlResponse>(&mut s).await.ok()
}

fn assert_refused(resp: Option<ControlResponse>) {
    match resp {
        None => {}
        Some(ControlResponse::Error(e)) => assert!(e.contains("unauthorized"), "error was: {e}"),
        Some(other) => panic!("peer without a valid token was served: {other:?}"),
    }
}

fn random_secret() -> String {
    let raw: [u8; 16] = OsRng.gen();
    hex::encode(raw)
}

// ─── No credential, no service ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn raw_tcp_without_token_gets_no_service_and_no_state_change() {
    let d = start_daemon().await;
    assert!(d.master_key_present());

    // A bare request as the first frame, exactly what the old protocol took.
    assert_refused(raw_exchange(d.port, &ControlRequest::Status).await);
    assert_refused(raw_exchange(d.port, &ControlRequest::Wipe).await);
    assert_refused(
        raw_exchange(
            d.port,
            &ControlRequest::TransferStartReceive {
                mid: "miasma:none".into(),
                output_path: d.path().join("stolen.bin").to_string_lossy().into_owned(),
                password: None,
                restart: false,
                via: vec![],
                via_ca_pem: None,
            },
        )
        .await,
    );

    // A well-formed auth frame with an empty token is no better.
    assert_refused(
        raw_exchange(
            d.port,
            &ControlAuth {
                token: String::new(),
            },
        )
        .await,
    );

    assert!(d.master_key_present(), "master.key must survive");
    assert!(!d.path().join("stolen.bin").exists());
    assert!(!d.path().join("stolen.bin.part").exists());

    // The daemon is still up and still serves the legitimate client.
    let resp = daemon_request(d.path(), ControlRequest::Status)
        .await
        .unwrap();
    assert!(matches!(resp, ControlResponse::Status(_)), "got {resp:?}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_token_is_refused_and_the_right_one_still_works() {
    let d = start_daemon().await;
    let real = d.token();
    let mut wrong = real.clone().into_bytes();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();

    for guess in [wrong, random_secret(), format!("{real}00")] {
        let mut s = TcpStream::connect(("127.0.0.1", d.port)).await.unwrap();
        write_frame(&mut s, &ControlAuth { token: guess })
            .await
            .unwrap();
        // Even a pipelined request behind the bad token must not run.
        let _ = write_frame(&mut s, &ControlRequest::Wipe).await;
        let resp = read_frame::<ControlResponse>(&mut s).await.ok();
        assert_refused(resp);
    }
    assert!(d.master_key_present());

    // Failures are delayed, not fatal: the real token is accepted right after.
    let resp = daemon_request(d.path(), ControlRequest::Status)
        .await
        .unwrap();
    assert!(matches!(resp, ControlResponse::Status(_)), "got {resp:?}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_attempts_are_delayed() {
    let d = start_daemon().await;
    let started = std::time::Instant::now();
    for _ in 0..3 {
        assert_refused(
            raw_exchange(
                d.port,
                &ControlAuth {
                    token: random_secret(),
                },
            )
            .await,
        );
    }
    // 100 ms + 200 ms + 400 ms of enforced delay across three failures.
    assert!(
        started.elapsed() >= Duration::from_millis(600),
        "three consecutive failures returned after only {:?}",
        started.elapsed()
    );
    d.stop().await;
}

// ─── Wipe needs a confirmation round trip ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn wipe_requires_the_daemon_issued_confirmation() {
    let d = start_daemon().await;

    // Without a challenge, a confirm does nothing.
    let resp = daemon_request(
        d.path(),
        ControlRequest::WipeConfirm {
            nonce: random_secret(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, ControlResponse::Error(_)), "got {resp:?}");
    assert!(d.master_key_present());

    // A single Wipe request only yields a challenge; the key is intact.
    let nonce = match daemon_request(d.path(), ControlRequest::Wipe)
        .await
        .unwrap()
    {
        ControlResponse::WipeChallenge { nonce } => nonce,
        other => panic!("Wipe must only issue a challenge, got {other:?}"),
    };
    assert!(d.master_key_present());

    // A guessed nonce is refused and does not consume the real one.
    let resp = daemon_request(
        d.path(),
        ControlRequest::WipeConfirm {
            nonce: random_secret(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, ControlResponse::Error(_)), "got {resp:?}");
    assert!(d.master_key_present());
    let status = daemon_request(d.path(), ControlRequest::Status)
        .await
        .unwrap();
    assert!(matches!(status, ControlResponse::Status(_)));

    // The real nonce wipes.
    let resp = daemon_request(d.path(), ControlRequest::WipeConfirm { nonce })
        .await
        .unwrap();
    assert!(matches!(resp, ControlResponse::Wiped), "got {resp:?}");
    let _ = tokio::time::timeout(Duration::from_secs(10), d.run).await;
    assert!(!d.dir.path().join("master.key").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_two_step_helper_wipes_and_a_nonce_is_single_use() {
    let d = start_daemon().await;
    let nonce = match daemon_request(d.path(), ControlRequest::Wipe)
        .await
        .unwrap()
    {
        ControlResponse::WipeChallenge { nonce } => nonce,
        other => panic!("got {other:?}"),
    };
    // A second Wipe replaces the outstanding challenge: the first nonce dies.
    let _ = daemon_request(d.path(), ControlRequest::Wipe)
        .await
        .unwrap();
    let resp = daemon_request(d.path(), ControlRequest::WipeConfirm { nonce })
        .await
        .unwrap();
    assert!(matches!(resp, ControlResponse::Error(_)), "got {resp:?}");
    assert!(d.master_key_present());

    let resp = daemon_wipe(d.path()).await.unwrap();
    assert!(matches!(resp, ControlResponse::Wiped), "got {resp:?}");
    let _ = tokio::time::timeout(Duration::from_secs(10), d.run).await;
    assert!(!d.dir.path().join("master.key").exists());
}

// ─── Token file ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn token_file_exists_and_is_256_bit_hex() {
    let d = start_daemon().await;
    let tok = std::fs::read_to_string(d.path().join(TOKEN_FILE)).unwrap();
    assert_eq!(tok.trim().len(), 64);
    assert!(tok.trim().bytes().all(|b| b.is_ascii_hexdigit()));
    d.stop().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn token_file_is_owner_only_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let d = start_daemon().await;
    let mode = std::fs::metadata(d.path().join(TOKEN_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    d.stop().await;
}

/// Windows: the token file carries an explicit, non-inherited ACL naming the
/// current user, and no broad principal.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn token_file_acl_excludes_broad_groups_on_windows() {
    let d = start_daemon().await;
    let out = std::process::Command::new("icacls")
        .arg(d.path().join(TOKEN_FILE))
        .output()
        .expect("icacls must be runnable");
    let listing = String::from_utf8_lossy(&out.stdout).to_lowercase();
    let user = std::env::var("USERNAME").unwrap().to_lowercase();
    assert!(
        listing.contains(&user),
        "ACL does not name {user}: {listing}"
    );
    for broad in ["everyone", "builtin\\users", "authenticated users"] {
        assert!(!listing.contains(broad), "ACL grants {broad}: {listing}");
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_token_from_a_crashed_daemon_is_replaced_and_removed_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    // Leftovers of a crashed daemon.
    let stale = random_secret() + &random_secret();
    std::fs::write(dir.path().join(TOKEN_FILE), &stale).unwrap();
    std::fs::write(dir.path().join(PORT_FILE), "1").unwrap();

    let d = start_daemon_in(dir).await;
    let fresh = d.token();
    assert_ne!(fresh, stale, "the stale token must not survive a restart");
    assert_eq!(fresh.len(), 64);

    // The stale token authenticates nothing; the fresh one does.
    assert_refused(raw_exchange(d.port, &ControlAuth { token: stale }).await);
    let resp = daemon_request(d.path(), ControlRequest::Status)
        .await
        .unwrap();
    assert!(matches!(resp, ControlResponse::Status(_)));

    let path = d.path().to_owned();
    d.stop().await;
    assert!(
        !path.join(TOKEN_FILE).exists(),
        "token file must be deleted at clean shutdown"
    );
}

// ─── Path policy ─────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn transfer_receive_refuses_relative_and_dotdot_output_paths() {
    let d = start_daemon().await;
    let mid = "miasma:0000000000000000000000000000000000000000000000";
    let escaping = d
        .path()
        .join("sub")
        .join("..")
        .join("..")
        .join("out.bin")
        .to_string_lossy()
        .into_owned();
    for bad in [
        "relative.bin".to_string(),
        "..\\up.bin".to_string(),
        escaping,
    ] {
        let resp = daemon_request(
            d.path(),
            ControlRequest::TransferStartReceive {
                mid: mid.into(),
                output_path: bad.clone(),
                password: None,
                restart: false,
                via: vec![],
                via_ca_pem: None,
            },
        )
        .await
        .unwrap();
        match resp {
            ControlResponse::Error(e) => {
                assert!(e.contains("output path rejected"), "{bad}: {e}")
            }
            other => panic!("{bad}: expected a path refusal, got {other:?}"),
        }
    }
    d.stop().await;
}

// ─── S-02: passwords do not outlive the request ─────────────────────────────

#[test]
fn password_bearing_requests_zeroize_their_secrets() {
    let mut protected = ControlRequest::PublishFileProtected {
        file_path: "f".into(),
        data_shards: 2,
        total_shards: 3,
        password: random_secret(),
    };
    protected.zeroize();
    match protected {
        ControlRequest::PublishFileProtected { password, .. } => assert!(password.is_empty()),
        _ => unreachable!(),
    }

    let mut receive = ControlRequest::TransferStartReceive {
        mid: "m".into(),
        output_path: "o".into(),
        password: Some(random_secret()),
        restart: false,
        via: vec![],
        via_ca_pem: None,
    };
    receive.zeroize();
    match receive {
        ControlRequest::TransferStartReceive { password, .. } => {
            assert!(password.unwrap().is_empty())
        }
        _ => unreachable!(),
    }

    let mut publish = ControlRequest::TransferStartPublish {
        file_path: "f".into(),
        data_shards: 2,
        total_shards: 3,
        password: Some(random_secret()),
        restart: false,
    };
    publish.zeroize();
    match publish {
        ControlRequest::TransferStartPublish { password, .. } => {
            assert!(password.unwrap().is_empty())
        }
        _ => unreachable!(),
    }

    let mut auth = ControlAuth {
        token: random_secret(),
    };
    auth.zeroize();
    assert!(auth.token.is_empty());
}

// ─── HTTP bridge ─────────────────────────────────────────────────────────────

async fn http(port: u16, method: &str, path: &str, bearer: Option<&str>, body: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let auth = bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn http_bridge_requires_the_token_even_without_an_origin_header() {
    let d = start_daemon().await;
    assert_ne!(d.http_port, 0, "bridge must be up for this test");
    let tok = d.token();

    // Liveness stays open so a web page can detect the bridge.
    let r = http(d.http_port, "GET", "/api/ping", None, "").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");

    // No Origin, no token: refused.
    let r = http(d.http_port, "GET", "/api/status", None, "").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    let r = http(d.http_port, "POST", "/api/wipe", None, "").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    let r = http(
        d.http_port,
        "GET",
        "/api/status",
        Some(&random_secret()),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    assert!(d.master_key_present());

    // With the token the read-only endpoint answers.
    let r = http(d.http_port, "GET", "/api/status", Some(&tok), "").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");

    // Wipe over HTTP is two-step too: no body yields a challenge, not a wipe.
    let r = http(d.http_port, "POST", "/api/wipe", Some(&tok), "").await;
    assert!(
        r.starts_with("HTTP/1.1 200") && r.contains("challenge"),
        "{r}"
    );
    assert!(d.master_key_present(), "a bare wipe request must not wipe");
    let bad = format!("{{\"confirm\":\"{}\"}}", random_secret());
    let r = http(d.http_port, "POST", "/api/wipe", Some(&tok), &bad).await;
    assert!(!r.contains("\"ok\":true"), "{r}");
    assert!(d.master_key_present());
    d.stop().await;
}
