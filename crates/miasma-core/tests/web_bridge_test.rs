//! The HTTP bridge as the browser client uses it: the client's own files are
//! served without a token, everything under `/api` (except the liveness ping)
//! needs one. Every test runs a real daemon against a throwaway data directory.
//! No test writes a literal password: secrets are drawn from the OS RNG at run
//! time.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use miasma_core::daemon::{
    control_auth,
    ipc::{daemon_request, ControlRequest, ControlResponse},
    DaemonServer,
};
use miasma_core::network::types::NodeType;
use miasma_core::{network::node::MiasmaNode, LocalShareStore, Multiaddr};
use rand::{rngs::OsRng, Rng};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

/// Everything the daemons log while these tests run, so a test can assert that a
/// password never reaches a log line.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> LogCapture {
        self.clone()
    }
}

fn logs() -> &'static LogCapture {
    static LOGS: OnceLock<LogCapture> = OnceLock::new();
    LOGS.get_or_init(|| {
        let capture = LogCapture::default();
        // miasma_core at trace: the most a debug build of the daemon would ever say.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("miasma_core=trace,warn"))
            .with_ansi(false)
            .with_writer(capture.clone())
            .try_init();
        capture
    })
}

fn captured_logs() -> String {
    String::from_utf8_lossy(&logs().0.lock().unwrap()).into_owned()
}

struct TestDaemon {
    dir: tempfile::TempDir,
    http_port: u16,
    /// Address another daemon can bootstrap from.
    addr: String,
    shutdown: tokio::sync::mpsc::Sender<()>,
    run: JoinHandle<anyhow::Result<()>>,
}

async fn start_daemon() -> TestDaemon {
    start_daemon_keyed(None, None).await
}

async fn start_daemon_keyed(key: Option<u8>, bootstrap: Option<&str>) -> TestDaemon {
    let _ = logs();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let master: [u8; 32] = match key {
        Some(k) => [k; 32],
        None => std::fs::read(dir.path().join("master.key"))
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.path().to_owned())
        .await
        .unwrap();
    let addr = format!("{}/p2p/{}", server.listen_addrs()[0], server.peer_id());
    if let Some(peer) = bootstrap {
        use libp2p::multiaddr::Protocol;
        let mut a: Multiaddr = peer.parse().unwrap();
        let id: libp2p::PeerId = a
            .iter()
            .find_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            })
            .unwrap();
        if matches!(a.iter().last(), Some(Protocol::P2p(_))) {
            a.pop();
        }
        server.add_bootstrap_peer(id, a).await.unwrap();
        server.bootstrap_dht().await.unwrap();
    }
    let http_port = server.http_bridge_port();
    let shutdown = server.shutdown_handle();
    let run = tokio::spawn(server.run());
    TestDaemon {
        dir,
        http_port,
        addr,
        shutdown,
        run,
    }
}

impl TestDaemon {
    fn token(&self) -> String {
        control_auth::read_token_file(self.dir.path())
            .unwrap()
            .as_str()
            .to_owned()
    }

    async fn stop(self) {
        let _ = self.shutdown.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.run).await;
    }
}

fn random_secret() -> String {
    let raw: [u8; 16] = OsRng.gen();
    hex::encode(raw)
}

/// A run-time password that satisfies the publish password policy (a digit,
/// letters and a symbol): the OS-random hex is wrapped in a fixed shape.
fn random_policy_password() -> String {
    format!("pw-1-{}", random_secret())
}

/// One raw HTTP/1.1 exchange. `origin` adds an `Origin` header.
async fn http_with(
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    origin: Option<&str>,
    body: &str,
) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let auth = bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let origin = origin
        .map(|o| format!("Origin: {o}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}{origin}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn http(port: u16, method: &str, path: &str, bearer: Option<&str>, body: &str) -> String {
    http_with(port, method, path, bearer, None, body).await
}

// ─── The client itself ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_bridge_serves_the_web_client_without_a_token() {
    let d = start_daemon().await;
    let tok = d.token();

    for (path, content_type) in [
        ("/", "text/html"),
        ("/index.html", "text/html"),
        ("/js/app.js", "text/javascript"),
        ("/js/bridge.js", "text/javascript"),
        ("/css/style.css", "text/css"),
        ("/sw.js", "text/javascript"),
        ("/pkg/miasma_wasm_bg.wasm", "application/wasm"),
    ] {
        let r = http(d.http_port, "GET", path, None, "").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{path}: {r:.200}");
        let lower = r.to_ascii_lowercase();
        assert!(
            lower.contains(&format!("content-type: {content_type}")),
            "{path}: {r:.300}"
        );
        assert!(lower.contains("x-content-type-options: nosniff"), "{path}");
        assert!(lower.contains("cache-control: no-cache"), "{path}");
        // Public code: the token is not in it.
        assert!(!r.contains(&tok), "{path} leaked the control token");
    }

    // The page is the real client.
    let r = http(d.http_port, "GET", "/", None, "").await;
    assert!(r.contains("<title>Miasma Web</title>"), "{r:.300}");

    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_the_client_does_not_open_the_api_or_the_filesystem() {
    let d = start_daemon().await;

    // The API keeps its token requirement.
    for path in ["/api/status", "/api/sharing-key", "/api/directed/inbox"] {
        let r = http(d.http_port, "GET", path, None, "").await;
        assert!(r.starts_with("HTTP/1.1 401"), "{path}: {r:.200}");
    }
    // No traversal, no files that are not the client's.
    for path in [
        "/../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/js/../../Cargo.toml",
        "/master.key",
        "/daemon.token",
        "/pkg/package.json",
        "/js/",
    ] {
        let r = http(d.http_port, "GET", path, None, "").await;
        assert!(
            r.starts_with("HTTP/1.1 404") || r.starts_with("HTTP/1.1 401"),
            "{path} must not be served: {r:.200}"
        );
        assert!(!r.contains("[package]"), "{path} leaked a manifest");
    }
    // POST to a client path is not a static hit.
    let r = http(d.http_port, "POST", "/index.html", None, "").await;
    assert!(!r.starts_with("HTTP/1.1 200"), "{r:.200}");

    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_origin_gets_neither_the_client_nor_the_api() {
    let d = start_daemon().await;
    let tok = d.token();

    let r = http_with(
        d.http_port,
        "GET",
        "/index.html",
        None,
        Some("https://evil.example"),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 403"), "{r:.200}");
    let r = http_with(
        d.http_port,
        "GET",
        "/api/status",
        Some(&tok),
        Some("https://evil.example"),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 403"), "{r:.200}");

    // A page on another localhost port (a static server the user runs) is allowed
    // and gets the CORS headers the Authorization header needs.
    let r = http_with(
        d.http_port,
        "OPTIONS",
        "/api/status",
        None,
        Some("http://localhost:8080"),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 204"), "{r:.200}");
    let lower = r.to_ascii_lowercase();
    assert!(lower.contains("access-control-allow-headers: content-type, authorization"));
    let r = http_with(
        d.http_port,
        "GET",
        "/api/status",
        Some(&tok),
        Some("http://localhost:8080"),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.200}");
    assert!(r
        .to_ascii_lowercase()
        .contains("access-control-allow-origin"));

    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_is_never_offered_to_a_caller_that_lacks_it() {
    let d = start_daemon().await;
    let tok = d.token();
    for path in ["/", "/api/ping", "/api/status", "/api/token", "/token"] {
        let r = http(d.http_port, "GET", path, None, "").await;
        assert!(!r.contains(&tok), "{path} exposed the token");
    }
    // A wrong token is refused, and the refusal does not echo any token.
    let wrong = random_secret();
    let r = http(d.http_port, "GET", "/api/status", Some(&wrong), "").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r:.200}");
    assert!(!r.contains(&tok) && !r.contains(&wrong));
    d.stop().await;
}

// ─── Transfers over HTTP ─────────────────────────────────────────────────────

fn body_of(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
}

fn json_of(response: &str) -> serde_json::Value {
    serde_json::from_str(body_of(response)).unwrap_or_else(|e| panic!("not JSON ({e}): {response}"))
}

/// Percent-encode everything but unreserved characters (a send id holds a path).
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_transfer_endpoint_needs_the_token() {
    let d = start_daemon().await;
    let wrong = random_secret();
    let body = r#"{"mid":"miasma:x","output_path":"/x"}"#;
    for (method, path) in [
        ("GET", "/api/transfers"),
        ("GET", "/api/transfers/miasma%3Aabc"),
        ("POST", "/api/transfers/receive"),
        ("POST", "/api/transfers/miasma%3Aabc/cancel"),
        ("POST", "/api/transfers/miasma%3Aabc/remove"),
        ("POST", "/api/transfers/clear-finished"),
    ] {
        let r = http(d.http_port, method, path, None, body).await;
        assert!(r.starts_with("HTTP/1.1 401"), "{method} {path}: {r:.200}");
        let r = http(d.http_port, method, path, Some(&wrong), body).await;
        assert!(r.starts_with("HTTP/1.1 401"), "{method} {path}: {r:.200}");
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn transfer_requests_that_are_wrong_are_refused_clearly_and_start_nothing() {
    let d = start_daemon().await;
    let tok = d.token();
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("never.bin");
    let out = out.to_string_lossy().replace('\\', "\\\\");

    // Nothing yet.
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.200}");
    assert_eq!(json_of(&r), serde_json::json!([]));

    // Unknown transfer: status is 404, cancel is 409 (nothing running to stop).
    let r = http(
        d.http_port,
        "GET",
        "/api/transfers/miasma%3Anope",
        Some(&tok),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r:.200}");
    let r = http(
        d.http_port,
        "POST",
        "/api/transfers/miasma%3Anope/cancel",
        Some(&tok),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 409"), "{r:.200}");
    let r = http(d.http_port, "GET", "/api/transfers/%zz", Some(&tok), "").await;
    assert!(r.starts_with("HTTP/1.1 400"), "{r:.200}");

    // Wrong shapes of route.
    for (method, path) in [
        ("DELETE", "/api/transfers"),
        ("GET", "/api/transfersx"),
        ("GET", "/api/transfers/a/b/c"),
        ("POST", "/api/transfers"),
    ] {
        let r = http(d.http_port, method, path, Some(&tok), "").await;
        assert!(r.starts_with("HTTP/1.1 404"), "{method} {path}: {r:.200}");
    }

    // A receive that the output-path policy or the MID check refuses.
    let bad_bodies = [
        (
            r#"{"mid":"miasma:abc","output_path":"relative/x.bin"}"#.to_string(),
            "output path rejected",
        ),
        (
            format!(r#"{{"mid":"miasma:abc","output_path":"{out}/../x.bin"}}"#),
            "output path rejected",
        ),
        (
            format!(r#"{{"mid":"not-a-mid","output_path":"{out}"}}"#),
            "invalid MID",
        ),
        (r#"{"mid":"miasma:abc"}"#.to_string(), "invalid JSON body"),
        ("not json".to_string(), "invalid JSON body"),
    ];
    for (body, needle) in &bad_bodies {
        let r = http(
            d.http_port,
            "POST",
            "/api/transfers/receive",
            Some(&tok),
            body,
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 400"), "{body}: {r:.300}");
        assert!(r.contains(needle), "{body}: {r:.300}");
    }
    // A password of the wrong type is refused without quoting it back.
    let secret_number = 1_234_567_891u64;
    let body =
        format!(r#"{{"mid":"miasma:abc","output_path":"{out}","password":{secret_number}}}"#);
    let r = http(
        d.http_port,
        "POST",
        "/api/transfers/receive",
        Some(&tok),
        &body,
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 400"), "{r:.300}");
    assert!(
        !r.contains(&secret_number.to_string()),
        "the value was echoed: {r}"
    );

    // Over-long fields.
    let long = "a".repeat(5000);
    let body = format!(r#"{{"mid":"miasma:abc","output_path":"/{long}"}}"#);
    let r = http(
        d.http_port,
        "POST",
        "/api/transfers/receive",
        Some(&tok),
        &body,
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 400"), "{r:.200}");

    // Still nothing started, nothing written.
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    assert_eq!(json_of(&r), serde_json::json!([]));
    assert!(!out_dir.path().join("never.bin").exists());
    d.stop().await;
}

async fn poll_until_not_running(port: u16, tok: &str, id: &str) -> serde_json::Value {
    let path = format!("/api/transfers/{}", enc(id));
    // About what the web client does (once a second): the read limit is 2 a second.
    for _ in 0..120 {
        let r = http(port, "GET", &path, Some(tok), "").await;
        if r.starts_with("HTTP/1.1 429") {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
        let v = json_of(&r);
        if v["state"] != "Running" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    panic!("transfer {id} still running after 90 s");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_protected_transfer_is_received_over_http_and_the_password_never_leaks() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let a = start_daemon_keyed(Some(0x61), None).await;
        let a_tok = a.token();

        // A publishes a password-protected file (drawn at run time, never a literal).
        let password = random_policy_password();
        let wrong_password = random_policy_password();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("payload.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 37 % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();
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

        let b = start_daemon_keyed(Some(0x62), Some(&a.addr)).await;
        let b_tok = b.token();
        tokio::time::sleep(Duration::from_millis(2000)).await;

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let out_json = out.to_string_lossy().replace('\\', "\\\\");
        let mut every_response = String::new();

        let receive = |password: Option<&str>| {
            let pw = match password {
                Some(p) => format!(r#","password":"{p}""#),
                None => String::new(),
            };
            format!(r#"{{"mid":"{mid}","output_path":"{out_json}"{pw}}}"#)
        };

        // Wrong password: the job ends Failed, before any piece is fetched.
        let r = http(
            b.http_port,
            "POST",
            "/api/transfers/receive",
            Some(&b_tok),
            &receive(Some(&wrong_password)),
        )
        .await;
        every_response.push_str(&r);
        assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
        assert_eq!(json_of(&r)["id"], serde_json::json!(mid));
        let s = poll_until_not_running(b.http_port, &b_tok, &mid).await;
        assert_eq!(s["state"], "Failed", "{s}");
        assert!(
            s["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("wrong password"),
            "{s}"
        );
        assert_eq!(s["pieces_fetched"], 0);
        every_response.push_str(&s.to_string());
        assert!(!out.exists());

        // No password: a distinct message.
        let r = http(
            b.http_port,
            "POST",
            "/api/transfers/receive",
            Some(&b_tok),
            &receive(None),
        )
        .await;
        every_response.push_str(&r);
        let s = poll_until_not_running(b.http_port, &b_tok, &mid).await;
        assert_eq!(s["state"], "Failed", "{s}");
        assert!(
            s["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("password-protected"),
            "{s}"
        );

        // Right password: the same request again is the resume.
        let r = http(
            b.http_port,
            "POST",
            "/api/transfers/receive",
            Some(&b_tok),
            &receive(Some(&password)),
        )
        .await;
        every_response.push_str(&r);
        assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
        let s = poll_until_not_running(b.http_port, &b_tok, &mid).await;
        every_response.push_str(&s.to_string());
        assert_eq!(s["state"], "Complete", "{s}");
        assert_eq!(s["kind"], "Receive");
        assert_eq!(s["id"], serde_json::json!(mid));
        assert_eq!(s["bytes_done"], data.len());
        assert_eq!(s["bytes_total"], data.len());
        assert_eq!(std::fs::read(&out).unwrap(), data);

        // The list has it, with its id; a finished transfer cannot be cancelled.
        let r = http(b.http_port, "GET", "/api/transfers", Some(&b_tok), "").await;
        every_response.push_str(&r);
        let list = json_of(&r);
        let entry = list
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == serde_json::json!(mid))
            .expect("the receive is listed");
        assert_eq!(entry["state"], "Complete");
        let r = http(
            b.http_port,
            "POST",
            &format!("/api/transfers/{}/cancel", enc(&mid)),
            Some(&b_tok),
            "",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 409"), "{r:.200}");

        // A's own send is listed with a `send:<path>` id that survives percent-encoding.
        let r = http(a.http_port, "GET", "/api/transfers", Some(&a_tok), "").await;
        let sends: Vec<_> = json_of(&r)
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["kind"] == "Send")
            .cloned()
            .collect();
        if let Some(send) = sends.first() {
            let id = send["id"].as_str().unwrap().to_owned();
            assert!(id.starts_with("send:"), "{id}");
            let r = http(
                a.http_port,
                "GET",
                &format!("/api/transfers/{}", enc(&id)),
                Some(&a_tok),
                "",
            )
            .await;
            assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
            assert_eq!(json_of(&r)["id"], serde_json::json!(id));
        }

        // The password is in no response and in no log line.
        let logged = captured_logs();
        for secret in [&password, &wrong_password] {
            assert!(
                !every_response.contains(secret.as_str()),
                "a response contains a password"
            );
            assert!(
                !logged.contains(secret.as_str()),
                "a log line contains a password"
            );
        }
        assert!(
            !logged.is_empty(),
            "the log capture saw nothing: the check above proves nothing"
        );

        let _ = a.shutdown.send(()).await;
        let _ = b.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_receive_can_be_stopped_over_http() {
    tokio::time::timeout(Duration::from_secs(120), async {
        // A knows the file; C is not connected to A, so its receive cannot finish.
        let a = start_daemon_keyed(Some(0x63), None).await;
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("payload.bin");
        std::fs::write(&src, vec![7u8; 200_000]).unwrap();
        let mid = match daemon_request(
            a.dir.path(),
            ControlRequest::PublishFile {
                file_path: src.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::Published { mid } => mid,
            other => panic!("unexpected: {other:?}"),
        };
        let c = start_daemon_keyed(Some(0x64), None).await;
        let tok = c.token();
        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir
            .path()
            .join("got.bin")
            .to_string_lossy()
            .replace('\\', "\\\\");
        let body = format!(r#"{{"mid":"{mid}","output_path":"{out}"}}"#);

        let r = http(
            c.http_port,
            "POST",
            "/api/transfers/receive",
            Some(&tok),
            &body,
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
        let cancel_path = format!("/api/transfers/{}/cancel", enc(&mid));
        let r = http(c.http_port, "POST", &cancel_path, Some(&tok), "").await;
        // Either it was still running and is now stopping, or it had already ended
        // (nothing to fetch from): never anything else.
        assert!(
            r.starts_with("HTTP/1.1 200") || r.starts_with("HTTP/1.1 409"),
            "{r:.300}"
        );
        let s = poll_until_not_running(c.http_port, &tok, &mid).await;
        assert_ne!(s["state"], "Running");
        assert_ne!(s["state"], "Complete", "it cannot have completed: {s}");

        let _ = a.shutdown.send(()).await;
        let _ = c.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_via_receive_is_passed_through_and_a_bad_via_is_refused_clearly() {
    let d = start_daemon().await;
    let tok = d.token();
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir
        .path()
        .join("via.bin")
        .to_string_lossy()
        .replace('\\', "\\\\");
    let mid = "miasma:abc";

    // Refused before anything starts, without echoing credentials.
    let too_many: Vec<String> = (0..9).map(|i| format!("wss://h{i}.example.com")).collect();
    let bad_vias = [
        serde_json::json!(["https://example.com"]),
        serde_json::json!(["wss://user:hunter2@example.com"]),
        serde_json::json!(["not a url"]),
        serde_json::json!(too_many),
        serde_json::json!("wss://not-a-list.example.com"),
    ];
    for via in &bad_vias {
        let body = format!(r#"{{"mid":"{mid}","output_path":"{out}","via":{via}}}"#);
        let r = http(
            d.http_port,
            "POST",
            "/api/transfers/receive",
            Some(&tok),
            &body,
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 400"), "{via}: {r:.300}");
        assert!(!r.contains("hunter2"), "credentials echoed: {r:.300}");
    }
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    assert_eq!(
        json_of(&r),
        serde_json::json!([]),
        "nothing may have started"
    );

    // A good `via` reaches the daemon and is used: the job fails on the endpoint
    // (nothing listens on port 1), not by looking the record up in the DHT.
    let mid = miasma_core::ContentId::compute(b"via test", b"params").to_string();
    let body = format!(r#"{{"mid":"{mid}","output_path":"{out}","via":["ws://127.0.0.1:1"]}}"#);
    let r = http(
        d.http_port,
        "POST",
        "/api/transfers/receive",
        Some(&tok),
        &body,
    )
    .await;
    if r.starts_with("HTTP/1.1 200") {
        let id = json_of(&r)["id"].as_str().unwrap().to_owned();
        let s = poll_until_not_running(d.http_port, &tok, &id).await;
        assert_eq!(s["state"], "Failed", "{s}");
        assert!(
            s["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("cannot reach"),
            "{s}"
        );
    } else {
        panic!("expected the request to be accepted: {r:.300}");
    }
    assert!(!out_dir.path().join("via.bin").exists());
    d.stop().await;
}

// ─── Removing finished transfers over HTTP ───────────────────────────────────

/// Put a receive job in `state` into the daemon's registry; returns its id.
fn inject_job(
    d: &TestDaemon,
    tag: &str,
    state: miasma_core::transfer::TransferState,
    resumable: bool,
) -> String {
    let id = miasma_core::ContentId::compute(tag.as_bytes(), b"p").to_string();
    let p = miasma_core::transfer::TransferProgress::new(id.clone());
    p.set_name(d.dir.path().join(format!("{tag}.bin")).to_string_lossy());
    if state != miasma_core::transfer::TransferState::Running {
        p.set_state(state, None, resumable);
    }
    miasma_core::transfer::jobs::registry_for(d.dir.path()).insert_for_tests(&id, p);
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_finished_transfer_is_removed_over_http_and_a_running_one_is_refused() {
    use miasma_core::transfer::TransferState as S;
    let d = start_daemon().await;
    let tok = d.token();
    let done = inject_job(&d, "http-done", S::Complete, false);
    let running = inject_job(&d, "http-running", S::Running, false);
    let paused = inject_job(&d, "http-paused", S::Paused, true);
    let partial = inject_job(&d, "http-partial", S::Cancelled, true);
    // Cancelled with a journal on disk: needs discard_partial.
    let reg = miasma_core::transfer::jobs::registry_for(d.dir.path());
    std::fs::create_dir_all(reg.journal_dir()).unwrap();
    let out = d.dir.path().join("http-partial.bin");
    let mid = miasma_core::ContentId::compute(b"http-partial", b"p");
    miasma_core::transfer::journal::ReceiveJournal {
        version: miasma_core::transfer::journal::JOURNAL_VERSION,
        mid: mid.to_string(),
        output_path: out.to_string_lossy().into_owned(),
        part_path: miasma_core::transfer::journal::part_path_for(&out)
            .to_string_lossy()
            .into_owned(),
        data_shards: 2,
        total_shards: 3,
        segment_count: 2,
        total_bytes: 2000,
        manifest_hash: None,
        next_segment: 1,
        bytes_done: 1000,
        started_at: 1,
        updated_at: 2,
        last_error: None,
        share_id: None,
    }
    .save(&miasma_core::transfer::journal::journal_path(
        &reg.journal_dir(),
        &mid,
    ))
    .unwrap();

    let url = |id: &str| format!("/api/transfers/{}/remove", enc(id));

    // Refusals: 409, and the job is still listed.
    for id in [&running, &paused, &partial] {
        let r = http(d.http_port, "POST", &url(id), Some(&tok), "").await;
        assert!(r.starts_with("HTTP/1.1 409"), "{id}: {r:.300}");
    }
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    assert_eq!(json_of(&r).as_array().unwrap().len(), 4, "{r}");

    // An unknown id is a 404, and a malformed body a 400.
    let r = http(d.http_port, "POST", &url("miasma:nope"), Some(&tok), "").await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r:.300}");
    let r = http(d.http_port, "POST", &url(&done), Some(&tok), "{nope").await;
    assert!(r.starts_with("HTTP/1.1 400"), "{r:.300}");

    // The finished one goes, and stays gone on the next poll.
    let r = http(d.http_port, "POST", &url(&done), Some(&tok), "").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
    assert_eq!(json_of(&r)["removed"], 1);
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    let list = json_of(&r);
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t["id"] != done.as_str()));
    let r = http(d.http_port, "POST", &url(&done), Some(&tok), "").await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r:.300}");

    // Discarding the cancelled one is explicit.
    let r = http(
        d.http_port,
        "POST",
        &url(&partial),
        Some(&tok),
        r#"{"discard_partial":true}"#,
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
    assert!(!miasma_core::transfer::journal::journal_path(&reg.journal_dir(), &mid).exists());

    // Clear-finished with nothing finished left removes nothing.
    let r = http(
        d.http_port,
        "POST",
        "/api/transfers/clear-finished",
        Some(&tok),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
    assert_eq!(json_of(&r)["removed"], 0);
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    assert_eq!(json_of(&r).as_array().unwrap().len(), 2, "{r}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_finished_over_http_removes_finished_rows_only() {
    use miasma_core::transfer::TransferState as S;
    let d = start_daemon().await;
    let tok = d.token();
    let a = inject_job(&d, "clr-done", S::Complete, false);
    let b = inject_job(&d, "clr-failed", S::Failed, false);
    let keep = inject_job(&d, "clr-running", S::Running, false);
    let r = http(
        d.http_port,
        "POST",
        "/api/transfers/clear-finished",
        Some(&tok),
        "",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.300}");
    assert_eq!(json_of(&r)["removed"], 2);
    let r = http(d.http_port, "GET", "/api/transfers", Some(&tok), "").await;
    let ids: Vec<String> = json_of(&r)
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec![keep]);
    assert!(!ids.contains(&a) && !ids.contains(&b));
    d.stop().await;
}
