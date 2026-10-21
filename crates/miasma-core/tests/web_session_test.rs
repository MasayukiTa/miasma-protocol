//! Signed browser sessions on the HTTP bridge, over a real daemon and a real
//! listener.  The signing client below stands in for a page: every key is made
//! at run time and no test carries a literal key, token or password.
//!
//! The last tests exchange signed vectors with the browser-side signer:
//!
//! * `writes_signed_vectors_for_the_browser_side` signs a set of requests with
//!   a fresh key and writes them as JSON (path printed, or set
//!   `MIASMA_WS_VECTORS_OUT`), so the browser side can verify Rust's strings
//!   and signatures.
//! * `verifies_vectors_signed_by_the_browser_side` (ignored by default) reads
//!   the JSON the browser-side node test wrote, from `MIASMA_WS_VECTORS`, and
//!   checks every canonical string and signature with the daemon's verifier.
//!   Run the node test first, then:
//!   `MIASMA_WS_VECTORS=<file> cargo test --package miasma-core --test
//!   web_session_test -- --ignored verifies_vectors_signed_by_the_browser_side`
//!
//! Vector file format (`version` 1), all binary values base64url without padding:
//!
//! ```text
//! { "version": 1, "vectors": [
//!   { "kind": "register", "origin": "...", "boot": "...", "public_key": "<65 bytes>",
//!     "ts": 1800000000000, "signature": "<64 bytes>", "canonical": "<optional>" },
//!   { "kind": "request", "origin": "...", "sid": "...", "ts": 1800000000000,
//!     "nonce": "<16 bytes>", "method": "POST", "path": "/api/x?y=1",
//!     "body_b64": "...", "public_key": "<65 bytes>", "signature": "<64 bytes>",
//!     "canonical": "<optional>" } ] }
//! ```

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64U},
    Engine,
};
use miasma_core::daemon::{
    control_auth,
    ipc::{daemon_request, ControlRequest, ControlResponse},
    web_session::{canonical_request, register_message, verify_signature},
    DaemonServer,
};
use miasma_core::network::types::NodeType;
use miasma_core::{network::node::MiasmaNode, LocalShareStore};
use rand::{rngs::OsRng, Rng};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

// ─── Harness ─────────────────────────────────────────────────────────────────

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
    shutdown: tokio::sync::mpsc::Sender<()>,
    run: JoinHandle<anyhow::Result<()>>,
}

async fn start_daemon() -> TestDaemon {
    let _ = logs();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let master: [u8; 32] = std::fs::read(dir.path().join("master.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let node = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.path().to_owned())
        .await
        .unwrap();
    let http_port = server.http_bridge_port();
    let shutdown = server.shutdown_handle();
    let run = tokio::spawn(server.run());
    TestDaemon {
        dir,
        http_port,
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

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    async fn stop(self) {
        let _ = self.shutdown.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.run).await;
    }

    /// A one-time bootstrap value over the authenticated IPC.
    async fn boot(&self) -> String {
        self.boot_for(&self.origin(), &[]).await.expect("issued")
    }

    async fn boot_for(&self, origin: &str, scopes: &[&str]) -> Result<String, String> {
        match daemon_request(
            self.dir.path(),
            ControlRequest::WebBootstrap {
                origin: origin.to_owned(),
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::WebBootstrapIssued { boot, expires_in_s } => {
                assert_eq!(expires_in_s, 60);
                Ok(boot)
            }
            ControlResponse::Error(e) => Err(e),
            other => panic!("unexpected {other:?}"),
        }
    }

    async fn register_with(&self, boot: &str, client: &Keys) -> Resp {
        let ts = now_ms();
        let body = client.register_body(&self.origin(), boot, ts);
        raw(
            self.http_port,
            "POST",
            "/api/session/register",
            &[("Origin", self.origin())],
            body.as_bytes(),
        )
        .await
    }

    /// A registered browser.
    async fn browser(&self) -> Browser {
        let boot = self.boot().await;
        let keys = Keys::new();
        let r = self.register_with(&boot, &keys).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let v = r.json();
        Browser {
            keys,
            sid: v["sid"].as_str().unwrap().to_owned(),
            origin: self.origin(),
            port: self.http_port,
        }
    }
}

struct Resp {
    status: u16,
    head: String,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or("").to_owned()
    }
}

/// One raw HTTP/1.1 exchange.
async fn raw(port: u16, method: &str, path: &str, headers: &[(&str, String)], body: &[u8]) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    s.write_all(&bytes).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Resp {
        status,
        head: head.to_ascii_lowercase(),
        body: body.to_owned(),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// A key pair made at run time.
struct Keys {
    kp: EcdsaKeyPair,
    rng: SystemRandom,
}

impl Keys {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self { kp, rng }
    }

    fn public(&self) -> String {
        B64U.encode(self.kp.public_key().as_ref())
    }

    fn sign(&self, message: &str) -> [u8; 64] {
        self.kp
            .sign(&self.rng, message.as_bytes())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap()
    }

    fn register_body(&self, origin: &str, boot: &str, ts: i64) -> String {
        let public = self.public();
        let pop = B64U.encode(self.sign(&register_message(origin, boot, &public, ts)));
        json!({ "v": 1, "boot": boot, "pub": public, "ts": ts, "pop": pop }).to_string()
    }
}

struct Browser {
    keys: Keys,
    sid: String,
    origin: String,
    port: u16,
}

impl Browser {
    /// The `Authorization` value for a request; `signed_*` are what the
    /// signature covers, so a test can send something else.
    fn auth(
        &self,
        signed_method: &str,
        signed_pq: &str,
        signed_body: &[u8],
        ts: i64,
        nonce: [u8; 16],
    ) -> String {
        let n = B64U.encode(nonce);
        let canon = canonical_request(
            signed_method,
            signed_pq,
            &self.origin,
            &self.sid,
            ts,
            &n,
            signed_body,
        );
        format!(
            "MiasmaSig v=1, sid={}, ts={ts}, n={n}, sig={}",
            self.sid,
            B64U.encode(self.keys.sign(&canon))
        )
    }

    /// A correctly signed request with a fresh time and nonce.
    async fn call(&self, method: &str, pq: &str, body: &[u8]) -> Resp {
        let nonce: [u8; 16] = OsRng.gen();
        let a = self.auth(method, pq, body, now_ms(), nonce);
        self.send(method, pq, body, a).await
    }

    async fn send(&self, method: &str, pq: &str, body: &[u8], auth: String) -> Resp {
        raw(
            self.port,
            method,
            pq,
            &[("Authorization", auth), ("Origin", self.origin.clone())],
            body,
        )
        .await
    }
}

// ─── Ping, Bearer ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ping_advertises_the_session_scheme_and_bearer_keeps_working() {
    let d = start_daemon().await;
    let tok = d.token();

    let r = raw(d.http_port, "GET", "/api/ping", &[], b"").await;
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["ok"], true);
    assert_eq!(v["web_auth"], json!(["bearer", "sig-v1"]));

    // A native client (no Origin, no fetch metadata): unchanged, no notice.
    let bearer = |extra: &[(&'static str, String)]| -> Vec<(&'static str, String)> {
        let mut h = vec![("Authorization", format!("Bearer {tok}"))];
        h.extend(extra.iter().cloned());
        h
    };
    let r = raw(d.http_port, "GET", "/api/status", &bearer(&[]), b"").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(!r.head.contains("deprecation"), "{}", r.head);

    // A browser page still using the token: served, marked, and counted.
    let counter = || async {
        match daemon_request(d.dir.path(), ControlRequest::WebSessionList)
            .await
            .unwrap()
        {
            ControlResponse::WebSessions {
                browser_bearer_requests,
                ..
            } => browser_bearer_requests,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(counter().await, 0);
    for i in 1..=3u64 {
        let r = raw(
            d.http_port,
            "GET",
            "/api/status",
            &bearer(&[("Origin", d.origin())]),
            b"",
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.head.contains("deprecation: true"), "{}", r.head);
        assert_eq!(counter().await, i);
    }
    // Fetch metadata alone also marks a browser.
    let r = raw(
        d.http_port,
        "GET",
        "/api/status",
        &bearer(&[("Sec-Fetch-Site", "same-origin".to_owned())]),
        b"",
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.head.contains("deprecation: true"));
    assert_eq!(counter().await, 4);

    // The native request did not count; a wrong token still fails and does not count.
    let wrong: [u8; 16] = OsRng.gen();
    let r = raw(
        d.http_port,
        "GET",
        "/api/status",
        &[
            ("Authorization", format!("Bearer {}", hex::encode(wrong))),
            ("Origin", d.origin()),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(counter().await, 4);

    // No credential at all.
    let r = raw(d.http_port, "GET", "/api/status", &[], b"").await;
    assert_eq!(r.status, 401);
    assert_eq!(r.code(), "session_required");

    d.stop().await;
}

// ─── Registration ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn registration_succeeds_and_the_session_works() {
    let d = start_daemon().await;
    let boot = d.boot().await;
    let keys = Keys::new();
    let r = d.register_with(&boot, &keys).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["v"], 1);
    assert_eq!(v["alg"], "ES256");
    assert_eq!(v["scopes"], json!(["status", "transfer", "directed"]));
    assert_eq!(v["idle_timeout_s"], 900);
    assert_eq!(v["expires_in_s"], 43_200);
    assert!((v["server_time_ms"].as_i64().unwrap() - now_ms()).abs() < 5_000);
    let sid = v["sid"].as_str().unwrap().to_owned();
    assert_eq!(B64U.decode(&sid).unwrap().len(), 16);

    let b = Browser {
        keys,
        sid,
        origin: d.origin(),
        port: d.http_port,
    };
    let r = b.call("GET", "/api/status", b"").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = b.call("GET", "/api/session", b"").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["scopes"], json!(["status", "transfer", "directed"]));
    assert!(v["idle_expires_in_s"].as_u64().unwrap() <= 900);

    // Signed requests do not use the token, and the listing shows no key material.
    match daemon_request(d.dir.path(), ControlRequest::WebSessionList)
        .await
        .unwrap()
    {
        ControlResponse::WebSessions {
            sessions,
            browser_bearer_requests,
        } => {
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].origin, d.origin());
            assert_eq!(sessions[0].sid_prefix, b.sid[..4]);
            assert_eq!(browser_bearer_requests, 0);
        }
        other => panic!("unexpected {other:?}"),
    }

    // Ending the session ends it.
    let r = b.call("POST", "/api/session/end", b"").await;
    assert_eq!(r.status, 200);
    let r = b.call("GET", "/api/status", b"").await;
    assert_eq!((r.status, r.code().as_str()), (401, "session_unknown"));

    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_refusals() {
    let d = start_daemon().await;
    let origin = d.origin();
    let ok_headers = || vec![("Origin", origin.clone())];

    // Wrong proof of possession: signed by another key.
    let boot = d.boot().await;
    let keys = Keys::new();
    let thief = Keys::new();
    let ts = now_ms();
    let forged = json!({
        "v": 1, "boot": boot, "pub": keys.public(), "ts": ts,
        "pop": B64U.encode(thief.sign(&register_message(&origin, &boot, &keys.public(), ts)))
    })
    .to_string();
    let r = raw(
        d.http_port,
        "POST",
        "/api/session/register",
        &ok_headers(),
        forged.as_bytes(),
    )
    .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (401, "bad_signature"),
        "{}",
        r.body
    );
    // The value was not used up: the right key still gets in.
    let r = d.register_with(&boot, &keys).await;
    assert_eq!(r.status, 200, "{}", r.body);

    // Replaying the value (a different key, same boot) ends the session it made.
    let honest = {
        let v = r.json();
        Browser {
            keys,
            sid: v["sid"].as_str().unwrap().to_owned(),
            origin: origin.clone(),
            port: d.http_port,
        }
    };
    assert_eq!(honest.call("GET", "/api/status", b"").await.status, 200);
    let attacker = Keys::new();
    let r = d.register_with(&boot, &attacker).await;
    assert_eq!((r.status, r.code().as_str()), (401, "boot_already_used"));
    let r = honest.call("GET", "/api/status", b"").await;
    assert_eq!((r.status, r.code().as_str()), (401, "session_unknown"));

    // An unknown value.
    let unknown: [u8; 32] = OsRng.gen();
    let r = d.register_with(&B64U.encode(unknown), &Keys::new()).await;
    assert_eq!((r.status, r.code().as_str()), (401, "boot_invalid"));

    // No Origin header (not a page), and a different page address.
    let boot = d.boot().await;
    let keys = Keys::new();
    let body = keys.register_body(&origin, &boot, now_ms());
    let r = raw(
        d.http_port,
        "POST",
        "/api/session/register",
        &[],
        body.as_bytes(),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (403, "origin_required"));
    let r = raw(
        d.http_port,
        "POST",
        "/api/session/register",
        &[("Origin", "http://localhost:9".to_owned())],
        body.as_bytes(),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (403, "origin_mismatch"));

    // A stale proof time carries the server time.
    let body = keys.register_body(&origin, &boot, now_ms() - 61_000);
    let r = raw(
        d.http_port,
        "POST",
        "/api/session/register",
        &ok_headers(),
        body.as_bytes(),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (401, "stale_timestamp"));
    assert!(r.json()["server_time_ms"].as_i64().is_some());

    // Bodies that are not registrations.
    for junk in ["", "{}", "not json", r#"{"v":2}"#] {
        let r = raw(
            d.http_port,
            "POST",
            "/api/session/register",
            &ok_headers(),
            junk.as_bytes(),
        )
        .await;
        assert_eq!(r.status, 400, "{junk}: {}", r.body);
    }
    let big = vec![b' '; 2048];
    let r = raw(
        d.http_port,
        "POST",
        "/api/session/register",
        &ok_headers(),
        &big,
    )
    .await;
    assert_eq!(r.status, 400);

    // The IPC refuses what a session may never hold, and a bad origin.
    assert!(d
        .boot_for(&origin, &["destructive"])
        .await
        .unwrap_err()
        .contains("destructive"));
    assert!(d.boot_for("https://evil.example", &[]).await.is_err());

    // Only a caller holding the control token can ask for a value.
    let wrong: [u8; 16] = OsRng.gen();
    let port: u16 = std::fs::read_to_string(d.dir.path().join(miasma_core::daemon::ipc::PORT_FILE))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    for frame in [
        json!({ "token": hex::encode(wrong) }).to_string(),
        json!({ "WebBootstrap": { "origin": origin, "scopes": [] } }).to_string(),
    ] {
        let _ = s.write_all(&(frame.len() as u32).to_le_bytes()).await;
        let _ = s.write_all(frame.as_bytes()).await;
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("unauthorized"), "{text}");
    assert!(!text.contains("WebBootstrapIssued"), "{text}");

    d.stop().await;
}

// ─── Signed requests ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn signatures_are_bound_to_method_path_body_and_time() {
    let d = start_daemon().await;
    let b = d.browser().await;
    let n = || -> [u8; 16] { OsRng.gen() };

    // Accepted, including a query string with percent-encoding.
    let r = b.call("GET", "/api/status", b"").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = b
        .call("GET", "/api/status?a=%2Fb%20c&d=%E3%81%82", b"")
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = br#"{"discard_partial":false}"#;
    let r = b.call("POST", "/api/transfers/none/remove", body).await;
    assert_eq!(
        r.status, 404,
        "signature passed, transfer unknown: {}",
        r.body
    );

    // One flipped bit in the signature.
    let a = b.auth("GET", "/api/status", b"", now_ms(), n());
    let (head, sig) = a.rsplit_once("sig=").unwrap();
    let mut raw_sig = B64U.decode(sig).unwrap();
    raw_sig[7] ^= 1;
    let flipped = format!("{head}sig={}", B64U.encode(raw_sig));
    let r = b.send("GET", "/api/status", b"", flipped).await;
    assert_eq!((r.status, r.code().as_str()), (401, "bad_signature"));

    // Tampered body, path, method.
    let a = b.auth("POST", "/api/transfers/none/remove", body, now_ms(), n());
    let r = b
        .send(
            "POST",
            "/api/transfers/none/remove",
            br#"{"discard_partial":true}"#,
            a,
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (401, "bad_signature"));
    let a = b.auth("GET", "/api/status", b"", now_ms(), n());
    let r = b.send("GET", "/api/sharing-key", b"", a).await;
    assert_eq!((r.status, r.code().as_str()), (401, "bad_signature"));
    let a = b.auth("GET", "/api/status?a=1", b"", now_ms(), n());
    let r = b.send("GET", "/api/status?a=2", b"", a).await;
    assert_eq!((r.status, r.code().as_str()), (401, "bad_signature"));
    let a = b.auth("GET", "/api/transfers", b"", now_ms(), n());
    let r = b
        .send("POST", "/api/transfers/clear-finished", b"", a)
        .await;
    assert_eq!((r.status, r.code().as_str()), (401, "bad_signature"));

    // Another key under this session id.
    let other = Browser {
        keys: Keys::new(),
        sid: b.sid.clone(),
        origin: b.origin.clone(),
        port: b.port,
    };
    let r = other.call("GET", "/api/status", b"").await;
    assert_eq!((r.status, r.code().as_str()), (401, "bad_signature"));
    // An unknown session id.
    let ghost = Browser {
        keys: Keys::new(),
        sid: B64U.encode(OsRng.gen::<[u8; 16]>()),
        origin: b.origin.clone(),
        port: b.port,
    };
    let r = ghost.call("GET", "/api/status", b"").await;
    assert_eq!((r.status, r.code().as_str()), (401, "session_unknown"));

    // Time: too old, too new (each carries the server time); inside the window is fine.
    for (offset, ok) in [
        (-59_000, true),
        (9_000, true),
        (-61_000, false),
        (11_000, false),
    ] {
        let a = b.auth("GET", "/api/status", b"", now_ms() + offset, n());
        let r = b.send("GET", "/api/status", b"", a).await;
        if ok {
            assert_eq!(r.status, 200, "offset {offset}: {}", r.body);
        } else {
            assert_eq!(
                (r.status, r.code().as_str()),
                (401, "stale_timestamp"),
                "{offset}"
            );
            assert!((r.json()["server_time_ms"].as_i64().unwrap() - now_ms()).abs() < 5_000);
        }
    }

    // A nonce can be used once.
    let nonce = n();
    let a = b.auth("GET", "/api/status", b"", now_ms(), nonce);
    assert_eq!(
        b.send("GET", "/api/status", b"", a.clone()).await.status,
        200
    );
    let r = b.send("GET", "/api/status", b"", a).await;
    assert_eq!((r.status, r.code().as_str()), (401, "replayed_nonce"));

    // An Origin that is not the session's.
    let a = b.auth("GET", "/api/status", b"", now_ms(), n());
    let r = raw(
        d.http_port,
        "GET",
        "/api/status",
        &[
            ("Authorization", a),
            ("Origin", "http://localhost:9".to_owned()),
        ],
        b"",
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (403, "origin_mismatch"));

    // A same-origin GET carries no Origin header: the registered origin is signed.
    let a = b.auth("GET", "/api/status", b"", now_ms(), n());
    let r = raw(
        d.http_port,
        "GET",
        "/api/status",
        &[
            ("Authorization", a),
            ("Sec-Fetch-Site", "same-origin".to_owned()),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);

    // Malformed headers.
    for bad in [
        "MiasmaSig".to_owned(),
        "MiasmaSig v=1".to_owned(),
        format!("MiasmaSig v=2, sid={}, ts=1, n=AA, sig=AA", b.sid),
        format!("MiasmaSig v=1, sid={}, ts=x, n=AA, sig=AA", b.sid),
    ] {
        let r = b.send("GET", "/api/status", b"", bad).await;
        assert_eq!((r.status, r.code().as_str()), (401, "bad_auth_header"));
    }

    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_nonce_table_is_bounded_and_answers_429_when_full() {
    let d = start_daemon().await;
    let b = d.browser().await;
    // `GET /api/session` is answered without touching the daemon; the read
    // rate limit answers some of these 429 (plain "rate limited"), but a nonce
    // is recorded as soon as the signature verifies.
    for i in 0..1024 {
        let r = b.call("GET", "/api/session", b"").await;
        assert!(
            r.status == 200 || r.status == 429,
            "request {i}: {} {}",
            r.status,
            r.body
        );
    }
    let r = b.call("GET", "/api/session", b"").await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (429, "nonce_cache_full"),
        "{}",
        r.body
    );
    // Nothing is forgotten to make room: a replay is still a replay, and a
    // second session is unaffected.
    let other = d.browser().await;
    let r = other.call("GET", "/api/session", b"").await;
    assert!(r.status == 200 || r.status == 429);
    assert_ne!(r.code(), "nonce_cache_full");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_sessions_are_refused_without_dropping_an_open_one() {
    let d = start_daemon().await;
    let first = d.browser().await;
    for _ in 0..7 {
        d.browser().await;
    }
    let boot = d.boot().await;
    let r = d.register_with(&boot, &Keys::new()).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (429, "too_many_sessions"),
        "{}",
        r.body
    );
    assert_eq!(first.call("GET", "/api/session", b"").await.status, 200);

    // Revoking over the IPC frees a place and ends the revoked session.
    match daemon_request(
        d.dir.path(),
        ControlRequest::WebSessionRevoke {
            sid_prefix: Some(first.sid[..4].to_owned()),
        },
    )
    .await
    .unwrap()
    {
        ControlResponse::WebSessionsRevoked { count } => assert!(count >= 1),
        other => panic!("unexpected {other:?}"),
    }
    let r = first.call("GET", "/api/session", b"").await;
    assert_eq!((r.status, r.code().as_str()), (401, "session_unknown"));
    let r = d.register_with(&boot, &Keys::new()).await;
    assert_eq!(r.status, 200, "{}", r.body);

    d.stop().await;
}

// ─── Scopes ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_session_cannot_reach_destructive_raw_path_or_ca_features() {
    let d = start_daemon().await;
    let b = d.browser().await;

    // Destructive: refused before the body is read, and the daemon is still up.
    let r = b.call("POST", "/api/wipe", b"").await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (403, "scope_required"),
        "{}",
        r.body
    );
    assert_eq!(r.json()["needed"], "destructive");
    assert_eq!(b.call("GET", "/api/status", b"").await.status, 200);

    // The raw host-path endpoints, from a page (Origin present) and from a
    // signed request without any browser header.
    for path in [
        "/api/publish-file",
        "/api/retrieve-to-file",
        "/api/directed/send-file",
        "/api/directed/retrieve-to-file",
    ] {
        let r = b.call("POST", path, b"{}").await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (403, "host_path_not_allowed_from_browser"),
            "{path}"
        );
        let a = b.auth("POST", path, b"{}", now_ms(), OsRng.gen());
        let r = raw(d.http_port, "POST", path, &[("Authorization", a)], b"{}").await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (403, "host_path_not_allowed_from_browser"),
            "{path} without an Origin"
        );
    }

    // A route no scope covers.
    let r = b.call("GET", "/api/not-a-route", b"").await;
    assert_eq!((r.status, r.code().as_str()), (403, "scope_required"));

    // `via_ca_pem` is refused; `via` and an empty value are not.
    let mid = "0".repeat(10);
    let with_ca =
        json!({ "mid": mid, "output_path": "/x/y", "via_ca_pem": "pem text" }).to_string();
    let r = b
        .call("POST", "/api/transfers/receive", with_ca.as_bytes())
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (400, "field_not_allowed_for_session"),
        "{}",
        r.body
    );
    let with_null = json!({ "mid": mid, "output_path": "/x/y", "via_ca_pem": null }).to_string();
    let r = b
        .call("POST", "/api/transfers/receive", with_null.as_bytes())
        .await;
    assert_ne!(r.code(), "field_not_allowed_for_session", "{}", r.body);

    // The native Bearer path to the same endpoints is untouched.
    let r = raw(
        d.http_port,
        "POST",
        "/api/retrieve-to-file",
        &[("Authorization", format!("Bearer {}", d.token()))],
        b"{}",
    )
    .await;
    assert_ne!(r.code(), "host_path_not_allowed_from_browser");
    assert_ne!(r.status, 401);

    // A narrower session is held to its scopes.
    let boot = d.boot_for(&d.origin(), &["status"]).await.unwrap();
    let keys = Keys::new();
    let reg = d.register_with(&boot, &keys).await;
    assert_eq!(reg.status, 200);
    assert_eq!(reg.json()["scopes"], json!(["status"]));
    let narrow = Browser {
        keys,
        sid: reg.json()["sid"].as_str().unwrap().to_owned(),
        origin: d.origin(),
        port: d.http_port,
    };
    assert_eq!(narrow.call("GET", "/api/status", b"").await.status, 200);
    let r = narrow.call("POST", "/api/publish", b"{}").await;
    assert_eq!((r.status, r.code().as_str()), (403, "scope_required"));
    assert_eq!(r.json()["needed"], "transfer");
    let r = narrow.call("GET", "/api/directed/inbox", b"").await;
    assert_eq!((r.status, r.code().as_str()), (403, "scope_required"));

    d.stop().await;
}

// ─── Logs ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_values_session_ids_and_signatures_stay_out_of_the_logs() {
    let d = start_daemon().await;
    let boot = d.boot().await;
    let keys = Keys::new();
    let r = d.register_with(&boot, &keys).await;
    assert_eq!(r.status, 200);
    let sid = r.json()["sid"].as_str().unwrap().to_owned();
    let b = Browser {
        keys,
        sid: sid.clone(),
        origin: d.origin(),
        port: d.http_port,
    };
    let n: [u8; 16] = OsRng.gen();
    let a = b.auth("GET", "/api/status", b"", now_ms(), n);
    let sig = a.rsplit_once("sig=").unwrap().1.to_owned();
    assert_eq!(
        b.send("GET", "/api/status", b"", a.clone()).await.status,
        200
    );
    // Exercise the failure and replay paths, which log the most.
    let _ = b.send("GET", "/api/status", b"", a).await;
    let _ = d.register_with(&boot, &Keys::new()).await;
    // And a page that still sends the token.
    let tok = d.token();
    let _ = raw(
        d.http_port,
        "GET",
        "/api/status",
        &[
            ("Authorization", format!("Bearer {tok}")),
            ("Origin", d.origin()),
        ],
        b"",
    )
    .await;

    let logs = captured_logs();
    assert!(!logs.contains(&boot), "boot value in the logs");
    assert!(!logs.contains(&sid), "full session id in the logs");
    assert!(!logs.contains(&sig), "signature in the logs");
    assert!(!logs.contains(&B64U.encode(n)), "request nonce in the logs");
    assert!(!logs.contains(&tok), "control token in the logs");
    d.stop().await;
}

// ─── Vectors shared with the browser-side signer ─────────────────────────────

#[test]
fn writes_signed_vectors_for_the_browser_side() {
    let keys = Keys::new();
    let origin = "http://127.0.0.1:17842";
    let sid = B64U.encode(OsRng.gen::<[u8; 16]>());
    let ts = now_ms();
    let mut vectors = Vec::new();

    let boot = B64U.encode(OsRng.gen::<[u8; 32]>());
    let canon = register_message(origin, &boot, &keys.public(), ts);
    vectors.push(json!({
        "kind": "register", "origin": origin, "boot": boot, "public_key": keys.public(),
        "ts": ts, "canonical": canon, "signature": B64U.encode(keys.sign(&canon)),
    }));

    let cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("GET", "/api/status", Vec::new()),
        ("GET", "/api/status?a=%2Fb%20c&d=%E3%81%82", Vec::new()),
        (
            "POST",
            "/api/transfers/send%3A%2Ftmp%2Fx/cancel",
            Vec::new(),
        ),
        (
            "POST",
            "/api/publish",
            br#"{"data":"AAAA","note":"line1\nline2"}"#.to_vec(),
        ),
        (
            "POST",
            "/api/directed/send",
            "{\"filename\":\"日本語.txt\"}".as_bytes().to_vec(),
        ),
    ];
    for (method, path, body) in &cases {
        let nonce = B64U.encode(OsRng.gen::<[u8; 16]>());
        let canon = canonical_request(method, path, origin, &sid, ts, &nonce, body);
        vectors.push(json!({
            "kind": "request", "origin": origin, "sid": sid, "ts": ts, "nonce": nonce,
            "method": method, "path": path, "body_b64": B64U.encode(body),
            "public_key": keys.public(), "canonical": canon,
            "signature": B64U.encode(keys.sign(&canon)),
        }));
    }

    // Round trip through the same checker the other direction uses.
    check_vectors(&vectors);

    let path = std::env::var("MIASMA_WS_VECTORS_OUT").unwrap_or_else(|_| {
        format!(
            "{}/websession_vectors_rust.json",
            env!("CARGO_TARGET_TMPDIR")
        )
    });
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({ "version": 1, "vectors": vectors })).unwrap(),
    )
    .unwrap();
    eprintln!("vectors written to {path}");
}

fn decode_any(s: &str) -> Vec<u8> {
    B64U.decode(s)
        .or_else(|_| STANDARD.decode(s))
        .unwrap_or_else(|_| panic!("not base64: {s}"))
}

/// Check each vector's canonical string against the daemon's own builder and
/// its signature against the daemon's verifier; a changed byte must fail.
fn check_vectors(vectors: &[Value]) {
    assert!(!vectors.is_empty(), "no vectors");
    for (i, v) in vectors.iter().enumerate() {
        let s = |k: &str| {
            v[k].as_str()
                .unwrap_or_else(|| panic!("vector {i}: missing {k}"))
        };
        let public = decode_any(s("public_key"));
        let signature = decode_any(s("signature"));
        let canonical = match s("kind") {
            "register" => register_message(
                s("origin"),
                s("boot"),
                s("public_key"),
                v["ts"].as_i64().unwrap(),
            ),
            "request" => canonical_request(
                s("method"),
                s("path"),
                s("origin"),
                s("sid"),
                v["ts"].as_i64().unwrap(),
                s("nonce"),
                &decode_any(s("body_b64")),
            ),
            other => panic!("vector {i}: unknown kind {other}"),
        };
        if let Some(given) = v["canonical"].as_str() {
            assert_eq!(given, canonical, "vector {i}: canonical string differs");
        }
        assert!(
            verify_signature(&public, canonical.as_bytes(), &signature),
            "vector {i} ({}): signature does not verify",
            s("kind")
        );
        let mut changed = canonical.into_bytes();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(
            !verify_signature(&public, &changed, &signature),
            "vector {i}: a changed message still verifies"
        );
    }
}

#[test]
#[ignore = "needs MIASMA_WS_VECTORS=<file written by the browser-side node test>"]
fn verifies_vectors_signed_by_the_browser_side() {
    let path = std::env::var("MIASMA_WS_VECTORS")
        .expect("set MIASMA_WS_VECTORS to the JSON file the node test wrote");
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(doc["version"], 1);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    check_vectors(vectors);
    eprintln!("{} browser-side vectors verified", vectors.len());
}
