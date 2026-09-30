//! The HTTP bridge as the browser client uses it: the client's own files are
//! served without a token, everything under `/api` (except the liveness ping)
//! needs one. Every test runs a real daemon against a throwaway data directory.
//! No test writes a literal password: secrets are drawn from the OS RNG at run
//! time.

use std::{sync::Arc, time::Duration};

use miasma_core::daemon::{control_auth, DaemonServer};
use miasma_core::network::types::NodeType;
use miasma_core::{network::node::MiasmaNode, LocalShareStore};
use rand::{rngs::OsRng, Rng};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};

struct TestDaemon {
    dir: tempfile::TempDir,
    http_port: u16,
    shutdown: tokio::sync::mpsc::Sender<()>,
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

    async fn stop(self) {
        let _ = self.shutdown.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.run).await;
    }
}

fn random_secret() -> String {
    let raw: [u8; 16] = OsRng.gen();
    hex::encode(raw)
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
