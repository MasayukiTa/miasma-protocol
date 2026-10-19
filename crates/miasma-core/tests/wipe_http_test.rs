//! The wipe endpoint of the HTTP bridge against a real daemon: it is not
//! rate limited (file operations cannot use up its allowance) but still needs
//! the control token, and the directed file route applies the same output path
//! policy as the plain one.

use std::{sync::Arc, time::Duration};

use miasma_core::daemon::{control_auth, DaemonServer};
use miasma_core::network::types::NodeType;
use miasma_core::{network::node::MiasmaNode, LocalShareStore};
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
async fn the_wipe_is_not_rate_limited_after_file_operations_but_needs_the_token() {
    let d = start_daemon().await;
    let tok = d.token();

    // Use up the heavy bucket the way a busy screen would.
    let mut limited = 0;
    for _ in 0..14 {
        let r = http(
            d.http_port,
            "POST",
            "/api/retrieve-to-file",
            Some(&tok),
            "{}",
        )
        .await;
        if r.starts_with("HTTP/1.1 429") {
            limited += 1;
        }
    }
    assert!(limited > 0, "the file operations are rate limited");

    // The wipe still gets through: step one of the two-step confirmation
    // answers with a challenge.
    let r = http(d.http_port, "POST", "/api/wipe", Some(&tok), "").await;
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "the wipe must not be rate limited: {r:.200}"
    );
    assert!(r.contains("challenge"), "{r:.300}");

    // Not limited does not mean open: the token is still required.
    let r = http(d.http_port, "POST", "/api/wipe", None, "").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r:.200}");
    let r = http(d.http_port, "POST", "/api/wipe", Some("not-the-token"), "").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r:.200}");

    d.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_directed_file_route_applies_the_same_output_path_policy() {
    let d = start_daemon().await;
    let tok = d.token();

    for bad in ["relative/out.bin", "/tmp/../etc/out.bin"] {
        for route in ["/api/retrieve-to-file", "/api/directed/retrieve-to-file"] {
            let body = format!(
                r#"{{"mid":"miasma:x","envelope_id":"e","password":"p","output_path":"{bad}"}}"#
            );
            let r = http(d.http_port, "POST", route, Some(&tok), &body).await;
            assert!(r.starts_with("HTTP/1.1 400"), "{route} {bad}: {r:.200}");
            assert!(
                r.contains("output_path must be absolute"),
                "{route} {bad}: {r:.300}"
            );
        }
    }

    d.stop().await;
}
