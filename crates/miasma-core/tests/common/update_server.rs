//! A local HTTPS server for the updater's tests: a throw-away CA, a leaf for
//! `localhost`, and a handful of routes that behave like the parts of GitHub the
//! updater meets (JSON, redirects, 404, rate limit, big downloads, hangs).
//! Nothing here touches a real network.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

pub struct TlsServer {
    pub port: u16,
    /// The CA that signed the server's certificate (PEM), to hand to the client.
    pub ca_pem: Vec<u8>,
    /// Request heads the server has seen, in order.
    pub seen: Arc<Mutex<Vec<String>>>,
}

impl TlsServer {
    pub fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.port, path)
    }
}

fn make_certs() -> (
    Vec<u8>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "miasma update test ca");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (ca.pem().into_bytes(), vec![leaf.der().clone()], key)
}

fn head(status: &str, extra: &[(&str, String)], len: Option<u64>) -> String {
    let mut h = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    if let Some(l) = len {
        h.push_str(&format!("Content-Length: {l}\r\n"));
    }
    for (k, v) in extra {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    h
}

fn query_u64(path: &str, key: &str) -> u64 {
    path.split_once('?')
        .and_then(|(_, q)| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

async fn write_big(s: &mut (impl AsyncWriteExt + Unpin), n: u64) -> std::io::Result<()> {
    let chunk = vec![0xa5u8; 64 * 1024];
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len() as u64) as usize;
        s.write_all(&chunk[..k]).await?;
        left -= k as u64;
    }
    Ok(())
}

async fn serve_one<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut s: S,
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 16 * 1024 {
            return Ok(());
        }
    }
    let req = String::from_utf8_lossy(&buf).into_owned();
    seen.lock().unwrap().push(req.clone());
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let route = path.split('?').next().unwrap_or("/");
    match route {
        "/json" => {
            let body = br#"[{"tag_name":"v1.0.0"}]"#;
            s.write_all(head("200 OK", &[], Some(body.len() as u64)).as_bytes())
                .await?;
            s.write_all(body).await?;
        }
        "/headers" => {
            s.write_all(head("200 OK", &[], Some(req.len() as u64)).as_bytes())
                .await?;
            s.write_all(req.as_bytes()).await?;
        }
        "/redirect" => {
            let loc = format!("https://localhost:{port}/json");
            s.write_all(head("302 Found", &[("Location", loc)], Some(0)).as_bytes())
                .await?;
        }
        "/redirect-http" => {
            let loc = format!("http://localhost:{port}/json");
            s.write_all(head("302 Found", &[("Location", loc)], Some(0)).as_bytes())
                .await?;
        }
        "/loop" => {
            let loc = format!("https://localhost:{port}/loop");
            s.write_all(head("302 Found", &[("Location", loc)], Some(0)).as_bytes())
                .await?;
        }
        "/limited" => {
            s.write_all(
                head(
                    "403 Forbidden",
                    &[("X-RateLimit-Remaining", "0".into())],
                    Some(2),
                )
                .as_bytes(),
            )
            .await?;
            s.write_all(b"{}").await?;
        }
        "/big" => {
            let n = query_u64(&path, "bytes");
            s.write_all(head("200 OK", &[], Some(n)).as_bytes()).await?;
            write_big(&mut s, n).await?;
        }
        // No Content-Length: the body ends when the connection closes.
        "/bigopen" => {
            let n = query_u64(&path, "bytes");
            s.write_all(head("200 OK", &[], None).as_bytes()).await?;
            write_big(&mut s, n).await?;
        }
        // Announces 100 bytes, sends 10, hangs up.
        "/short" => {
            s.write_all(head("200 OK", &[], Some(100)).as_bytes())
                .await?;
            s.write_all(b"0123456789").await?;
        }
        // Never answers.
        "/hang" => {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        _ => {
            s.write_all(head("404 Not Found", &[], Some(0)).as_bytes())
                .await?;
        }
    }
    let _ = s.shutdown().await;
    Ok(())
}

pub fn start() -> TlsServer {
    let (ca_pem, chain, key) = make_certs();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((tcp, _)) = l.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let seen = seen2.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = serve_one(tls, port, seen).await;
                    }
                });
            }
        });
    });
    TlsServer { port, ca_pem, seen }
}
