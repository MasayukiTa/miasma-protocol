//! In-process shims that make a loopback path behave like a bad network, for
//! integration tests. Include with
//! `#[path = "support/hostile_net.rs"] mod hostile_net;`.
//!
//! * [`TcpShim`]: forwards TCP to an upstream address and can, while running,
//!   switch to: reset a connection whose first bytes match a pattern, go silent
//!   (a black hole) after N bytes, cap the bandwidth, add latency and jitter,
//!   or go down (every connection reset, new ones reset on arrival). An
//!   [`OutageSchedule`] flips the down state on a timetable.
//! * [`UdpShim`]: forwards UDP datagrams and can drop all of them, drop a
//!   share of them, or delay them.
//! * [`InspectionCa`] / [`TlsInspector`]: a proxy that terminates TLS with a
//!   certificate signed by a generated CA named "Test Inspection CA" and
//!   forwards the decrypted bytes, as an HTTPS-inspecting gateway does.
//!
//! Everything binds to 127.0.0.1 and is reached by ordinary connections. These
//! shims only reproduce a failing network on this machine; they do not touch
//! traffic that belongs to anyone else.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    task::JoinHandle,
};

// ─── TCP ─────────────────────────────────────────────────────────────────────

/// What a [`TcpShim`] does with a new connection's traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpMode {
    /// Forward everything.
    Pass,
    /// Reset (RST) a connection whose first bytes from the client contain this
    /// pattern within the first 512 bytes: a prefix such as a TLS record header,
    /// or a name inside a hello.
    ResetOnPattern(Vec<u8>),
    /// Forward the first N bytes (both directions together), then read and
    /// discard everything: the connection stays open and nothing arrives.
    BlackholeAfter(usize),
}

#[derive(Default)]
struct TcpShared {
    mode: Mutex<Option<TcpMode>>,
    /// Bytes per second per direction; 0 = no cap.
    rate: AtomicU64,
    latency_ms: AtomicU64,
    jitter_ms: AtomicU64,
    down: AtomicBool,
    accepted: AtomicU64,
    resets: AtomicU64,
    up_bytes: AtomicU64,
    down_bytes: AtomicU64,
}

/// Counters of a [`TcpShim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpStats {
    pub accepted: u64,
    /// Connections the shim ended with a reset.
    pub resets: u64,
    /// Bytes forwarded client -> upstream.
    pub up_bytes: u64,
    /// Bytes forwarded upstream -> client.
    pub down_bytes: u64,
}

pub struct TcpShim {
    pub addr: SocketAddr,
    shared: Arc<TcpShared>,
    kill: watch::Sender<u64>,
    accept: JoinHandle<()>,
}

impl TcpShim {
    /// Listen on 127.0.0.1 (a free port) and forward to `upstream`.
    pub async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(TcpShared::default());
        *shared.mode.lock().unwrap() = Some(TcpMode::Pass);
        let (kill, _) = watch::channel(0u64);
        let accept = {
            let shared = shared.clone();
            let kill = kill.clone();
            tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    shared.accepted.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(connection(
                        client,
                        upstream,
                        shared.clone(),
                        kill.subscribe(),
                    ));
                }
            })
        };
        Self {
            addr,
            shared,
            kill,
            accept,
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.addr)
    }

    pub fn set_mode(&self, mode: TcpMode) {
        *self.shared.mode.lock().unwrap() = Some(mode);
    }

    /// Cap each direction at `bytes_per_sec` (`None`: no cap).
    pub fn set_bandwidth(&self, bytes_per_sec: Option<u64>) {
        self.shared
            .rate
            .store(bytes_per_sec.unwrap_or(0), Ordering::SeqCst);
    }

    /// Delay every forwarded chunk by `latency` plus up to `jitter`.
    pub fn set_delay(&self, latency: Duration, jitter: Duration) {
        self.shared
            .latency_ms
            .store(latency.as_millis() as u64, Ordering::SeqCst);
        self.shared
            .jitter_ms
            .store(jitter.as_millis() as u64, Ordering::SeqCst);
    }

    /// Down: every connection is reset now and each new one is reset on
    /// arrival. Up again: new connections are forwarded.
    pub fn set_down(&self, down: bool) {
        self.shared.down.store(down, Ordering::SeqCst);
        if down {
            self.kill_connections();
        }
    }

    /// Reset every connection that is open now.
    pub fn kill_connections(&self) {
        self.kill.send_modify(|n| *n += 1);
    }

    pub fn stats(&self) -> TcpStats {
        TcpStats {
            accepted: self.shared.accepted.load(Ordering::SeqCst),
            resets: self.shared.resets.load(Ordering::SeqCst),
            up_bytes: self.shared.up_bytes.load(Ordering::SeqCst),
            down_bytes: self.shared.down_bytes.load(Ordering::SeqCst),
        }
    }

    /// Run `schedule` against this shim in the background. Dropping the
    /// returned handle's task (`abort`) stops it; the shim is left in the state
    /// of the last step.
    pub fn run_schedule(&self, schedule: OutageSchedule) -> JoinHandle<()> {
        let shared = self.shared.clone();
        let kill = self.kill.clone();
        tokio::spawn(async move {
            loop {
                for (up, d) in &schedule.steps {
                    shared.down.store(!up, Ordering::SeqCst);
                    if !up {
                        kill.send_modify(|n| *n += 1);
                    }
                    tokio::time::sleep(*d).await;
                }
                if !schedule.repeat {
                    break;
                }
            }
            shared.down.store(false, Ordering::SeqCst);
        })
    }
}

impl Drop for TcpShim {
    fn drop(&mut self) {
        self.accept.abort();
        self.kill.send_modify(|n| *n += 1);
    }
}

/// A timetable of up and down periods.
#[derive(Clone, Debug)]
pub struct OutageSchedule {
    /// `(up?, how long)`, in order.
    pub steps: Vec<(bool, Duration)>,
    /// Start again after the last step.
    pub repeat: bool,
}

impl OutageSchedule {
    /// Up for `up`, then down for `down`, over and over.
    pub fn periodic(up: Duration, down: Duration) -> Self {
        Self {
            steps: vec![(true, up), (false, down)],
            repeat: true,
        }
    }
}

/// End a connection with a reset: close with a zero linger so the peer sees RST.
#[allow(deprecated)]
fn reset(s: TcpStream) {
    let _ = s.set_linger(Some(Duration::ZERO));
    drop(s);
}

async fn connection(
    client: TcpStream,
    upstream: SocketAddr,
    sh: Arc<TcpShared>,
    mut kill: watch::Receiver<u64>,
) {
    if sh.down.load(Ordering::SeqCst) {
        sh.resets.fetch_add(1, Ordering::SeqCst);
        reset(client);
        return;
    }
    let Ok(server) = TcpStream::connect(upstream).await else {
        sh.resets.fetch_add(1, Ordering::SeqCst);
        reset(client);
        return;
    };
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let total = Arc::new(AtomicU64::new(0));
    let first_checked = Arc::new(AtomicBool::new(false));
    let up = pump(
        &mut cr,
        &mut sw,
        true,
        sh.clone(),
        total.clone(),
        first_checked,
        stop_tx.clone(),
    );
    // Held until the end so the stop channel never reports "closed".
    let stop_keep = stop_tx.clone();
    let down = pump(
        &mut sr,
        &mut cw,
        false,
        sh.clone(),
        total,
        Arc::new(AtomicBool::new(true)),
        stop_tx,
    );
    let both = async {
        tokio::join!(up, down);
    };
    let killed = tokio::select! {
        _ = both => false,
        _ = kill.changed() => true,
        _ = stop_rx.changed() => true,
    };
    if killed {
        sh.resets.fetch_add(1, Ordering::SeqCst);
        if let Ok(c) = cr.reunite(cw) {
            reset(c);
        }
        if let Ok(s) = sr.reunite(sw) {
            reset(s);
        }
    }
    drop(stop_keep);
}

/// Copy one direction, applying the shim's current behaviour to every chunk.
async fn pump(
    from: &mut tokio::net::tcp::OwnedReadHalf,
    to: &mut tokio::net::tcp::OwnedWriteHalf,
    is_up: bool,
    sh: Arc<TcpShared>,
    total: Arc<AtomicU64>,
    first_checked: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = to.shutdown().await;
                return;
            }
            Ok(n) => n,
        };
        let mode = sh.mode.lock().unwrap().clone().unwrap_or(TcpMode::Pass);
        if is_up && !first_checked.swap(true, Ordering::SeqCst) {
            if let TcpMode::ResetOnPattern(p) = &mode {
                let head = &buf[..n.min(512)];
                if !p.is_empty() && head.windows(p.len()).any(|w| w == p.as_slice()) {
                    let _ = stop.send(true);
                    // Park: the connection task resets both sockets.
                    std::future::pending::<()>().await;
                }
            }
        }
        let before = total.fetch_add(n as u64, Ordering::SeqCst);
        if let TcpMode::BlackholeAfter(limit) = mode {
            if before >= limit as u64 {
                continue; // read and discard
            }
        }
        let latency = sh.latency_ms.load(Ordering::SeqCst);
        let jitter = sh.jitter_ms.load(Ordering::SeqCst);
        if latency > 0 || jitter > 0 {
            let extra = if jitter > 0 {
                rand::random::<u64>() % (jitter + 1)
            } else {
                0
            };
            tokio::time::sleep(Duration::from_millis(latency + extra)).await;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
        let counter = if is_up { &sh.up_bytes } else { &sh.down_bytes };
        counter.fetch_add(n as u64, Ordering::SeqCst);
        let rate = sh.rate.load(Ordering::SeqCst);
        if rate > 0 {
            tokio::time::sleep(Duration::from_secs_f64(n as f64 / rate as f64)).await;
        }
    }
}

// ─── UDP ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpMode {
    Pass,
    /// Every datagram, both ways, is dropped.
    DropAll,
}

#[derive(Default)]
struct UdpShared {
    drop_all: AtomicBool,
    loss_percent: AtomicU64,
    latency_ms: AtomicU64,
    jitter_ms: AtomicU64,
    forwarded: AtomicU64,
    dropped: AtomicU64,
}

pub struct UdpShim {
    pub addr: SocketAddr,
    shared: Arc<UdpShared>,
    task: JoinHandle<()>,
}

impl UdpShim {
    pub async fn start(upstream: SocketAddr) -> Self {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let shared = Arc::new(UdpShared::default());
        let task = {
            let (front, shared) = (front.clone(), shared.clone());
            tokio::spawn(async move {
                // One upstream-facing socket per client, so replies find their way back.
                let mut back: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok((n, client)) = front.recv_from(&mut buf).await {
                    if lost(&shared) {
                        continue;
                    }
                    let sock = match back.get(&client) {
                        Some(s) => s.clone(),
                        None => {
                            let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                            let (front, shared, s2) = (front.clone(), shared.clone(), s.clone());
                            tokio::spawn(async move {
                                let mut rb = vec![0u8; 64 * 1024];
                                while let Ok((m, _)) = s2.recv_from(&mut rb).await {
                                    if lost(&shared) {
                                        continue;
                                    }
                                    delay(&shared).await;
                                    let _ = front.send_to(&rb[..m], client).await;
                                }
                            });
                            back.insert(client, s.clone());
                            s
                        }
                    };
                    let data = buf[..n].to_vec();
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        delay(&shared).await;
                        let _ = sock.send_to(&data, upstream).await;
                    });
                }
            })
        };
        Self { addr, shared, task }
    }

    pub fn set_mode(&self, mode: UdpMode) {
        self.shared
            .drop_all
            .store(mode == UdpMode::DropAll, Ordering::SeqCst);
    }

    /// Drop this share (0..=100) of the datagrams at random.
    pub fn set_loss_percent(&self, p: u64) {
        self.shared.loss_percent.store(p.min(100), Ordering::SeqCst);
    }

    pub fn set_delay(&self, latency: Duration, jitter: Duration) {
        self.shared
            .latency_ms
            .store(latency.as_millis() as u64, Ordering::SeqCst);
        self.shared
            .jitter_ms
            .store(jitter.as_millis() as u64, Ordering::SeqCst);
    }

    /// `(forwarded, dropped)` datagram counts.
    pub fn counts(&self) -> (u64, u64) {
        (
            self.shared.forwarded.load(Ordering::SeqCst),
            self.shared.dropped.load(Ordering::SeqCst),
        )
    }
}

impl Drop for UdpShim {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn lost(sh: &UdpShared) -> bool {
    let gone = sh.drop_all.load(Ordering::SeqCst)
        || (rand::random::<u64>() % 100) < sh.loss_percent.load(Ordering::SeqCst);
    if gone {
        sh.dropped.fetch_add(1, Ordering::SeqCst);
    } else {
        sh.forwarded.fetch_add(1, Ordering::SeqCst);
    }
    gone
}

async fn delay(sh: &UdpShared) {
    let latency = sh.latency_ms.load(Ordering::SeqCst);
    let jitter = sh.jitter_ms.load(Ordering::SeqCst);
    if latency > 0 || jitter > 0 {
        let extra = if jitter > 0 {
            rand::random::<u64>() % (jitter + 1)
        } else {
            0
        };
        tokio::time::sleep(Duration::from_millis(latency + extra)).await;
    }
}

// ─── TLS re-signing ──────────────────────────────────────────────────────────

/// A throw-away CA with the name an inspecting gateway's certificate has in the
/// tests: "Test Inspection CA".
pub struct InspectionCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl InspectionCa {
    pub const NAME: &'static str = "Test Inspection CA";

    pub fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, Self::NAME);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    pub fn der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }

    /// The CA as PEM text, what `transport.iroh_extra_ca_pem` points at.
    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A server certificate for `names` (DNS names or IP addresses) signed by
    /// this CA.
    pub fn leaf(&self, names: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let leaf = params.signed_by(&leaf_key, &self.cert, &self.key).unwrap();
        (
            leaf.der().clone(),
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
    }
}

/// Where a [`TlsInspector`] forwards to.
pub enum Upstream {
    /// Plain TCP.
    Plain(SocketAddr),
    /// TLS, with the upstream certificate not checked (the test servers use
    /// self-signed ones).
    Tls { addr: SocketAddr, name: String },
}

/// Terminates TLS with a certificate from an [`InspectionCa`] and forwards the
/// decrypted bytes upstream.
pub struct TlsInspector {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl TlsInspector {
    /// `names`: what the re-signed certificate is valid for.
    pub async fn start(ca: &InspectionCa, names: &[&str], upstream: Upstream) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (cert, key) = ca.leaf(names);
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = Arc::new(upstream);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, connector, upstream) =
                    (acceptor.clone(), connector.clone(), upstream.clone());
                tokio::spawn(async move {
                    let Ok(mut client) = acceptor.accept(tcp).await else {
                        return;
                    };
                    match &*upstream {
                        Upstream::Plain(a) => {
                            let Ok(mut s) = TcpStream::connect(a).await else {
                                return;
                            };
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut s).await;
                        }
                        Upstream::Tls { addr, name } => {
                            let Ok(tcp) = TcpStream::connect(addr).await else {
                                return;
                            };
                            let Ok(sni) = ServerName::try_from(name.clone()) else {
                                return;
                            };
                            let Ok(mut s) = connector.connect(sni, tcp).await else {
                                return;
                            };
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut s).await;
                        }
                    }
                });
            }
        });
        Self { addr, task }
    }
}

impl Drop for TlsInspector {
    fn drop(&mut self) {
        self.task.abort();
    }
}
