//! Tests that run the transports and the reachability matrix over loopback
//! paths made hostile by the shims in `support/hostile_net.rs`: a connection
//! reset on its first bytes, a black hole, a bandwidth cap, delay, outages on a
//! timetable, dropped UDP, a tampered DNS answer, and a gateway that re-signs
//! TLS. No traffic leaves this machine.

#![cfg(feature = "iroh")]

#[path = "support/hostile_net.rs"]
mod hostile_net;

use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use hostile_net::{
    InspectionCa, OutageSchedule, TcpMode, TcpShim, TlsInspector, UdpMode, UdpShim, Upstream,
};
use iroh::tls::CaTlsConfig;
use miasma_core::{
    config::{IrohMode, PushConfig},
    push::{
        retry::RetryPolicy,
        service::{PushService, PushSettings},
        ContactCode, PushState,
    },
    transport::{
        iroh_direct::{endpoint_builder, IrohNode, IrohServerLimits, IrohSettings},
        reach::{
            run_matrix, DnsResult, LanEvent, MatrixOptions, MatrixReport, Net, Outcome,
            ProbeResult, RelayEvent, Role, Target, TcpEvent, TlsEvent, UdpEvent, WsEvent,
        },
        reach_net::SystemNet,
        relay_tls,
    },
    LocalShareStore,
};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

// ─── Small servers the shims forward to ──────────────────────────────────────

/// Echoes every byte back.
async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Echoes every datagram back.
async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// A DNS server that answers every `A` query with `ip`.
async fn fake_dns(ip: [u8; 4]) -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            if n < 17 {
                continue;
            }
            // The question ends after the zero label and 4 more bytes.
            let mut p = 12;
            while p < n && buf[p] != 0 {
                p += 1 + buf[p] as usize;
            }
            let qend = (p + 5).min(n);
            let mut r = Vec::new();
            r.extend_from_slice(&buf[..2]);
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            r.extend_from_slice(&buf[12..qend]);
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            r.extend_from_slice(&ip);
            let _ = s.send_to(&r, from).await;
        }
    });
    addr
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

async fn round_trip(addr: SocketAddr, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(msg).await?;
    let mut got = vec![0u8; msg.len()];
    s.read_exact(&mut got).await?;
    Ok(got)
}

// ─── The shims themselves ────────────────────────────────────────────────────

#[tokio::test]
async fn tcp_shim_passes_traffic_and_counts_it() {
    let echo = echo_server().await;
    let shim = TcpShim::start(echo).await;
    assert_eq!(round_trip(shim.addr, b"hello").await.unwrap(), b"hello");
    // The counters are bumped just after the write that the client sees, so
    // give them a moment.
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end && (shim.stats().up_bytes, shim.stats().down_bytes) != (5, 5) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let st = shim.stats();
    assert!(st.accepted >= 1);
    assert_eq!((st.up_bytes, st.down_bytes), (5, 5));
}

#[tokio::test]
async fn tcp_shim_resets_a_connection_whose_first_bytes_match() {
    let echo = echo_server().await;
    let shim = TcpShim::start(echo).await;
    shim.set_mode(TcpMode::ResetOnPattern(vec![0x16, 0x03]));
    let err = round_trip(shim.addr, &[0x16, 0x03, 0x01, 0x02, 0x00])
        .await
        .unwrap_err();
    use std::io::ErrorKind as K;
    assert!(
        matches!(
            err.kind(),
            K::ConnectionReset | K::ConnectionAborted | K::UnexpectedEof | K::BrokenPipe
        ),
        "{err:?}"
    );
    // Other traffic still passes, and the reset is counted.
    assert_eq!(round_trip(shim.addr, b"plain").await.unwrap(), b"plain");
    assert_eq!(shim.stats().resets, 1);
}

#[tokio::test]
async fn tcp_shim_black_holes_after_n_bytes_and_keeps_the_connection_open() {
    let echo = echo_server().await;
    let shim = TcpShim::start(echo).await;
    shim.set_mode(TcpMode::BlackholeAfter(100));
    let mut s = TcpStream::connect(shim.addr).await.unwrap();
    s.write_all(&[7u8; 60]).await.unwrap();
    let mut got = [0u8; 60];
    s.read_exact(&mut got).await.unwrap();
    // Past the limit nothing comes back, but the socket is not closed.
    s.write_all(&[8u8; 400]).await.unwrap();
    let mut more = [0u8; 1];
    let r = timeout(Duration::from_millis(600), s.read(&mut more)).await;
    assert!(r.is_err(), "data arrived through a black hole: {r:?}");
}

#[tokio::test]
async fn tcp_shim_caps_bandwidth_and_adds_latency_and_jitter() {
    let echo = echo_server().await;
    let shim = TcpShim::start(echo).await;
    let payload = vec![1u8; 100_000];
    let t = Instant::now();
    round_trip(shim.addr, &payload).await.unwrap();
    let free = t.elapsed();

    shim.set_bandwidth(Some(100_000));
    let t = Instant::now();
    round_trip(shim.addr, &payload).await.unwrap();
    let capped = t.elapsed();
    assert!(
        capped >= Duration::from_millis(800),
        "{capped:?} vs {free:?}"
    );
    shim.set_bandwidth(None);

    shim.set_delay(Duration::from_millis(80), Duration::from_millis(40));
    let t = Instant::now();
    round_trip(shim.addr, b"x").await.unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(150),
        "{:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn tcp_shim_follows_an_outage_schedule() {
    let echo = echo_server().await;
    let shim = TcpShim::start(echo).await;
    let job = shim.run_schedule(OutageSchedule::periodic(
        Duration::from_millis(400),
        Duration::from_millis(400),
    ));
    let (mut ok, mut failed) = (0, 0);
    let end = Instant::now() + Duration::from_millis(2500);
    while Instant::now() < end {
        match timeout(Duration::from_secs(1), round_trip(shim.addr, b"ping")).await {
            Ok(Ok(_)) => ok += 1,
            _ => failed += 1,
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    job.abort();
    assert!(ok > 3, "ok={ok} failed={failed}");
    assert!(failed > 3, "ok={ok} failed={failed}");
    // An open connection is reset when the down period starts.
    shim.set_down(false);
    let mut s = TcpStream::connect(shim.addr).await.unwrap();
    s.write_all(b"a").await.unwrap();
    let mut one = [0u8; 1];
    s.read_exact(&mut one).await.unwrap();
    shim.set_down(true);
    let r = timeout(Duration::from_secs(2), s.read(&mut one))
        .await
        .unwrap();
    assert!(r.is_err() || r.unwrap() == 0);
}

#[tokio::test]
async fn udp_shim_drops_loses_and_delays() {
    let echo = udp_echo().await;
    let shim = UdpShim::start(echo).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 64];

    client.send_to(b"one", shim.addr).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"one");

    shim.set_mode(UdpMode::DropAll);
    client.send_to(b"two", shim.addr).await.unwrap();
    assert!(
        timeout(Duration::from_millis(500), client.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(shim.counts().1 >= 1);

    shim.set_mode(UdpMode::Pass);
    shim.set_loss_percent(100);
    client.send_to(b"three", shim.addr).await.unwrap();
    assert!(
        timeout(Duration::from_millis(500), client.recv_from(&mut buf))
            .await
            .is_err()
    );

    shim.set_loss_percent(0);
    shim.set_delay(Duration::from_millis(100), Duration::ZERO);
    let t = Instant::now();
    client.send_to(b"four", shim.addr).await.unwrap();
    timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(180),
        "{:?}",
        t.elapsed()
    );
}

// ─── Re-signed TLS, with and without the extra CA ────────────────────────────

fn settings_with_ca(ca_pem: Option<&str>) -> IrohSettings {
    IrohSettings {
        mode: IrohMode::N0,
        relay_urls: vec![],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(5),
        ca_pem: ca_pem.map(|p| p.as_bytes().to_vec()),
        proxy_from_env: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resigned_certificate_is_untrusted_without_the_extra_ca_and_trusted_with_it() {
    let echo = echo_server().await;
    let ca = InspectionCa::new();
    let gateway =
        TlsInspector::start(&ca, &["localhost", "127.0.0.1"], Upstream::Plain(echo)).await;
    let port = gateway.addr.port();

    // The certificate reader: issuer named, not a public CA, not trusted.
    let seen = relay_tls::probe(
        "localhost",
        port,
        &CaTlsConfig::embedded(),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(seen.issuer, InspectionCa::NAME);
    assert!(!seen.public_ca);
    assert!(!seen.trusted);
    let with = CaTlsConfig::embedded().with_extra_roots([CertificateDer::from(ca.der())]);
    let seen = relay_tls::probe("localhost", port, &with, Duration::from_secs(10))
        .await
        .unwrap();
    assert!(seen.trusted && !seen.public_ca);

    // The same through the matrix's network layer (the daemon's trust settings).
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let plain = SystemNet::new(settings_with_ca(None));
    let ev = plain.tls(addr, "localhost", Duration::from_secs(10)).await;
    assert_eq!(
        ev,
        TlsEvent::Cert {
            issuer: InspectionCa::NAME.into(),
            public_ca: false,
            trusted: false
        }
    );
    let pem = ca.pem();
    let trusting = SystemNet::new(settings_with_ca(Some(&pem)));
    let ev = trusting
        .tls(addr, "localhost", Duration::from_secs(10))
        .await;
    assert_eq!(
        ev,
        TlsEvent::Cert {
            issuer: InspectionCa::NAME.into(),
            public_ca: false,
            trusted: true
        }
    );
}

struct LocalRelay {
    _server: iroh_relay::server::Server,
    addr: SocketAddr,
}

async fn local_relay() -> LocalRelay {
    let mut cfg = iroh_relay::server::testing::server_config();
    cfg.quic = None;
    let server = iroh_relay::server::Server::spawn(cfg).await.unwrap();
    let addr = server.https_addr().unwrap();
    LocalRelay {
        _server: server,
        addr,
    }
}

fn custom_settings(url: &str, ca_pem: Option<&str>, connect: Duration) -> IrohSettings {
    IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec![url.to_owned()],
        discovery: false,
        lan_discovery: false,
        connect_timeout: connect,
        ca_pem: ca_pem.map(|p| p.as_bytes().to_vec()),
        proxy_from_env: false,
    }
}

fn empty_store() -> (tempfile::TempDir, Arc<LocalShareStore>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 10).unwrap());
    (dir, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_iroh_node_reaches_a_relay_through_a_resigning_gateway_only_with_the_extra_ca() {
    timeout(Duration::from_secs(90), async {
        let relay = local_relay().await;
        let ca = InspectionCa::new();
        let gateway = TlsInspector::start(
            &ca,
            &["127.0.0.1", "localhost"],
            Upstream::Tls {
                addr: relay.addr,
                name: "localhost".into(),
            },
        )
        .await;
        let url = format!("https://{}", gateway.addr);

        // The gateway's CA is configured, as `transport.iroh_extra_ca_pem` does.
        let pem = ca.pem();
        let (d1, s1) = empty_store();
        let node = IrohNode::start(
            &rand::random(),
            custom_settings(&url, Some(&pem), Duration::from_secs(10)),
            s1,
            None,
        )
        .await
        .unwrap();
        assert!(node.wait_online(Duration::from_secs(20)).await);
        node.shutdown().await;

        // Without it the node never gets a relay, and says why.
        let (d2, s2) = empty_store();
        let node = IrohNode::start(
            &rand::random(),
            custom_settings(&url, None, Duration::from_secs(5)),
            s2,
            None,
        )
        .await
        .unwrap();
        assert!(!node.wait_online(Duration::from_secs(6)).await);
        assert!(!node.status().relay_connected);
        node.shutdown().await;
        drop((d1, d2));
    })
    .await
    .expect("timed out");
}

// ─── Relay watchdog over an outage schedule ──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_relay_watchdog_recovers_the_home_relay_after_outages() {
    timeout(Duration::from_secs(240), async {
        let relay = local_relay().await;
        let shim = TcpShim::start(relay.addr).await;
        let s = custom_settings(&shim.url(), None, Duration::from_secs(5));
        let seed: [u8; 32] = rand::random();
        let builder = endpoint_builder(Some(&seed), &s, false)
            .unwrap()
            .ca_tls_config(CaTlsConfig::insecure_skip_verify());
        let (_dir, store) = empty_store();
        let node =
            IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
                .await
                .unwrap();
        node.spawn_relay_watchdog();
        assert!(
            node.wait_online(Duration::from_secs(20)).await,
            "first connect"
        );
        assert!(node.status().relay_connected);

        // A short outage: the relay link drops and comes back.
        shim.set_down(true);
        let end = Instant::now() + Duration::from_secs(15);
        while node.status().relay_connected && Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(!node.status().relay_connected, "the drop was not noticed");
        shim.set_down(false);
        assert!(
            wait_connected(&node, Duration::from_secs(60)).await,
            "no recovery after the short outage: {:?}",
            node.status().last_error
        );

        // A long one, past the watchdog's grace period (30 s after a drop): it
        // must refresh at least once, and the link comes back when the relay does.
        let refreshes_before = node.status().relay_refreshes;
        shim.set_down(true);
        let outage = Instant::now() + Duration::from_secs(46);
        while Instant::now() < outage {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let during = node.status();
        assert!(!during.relay_connected);
        assert!(
            during.relay_refreshes > refreshes_before,
            "the watchdog did not refresh during a 46-s outage"
        );
        assert!(during.relay_down_secs.unwrap_or(0) >= 30);
        shim.set_down(false);
        assert!(
            wait_connected(&node, Duration::from_secs(60)).await,
            "no recovery after the long outage: {:?}",
            node.status().last_error
        );
        assert!(node.status().relay_down_secs.is_none());
        node.shutdown().await;
    })
    .await
    .expect("timed out");
}

async fn wait_connected(node: &IrohNode, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if node.status().relay_connected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

// ─── The matrix against each hostile behaviour ───────────────────────────────

/// The real network layer, except that name lookups are answered from a table
/// (an injected resolver): `*.test` names resolve to loopback, and a few are
/// made to answer something else.
struct ShimNet {
    inner: SystemNet,
    tampered: Vec<String>,
}

#[async_trait]
impl Net for ShimNet {
    async fn system_dns(&self, host: &str, _limit: Duration) -> DnsResult {
        if self.tampered.iter().any(|t| t == host) {
            return Ok(vec!["198.51.100.7".parse::<IpAddr>().unwrap()]);
        }
        Ok(vec![IpAddr::from([127, 0, 0, 1])])
    }
    async fn udp_dns(&self, r: SocketAddr, h: &str, l: Duration) -> DnsResult {
        self.inner.udp_dns(r, h, l).await
    }
    async fn tcp(&self, a: SocketAddr, l: Duration) -> TcpEvent {
        self.inner.tcp(a, l).await
    }
    async fn tls(&self, a: SocketAddr, sni: &str, l: Duration) -> TlsEvent {
        self.inner.tls(a, sni, l).await
    }
    async fn udp(&self, _l: Duration) -> UdpEvent {
        UdpEvent::default()
    }
    async fn relay_path(&self, _l: Duration) -> RelayEvent {
        RelayEvent::Failed
    }
    async fn websocket(&self, a: SocketAddr, t: &Target, l: Duration) -> WsEvent {
        self.inner.websocket(a, t, l).await
    }
    async fn lan(&self, _l: Duration) -> LanEvent {
        LanEvent::NotSeen
    }
}

fn relay_target(host: &str, port: u16) -> Target {
    Target {
        host: host.to_owned(),
        port,
        role: Role::Relay,
        path: "/".into(),
        tls: true,
    }
}

fn row<'a>(r: &'a MatrixReport, id: &str) -> &'a ProbeResult {
    r.probes.iter().find(|p| p.id == id).unwrap_or_else(|| {
        panic!(
            "no row {id}: {:?}",
            r.probes.iter().map(|p| &p.id).collect::<Vec<_>>()
        )
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn the_matrix_classifies_each_hostile_behaviour() {
    let echo = echo_server().await;
    let ca = InspectionCa::new();
    let names = [
        "pass.test",
        "reset.test",
        "blackhole.test",
        "down.test",
        "cut-sni.test",
        "tampered.test",
    ];
    let gateway = TlsInspector::start(&ca, &names, Upstream::Plain(echo)).await;

    // pass.test goes straight to the gateway; the others through a shim.
    let reset = TcpShim::start(gateway.addr).await;
    reset.set_mode(TcpMode::ResetOnPattern(vec![0x16, 0x03]));
    let blackhole = TcpShim::start(gateway.addr).await;
    blackhole.set_mode(TcpMode::BlackholeAfter(0));
    let down = TcpShim::start(gateway.addr).await;
    down.set_down(true);
    // Resets a hello only if the (neutral) name it carries is the blocked one.
    let cut_sni = TcpShim::start(gateway.addr).await;
    cut_sni.set_mode(TcpMode::ResetOnPattern(b"blocked-name.test".to_vec()));
    let refused = closed_port().await;

    // Public resolvers: both answer 127.0.0.1 for everything, over UDP shims.
    let dns = fake_dns([127, 0, 0, 1]).await;
    let udp_a = UdpShim::start(dns).await;
    let udp_b = UdpShim::start(dns).await;

    let pem = ca.pem();
    let net = ShimNet {
        inner: SystemNet::new(settings_with_ca(Some(&pem))),
        tampered: vec!["tampered.test".into()],
    };
    let mut opts = MatrixOptions::from_settings(&settings_with_ca(Some(&pem)), vec![]);
    opts.targets = vec![
        relay_target("pass.test", gateway.addr.port()),
        relay_target("reset.test", reset.addr.port()),
        relay_target("blackhole.test", blackhole.addr.port()),
        relay_target("down.test", down.addr.port()),
        relay_target("cut-sni.test", cut_sni.addr.port()),
        relay_target("refused.test", refused),
        relay_target("tampered.test", gateway.addr.port()),
    ];
    opts.resolvers = [udp_a.addr, udp_b.addr];
    opts.neutral_sni = "blocked-name.test".into();
    opts.run_iroh = false;

    let started = Instant::now();
    let r = run_matrix(&net, &opts).await;
    assert!(started.elapsed() < Duration::from_secs(40));

    // DNS: injected resolver says tampered.test differs from the public answer.
    assert_eq!(row(&r, "dns:relay:pass.test").outcome, Outcome::Ok);
    assert_eq!(
        row(&r, "dns:relay:tampered.test").outcome,
        Outcome::AnswerDiffers
    );
    // TCP: a closed port is refused; the others accept.
    assert_eq!(
        row(&r, "tcp:relay:refused.test#1").outcome,
        Outcome::Refused
    );
    assert_eq!(row(&r, "tcp:relay:pass.test#1").outcome, Outcome::Ok);
    assert_eq!(row(&r, "tcp:relay:blackhole.test#1").outcome, Outcome::Ok);
    // TLS: the re-signed certificate is named, and trusted (the CA is configured).
    let t = row(&r, "tls:relay:pass.test");
    assert_eq!(t.outcome, Outcome::NonPublicCa);
    assert!(t.ok);
    assert_eq!(
        t.detail.as_deref(),
        Some("issuer=Test Inspection CA; trusted=true")
    );
    // A reset on the hello is not a timeout, and a black hole is not a reset.
    assert_eq!(
        row(&r, "tls:relay:reset.test").outcome,
        Outcome::ResetInHandshake
    );
    assert_eq!(
        row(&r, "tls:relay:blackhole.test").outcome,
        Outcome::Timeout
    );
    assert_eq!(
        row(&r, "tls:relay:down.test").outcome,
        Outcome::ResetInHandshake
    );
    // Nothing is handshaken on a port that refused.
    assert_eq!(row(&r, "tls:relay:refused.test").outcome, Outcome::Skipped);
    // SNI: the first reachable relay is pass.test, which treats both names alike.
    assert_eq!(row(&r, "sni:relay:pass.test").outcome, Outcome::Ok);

    // The SNI comparison on a path that cuts one name only.
    let mut o2 = opts.clone();
    o2.targets = vec![relay_target("cut-sni.test", cut_sni.addr.port())];
    let r2 = run_matrix(&net, &o2).await;
    let s = row(&r2, "sni:relay:cut-sni.test");
    assert_eq!(s.outcome, Outcome::SniDiffers);
    assert_eq!(s.detail.as_deref(), Some("real=handshake; neutral=reset"));

    // UDP DNS dropped by the network: the system resolver still answers.
    udp_a.set_mode(UdpMode::DropAll);
    udp_b.set_mode(UdpMode::DropAll);
    let mut o3 = opts.clone();
    o3.targets = vec![relay_target("pass.test", gateway.addr.port())];
    let r3 = run_matrix(&net, &o3).await;
    let d = row(&r3, "dns:relay:pass.test");
    assert_eq!(d.outcome, Outcome::UdpDnsBlocked);
    assert!(d.ok);
}

// ─── Push over a path with periodic disconnects ──────────────────────────────

struct PushPeer {
    node: Arc<IrohNode>,
    svc: Arc<PushService>,
    dir: tempfile::TempDir,
    inbox: PathBuf,
}

/// A push peer whose only path is the relay (no IP transport), so every byte
/// crosses the shim in front of the relay.
async fn relay_only_peer(relay_url: &str) -> PushPeer {
    let dir = tempfile::tempdir().unwrap();
    let (store_dir, store) = empty_store();
    let s = custom_settings(relay_url, None, Duration::from_secs(20));
    let seed: [u8; 32] = rand::random();
    let builder = endpoint_builder(Some(&seed), &s, false)
        .unwrap()
        .clear_ip_transports()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    let node = IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap();
    assert!(node.wait_online(Duration::from_secs(20)).await);
    let inbox = dir.path().join("inbox");
    let mut settings = PushSettings::from_config(&PushConfig::default(), dir.path());
    settings.min_free_bytes = 0;
    settings.retry = RetryPolicy {
        ladder: vec![Duration::from_secs(1)],
        then_every: Duration::from_secs(1),
        window: Some(Duration::from_secs(600)),
        jitter: 0.0,
        min_gap: Duration::from_millis(500),
    };
    settings.idle_timeout = Duration::from_secs(20);
    settings.stall_timeout = Duration::from_secs(10);
    let svc = PushService::start(dir.path(), node.clone(), settings);
    std::mem::forget(store_dir);
    PushPeer {
        node,
        svc,
        dir,
        inbox,
    }
}

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

fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(f) = find_file(&p, name) {
                return Some(f);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

/// 20 MiB between two relay-only peers while the relay path is cut for 1.5 s
/// every 6 s and capped at 6 MiB/s: the file arrives complete and identical,
/// each cut ending an attempt that the sender then resumes on a new connection.
#[tokio::test(flavor = "multi_thread")]
async fn push_of_20_mib_completes_over_a_path_with_periodic_disconnects() {
    timeout(Duration::from_secs(300), async {
        let relay = local_relay().await;
        let shim = TcpShim::start(relay.addr).await;
        shim.set_bandwidth(Some(6 * 1024 * 1024));
        let url = shim.url();
        let alice = relay_only_peer(&url).await;
        let bob = relay_only_peer(&url).await;
        alice
            .svc
            .add_contact(&ContactCode::new(bob.node.endpoint_id()), Some("bob"))
            .unwrap();
        bob.svc
            .add_contact(&ContactCode::new(alice.node.endpoint_id()), Some("alice"))
            .unwrap();

        let data = content(20 * 1024 * 1024);
        let src = alice.dir.path().join("big.bin");
        std::fs::write(&src, &data).unwrap();
        let id = alice.svc.queue_send("bob", &src).unwrap();

        // Cuts start once the transfer has begun.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let cuts = shim.run_schedule(OutageSchedule::periodic(
            Duration::from_secs(6),
            Duration::from_millis(1500),
        ));
        let end = Instant::now() + Duration::from_secs(240);
        let done = loop {
            let t = alice.svc.board().get(&id).expect("on the board");
            if t.state.is_finished() {
                break t;
            }
            assert!(Instant::now() < end, "timed out in state {:?}", t.state);
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        cuts.abort();
        assert_eq!(done.state, PushState::Done, "{:?}", done.error);
        assert!(shim.stats().resets > 0, "the path was never cut");
        let got = find_file(&bob.inbox, "big.bin").expect("received file");
        assert_eq!(
            blake3::hash(&std::fs::read(got).unwrap()),
            blake3::hash(&data)
        );
    })
    .await
    .expect("timed out");
}
