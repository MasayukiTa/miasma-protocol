//! Classification and orchestration tests for the reachability matrix. Every
//! network call is a fake, so these need no network.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
    sync::Mutex,
};

use super::*;

const IP: &str = "203.0.113.5";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A network where everything works unless a test says otherwise.
struct Fake {
    sys: Mutex<HashMap<String, DnsResult>>,
    public: Mutex<HashMap<String, DnsResult>>,
    tcp: Mutex<HashMap<String, TcpEvent>>,
    tls: Mutex<HashMap<String, TlsEvent>>,
    udp: Mutex<UdpEvent>,
    relay: Mutex<RelayEvent>,
    ws: Mutex<WsEvent>,
    lan: Mutex<LanEvent>,
    delay: Duration,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

fn good_cert() -> TlsEvent {
    TlsEvent::Cert {
        issuer: "Public Root".into(),
        public_ca: true,
        trusted: true,
    }
}

impl Fake {
    fn new() -> Self {
        Self {
            sys: Default::default(),
            public: Default::default(),
            tcp: Default::default(),
            tls: Default::default(),
            udp: Mutex::new(UdpEvent {
                udp_v4: true,
                udp_v6: false,
                nat_varies: Some(false),
                quic_relays: 2,
                failed: false,
            }),
            relay: Mutex::new(RelayEvent::Done {
                rtt_ms: 40,
                kib_per_s: Some(900),
            }),
            ws: Mutex::new(WsEvent::Upgraded { rtt_ms: Some(30) }),
            lan: Mutex::new(LanEvent::Seen),
            delay: Duration::ZERO,
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    async fn busy(&self) {
        let n = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Net for Fake {
    async fn system_dns(&self, host: &str, _l: Duration) -> DnsResult {
        self.busy().await;
        self.sys
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .unwrap_or_else(|| Ok(vec![ip(IP)]))
    }
    async fn udp_dns(&self, _r: SocketAddr, host: &str, _l: Duration) -> DnsResult {
        self.busy().await;
        self.public
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .unwrap_or_else(|| Ok(vec![ip(IP)]))
    }
    async fn tcp(&self, _a: SocketAddr, _l: Duration) -> TcpEvent {
        self.busy().await;
        // Keyed by port: a test makes one kind of host fail by its port.
        self.tcp
            .lock()
            .unwrap()
            .get(&_a.port().to_string())
            .cloned()
            .unwrap_or(TcpEvent::Connected)
    }
    async fn tls(&self, _a: SocketAddr, sni: &str, _l: Duration) -> TlsEvent {
        self.busy().await;
        self.tls
            .lock()
            .unwrap()
            .get(sni)
            .cloned()
            .unwrap_or_else(good_cert)
    }
    async fn udp(&self, _l: Duration) -> UdpEvent {
        self.busy().await;
        self.udp.lock().unwrap().clone()
    }
    async fn relay_path(&self, _l: Duration) -> RelayEvent {
        self.busy().await;
        self.relay.lock().unwrap().clone()
    }
    async fn websocket(&self, _a: SocketAddr, _t: &Target, _l: Duration) -> WsEvent {
        self.busy().await;
        self.ws.lock().unwrap().clone()
    }
    async fn lan(&self, _l: Duration) -> LanEvent {
        self.busy().await;
        *self.lan.lock().unwrap()
    }
}

fn opts(user: &[&str]) -> MatrixOptions {
    let settings = IrohSettings {
        mode: IrohMode::N0,
        relay_urls: vec![],
        discovery: true,
        lan_discovery: true,
        connect_timeout: Duration::from_secs(5),
        ca_pem: None,
        proxy_from_env: false,
    };
    MatrixOptions::from_settings(
        &settings,
        user.iter().map(|u| UserProbe::parse(u).unwrap()).collect(),
    )
}

fn find<'a>(r: &'a MatrixReport, id_prefix: &str) -> &'a ProbeResult {
    r.probes
        .iter()
        .find(|p| p.id.starts_with(id_prefix))
        .unwrap_or_else(|| {
            panic!(
                "no row {id_prefix}: {:?}",
                r.probes.iter().map(|p| &p.id).collect::<Vec<_>>()
            )
        })
}

fn codes(r: &MatrixReport) -> Vec<AdviceCode> {
    r.advice.iter().map(|a| a.code).collect()
}

// ─── Pure classification ─────────────────────────────────────────────────────

#[test]
fn dns_every_class_is_reached() {
    let good: DnsResult = Ok(vec![ip("1.2.3.4")]);
    let other: DnsResult = Ok(vec![ip("9.9.9.9")]);
    let timeout: DnsResult = Err(DnsFail::Timeout);
    let nx: DnsResult = Err(DnsFail::NxDomain);
    // Same answer everywhere.
    assert_eq!(
        classify_dns(&good, &[good.clone(), good.clone()]).0,
        Outcome::Ok
    );
    // One public resolver agrees, the other is silent: still fine.
    assert_eq!(
        classify_dns(&good, &[good.clone(), timeout.clone()]).0,
        Outcome::Ok
    );
    // System answer shares nothing with the public ones.
    assert_eq!(
        classify_dns(&other, &[good.clone(), good.clone()]).0,
        Outcome::AnswerDiffers
    );
    // The system resolver says no such name, a public one answers.
    let (o, d) = classify_dns(&nx, &[good.clone(), nx.clone()]);
    assert_eq!(o, Outcome::Nxdomain);
    assert_eq!(d.as_deref(), Some("public_resolvers_answer"));
    // The system resolver answers, public resolvers say no such name.
    assert_eq!(
        classify_dns(&good, &[nx.clone(), nx.clone()]).0,
        Outcome::AnswerDiffers
    );
    // UDP DNS silent to both while the system resolver works.
    assert_eq!(
        classify_dns(&good, &[timeout.clone(), timeout.clone()]).0,
        Outcome::UdpDnsBlocked
    );
    assert_eq!(
        classify_dns(&timeout, &[good.clone(), good.clone()]).0,
        Outcome::Timeout
    );
    assert_eq!(classify_dns(&Err(DnsFail::Other), &[]).0, Outcome::Failed);
    // Only IPv6 from the system resolver: nothing to compare, not a difference.
    let v6: DnsResult = Ok(vec![ip("2001:db8::1")]);
    assert_eq!(classify_dns(&v6, &[good.clone(), good]).0, Outcome::Ok);
}

#[test]
fn tcp_events_map_one_to_one() {
    assert_eq!(classify_tcp(&TcpEvent::Connected), Outcome::Ok);
    assert_eq!(classify_tcp(&TcpEvent::Refused), Outcome::Refused);
    assert_eq!(classify_tcp(&TcpEvent::Reset), Outcome::Reset);
    assert_eq!(classify_tcp(&TcpEvent::Timeout), Outcome::Timeout);
    assert_eq!(classify_tcp(&TcpEvent::Unreachable), Outcome::Unreachable);
    assert_eq!(classify_tcp(&TcpEvent::Other), Outcome::Failed);
}

#[test]
fn tls_events_map_and_report_only_the_issuers_name() {
    assert_eq!(classify_tls(&good_cert()), (Outcome::Ok, true, None));
    let inspected = |trusted| TlsEvent::Cert {
        issuer: "Test Inspection CA".into(),
        public_ca: false,
        trusted,
    };
    let (o, ok, d) = classify_tls(&inspected(false));
    assert_eq!(o, Outcome::NonPublicCa);
    assert!(!ok);
    assert_eq!(
        d.as_deref(),
        Some("issuer=Test Inspection CA; trusted=false")
    );
    let (o, ok, _) = classify_tls(&inspected(true));
    assert_eq!((o, ok), (Outcome::NonPublicCa, true));
    assert_eq!(
        classify_tls(&TlsEvent::Cert {
            issuer: "Public Root".into(),
            public_ca: true,
            trusted: false
        })
        .0,
        Outcome::CertUntrusted
    );
    assert_eq!(classify_tls(&TlsEvent::Reset).0, Outcome::ResetInHandshake);
    assert_eq!(classify_tls(&TlsEvent::Timeout).0, Outcome::Timeout);
    assert_eq!(classify_tls(&TlsEvent::Other).0, Outcome::Failed);
    // An issuer name with control characters or a huge length is cleaned.
    assert_eq!(clean_issuer("a\u{7}b\nc"), "abc");
    assert_eq!(clean_issuer(&"x".repeat(200)).len(), 64);
}

#[test]
fn sni_comparison_says_only_whether_the_two_differ() {
    let (o, d) = classify_sni(&good_cert(), &good_cert());
    assert_eq!((o, d.as_deref()), (Outcome::Ok, Some("both=handshake")));
    let (o, d) = classify_sni(&good_cert(), &TlsEvent::Reset);
    assert_eq!(o, Outcome::SniDiffers);
    assert_eq!(d.as_deref(), Some("real=handshake; neutral=reset"));
    let (o, _) = classify_sni(&TlsEvent::Timeout, &TlsEvent::Timeout);
    assert_eq!(o, Outcome::Ok);
}

#[test]
fn user_probes_parse() {
    let p = UserProbe::parse("wss://Relay.Example/ws/x?token=1")
        .unwrap()
        .0;
    assert_eq!(
        (p.host.as_str(), p.port, p.tls, p.path.as_str()),
        ("relay.example", 443, true, "/ws/x?token=1")
    );
    let p = UserProbe::parse("ws://h.example:8080").unwrap().0;
    assert_eq!((p.port, p.tls, p.path.as_str()), (8080, false, "/"));
    assert_eq!(UserProbe::parse("https://h.example").unwrap().0.port, 443);
    assert!(UserProbe::parse("ftp://h.example").is_err());
    assert!(UserProbe::parse("wss://user:pw@h.example/").is_err());
    assert!(UserProbe::parse("wss://h.example:notaport/").is_err());
    assert!(UserProbe::parse("wss:///path").is_err());
    assert!(UserProbe::parse("wss://bad host/").is_err());
}

#[test]
fn custom_mode_probes_the_configured_relays_and_no_n0_relay() {
    let s = IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec!["https://relay.mine.example:7443/".into(), "nonsense".into()],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(5),
        ca_pem: None,
        proxy_from_env: false,
    };
    let o = MatrixOptions::from_settings(&s, vec![]);
    let relays: Vec<_> = o.targets.iter().filter(|t| t.role == Role::Relay).collect();
    assert_eq!(relays.len(), 1);
    assert_eq!(
        (relays[0].host.as_str(), relays[0].port),
        ("relay.mine.example", 7443)
    );
    assert!(o.custom_relays);
    assert!(!o.targets.iter().any(|t| t.role == Role::Discovery));
    let off = MatrixOptions::from_settings(
        &IrohSettings {
            mode: IrohMode::Off,
            ..s
        },
        vec![],
    );
    assert!(!off.run_iroh);
    assert!(!off.targets.iter().any(|t| t.role == Role::Relay));
}

// ─── The whole run, with fakes ───────────────────────────────────────────────

#[tokio::test]
async fn an_open_network_works_everywhere() {
    let net = Fake::new();
    let r = run_matrix(&net, &opts(&["wss://ep.example/x"])).await;
    assert_eq!(r.schema, SCHEMA_VERSION);
    assert!(
        r.probes.iter().all(|p| p.ok),
        "{:?}",
        r.probes.iter().filter(|p| !p.ok).collect::<Vec<_>>()
    );
    let c = codes(&r);
    assert!(c.contains(&AdviceCode::RelayObserved));
    assert!(c.contains(&AdviceCode::DirectUdpObserved));
    assert!(c.contains(&AdviceCode::LanObserved));
    assert!(c.contains(&AdviceCode::TunnelObserved));
    assert!(c.contains(&AdviceCode::CustomEndpointObserved));
    assert!(!c.contains(&AdviceCode::NothingObserved));
    let rel = find(&r, "relay:relay:iroh-relay");
    assert_eq!((rel.rtt_ms, rel.kib_per_s), (Some(40), Some(900)));
    assert_eq!(find(&r, "sni:").outcome, Outcome::Ok);
    // Ids are unique and the order is the same on a second run.
    let mut ids: Vec<_> = r.probes.iter().map(|p| p.id.clone()).collect();
    let again: Vec<_> = run_matrix(&net, &opts(&["wss://ep.example/x"]))
        .await
        .probes
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(ids, again);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), r.probes.len());
}

#[tokio::test]
async fn a_tampered_dns_answer_is_reported_and_advised_on() {
    let net = Fake::new();
    net.sys.lock().unwrap().insert(
        "use1-1.relay.n0.iroh.link".into(),
        Ok(vec![ip("198.51.100.99")]),
    );
    let r = run_matrix(&net, &opts(&[])).await;
    let d = find(&r, "dns:relay:use1-1.relay.n0.iroh.link");
    assert_eq!(d.outcome, Outcome::AnswerDiffers);
    assert!(!d.ok);
    assert!(codes(&r).contains(&AdviceCode::DnsProblem));
    // The other relay is fine, so a relay is still observed.
    assert!(codes(&r).contains(&AdviceCode::RelayObserved));
}

#[tokio::test]
async fn nxdomain_and_udp_dns_blocking_are_told_apart() {
    let net = Fake::new();
    net.sys
        .lock()
        .unwrap()
        .insert("dns.iroh.link".into(), Err(DnsFail::NxDomain));
    net.public
        .lock()
        .unwrap()
        .insert("dns.iroh.link".into(), Err(DnsFail::NxDomain));
    net.public
        .lock()
        .unwrap()
        .insert("example.com".into(), Err(DnsFail::Timeout));
    let r = run_matrix(&net, &opts(&[])).await;
    assert_eq!(find(&r, "dns:discovery:").outcome, Outcome::Nxdomain);
    assert_eq!(
        find(&r, "dns:neutral:example.com").outcome,
        Outcome::UdpDnsBlocked
    );
    // UDP DNS being blocked is information, not a failure of the path.
    assert!(find(&r, "dns:neutral:example.com").ok);
    // No address, so the discovery host has no TCP row that worked.
    assert_eq!(find(&r, "tcp:discovery:").outcome, Outcome::Skipped);
    assert!(codes(&r).contains(&AdviceCode::DiscoveryNotObserved));
}

#[tokio::test]
async fn the_system_resolver_failing_falls_back_to_the_public_answer() {
    let net = Fake::new();
    net.sys
        .lock()
        .unwrap()
        .insert("use1-1.relay.n0.iroh.link".into(), Err(DnsFail::Timeout));
    let r = run_matrix(&net, &opts(&[])).await;
    assert_eq!(
        find(&r, "dns:relay:use1-1.relay.n0.iroh.link").outcome,
        Outcome::Timeout
    );
    let t = find(&r, "tcp:relay:use1-1.relay.n0.iroh.link");
    assert!(t.ok);
    assert_eq!(t.detail.as_deref(), Some("address_from_public_resolver"));
}

#[tokio::test]
async fn a_handshake_cut_is_told_from_a_closed_port_and_the_sni_is_compared() {
    let net = Fake::new();
    {
        let mut tls = net.tls.lock().unwrap();
        // Real names are cut, the neutral name goes through.
        tls.insert("use1-1.relay.n0.iroh.link".into(), TlsEvent::Reset);
        tls.insert("aps1-1.relay.n0.iroh.link".into(), TlsEvent::Timeout);
    }
    *net.relay.lock().unwrap() = RelayEvent::Failed;
    let r = run_matrix(&net, &opts(&[])).await;
    assert_eq!(
        find(&r, "tls:relay:use1-1.relay.n0.iroh.link").outcome,
        Outcome::ResetInHandshake
    );
    assert_eq!(
        find(&r, "tls:relay:aps1-1.relay.n0.iroh.link").outcome,
        Outcome::Timeout
    );
    let sni = find(&r, "sni:");
    assert_eq!(sni.outcome, Outcome::SniDiffers);
    assert_eq!(sni.detail.as_deref(), Some("real=reset; neutral=handshake"));
    assert!(codes(&r).contains(&AdviceCode::HandshakeCut));
    assert!(!codes(&r).contains(&AdviceCode::RelayObserved));
}

#[tokio::test]
async fn a_refused_port_is_not_a_handshake_problem() {
    let net = Fake::new();
    net.tcp
        .lock()
        .unwrap()
        .insert("443".into(), TcpEvent::Refused);
    let r = run_matrix(&net, &opts(&[])).await;
    assert!(r
        .probes
        .iter()
        .filter(|p| p.group == Group::Tcp)
        .all(|p| p.outcome == Outcome::Refused));
    // Without a reachable address nothing is handshaken or transferred.
    assert!(r
        .probes
        .iter()
        .filter(|p| p.group == Group::Tls)
        .all(|p| p.outcome == Outcome::Skipped));
    let rel = find(&r, "relay:relay:iroh-relay");
    assert_eq!(rel.outcome, Outcome::Skipped);
    assert_eq!(rel.detail.as_deref(), Some("relay_unreachable"));
    assert!(!codes(&r).contains(&AdviceCode::HandshakeCut));
}

#[tokio::test]
async fn a_resigned_certificate_names_its_issuer_and_suggests_the_ca_setting() {
    let net = Fake::new();
    net.tls.lock().unwrap().insert(
        "use1-1.relay.n0.iroh.link".into(),
        TlsEvent::Cert {
            issuer: "Test Inspection CA".into(),
            public_ca: false,
            trusted: false,
        },
    );
    let r = run_matrix(&net, &opts(&[])).await;
    let t = find(&r, "tls:relay:use1-1.relay.n0.iroh.link");
    assert_eq!(t.outcome, Outcome::NonPublicCa);
    assert_eq!(
        t.detail.as_deref(),
        Some("issuer=Test Inspection CA; trusted=false")
    );
    let a = r
        .advice
        .iter()
        .find(|a| a.code == AdviceCode::TlsInspectedUntrusted)
        .expect("advice");
    assert_eq!(a.config_keys, vec!["transport.iroh_extra_ca_pem"]);
}

#[tokio::test]
async fn udp_blocked_with_a_working_relay_says_relay_only() {
    let net = Fake::new();
    *net.udp.lock().unwrap() = UdpEvent::default();
    let r = run_matrix(&net, &opts(&[])).await;
    assert_eq!(find(&r, "udp:").outcome, Outcome::UdpBlocked);
    assert_eq!(find(&r, "quic:").outcome, Outcome::UdpBlocked);
    let c = codes(&r);
    assert!(c.contains(&AdviceCode::UdpNotObserved));
    assert!(!c.contains(&AdviceCode::DirectUdpObserved));
}

#[tokio::test]
async fn a_user_endpoint_is_tested_like_the_relay_and_can_be_the_only_way_out() {
    let net = Fake::new();
    // Every n0 host is cut at the handshake; the user's own endpoint is not.
    {
        let mut tls = net.tls.lock().unwrap();
        for h in [
            "use1-1.relay.n0.iroh.link",
            "aps1-1.relay.n0.iroh.link",
            "dns.iroh.link",
        ] {
            tls.insert(h.into(), TlsEvent::Reset);
        }
    }
    *net.relay.lock().unwrap() = RelayEvent::Failed;
    let r = run_matrix(&net, &opts(&["wss://mine.example:8443/ws"])).await;
    let ws = find(&r, "relay:custom:mine.example");
    assert!(ws.ok);
    assert_eq!(ws.rtt_ms, Some(30));
    assert_eq!(find(&r, "tcp:custom:mine.example").outcome, Outcome::Ok);
    let c = codes(&r);
    assert!(c.contains(&AdviceCode::CustomEndpointObserved));
    assert!(c.contains(&AdviceCode::HandshakeCut));
    // The path to the user's host is reported by name only.
    assert!(!serde_json::to_string(&r).unwrap().contains("/ws"));
}

#[tokio::test]
async fn a_user_endpoint_that_resets_is_classified() {
    let net = Fake::new();
    *net.ws.lock().unwrap() = WsEvent::Reset;
    let r = run_matrix(&net, &opts(&["wss://mine.example/ws"])).await;
    assert_eq!(
        find(&r, "relay:custom:mine.example").outcome,
        Outcome::ResetInHandshake
    );
    assert!(codes(&r).contains(&AdviceCode::CustomEndpointNotObserved));
}

#[tokio::test]
async fn nothing_working_is_said_plainly() {
    let net = Fake::new();
    for h in [
        "use1-1.relay.n0.iroh.link",
        "aps1-1.relay.n0.iroh.link",
        "dns.iroh.link",
        "api.trycloudflare.com",
        "example.com",
        "www.wikipedia.org",
        "one.one.one.one",
    ] {
        net.sys
            .lock()
            .unwrap()
            .insert(h.into(), Err(DnsFail::Timeout));
        net.public
            .lock()
            .unwrap()
            .insert(h.into(), Err(DnsFail::Timeout));
    }
    *net.lan.lock().unwrap() = LanEvent::NotSeen;
    *net.udp.lock().unwrap() = UdpEvent {
        failed: true,
        ..Default::default()
    };
    let r = run_matrix(&net, &opts(&[])).await;
    let c = codes(&r);
    assert!(c.contains(&AdviceCode::NothingObserved), "{c:?}");
    assert!(c.contains(&AdviceCode::TunnelNotObserved));
    assert!(c.contains(&AdviceCode::LanNotObserved));
    assert!(!c.contains(&AdviceCode::RelayObserved));
}

#[tokio::test]
async fn at_most_four_probes_run_at_once_and_the_run_stays_in_budget() {
    let mut net = Fake::new();
    net.delay = Duration::from_millis(15);
    let started = Instant::now();
    let r = run_matrix(&net, &opts(&["wss://a.example/x", "wss://b.example/y"])).await;
    assert!(net.peak.load(Ordering::SeqCst) <= MAX_CONCURRENCY);
    assert!(
        net.peak.load(Ordering::SeqCst) >= 2,
        "no concurrency at all"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(r.elapsed_ms < 10_000);

    // A budget that is far too small: every call that has not started is
    // skipped, and the run still ends.
    let mut slow = Fake::new();
    slow.delay = Duration::from_millis(200);
    let mut o = opts(&[]);
    o.budget = Duration::from_millis(100);
    let started = Instant::now();
    let r = run_matrix(&slow, &o).await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(r
        .probes
        .iter()
        .any(|p| p.detail.as_deref() == Some("time_budget") || p.outcome == Outcome::Skipped));
}

#[tokio::test]
async fn the_report_names_no_address_and_no_unprobed_host() {
    let net = Fake::new();
    net.sys.lock().unwrap().insert(
        "mine.example".into(),
        Ok(vec![ip("203.0.113.77"), ip("2001:db8::77")]),
    );
    let r = run_matrix(&net, &opts(&["wss://mine.example/secret-path?token=abc"])).await;
    let json = serde_json::to_string_pretty(&r).unwrap();
    for needle in ["203.0.113", "2001:db8", "secret-path", "token", "127.0.0.1"] {
        assert!(!json.contains(needle), "{needle} leaked: {json}");
    }
    let hosts: std::collections::BTreeSet<&str> =
        r.probes.iter().map(|p| p.target.as_str()).collect();
    let allowed = [
        "use1-1.relay.n0.iroh.link",
        "aps1-1.relay.n0.iroh.link",
        "dns.iroh.link",
        "api.trycloudflare.com",
        "example.com",
        "www.wikipedia.org",
        "one.one.one.one",
        "mine.example",
        "iroh-relay",
        "udp",
        "quic",
        "mdns",
    ];
    for h in hosts {
        assert!(allowed.contains(&h), "unexpected target {h}");
    }
}

// ─── The JSON layout ─────────────────────────────────────────────────────────

#[test]
fn the_json_layout_is_stable() {
    let report = MatrixReport {
        schema: SCHEMA_VERSION,
        iroh_mode: "n0".into(),
        elapsed_ms: 1234,
        probes: vec![
            ProbeResult {
                id: "tls:relay:relay.example".into(),
                group: Group::Tls,
                role: Role::Relay,
                target: "relay.example".into(),
                ok: false,
                outcome: Outcome::NonPublicCa,
                millis: Some(87),
                rtt_ms: None,
                kib_per_s: None,
                detail: Some("issuer=Test Inspection CA; trusted=false".into()),
            },
            ProbeResult {
                id: "relay:relay:iroh-relay".into(),
                group: Group::Relay,
                role: Role::Relay,
                target: "iroh-relay".into(),
                ok: true,
                outcome: Outcome::Ok,
                millis: Some(900),
                rtt_ms: Some(41),
                kib_per_s: Some(512),
                detail: None,
            },
        ],
        advice: vec![Advice {
            code: AdviceCode::TlsInspectedUntrusted,
            config_keys: vec!["transport.iroh_extra_ca_pem"],
        }],
    };
    let expected = r#"{
  "schema": 1,
  "iroh_mode": "n0",
  "elapsed_ms": 1234,
  "probes": [
    {
      "id": "tls:relay:relay.example",
      "group": "tls",
      "role": "relay",
      "target": "relay.example",
      "ok": false,
      "outcome": "non_public_ca",
      "millis": 87,
      "rtt_ms": null,
      "kib_per_s": null,
      "detail": "issuer=Test Inspection CA; trusted=false"
    },
    {
      "id": "relay:relay:iroh-relay",
      "group": "relay",
      "role": "relay",
      "target": "iroh-relay",
      "ok": true,
      "outcome": "ok",
      "millis": 900,
      "rtt_ms": 41,
      "kib_per_s": 512,
      "detail": null
    }
  ],
  "advice": [
    {
      "code": "tls_inspected_untrusted",
      "config_keys": [
        "transport.iroh_extra_ca_pem"
      ]
    }
  ]
}"#;
    assert_eq!(serde_json::to_string_pretty(&report).unwrap(), expected);
}

#[test]
fn every_enum_value_has_a_stable_snake_case_name() {
    for o in Outcome::ALL {
        let j = serde_json::to_string(&o).unwrap();
        assert!(
            j.chars()
                .all(|c| c == '"' || c == '_' || c.is_ascii_lowercase()),
            "{j}"
        );
    }
    for g in Group::ALL {
        assert_eq!(
            serde_json::to_string(&g).unwrap(),
            format!("\"{}\"", g.as_str())
        );
    }
    for r in Role::ALL {
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            format!("\"{}\"", r.as_str())
        );
    }
    // The lists are complete: a new variant breaks one of these matches.
    for o in Outcome::ALL {
        match o {
            Outcome::Ok
            | Outcome::Nxdomain
            | Outcome::Timeout
            | Outcome::AnswerDiffers
            | Outcome::UdpDnsBlocked
            | Outcome::Refused
            | Outcome::Reset
            | Outcome::Unreachable
            | Outcome::ResetInHandshake
            | Outcome::NonPublicCa
            | Outcome::CertUntrusted
            | Outcome::SniDiffers
            | Outcome::UdpBlocked
            | Outcome::Failed
            | Outcome::Skipped => {}
        }
    }
}
