//! The real network calls behind the reachability matrix ([`super::reach::Net`]).
//!
//! Each call is one ordinary connection attempt with its own time limit and
//! reduces what happened to a small event; the judging is in [`super::reach`].
//! Nothing here sends user data: the relay round trip is between two throw-away
//! endpoints created for it, with keys that live as long as the probe.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use iroh::{endpoint::presets::Minimal, tls::CaTlsConfig, Endpoint, RelayMode, Watcher};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use rustls::pki_types::ServerName;
use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
};

use super::{
    iroh_direct::{ca_tls_config, endpoint_builder, parse_ca_roots, IrohSettings},
    reach::{
        DnsFail, DnsResult, LanEvent, Net, RelayEvent, Target, TcpEvent, TlsEvent, UdpEvent,
        WsEvent,
    },
    reach_dns::{build_query, parse_reply, DnsReply},
    relay_tls::{handshake, HandshakeEnd},
};

/// ALPN of the throw-away relay round trip. Not served by the daemon.
const REACH_ALPN: &[u8] = b"miasma/reach-probe/1";
/// Bytes sent through the relay for the rate measurement.
const TRANSFER_BYTES: usize = 1024 * 1024;

/// The real network.
pub struct SystemNet {
    settings: IrohSettings,
    tls: CaTlsConfig,
}

impl SystemNet {
    /// Uses the same trust settings as the daemon (OS store plus the extra CA).
    pub fn new(settings: IrohSettings) -> Self {
        let extra = match &settings.ca_pem {
            Some(pem) => parse_ca_roots(pem).unwrap_or_default(),
            None => Vec::new(),
        };
        Self {
            tls: ca_tls_config(extra),
            settings,
        }
    }

    /// The settings without anything that talks to a discovery service or the
    /// local network: the probes want the relay and nothing else.
    fn quiet_settings(&self) -> IrohSettings {
        let mut s = self.settings.clone();
        s.discovery = false;
        s.lan_discovery = false;
        s
    }
}

/// Whether a failed system lookup means "no such name" (as opposed to a broken
/// resolver). The text is the platform's: WSAHOST_NOT_FOUND / WSANO_DATA on
/// Windows, `EAI_NONAME` / `EAI_NODATA` elsewhere.
pub fn lookup_error_is_nxdomain(e: &io::Error) -> bool {
    if matches!(e.raw_os_error(), Some(11001) | Some(11004)) {
        return true;
    }
    let t = e.to_string().to_ascii_lowercase();
    [
        "not known",
        "no such host",
        "host not found",
        "nodename nor servname",
        "no address associated",
        "name or service not known",
        "11001",
        "11004",
    ]
    .iter()
    .any(|m| t.contains(m))
}

/// How a failed connect is classified.
pub fn tcp_event_from_io(e: &io::Error) -> TcpEvent {
    use io::ErrorKind as K;
    // Windows: WSAENETUNREACH 10051, WSAEHOSTUNREACH 10065, WSAECONNREFUSED
    // 10061, WSAECONNRESET 10054, WSAECONNABORTED 10053. Unix: ENETUNREACH 101,
    // EHOSTUNREACH 113.
    match e.raw_os_error() {
        Some(10051) | Some(10065) | Some(101) | Some(113) => return TcpEvent::Unreachable,
        Some(10061) => return TcpEvent::Refused,
        Some(10054) | Some(10053) => return TcpEvent::Reset,
        _ => {}
    }
    match e.kind() {
        K::ConnectionRefused => TcpEvent::Refused,
        K::ConnectionReset | K::ConnectionAborted => TcpEvent::Reset,
        K::TimedOut => TcpEvent::Timeout,
        K::NetworkUnreachable | K::HostUnreachable => TcpEvent::Unreachable,
        _ => TcpEvent::Other,
    }
}

fn ws_event_from_io(e: &io::Error) -> WsEvent {
    match tcp_event_from_io(e) {
        TcpEvent::Refused => WsEvent::Refused,
        TcpEvent::Reset => WsEvent::Reset,
        TcpEvent::Timeout => WsEvent::Timeout,
        _ => match e.kind() {
            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe => WsEvent::Reset,
            _ => WsEvent::Other,
        },
    }
}

#[async_trait]
impl Net for SystemNet {
    async fn system_dns(&self, host: &str, limit: Duration) -> DnsResult {
        match tokio::time::timeout(limit, tokio::net::lookup_host((host, 0))).await {
            Err(_) => Err(DnsFail::Timeout),
            Ok(Err(e)) if lookup_error_is_nxdomain(&e) => Err(DnsFail::NxDomain),
            Ok(Err(_)) => Err(DnsFail::Other),
            Ok(Ok(addrs)) => {
                let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                ips.sort();
                ips.dedup();
                Ok(ips)
            }
        }
    }

    async fn udp_dns(&self, resolver: SocketAddr, host: &str, limit: Duration) -> DnsResult {
        let id: u16 = rand::random();
        let query = build_query(id, host).map_err(|_| DnsFail::Other)?;
        let bind: SocketAddr = if resolver.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await.map_err(|_| DnsFail::Other)?;
        sock.send_to(&query, resolver)
            .await
            .map_err(|_| DnsFail::Other)?;
        let wait = async {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.ok()?;
                // Only the resolver asked, and only an answer to this query.
                if from != resolver {
                    continue;
                }
                match parse_reply(id, &buf[..n]) {
                    Ok(reply) => return Some(reply),
                    Err(_) => continue,
                }
            }
        };
        match tokio::time::timeout(limit, wait).await {
            Err(_) | Ok(None) => Err(DnsFail::Timeout),
            Ok(Some(DnsReply::Answer(v))) => Ok(v.into_iter().map(IpAddr::V4).collect()),
            Ok(Some(DnsReply::NxDomain)) => Err(DnsFail::NxDomain),
            Ok(Some(DnsReply::ServerFailure(_))) => Err(DnsFail::Other),
        }
    }

    async fn tcp(&self, addr: SocketAddr, limit: Duration) -> TcpEvent {
        match tokio::time::timeout(limit, TcpStream::connect(addr)).await {
            Err(_) => TcpEvent::Timeout,
            Ok(Ok(_)) => TcpEvent::Connected,
            Ok(Err(e)) => tcp_event_from_io(&e),
        }
    }

    async fn tls(&self, addr: SocketAddr, sni: &str, limit: Duration) -> TlsEvent {
        match handshake(addr, sni, &self.tls, limit).await {
            HandshakeEnd::Certificate(c) => TlsEvent::Cert {
                issuer: c.issuer,
                public_ca: c.public_ca,
                trusted: c.trusted,
            },
            HandshakeEnd::Reset => TlsEvent::Reset,
            HandshakeEnd::Timeout => TlsEvent::Timeout,
            HandshakeEnd::Other(_) => TlsEvent::Other,
        }
    }

    async fn udp(&self, limit: Duration) -> UdpEvent {
        let failed = UdpEvent {
            failed: true,
            ..Default::default()
        };
        let Ok(builder) = endpoint_builder(None, &self.quiet_settings(), false) else {
            return failed;
        };
        let Ok(endpoint) = builder.bind().await else {
            return failed;
        };
        let report = tokio::time::timeout(limit, endpoint.net_report().initialized())
            .await
            .ok();
        endpoint.close().await;
        let Some(r) = report else {
            return failed;
        };
        use iroh::unstable_net_report::Probe;
        let mut quic: Vec<String> = r
            .relay_latency
            .iter()
            .filter(|(p, _, _)| !matches!(p, Probe::Https))
            .map(|(_, url, _)| url.to_string())
            .collect();
        quic.sort();
        quic.dedup();
        UdpEvent {
            udp_v4: r.udp_v4,
            udp_v6: r.udp_v6,
            nat_varies: r.mapping_varies_by_dest(),
            quic_relays: quic.len(),
            failed: false,
        }
    }

    async fn relay_path(&self, limit: Duration) -> RelayEvent {
        // Leave a second to report what was measured before the hard stop.
        let inner_deadline = Instant::now() + limit.saturating_sub(Duration::from_secs(1));
        match tokio::time::timeout(
            limit,
            relay_round_trip(&self.quiet_settings(), inner_deadline),
        )
        .await
        {
            Err(_) => RelayEvent::Timeout,
            Ok(Ok(ev)) => ev,
            Ok(Err(_)) => RelayEvent::Failed,
        }
    }

    async fn websocket(&self, addr: SocketAddr, target: &Target, limit: Duration) -> WsEvent {
        match tokio::time::timeout(limit, self.ws_upgrade(addr, target, limit)).await {
            Err(_) => WsEvent::Timeout,
            Ok(ev) => ev,
        }
    }

    async fn lan(&self, limit: Duration) -> LanEvent {
        match tokio::time::timeout(limit, lan_round_trip()).await {
            Err(_) => LanEvent::NotSeen,
            Ok(ev) => ev,
        }
    }
}

impl SystemNet {
    async fn ws_upgrade(&self, addr: SocketAddr, t: &Target, limit: Duration) -> WsEvent {
        let started = Instant::now();
        let tcp = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => return ws_event_from_io(&e),
        };
        let url = format!(
            "{}://{}:{}{}",
            if t.tls { "wss" } else { "ws" },
            t.host,
            t.port,
            t.path
        );
        let rest = |started: Instant| {
            limit
                .saturating_sub(started.elapsed())
                .min(Duration::from_secs(3))
        };
        if !t.tls {
            return upgrade_and_ping(url, tcp, rest(started)).await;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let Ok(verifier) = self.tls.server_cert_verifier(provider.clone()) else {
            return WsEvent::Other;
        };
        let Ok(builder) = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        else {
            return WsEvent::Other;
        };
        let cfg = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let Ok(name) = ServerName::try_from(t.host.clone()) else {
            return WsEvent::Other;
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        match connector.connect(name, tcp).await {
            Ok(stream) => upgrade_and_ping(url, stream, rest(started)).await,
            Err(e) => ws_event_from_io(&e),
        }
    }
}

/// The WebSocket upgrade on an open stream, then a ping any server must
/// answer; the time to the pong is the round trip.
async fn upgrade_and_ping<S>(url: String, stream: S, ping_limit: Duration) -> WsEvent
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as WsError, Message};
    let mut ws = match tokio_tungstenite::client_async(url, stream).await {
        Ok((ws, _)) => ws,
        Err(WsError::Io(e)) => return ws_event_from_io(&e),
        Err(WsError::Http(_)) | Err(WsError::HttpFormat(_)) => return WsEvent::Refused,
        Err(_) => return WsEvent::Other,
    };
    let t0 = Instant::now();
    let pong = async {
        ws.send(Message::Ping(vec![0x6d, 0x72])).await.ok()?;
        while let Some(m) = ws.next().await {
            if let Message::Pong(_) = m.ok()? {
                return Some(t0.elapsed().as_millis() as u64);
            }
        }
        None
    };
    let rtt_ms = tokio::time::timeout(ping_limit, pong).await.ok().flatten();
    WsEvent::Upgraded { rtt_ms }
}

/// Two relay-only endpoints, one dialling the other through the relay: a round
/// trip, then 1 MiB. Neither has an IP transport, so no direct path can form
/// and the numbers are the relay's.
async fn relay_round_trip(
    settings: &IrohSettings,
    deadline: Instant,
) -> Result<RelayEvent, String> {
    let client = endpoint_builder(None, settings, false)
        .map_err(|e| e.to_string())?
        .clear_ip_transports()
        .bind()
        .await
        .map_err(|e| e.to_string())?;
    let seed: [u8; 32] = rand::random();
    let server = endpoint_builder(Some(&seed), settings, false)
        .map_err(|e| e.to_string())?
        .clear_ip_transports()
        .alpns(vec![REACH_ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| e.to_string())?;
    let result = relay_exchange(&client, &server, deadline).await;
    client.close().await;
    server.close().await;
    result
}

async fn relay_exchange(
    client: &Endpoint,
    server: &Endpoint,
    deadline: Instant,
) -> Result<RelayEvent, String> {
    server.online().await;
    let addr = server.addr();
    let srv = server.clone();
    let echo = tokio::spawn(async move {
        let incoming = srv.accept().await?;
        let conn = incoming.await.ok()?;
        let (mut tx, mut rx) = conn.accept_bi().await.ok()?;
        let mut one = [0u8; 1];
        rx.read_exact(&mut one).await.ok()?;
        tx.write_all(&one).await.ok()?;
        let mut sink = Vec::with_capacity(TRANSFER_BYTES);
        rx.take(2 * TRANSFER_BYTES as u64)
            .read_to_end(&mut sink)
            .await
            .ok()?;
        tx.write_all(&[1]).await.ok()?;
        tx.finish().ok()?;
        // Wait for the client to be done before the connection is dropped.
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
        Some(())
    });
    let left = |d: Instant| d.saturating_duration_since(Instant::now());
    let conn = tokio::time::timeout(left(deadline), client.connect(addr, REACH_ALPN))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    tx.write_all(&[1]).await.map_err(|e| e.to_string())?;
    let mut one = [0u8; 1];
    tokio::time::timeout(left(deadline), rx.read_exact(&mut one))
        .await
        .map_err(|_| "no echo".to_owned())?
        .map_err(|e| e.to_string())?;
    let rtt_ms = t0.elapsed().as_millis() as u64;
    // The rate, if the rest fits in the time left.
    let t1 = Instant::now();
    let payload = vec![0x5Au8; TRANSFER_BYTES];
    let transfer = async {
        tx.write_all(&payload).await.map_err(|e| e.to_string())?;
        tx.finish().map_err(|e| e.to_string())?;
        let mut ack = [0u8; 1];
        rx.read_exact(&mut ack).await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    };
    let kib_per_s = match tokio::time::timeout(left(deadline), transfer).await {
        Ok(Ok(())) => {
            let secs = t1.elapsed().as_secs_f64().max(0.001);
            Some(((TRANSFER_BYTES as f64 / 1024.0) / secs) as u64)
        }
        _ => None,
    };
    conn.close(0u32.into(), b"done");
    echo.abort();
    Ok(RelayEvent::Done { rtt_ms, kib_per_s })
}

/// One endpoint announces itself on the local network, another looks it up.
async fn lan_round_trip() -> LanEvent {
    const SERVICE: &str = "miasma-reach-probe";
    let build = |advertise: bool| async move {
        Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .address_lookup(
                MdnsAddressLookup::builder()
                    .advertise(advertise)
                    .service_name(SERVICE),
            )
            .bind()
            .await
    };
    let Ok(announcer) = build(true).await else {
        return LanEvent::Failed;
    };
    let Ok(browser) = build(false).await else {
        announcer.close().await;
        return LanEvent::Failed;
    };
    let id = announcer.id();
    let seen = match browser.address_lookup() {
        Ok(lookup) => {
            let mut stream = Box::pin(lookup.resolve(id));
            let mut seen = false;
            while let Some(item) = stream.next().await {
                if matches!(item, Ok(Ok(_))) {
                    seen = true;
                    break;
                }
            }
            seen
        }
        Err(_) => {
            announcer.close().await;
            browser.close().await;
            return LanEvent::Failed;
        }
    };
    announcer.close().await;
    browser.close().await;
    if seen {
        LanEvent::Seen
    } else {
        LanEvent::NotSeen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_errors_that_mean_no_such_name() {
        assert!(lookup_error_is_nxdomain(&io::Error::from_raw_os_error(
            11001
        )));
        assert!(lookup_error_is_nxdomain(&io::Error::new(
            io::ErrorKind::Other,
            "failed to lookup address information: Name or service not known"
        )));
        assert!(!lookup_error_is_nxdomain(&io::Error::new(
            io::ErrorKind::Other,
            "failed to lookup address information: Temporary failure in name resolution"
        )));
        assert!(!lookup_error_is_nxdomain(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
    }

    #[test]
    fn connect_errors_are_told_apart() {
        use io::ErrorKind as K;
        assert_eq!(
            tcp_event_from_io(&io::Error::from(K::ConnectionRefused)),
            TcpEvent::Refused
        );
        assert_eq!(
            tcp_event_from_io(&io::Error::from(K::ConnectionReset)),
            TcpEvent::Reset
        );
        assert_eq!(
            tcp_event_from_io(&io::Error::from(K::TimedOut)),
            TcpEvent::Timeout
        );
        assert_eq!(
            tcp_event_from_io(&io::Error::from(K::NetworkUnreachable)),
            TcpEvent::Unreachable
        );
        assert_eq!(
            tcp_event_from_io(&io::Error::from_raw_os_error(10065)),
            TcpEvent::Unreachable
        );
        assert_eq!(
            tcp_event_from_io(&io::Error::from_raw_os_error(10061)),
            TcpEvent::Refused
        );
        assert_eq!(
            tcp_event_from_io(&io::Error::from(K::InvalidInput)),
            TcpEvent::Other
        );
    }
}
