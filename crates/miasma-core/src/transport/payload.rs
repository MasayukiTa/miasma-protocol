/// Payload transport layer — separates discovery-plane from data-plane.
///
/// # Architecture
/// ```text
///                        ┌─────────────────────────┐
///                        │  RetrievalCoordinator    │
///                        └─────────┬───────────────┘
///                                  │ ShareSource::fetch(locator)
///                        ┌─────────▼───────────────┐
///                        │  FallbackShareFetcher    │
///                        │  (payload transport)     │
///                        └─────────┬───────────────┘
///                  tries each transport in order:
///          ┌───────────────┼──────────────┬──────────────┐
///          ▼               ▼              ▼              ▼
///   DirectLibp2p     TcpDirect      WssTunnel     RelayHop
///   (QUIC+TCP via    (raw TCP,      (WSS/443,     (libp2p
///    libp2p swarm)    no libp2p)     innocuous     relay via
///                                    SNI)          DCUtR)
/// ```
///
/// # Transport matrix
///
/// | Transport       | Layer     | DPI-resistant | NAT traversal | Status    |
/// |-----------------|-----------|---------------|---------------|-----------|
/// | DirectLibp2p    | QUIC+TCP  | No            | AutoNAT+DCUtR | Active    |
/// | TcpDirect       | TCP       | No            | No            | Active    |
/// | WssTunnel       | WSS/443   | Yes (SNI)     | Via proxy     | Phase 2.1 |
/// | RelayHop        | Relay     | Partial       | Yes           | Active    |
/// | ObfuscatedQuic  | QUIC      | Yes (REALITY) | No            | Phase 2.1 |
///
/// # Failure signals
///
/// Each transport attempt records a `TransportAttempt` with:
/// - Transport name
/// - Phase (session / data)
/// - Error reason (if failed)
/// - Duration
///
/// The `FallbackShareFetcher` tries transports in configured order,
/// stops on first success, and returns all attempts for observability.
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::share::MiasmaShare;

// ─── Transport identification ────────────────────────────────────────────────

/// Identifies which transport carried (or attempted to carry) a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadTransportKind {
    /// libp2p native: QUIC + TCP + yamux, via the Swarm's request-response protocol.
    DirectLibp2p,
    /// Raw TCP connection (no libp2p framing). For environments where
    /// QUIC is blocked but TCP on high ports works.
    TcpDirect,
    /// WebSocket-over-TLS on port 443 with an innocuous SNI.
    /// DPI sees ordinary HTTPS/WSS traffic.
    WssTunnel,
    /// libp2p relay hop via a relay node (DCUtR / circuit relay v2).
    RelayHop,
    /// REALITY-style obfuscated QUIC. Active-probing resistant.
    ObfuscatedQuic,
}

impl fmt::Display for PayloadTransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectLibp2p => write!(f, "direct-libp2p"),
            Self::TcpDirect => write!(f, "tcp-direct"),
            Self::WssTunnel => write!(f, "wss-tunnel"),
            Self::RelayHop => write!(f, "relay-hop"),
            Self::ObfuscatedQuic => write!(f, "obfuscated-quic"),
        }
    }
}

// ─── Transport attempt record ────────────────────────────────────────────────

/// Phase of the transport attempt that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPhase {
    /// Transport session could not be established (connection refused, timeout, etc.)
    Session,
    /// Session established but payload transfer failed (incomplete read, protocol error).
    Data,
}

impl fmt::Display for TransportPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session => write!(f, "session"),
            Self::Data => write!(f, "data"),
        }
    }
}

/// Record of a single transport attempt (success or failure).
#[derive(Debug, Clone)]
pub struct TransportAttempt {
    pub transport: PayloadTransportKind,
    pub succeeded: bool,
    pub phase: TransportPhase,
    pub error: Option<String>,
    pub duration: Duration,
}

impl fmt::Display for TransportAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.succeeded {
            write!(f, "{}: OK ({:?})", self.transport, self.duration)
        } else {
            write!(
                f,
                "{}: FAILED at {} — {} ({:?})",
                self.transport,
                self.phase,
                self.error.as_deref().unwrap_or("unknown"),
                self.duration
            )
        }
    }
}

// ─── Fetch result with transport metadata ────────────────────────────────────

/// Result of a share fetch that includes transport observability data.
#[derive(Debug)]
pub struct TransportedShare {
    pub share: MiasmaShare,
    /// Which transport carried this share.
    pub transport_used: PayloadTransportKind,
    /// All transport attempts (including failures before the successful one).
    pub attempts: Vec<TransportAttempt>,
}

/// Error that includes all transport attempts for diagnostics.
#[derive(Debug)]
pub struct TransportExhaustedError {
    pub attempts: Vec<TransportAttempt>,
}

impl fmt::Display for TransportExhaustedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "all {} payload transports failed:", self.attempts.len())?;
        for a in &self.attempts {
            write!(f, "\n  {a}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TransportExhaustedError {}

// ─── PayloadTransport trait ──────────────────────────────────────────────────

/// A single strategy for fetching a share from a remote peer.
///
/// Unlike `PluggableTransport` (which is a raw byte-stream abstraction),
/// `PayloadTransport` operates at the share-fetch level: given a peer
/// address and a share request, it returns a `MiasmaShare` or an error
/// with phase information.
#[async_trait::async_trait]
pub trait PayloadTransport: Send + Sync {
    fn kind(&self) -> PayloadTransportKind;

    /// Attempt to fetch a share from a peer.
    ///
    /// Returns `Ok(Some(share))` on success, `Ok(None)` if the peer
    /// does not have the share, or `Err` with phase info on failure.
    async fn fetch_share(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError>;
}

/// Error from a single transport attempt, with phase information.
#[derive(Debug)]
pub struct PayloadTransportError {
    pub phase: TransportPhase,
    pub message: String,
}

impl fmt::Display for PayloadTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} error: {}", self.phase, self.message)
    }
}

impl std::error::Error for PayloadTransportError {}

// ─── Fallback engine ─────────────────────────────────────────────────────────

/// Ordered fallback across multiple payload transports.
///
/// Tries each transport in order. Stops on first success.
/// Records all attempts for diagnostics.
pub struct PayloadTransportSelector {
    transports: Vec<Box<dyn PayloadTransport>>,
    /// Running counters for observability.
    stats: Arc<TransportStats>,
}

impl PayloadTransportSelector {
    pub fn new(transports: Vec<Box<dyn PayloadTransport>>) -> Self {
        Self {
            transports,
            stats: Arc::new(TransportStats::default()),
        }
    }

    /// Returns a snapshot of transport statistics.
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Fetch a share, trying each transport in fallback order.
    ///
    /// Returns the share + metadata about which transport succeeded and
    /// all attempts made. Returns `TransportExhaustedError` if all fail.
    pub async fn fetch_share(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<TransportedShare, TransportExhaustedError> {
        let mut attempts = Vec::with_capacity(self.transports.len());

        for transport in &self.transports {
            let start = Instant::now();
            let kind = transport.kind();

            match transport
                .fetch_share(peer_addr, mid_digest, slot_index, segment_index)
                .await
            {
                Ok(Some(share)) => {
                    let duration = start.elapsed();
                    attempts.push(TransportAttempt {
                        transport: kind,
                        succeeded: true,
                        phase: TransportPhase::Data,
                        error: None,
                        duration,
                    });
                    self.stats.record_success(kind);
                    return Ok(TransportedShare {
                        share,
                        transport_used: kind,
                        attempts,
                    });
                }
                Ok(None) => {
                    // Peer doesn't have the share — not a transport failure.
                    // Don't try other transports; the share is genuinely absent.
                    let duration = start.elapsed();
                    attempts.push(TransportAttempt {
                        transport: kind,
                        succeeded: true,
                        phase: TransportPhase::Data,
                        error: Some("share not found on peer".into()),
                        duration,
                    });
                    // Return as exhausted but with "not found" — caller handles this.
                    return Err(TransportExhaustedError { attempts });
                }
                Err(e) => {
                    let duration = start.elapsed();
                    let phase = e.phase;
                    let msg = e.message;
                    attempts.push(TransportAttempt {
                        transport: kind,
                        succeeded: false,
                        phase,
                        error: Some(msg.clone()),
                        duration,
                    });
                    self.stats.record_failure(kind, phase, &msg);
                    // Try next transport.
                }
            }
        }

        Err(TransportExhaustedError { attempts })
    }

    /// List of configured transports in fallback order.
    pub fn transport_names(&self) -> Vec<PayloadTransportKind> {
        self.transports.iter().map(|t| t.kind()).collect()
    }
}

// ─── Transport statistics ────────────────────────────────────────────────────

/// Per-transport atomic counters for success, failure, and phase breakdown.
#[derive(Debug, Default)]
struct KindCounters {
    success: AtomicU64,
    failure: AtomicU64,
    session_failures: AtomicU64,
    data_failures: AtomicU64,
}

/// Running counters for payload transport usage.
#[derive(Debug, Default)]
pub struct TransportStats {
    libp2p: KindCounters,
    tcp: KindCounters,
    wss: KindCounters,
    relay: KindCounters,
    obfuscated: KindCounters,
    /// Most recent error per transport kind.
    last_errors: Mutex<std::collections::HashMap<PayloadTransportKind, String>>,
    /// The transport kind that most recently succeeded (if any).
    last_selected: Mutex<Option<PayloadTransportKind>>,
}

impl TransportStats {
    fn counters(&self, kind: PayloadTransportKind) -> &KindCounters {
        match kind {
            PayloadTransportKind::DirectLibp2p => &self.libp2p,
            PayloadTransportKind::TcpDirect => &self.tcp,
            PayloadTransportKind::WssTunnel => &self.wss,
            PayloadTransportKind::RelayHop => &self.relay,
            PayloadTransportKind::ObfuscatedQuic => &self.obfuscated,
        }
    }

    fn record_success(&self, kind: PayloadTransportKind) {
        self.counters(kind).success.fetch_add(1, Ordering::Relaxed);
        *self.last_selected.lock().unwrap() = Some(kind);
    }

    fn record_failure(&self, kind: PayloadTransportKind, phase: TransportPhase, message: &str) {
        let c = self.counters(kind);
        c.failure.fetch_add(1, Ordering::Relaxed);
        match phase {
            TransportPhase::Session => c.session_failures.fetch_add(1, Ordering::Relaxed),
            TransportPhase::Data => c.data_failures.fetch_add(1, Ordering::Relaxed),
        };
        self.last_errors
            .lock()
            .unwrap()
            .insert(kind, message.to_string());
    }

    /// Snapshot for diagnostics display.
    pub fn snapshot(&self) -> Vec<TransportReadiness> {
        let errors = self.last_errors.lock().unwrap();
        let selected = *self.last_selected.lock().unwrap();
        let kinds = [
            PayloadTransportKind::DirectLibp2p,
            PayloadTransportKind::TcpDirect,
            PayloadTransportKind::WssTunnel,
            PayloadTransportKind::RelayHop,
            PayloadTransportKind::ObfuscatedQuic,
        ];
        kinds
            .iter()
            .map(|&kind| {
                let c = self.counters(kind);
                TransportReadiness {
                    transport: kind,
                    available: true,
                    selected: selected == Some(kind),
                    success_count: c.success.load(Ordering::Relaxed),
                    failure_count: c.failure.load(Ordering::Relaxed),
                    session_failures: c.session_failures.load(Ordering::Relaxed),
                    data_failures: c.data_failures.load(Ordering::Relaxed),
                    last_error: errors.get(&kind).cloned(),
                    reason: None,
                }
            })
            .collect()
    }
}

// ─── Transport readiness (diagnostics) ───────────────────────────────────────

/// Per-transport readiness status for diagnostics output.
#[derive(Debug, Clone)]
pub struct TransportReadiness {
    pub transport: PayloadTransportKind,
    pub available: bool,
    /// Was this the transport used for the most recent successful fetch?
    pub selected: bool,
    pub success_count: u64,
    pub failure_count: u64,
    /// Number of failures at session phase (connection refused, timeout, etc.)
    pub session_failures: u64,
    /// Number of failures at data phase (connected but transfer failed).
    pub data_failures: u64,
    /// Most recent error message for this transport.
    pub last_error: Option<String>,
    pub reason: Option<String>,
}

impl fmt::Display for TransportReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.available {
            "AVAILABLE"
        } else {
            "UNAVAILABLE"
        };
        let sel = if self.selected { " [SELECTED]" } else { "" };
        write!(
            f,
            "{:<20} {:<12} success={} failure={} (session={} data={}){}",
            self.transport.to_string(),
            status,
            self.success_count,
            self.failure_count,
            self.session_failures,
            self.data_failures,
            sel,
        )?;
        if let Some(ref err) = self.last_error {
            write!(f, "  last_err={err}")?;
        }
        if let Some(ref reason) = self.reason {
            write!(f, "  ({reason})")?;
        }
        Ok(())
    }
}

// ─── Concrete transports ─────────────────────────────────────────────────────

/// libp2p-native transport: delegates to `ShareExchangeHandle::fetch`.
///
/// This is the current production path (QUIC + TCP via libp2p Swarm).
///
/// When called via `FallbackShareSource`, the `peer_addr` parameter carries
/// a multiaddr string and `peer_id_hex` / `addrs` are embedded in the locator
/// by the source. This avoids a redundant DHT lookup — the source already
/// resolved the record once.
///
/// When called directly (e.g., from tests), it falls back to a DHT lookup.
pub struct Libp2pPayloadTransport {
    share_handle: crate::network::node::ShareExchangeHandle,
    dht_handle: crate::network::node::DhtHandle,
    record_cache: Mutex<std::collections::HashMap<[u8; 32], crate::network::types::DhtRecord>>,
}

impl Libp2pPayloadTransport {
    pub fn new(
        share_handle: crate::network::node::ShareExchangeHandle,
        dht_handle: crate::network::node::DhtHandle,
    ) -> Self {
        Self {
            share_handle,
            dht_handle,
            record_cache: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Seed the record cache (used by integration tests to bypass DHT).
    pub fn seed_record(&self, record: crate::network::types::DhtRecord) {
        let mut cache = self.record_cache.lock().unwrap();
        cache.insert(record.mid_digest, record);
    }
}

#[async_trait::async_trait]
impl PayloadTransport for Libp2pPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::DirectLibp2p
    }

    async fn fetch_share(
        &self,
        _peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        // 1. Look up the DhtRecord to find which peer holds this shard.
        let record = {
            let cache = self.record_cache.lock().unwrap();
            cache.get(&mid_digest).cloned()
        };

        let record = match record {
            Some(r) => r,
            None => {
                // DHT lookup (fallback if FallbackShareSource didn't provide peer info)
                match self.dht_handle.get_record(mid_digest).await {
                    Ok(Some(r)) => {
                        let mut cache = self.record_cache.lock().unwrap();
                        cache.insert(mid_digest, r.clone());
                        r
                    }
                    Ok(None) => {
                        return Err(PayloadTransportError {
                            phase: TransportPhase::Session,
                            message: "no DHT record found".into(),
                        });
                    }
                    Err(e) => {
                        return Err(PayloadTransportError {
                            phase: TransportPhase::Session,
                            message: format!("DHT lookup failed: {e}"),
                        });
                    }
                }
            }
        };

        // 2. Find the location for this slot.
        let location = match record
            .locations
            .iter()
            .find(|l| l.shard_index == slot_index)
        {
            Some(l) => l,
            None => return Ok(None),
        };

        // 3. Parse peer_id.
        let peer_id = libp2p::PeerId::from_bytes(&location.peer_id_bytes).map_err(|e| {
            PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("invalid peer_id: {e}"),
            }
        })?;

        // 4. Fetch via share-exchange protocol.
        let request = crate::network::node::ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        };

        match self
            .share_handle
            .fetch(peer_id, location.addrs.clone(), request)
            .await
        {
            Ok(share) => Ok(share),
            Err(e) => Err(PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("share fetch failed: {e}"),
            }),
        }
    }
}

/// TCP direct transport — raw TCP share fetch without libp2p framing.
///
/// For environments where QUIC is blocked but TCP on high ports works.
/// Uses the same bincode wire format as the libp2p share-exchange protocol
/// but over a plain TCP connection.
pub struct TcpDirectPayloadTransport;

#[async_trait::async_trait]
impl PayloadTransport for TcpDirectPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::TcpDirect
    }

    async fn fetch_share(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // 1. Connect
        let mut stream =
            TcpStream::connect(peer_addr)
                .await
                .map_err(|e| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("TCP connect to {peer_addr}: {e}"),
                })?;

        // 2. Send request: 4-byte LE length + bincode(ShareFetchRequest)
        let request = crate::network::node::ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        };
        let body = bincode::serialize(&request).map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("serialize request: {e}"),
        })?;
        let len = (body.len() as u32).to_le_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("write request: {e}"),
            })?;
        stream
            .write_all(&body)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("write request body: {e}"),
            })?;

        // 3. Read response: 4-byte LE length + bincode(Option<MiasmaShare>)
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("read response length: {e}"),
            })?;
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        if resp_len > 64 * 1024 * 1024 {
            return Err(PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("response too large: {resp_len} bytes"),
            });
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("read response body: {e}"),
            })?;

        let share: Option<MiasmaShare> =
            bincode::deserialize(&resp_buf).map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("deserialize response: {e}"),
            })?;

        Ok(share)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_kind_display() {
        assert_eq!(
            PayloadTransportKind::DirectLibp2p.to_string(),
            "direct-libp2p"
        );
        assert_eq!(PayloadTransportKind::WssTunnel.to_string(), "wss-tunnel");
        assert_eq!(
            PayloadTransportKind::ObfuscatedQuic.to_string(),
            "obfuscated-quic"
        );
    }

    #[test]
    fn transport_phase_display() {
        assert_eq!(TransportPhase::Session.to_string(), "session");
        assert_eq!(TransportPhase::Data.to_string(), "data");
    }

    #[test]
    fn transport_attempt_display_success() {
        let a = TransportAttempt {
            transport: PayloadTransportKind::DirectLibp2p,
            succeeded: true,
            phase: TransportPhase::Data,
            error: None,
            duration: Duration::from_millis(42),
        };
        let s = a.to_string();
        assert!(s.contains("direct-libp2p"));
        assert!(s.contains("OK"));
    }

    #[test]
    fn transport_attempt_display_failure() {
        let a = TransportAttempt {
            transport: PayloadTransportKind::WssTunnel,
            succeeded: false,
            phase: TransportPhase::Session,
            error: Some("connection refused".into()),
            duration: Duration::from_millis(100),
        };
        let s = a.to_string();
        assert!(s.contains("wss-tunnel"));
        assert!(s.contains("FAILED"));
        assert!(s.contains("session"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn transport_exhausted_error_display() {
        let e = TransportExhaustedError {
            attempts: vec![
                TransportAttempt {
                    transport: PayloadTransportKind::DirectLibp2p,
                    succeeded: false,
                    phase: TransportPhase::Session,
                    error: Some("QUIC blocked".into()),
                    duration: Duration::from_millis(5000),
                },
                TransportAttempt {
                    transport: PayloadTransportKind::TcpDirect,
                    succeeded: false,
                    phase: TransportPhase::Session,
                    error: Some("connection refused".into()),
                    duration: Duration::from_millis(200),
                },
            ],
        };
        let s = e.to_string();
        assert!(s.contains("all 2 payload transports failed"));
        assert!(s.contains("QUIC blocked"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn transport_readiness_display() {
        let r = TransportReadiness {
            transport: PayloadTransportKind::WssTunnel,
            available: false,
            selected: false,
            success_count: 0,
            failure_count: 3,
            session_failures: 2,
            data_failures: 1,
            last_error: Some("connection refused".into()),
            reason: Some("not yet implemented".into()),
        };
        let s = r.to_string();
        assert!(s.contains("wss-tunnel"));
        assert!(s.contains("UNAVAILABLE"));
        assert!(s.contains("session=2"));
        assert!(s.contains("data=1"));
        assert!(s.contains("connection refused"));
        assert!(s.contains("not yet implemented"));
    }

    #[test]
    fn transport_stats_snapshot() {
        let stats = TransportStats::default();
        stats.record_success(PayloadTransportKind::DirectLibp2p);
        stats.record_success(PayloadTransportKind::DirectLibp2p);
        stats.record_failure(
            PayloadTransportKind::TcpDirect,
            TransportPhase::Session,
            "test",
        );

        let snap = stats.snapshot();
        let libp2p = snap
            .iter()
            .find(|r| r.transport == PayloadTransportKind::DirectLibp2p)
            .unwrap();
        assert_eq!(libp2p.success_count, 2);
        assert_eq!(libp2p.failure_count, 0);
        assert!(libp2p.available);

        let tcp = snap
            .iter()
            .find(|r| r.transport == PayloadTransportKind::TcpDirect)
            .unwrap();
        assert_eq!(tcp.failure_count, 1);
    }

    /// Mock transport that always fails with a given phase.
    struct FailTransport {
        kind: PayloadTransportKind,
        phase: TransportPhase,
        message: String,
    }

    #[async_trait::async_trait]
    impl PayloadTransport for FailTransport {
        fn kind(&self) -> PayloadTransportKind {
            self.kind
        }

        async fn fetch_share(
            &self,
            _peer_addr: &str,
            _mid_digest: [u8; 32],
            _slot_index: u16,
            _segment_index: u32,
        ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
            Err(PayloadTransportError {
                phase: self.phase,
                message: self.message.clone(),
            })
        }
    }

    /// Mock transport that succeeds with a dummy share.
    struct SuccessTransport {
        kind: PayloadTransportKind,
    }

    #[async_trait::async_trait]
    impl PayloadTransport for SuccessTransport {
        fn kind(&self) -> PayloadTransportKind {
            self.kind
        }

        async fn fetch_share(
            &self,
            _peer_addr: &str,
            _mid_digest: [u8; 32],
            slot_index: u16,
            segment_index: u32,
        ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
            Ok(Some(MiasmaShare {
                version: 1,
                mid_prefix: [0; 8],
                segment_index,
                slot_index,
                shard_data: vec![0xAA; 64],
                key_share: vec![0xBB; 32],
                shard_hash: [0; 32],
                nonce: [0; 12],
                original_len: 64,
                timestamp: 0,
            }))
        }
    }

    #[tokio::test]
    async fn selector_tries_fallback_on_failure() {
        let selector = PayloadTransportSelector::new(vec![
            Box::new(FailTransport {
                kind: PayloadTransportKind::DirectLibp2p,
                phase: TransportPhase::Session,
                message: "QUIC blocked".into(),
            }),
            Box::new(SuccessTransport {
                kind: PayloadTransportKind::TcpDirect,
            }),
        ]);

        let result = selector
            .fetch_share("127.0.0.1:9000", [0u8; 32], 0, 0)
            .await
            .unwrap();

        assert_eq!(result.transport_used, PayloadTransportKind::TcpDirect);
        assert_eq!(result.attempts.len(), 2);
        assert!(!result.attempts[0].succeeded);
        assert!(result.attempts[1].succeeded);
    }

    #[tokio::test]
    async fn selector_stops_on_first_success() {
        let selector = PayloadTransportSelector::new(vec![
            Box::new(SuccessTransport {
                kind: PayloadTransportKind::DirectLibp2p,
            }),
            Box::new(FailTransport {
                kind: PayloadTransportKind::TcpDirect,
                phase: TransportPhase::Session,
                message: "should not be reached".into(),
            }),
        ]);

        let result = selector
            .fetch_share("127.0.0.1:9000", [0u8; 32], 0, 0)
            .await
            .unwrap();

        assert_eq!(result.transport_used, PayloadTransportKind::DirectLibp2p);
        assert_eq!(result.attempts.len(), 1);
    }

    #[tokio::test]
    async fn selector_returns_all_failures_when_exhausted() {
        let selector = PayloadTransportSelector::new(vec![
            Box::new(FailTransport {
                kind: PayloadTransportKind::DirectLibp2p,
                phase: TransportPhase::Session,
                message: "QUIC blocked".into(),
            }),
            Box::new(FailTransport {
                kind: PayloadTransportKind::TcpDirect,
                phase: TransportPhase::Session,
                message: "connection refused".into(),
            }),
        ]);

        let err = selector
            .fetch_share("127.0.0.1:9000", [0u8; 32], 0, 0)
            .await
            .unwrap_err();

        assert_eq!(err.attempts.len(), 2);
        assert!(!err.attempts[0].succeeded);
        assert!(!err.attempts[1].succeeded);
    }

    #[tokio::test]
    async fn selector_records_stats() {
        let selector = PayloadTransportSelector::new(vec![
            Box::new(FailTransport {
                kind: PayloadTransportKind::DirectLibp2p,
                phase: TransportPhase::Session,
                message: "blocked".into(),
            }),
            Box::new(SuccessTransport {
                kind: PayloadTransportKind::TcpDirect,
            }),
        ]);

        let _ = selector.fetch_share("x", [0u8; 32], 0, 0).await;
        let _ = selector.fetch_share("x", [0u8; 32], 1, 0).await;

        let snap = selector.stats().snapshot();
        let libp2p = snap
            .iter()
            .find(|r| r.transport == PayloadTransportKind::DirectLibp2p)
            .unwrap();
        assert_eq!(libp2p.failure_count, 2);
        let tcp = snap
            .iter()
            .find(|r| r.transport == PayloadTransportKind::TcpDirect)
            .unwrap();
        assert_eq!(tcp.success_count, 2);
    }

    #[test]
    fn selector_transport_names() {
        let selector = PayloadTransportSelector::new(vec![
            Box::new(SuccessTransport {
                kind: PayloadTransportKind::DirectLibp2p,
            }),
            Box::new(SuccessTransport {
                kind: PayloadTransportKind::TcpDirect,
            }),
        ]);
        let names = selector.transport_names();
        assert_eq!(
            names,
            vec![
                PayloadTransportKind::DirectLibp2p,
                PayloadTransportKind::TcpDirect
            ]
        );
    }
}
