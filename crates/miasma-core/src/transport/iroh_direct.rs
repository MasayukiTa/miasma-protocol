//! Direct transport by public key, over iroh (QUIC, hole punching, relay fallback).
//!
//! A receiver that holds only a share ID and the password has no address for the
//! sender, and the sender has no open port and no tunnel. The share ID names the
//! publisher's Ed25519 key; the daemon's iroh endpoint uses that same key as its
//! identity (the node's persistent `dht_signing_key` seed), so the receiver can
//! dial the endpoint ID it read from the share ID and iroh finds the address
//! (n0's discovery service) and connects directly, or through a relay.
//!
//! * Server: [`IrohNode`] accepts bi-directional streams on ALPN
//!   [`IROH_ALPN`]. One stream is one request: `u32 length || wire message`, the
//!   same `WsRequest` / `WsResponse` messages as the WebSocket endpoint, answered
//!   by the very same [`handle_direct_request`], so the answers, the size caps
//!   and the signed-record envelope are identical on both transports. Nothing
//!   else is reachable: no IPC, no token, no control channel.
//! * Client: [`IrohDirectClient`] dials the publisher's endpoint ID, checks the
//!   peer that answered is exactly that key (QUIC/TLS already proves the peer
//!   holds it), and keeps one connection for the many requests a transfer makes.
//!   What it returns is untrusted and is verified by the caller against the
//!   share ID exactly as for `--via`.
//!
//! What iroh does **not** give: a dead proxy or a blocked relay does not make
//! `connect` fail, it waits for ever. Every dial here has a timeout, and the
//! error says what the endpoint itself reports about its relay connection.
//!
//! Privacy: in `n0` mode the endpoint publishes its ID, home relay and IP
//! addresses to n0's discovery service (see `IrohMode`).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::Duration,
};

use iroh::{
    address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Builder, Connection},
    tls::CaTlsConfig,
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, Watcher,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, info, warn};

use super::websocket::{
    decode_ws_message, encode_ws_message, handle_direct_request, RecordProvider, WsRequest,
    WsResponse, WS_MAX_MESSAGE_BYTES, WS_MAX_REQUESTS_PER_CONNECTION, WS_REQUEST_MAX_BYTES,
};
use crate::{
    config::{IrohMode, TransportConfig},
    daemon::ipc::IrohStatus,
    network::node::ShareFetchRequest,
    share::MiasmaShare,
    store::LocalShareStore,
    MiasmaError,
};

/// Application protocol name on the wire.
pub const IROH_ALPN: &[u8] = b"miasma/direct/1";

/// Largest extra CA bundle accepted (PEM text), as for `--via`.
const MAX_CA_PEM_BYTES: usize = 256 * 1024;

// ─── Settings ────────────────────────────────────────────────────────────────

/// How an endpoint is built. Derived from [`TransportConfig`] by
/// [`IrohSettings::from_config`].
#[derive(Debug, Clone)]
pub struct IrohSettings {
    pub mode: IrohMode,
    /// Relay URLs: the relay set in `custom` mode, dial hints in every mode.
    pub relay_urls: Vec<String>,
    /// Publish to / resolve from n0's discovery service.
    pub discovery: bool,
    /// Upper bound on one dial.
    pub connect_timeout: Duration,
    /// Extra CA certificate(s), PEM text, trusted in addition to the bundled
    /// roots for the relay's and discovery service's TLS.
    pub ca_pem: Option<Vec<u8>>,
    /// Use `HTTP(S)_PROXY` for relay and discovery traffic.
    pub proxy_from_env: bool,
}

impl IrohSettings {
    pub fn from_config(t: &TransportConfig) -> Self {
        Self {
            mode: t.iroh_mode,
            relay_urls: t.iroh_relay_urls.clone(),
            discovery: t.iroh_discovery,
            connect_timeout: Duration::from_secs(t.iroh_connect_timeout_secs.max(1)),
            ca_pem: None,
            proxy_from_env: proxy_env_is_set(),
        }
    }

    fn relay_hints(&self) -> Vec<RelayUrl> {
        self.relay_urls
            .iter()
            .filter_map(|u| match u.trim().parse::<RelayUrl>() {
                Ok(url) => Some(url),
                Err(e) => {
                    warn!("ignoring iroh relay URL that does not parse: {e}");
                    None
                }
            })
            .collect()
    }
}

fn proxy_env_is_set() -> bool {
    ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
}

/// Appended to the "not connected to a relay server" diagnosis. iroh does not
/// report *why* a relay handshake failed when it never got as far as choosing a
/// home relay, so a rejected relay certificate cannot be told apart from a
/// blocked network; the likely TLS cause is named rather than left out.
pub const RELAY_TLS_HINT: &str = "; relay TLS certificate not trusted? if you are behind a \
     TLS-inspecting proxy, install its CA in the OS certificate store or pass --ca-cert";

/// Who is trusted to vouch for the relay, pkarr and DNS-over-HTTPS servers.
///
/// The OS certificate store (through `rustls-platform-verifier`, the same
/// verifier the `wss://` direct path uses), plus `extra_roots` (`--ca-cert`). A
/// TLS-inspecting proxy whose CA is installed in the OS therefore works without
/// any setting. These roots only authenticate iroh's HTTPS services; the peer
/// itself is authenticated by its key, not by any CA.
///
/// Android is the one platform where rustls-platform-verifier cannot take extra
/// roots, so there the bundled Mozilla roots plus `extra_roots` are used (as
/// for `wss://`).
#[cfg(not(target_os = "android"))]
pub fn ca_tls_config(extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>) -> CaTlsConfig {
    CaTlsConfig::system().with_extra_roots(extra_roots)
}

/// See the non-Android variant.
#[cfg(target_os = "android")]
pub fn ca_tls_config(extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>) -> CaTlsConfig {
    CaTlsConfig::embedded().with_extra_roots(extra_roots)
}

/// The endpoint builder for `settings`.
///
/// `seed` is the endpoint's identity: the raw Ed25519 seed. `None` makes a fresh
/// throw-away identity (a client-only endpoint). `publish` decides whether the
/// endpoint announces itself to n0's discovery service.
///
/// Public so a test can add an address lookup of its own or a local relay's
/// certificate; production code goes through [`IrohNode::start`].
pub fn endpoint_builder(
    seed: Option<&[u8; 32]>,
    settings: &IrohSettings,
    publish: bool,
) -> Result<Builder, MiasmaError> {
    let mut b = Endpoint::builder(iroh::endpoint::presets::Minimal);
    match settings.mode {
        IrohMode::Off => {
            return Err(MiasmaError::Network(
                "iroh is switched off (transport.iroh_mode = off)".into(),
            ))
        }
        IrohMode::N0 => b = b.relay_mode(RelayMode::Default),
        IrohMode::Custom => {
            let relays = settings.relay_hints();
            if relays.is_empty() {
                return Err(MiasmaError::Network(
                    "transport.iroh_mode = custom needs at least one valid URL in \
                     transport.iroh_relay_urls"
                        .into(),
                ));
            }
            b = b.relay_mode(RelayMode::custom(relays));
        }
    }
    if settings.discovery {
        if publish {
            b = b.address_lookup(PkarrPublisher::n0_dns());
        }
        b = b
            .address_lookup(PkarrResolver::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns());
    }
    if settings.proxy_from_env {
        b = b.proxy_from_env();
    }
    let extra_roots = match &settings.ca_pem {
        Some(pem) => {
            if pem.len() > MAX_CA_PEM_BYTES {
                return Err(MiasmaError::Network("the CA file is too large".into()));
            }
            let certs = rustls_pemfile::certs(&mut &pem[..])
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| MiasmaError::Network(format!("the CA file is not valid PEM: {e}")))?;
            if certs.is_empty() {
                return Err(MiasmaError::Network(
                    "the CA file contains no certificate".into(),
                ));
            }
            certs
        }
        None => Vec::new(),
    };
    b = b.ca_tls_config(ca_tls_config(extra_roots));
    if let Some(seed) = seed {
        b = b.secret_key(SecretKey::from_bytes(seed));
        b = b.alpns(vec![IROH_ALPN.to_vec()]);
    }
    Ok(b)
}

// ─── Server limits ───────────────────────────────────────────────────────────

/// Bounds on what one remote party can make the server do.
#[derive(Debug, Clone)]
pub struct IrohServerLimits {
    /// Connections served at once; further ones are refused at the handshake.
    pub max_connections: usize,
    /// Requests served on one connection before it is closed (the client dials
    /// again). Same constant as the WebSocket endpoint.
    pub max_requests_per_connection: usize,
    /// Requests answered concurrently on one connection.
    pub concurrent_streams: usize,
    /// How long an idle connection is kept, and the wait for a first request.
    pub idle_timeout: Duration,
    /// Time allowed for the QUIC handshake.
    pub handshake_timeout: Duration,
    /// Time allowed to receive one request once its stream is open.
    pub read_timeout: Duration,
    /// Time allowed to send one response.
    pub write_timeout: Duration,
}

impl Default for IrohServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_requests_per_connection: WS_MAX_REQUESTS_PER_CONNECTION,
            concurrent_streams: 8,
            idle_timeout: Duration::from_secs(120),
            handshake_timeout: Duration::from_secs(20),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(60),
        }
    }
}

// ─── The node ────────────────────────────────────────────────────────────────

/// A running iroh endpoint: serves this node's shares and records, and dials
/// other nodes for receives.
pub struct IrohNode {
    endpoint: Endpoint,
    settings: IrohSettings,
    server: StdMutex<Option<JoinHandle<()>>>,
}

impl IrohNode {
    /// Start the endpoint with `seed` (the node's DHT signing seed) as identity.
    pub async fn start(
        seed: &[u8; 32],
        settings: IrohSettings,
        store: Arc<LocalShareStore>,
        records: Option<Arc<dyn RecordProvider>>,
    ) -> Result<Arc<Self>, MiasmaError> {
        let builder = endpoint_builder(Some(seed), &settings, true)?;
        Self::start_from_builder(
            builder,
            settings,
            store,
            records,
            IrohServerLimits::default(),
        )
        .await
    }

    /// As [`start`](Self::start) from a prepared builder and explicit limits.
    pub async fn start_from_builder(
        builder: Builder,
        settings: IrohSettings,
        store: Arc<LocalShareStore>,
        records: Option<Arc<dyn RecordProvider>>,
        limits: IrohServerLimits,
    ) -> Result<Arc<Self>, MiasmaError> {
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| MiasmaError::Network(format!("cannot start the iroh endpoint: {e}")))?;
        let ctx = Arc::new(ServeCtx {
            store,
            records,
            limits,
        });
        let server = tokio::spawn(accept_loop(endpoint.clone(), ctx));
        Ok(Arc::new(Self {
            endpoint,
            settings,
            server: StdMutex::new(Some(server)),
        }))
    }

    /// The endpoint ID: the Ed25519 public key, equal to the publisher key in a
    /// share ID this node publishes.
    pub fn endpoint_id(&self) -> [u8; 32] {
        *self.endpoint.id().as_bytes()
    }

    pub fn settings(&self) -> &IrohSettings {
        &self.settings
    }

    /// The addresses this endpoint currently advertises (for tests and status).
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// The underlying endpoint (tests build raw clients and servers with it).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Wait until the endpoint has a home relay connection, at most `limit`.
    /// `false` if it did not get one in time.
    pub async fn wait_online(&self, limit: Duration) -> bool {
        tokio::time::timeout(limit, self.endpoint.online())
            .await
            .is_ok()
    }

    /// A client for the publisher `publisher` (an endpoint ID) on this node's own
    /// endpoint.
    pub fn client(&self, publisher: &[u8; 32]) -> Result<IrohDirectClient, MiasmaError> {
        IrohDirectClient::new(
            self.endpoint.clone(),
            publisher,
            self.settings.relay_hints(),
            self.settings.connect_timeout,
        )
    }

    /// A client on a separate, throw-away, client-only endpoint that also trusts
    /// `ca_pem` for the relay's TLS (`network-get --ca-cert`). The endpoint has a
    /// fresh identity and publishes nothing.
    pub async fn client_with_ca(
        &self,
        publisher: &[u8; 32],
        ca_pem: &[u8],
    ) -> Result<IrohDirectClient, MiasmaError> {
        let mut settings = self.settings.clone();
        settings.ca_pem = Some(ca_pem.to_vec());
        let endpoint = endpoint_builder(None, &settings, false)?
            .bind()
            .await
            .map_err(|e| MiasmaError::Network(format!("cannot start the iroh endpoint: {e}")))?;
        IrohDirectClient::new(
            endpoint,
            publisher,
            settings.relay_hints(),
            settings.connect_timeout,
        )
    }

    /// What `miasma status` shows.
    pub fn status(&self) -> IrohStatus {
        let relays = self.endpoint.home_relay_status().get();
        let connected = relays.iter().find(|r| r.is_connected());
        let shown = connected.or_else(|| relays.first());
        IrohStatus {
            mode: self.settings.mode.as_str().to_owned(),
            endpoint_id: hex::encode(self.endpoint.id().as_bytes()),
            home_relay: shown.map(|r| r.url().to_string()),
            relay_connected: connected.is_some(),
            last_error: if connected.is_some() {
                None
            } else {
                relays
                    .iter()
                    .find_map(|r| r.last_error().map(|e| one_line(&format!("{e:?}"))))
            },
            discovery: self.settings.discovery,
        }
    }

    /// Stop accepting and close the endpoint.
    pub async fn shutdown(&self) {
        let handle = self.server.lock().unwrap().take();
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
        self.endpoint.close().await;
    }
}

impl Drop for IrohNode {
    fn drop(&mut self) {
        if let Ok(mut g) = self.server.lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ─── Per-daemon registry ─────────────────────────────────────────────────────
//
// Like the transfer registry: the daemon's request handler and the receive jobs
// find the node by data directory, so no new parameter threads through them and
// two daemons in one test process never share a node.

static NODES: OnceLock<StdMutex<HashMap<PathBuf, Arc<IrohNode>>>> = OnceLock::new();

fn nodes() -> &'static StdMutex<HashMap<PathBuf, Arc<IrohNode>>> {
    NODES.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// The iroh node of the daemon that owns `data_dir`, if it runs one.
pub fn node_for(data_dir: &Path) -> Option<Arc<IrohNode>> {
    nodes().lock().unwrap().get(data_dir).cloned()
}

pub(crate) fn register_node(data_dir: &Path, node: Arc<IrohNode>) {
    nodes().lock().unwrap().insert(data_dir.to_path_buf(), node);
}

pub(crate) fn unregister_node(data_dir: &Path) -> Option<Arc<IrohNode>> {
    nodes().lock().unwrap().remove(data_dir)
}

// ─── Server ──────────────────────────────────────────────────────────────────

struct ServeCtx {
    store: Arc<LocalShareStore>,
    records: Option<Arc<dyn RecordProvider>>,
    limits: IrohServerLimits,
}

async fn accept_loop(endpoint: Endpoint, ctx: Arc<ServeCtx>) {
    let slots = Arc::new(Semaphore::new(ctx.limits.max_connections));
    let mut connections = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        while let Some(done) = connections.try_join_next() {
            if let Err(e) = done {
                debug!("iroh connection task: {e}");
            }
        }
        // Over the cap: refuse now. Nothing waits for a slot, so a flood holds
        // no task and no buffer.
        let permit = match slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("iroh endpoint at capacity, refusing a connection");
                incoming.refuse();
                continue;
            }
        };
        let ctx = ctx.clone();
        connections.spawn(async move {
            let _permit = permit;
            let conn = match tokio::time::timeout(ctx.limits.handshake_timeout, incoming).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => return debug!("iroh handshake failed: {e}"),
                Err(_) => return debug!("iroh handshake timed out"),
            };
            serve_connection(conn, &ctx).await;
        });
    }
}

/// Answer the requests of one connection. Each request is one bi-directional
/// stream; a few are answered concurrently so a receiver can fetch pieces in
/// parallel over one connection.
async fn serve_connection(conn: Connection, ctx: &Arc<ServeCtx>) {
    let limits = &ctx.limits;
    let streams = Arc::new(Semaphore::new(limits.concurrent_streams.max(1)));
    let mut tasks = JoinSet::new();
    let mut served = 0usize;
    while served < limits.max_requests_per_connection {
        let permit = match streams.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let (tx, rx) = match tokio::time::timeout(limits.idle_timeout, conn.accept_bi()).await {
            // Idle, or the peer closed.
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(s)) => s,
        };
        served += 1;
        let ctx = ctx.clone();
        let conn2 = conn.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(why) = serve_stream(tx, rx, &ctx).await {
                // A request that does not parse, or is over a cap, ends the
                // connection and nothing about it is echoed back.
                debug!("iroh request refused: {why}");
                conn2.close(1u32.into(), b"refused");
            }
        });
        while let Some(done) = tasks.try_join_next() {
            if let Err(e) = done {
                debug!("iroh stream task: {e}");
            }
        }
    }
    // Let in-flight answers finish before the connection goes away.
    while tasks.join_next().await.is_some() {}
    conn.close(0u32.into(), b"done");
}

async fn serve_stream(
    mut tx: iroh::endpoint::SendStream,
    mut rx: iroh::endpoint::RecvStream,
    ctx: &ServeCtx,
) -> Result<(), String> {
    let limits = &ctx.limits;
    let request: WsRequest = tokio::time::timeout(limits.read_timeout, async {
        let declared = rx.read_u32().await.map_err(|e| e.to_string())? as usize;
        // The declared length is checked before any buffer is sized from it.
        if declared == 0 || declared > WS_REQUEST_MAX_BYTES {
            return Err("request length out of bounds".to_owned());
        }
        let mut body = vec![0u8; declared];
        rx.read_exact(&mut body).await.map_err(|e| e.to_string())?;
        decode_ws_message(&body, WS_REQUEST_MAX_BYTES)
    })
    .await
    .map_err(|_| "request timed out".to_owned())??;

    let response = handle_direct_request(&ctx.store, ctx.records.as_ref(), request).await;
    let body = encode_ws_message(&response)?;
    let len = u32::try_from(body.len()).map_err(|_| "response too large".to_owned())?;
    tokio::time::timeout(limits.write_timeout, async {
        tx.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        tx.write_all(&body).await.map_err(|e| e.to_string())?;
        tx.finish().map_err(|e| e.to_string())?;
        // Wait until the peer has the whole answer, so closing the connection
        // afterwards cannot cut it off.
        let _ = tx.stopped().await;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "response write timed out".to_owned())??;
    Ok(())
}

// ─── Client ──────────────────────────────────────────────────────────────────

/// Why a request to the sender failed.
#[derive(Debug, Clone)]
pub enum IrohClientError {
    /// Could not reach the endpoint: discovery, relay, hole punch or handshake.
    /// Retrying the same dial will not help.
    Unreachable(String),
    /// The connection broke or a stream failed. May be transient.
    Connection(String),
    /// The peer answered, but not in this protocol (or is not the expected key).
    Protocol(String),
}

impl IrohClientError {
    /// Whether trying again could succeed.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Unreachable(_) | Self::Protocol(_))
    }
}

impl std::fmt::Display for IrohClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(e) => write!(f, "cannot reach the sender over iroh: {e}"),
            Self::Connection(e) => write!(f, "the iroh connection failed: {e}"),
            Self::Protocol(e) => write!(f, "the iroh peer did not answer as expected: {e}"),
        }
    }
}

impl std::error::Error for IrohClientError {}

impl From<IrohClientError> for MiasmaError {
    fn from(e: IrohClientError) -> Self {
        MiasmaError::Network(e.to_string())
    }
}

/// A client for one publisher's endpoint, reusing one connection.
pub struct IrohDirectClient {
    endpoint: Endpoint,
    target: EndpointId,
    hints: Vec<RelayUrl>,
    direct_addrs: Vec<std::net::SocketAddr>,
    connect_timeout: Duration,
    conn: Mutex<Option<Connection>>,
}

impl std::fmt::Debug for IrohDirectClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohDirectClient")
            .field("target", &self.target.fmt_short().to_string())
            .finish()
    }
}

const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(90);

impl IrohDirectClient {
    /// A client dialing `publisher` from `endpoint`, with `hints` as relay
    /// hints and `connect_timeout` bounding every dial.
    pub fn new(
        endpoint: Endpoint,
        publisher: &[u8; 32],
        hints: Vec<RelayUrl>,
        connect_timeout: Duration,
    ) -> Result<Self, MiasmaError> {
        let target = EndpointId::from_bytes(publisher)
            .map_err(|_| MiasmaError::Network("the publisher key is not a valid key".into()))?;
        Ok(Self {
            endpoint,
            target,
            hints,
            direct_addrs: Vec::new(),
            connect_timeout,
            conn: Mutex::new(None),
        })
    }

    /// Also try these socket addresses (a LAN address, say) besides discovery
    /// and the relay hints. Whoever answers must still prove it holds the
    /// publisher's key, wherever the address leads.
    pub fn with_direct_addrs(mut self, addrs: Vec<std::net::SocketAddr>) -> Self {
        self.direct_addrs = addrs;
        self
    }

    /// `abcdef012345…`: the first 12 hex digits of the dialed key, for messages.
    pub fn display_addr(&self) -> String {
        format!("iroh:{}…", &hex::encode(self.target.as_bytes())[..12])
    }

    /// `direct` (a hole-punched or LAN connection) or `relay` for the path the
    /// connection currently uses; `None` before a connection exists.
    pub fn path_kind(&self) -> Option<&'static str> {
        let guard = self.conn.try_lock().ok()?;
        let conn = guard.as_ref()?;
        let mut kind = None;
        for p in conn.paths().iter() {
            if p.is_selected() {
                if p.is_ip() {
                    return Some("direct");
                }
                if p.is_relay() {
                    kind = Some("relay");
                }
            }
        }
        kind
    }

    /// The signed record envelope for `mid_digest` (see
    /// `RecordProvider::record_value`), or `None`. Untrusted: open it with
    /// `transfer::open_signed_record`.
    pub async fn fetch_record(
        &self,
        mid_digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, IrohClientError> {
        match self.round_trip(&WsRequest::Record { mid_digest }).await? {
            WsResponse::Record { value } => Ok(value),
            WsResponse::Share(_) => Err(IrohClientError::Protocol(
                "a share answered a record request".into(),
            )),
        }
    }

    /// One share, or `None` if the sender does not hold it.
    pub async fn fetch_share(
        &self,
        mid_digest: [u8; 32],
        segment_index: u32,
        slot_index: u16,
    ) -> Result<Option<MiasmaShare>, IrohClientError> {
        let request = WsRequest::Share(ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        });
        match self.round_trip(&request).await? {
            WsResponse::Share(r) => Ok(r.share),
            WsResponse::Record { .. } => Err(IrohClientError::Protocol(
                "a record answered a share request".into(),
            )),
        }
    }

    async fn round_trip(&self, request: &WsRequest) -> Result<WsResponse, IrohClientError> {
        let message = encode_ws_message(request).map_err(IrohClientError::Protocol)?;
        // A kept connection may have been closed by the server since its last
        // use (idle, or its request limit): that costs one redial, not an error.
        let mut allow_reuse = true;
        loop {
            let (conn, reused) = self.connection(allow_reuse).await?;
            match exchange(&conn, &message).await {
                Ok(response) => return Ok(response),
                Err(IrohClientError::Connection(e)) if reused => {
                    debug!("kept iroh connection unusable ({e}); dialing again");
                    self.forget(&conn).await;
                    allow_reuse = false;
                }
                Err(e) => {
                    if matches!(e, IrohClientError::Connection(_)) {
                        self.forget(&conn).await;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Drop `conn` from the slot if it is still the current one.
    async fn forget(&self, conn: &Connection) {
        let mut slot = self.conn.lock().await;
        if slot
            .as_ref()
            .is_some_and(|c| c.stable_id() == conn.stable_id())
        {
            *slot = None;
        }
    }

    async fn connection(&self, allow_reuse: bool) -> Result<(Connection, bool), IrohClientError> {
        let mut slot = self.conn.lock().await;
        if allow_reuse {
            if let Some(c) = slot.as_ref() {
                if c.close_reason().is_none() {
                    return Ok((c.clone(), true));
                }
            }
        }
        let fresh = self.dial().await?;
        *slot = Some(fresh.clone());
        Ok((fresh, false))
    }

    async fn dial(&self) -> Result<Connection, IrohClientError> {
        let mut addr = EndpointAddr::new(self.target);
        for hint in &self.hints {
            addr = addr.with_relay_url(hint.clone());
        }
        for ip in &self.direct_addrs {
            addr = addr.with_ip_addr(*ip);
        }
        let attempt =
            tokio::time::timeout(self.connect_timeout, self.endpoint.connect(addr, IROH_ALPN))
                .await;
        match attempt {
            Ok(Ok(conn)) => {
                // TLS already proved the peer holds the key it presented; say it
                // out loud so a change in that guarantee cannot pass unnoticed.
                if conn.remote_id() != self.target {
                    conn.close(2u32.into(), b"wrong peer");
                    return Err(IrohClientError::Protocol(
                        "the peer that answered is not the publisher named in the share ID".into(),
                    ));
                }
                Ok(conn)
            }
            Ok(Err(e)) => Err(IrohClientError::Unreachable(format!(
                "{}{}",
                one_line(&e.to_string()),
                self.relay_diagnosis()
            ))),
            Err(_) => Err(IrohClientError::Unreachable(format!(
                "no connection within {} s (the sender is offline or not running iroh, or this \
                 network blocks iroh's relay and discovery servers){}",
                self.connect_timeout.as_secs(),
                self.relay_diagnosis()
            ))),
        }
    }

    /// What this endpoint itself says about its relay connection: a dead proxy
    /// or a blocked relay shows up here and nowhere in `connect`'s result.
    fn relay_diagnosis(&self) -> String {
        let relays = self.endpoint.home_relay_status().get();
        if relays.iter().any(|r| r.is_connected()) {
            return String::new();
        }
        let why = relays
            .iter()
            .find_map(|r| {
                r.auth_denied_reason()
                    .map(|a| format!("relay denied access: {a}"))
                    .or_else(|| r.last_error().map(|e| one_line(&format!("{e:?}"))))
            })
            .unwrap_or_else(|| "no relay connection yet".to_owned());
        format!("; this computer is not connected to a relay server ({why}){RELAY_TLS_HINT}")
    }
}

/// One request and its response on an open connection.
async fn exchange(conn: &Connection, message: &[u8]) -> Result<WsResponse, IrohClientError> {
    let broken =
        |what: &str, e: &dyn std::fmt::Display| IrohClientError::Connection(format!("{what}: {e}"));
    let (mut tx, mut rx) = conn
        .open_bi()
        .await
        .map_err(|e| broken("open stream", &e))?;
    let len = u32::try_from(message.len())
        .map_err(|_| IrohClientError::Protocol("request too large".into()))?;
    tokio::time::timeout(WRITE_TIMEOUT, async {
        tx.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        tx.write_all(message).await.map_err(|e| e.to_string())?;
        tx.finish().map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| IrohClientError::Connection("write timed out".into()))?
    .map_err(|e| broken("send", &e))?;

    let body = tokio::time::timeout(READ_TIMEOUT, async {
        let declared = rx.read_u32().await.map_err(|e| broken("receive", &e))? as usize;
        // Checked before any buffer is sized from it.
        if declared > WS_MAX_MESSAGE_BYTES {
            return Err(IrohClientError::Protocol("response too large".into()));
        }
        // Grows with what actually arrives; a peer that declares much and sends
        // nothing costs nothing.
        let mut body = Vec::new();
        (&mut rx)
            .take(declared as u64)
            .read_to_end(&mut body)
            .await
            .map_err(|e| broken("receive", &e))?;
        if body.len() != declared {
            return Err(IrohClientError::Connection(
                "the response was cut short".into(),
            ));
        }
        Ok(body)
    })
    .await
    .map_err(|_| IrohClientError::Connection("no response in time".into()))??;
    decode_ws_message(&body, WS_MAX_MESSAGE_BYTES).map_err(IrohClientError::Protocol)
}

/// Log, once at daemon start, what n0 mode shares (the one-line notice).
pub fn log_privacy_notice(settings: &IrohSettings) {
    if settings.mode == IrohMode::N0 && settings.discovery {
        info!(
            "iroh discovery via n0 is enabled: your endpoint id and addresses are published to \
             n0; disable with transport.iroh_mode=off"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::ca_tls_config;

    const HOST: &str = "relay.miasma-test.invalid";

    /// A CA and a leaf certificate for `HOST` signed by it.
    fn ca_and_leaf() -> (CertificateDer<'static>, CertificateDer<'static>) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "miasma test ca");
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec![HOST.to_string()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        (ca.der().clone(), leaf.der().clone())
    }

    fn verify(
        extra: Vec<CertificateDer<'static>>,
        leaf: &CertificateDer<'static>,
        host: &str,
    ) -> Result<(), rustls::Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = ca_tls_config(extra)
            .server_cert_verifier(provider)
            .expect("the platform verifier starts");
        let name = ServerName::try_from(host.to_string()).unwrap();
        verifier
            .verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn a_certificate_from_an_unknown_ca_is_refused() {
        let (_ca, leaf) = ca_and_leaf();
        assert!(verify(Vec::new(), &leaf, HOST).is_err());
        // An unrelated extra root does not help.
        let (other_ca, _) = ca_and_leaf();
        assert!(verify(vec![other_ca], &leaf, HOST).is_err());
    }

    #[test]
    fn a_certificate_from_a_ca_given_as_extra_root_is_accepted() {
        let (ca, leaf) = ca_and_leaf();
        verify(vec![ca.clone()], &leaf, HOST).expect("the extra root vouches for the leaf");
        // ...but only for the name it was issued to.
        assert!(verify(vec![ca], &leaf, "other.miasma-test.invalid").is_err());
    }

    #[test]
    fn a_fully_qualified_name_with_a_trailing_dot_is_verified_like_the_plain_one() {
        let (ca, leaf) = ca_and_leaf();
        let dotted = format!("{HOST}.");
        verify(vec![ca], &leaf, &dotted).expect("trailing-dot host name");
    }
}
