//! HTTP bridge for web client access.
//!
//! Exposes the daemon's control API over HTTP/1.1 on localhost so that
//! browser-based clients (standalone web app, Android WebView, iOS WKWebView)
//! can reach the daemon without a custom binary protocol.
//!
//! # Endpoints
//!
//! | Method | Path            | Description                              |
//! |--------|-----------------|------------------------------------------|
//! | GET    | `/`, `/js/...`  | The web client itself (public, no token) |
//! | GET    | `/api/ping`     | Connection liveness check                |
//! | GET    | `/api/status`   | Full `DaemonStatus` snapshot             |
//! | POST   | `/api/publish`  | Dissolve + publish (base64 data)         |
//! | POST   | `/api/retrieve` | Network retrieve by MID (returns base64) |
//! | POST   | `/api/wipe`     | Distress wipe                            |
//! | GET    | `/api/transfers`             | Every transfer (running, paused, done) |
//! | GET    | `/api/transfers/<id>`        | One transfer's status                  |
//! | POST   | `/api/transfers/receive`     | Start or resume a receive (`mid`, `output_path` on the daemon's computer, optional `password`) |
//! | POST   | `/api/transfers/<id>/cancel` | Stop a running transfer, keeping it resumable |
//!
//! # Security
//!
//! Binds only to `127.0.0.1` — unreachable from the network.  Reaching
//! localhost is not a credential, so every endpoint except `GET /api/ping`
//! (liveness only) requires the daemon's control token as
//! `Authorization: Bearer <token>`; the token is in `<data_dir>/daemon.token`
//! (see `control_auth`).  A missing `Origin` header no longer grants access:
//! non-browser clients authenticate like everyone else, and browser origins
//! that are not localhost are still refused.  `POST /api/wipe` is two-step:
//! without a body it returns a challenge, `{"confirm": "<challenge>"}` wipes.
//!
//! The web client (`web/`) is compiled in (`web_assets`) and served from the
//! bridge's own origin.  Those files are public code and need no token; `miasma
//! web` prints a link `http://127.0.0.1:<port>/#token=<token>` whose fragment the
//! page reads once, keeps in `sessionStorage` and strips from the URL.  A URL
//! fragment is never sent to the server, so the token does not appear in this
//! process's request path, in logs, or in `Referer`.  The bridge never hands the
//! token to a caller that does not already hold it.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes, Incoming},
    header, Method, Request, Response, StatusCode,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{debug, warn};
use zeroize::Zeroize;

use crate::{network::coordinator::MiasmaCoordinator, store::LocalShareStore};

use super::{
    ipc::{ControlRequest, ControlResponse},
    process_request,
    rate_limit::{
        classify_endpoint, validate_field_length, validate_origin, MAX_MID_LEN, MAX_PASSWORD_LEN,
    },
    replication::ReplicationQueue,
    BridgeLiveState,
};

/// Maximum HTTP request body size (16 MiB, matching IPC FRAME_MAX).
const MAX_BODY: usize = 16 * 1024 * 1024;

// ─── HTTP request/response types ─────────────────────────────────────────────

#[derive(Deserialize)]
struct PublishRequest {
    /// Base64-encoded plaintext data.
    data: String,
    #[serde(default = "default_k")]
    data_shards: u8,
    #[serde(default = "default_n")]
    total_shards: u8,
}
fn default_k() -> u8 {
    10
}
fn default_n() -> u8 {
    20
}

#[derive(Serialize)]
struct PublishResponse {
    mid: String,
}

#[derive(Deserialize)]
struct RetrieveRequest {
    mid: String,
    #[serde(default = "default_k")]
    data_shards: u8,
    #[serde(default = "default_n")]
    total_shards: u8,
}

#[derive(Serialize)]
struct RetrieveResponse {
    /// Base64-encoded retrieved plaintext.
    data: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

// ─── Shared state ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct BridgeState {
    coord: Arc<MiasmaCoordinator>,
    queue: Arc<Mutex<ReplicationQueue>>,
    store: Arc<LocalShareStore>,
    listen_addrs: Vec<String>,
    wss_port: u16,
    wss_tls_enabled: bool,
    proxy_configured: bool,
    proxy_type: Option<String>,
    obfs_quic_port: u16,
    sharing_secret: super::SharingSecretState,
    sharing_pubkey: [u8; 32],
    data_dir: std::path::PathBuf,
    /// Bridge superhardening live state (rate limiter, health monitor, env snapshot).
    bridge_live: BridgeLiveState,
}

// ─── HttpBridge ──────────────────────────────────────────────────────────────

pub struct HttpBridge {
    listener: TcpListener,
    state: BridgeState,
}

impl HttpBridge {
    /// Bind the HTTP bridge.  Tries `preferred_port` first, falls back to
    /// OS-assigned if that port is occupied.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        preferred_port: u16,
        coord: Arc<MiasmaCoordinator>,
        queue: Arc<Mutex<ReplicationQueue>>,
        store: Arc<LocalShareStore>,
        listen_addrs: Vec<String>,
        wss_port: u16,
        wss_tls_enabled: bool,
        proxy_configured: bool,
        proxy_type: Option<String>,
        obfs_quic_port: u16,
        sharing_secret: super::SharingSecretState,
        sharing_pubkey: [u8; 32],
        data_dir: std::path::PathBuf,
        bridge_live: BridgeLiveState,
    ) -> Result<Self> {
        let listener = match TcpListener::bind(format!("127.0.0.1:{preferred_port}")).await {
            Ok(l) => l,
            Err(_) => {
                warn!(
                    preferred_port,
                    "HTTP bridge: preferred port occupied, falling back to OS-assigned"
                );
                TcpListener::bind("127.0.0.1:0")
                    .await
                    .context("cannot bind HTTP bridge")?
            }
        };

        let state = BridgeState {
            coord,
            queue,
            store,
            listen_addrs,
            wss_port,
            wss_tls_enabled,
            proxy_configured,
            proxy_type,
            obfs_quic_port,
            sharing_secret,
            sharing_pubkey,
            data_dir,
            bridge_live,
        };

        Ok(Self { listener, state })
    }

    /// The actual bound port.
    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Run the HTTP server loop.  Does not return until the task is cancelled.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    debug!("HTTP bridge client: {peer}");
                    let state = self.state.clone();
                    let io = hyper_util::rt::TokioIo::new(stream);
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |req| {
                            let st = state.clone();
                            async move { handle(req, st).await }
                        });
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
                            debug!("HTTP bridge connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!("HTTP bridge accept error: {e}");
                    break;
                }
            }
        }
    }
}

// ─── Request handler ─────────────────────────────────────────────────────────

async fn handle(
    req: Request<Incoming>,
    state: BridgeState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Handle CORS preflight
    if req.method() == Method::OPTIONS {
        return Ok(cors(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        ));
    }

    // Origin validation — reject non-localhost origins
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    if !validate_origin(origin) {
        warn!("HTTP bridge: rejected non-localhost origin: {:?}", origin);
        return Ok(cors(json_error(
            StatusCode::FORBIDDEN,
            "origin not allowed",
        )));
    }

    // The web client's own files: public code, no token, but the same Origin gate.
    if req.method() == Method::GET {
        if let Some(asset) = super::web_assets::lookup(req.uri().path()) {
            return Ok(static_response(asset));
        }
    }

    // Authentication — everything but the liveness probe needs the token.
    if !(req.method() == Method::GET && req.uri().path() == "/api/ping") {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if let Err(delay) = state.bridge_live.control_auth.check(presented) {
            tokio::time::sleep(delay).await;
            return Ok(cors(json_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized: missing or invalid control token",
            )));
        }
    }

    // Rate limiting — check before routing
    let method_str = req.method().as_str().to_string();
    let path_str = req.uri().path().to_string();
    let rate_class = classify_endpoint(&method_str, &path_str);
    {
        let mut rl = state.bridge_live.rate_limiter.lock().unwrap();
        if !rl.check(rate_class) {
            debug!("HTTP bridge: rate limited {} {}", method_str, path_str);
            return Ok(cors(
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(r#"{"error":"rate limited"}"#)))
                    .unwrap(),
            ));
        }
    }

    // Transfers (list, status, start a receive, cancel): the same handlers the CLI and
    // the desktop app use, reached through the same request type.
    if let Some(rest) = path_str.strip_prefix("/api/transfers") {
        let resp = route_transfers(req, rest.to_owned(), state).await;
        return Ok(cors(resp));
    }

    let resp = match (req.method().clone(), req.uri().path()) {
        (Method::GET, "/api/ping") => json_ok(&OkResponse { ok: true }),

        (Method::GET, "/api/status") => handle_status(state).await,

        (Method::POST, "/api/publish") => match read_body(req).await {
            Ok(body) => handle_publish(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        (Method::POST, "/api/retrieve") => match read_body(req).await {
            Ok(body) => handle_retrieve(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        (Method::POST, "/api/wipe") => match read_body(req).await {
            Ok(body) => handle_wipe(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        // ── Directed sharing endpoints ──────────────────────────────────
        (Method::GET, "/api/sharing-key") => handle_sharing_key(state).await,

        (Method::POST, "/api/directed/send") => match read_body(req).await {
            Ok(body) => handle_directed_send(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        (Method::POST, "/api/directed/confirm") => match read_body(req).await {
            Ok(body) => handle_directed_confirm(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        (Method::POST, "/api/directed/retrieve") => match read_body(req).await {
            Ok(body) => handle_directed_retrieve(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        (Method::POST, "/api/directed/revoke") => match read_body(req).await {
            Ok(body) => handle_directed_revoke(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },

        (Method::GET, "/api/directed/inbox") => handle_directed_inbox(state).await,

        (Method::GET, "/api/directed/outbox") => handle_directed_outbox(state).await,

        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    };

    Ok(cors(resp))
}

/// Send a ControlRequest through process_request with all bridge state params.
async fn bridge_request(state: BridgeState, req: ControlRequest) -> ControlResponse {
    process_request(
        req,
        state.coord,
        state.queue,
        state.store,
        state.listen_addrs,
        state.wss_port,
        state.wss_tls_enabled,
        state.proxy_configured,
        state.proxy_type,
        state.obfs_quic_port,
        state.sharing_secret,
        state.sharing_pubkey,
        state.data_dir,
        state.bridge_live,
    )
    .await
}

async fn handle_status(state: BridgeState) -> Response<Full<Bytes>> {
    let resp = bridge_request(state, ControlRequest::Status).await;

    match resp {
        ControlResponse::Status(status) => json_ok(&status),
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_publish(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let req: PublishRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };

    let data = match B64.decode(&req.data) {
        Ok(d) => d,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid base64: {e}")),
    };

    let resp = bridge_request(
        state,
        ControlRequest::Publish {
            data,
            data_shards: req.data_shards,
            total_shards: req.total_shards,
        },
    )
    .await;

    match resp {
        ControlResponse::Published { mid } => json_ok(&PublishResponse { mid }),
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_retrieve(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let req: RetrieveRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };

    let resp = bridge_request(
        state,
        ControlRequest::Get {
            mid: req.mid,
            data_shards: req.data_shards,
            total_shards: req.total_shards,
        },
    )
    .await;

    match resp {
        ControlResponse::Retrieved { data } => json_ok(&RetrieveResponse {
            data: B64.encode(&data),
        }),
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

#[derive(Deserialize, Default)]
struct WipeBody {
    #[serde(default)]
    confirm: Option<String>,
}

#[derive(Serialize)]
struct WipeChallengeResponse {
    challenge: String,
}

async fn handle_wipe(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let parsed: WipeBody = if body.is_empty() {
        WipeBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
        }
    };
    let req = match parsed.confirm {
        Some(nonce) => ControlRequest::WipeConfirm { nonce },
        None => ControlRequest::Wipe,
    };
    let resp = bridge_request(state, req).await;

    match resp {
        ControlResponse::WipeChallenge { nonce } => {
            json_ok(&WipeChallengeResponse { challenge: nonce })
        }
        ControlResponse::Wiped => json_ok(&OkResponse { ok: true }),
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

// ─── Directed sharing HTTP types ─────────────────────────────────────────────

#[derive(Deserialize)]
struct DirectedSendRequest {
    recipient_contact: String,
    data: String, // base64
    password: String,
    retention_secs: u64,
    #[serde(default)]
    filename: Option<String>,
}

#[derive(Serialize)]
struct DirectedSendResponse {
    envelope_id: String,
}

#[derive(Deserialize)]
struct DirectedConfirmRequest {
    envelope_id: String,
    challenge_code: String,
}

#[derive(Deserialize)]
struct DirectedRetrieveRequest {
    envelope_id: String,
    password: String,
}

#[derive(Serialize)]
struct DirectedRetrieveResponse {
    data: String, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
}

#[derive(Deserialize)]
struct DirectedRevokeRequest {
    envelope_id: String,
}

#[derive(Serialize)]
struct SharingKeyResponse {
    key: String,
    contact: String,
}

// ─── Directed sharing HTTP handlers ─────────────────────────────────────────

async fn handle_sharing_key(state: BridgeState) -> Response<Full<Bytes>> {
    let resp = bridge_request(state, ControlRequest::SharingKey).await;
    match resp {
        ControlResponse::SharingKey { key, contact } => {
            json_ok(&SharingKeyResponse { key, contact })
        }
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_directed_send(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let req: DirectedSendRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let data = match B64.decode(&req.data) {
        Ok(d) => d,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid base64: {e}")),
    };
    let resp = bridge_request(
        state,
        ControlRequest::DirectedSend {
            recipient_contact: req.recipient_contact,
            data,
            password: req.password,
            retention_secs: req.retention_secs,
            filename: req.filename,
        },
    )
    .await;
    match resp {
        ControlResponse::DirectedSent { envelope_id } => {
            json_ok(&DirectedSendResponse { envelope_id })
        }
        ControlResponse::Error(e) => json_error(StatusCode::BAD_REQUEST, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_directed_confirm(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let req: DirectedConfirmRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let resp = bridge_request(
        state,
        ControlRequest::DirectedConfirm {
            envelope_id: req.envelope_id,
            challenge_code: req.challenge_code,
        },
    )
    .await;
    match resp {
        ControlResponse::DirectedConfirmed => json_ok(&OkResponse { ok: true }),
        ControlResponse::Error(e) => json_error(StatusCode::BAD_REQUEST, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_directed_retrieve(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let req: DirectedRetrieveRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let resp = bridge_request(
        state,
        ControlRequest::DirectedRetrieve {
            envelope_id: req.envelope_id,
            password: req.password,
        },
    )
    .await;
    match resp {
        ControlResponse::DirectedRetrieved { data, filename } => {
            json_ok(&DirectedRetrieveResponse {
                data: B64.encode(&data),
                filename,
            })
        }
        ControlResponse::Error(e) => json_error(StatusCode::BAD_REQUEST, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_directed_revoke(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    let req: DirectedRevokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let resp = bridge_request(
        state,
        ControlRequest::DirectedRevoke {
            envelope_id: req.envelope_id,
        },
    )
    .await;
    match resp {
        ControlResponse::DirectedRevoked => json_ok(&OkResponse { ok: true }),
        ControlResponse::Error(e) => json_error(StatusCode::BAD_REQUEST, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_directed_inbox(state: BridgeState) -> Response<Full<Bytes>> {
    let resp = bridge_request(state, ControlRequest::DirectedInbox).await;
    match resp {
        ControlResponse::DirectedInboxList(entries) => json_ok(&entries),
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_directed_outbox(state: BridgeState) -> Response<Full<Bytes>> {
    let resp = bridge_request(state, ControlRequest::DirectedOutbox).await;
    match resp {
        ControlResponse::DirectedOutboxList(entries) => json_ok(&entries),
        ControlResponse::Error(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

// ─── Transfers ───────────────────────────────────────────────────────────────

/// Longest output path accepted; far above what any OS allows.
const MAX_OUTPUT_PATH_LEN: usize = 4096;

/// A transfer as the web client sees it: the daemon's status plus the id that
/// `/api/transfers/<id>` and `.../cancel` take (the MID for a receive,
/// `send:<path>` for a send, exactly what `TransferCancel` takes).
#[derive(Serialize)]
struct TransferJson {
    id: String,
    #[serde(flatten)]
    status: crate::transfer::TransferStatus,
}

fn transfer_json(status: crate::transfer::TransferStatus) -> TransferJson {
    let id = match status.kind {
        crate::transfer::TransferKind::Receive => status.mid.clone(),
        crate::transfer::TransferKind::Send => {
            crate::transfer::jobs::send_id(std::path::Path::new(&status.name))
        }
    };
    TransferJson { id, status }
}

#[derive(Deserialize)]
struct TransferReceiveRequest {
    mid: String,
    /// Absolute path on the daemon's computer. A browser has no filesystem path
    /// to offer, so the person types where the *daemon* should save the file;
    /// the same policy as every other daemon-side write applies (absolute, no `..`).
    output_path: String,
    #[serde(default)]
    password: Option<String>,
    /// Discard any partial transfer and start over.
    #[serde(default)]
    restart: bool,
}

// The password is never printed, whatever formats this.
impl std::fmt::Debug for TransferReceiveRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferReceiveRequest")
            .field("mid", &self.mid)
            .field("output_path", &"<redacted>")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("restart", &self.restart)
            .finish()
    }
}

impl Drop for TransferReceiveRequest {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.zeroize();
        }
    }
}

#[derive(Serialize)]
struct TransferStartedResponse {
    id: String,
}

/// Decode `%XX` escapes (a send id contains a path, so it arrives encoded).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// HTTP status for an error string the request handlers produce.
fn transfer_error_status(e: &str) -> StatusCode {
    if e.starts_with("output path rejected") || e.starts_with("invalid MID") {
        StatusCode::BAD_REQUEST
    } else if e.starts_with("no such transfer") {
        StatusCode::NOT_FOUND
    } else if e.starts_with("no running transfer") {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn route_transfers(
    req: Request<Incoming>,
    rest: String,
    state: BridgeState,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let segments: Vec<&str> = match rest.strip_prefix('/') {
        None if rest.is_empty() => Vec::new(),
        None => return json_error(StatusCode::NOT_FOUND, "not found"),
        Some(r) => r.split('/').collect(),
    };
    match (&method, segments.as_slice()) {
        (&Method::GET, []) => handle_transfer_list(state).await,
        (&Method::POST, ["receive"]) => match read_body(req).await {
            Ok(body) => handle_transfer_receive(body, state).await,
            Err(e) => json_error(StatusCode::BAD_REQUEST, &e.to_string()),
        },
        (&Method::GET, [id]) if !id.is_empty() => match percent_decode(id) {
            Some(id) => handle_transfer_status(id, state).await,
            None => json_error(StatusCode::BAD_REQUEST, "bad transfer id"),
        },
        (&Method::POST, [id, "cancel"]) if !id.is_empty() => match percent_decode(id) {
            Some(id) => handle_transfer_cancel(id, state).await,
            None => json_error(StatusCode::BAD_REQUEST, "bad transfer id"),
        },
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn handle_transfer_list(state: BridgeState) -> Response<Full<Bytes>> {
    match bridge_request(state, ControlRequest::TransferList).await {
        ControlResponse::TransferList(list) => {
            let list: Vec<TransferJson> = list.into_iter().map(transfer_json).collect();
            json_ok(&list)
        }
        ControlResponse::Error(e) => json_error(transfer_error_status(&e), &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_transfer_status(id: String, state: BridgeState) -> Response<Full<Bytes>> {
    match bridge_request(state, ControlRequest::TransferStatus { id }).await {
        ControlResponse::TransferStatus(s) => json_ok(&transfer_json(s)),
        ControlResponse::Error(e) => json_error(transfer_error_status(&e), &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_transfer_cancel(id: String, state: BridgeState) -> Response<Full<Bytes>> {
    match bridge_request(state, ControlRequest::TransferCancel { id }).await {
        ControlResponse::TransferCancelled => json_ok(&OkResponse { ok: true }),
        ControlResponse::Error(e) => json_error(transfer_error_status(&e), &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

async fn handle_transfer_receive(body: Bytes, state: BridgeState) -> Response<Full<Bytes>> {
    // A serde error message can quote the offending value (a password sent as a
    // number, say), so this endpoint answers "bad body" and nothing more.
    let parsed = serde_json::from_slice::<TransferReceiveRequest>(&body);
    scrub(body);
    let mut req = match parsed {
        Ok(r) => r,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid JSON body: expected {\"mid\", \"output_path\", optional \"password\", \"restart\"}",
            )
        }
    };
    let checks = [
        validate_field_length("mid", &req.mid, MAX_MID_LEN),
        validate_field_length("output_path", &req.output_path, MAX_OUTPUT_PATH_LEN),
        match &req.password {
            Some(p) => validate_field_length("password", p, MAX_PASSWORD_LEN),
            None => Ok(()),
        },
    ];
    if let Some(Err(e)) = checks.into_iter().find(|c| c.is_err()) {
        return json_error(StatusCode::BAD_REQUEST, &e);
    }

    // An empty password field means "no password".
    let password = req.password.take().filter(|p| !p.is_empty());
    let request = ControlRequest::TransferStartReceive {
        mid: std::mem::take(&mut req.mid),
        output_path: std::mem::take(&mut req.output_path),
        password,
        restart: req.restart,
    };
    // The output-path policy (absolute, no `..`) and the MID check are the
    // daemon's own, the same as for the CLI and the desktop app.
    match bridge_request(state, request).await {
        ControlResponse::TransferStarted { id } => json_ok(&TransferStartedResponse { id }),
        ControlResponse::Error(e) => json_error(transfer_error_status(&e), &e),
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected response"),
    }
}

/// Overwrite the raw request body when this is its only owner (best effort: the
/// HTTP stack may have made other copies).
fn scrub(body: Bytes) {
    if let Ok(mut m) = body.try_into_mut() {
        Zeroize::zeroize(&mut m[..]);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn read_body(req: Request<Incoming>) -> Result<Bytes> {
    let upper = req.body().size_hint().upper().unwrap_or(u64::MAX) as usize;
    if upper > MAX_BODY {
        anyhow::bail!("request body too large ({upper} bytes, max {MAX_BODY})");
    }
    let body = req
        .collect()
        .await
        .context("reading request body")?
        .to_bytes();
    if body.len() > MAX_BODY {
        anyhow::bail!(
            "request body too large ({} bytes, max {MAX_BODY})",
            body.len()
        );
    }
    Ok(body)
}

fn json_ok<T: Serialize>(value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn json_error(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: msg.to_string(),
    })
    .unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn static_response(asset: &'static super::web_assets::Asset) -> Response<Full<Bytes>> {
    // `no-cache` so a new daemon build is picked up on the next load; the client's
    // service worker keeps its own versioned cache for offline use.
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_FRAME_OPTIONS, "DENY")
        .body(Full::new(Bytes::from_static(asset.body)))
        .unwrap()
}

/// Add CORS headers to a response.  Localhost-only binding makes wildcard
/// origin safe — any local process can already reach the daemon via IPC.
fn cors(mut resp: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = resp.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "Content-Type, Authorization".parse().unwrap(),
    );
    resp
}
