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
//! | GET    | `/api/ping`     | Connection liveness check                |
//! | GET    | `/api/status`   | Full `DaemonStatus` snapshot             |
//! | POST   | `/api/publish`  | Dissolve + publish (base64 data)         |
//! | POST   | `/api/retrieve` | Network retrieve by MID (returns base64) |
//! | POST   | `/api/wipe`     | Distress wipe                            |
//!
//! # Security
//!
//! Binds only to `127.0.0.1` — unreachable from the network.  Same trust
//! model as the IPC listener: if you can reach localhost, you are the user.
//! CORS `Access-Control-Allow-Origin: *` is safe under this constraint.

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

use crate::{network::coordinator::MiasmaCoordinator, store::LocalShareStore};

use super::{
    ipc::{ControlRequest, ControlResponse},
    process_request,
    replication::ReplicationQueue,
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
    sharing_secret: [u8; 32],
    sharing_pubkey: [u8; 32],
    data_dir: std::path::PathBuf,
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
        sharing_secret: [u8; 32],
        sharing_pubkey: [u8; 32],
        data_dir: std::path::PathBuf,
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

        (Method::POST, "/api/wipe") => handle_wipe(state).await,

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

async fn handle_wipe(state: BridgeState) -> Response<Full<Bytes>> {
    let resp = bridge_request(state, ControlRequest::Wipe).await;

    match resp {
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
        "Content-Type".parse().unwrap(),
    );
    resp
}
