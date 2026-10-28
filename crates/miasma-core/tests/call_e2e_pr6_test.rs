//! End-to-end call over two real peers on a local iroh relay. Each peer runs
//! its own real `ChatService` and a real `CallRuntime`; the control plane
//! (`send_call_control` / inbound dispatch) and the hybrid key derivation run
//! over the real authenticated connection with no mocks. Keys come from the
//! real Offer/Answer shares. The caller drives the call through the IPC handle
//! exactly as the daemon does.
//!
//! The harness is the real-network one from `chat_sync_net_test.rs` /
//! `chat_pqc_net_test.rs`: in-process iroh nodes on a local relay, no traffic to
//! any public service. The media-ready gate (`media_gate`) only reports `Ready`
//! once the hybrid exchange has completed, so each scenario performs that
//! exchange first (one chat message, then a bounded wait for `pqc == hybrid` on
//! both sides) before dialing.

#![cfg(all(feature = "iroh", feature = "pqc"))]

use std::{sync::Arc, time::Duration};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        call::runtime::{register_runtime, CallRuntime},
        crypto::Identity,
        ipc::{handle_with, CallRequest, CallResponse, CallStatusDto, ChatRequest, ChatResponse},
        service::{ChatService, ChatSettings},
        store::StoreSettings,
    },
    config::{IrohMode, PqcMode},
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{endpoint_builder, IrohNode, IrohServerLimits, IrohSettings},
    LocalShareStore,
};
use tempfile::TempDir;
use tokio::time::timeout;

struct Relay {
    _server: iroh_relay::server::Server,
    url: String,
}

async fn relay() -> Relay {
    let mut cfg = iroh_relay::server::testing::server_config();
    cfg.quic = None;
    let server = iroh_relay::server::Server::spawn(cfg).await.unwrap();
    let url = format!("https://{}", server.https_addr().unwrap());
    Relay {
        _server: server,
        url,
    }
}

fn settings() -> ChatSettings {
    ChatSettings {
        retry_delays: vec![Duration::from_millis(200)],
        retry_every: Duration::from_millis(300),
        retry_jitter: 0.0,
        idle_timeout: Duration::from_secs(20),
        pqc_mode: PqcMode::Require,
        ..ChatSettings::default()
    }
}

async fn start_node(relay: &Relay, seed: &[u8; 32]) -> Arc<IrohNode> {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(store_dir.path(), 10).unwrap());
    let s = IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec![relay.url.clone()],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(4),
        ca_pem: None,
        proxy_from_env: false,
    };
    let builder = endpoint_builder(Some(seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    let node = IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap();
    assert!(node.wait_online(Duration::from_secs(20)).await);
    std::mem::forget(store_dir);
    node
}

/// One real peer: a real `ChatService` over its own real iroh node, with a real
/// `CallRuntime` registered so the IPC handle can reach it. The runtime uses
/// the production `IrohLinkProvider` (via `CallRuntime::start`), which opens
/// media links over the same real nodes.
struct Peer {
    svc: Arc<ChatService>,
    _runtime: Arc<CallRuntime>,
    node: Arc<IrohNode>,
    contacts: Arc<ContactStore>,
    _dir: TempDir,
}

impl Peer {
    fn id(&self) -> [u8; 32] {
        self.node.endpoint_id()
    }
}

async fn peer(relay: &Relay) -> Peer {
    let dir = tempfile::tempdir().unwrap();
    let seed: [u8; 32] = rand::random();
    let node = start_node(relay, &seed).await;
    let contacts = Arc::new(ContactStore::open(dir.path()));
    let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
    let svc = ChatService::start(
        &dir.path().join("chat"),
        node.clone(),
        &seed,
        keys,
        contacts.clone(),
        StoreSettings::default(),
        settings(),
    )
    .expect("chat starts");
    assert_eq!(Identity::from_seed(&seed).id(), node.endpoint_id());
    // The real runtime over the real service; register it under this data dir so
    // `handle_with(.., ChatRequest::Call(..))` resolves it the way the daemon does.
    let runtime = CallRuntime::start(svc.clone());
    register_runtime(dir.path(), runtime.clone());
    Peer {
        svc,
        _runtime: runtime,
        node,
        contacts,
        _dir: dir,
    }
}

fn register(a: &Peer, b_id: [u8; 32], label: &str) {
    a.contacts
        .add(&ContactCode::new(b_id), Some(label), Some(&a.id()))
        .unwrap();
}

fn send(a: &Peer, label: &str, text: &str) {
    let r = handle_with(
        &a.svc,
        ChatRequest::Send {
            contact: label.into(),
            text: text.into(),
        },
    );
    assert!(matches!(r, ChatResponse::Queued { .. }), "{r:?}");
}

fn received(p: &Peer, other: &[u8; 32]) -> usize {
    p.svc
        .core()
        .history(other, None, 200)
        .into_iter()
        .filter(|m| !m.outgoing)
        .count()
}

fn pqc_hybrid(p: &Peer, other: &[u8; 32]) -> bool {
    match handle_with(&p.svc, ChatRequest::Conversations {}) {
        ChatResponse::Conversations(list) => {
            list.into_iter()
                .find(|c| c.endpoint_id == hex::encode(other))
                .and_then(|c| c.pqc)
                .as_deref()
                == Some("hybrid")
        }
        _ => false,
    }
}

fn call(p: &Peer, request: CallRequest) -> CallResponse {
    match handle_with(&p.svc, ChatRequest::Call(request)) {
        ChatResponse::Call(r) => r,
        other => panic!("expected a call response, got {other:?}"),
    }
}

fn status(p: &Peer) -> CallStatusDto {
    match call(p, CallRequest::Status) {
        CallResponse::Status(s) => s,
        other => panic!("expected a status, got {other:?}"),
    }
}

async fn until(secs: u64, what: &str, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(
            std::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Two peers that know each other and have completed the real hybrid exchange,
/// so the media gate reports `Ready` and a dial is admitted. One chat message
/// in each direction drives the exchange; the wait is bounded.
async fn ready_pair(relay: &Relay) -> (Peer, Peer) {
    let (a, b) = (peer(relay).await, peer(relay).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "hello");
    until(60, "the first message", || received(&b, &a.id()) == 1).await;
    until(60, "hybrid at both sides", || {
        pqc_hybrid(&a, &b.id()) && pqc_hybrid(&b, &a.id())
    })
    .await;
    (a, b)
}

/// The outstanding incoming-call token on the callee, once it is ringing.
async fn ringing_token(b: &Peer) -> u64 {
    let mut token = None;
    until(30, "the callee to ring", || {
        let s = status(b);
        if s.state == "ringing" {
            token = s.pending_token;
        }
        token.is_some()
    })
    .await;
    token.expect("a pending token once ringing")
}

#[tokio::test(flavor = "multi_thread")]
async fn dial_accept_reaches_connected_and_media_flows() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;

        // A dials B through the IPC handle.
        assert!(matches!(
            call(
                &a,
                CallRequest::Dial {
                    contact: "bob".into()
                }
            ),
            CallResponse::Ok
        ));

        // B sees the incoming call and accepts it.
        let token = ringing_token(&b).await;
        assert!(matches!(
            call(&b, CallRequest::Accept { token }),
            CallResponse::Ok
        ));

        // Both sides reach Connected over the real signalling.
        until(30, "both connected", || {
            status(&a).state == "connected" && status(&b).state == "connected"
        })
        .await;

        // Real media flows in both directions: sent and played counters rise on
        // both peers. The link, frames and counters are the production ones.
        until(60, "media on both sides", || {
            let (sa, sb) = (status(&a), status(&b));
            sa.media_frames_sent > 0
                && sa.media_frames_played > 0
                && sb.media_frames_sent > 0
                && sb.media_frames_played > 0
        })
        .await;

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("dial/accept/media timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn reject_starts_no_media() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;

        assert!(matches!(
            call(
                &a,
                CallRequest::Dial {
                    contact: "bob".into()
                }
            ),
            CallResponse::Ok
        ));
        let token = ringing_token(&b).await;
        assert!(matches!(
            call(&b, CallRequest::Reject { token }),
            CallResponse::Ok
        ));

        // Neither side connects, and no media ever starts.
        until(30, "the caller to leave calling", || {
            status(&a).state != "calling"
        })
        .await;
        // Give any (incorrect) media task a chance to run before asserting zero.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for p in [&a, &b] {
            let s = status(p);
            assert_ne!(s.state, "connected");
            assert_eq!(s.media_frames_sent, 0);
            assert_eq!(s.media_frames_played, 0);
        }

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("reject scenario timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn hang_up_returns_both_to_idle_with_zero_counters() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;

        assert!(matches!(
            call(
                &a,
                CallRequest::Dial {
                    contact: "bob".into()
                }
            ),
            CallResponse::Ok
        ));
        let token = ringing_token(&b).await;
        assert!(matches!(
            call(&b, CallRequest::Accept { token }),
            CallResponse::Ok
        ));
        until(30, "both connected", || {
            status(&a).state == "connected" && status(&b).state == "connected"
        })
        .await;
        until(60, "media before the hang-up", || {
            let (sa, sb) = (status(&a), status(&b));
            sa.media_frames_sent > 0
                && sa.media_frames_played > 0
                && sb.media_frames_sent > 0
                && sb.media_frames_played > 0
        })
        .await;

        // A hangs up while connected.
        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));

        // Both sides return to Idle, and the status counters read zero (the
        // status reports no media once the call is not Connected).
        until(30, "both back to idle", || {
            status(&a).state == "idle" && status(&b).state == "idle"
        })
        .await;
        for p in [&a, &b] {
            let s = status(p);
            assert_eq!(s.state, "idle");
            assert_eq!(s.media_frames_sent, 0);
            assert_eq!(s.media_frames_played, 0);
        }

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("hang-up scenario timed out");
}
