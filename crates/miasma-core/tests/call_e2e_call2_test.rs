//! STEP CALL1 end-to-end call-control test: a busy callee over three real
//! peers on a local relay.
//!
//! This scenario complements the existing call E2E suites
//! (`call_e2e_call1_test.rs`, `call_e2e_pr6_test.rs`, `call_e2e_video_test.rs`,
//! `call_ipc_media_test.rs`) by proving one thing none of them assert:
//!
//!   (f) a dial to a callee that is already in a connected call is refused
//!       cleanly. With B and C connected, A dials B: A receives a `peer_busy`
//!       notice and returns to `idle` having started no media, while B and C
//!       stay connected and undisturbed.
//!
//! The harness mirrors `call_e2e_call1_test.rs`: each peer runs its own real
//! `ChatService` over its own real in-process iroh node on a local relay (no
//! traffic to any public service), with a real `CallRuntime` whose camera and
//! screen factories are deterministic fakes injected through the documented
//! `CallRuntime::start_with_factories` hook. No real capture device is opened
//! and nothing depends on a capture backend. No fixed key, salt or password
//! appears here; seeds come from `rand::random()`. No frame, pixel or key is
//! ever printed.

#![cfg(all(feature = "iroh", feature = "pqc"))]

use std::{sync::Arc, time::Duration};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        call::{
            media_task::IrohLinkProvider,
            runtime::{register_runtime, CallRuntime},
            video::{ScreenSourceFactory, VideoSource},
        },
        crypto::Identity,
        ipc::{
            handle_with, CallNoticeDto, CallRequest, CallResponse, CallStatusDto, ChatRequest,
            ChatResponse,
        },
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

/// A camera factory that never opens a device: these scenarios never start the
/// camera or a screen share, so no video source is ever created.
struct NoVideo;
impl ScreenSourceFactory for NoVideo {
    fn create(&self) -> Option<Box<dyn VideoSource + Send>> {
        None
    }
}

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

/// One real peer with a real runtime whose camera and screen factories never
/// open a device: this suite tests call control, not media capture.
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
    let provider = Arc::new(IrohLinkProvider::new(svc.node().clone()));
    let runtime = CallRuntime::start_with_factories(
        svc.clone(),
        provider,
        Arc::new(NoVideo),
        Arc::new(NoVideo),
    );
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

/// All notice codes raised on `p` since the start of the call, read through the
/// IPC `Events` request from sequence zero.
fn notice_codes(p: &Peer) -> Vec<String> {
    match call(p, CallRequest::Events { since: 0 }) {
        CallResponse::Events { notices, .. } => notices
            .into_iter()
            .map(|CallNoticeDto { code }| code)
            .collect(),
        other => panic!("expected an events response, got {other:?}"),
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

/// Drive a real hybrid exchange between two peers already registered to each
/// other under the given labels, so both sides report `hybrid` and the media
/// gate is ready to dial.
async fn warm_hybrid(a: &Peer, a_to_b: &str, b: &Peer) {
    send(a, a_to_b, "hello");
    until(60, "the first message", || received(b, &a.id()) == 1).await;
    until(60, "hybrid at both sides", || {
        pqc_hybrid(a, &b.id()) && pqc_hybrid(b, &a.id())
    })
    .await;
}

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

/// Dial from `a` to contact `label` and accept on `b`, leaving both connected.
async fn dial_and_accept(a: &Peer, label: &str, b: &Peer) {
    assert!(matches!(
        call(
            a,
            CallRequest::Dial {
                contact: label.into()
            }
        ),
        CallResponse::Ok
    ));
    let token = ringing_token(b).await;
    assert!(matches!(
        call(b, CallRequest::Accept { token }),
        CallResponse::Ok
    ));
    until(30, "both connected", || {
        status(a).state == "connected" && status(b).state == "connected"
    })
    .await;
}

/// (f) A dial to a callee already in a connected call is refused cleanly with a
/// `peer_busy` notice, and the existing call is undisturbed.
#[tokio::test(flavor = "multi_thread")]
async fn dial_to_busy_callee_is_refused_and_existing_call_survives() {
    timeout(Duration::from_secs(150), async {
        let relay = relay().await;
        let (a, b, c) = (peer(&relay).await, peer(&relay).await, peer(&relay).await);

        // A knows B; B and C know each other. Each direction used below is
        // registered so a dial resolves the contact.
        register(&a, b.id(), "bob");
        register(&b, a.id(), "alice");
        register(&b, c.id(), "carol");
        register(&c, b.id(), "bob");

        // Warm both pairs to hybrid so every later dial's gate is ready.
        warm_hybrid(&a, "bob", &b).await;
        warm_hybrid(&c, "bob", &b).await;

        // B and C establish a connected call.
        dial_and_accept(&c, "bob", &b).await;

        // A dials B while B is connected to C. The local gate is ready, so the
        // dial is admitted and A enters `calling`.
        assert!(matches!(
            call(
                &a,
                CallRequest::Dial {
                    contact: "bob".into()
                }
            ),
            CallResponse::Ok
        ));
        until(10, "A to be calling", || status(&a).state == "calling").await;

        // B is busy: it replies Busy, so A leaves `calling`, returns to idle and
        // raises a `peer_busy` notice without ever starting media.
        until(60, "A to return to idle after a busy callee", || {
            status(&a).state == "idle"
        })
        .await;
        assert!(
            notice_codes(&a).iter().any(|c| c == "peer_busy"),
            "a peer_busy notice should be raised when the callee is in a call"
        );
        let sa = status(&a);
        assert_eq!(sa.state, "idle");
        assert_eq!(sa.media_frames_sent, 0);
        assert_eq!(sa.media_frames_played, 0);

        // The B<->C call is undisturbed: both remain connected.
        assert_eq!(status(&b).state, "connected");
        assert_eq!(status(&c).state, "connected");

        // A clean hang-up on C returns both B and C to idle.
        assert!(matches!(call(&c, CallRequest::HangUp), CallResponse::Ok));
        until(30, "B and C back to idle", || {
            status(&b).state == "idle" && status(&c).state == "idle"
        })
        .await;

        a.svc.shutdown();
        b.svc.shutdown();
        c.svc.shutdown();
    })
    .await
    .expect("busy-callee scenario timed out");
}
