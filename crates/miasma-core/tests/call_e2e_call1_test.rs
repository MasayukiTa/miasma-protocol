//! STEP CALL1 end-to-end call tests over two real peers on a local relay.
//!
//! These scenarios complement the existing call E2E suites
//! (`call_e2e_pr6_test.rs`, `call_e2e_video_test.rs`, `call_ipc_media_test.rs`)
//! by proving three things those suites do not yet assert directly:
//!
//!   (a) a voice call carries at least 50 audio frames in BOTH directions
//!       before the caller hangs up and both sides return to idle;
//!   (b) a screen share during a call is DECODED on the receiving side: with
//!       both peers sharing, each decodes the other's screen stream and the
//!       received remote frame has the exact size of the fake screen source;
//!       stopping releases the source and clears the sharing flag;
//!   (e) a call to an OFFLINE callee ends cleanly: the caller leaves `calling`,
//!       returns to `idle`, raises a `no_answer` notice and starts no media.
//!
//! The harness mirrors `call_ipc_media_test.rs`: each peer runs its own real
//! `ChatService` over its own real in-process iroh node on a local relay (no
//! traffic to any public service), with a real `CallRuntime` whose camera and
//! screen factories are deterministic fakes injected through the documented
//! `CallRuntime::start_with_factories` hook. No real capture device is opened
//! and nothing depends on a capture backend. No fixed key, salt or password
//! appears here; seeds come from `rand::random()`. No frame, pixel or key is
//! ever printed.

#![cfg(all(feature = "iroh", feature = "pqc"))]

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        call::{
            media_task::IrohLinkProvider,
            runtime::{register_runtime, CallRuntime},
            video::{RawPicture, ScreenSourceFactory, VideoSource},
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

// The fake screen source hands out a fixed picture of this exact size, distinct
// from the camera geometry, so the receiving side can assert the decoded remote
// frame carries the screen dimensions and nothing else.
const SCREEN_WIDTH: u16 = 32;
const SCREEN_HEIGHT: u16 = 24;
const SCREEN_SIZE: usize = (SCREEN_WIDTH as usize) * (SCREEN_HEIGHT as usize);

// How many audio frames must cross the wire in each direction for the voice
// test to pass. At one 20 ms frame per tick this is one second of audio.
const AUDIO_FRAMES_REQUIRED: u64 = 50;

/// A fake video source that reports open and hands out a fixed picture, so a
/// media task's screen driver captures and the sharing flag follows. Holds no
/// device and no secret. On drop it bumps a shared counter, so a test can see
/// the source was released on stop or hang-up without touching the device.
struct FakeScreen {
    open: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}

impl Drop for FakeScreen {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl VideoSource for FakeScreen {
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }
    fn next_picture(&mut self) -> Option<RawPicture> {
        Some(RawPicture {
            width: SCREEN_WIDTH,
            height: SCREEN_HEIGHT,
            pixels: vec![128u8; SCREEN_SIZE],
        })
    }
}

/// A fake factory that opens a `FakeScreen` on demand. The shared counters let
/// a test observe how many sources were created and dropped.
struct FakeScreenFactory {
    creates: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl ScreenSourceFactory for FakeScreenFactory {
    fn create(&self) -> Option<Box<dyn VideoSource + Send>> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        Some(Box::new(FakeScreen {
            open: Arc::new(AtomicBool::new(true)),
            drops: self.drops.clone(),
        }))
    }
}

/// A camera factory that never opens a device: these scenarios never start the
/// camera, so the camera stream stays dormant.
struct NoCamera;
impl ScreenSourceFactory for NoCamera {
    fn create(&self) -> Option<Box<dyn VideoSource + Send>> {
        None
    }
}

/// The create/drop counters for the screen factory, kept beside the peer so a
/// test can read them after a press.
#[derive(Clone)]
struct Counters {
    creates: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Counters {
    fn new() -> Self {
        Self {
            creates: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn factory(&self) -> Arc<dyn ScreenSourceFactory> {
        Arc::new(FakeScreenFactory {
            creates: self.creates.clone(),
            drops: self.drops.clone(),
        })
    }
    fn created(&self) -> usize {
        self.creates.load(Ordering::SeqCst)
    }
    fn dropped(&self) -> usize {
        self.drops.load(Ordering::SeqCst)
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

/// One real peer with a real runtime whose screen factory is the fake above and
/// whose camera factory never opens a device. The peer keeps the screen
/// factory's create/drop counters so a test can read them.
struct Peer {
    svc: Arc<ChatService>,
    _runtime: Arc<CallRuntime>,
    node: Arc<IrohNode>,
    contacts: Arc<ContactStore>,
    screen: Counters,
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
    // The real production media link provider, same as `CallRuntime::start`;
    // only the screen factory is a test fake and the camera stays dormant.
    let provider = Arc::new(IrohLinkProvider::new(svc.node().clone()));
    let screen = Counters::new();
    let runtime = CallRuntime::start_with_factories(
        svc.clone(),
        provider,
        Arc::new(NoCamera),
        screen.factory(),
    );
    register_runtime(dir.path(), runtime.clone());
    Peer {
        svc,
        _runtime: runtime,
        node,
        contacts,
        screen,
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

/// The latest decoded remote frame's size, read through the IPC `RemoteFrame`
/// request, or `None` when nothing newer than `last_seen` has been decoded.
fn remote_frame_size(p: &Peer, last_seen: u64) -> Option<(u16, u16, usize)> {
    match call(p, CallRequest::RemoteFrame { last_seen }) {
        CallResponse::RemoteFrame(Some(frame)) => {
            Some((frame.width, frame.height, frame.rgba.len()))
        }
        CallResponse::RemoteFrame(None) => None,
        other => panic!("expected a remote-frame response, got {other:?}"),
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

async fn dial_and_accept(a: &Peer, b: &Peer) {
    assert!(matches!(
        call(
            a,
            CallRequest::Dial {
                contact: "bob".into()
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
    // Video is negotiated by default on both sides, so a screen share is
    // admitted rather than refused with `not_ready`.
    for p in [a, b] {
        assert!(
            status(p).negotiated_video,
            "both sides should negotiate video"
        );
    }
}

/// (a) A voice call carries at least 50 audio frames in both directions, then a
/// hang-up returns both sides to idle with the audio counters back to zero.
#[tokio::test(flavor = "multi_thread")]
async fn voice_call_carries_fifty_audio_frames_both_ways_then_hang_up() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;
        dial_and_accept(&a, &b).await;

        // At least 50 audio frames are sent and played on BOTH peers: the real
        // link, frames and counters are the production ones.
        until(90, "fifty audio frames both ways", || {
            let (sa, sb) = (status(&a), status(&b));
            sa.media_frames_sent >= AUDIO_FRAMES_REQUIRED
                && sa.media_frames_played >= AUDIO_FRAMES_REQUIRED
                && sb.media_frames_sent >= AUDIO_FRAMES_REQUIRED
                && sb.media_frames_played >= AUDIO_FRAMES_REQUIRED
        })
        .await;

        // A hangs up while connected; both return to idle with zero counters.
        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));
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
    .expect("voice-call scenario timed out");
}

/// (b) Screen sharing is decoded on the receiving side. Both peers start
/// sharing a fake screen source, so each has a screen driver that decodes the
/// other's stream. Within a bounded wait B decodes a remote frame whose size is
/// exactly the fake screen source's size. Each side opened one screen source on
/// its press. A then stops: A's source is released and its sharing flag clears,
/// while audio keeps flowing on B.
#[tokio::test(flavor = "multi_thread")]
async fn screen_share_is_received_with_the_expected_size_then_stopped() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;
        dial_and_accept(&a, &b).await;

        // Audio must be flowing before the screen requests, so each media task
        // is running and able to accept the attach control.
        until(60, "audio on both sides", || {
            status(&a).media_frames_played > 0 && status(&b).media_frames_played > 0
        })
        .await;

        // Both sides start sharing: each opens exactly one fake screen source
        // and reports screen sharing. Both are needed so each side has a screen
        // driver that can decode the other's screen stream.
        for p in [&a, &b] {
            assert!(matches!(
                call(p, CallRequest::StartScreenShare),
                CallResponse::Ok
            ));
        }
        assert_eq!(a.screen.created(), 1, "A opened one screen source");
        assert_eq!(b.screen.created(), 1, "B opened one screen source");
        until(30, "both to report screen sharing", || {
            status(&a).screen_sharing && status(&b).screen_sharing
        })
        .await;

        // B decodes a remote screen frame carried over the real fragmentation,
        // network and reassembly path. Its size is exactly the fake screen
        // source's size (no camera is running, so the screen picture is the one
        // published). The pixels themselves are never inspected.
        until(
            60,
            "B to decode a remote screen frame of the expected size",
            || {
                matches!(
                    remote_frame_size(&b, 0),
                    Some((w, h, len))
                        if w == SCREEN_WIDTH && h == SCREEN_HEIGHT && len == SCREEN_SIZE
                )
            },
        )
        .await;

        let audio_before = status(&b).media_frames_played;

        // A stops sharing: the source A opened is released and the flag clears.
        assert!(matches!(
            call(&a, CallRequest::StopScreenShare),
            CallResponse::Ok
        ));
        until(30, "A's screen source to be released", || {
            a.screen.dropped() >= 1
        })
        .await;
        until(30, "A to stop reporting screen sharing", || {
            !status(&a).screen_sharing
        })
        .await;

        // Audio keeps flowing on B across the screen stop.
        until(30, "audio to keep arriving on B", || {
            status(&b).media_frames_played > audio_before
        })
        .await;

        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));
        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("screen-share receive scenario timed out");
}

/// (e) A call to an offline callee ends cleanly. A and B complete the hybrid
/// exchange, then B goes offline (its node and service shut down). A dials: the
/// gate is still Ready from the cached session, so the dial is admitted and A
/// enters `calling`. With no answer, A's offer times out: A returns to `idle`,
/// raises a `no_answer` notice and never starts media.
#[tokio::test(flavor = "multi_thread")]
async fn call_to_offline_callee_ends_cleanly_with_no_answer() {
    // The caller's offer times out after OFFER_TTL_MS (45 s); allow headroom.
    timeout(Duration::from_secs(110), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;

        // B goes offline: shut its service and node down so it can neither ring
        // nor answer. A still holds the completed hybrid session, so its gate
        // stays Ready and the dial is admitted.
        b.svc.shutdown();
        b.node.shutdown().await;

        assert!(matches!(
            call(
                &a,
                CallRequest::Dial {
                    contact: "bob".into()
                }
            ),
            CallResponse::Ok
        ));
        // A is calling an endpoint that will never answer.
        until(10, "A to be calling", || status(&a).state == "calling").await;

        // With no answer, A's offer times out and A returns cleanly to idle.
        until(90, "A to return to idle after no answer", || {
            status(&a).state == "idle"
        })
        .await;

        // The clean outcome is reported as a `no_answer` notice, and no media
        // was ever established on A.
        assert!(
            notice_codes(&a).iter().any(|c| c == "no_answer"),
            "a no_answer notice should be raised for an offline callee"
        );
        let s = status(&a);
        assert_eq!(s.state, "idle");
        assert_eq!(s.media_frames_sent, 0);
        assert_eq!(s.media_frames_played, 0);

        a.svc.shutdown();
    })
    .await
    .expect("offline-callee scenario timed out");
}
