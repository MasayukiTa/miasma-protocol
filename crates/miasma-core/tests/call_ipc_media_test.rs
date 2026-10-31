//! End-to-end media control over two real peers on a local relay, driven
//! through the IPC request path. Each peer runs its own real `ChatService`
//! over its own real node and a real `CallRuntime`, as in
//! `call_e2e_pr6_test.rs` and `call_e2e_video_test.rs`. The addition here is
//! that the camera and screen streams are started and stopped through the IPC
//! requests `CallRequest::StartCamera` / `StopCamera` /
//! `CallRequest::StartScreenShare` / `StopScreenShare`, exactly as the daemon
//! does, with fake camera and screen factories injected through the existing
//! `CallRuntime::start_with_factories` test hook. No real device is opened and
//! nothing depends on a capture backend.
//!
//! The factories hand out deterministic fake sources (a small fixed picture)
//! and count how many were created and dropped, so a test can observe that a
//! source was opened on the press and released on stop or hang-up without
//! looking at any pixels. Each peer injects both factories, so each side has a
//! video driver once it starts its camera and can therefore decode the frames
//! the other side sends over the real fragmentation, network and reassembly
//! path.
//!
//! The harness mirrors the one in `call_e2e_pr6_test.rs`: in-process nodes on a
//! local relay, no traffic to any public service, and a bounded real hybrid
//! exchange before dialing so the media gate reports ready. No fixed key or
//! password appears here; no frame, pixel or key is ever printed.

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

// Fake picture geometry. Small and fixed; the pixels are never inspected or
// printed, only counted on the wire via the video-played counter.
const PIC_WIDTH: u16 = 8;
const PIC_HEIGHT: u16 = 8;
const PIC_SIZE: usize = (PIC_WIDTH as usize) * (PIC_HEIGHT as usize);

/// A fake video source that reports open and hands out a fixed small picture,
/// so a media task's driver captures and the in-use flag follows. Holds no
/// device and no secret. On drop it bumps a shared counter, so a test can see
/// the source was released on stop or hang-up without touching the device.
struct FakeSource {
    open: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}

impl Drop for FakeSource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl VideoSource for FakeSource {
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }
    fn next_picture(&mut self) -> Option<RawPicture> {
        Some(RawPicture {
            width: PIC_WIDTH,
            height: PIC_HEIGHT,
            pixels: vec![0u8; PIC_SIZE],
        })
    }
}

/// A fake factory that opens a `FakeSource` on demand. The shared counters let
/// a test observe how many sources were created and dropped. Used for both the
/// camera and the screen stream; each stream gets its own factory instance.
struct FakeFactory {
    creates: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl ScreenSourceFactory for FakeFactory {
    fn create(&self) -> Option<Box<dyn VideoSource + Send>> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        Some(Box::new(FakeSource {
            open: Arc::new(AtomicBool::new(true)),
            drops: self.drops.clone(),
        }))
    }
}

/// The create/drop counters for one stream's factory, kept beside the peer so
/// a test can read them after the press.
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
        Arc::new(FakeFactory {
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

/// One real peer with a real runtime whose camera and screen factories are the
/// fakes above, injected through `CallRuntime::start_with_factories`. The peer
/// keeps the create/drop counters for each stream so a test can read them.
struct Peer {
    svc: Arc<ChatService>,
    _runtime: Arc<CallRuntime>,
    node: Arc<IrohNode>,
    contacts: Arc<ContactStore>,
    camera: Counters,
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
    // only the camera and screen factories are the test fakes.
    let provider = Arc::new(IrohLinkProvider::new(svc.node().clone()));
    let camera = Counters::new();
    let screen = Counters::new();
    let runtime = CallRuntime::start_with_factories(
        svc.clone(),
        provider,
        camera.factory(),
        screen.factory(),
    );
    register_runtime(dir.path(), runtime.clone());
    Peer {
        svc,
        _runtime: runtime,
        node,
        contacts,
        camera,
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

/// Whether peer `p` has decoded at least one remote video frame newer than
/// `last_seen`, read through the IPC `RemoteFrame` request. Returns the new
/// counter when a frame is present. The pixels are not inspected.
fn remote_frame_counter(p: &Peer, last_seen: u64) -> Option<u64> {
    match call(p, CallRequest::RemoteFrame { last_seen }) {
        CallResponse::RemoteFrame(Some(frame)) => Some(frame.counter),
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
    // Video is negotiated by default on both sides (the runtime leaves video on
    // unless a test turns it off), so the camera and screen requests below are
    // admitted rather than refused with `not_ready`.
    for p in [a, b] {
        assert!(
            status(p).negotiated_video,
            "both sides should negotiate video"
        );
    }
}

/// (1) StartCamera through the IPC path: A presses, B presses so it has a
/// receive driver, and within a bounded wait B decodes a video frame that came
/// from A over the real wire. A's status shows the camera in use. A fresh
/// camera source was opened on A's press.
#[tokio::test(flavor = "multi_thread")]
async fn start_camera_reaches_a_decoded_frame_on_the_peer() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;
        dial_and_accept(&a, &b).await;

        // A presses StartCamera; the fake factory opens exactly one source.
        assert!(matches!(
            call(&a, CallRequest::StartCamera),
            CallResponse::Ok
        ));
        assert_eq!(a.camera.created(), 1, "A opened one camera source");
        // B presses too, so B's media task has a video driver to decode into.
        assert!(matches!(
            call(&b, CallRequest::StartCamera),
            CallResponse::Ok
        ));

        // B decodes at least one remote video frame that crossed the wire, read
        // through the IPC RemoteFrame request, and the video-played counter
        // rises on B.
        until(60, "B to decode a remote video frame", || {
            remote_frame_counter(&b, 0).is_some() && status(&b).media_video_frames_played > 0
        })
        .await;

        // A's status reports the camera in use while connected.
        until(30, "A to report the camera in use", || {
            status(&a).camera_in_use
        })
        .await;

        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));
        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("start-camera scenario timed out");
}

/// (2) StopCamera through the IPC path: after frames flow, A stops the camera.
/// No further video frames arrive at B after a bounded wait, A's fake camera
/// source is released (its drop counter rises), and A's status reports the
/// camera no longer in use. Audio keeps flowing on B throughout.
#[tokio::test(flavor = "multi_thread")]
async fn stop_camera_halts_video_releases_source_and_keeps_audio() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;
        dial_and_accept(&a, &b).await;

        assert!(matches!(
            call(&a, CallRequest::StartCamera),
            CallResponse::Ok
        ));
        assert!(matches!(
            call(&b, CallRequest::StartCamera),
            CallResponse::Ok
        ));
        until(60, "B to decode a remote video frame", || {
            status(&b).media_video_frames_played > 0
        })
        .await;
        until(30, "A to report the camera in use", || {
            status(&a).camera_in_use
        })
        .await;
        // Audio is flowing on B before the stop.
        until(60, "audio on B before the stop", || {
            status(&b).media_frames_played > 0
        })
        .await;

        // A stops the camera. The source A opened must be released.
        assert!(matches!(
            call(&a, CallRequest::StopCamera),
            CallResponse::Ok
        ));
        until(30, "A's camera source to be released", || {
            a.camera.dropped() >= 1
        })
        .await;
        until(30, "A to report the camera not in use", || {
            !status(&a).camera_in_use
        })
        .await;

        // After a bounded settle, B's video-played counter stops advancing: no
        // further frames arrive once A has stopped sending. Audio keeps rising.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let audio_before = status(&b).media_frames_played;
        let video_after_stop = status(&b).media_video_frames_played;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let video_later = status(&b).media_video_frames_played;
        assert_eq!(
            video_later, video_after_stop,
            "no further video frames after StopCamera"
        );
        assert!(
            status(&b).media_frames_played > audio_before,
            "audio keeps arriving on B after StopCamera"
        );

        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));
        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("stop-camera scenario timed out");
}

/// (3) StartScreenShare / StopScreenShare through the IPC path: A starts
/// sharing, its status reports screen sharing, a fake screen source was opened;
/// then A stops, the source is released and the flag clears. Audio keeps
/// flowing on B throughout.
#[tokio::test(flavor = "multi_thread")]
async fn screen_share_start_and_stop_through_ipc() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;
        dial_and_accept(&a, &b).await;

        // Audio must be flowing before the screen requests, so the media task
        // is running and able to accept the attach control.
        until(60, "audio on both sides", || {
            status(&a).media_frames_played > 0 && status(&b).media_frames_played > 0
        })
        .await;

        assert!(matches!(
            call(&a, CallRequest::StartScreenShare),
            CallResponse::Ok
        ));
        assert_eq!(a.screen.created(), 1, "A opened one screen source");
        until(30, "A to report screen sharing", || {
            status(&a).screen_sharing
        })
        .await;

        let audio_before = status(&b).media_frames_played;

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

        // Audio keeps flowing on B across the screen start and stop.
        until(30, "audio to keep arriving on B", || {
            status(&b).media_frames_played > audio_before
        })
        .await;

        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));
        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("screen-share scenario timed out");
}

/// (5) StartCamera before the call is connected is refused with `not_ready`
/// and opens no source: the fake factory is never consulted.
#[tokio::test(flavor = "multi_thread")]
async fn start_camera_before_connect_is_not_ready_and_opens_no_source() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay).await;

        // No dial yet: the call is idle, video is not negotiated, so the camera
        // request is refused and no device is opened.
        assert_eq!(status(&a).state, "idle");
        match call(&a, CallRequest::StartCamera) {
            CallResponse::Error(reason) => assert_eq!(reason, "not_ready"),
            other => panic!("expected not_ready, got {other:?}"),
        }
        assert_eq!(
            a.camera.created(),
            0,
            "no camera source is opened before connect"
        );

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("not-ready scenario timed out");
}
