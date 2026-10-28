//! End-to-end video over two real peers on a local relay. Each peer runs its
//! own real `ChatService` over its own real node and a real `CallRuntime`, as
//! in `call_e2e_pr6_test.rs`. The only addition is a documented test hook,
//! `CallRuntime::start_with_video`, which injects pseudo video parts (a moving
//! pattern source, a recording sink and a pass-through codec) into each media
//! task so the real fragmentation, pacing, network and reassembly path carries
//! video end to end. No camera or audio device is used; nothing here depends on
//! any capture backend.
//!
//! The harness mirrors the one in `call_e2e_pr6_test.rs`: in-process nodes on a
//! local relay, no traffic to any public service, and a bounded real hybrid
//! exchange before dialing so the media gate reports ready.

#![cfg(all(feature = "iroh", feature = "pqc"))]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        call::{
            media_task::{IrohLinkProvider, VideoParts},
            runtime::{register_runtime, CallRuntime},
            video::{PassthroughCodec, RawPicture, TestPatternSource, VideoSink},
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

// Pseudo picture geometry. Small and fixed; the exact bytes are deterministic
// (see `TestPatternSource`), so a sink can checksum what it received and match
// it against the known pattern.
const PIC_WIDTH: u16 = 8;
const PIC_HEIGHT: u16 = 8;
const PIC_SIZE: usize = (PIC_WIDTH as usize) * (PIC_HEIGHT as usize);

/// A sink that records every decoded picture into a shared buffer so the test
/// can read what crossed the network after the driver has taken ownership of
/// the sink. Holds only opaque pixels; no key, nonce, call id or peer id, so it
/// is safe without a Debug impl (and it derives none).
struct SharedRecordingSink {
    pictures: Arc<Mutex<Vec<RawPicture>>>,
}

impl VideoSink for SharedRecordingSink {
    fn put_picture(&mut self, picture: &RawPicture) {
        self.pictures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(picture.clone());
    }
}

/// A simple order-independent checksum over a picture's geometry and pixels.
/// Enough to tell one pseudo frame from another and to detect any corruption
/// on the wire.
fn checksum(picture: &RawPicture) -> u64 {
    let mut acc: u64 = 1469598103934665603; // FNV-1a offset basis.
    let mut mix = |byte: u8| {
        acc ^= byte as u64;
        acc = acc.wrapping_mul(1099511628211);
    };
    mix((picture.width >> 8) as u8);
    mix(picture.width as u8);
    mix((picture.height >> 8) as u8);
    mix(picture.height as u8);
    for &b in &picture.pixels {
        mix(b);
    }
    acc
}

/// The set of checksums the moving-pattern source produces for its first
/// `count` pictures, in order. The source is deterministic, so the receiver's
/// recorded pictures must each match one of these.
fn expected_checksums(count: u8) -> Vec<u64> {
    use miasma_core::chat::call::video::VideoSource;
    let mut source = TestPatternSource::new(PIC_WIDTH, PIC_HEIGHT, PIC_SIZE);
    let mut out = Vec::new();
    for _ in 0..count {
        if let Some(picture) = source.next_picture() {
            out.push(checksum(&picture));
        }
    }
    out
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

/// One real peer with a real runtime. `video` controls whether this endpoint
/// offers video and injects pseudo parts: `Some(sink)` records the pictures it
/// receives into the shared buffer; `None` runs audio only (no video parts and
/// no video in its advertised capabilities).
struct Peer {
    svc: Arc<ChatService>,
    _runtime: Arc<CallRuntime>,
    node: Arc<IrohNode>,
    contacts: Arc<ContactStore>,
    received_pictures: Option<Arc<Mutex<Vec<RawPicture>>>>,
    _dir: TempDir,
}

impl Peer {
    fn id(&self) -> [u8; 32] {
        self.node.endpoint_id()
    }
}

/// Build a video parts factory whose sink records into `pictures`. The factory
/// is called once per media task, handing each task a fresh source, recording
/// sink (sharing the same buffer), and pass-through codec.
fn video_factory(
    pictures: Arc<Mutex<Vec<RawPicture>>>,
) -> Arc<dyn Fn() -> Option<VideoParts> + Send + Sync> {
    Arc::new(move || {
        Some(VideoParts {
            source: Box::new(TestPatternSource::new(PIC_WIDTH, PIC_HEIGHT, PIC_SIZE)),
            sink: Box::new(SharedRecordingSink {
                pictures: pictures.clone(),
            }),
            encoder: Box::new(PassthroughCodec::new()),
            decoder: Box::new(PassthroughCodec::new()),
        })
    })
}

async fn peer(relay: &Relay, offers_video: bool) -> Peer {
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
    // The real production media link provider, same as `CallRuntime::start`.
    let provider = Arc::new(IrohLinkProvider::new(svc.node().clone()));
    let received_pictures = if offers_video {
        Some(Arc::new(Mutex::new(Vec::new())))
    } else {
        None
    };
    let factory = video_factory(
        received_pictures
            .clone()
            .unwrap_or_else(|| Arc::new(Mutex::new(Vec::new()))),
    );
    let runtime = CallRuntime::start_with_video(svc.clone(), provider, offers_video, factory);
    register_runtime(dir.path(), runtime.clone());
    Peer {
        svc,
        _runtime: runtime,
        node,
        contacts,
        received_pictures,
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

async fn ready_pair(relay: &Relay, a_video: bool, b_video: bool) -> (Peer, Peer) {
    let (a, b) = (peer(relay, a_video).await, peer(relay, b_video).await);
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
}

/// (a) Both sides offer video: the call connects, both sides play video frames
/// within a bounded wait and report negotiated video, then a hang-up returns
/// both to idle with the video counters back to zero.
#[tokio::test(flavor = "multi_thread")]
async fn both_sides_video_frames_flow_then_zero_after_hang_up() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay, true, true).await;
        dial_and_accept(&a, &b).await;

        until(60, "video played on both sides", || {
            let (sa, sb) = (status(&a), status(&b));
            sa.media_video_frames_played > 0 && sb.media_video_frames_played > 0
        })
        .await;
        for s in [status(&a), status(&b)] {
            assert!(s.negotiated_video, "both sides should negotiate video");
        }

        assert!(matches!(call(&a, CallRequest::HangUp), CallResponse::Ok));
        until(30, "both back to idle", || {
            status(&a).state == "idle" && status(&b).state == "idle"
        })
        .await;
        for s in [status(&a), status(&b)] {
            assert_eq!(s.state, "idle");
            assert_eq!(s.media_video_frames_sent, 0);
            assert_eq!(s.media_video_frames_played, 0);
        }

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("both-sides video scenario timed out");
}

/// (b) One side has no video parts: the call connects as audio only, the video
/// counters stay zero and neither side reports negotiated video.
#[tokio::test(flavor = "multi_thread")]
async fn one_side_without_video_is_audio_only() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay, true, false).await;
        dial_and_accept(&a, &b).await;

        // Audio still flows, so wait on the audio path to confirm the media task
        // is running before asserting the video counters stayed at zero.
        until(60, "audio on both sides", || {
            let (sa, sb) = (status(&a), status(&b));
            sa.media_frames_sent > 0
                && sa.media_frames_played > 0
                && sb.media_frames_sent > 0
                && sb.media_frames_played > 0
        })
        .await;
        // Give any (incorrect) video path a chance to run before asserting zero.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for s in [status(&a), status(&b)] {
            assert!(
                !s.negotiated_video,
                "audio-only call must not negotiate video"
            );
            assert_eq!(s.media_video_frames_sent, 0);
            assert_eq!(s.media_video_frames_played, 0);
        }

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("audio-only scenario timed out");
}

/// (c) Video frames survive the real network path in both directions: each
/// peer's recording sink holds at least one picture whose checksum matches a
/// picture the deterministic pattern source produced, proving the pixels were
/// carried intact across fragmentation, the wire and reassembly.
#[tokio::test(flavor = "multi_thread")]
async fn video_frames_survive_the_wire_in_both_directions() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let (a, b) = ready_pair(&relay, true, true).await;
        dial_and_accept(&a, &b).await;

        until(60, "a recorded video on both sinks", || {
            let a_got = a
                .received_pictures
                .as_ref()
                .map(|p| !p.lock().unwrap_or_else(|e| e.into_inner()).is_empty())
                .unwrap_or(false);
            let b_got = b
                .received_pictures
                .as_ref()
                .map(|p| !p.lock().unwrap_or_else(|e| e.into_inner()).is_empty())
                .unwrap_or(false);
            a_got && b_got
        })
        .await;

        // Both pseudo sources follow the same deterministic pattern, so every
        // received picture must match one of the first N source checksums.
        let expected = expected_checksums(200);
        for peer in [&a, &b] {
            let pictures = peer
                .received_pictures
                .as_ref()
                .expect("a video peer records pictures")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            assert!(!pictures.is_empty(), "a recorded at least one picture");
            let first = &pictures[0];
            assert_eq!(first.width, PIC_WIDTH);
            assert_eq!(first.height, PIC_HEIGHT);
            assert_eq!(first.pixels.len(), PIC_SIZE);
            assert!(
                expected.contains(&checksum(first)),
                "received picture checksum must match a source picture"
            );
        }

        a.svc.shutdown();
        b.svc.shutdown();
    })
    .await
    .expect("wire-survival scenario timed out");
}
