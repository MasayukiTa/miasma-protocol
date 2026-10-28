//! Transport and task for call media.
#[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
use super::audio_bridge::{build_real_audio, DeviceSelection};
#[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
use super::audio_device::DeviceChoice;
use super::{
    controller::{CallController, CallPorts},
    device::{AudioSink, AudioSource, RecordingSink, ToneSource},
    media::Direction,
    media::FRAME_PLAINTEXT_LEN,
    session::{DatagramLink, MediaSession, TickStatus},
    state::State,
    video::{
        DiscardVideoSink, PassthroughCodec, RawPicture, VideoDecoder, VideoDriver, VideoEncoder,
        VideoSink, VideoSource,
    },
};
use crate::chat::ipc::{store_remote_frame, RemoteFrameStore};
use crate::transport::{
    call_link::IrohDatagramLink,
    iroh_direct::{CallConnectionHandler, IrohNode},
};
use iroh::endpoint::Connection;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};

#[derive(Clone, Default)]
pub struct MediaStats {
    pub frames_sent: Arc<AtomicU64>,
    pub frames_played: Arc<AtomicU64>,
    pub video_frames_sent: Arc<AtomicU64>,
    pub video_frames_played: Arc<AtomicU64>,
    pub camera_in_use: Arc<AtomicBool>,
    pub screen_sharing: Arc<AtomicBool>,
    pub(super) control: Arc<Mutex<Option<mpsc::Sender<MediaControl>>>>,
    /// Set true to mute the local microphone mid-call. The media task reads it
    /// each tick and tells the capture source; with no input device it has no
    /// effect.
    pub muted: Arc<std::sync::atomic::AtomicBool>,
}

pub(super) enum MediaControl {
    AttachCamera(Box<dyn VideoSource + Send>),
    DetachCamera,
    AttachScreen(Box<dyn VideoSource + Send>),
    DetachScreen,
}

pub struct VideoParts {
    pub source: Box<dyn VideoSource + Send>,
    pub sink: Box<dyn VideoSink + Send>,
    pub encoder: Box<dyn VideoEncoder + Send>,
    pub decoder: Box<dyn VideoDecoder + Send>,
}
struct CameraGuard(Arc<AtomicBool>, Arc<AtomicBool>);
impl Drop for CameraGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
        self.1.store(false, Ordering::Relaxed);
    }
}

struct MutedSource<S> {
    source: S,
    muted: Arc<AtomicBool>,
}
impl<S: AudioSource> AudioSource for MutedSource<S> {
    fn next_frame(&mut self) -> Option<[u8; FRAME_PLAINTEXT_LEN]> {
        if self.muted.load(Ordering::SeqCst) {
            Some([0; FRAME_PLAINTEXT_LEN])
        } else {
            self.source.next_frame()
        }
    }
}
impl<S: AudioSource> MuteControl for MutedSource<S> {
    fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::SeqCst);
    }
}
pub trait MediaLinkProvider: Send + Sync {
    fn open(
        &self,
        peer: [u8; 32],
        role: Direction,
    ) -> Pin<Box<dyn Future<Output = Option<Box<dyn DatagramLink>>> + Send>>;
}

struct Incoming {
    entries: Mutex<VecDeque<([u8; 32], Instant, Connection)>>,
    wake: Notify,
}
impl Incoming {
    fn prune(entries: &mut VecDeque<([u8; 32], Instant, Connection)>) {
        entries.retain(|(_, time, conn)| {
            if time.elapsed() >= Duration::from_secs(30) {
                conn.close(0u32.into(), b"");
                false
            } else {
                true
            }
        });
    }
}
#[async_trait::async_trait]
impl CallConnectionHandler for Incoming {
    async fn handle(&self, conn: Connection) {
        let peer = *conn.remote_id().as_bytes();
        let received = Instant::now();
        {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            Self::prune(&mut entries);
            if let Some(i) = entries.iter().position(|(id, _, _)| *id == peer) {
                if let Some((_, _, old)) = entries.remove(i) {
                    old.close(0u32.into(), b"");
                }
            }
            if entries.len() == 4 {
                if let Some((_, _, old)) = entries.pop_front() {
                    old.close(0u32.into(), b"");
                }
            }
            entries.push_back((peer, received, conn.clone()));
        }
        self.wake.notify_one();
        tokio::select! {
            _ = conn.closed() => {},
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let expired = {
                    let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                    let i = entries.iter().position(|(id, time, _)| *id == peer && *time == received && time.elapsed() >= Duration::from_secs(30));
                    i.and_then(|i| entries.remove(i))
                };
                if expired.is_some() { conn.close(0u32.into(), b""); }
                else { conn.closed().await; }
            }
        }
    }
}
pub struct IrohLinkProvider {
    node: Arc<IrohNode>,
    incoming: Arc<Incoming>,
}
impl IrohLinkProvider {
    pub fn new(node: Arc<IrohNode>) -> Self {
        static INSTALLED: OnceLock<Mutex<Vec<(Weak<IrohNode>, Weak<Incoming>)>>> = OnceLock::new();
        let mut installed = INSTALLED
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        installed.retain(|(node, incoming)| node.strong_count() > 0 && incoming.strong_count() > 0);
        if let Some(incoming) = installed.iter().find_map(|(old, incoming)| {
            old.upgrade()
                .filter(|old| Arc::ptr_eq(old, &node))
                .and_then(|_| incoming.upgrade())
        }) {
            return Self { node, incoming };
        }
        let incoming = Arc::new(Incoming {
            entries: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
        });
        node.set_call_handler(incoming.clone());
        installed.push((Arc::downgrade(&node), Arc::downgrade(&incoming)));
        Self { node, incoming }
    }
}
impl MediaLinkProvider for IrohLinkProvider {
    fn open(
        &self,
        peer: [u8; 32],
        role: Direction,
    ) -> Pin<Box<dyn Future<Output = Option<Box<dyn DatagramLink>>> + Send>> {
        let node = self.node.clone();
        let incoming = self.incoming.clone();
        Box::pin(async move {
            let conn = tokio::time::timeout(Duration::from_secs(10), async move {
                match role {
                    Direction::Caller => node.connect_call(&peer).await.ok(),
                    Direction::Callee => loop {
                        let notified = incoming.wake.notified();
                        let found = {
                            let mut entries =
                                incoming.entries.lock().unwrap_or_else(|e| e.into_inner());
                            Incoming::prune(&mut entries);
                            entries
                                .iter()
                                .position(|(id, _, _)| *id == peer)
                                .and_then(|i| entries.remove(i))
                                .map(|(_, _, conn)| conn)
                        };
                        if found.is_some() {
                            break found;
                        }
                        notified.await;
                    },
                }
            })
            .await
            .ok()
            .flatten()?;
            Some(Box::new(IrohDatagramLink::new(conn)) as Box<dyn DatagramLink>)
        })
    }
}
/// The audio devices chosen for a call: each name, or `None` for the host
/// default. Plain `String`s only, so this crosses into the media task freely
/// and needs none of the platform audio types; the desktop media path turns it
/// into the backend's own selection, and every other platform ignores it.
#[derive(Clone, Default)]
pub(super) struct AudioChoice {
    pub input: Option<String>,
    pub output: Option<String>,
}

/// Build the camera's video parts from an opened camera source: the source
/// drives capture, the sink discards any decoded loopback (the remote picture
/// is published through `take_decoded_picture`, not this sink), and the codec
/// pair carries the raw pictures through fragmentation. The passthrough codec
/// embeds each picture's geometry, so the camera's own capture size is
/// reproduced on the far side without a fixed-size codec. Holds no key, nonce,
/// call id or peer id.
fn camera_parts(source: Box<dyn VideoSource + Send>) -> VideoParts {
    VideoParts {
        source,
        sink: Box::new(DiscardVideoSink),
        encoder: Box::new(PassthroughCodec::new()),
        decoder: Box::new(PassthroughCodec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn maybe_start_media<P: CallPorts>(
    controller: &mut CallController<P>,
    provider: Arc<dyn MediaLinkProvider>,
    running: bool,
    stats: MediaStats,
    video: Option<VideoParts>,
    _muted: Arc<AtomicBool>,
    devices: AudioChoice,
    camera_source: Option<Box<dyn VideoSource + Send>>,
    screen_source: Option<Box<dyn VideoSource + Send>>,
    remote_frames: RemoteFrameStore,
) -> Option<JoinHandle<bool>> {
    if running || controller.status().state != State::Connected {
        return None;
    }
    let negotiated = controller.negotiated_video();
    // The camera rides the negotiated-video gate. A test may inject pseudo
    // `video` parts directly; otherwise an opened camera source builds the
    // production parts here. The injected parts win when both are present, so
    // the existing test hooks keep their exact behaviour.
    let video = if negotiated {
        video.or_else(|| camera_source.map(camera_parts))
    } else {
        None
    };
    // The screen stream is a second video-like stream (media_type 0x02); it
    // rides the same negotiated-video gate as the camera.
    let screen_source = if negotiated { screen_source } else { None };
    let peer = controller.active_peer()?;
    let call_id = controller.active_call_id()?;
    let roots = controller.take_media_roots()?;
    let (control_tx, control_rx) = mpsc::channel(32);
    *stats.control.lock().unwrap_or_else(|e| e.into_inner()) = Some(control_tx);
    Some(tokio::spawn(async move {
        let _camera_guard = CameraGuard(stats.camera_in_use.clone(), stats.screen_sharing.clone());
        let Some(link) = provider.open(peer, roots.direction).await else {
            return false;
        };
        run_media(
            roots,
            *call_id,
            link,
            stats,
            devices,
            video,
            screen_source,
            remote_frames,
            control_rx,
        )
        .await
    }))
}

/// Drive one call's media to completion. Uses the real audio devices when the
/// call-audio feature is on, the target is Windows or macOS, and a device
/// can be opened; otherwise, and in tests, it uses the pseudo devices. A missing or refused device is absorbed by the
/// real source/sink into receive-only operation, so this returns `false` only
/// on a fatal session error.
async fn run_media(
    roots: super::controller::MediaRoots,
    call_id: [u8; 16],
    link: Box<dyn DatagramLink>,
    stats: MediaStats,
    devices: AudioChoice,
    video: Option<VideoParts>,
    screen_source: Option<Box<dyn VideoSource + Send>>,
    remote_frames: RemoteFrameStore,
    control_rx: mpsc::Receiver<MediaControl>,
) -> bool {
    #[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
    {
        // Turn the chosen names into the backend's selection: a name picks that
        // device, and `None` leaves the host default in place.
        let selection = DeviceSelection {
            input: device_choice(devices.input),
            output: device_choice(devices.output),
        };
        match build_real_audio(&selection) {
            Ok((source, sink)) => {
                return drive_session(
                    roots,
                    call_id,
                    source,
                    sink,
                    link,
                    stats,
                    video,
                    screen_source,
                    remote_frames,
                    control_rx,
                )
                .await;
            }
            Err(_) => {
                // A fatal audio-stack error (for example the codec could not be
                // built): fall back to the pseudo devices so the secured link
                // still runs and the controller can post a notice.
            }
        }
    }
    // On a platform without the audio backend, and in tests, the chosen devices
    // are accepted but unused: the pseudo devices below carry the call.
    #[cfg(not(all(feature = "call-audio", any(windows, target_os = "macos"), not(test))))]
    let _ = devices;
    // `frames_played` is driven from `session.stats().played` in the tick loop
    // below, so both the real sink and the pseudo sink report the same way;
    // the pseudo sink needs no counter of its own.
    // On other platforms calls carry the pseudo tone pattern rather than voice.
    // The pseudo source is wrapped in `MutedSource` sharing the same
    // `stats.muted` flag, so mute applies on the fallback path too.
    let source = MutedSource {
        source: ToneSource::new(),
        muted: stats.muted.clone(),
    };
    let sink = RecordingSink::new();
    drive_session(
        roots,
        call_id,
        source,
        sink,
        link,
        stats,
        video,
        screen_source,
        remote_frames,
        control_rx,
    )
    .await
}

/// The shared 20 ms tick loop, generic over the source and sink so the real
/// and pseudo devices share one code path and the `MediaStats` counters work
/// the same way for both.
async fn drive_session<S, K>(
    roots: super::controller::MediaRoots,
    call_id: [u8; 16],
    source: S,
    sink: K,
    link: Box<dyn DatagramLink>,
    stats: MediaStats,
    video: Option<VideoParts>,
    screen_source: Option<Box<dyn VideoSource + Send>>,
    remote_frames: RemoteFrameStore,
    mut control_rx: mpsc::Receiver<MediaControl>,
) -> bool
where
    S: AudioSource + MuteControl,
    K: AudioSink,
{
    let Ok(mut session) = MediaSession::with_roots(
        &roots.send,
        &roots.recv,
        call_id,
        roots.direction,
        crate::chat::engine::now_ms(),
        source,
        sink,
        link,
    ) else {
        return false;
    };
    drop(roots);
    let mut video = video.map(|p| VideoDriver::new(p.source, p.sink, p.encoder, p.decoder, 20));
    // The screen stream is a second video-like stream (media_type 0x02).
    // It captures from its own source, discards any decoded frames (no
    // local screen playback is wired here) and shares the camera codec
    // size. It is paced far below the camera at the source: a new screen
    // frame begins only every SCREEN_FRAME_INTERVAL_MS, i.e. 1000 / 5 =
    // 200 ms for 5 frames per second (the session's packet budget still
    // caps how many fragments ride per tick). Kept wholly separate from
    // the camera driver above so the two never mix.
    const SCREEN_FRAMES_PER_SECOND: u64 = 5;
    const SCREEN_FRAME_INTERVAL_MS: u64 = 1000 / SCREEN_FRAMES_PER_SECOND;
    let mut screen = screen_source.map(|src| {
        VideoDriver::new(
            src,
            DiscardVideoSink,
            PassthroughCodec::new(),
            PassthroughCodec::new(),
            SCREEN_FRAME_INTERVAL_MS,
        )
    });
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    let empty: [[u8; super::media::FRAME_PLAINTEXT_LEN]; 0] = [];
    loop {
        interval.tick().await;
        while let Ok(control) = control_rx.try_recv() {
            match control {
                MediaControl::AttachCamera(source) => {
                    let p = camera_parts(source);
                    video = Some(VideoDriver::new(p.source, p.sink, p.encoder, p.decoder, 20));
                    stats.camera_in_use.store(true, Ordering::SeqCst);
                }
                MediaControl::DetachCamera => {
                    video = None;
                    stats.camera_in_use.store(false, Ordering::SeqCst);
                }
                MediaControl::AttachScreen(source) => {
                    screen = Some(VideoDriver::new(
                        source,
                        DiscardVideoSink,
                        PassthroughCodec::new(),
                        PassthroughCodec::new(),
                        SCREEN_FRAME_INTERVAL_MS,
                    ));
                    stats.screen_sharing.store(true, Ordering::SeqCst);
                }
                MediaControl::DetachScreen => {
                    screen = None;
                    stats.screen_sharing.store(false, Ordering::SeqCst);
                }
            }
        }
        session
            .source_mut()
            .set_muted(stats.muted.load(Ordering::Relaxed));
        let now = crate::chat::engine::now_ms();
        // Camera fragments for this tick (empty when the camera is off).
        let camera_packets = match video.as_mut() {
            Some(driver) => {
                stats
                    .camera_in_use
                    .store(driver.source_is_open(), Ordering::Relaxed);
                driver.tick(now)
            }
            None => {
                stats.camera_in_use.store(false, Ordering::Relaxed);
                Vec::new()
            }
        };
        // Screen fragments for this tick (empty when not sharing).
        let screen_packets = match screen.as_mut() {
            Some(driver) => driver.tick_with_budget(
                now,
                super::video::MAX_VIDEO_FRAGMENTS_PER_TICK.saturating_sub(camera_packets.len()),
            ),
            None => Vec::new(),
        };
        let camera_slice: &[[u8; super::media::FRAME_PLAINTEXT_LEN]] = if video.is_some() {
            &camera_packets
        } else {
            &empty
        };
        let screen_slice: &[[u8; super::media::FRAME_PLAINTEXT_LEN]] = if screen.is_some() {
            &screen_packets
        } else {
            &empty
        };
        let status = {
            let video_ref = &mut video;
            let screen_ref = &mut screen;
            session.tick_with_media(
                now,
                camera_slice,
                screen_slice,
                |body, time| {
                    if let Some(driver) = video_ref.as_mut() {
                        driver.receive(body, time);
                    }
                },
                |body, time| {
                    if let Some(driver) = screen_ref.as_mut() {
                        driver.receive(body, time);
                    }
                },
            )
        };
        if let Some(driver) = video.as_mut() {
            // Publish the newest decoded remote picture for the UI. The
            // camera driver hands back at most one picture per tick; the
            // store gives it the next counter so a reader sees only new
            // frames. Only the camera stream feeds the remote view; the
            // screen stream's decoded frames are discarded.
            if let Some(picture) = driver.take_decoded_picture() {
                let RawPicture {
                    width,
                    height,
                    pixels,
                } = picture;
                store_remote_frame(&remote_frames, width, height, pixels);
            }
            stats
                .video_frames_sent
                .store(driver.frames_sent, Ordering::Relaxed);
            stats
                .video_frames_played
                .store(driver.frames_played, Ordering::Relaxed);
        }
        stats
            .frames_sent
            .store(session.stats().sent, Ordering::Relaxed);
        stats
            .frames_played
            .store(session.stats().played, Ordering::Relaxed);
        if status == TickStatus::Fatal {
            return false;
        }
    }
}

/// Turn a chosen device name into the backend's [`DeviceChoice`]: a name picks
/// that device and `None` leaves the host default. Only built on the desktop
/// audio path.
#[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
fn device_choice(name: Option<String>) -> DeviceChoice {
    match name {
        Some(name) => DeviceChoice::ByName(name),
        None => DeviceChoice::Default,
    }
}

/// A source that may be muted mid-call. The pseudo source ignores it; the real
/// capture source forwards it to the device.
pub trait MuteControl {
    fn set_muted(&self, muted: bool);
}
impl MuteControl for ToneSource {
    fn set_muted(&self, _muted: bool) {}
}
#[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
impl MuteControl for super::audio_bridge::EncodingSource {
    fn set_muted(&self, muted: bool) {
        super::audio_bridge::EncodingSource::set_muted(self, muted);
    }
}

#[cfg(test)]
mod mute_tests {
    use super::*;
    #[test]
    fn muted_source_sends_silence_and_resumes_source() {
        let muted = Arc::new(AtomicBool::new(false));
        let mut source = MutedSource {
            source: ToneSource::new(),
            muted: muted.clone(),
        };
        assert!(source.next_frame() == Some([0; FRAME_PLAINTEXT_LEN]));
        muted.store(true, Ordering::SeqCst);
        assert!(source.next_frame() == Some([0; FRAME_PLAINTEXT_LEN]));
        muted.store(false, Ordering::SeqCst);
        assert!(source.next_frame() == Some([1; FRAME_PLAINTEXT_LEN]));
    }
}
