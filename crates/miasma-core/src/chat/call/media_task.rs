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
    video::{VideoDecoder, VideoDriver, VideoEncoder, VideoSink, VideoSource},
};
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
use tokio::{sync::Notify, task::JoinHandle};

#[derive(Clone, Default)]
pub struct MediaStats {
    pub frames_sent: Arc<AtomicU64>,
    pub frames_played: Arc<AtomicU64>,
    pub video_frames_sent: Arc<AtomicU64>,
    pub video_frames_played: Arc<AtomicU64>,
    pub camera_in_use: Arc<AtomicBool>,
    /// Set true to mute the local microphone mid-call. The media task reads it
    /// each tick and tells the capture source; with no input device it has no
    /// effect.
    pub muted: Arc<std::sync::atomic::AtomicBool>,
}

pub struct VideoParts {
    pub source: Box<dyn VideoSource + Send>,
    pub sink: Box<dyn VideoSink + Send>,
    pub encoder: Box<dyn VideoEncoder + Send>,
    pub decoder: Box<dyn VideoDecoder + Send>,
}
struct CameraGuard(Arc<AtomicBool>);
impl Drop for CameraGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
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

pub(super) fn maybe_start_media<P: CallPorts>(
    controller: &mut CallController<P>,
    provider: Arc<dyn MediaLinkProvider>,
    running: bool,
    stats: MediaStats,
    video: Option<VideoParts>,
    _muted: Arc<AtomicBool>,
    devices: AudioChoice,
) -> Option<JoinHandle<bool>> {
    if running || controller.status().state != State::Connected {
        return None;
    }
    let video = if controller.negotiated_video() {
        video
    } else {
        None
    };
    let peer = controller.active_peer()?;
    let call_id = controller.active_call_id()?;
    let roots = controller.take_media_roots()?;
    Some(tokio::spawn(async move {
        let _camera_guard = CameraGuard(stats.camera_in_use.clone());
        let Some(link) = provider.open(peer, roots.direction).await else {
            return false;
        };
        // When video was negotiated, drive audio and video together in one tick
        // loop over the pseudo audio devices. Audio-only calls (no video parts)
        // go through `run_media`, which opens the real capture/playback devices
        // on desktop and falls back to the pseudo devices elsewhere and in
        // tests. Mute applies on both paths through `stats.muted`.
        if let Some(parts) = video {
            let mut driver =
                VideoDriver::new(parts.source, parts.sink, parts.encoder, parts.decoder, 20);
            let Ok(mut session) = MediaSession::with_roots(
                &roots.send,
                &roots.recv,
                *call_id,
                roots.direction,
                crate::chat::engine::now_ms(),
                MutedSource {
                    source: ToneSource::new(),
                    muted: stats.muted.clone(),
                },
                RecordingSink::new(),
                link,
            ) else {
                return false;
            };
            drop(roots);
            let mut interval = tokio::time::interval(Duration::from_millis(20));
            loop {
                interval.tick().await;
                session
                    .source_mut()
                    .set_muted(stats.muted.load(Ordering::Relaxed));
                let now = crate::chat::engine::now_ms();
                stats
                    .camera_in_use
                    .store(driver.source_is_open(), Ordering::Relaxed);
                let packets = driver.tick(now);
                let status =
                    session.tick_with_video(now, &packets, |body, time| driver.receive(body, time));
                stats
                    .video_frames_sent
                    .store(driver.frames_sent, Ordering::Relaxed);
                stats
                    .video_frames_played
                    .store(driver.frames_played, Ordering::Relaxed);
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
        run_media(roots, *call_id, link, stats, devices).await
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
                return drive_session(roots, call_id, source, sink, link, stats).await;
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
    drive_session(roots, call_id, source, sink, link, stats).await
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
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    loop {
        interval.tick().await;
        session
            .source_mut()
            .set_muted(stats.muted.load(Ordering::Relaxed));
        let status = session.tick(crate::chat::engine::now_ms());
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
        assert_eq!(source.next_frame(), Some([0; FRAME_PLAINTEXT_LEN]));
        muted.store(true, Ordering::SeqCst);
        assert_eq!(source.next_frame(), Some([0; FRAME_PLAINTEXT_LEN]));
        muted.store(false, Ordering::SeqCst);
        assert_eq!(source.next_frame(), Some([1; FRAME_PLAINTEXT_LEN]));
    }
}
