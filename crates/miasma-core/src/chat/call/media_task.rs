//! Transport and task for call media.
#[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
use super::audio_bridge::{build_real_audio, DeviceSelection};
use super::{
    controller::{CallController, CallPorts},
    device::{AudioSink, AudioSource, RecordingSink, ToneSource},
    media::Direction,
    session::{DatagramLink, MediaSession, TickStatus},
    state::State,
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
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
use tokio::{sync::Notify, task::JoinHandle};

#[derive(Clone, Default)]
pub struct MediaStats {
    pub frames_sent: Arc<AtomicU64>,
    pub frames_played: Arc<AtomicU64>,
    /// Set true to mute the local microphone mid-call. The media task reads it
    /// each tick and tells the capture source; with no input device it has no
    /// effect.
    pub muted: Arc<std::sync::atomic::AtomicBool>,
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
pub(super) fn maybe_start_media<P: CallPorts>(
    controller: &mut CallController<P>,
    provider: Arc<dyn MediaLinkProvider>,
    running: bool,
    stats: MediaStats,
) -> Option<JoinHandle<bool>> {
    if running || controller.status().state != State::Connected {
        return None;
    }
    let peer = controller.active_peer()?;
    let call_id = controller.active_call_id()?;
    let roots = controller.take_media_roots()?;
    Some(tokio::spawn(async move {
        let Some(link) = provider.open(peer, roots.direction).await else {
            return false;
        };
        run_media(roots, *call_id, link, stats).await
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
) -> bool {
    #[cfg(all(feature = "call-audio", any(windows, target_os = "macos"), not(test)))]
    {
        match build_real_audio(&DeviceSelection::default()) {
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
    // `frames_played` is driven from `session.stats().played` in the tick loop
    // below, so both the real sink and the pseudo sink report the same way;
    // the pseudo sink needs no counter of its own.
    // On other platforms calls carry the pseudo tone pattern rather than voice.
    let source = ToneSource::new();
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
