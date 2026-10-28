use super::{
    controller::{CallController, CallError, CallNotice, CallPorts, MediaGate, SasInputs},
    media_task::{
        maybe_start_media, AudioChoice, IrohLinkProvider, MediaLinkProvider, MediaStats, VideoParts,
    },
    state::State,
};
use crate::chat::{
    ipc::{AudioDeviceListDto, CallNoticeDto, CallRequest, CallResponse, CallStatusDto},
    service::ChatService,
};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};

struct RuntimePorts(Arc<ChatService>);
impl CallPorts for RuntimePorts {
    fn now_ms(&self) -> u64 {
        crate::chat::engine::now_ms()
    }
    fn is_contact_allowed(&self, peer: &[u8; 32]) -> bool {
        matches!(self.0.contacts().by_endpoint(peer), Some(c) if c.allow_send && c.allow_receive)
    }
    fn media_gate(&self, peer: &[u8; 32]) -> MediaGate {
        self.0.media_gate(peer)
    }
    fn sas_inputs(&self, peer: super::state::PeerId) -> Option<SasInputs> {
        self.0.sas_inputs(&peer.0)
    }
}

#[derive(Default)]
struct NoticeRing {
    items: VecDeque<(u64, CallNotice)>,
    next: u64,
}
impl NoticeRing {
    fn push(&mut self, notice: CallNotice) {
        if let Some(next) = self.next.checked_add(1) {
            self.next = next;
            if self.items.len() == 64 {
                self.items.pop_front();
            }
            self.items.push_back((next, notice));
        }
    }
    fn events(&self, since: u64) -> CallResponse {
        let gap = self
            .items
            .front()
            .map_or(false, |(seq, _)| *seq > since.saturating_add(1));
        let notices = self
            .items
            .iter()
            .filter(|(seq, _)| *seq > since)
            .map(|(_, notice)| CallNoticeDto {
                code: notice_word(*notice).into(),
            })
            .collect();
        CallResponse::Events {
            next: self.next,
            gap,
            notices,
        }
    }
}
struct Inner {
    controller: CallController<RuntimePorts>,
    notices: NoticeRing,
    media_stats: Option<MediaStats>,
    muted: Arc<AtomicBool>,
    /// The audio devices chosen for the next call. A running call keeps the
    /// devices it already opened; this is read when the next call starts its
    /// media task.
    devices: AudioChoice,
}
impl Inner {
    fn collect(&mut self) {
        for notice in self.controller.take_notices().0 {
            self.notices.push(notice);
        }
    }
}
fn media_failed<P: CallPorts>(controller: &mut CallController<P>, notices: &mut NoticeRing) {
    if controller.status().state == State::Connected {
        notices.push(CallNotice::EstablishmentFailed);
        controller.hang_up();
    }
}
/// Builds the pseudo video parts (source, sink, encoder, decoder) for one
/// media task. Returns `None` when this endpoint runs audio only. Each media
/// task gets a fresh set, so the factory is called once per task start.
type VideoPartsFactory = dyn Fn() -> Option<VideoParts> + Send + Sync;

fn sync_media<P: CallPorts>(
    controller: &mut CallController<P>,
    provider: Arc<dyn MediaLinkProvider>,
    media: &mut Option<JoinHandle<bool>>,
    stats: &mut Option<MediaStats>,
    muted: Arc<AtomicBool>,
    video_factory: Option<&Arc<VideoPartsFactory>>,
    devices: AudioChoice,
) {
    if controller.status().state != State::Connected {
        *stats = None;
        if controller.status().state == State::Idle {
            muted.store(false, Ordering::SeqCst);
        }
        if let Some(task) = media.take() {
            task.abort();
        }
    } else if media.is_none() {
        let mut new_stats = MediaStats::default();
        // Share the runtime's mute flag with the media task via `stats.muted`
        // so a mid-call SetMuted reaches the tick loop; the media task reads
        // the flag through the stats it was handed.
        new_stats.muted = muted.clone();
        // When this endpoint injects pseudo video parts, build a fresh set for
        // this media task; audio-only endpoints pass no factory and get `None`.
        let video = video_factory.and_then(|factory| factory());
        *media = maybe_start_media(
            controller,
            provider,
            false,
            new_stats.clone(),
            video,
            muted,
            devices,
        );
        *stats = media.as_ref().map(|_| new_stats);
    }
}
pub struct CallRuntime {
    svc: Arc<ChatService>,
    inner: Arc<Mutex<Inner>>,
    wake: Arc<Notify>,
    stop: Arc<Notify>,
    task: Mutex<Option<JoinHandle<()>>>,
}
impl CallRuntime {
    pub fn start(svc: Arc<ChatService>) -> Arc<Self> {
        let provider = Arc::new(IrohLinkProvider::new(svc.node().clone()));
        Self::start_with_provider(svc, provider)
    }
    pub fn start_with_provider(
        svc: Arc<ChatService>,
        provider: Arc<dyn MediaLinkProvider>,
    ) -> Arc<Self> {
        Self::start_full(svc, provider, true, None)
    }
    /// Test hook: start a runtime that injects pseudo video parts into each
    /// media task. `offers_video` controls whether this endpoint advertises
    /// video in its own capabilities; when false the call negotiates audio
    /// only and `parts_factory` is never consulted. When true, `parts_factory`
    /// builds a fresh set of pseudo parts (source, sink, encoder, decoder) for
    /// each media task. Production uses [`start`] / [`start_with_provider`],
    /// which leave video on and inject no parts, so this hook does not change
    /// the shipped behaviour.
    #[doc(hidden)]
    pub fn start_with_video(
        svc: Arc<ChatService>,
        provider: Arc<dyn MediaLinkProvider>,
        offers_video: bool,
        parts_factory: Arc<VideoPartsFactory>,
    ) -> Arc<Self> {
        Self::start_full(svc, provider, offers_video, Some(parts_factory))
    }
    fn start_full(
        svc: Arc<ChatService>,
        provider: Arc<dyn MediaLinkProvider>,
        offers_video: bool,
        video_factory: Option<Arc<VideoPartsFactory>>,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel(32);
        svc.set_call_sink(tx);
        let mut controller = CallController::new(RuntimePorts(svc.clone()));
        if !offers_video {
            controller.set_local_offers_video(false);
        }
        let inner = Arc::new(Mutex::new(Inner {
            controller,
            notices: NoticeRing::default(),
            media_stats: None,
            muted: Arc::new(AtomicBool::new(false)),
            devices: AudioChoice::default(),
        }));
        let wake = Arc::new(Notify::new());
        let stop_task = Arc::new(Notify::new());
        let task_inner = inner.clone();
        let task_svc = svc.clone();
        let task_wake = wake.clone();
        let task_stop = stop_task.clone();
        let task_video = video_factory;
        let mut stop = svc.call_shutdown();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            let mut sending = tokio::task::JoinSet::new();
            let mut media: Option<JoinHandle<bool>> = None;
            loop {
                tokio::select! {
                    incoming = rx.recv() => match incoming {
                        Some(inbound) => { let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner()); state.controller.on_inbound(inbound); state.collect(); }
                        None => break,
                    },
                    _ = interval.tick() => { let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner()); state.controller.on_tick(); state.collect(); },
                    _ = task_wake.notified() => {},
                    result = sending.join_next(), if !sending.is_empty() => {
                        if let Some(Ok((ticket, ok))) = result {
                            let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner());
                            state.controller.report_send_result(ticket, ok);
                            state.collect();
                        }
                    },
                    result = async { match media.as_mut() { Some(task) => Some(task.await), None => None } }, if media.is_some() => {
                        media = None;
                        task_inner.lock().unwrap_or_else(|e| e.into_inner()).media_stats = None;
                        if matches!(result, Some(Ok(false))) {
                            let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner());
                            let Inner { controller, notices, .. } = &mut *state;
                            media_failed(controller, notices);
                            state.collect();
                        }
                    },
                    _ = stop.changed() => break,
                    _ = task_stop.notified() => break,
                }
                let sends = {
                    let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner());
                    let Inner {
                        controller,
                        media_stats,
                        muted,
                        devices,
                        ..
                    } = &mut *state;
                    let muted = muted.clone();
                    let devices = devices.clone();
                    sync_media(
                        controller,
                        provider.clone(),
                        &mut media,
                        media_stats,
                        muted,
                        task_video.as_ref(),
                        devices,
                    );
                    let sends = state.controller.drain_encoded();
                    state.collect();
                    sends
                };
                for (peer, bytes, ticket) in sends {
                    if sending.len() >= 32 {
                        let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner());
                        state.controller.report_send_result(ticket, false);
                        state.collect();
                        continue;
                    }
                    let svc = task_svc.clone();
                    sending.spawn(async move {
                        let ok = svc.send_call_control(&peer, &bytes).await.is_ok();
                        (ticket, ok)
                    });
                }
            }
            task_inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .media_stats = None;
            if let Some(task) = media {
                task.abort();
                let _ = task.await;
            }
            sending.shutdown().await;
        });
        Arc::new(Self {
            svc,
            inner,
            wake,
            stop: stop_task,
            task: Mutex::new(Some(task)),
        })
    }
    pub async fn stop(&self) {
        let task = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            self.stop.notify_one();
            let _ = task.await;
        }
    }
    pub(crate) fn handle(&self, request: CallRequest, peer: Option<[u8; 32]>) -> CallResponse {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let response = match request {
            CallRequest::Dial { .. } => match peer {
                Some(peer) => dial_result(state.controller.dial(peer)),
                None => CallResponse::Error("unavailable".into()),
            },
            CallRequest::Accept { token } => {
                if state.controller.accept(token) {
                    CallResponse::Ok
                } else {
                    CallResponse::Error("stale".into())
                }
            }
            CallRequest::Reject { token } => {
                if state.controller.reject(token) {
                    CallResponse::Ok
                } else {
                    CallResponse::Error("stale".into())
                }
            }
            CallRequest::HangUp => {
                if state.controller.status().state == State::Idle {
                    CallResponse::Error("stale".into())
                } else {
                    state.controller.hang_up();
                    CallResponse::Ok
                }
            }
            CallRequest::SetMuted { muted } => {
                if state.controller.status().state == State::Idle {
                    CallResponse::Error("stale".into())
                } else {
                    state.muted.store(muted, Ordering::SeqCst);
                    CallResponse::Ok
                }
            }
            CallRequest::Status => {
                let mut dto = status_dto(&state.controller, state.media_stats.as_ref());
                dto.muted = state.muted.load(Ordering::SeqCst);
                CallResponse::Status(dto)
            }
            CallRequest::Events { since } => state.notices.events(since),
            CallRequest::ListAudioDevices => CallResponse::AudioDevices(host_device_list()),
            CallRequest::SelectAudioDevices { input, output } => {
                apply_selection(&mut state.devices, input, output)
            }
        };
        state.collect();
        drop(state);
        self.wake.notify_one();
        response
    }
}
/// Record a device choice for the next call and echo it back. A running call
/// keeps the devices it already opened; only the next call reads this. Split
/// out so the pure storage behaviour can be tested without a running service.
fn apply_selection(
    devices: &mut AudioChoice,
    input: Option<String>,
    output: Option<String>,
) -> CallResponse {
    devices.input = input.clone();
    devices.output = output.clone();
    CallResponse::AudioDevicesSelected { input, output }
}

fn status_dto<P: CallPorts>(
    controller: &CallController<P>,
    stats: Option<&MediaStats>,
) -> CallStatusDto {
    let status = controller.status();
    let stats = if status.state == State::Connected {
        stats
    } else {
        None
    };
    CallStatusDto {
        state: state_word(status.state).into(),
        pending_token: status.pending_token,
        signalling_connected: status.signalling_connected,
        negotiated_video: status.negotiated_video,
        safety_code: controller.safety_code(),
        muted: false,
        screen_sharing: false,
        media_frames_sent: stats.map_or(0, |s| s.frames_sent.load(Ordering::Relaxed)),
        media_frames_played: stats.map_or(0, |s| s.frames_played.load(Ordering::Relaxed)),
        camera_in_use: stats.map_or(false, |s| s.camera_in_use.load(Ordering::Relaxed)),
        media_video_frames_sent: stats.map_or(0, |s| s.video_frames_sent.load(Ordering::Relaxed)),
        media_video_frames_played: stats
            .map_or(0, |s| s.video_frames_played.load(Ordering::Relaxed)),
    }
}
fn dial_result(result: Result<(), CallError>) -> CallResponse {
    match result {
        Ok(()) => CallResponse::Ok,
        Err(CallError::NotAllowed) => CallResponse::Error("not_allowed".into()),
        Err(CallError::Busy) => CallResponse::Error("busy".into()),
        Err(CallError::NotReady) => CallResponse::Error("not_ready".into()),
        Err(CallError::Refused) => CallResponse::Error("refused".into()),
    }
}
fn state_word(state: State) -> &'static str {
    match state {
        State::Idle => "idle",
        State::Calling => "calling",
        State::Ringing => "ringing",
        State::Connected => "connected",
    }
}
fn notice_word(notice: CallNotice) -> &'static str {
    match notice {
        CallNotice::IncomingRinging => "incoming_ringing",
        CallNotice::Rejected => "rejected",
        CallNotice::PeerBusy => "peer_busy",
        CallNotice::NoAnswer => "no_answer",
        CallNotice::Connected => "connected",
        CallNotice::CallEnded => "call_ended",
        CallNotice::EstablishmentFailed => "establishment_failed",
        CallNotice::ClearIncoming => "clear_incoming",
        CallNotice::SendFailed => "send_failed",
    }
}
/// The host's audio devices as an IPC DTO. On a desktop build with the audio
/// backend this enumerates the host (off the caller's thread, inside
/// [`super::audio_device::list_devices`]); on every other platform the backend
/// is absent, so the lists are empty and the selection is accepted but unused.
#[cfg(all(feature = "call-audio", any(windows, target_os = "macos")))]
fn host_device_list() -> AudioDeviceListDto {
    let list = super::audio_device::list_devices();
    AudioDeviceListDto {
        inputs: list.inputs,
        outputs: list.outputs,
        default_input: list.default_input,
        default_output: list.default_output,
    }
}

#[cfg(not(all(feature = "call-audio", any(windows, target_os = "macos"))))]
fn host_device_list() -> AudioDeviceListDto {
    AudioDeviceListDto::default()
}

static RUNTIMES: OnceLock<Mutex<HashMap<PathBuf, Arc<CallRuntime>>>> = OnceLock::new();
fn runtimes() -> &'static Mutex<HashMap<PathBuf, Arc<CallRuntime>>> {
    RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()))
}
pub fn register_runtime(data_dir: &Path, runtime: Arc<CallRuntime>) {
    runtimes()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(data_dir.to_owned(), runtime);
}
pub fn runtime_for(data_dir: &Path) -> Option<Arc<CallRuntime>> {
    runtimes()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(data_dir)
        .cloned()
}
pub fn unregister(data_dir: &Path) -> Option<Arc<CallRuntime>> {
    runtimes()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(data_dir)
}
pub(crate) fn runtime_for_service(svc: &Arc<ChatService>) -> Option<Arc<CallRuntime>> {
    runtimes()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .find(|runtime| Arc::ptr_eq(&runtime.svc, svc))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::super::{
        inbound::CallInbound, media::Direction, session::DatagramLink, signal::Record,
    };
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Ports;
    impl CallPorts for Ports {
        fn now_ms(&self) -> u64 {
            1000
        }
        fn is_contact_allowed(&self, _: &[u8; 32]) -> bool {
            true
        }
        fn media_gate(&self, _: &[u8; 32]) -> MediaGate {
            MediaGate::Ready
        }
        fn sas_inputs(&self, _: super::super::state::PeerId) -> Option<SasInputs> {
            None
        }
    }
    struct Link {
        incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
        outgoing: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }
    impl DatagramLink for Link {
        fn max_len(&self) -> usize {
            90
        }
        fn send(&mut self, packet: &[u8]) -> bool {
            self.outgoing.lock().unwrap().push_back(packet.to_vec());
            true
        }
        fn try_recv(&mut self) -> Option<Vec<u8>> {
            self.incoming.lock().unwrap().pop_front()
        }
    }
    struct Provider {
        links: Mutex<VecDeque<Box<dyn DatagramLink>>>,
        opens: AtomicUsize,
    }
    impl MediaLinkProvider for Provider {
        fn open(
            &self,
            _: [u8; 32],
            _: Direction,
        ) -> Pin<Box<dyn Future<Output = Option<Box<dyn DatagramLink>>> + Send>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let link = self.links.lock().unwrap().pop_front();
            Box::pin(async move { link })
        }
    }
    fn connected() -> (CallController<Ports>, CallController<Ports>) {
        let mut a = CallController::new(Ports);
        let mut b = CallController::new(Ports);
        assert!(a.dial([2; 32]).is_ok());
        let offer = a.drain_encoded().remove(0).1;
        b.on_inbound(CallInbound {
            peer: [1; 32],
            signal: Record::decode(&offer).unwrap(),
            received_at_ms: 1000,
        });
        assert!(b.accept(b.status().pending_token.unwrap()));
        let answer = b.drain_encoded().remove(0).1;
        a.on_inbound(CallInbound {
            peer: [2; 32],
            signal: Record::decode(&answer).unwrap(),
            received_at_ms: 1000,
        });
        (a, b)
    }
    #[tokio::test]
    async fn media_starts_once_and_stops_on_hangup() {
        let (mut a, mut b) = connected();
        let x = Arc::new(Mutex::new(VecDeque::new()));
        let y = Arc::new(Mutex::new(VecDeque::new()));
        let provider = Arc::new(Provider {
            links: Mutex::new(VecDeque::from([
                Box::new(Link {
                    incoming: x.clone(),
                    outgoing: y.clone(),
                }) as Box<dyn DatagramLink>,
                Box::new(Link {
                    incoming: y,
                    outgoing: x,
                }) as Box<dyn DatagramLink>,
            ])),
            opens: AtomicUsize::new(0),
        });
        let mut am = None;
        let mut bm = None;
        let mut a_stats = None;
        let mut b_stats = None;
        sync_media(
            &mut a,
            provider.clone(),
            &mut am,
            &mut a_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
        );
        sync_media(
            &mut b,
            provider.clone(),
            &mut bm,
            &mut b_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
        );
        sync_media(
            &mut a,
            provider.clone(),
            &mut am,
            &mut a_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
        );
        tokio::task::yield_now().await;
        assert_eq!(provider.opens.load(Ordering::SeqCst), 2);
        assert_eq!(a.status().state, State::Connected);
        assert_eq!(b.status().state, State::Connected);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let a_status = status_dto(&a, a_stats.as_ref());
                let b_status = status_dto(&b, b_stats.as_ref());
                if a_status.media_frames_sent > 0
                    && a_status.media_frames_played > 0
                    && b_status.media_frames_sent > 0
                    && b_status.media_frames_played > 0
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("media did not flow in time");
        a.hang_up();
        b.hang_up();
        sync_media(
            &mut a,
            provider.clone(),
            &mut am,
            &mut a_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
        );
        sync_media(
            &mut b,
            provider,
            &mut bm,
            &mut b_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
        );
        assert!(am.is_none() && bm.is_none());
        for status in [
            status_dto(&a, a_stats.as_ref()),
            status_dto(&b, b_stats.as_ref()),
        ] {
            assert_eq!(status.media_frames_sent, 0);
            assert_eq!(status.media_frames_played, 0);
        }
    }
    #[tokio::test]
    async fn unreachable_link_reports_failure_and_hangs_up() {
        let (mut a, _) = connected();
        let provider = Arc::new(Provider {
            links: Mutex::new(VecDeque::new()),
            opens: AtomicUsize::new(0),
        });
        let mut media = None;
        let mut stats = None;
        sync_media(
            &mut a,
            provider,
            &mut media,
            &mut stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
        );
        assert!(!media.take().unwrap().await.unwrap());
        let mut notices = NoticeRing::default();
        media_failed(&mut a, &mut notices);
        assert_eq!(a.status().state, State::Idle);
        assert!(notices
            .items
            .iter()
            .any(|(_, n)| *n == CallNotice::EstablishmentFailed));
        assert!(!a.drain_encoded().is_empty());
    }
    #[test]
    fn ring_is_bounded_and_reports_gaps() {
        let mut ring = NoticeRing::default();
        for _ in 0..65 {
            ring.push(CallNotice::Connected);
        }
        assert_eq!(ring.items.len(), 64);
        match ring.events(0) {
            CallResponse::Events { next, gap, notices } => {
                assert_eq!(next, 65);
                assert!(gap);
                assert_eq!(notices.len(), 64);
            }
            _ => panic!("unexpected response"),
        }
        match ring.events(64) {
            CallResponse::Events { next, gap, notices } => {
                assert_eq!(next, 65);
                assert!(!gap);
                assert_eq!(notices.len(), 1);
            }
            _ => panic!("unexpected response"),
        }
    }
    #[test]
    fn fixed_results_and_states() {
        assert!(matches!(dial_result(Ok(())), CallResponse::Ok));
        assert!(
            matches!(dial_result(Err(CallError::NotAllowed)), CallResponse::Error(s) if s == "not_allowed")
        );
        assert!(matches!(dial_result(Err(CallError::Busy)), CallResponse::Error(s) if s == "busy"));
        assert!(
            matches!(dial_result(Err(CallError::NotReady)), CallResponse::Error(s) if s == "not_ready")
        );
        assert!(
            matches!(dial_result(Err(CallError::Refused)), CallResponse::Error(s) if s == "refused")
        );
        assert_eq!(
            [
                state_word(State::Idle),
                state_word(State::Calling),
                state_word(State::Ringing),
                state_word(State::Connected)
            ],
            ["idle", "calling", "ringing", "connected"]
        );
    }

    #[test]
    fn a_selection_is_stored_and_echoed() {
        // The chosen names are recorded for the next call and echoed back.
        let mut devices = AudioChoice::default();
        assert!(devices.input.is_none() && devices.output.is_none());
        let response = apply_selection(
            &mut devices,
            Some("Mic A".to_owned()),
            Some("Speaker B".to_owned()),
        );
        assert_eq!(devices.input.as_deref(), Some("Mic A"));
        assert_eq!(devices.output.as_deref(), Some("Speaker B"));
        match response {
            CallResponse::AudioDevicesSelected { input, output } => {
                assert_eq!(input.as_deref(), Some("Mic A"));
                assert_eq!(output.as_deref(), Some("Speaker B"));
            }
            _ => panic!("unexpected response"),
        }
        // Choosing the host default on both clears the stored names.
        let response = apply_selection(&mut devices, None, None);
        assert!(devices.input.is_none() && devices.output.is_none());
        assert!(matches!(
            response,
            CallResponse::AudioDevicesSelected {
                input: None,
                output: None,
            }
        ));
    }

    #[test]
    fn listing_audio_devices_never_panics() {
        // On a platform without the audio backend this returns empty lists; on
        // a desktop build it enumerates the host. Either way it must return a
        // value rather than panic, so a client always gets an answer.
        let list = host_device_list();
        // Without the backend both lists are empty; with it they may or may not
        // be, so only the no-panic return is asserted here.
        let _ = (
            list.inputs,
            list.outputs,
            list.default_input,
            list.default_output,
        );
    }
}
