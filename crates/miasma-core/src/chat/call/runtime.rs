use super::{
    controller::{CallController, CallError, CallNotice, CallPorts, MediaGate, SasInputs},
    media_task::{
        maybe_start_media, AudioChoice, IrohLinkProvider, MediaLinkProvider, MediaStats, VideoParts,
    },
    state::State,
    video::ScreenSourceFactory,
};
use crate::chat::{
    ipc::{
        remote_frame_since, AudioDeviceListDto, CallNoticeDto, CallRequest, CallResponse,
        CallStatusDto, RemoteFrameStore,
    },
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
    /// Whether the user has asked to share the screen. Set only by the
    /// StartScreenShare IPC while connected with video negotiated, and cleared
    /// on StopScreenShare, on hang up and whenever the call leaves Connected.
    /// Never set automatically.
    screen_sharing: bool,
    /// Whether the user has asked to send the camera. Set only by the
    /// StartCamera IPC while connected with video negotiated and a camera the
    /// factory could open, and cleared on StopCamera, on hang up and whenever
    /// the call leaves Connected. Never set automatically, so no camera device
    /// is opened before an explicit press.
    camera_requested: bool,
    /// The camera factory the StartCamera handler consults to open the device
    /// on an explicit request. A build without a real camera holds the dormant
    /// `NoCameraFactory`, which always declines, so StartCamera reports
    /// `no_camera`.
    camera_factory: Arc<dyn ScreenSourceFactory>,
    /// The camera source opened by the StartCamera handler, waiting for the
    /// next media sync to hand it to the media task. Opened once on the press
    /// (so the device is not opened twice), taken by the media sync. Dropped,
    /// releasing the device, on StopCamera, on hang up and whenever the call
    /// leaves Connected. Holds a device handle and no key, nonce, call id or
    /// peer id; it is never logged or formatted.
    pending_camera: Option<Box<dyn super::video::VideoSource + Send>>,
    /// The latest decoded remote video frame, shared with the media task that
    /// writes it and read by the IPC handler. Lives beside the call status.
    remote_frames: RemoteFrameStore,
}
impl Inner {
    fn collect(&mut self) {
        for notice in self.controller.take_notices().0 {
            self.notices.push(notice);
        }
        // Neither the screen share nor the camera can outlive the connected
        // call it belongs to; both are cleared the moment the call leaves
        // Connected. Dropping `pending_camera` releases a camera opened for
        // this call but not yet handed to a media task, so the device is
        // released when the call ends even if no media task ever took it.
        if self.controller.status().state != State::Connected {
            self.screen_sharing = false;
            self.camera_requested = false;
            self.pending_camera = None;
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

#[allow(clippy::too_many_arguments)]
fn sync_media<P: CallPorts>(
    controller: &mut CallController<P>,
    provider: Arc<dyn MediaLinkProvider>,
    media: &mut Option<JoinHandle<bool>>,
    stats: &mut Option<MediaStats>,
    muted: Arc<AtomicBool>,
    video_factory: Option<&Arc<VideoPartsFactory>>,
    devices: AudioChoice,
    camera_source: Option<Box<dyn super::video::VideoSource + Send>>,
    screen_factory: Option<&Arc<dyn ScreenSourceFactory>>,
    screen_sharing: bool,
    remote_frames: RemoteFrameStore,
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
        // The camera source was opened by the StartCamera handler on the press
        // and handed in here; this sync just moves it into the media task. It
        // is `Some` only when the user asked for the camera and a device could
        // be opened, so no device is touched here and none before the press. An
        // injected pseudo `video` factory wins over this in
        // `maybe_start_media`, so the test hooks are unaffected.
        // Only open a screen source when the user has asked to share and a
        // factory is present; the factory may still decline (returns None).
        let screen_source = if screen_sharing {
            screen_factory.and_then(|f| f.create())
        } else {
            None
        };
        *media = maybe_start_media(
            controller,
            provider,
            false,
            new_stats.clone(),
            video,
            muted,
            devices,
            camera_source,
            screen_source,
            remote_frames,
        );
        *stats = media.as_ref().map(|_| new_stats);
    }
}
/// A [`ScreenSourceFactory`] that never opens a source. Used as the runtime
/// default when no real screen factory is wired in, so the screen stream stays
/// dormant until a build or test supplies a working factory.
struct NoScreenFactory;
impl ScreenSourceFactory for NoScreenFactory {
    fn create(&self) -> Option<Box<dyn super::video::VideoSource + Send>> {
        None
    }
}
/// A camera source factory that never opens a device. Used as the runtime
/// default when no real camera factory is wired in (a build without the
/// camera feature, or a non-desktop target), so the camera stays dormant and
/// a StartCamera request reports no camera. The camera source factory reuses
/// the [`ScreenSourceFactory`] contract: both build an opened
/// [`super::video::VideoSource`] on demand or decline with `None`.
struct NoCameraFactory;
impl ScreenSourceFactory for NoCameraFactory {
    fn create(&self) -> Option<Box<dyn super::video::VideoSource + Send>> {
        None
    }
}
/// The real camera factory for the shipped daemon: on a desktop build with the
/// `call-camera` feature it opens the default camera on demand
/// ([`super::video_camera::CameraFactory`]); on every other build it is the
/// dormant [`NoCameraFactory`], so the camera stays off and a StartCamera
/// request reports no camera. The camera device is still opened only on an
/// explicit request (the factory is consulted when `camera_requested` is set),
/// never at startup.
fn real_camera_factory() -> Arc<dyn ScreenSourceFactory> {
    #[cfg(all(feature = "call-camera", any(windows, target_os = "macos")))]
    {
        Arc::new(super::video_camera::CameraFactory)
    }
    #[cfg(not(all(feature = "call-camera", any(windows, target_os = "macos"))))]
    {
        Arc::new(NoCameraFactory)
    }
}
/// The real screen factory for the shipped daemon: on a desktop build with the
/// `call-screen` feature it opens the primary display on demand
/// ([`super::screen_capture::PrimaryScreenFactory`]); on every other build it
/// is the dormant [`NoScreenFactory`], so the screen stream stays off until a
/// build supplies a working factory.
fn real_screen_factory() -> Arc<dyn ScreenSourceFactory> {
    #[cfg(all(feature = "call-screen", any(windows, target_os = "macos")))]
    {
        Arc::new(super::screen_capture::PrimaryScreenFactory)
    }
    #[cfg(not(all(feature = "call-screen", any(windows, target_os = "macos"))))]
    {
        Arc::new(NoScreenFactory)
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
        // The shipped daemon gives the runtime the real camera and screen
        // factories for the platforms and features where they exist; where
        // they do not, the dormant defaults are used and both streams stay
        // off. See [`real_camera_factory`] / [`real_screen_factory`].
        let camera_factory = real_camera_factory();
        let screen_factory = real_screen_factory();
        Self::start_full(svc, provider, true, None, camera_factory, screen_factory)
    }
    pub fn start_with_provider(
        svc: Arc<ChatService>,
        provider: Arc<dyn MediaLinkProvider>,
    ) -> Arc<Self> {
        Self::start_full(
            svc,
            provider,
            true,
            None,
            Arc::new(NoCameraFactory),
            Arc::new(NoScreenFactory),
        )
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
        Self::start_full(
            svc,
            provider,
            offers_video,
            Some(parts_factory),
            Arc::new(NoCameraFactory),
            Arc::new(NoScreenFactory),
        )
    }
    /// Test hook: start a runtime with explicit camera and screen factories so
    /// a fake camera/screen source can drive the streams without a device.
    /// Production uses [`start`], which supplies the real factories.
    #[doc(hidden)]
    pub fn start_with_factories(
        svc: Arc<ChatService>,
        provider: Arc<dyn MediaLinkProvider>,
        camera_factory: Arc<dyn ScreenSourceFactory>,
        screen_factory: Arc<dyn ScreenSourceFactory>,
    ) -> Arc<Self> {
        Self::start_full(svc, provider, true, None, camera_factory, screen_factory)
    }
    #[allow(clippy::too_many_arguments)]
    fn start_full(
        svc: Arc<ChatService>,
        provider: Arc<dyn MediaLinkProvider>,
        offers_video: bool,
        video_factory: Option<Arc<VideoPartsFactory>>,
        camera_factory: Arc<dyn ScreenSourceFactory>,
        screen_factory: Arc<dyn ScreenSourceFactory>,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel(32);
        svc.set_call_sink(tx);
        let mut controller = CallController::new(RuntimePorts(svc.clone()));
        if !offers_video {
            controller.set_local_offers_video(false);
        }
        let task_screen_factory = screen_factory.clone();
        let remote_frames: RemoteFrameStore = Arc::new(Mutex::new(None));
        let inner = Arc::new(Mutex::new(Inner {
            controller,
            notices: NoticeRing::default(),
            media_stats: None,
            muted: Arc::new(AtomicBool::new(false)),
            devices: AudioChoice::default(),
            screen_sharing: false,
            camera_requested: false,
            camera_factory,
            pending_camera: None,
            remote_frames: remote_frames.clone(),
        }));
        let wake = Arc::new(Notify::new());
        let stop_task = Arc::new(Notify::new());
        let task_inner = inner.clone();
        let task_svc = svc.clone();
        let task_wake = wake.clone();
        let task_stop = stop_task.clone();
        let task_video = video_factory;
        let task_frames = remote_frames;
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
                        screen_sharing,
                        pending_camera,
                        ..
                    } = &mut *state;
                    let muted = muted.clone();
                    let devices = devices.clone();
                    let screen_sharing = *screen_sharing;
                    // Hand the opened camera source to the media sync only when
                    // one is about to be started (no media task yet). Taking it
                    // only then avoids dropping the source on a sync that does
                    // not start a task; a later sync that does start one still
                    // finds it waiting. When a media task is already running,
                    // the source stays in `pending_camera` until that task ends
                    // and the next sync can use it.
                    let camera_source = if media.is_none() {
                        pending_camera.take()
                    } else {
                        None
                    };
                    sync_media(
                        controller,
                        provider.clone(),
                        &mut media,
                        media_stats,
                        muted,
                        task_video.as_ref(),
                        devices,
                        camera_source,
                        Some(&task_screen_factory),
                        screen_sharing,
                        task_frames.clone(),
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
                let mut dto = status_dto(
                    &state.controller,
                    state.media_stats.as_ref(),
                    state.screen_sharing,
                );
                dto.muted = state.muted.load(Ordering::SeqCst);
                CallResponse::Status(dto)
            }
            // Screen sharing is honoured only while the call is connected with
            // video negotiated, and is never started automatically.
            CallRequest::StartScreenShare => {
                if state.controller.negotiated_video() {
                    state.screen_sharing = true;
                    CallResponse::Ok
                } else {
                    CallResponse::Error("not_ready".into())
                }
            }
            // Stopping is idempotent: it always succeeds and leaves any camera
            // stream untouched.
            CallRequest::StopScreenShare => {
                state.screen_sharing = false;
                CallResponse::Ok
            }
            // The camera is honoured only while the call is connected with video
            // negotiated, and is never started automatically. The device is
            // opened here, on the explicit press: the factory is consulted and,
            // if it opens a camera, the source is held until the next media sync
            // hands it to the media task and `camera_in_use` follows. If no
            // device can be opened the factory declines and the request is
            // refused with `no_camera`; nothing is left requested. Leaving video
            // unnegotiated refuses the request outright with `not_ready` without
            // touching any device.
            CallRequest::StartCamera => {
                let negotiated = state.controller.negotiated_video();
                let (response, source) =
                    decide_start_camera(negotiated, state.camera_requested, &state.camera_factory);
                // Only a fresh successful start yields a source: hold it for the
                // next media sync and mark the camera requested. A refusal or an
                // idempotent repeat changes no state.
                if let Some(source) = source {
                    state.pending_camera = Some(source);
                    state.camera_requested = true;
                }
                response
            }
            // Stopping is idempotent: it always succeeds, clears the request and
            // drops any camera source opened but not yet taken by a media task
            // (releasing the device), and leaves any screen stream untouched. A
            // media task already driving the camera releases the device when it
            // ends; the next media sync starts no new camera because the flag is
            // clear.
            CallRequest::StopCamera => {
                state.camera_requested = false;
                state.pending_camera = None;
                CallResponse::Ok
            }
            CallRequest::Events { since } => state.notices.events(since),
            CallRequest::ListAudioDevices => CallResponse::AudioDevices(host_device_list()),
            CallRequest::SelectAudioDevices { input, output } => {
                apply_selection(&mut state.devices, input, output)
            }
            CallRequest::RemoteFrame { last_seen } => {
                CallResponse::RemoteFrame(remote_frame_since(&state.remote_frames, last_seen))
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

/// The StartCamera decision, factored out so it can be unit-tested without a
/// running service. The camera is honoured only while video is negotiated; an
/// already-requested camera is an idempotent success that opens no second
/// device; otherwise the factory is consulted on the press and either yields a
/// source (held for the next media sync) or declines, which refuses the request
/// with `no_camera`. Leaving video unnegotiated refuses with `not_ready` and
/// touches no device. Returns the response and, on a fresh successful start,
/// the opened source to hold; the caller stores it and sets the requested flag.
fn decide_start_camera(
    negotiated_video: bool,
    already_requested: bool,
    factory: &Arc<dyn ScreenSourceFactory>,
) -> (
    CallResponse,
    Option<Box<dyn super::video::VideoSource + Send>>,
) {
    if !negotiated_video {
        (CallResponse::Error("not_ready".into()), None)
    } else if already_requested {
        (CallResponse::Ok, None)
    } else {
        match factory.create() {
            Some(source) => (CallResponse::Ok, Some(source)),
            None => (CallResponse::Error("no_camera".into()), None),
        }
    }
}

fn status_dto<P: CallPorts>(
    controller: &CallController<P>,
    stats: Option<&MediaStats>,
    screen_sharing: bool,
) -> CallStatusDto {
    let status = controller.status();
    let connected = status.state == State::Connected;
    let stats = if connected { stats } else { None };
    CallStatusDto {
        state: state_word(status.state).into(),
        pending_token: status.pending_token,
        signalling_connected: status.signalling_connected,
        negotiated_video: status.negotiated_video,
        safety_code: controller.safety_code(),
        muted: false,
        media_frames_sent: stats.map_or(0, |s| s.frames_sent.load(Ordering::Relaxed)),
        media_frames_played: stats.map_or(0, |s| s.frames_played.load(Ordering::Relaxed)),
        camera_in_use: stats.map_or(false, |s| s.camera_in_use.load(Ordering::Relaxed)),
        media_video_frames_sent: stats.map_or(0, |s| s.video_frames_sent.load(Ordering::Relaxed)),
        media_video_frames_played: stats
            .map_or(0, |s| s.video_frames_played.load(Ordering::Relaxed)),
        // Only ever true inside a connected call.
        screen_sharing: connected && screen_sharing,
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
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        sync_media(
            &mut b,
            provider.clone(),
            &mut bm,
            &mut b_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        sync_media(
            &mut a,
            provider.clone(),
            &mut am,
            &mut a_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        tokio::task::yield_now().await;
        assert_eq!(provider.opens.load(Ordering::SeqCst), 2);
        assert_eq!(a.status().state, State::Connected);
        assert_eq!(b.status().state, State::Connected);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let a_status = status_dto(&a, a_stats.as_ref(), false);
                let b_status = status_dto(&b, b_stats.as_ref(), false);
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
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        sync_media(
            &mut b,
            provider,
            &mut bm,
            &mut b_stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        assert!(am.is_none() && bm.is_none());
        for status in [
            status_dto(&a, a_stats.as_ref(), false),
            status_dto(&b, b_stats.as_ref(), false),
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
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
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

    #[test]
    fn status_dto_reports_screen_sharing_only_when_connected() {
        // A connected call with the flag set reports it.
        let (a, _b) = connected();
        assert_eq!(a.status().state, State::Connected);
        assert!(status_dto(&a, None, true).screen_sharing);
        assert!(!status_dto(&a, None, false).screen_sharing);

        // An idle controller never reports screen sharing, even if asked to.
        let idle = CallController::new(Ports);
        assert_eq!(idle.status().state, State::Idle);
        assert!(!status_dto(&idle, None, true).screen_sharing);
    }

    // The screen-share start/stop decision taken by `CallRuntime::handle`:
    // start is honoured only while video is negotiated; stop always clears it.
    fn decide_screen_share(controller: &CallController<Ports>, start: bool, prev: bool) -> bool {
        if start {
            if controller.negotiated_video() {
                true
            } else {
                prev
            }
        } else {
            false
        }
    }

    #[test]
    fn screen_share_start_needs_negotiated_video_and_stop_is_idempotent() {
        // Connected with video negotiated: start turns it on, stop turns it off,
        // and a repeated stop stays off.
        let (a, _b) = connected();
        assert!(a.negotiated_video());
        assert!(decide_screen_share(&a, true, false));
        assert!(!decide_screen_share(&a, false, true));
        assert!(!decide_screen_share(&a, false, false));

        // Not connected (no video negotiated): start is refused, leaving the
        // previous value untouched; stop still clears it.
        let idle = CallController::new(Ports);
        assert!(!idle.negotiated_video());
        assert!(!decide_screen_share(&idle, true, false));
        assert!(!decide_screen_share(&idle, false, true));
    }

    /// A fake camera source that reports open and hands out a fixed small
    /// picture, so a media task's camera driver captures and `camera_in_use`
    /// follows. Holds no device and no secret.
    struct FakeCamera {
        open: Arc<AtomicBool>,
    }
    impl super::super::video::VideoSource for FakeCamera {
        fn is_open(&self) -> bool {
            self.open.load(Ordering::Relaxed)
        }
        fn next_picture(&mut self) -> Option<super::super::video::RawPicture> {
            Some(super::super::video::RawPicture {
                width: 8,
                height: 8,
                pixels: vec![0u8; 64],
            })
        }
    }
    /// A fake camera factory that opens a `FakeCamera` on demand. The shared
    /// `open` flag lets a test observe that the source the media task holds is
    /// the one it created.
    struct FakeCameraFactory {
        open: Arc<AtomicBool>,
    }
    impl ScreenSourceFactory for FakeCameraFactory {
        fn create(&self) -> Option<Box<dyn super::super::video::VideoSource + Send>> {
            Some(Box::new(FakeCamera {
                open: self.open.clone(),
            }))
        }
    }

    #[test]
    fn start_camera_needs_connect_and_negotiated_video() {
        // Before connect (a fresh idle controller never negotiated video):
        // StartCamera is refused with `not_ready` and opens no device.
        let idle = CallController::new(Ports);
        assert!(!idle.negotiated_video());
        let open = Arc::new(AtomicBool::new(true));
        let factory: Arc<dyn ScreenSourceFactory> = Arc::new(FakeCameraFactory { open });
        let (response, source) = decide_start_camera(idle.negotiated_video(), false, &factory);
        assert!(matches!(response, CallResponse::Error(ref s) if s == "not_ready"));
        assert!(source.is_none());
    }

    #[tokio::test]
    async fn start_camera_with_a_camera_starts_and_stop_and_hangup_release_it() {
        // Connected with video negotiated and a camera the factory can open:
        // StartCamera succeeds and yields a source to hold.
        let (a, _b) = connected();
        assert!(a.negotiated_video());
        let open = Arc::new(AtomicBool::new(true));
        let factory: Arc<dyn ScreenSourceFactory> =
            Arc::new(FakeCameraFactory { open: open.clone() });
        let (response, source) = decide_start_camera(a.negotiated_video(), false, &factory);
        assert!(matches!(response, CallResponse::Ok));
        let source = source.expect("a camera was opened");

        // Driving a media task with that source turns `camera_in_use` true.
        let x = Arc::new(Mutex::new(VecDeque::new()));
        let y = Arc::new(Mutex::new(VecDeque::new()));
        let provider = Arc::new(Provider {
            links: Mutex::new(VecDeque::from([Box::new(Link {
                incoming: x.clone(),
                outgoing: y,
            }) as Box<dyn DatagramLink>])),
            opens: AtomicUsize::new(0),
        });
        let mut a = a;
        let mut media = None;
        let mut stats = None;
        sync_media(
            &mut a,
            provider.clone(),
            &mut media,
            &mut stats,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
            Some(source),
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        // The media task was started; wait for the camera to report in use.
        let stats = stats.expect("a media task was started");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !stats.camera_in_use.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("camera_in_use did not become true in time");
        assert!(status_dto(&a, Some(&stats), false).camera_in_use);

        // Ending the call stops the media task: the next sync aborts it and
        // clears the stats. A disconnected call never reports the camera in
        // use, whatever the shared flag, because `status_dto` ignores the
        // stats once the call is not connected.
        a.hang_up();
        let mut after = None;
        sync_media(
            &mut a,
            provider,
            &mut media,
            &mut after,
            Arc::new(AtomicBool::new(false)),
            None,
            AudioChoice::default(),
            None,
            None,
            false,
            Arc::new(Mutex::new(None)),
        );
        assert!(media.is_none());
        assert!(after.is_none());
        assert!(!status_dto(&a, Some(&stats), false).camera_in_use);
    }

    #[test]
    fn start_camera_without_a_camera_reports_no_camera() {
        // Connected with video negotiated but the factory declines (no device):
        // StartCamera is refused with `no_camera` and holds no source.
        let (a, _b) = connected();
        assert!(a.negotiated_video());
        let factory: Arc<dyn ScreenSourceFactory> = Arc::new(NoCameraFactory);
        let (response, source) = decide_start_camera(a.negotiated_video(), false, &factory);
        assert!(matches!(response, CallResponse::Error(ref s) if s == "no_camera"));
        assert!(source.is_none());
    }

    #[test]
    fn start_camera_is_idempotent_and_opens_no_second_device() {
        // When the camera is already requested, a repeat StartCamera is an
        // idempotent success that consults no factory and opens no new source.
        let (a, _b) = connected();
        assert!(a.negotiated_video());
        let open = Arc::new(AtomicBool::new(true));
        let factory: Arc<dyn ScreenSourceFactory> = Arc::new(FakeCameraFactory { open });
        let (response, source) = decide_start_camera(a.negotiated_video(), true, &factory);
        assert!(matches!(response, CallResponse::Ok));
        assert!(source.is_none());
    }
}
