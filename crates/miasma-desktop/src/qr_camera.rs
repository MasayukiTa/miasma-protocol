//! Reading a contact code from the camera, as one more way to fill the "Add a contact" form.
//!
//! The camera itself is behind two small traits ([`CameraBackend`], [`CameraSource`]) so that
//! everything that matters is tested with a fake camera: the scan loop, its stop conditions and
//! the release of the camera. The real backend (Media Foundation on Windows, AVFoundation on macOS)
//! is the last part of this file.
//!
//! What the scan does and does not do:
//! * Frames are kept in memory only. Nothing is written to disk, logged or sent anywhere. Only
//!   the newest frame is held for the preview, and it is dropped when the scan ends.
//! * One scan reads about [`ScanConfig::frame_interval`] apart (10 per second by default), at most
//!   [`ScanConfig::max_side`] pixels on the long side, and ends after [`ScanConfig::timeout`].
//! * A frame goes through the same scanner and the same check as a picture or a pasted text
//!   (`qr_image::decode_luma_texts`, `extract_contact_code`).
//! * The camera is let go (the source is dropped on the scan thread) as soon as a code is
//!   accepted, the person stops the scan, the time runs out, or the window stops drawing the form
//!   (see [`ScanHandle::touch`]): a closed dialog, a hidden tab or a minimised window all stop the
//!   heartbeat.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::qr_image;

/// Why the camera gave nothing. Each one has its own sentence in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraError {
    /// No camera is connected.
    NoCamera,
    /// The system does not let Miasma use the camera.
    Denied,
    /// Another program is using the camera.
    Busy,
    /// Anything else (the camera could not be started, or stopped delivering pictures).
    Failed,
}

/// One camera picture, grey, `width * height` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub luma: Vec<u8>,
}

/// An open camera. Dropping it lets the camera go. It is opened and used on the scan thread only
/// (the system camera objects cannot be moved between threads), so it need not be `Send`.
pub trait CameraSource {
    /// The next picture; waits until there is one.
    fn next_frame(&mut self) -> Result<Frame, CameraError>;
}

/// Finds and opens the camera.
pub trait CameraBackend: Send + Sync {
    /// Whether this kind of computer can use a camera at all (the button is hidden otherwise).
    fn supported(&self) -> bool;
    /// How many cameras are connected.
    fn camera_count(&self) -> Result<usize, CameraError>;
    /// Open the first camera and start its picture stream. Asks for permission first where the
    /// system wants that.
    fn open(&self) -> Result<Box<dyn CameraSource>, CameraError>;
}

/// The limits of one scan. Each has its reason:
/// * `timeout`: a camera left on by mistake must not stay on (60 s with no code).
/// * `frame_interval`: reading a picture costs CPU; a QR code does not need more than ~10 a second.
/// * `max_side`: a 4K frame costs 8 times the time of a 720p one and reads no better.
/// * `preview_side`: the preview is small.
/// * `stale_after`: the form must have been drawn within this time, otherwise the scan ends.
#[derive(Clone, Copy, Debug)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub frame_interval: Duration,
    pub max_side: usize,
    pub preview_side: usize,
    pub stale_after: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            frame_interval: Duration::from_millis(100),
            max_side: 1280,
            preview_side: 320,
            stale_after: Duration::from_millis(1500),
        }
    }
}

/// How a scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// A code was accepted.
    Found,
    /// The person stopped it, or the form is no longer shown.
    Stopped,
    /// No code within the time.
    TimedOut,
    /// The camera failed.
    Error(CameraError),
}

/// What the scan thread tells the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanEvent {
    /// The camera is open and delivering pictures.
    Started,
    /// A QR code was seen, but it holds no Miasma contact code.
    NotMiasma,
    /// A contact code was accepted.
    Found(String),
    /// The scan is over; the camera has been let go.
    Ended(End),
}

/// A running scan. Dropping it stops the scan.
pub struct ScanHandle {
    stop: Arc<AtomicBool>,
    beat: Arc<AtomicU64>,
    epoch: Instant,
    rx: Receiver<ScanEvent>,
    preview: Arc<Mutex<Option<Frame>>>,
}

impl ScanHandle {
    /// Start a scan on its own thread. `repaint` is called when there is something new to show.
    pub fn start(
        backend: Arc<dyn CameraBackend>,
        cfg: ScanConfig,
        repaint: Arc<dyn Fn() + Send + Sync>,
    ) -> Option<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let beat = Arc::new(AtomicU64::new(0));
        let preview = Arc::new(Mutex::new(None));
        let epoch = Instant::now();
        let (tx, rx) = channel();
        let job = ScanJob {
            backend,
            cfg,
            stop: stop.clone(),
            beat: beat.clone(),
            epoch,
            preview: preview.clone(),
            tx,
            repaint,
        };
        std::thread::Builder::new()
            .name("qr-camera".into())
            .spawn(move || job.run())
            .ok()?;
        Some(Self {
            stop,
            beat,
            epoch,
            rx,
            preview,
        })
    }

    /// The form is being drawn: the scan may go on. Call this every frame the form is shown.
    pub fn touch(&self) {
        self.beat
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Ask the scan to end; the camera is let go within one picture.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// The next event, if there is one.
    pub fn poll(&self) -> Option<ScanEvent> {
        match self.rx.try_recv() {
            Ok(e) => Some(e),
            Err(TryRecvError::Empty) => None,
            // The thread is gone without a last word.
            Err(TryRecvError::Disconnected) => {
                Some(ScanEvent::Ended(End::Error(CameraError::Failed)))
            }
        }
    }

    /// The newest preview picture, once (taking it empties the slot).
    pub fn take_preview(&self) -> Option<Frame> {
        self.preview.lock().ok()?.take()
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Everything the scan thread needs.
struct ScanJob {
    backend: Arc<dyn CameraBackend>,
    cfg: ScanConfig,
    stop: Arc<AtomicBool>,
    beat: Arc<AtomicU64>,
    epoch: Instant,
    preview: Arc<Mutex<Option<Frame>>>,
    tx: Sender<ScanEvent>,
    repaint: Arc<dyn Fn() + Send + Sync>,
}

impl ScanJob {
    fn run(self) {
        // A panic in a camera or decoder library must not leave the window waiting; the camera
        // source is a local of `scan`, so it is dropped (let go) on the way out in either case.
        let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.scan()))
            .unwrap_or(End::Error(CameraError::Failed));
        if end != End::Found {
            let _ = self.tx.send(ScanEvent::Ended(end));
        }
        if let Ok(mut slot) = self.preview.lock() {
            *slot = None;
        }
        (self.repaint)();
    }

    fn stale(&self) -> bool {
        let now = self.epoch.elapsed().as_millis() as u64;
        now.saturating_sub(self.beat.load(Ordering::Relaxed))
            > self.cfg.stale_after.as_millis() as u64
    }

    fn scan(&self) -> End {
        let mut camera = match self.backend.open() {
            Ok(c) => c,
            Err(e) => return End::Error(e),
        };
        let _ = self.tx.send(ScanEvent::Started);
        (self.repaint)();
        let deadline = Instant::now() + self.cfg.timeout;
        let mut last_read: Option<Instant> = None;
        let mut bad_frames = 0u32;
        let mut told_not_miasma = false;
        loop {
            if self.stop.load(Ordering::Relaxed) || self.stale() {
                return End::Stopped;
            }
            if Instant::now() >= deadline {
                return End::TimedOut;
            }
            let frame = match camera.next_frame() {
                Ok(f) => {
                    bad_frames = 0;
                    f
                }
                Err(e @ (CameraError::NoCamera | CameraError::Denied | CameraError::Busy)) => {
                    return End::Error(e)
                }
                Err(CameraError::Failed) => {
                    bad_frames += 1;
                    if bad_frames >= 30 {
                        return End::Error(CameraError::Failed);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
            };
            // Pictures between two reads are dropped unread.
            if last_read.is_some_and(|t| t.elapsed() < self.cfg.frame_interval) {
                continue;
            }
            last_read = Some(Instant::now());
            let (pw, ph, pixels) = qr_image::downscale_luma(
                frame.width,
                frame.height,
                &frame.luma,
                self.cfg.preview_side,
            );
            if let Ok(mut slot) = self.preview.lock() {
                *slot = Some(Frame {
                    width: pw,
                    height: ph,
                    luma: pixels,
                });
            }
            (self.repaint)();
            let (w, h, luma) =
                qr_image::downscale_luma(frame.width, frame.height, &frame.luma, self.cfg.max_side);
            let Ok(texts) = qr_image::decode_luma_texts(w, h, &luma) else {
                continue;
            };
            if let Some(code) = qr_image::first_contact_code(&texts) {
                let _ = self.tx.send(ScanEvent::Found(code));
                return End::Found;
            }
            if !told_not_miasma {
                told_not_miasma = true;
                let _ = self.tx.send(ScanEvent::NotMiasma);
                (self.repaint)();
            }
        }
    }
}

/// Where a scan stands, as the window shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    /// Opening the camera (and, on macOS, waiting for the permission answer).
    Starting,
    Scanning,
    /// A code was accepted; the camera is already let go.
    Found,
    Denied,
    NoCamera,
    Busy,
    Failed,
    TimedOut,
}

/// The window's side of a scan: the state, and the running scan if there is one.
pub struct Scanner {
    state: ScanState,
    handle: Option<ScanHandle>,
    /// A QR code that is not a contact code is in view.
    pub not_miasma: bool,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            state: ScanState::Idle,
            handle: None,
            not_miasma: false,
        }
    }
}

impl Scanner {
    pub fn state(&self) -> ScanState {
        self.state
    }

    #[cfg(test)]
    pub fn set_state_for_test(&mut self, state: ScanState) {
        self.state = state;
    }

    /// The camera is open or being opened.
    pub fn running(&self) -> bool {
        self.handle.is_some()
    }

    /// Begin a scan. Does nothing while one is running.
    pub fn start(
        &mut self,
        backend: Arc<dyn CameraBackend>,
        cfg: ScanConfig,
        repaint: Arc<dyn Fn() + Send + Sync>,
    ) {
        if self.handle.is_some() {
            return;
        }
        self.not_miasma = false;
        match ScanHandle::start(backend, cfg, repaint) {
            Some(h) => {
                h.touch();
                self.handle = Some(h);
                self.state = ScanState::Starting;
            }
            None => self.state = ScanState::Failed,
        }
    }

    /// End the scan now (the camera is let go on the scan thread).
    pub fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.stop();
        }
        if matches!(self.state, ScanState::Starting | ScanState::Scanning) {
            self.state = ScanState::Idle;
        }
        self.not_miasma = false;
    }

    /// Forget how an earlier scan ended (before the form is shown again).
    pub fn reset(&mut self) {
        self.stop();
        self.state = ScanState::Idle;
    }

    /// Call every frame the form is drawn. Keeps the scan alive, takes up what the scan thread
    /// said, and returns the contact code when one was accepted.
    pub fn pump(&mut self) -> Option<String> {
        let h = self.handle.as_ref()?;
        h.touch();
        let mut found = None;
        let mut ended = None;
        while let Some(e) = h.poll() {
            match e {
                ScanEvent::Started => self.state = ScanState::Scanning,
                ScanEvent::NotMiasma => self.not_miasma = true,
                ScanEvent::Found(code) => {
                    found = Some(code);
                    ended = Some(End::Found);
                    break;
                }
                ScanEvent::Ended(end) => {
                    ended = Some(end);
                    break;
                }
            }
        }
        if let Some(end) = ended {
            self.handle = None;
            self.not_miasma = false;
            self.state = match end {
                End::Found => ScanState::Found,
                End::Stopped => ScanState::Idle,
                End::TimedOut => ScanState::TimedOut,
                End::Error(CameraError::NoCamera) => ScanState::NoCamera,
                End::Error(CameraError::Denied) => ScanState::Denied,
                End::Error(CameraError::Busy) => ScanState::Busy,
                End::Error(CameraError::Failed) => ScanState::Failed,
            };
        }
        found
    }

    /// The newest preview picture, if there is a new one.
    pub fn take_preview(&self) -> Option<Frame> {
        self.handle.as_ref()?.take_preview()
    }
}

// ─── The real camera ────────────────────────────────────────────────────────

/// The camera of this computer, or `None` where no backend is built in.
pub fn system_backend() -> Option<Arc<dyn CameraBackend>> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        Some(Arc::new(system::SystemCamera))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod system {
    use super::{CameraBackend, CameraError, CameraSource, Frame};
    use nokhwa::pixel_format::LumaFormat;
    use nokhwa::utils::{
        ApiBackend, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType, Resolution,
    };
    use nokhwa::{Buffer, Camera, NokhwaError};

    /// Media Foundation (Windows) or AVFoundation (macOS), through `nokhwa`.
    pub struct SystemCamera;

    /// The wording of the system's refusal differs by platform; this reads the usual words.
    fn classify(e: &NokhwaError) -> CameraError {
        let text = e.to_string().to_ascii_lowercase();
        if [
            "denied",
            "permission",
            "not authorized",
            "unauthorized",
            "0x80070005",
        ]
        .iter()
        .any(|w| text.contains(w))
        {
            CameraError::Denied
        } else if ["busy", "in use", "being used", "exclusive", "0xc00d3704"]
            .iter()
            .any(|w| text.contains(w))
        {
            CameraError::Busy
        } else {
            CameraError::Failed
        }
    }

    /// macOS asks the person once; the answer comes back through a callback. Other systems
    /// answer at once.
    fn permission() -> bool {
        if nokhwa::nokhwa_check() {
            return true;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        nokhwa::nokhwa_initialize(move |granted| {
            let _ = tx.send(granted);
        });
        rx.recv_timeout(std::time::Duration::from_secs(120))
            .unwrap_or(false)
    }

    impl CameraBackend for SystemCamera {
        fn supported(&self) -> bool {
            true
        }

        fn camera_count(&self) -> Result<usize, CameraError> {
            nokhwa::query(ApiBackend::Auto)
                .map(|list| list.len())
                .map_err(|e| classify(&e))
        }

        fn open(&self) -> Result<Box<dyn CameraSource>, CameraError> {
            if !permission() {
                return Err(CameraError::Denied);
            }
            if self.camera_count()? == 0 {
                return Err(CameraError::NoCamera);
            }
            let format = RequestedFormat::new::<LumaFormat>(
                RequestedFormatType::HighestResolution(Resolution::new(1280, 720)),
            );
            let mut camera =
                Camera::new(CameraIndex::Index(0), format).map_err(|e| classify(&e))?;
            camera.open_stream().map_err(|e| classify(&e))?;
            Ok(Box::new(Source { camera }))
        }
    }

    struct Source {
        camera: Camera,
    }

    impl CameraSource for Source {
        fn next_frame(&mut self) -> Result<Frame, CameraError> {
            let buffer: Buffer = self.camera.frame().map_err(|e| classify(&e))?;
            if buffer.source_frame_format() == FrameFormat::MJPEG {
                // Decoded with the picture decoder of the add form (same limits), not by nokhwa.
                let (width, height, luma) = crate::qr_image::luma_from_picture(buffer.buffer())
                    .map_err(|_| CameraError::Failed)?;
                return Ok(Frame {
                    width,
                    height,
                    luma,
                });
            }
            let grey = buffer
                .decode_image::<LumaFormat>()
                .map_err(|_| CameraError::Failed)?;
            Ok(Frame {
                width: grey.width() as usize,
                height: grey.height() as usize,
                luma: grey.into_raw(),
            })
        }
    }
    // Dropping `Source` drops the `Camera`, which stops the stream and lets the camera go.
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    /// A fake camera: hands out the given pictures one after another, then the last one again
    /// (or fails when `then` says so), pausing `pace` between pictures. `released` turns true
    /// when the source is dropped.
    pub(crate) struct FakeCamera {
        pub frames: Vec<Frame>,
        pub then: Option<CameraError>,
        pub open_error: Option<CameraError>,
        pub pace: Duration,
        pub released: Arc<AtomicBool>,
        pub opened: Arc<AtomicUsize>,
    }

    impl FakeCamera {
        pub(crate) fn new(frames: Vec<Frame>) -> Self {
            Self {
                frames,
                then: None,
                open_error: None,
                pace: Duration::from_millis(5),
                released: Arc::new(AtomicBool::new(false)),
                opened: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    struct FakeSource {
        queue: VecDeque<Frame>,
        last: Option<Frame>,
        then: Option<CameraError>,
        pace: Duration,
        released: Arc<AtomicBool>,
    }

    impl Drop for FakeSource {
        fn drop(&mut self) {
            self.released.store(true, Ordering::SeqCst);
        }
    }

    impl CameraSource for FakeSource {
        fn next_frame(&mut self) -> Result<Frame, CameraError> {
            std::thread::sleep(self.pace);
            if let Some(f) = self.queue.pop_front() {
                self.last = Some(f.clone());
                return Ok(f);
            }
            match (self.then, &self.last) {
                (Some(e), _) => Err(e),
                (None, Some(f)) => Ok(f.clone()),
                (None, None) => Err(CameraError::Failed),
            }
        }
    }

    impl CameraBackend for FakeCamera {
        fn supported(&self) -> bool {
            true
        }
        fn camera_count(&self) -> Result<usize, CameraError> {
            match self.open_error {
                Some(CameraError::NoCamera) => Ok(0),
                Some(e) => Err(e),
                None => Ok(1),
            }
        }
        fn open(&self) -> Result<Box<dyn CameraSource>, CameraError> {
            if let Some(e) = self.open_error {
                return Err(e);
            }
            self.opened.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeSource {
                queue: self.frames.clone().into(),
                last: None,
                then: self.then,
                pace: self.pace,
                released: self.released.clone(),
            }))
        }
    }

    fn fast() -> ScanConfig {
        ScanConfig {
            timeout: Duration::from_secs(10),
            frame_interval: Duration::from_millis(10),
            max_side: 1280,
            preview_side: 160,
            stale_after: Duration::from_millis(400),
        }
    }

    fn no_repaint() -> Arc<dyn Fn() + Send + Sync> {
        Arc::new(|| {})
    }

    /// A camera picture of `text`: the QR picture with a grey border, as a camera would see it.
    pub(crate) fn frame_of(text: &str, scale: u32) -> Frame {
        let png = crate::qr_image::tests::png_of(text, scale);
        let (width, height, luma) = qr_image::luma_from_picture(&png).unwrap();
        Frame {
            width,
            height,
            luma,
        }
    }

    fn blank() -> Frame {
        Frame {
            width: 160,
            height: 120,
            luma: vec![200; 160 * 120],
        }
    }

    /// Run the window side of a scan until `done` holds, keeping the form "drawn".
    fn pump_until(s: &mut Scanner, mut done: impl FnMut(&Scanner) -> bool) -> Option<String> {
        let mut code = None;
        for _ in 0..1000 {
            if let Some(c) = s.pump() {
                code = Some(c);
            }
            if done(s) {
                return code;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the scan did not reach the expected state: {:?}", s.state());
    }

    fn released(flag: &Arc<AtomicBool>) -> bool {
        for _ in 0..500 {
            if flag.load(Ordering::SeqCst) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn a_code_in_front_of_the_camera_is_accepted_and_the_camera_is_let_go() {
        let code = crate::qr_image::tests::fresh_code();
        let cam = FakeCamera::new(vec![
            blank(),
            frame_of("https://example.org/", 4),
            frame_of(&crate::contacts::qr_payload(&code), 4),
        ]);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        assert_eq!(s.state(), ScanState::Starting);
        let got = pump_until(&mut s, |s| s.state() == ScanState::Found);
        assert_eq!(got.as_deref(), Some(code.as_str()));
        assert!(!s.running());
        assert!(released(&released_flag), "the camera was not let go");
    }

    #[test]
    fn a_qr_code_that_is_not_a_contact_code_is_noted_and_the_scan_goes_on() {
        let cam = FakeCamera::new(vec![frame_of("https://example.org/", 4)]);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        pump_until(&mut s, |s| s.not_miasma);
        assert_eq!(s.state(), ScanState::Scanning);
        s.stop();
        assert!(released(&released_flag));
    }

    #[test]
    fn stopping_lets_the_camera_go() {
        let cam = FakeCamera::new(vec![blank()]);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::Scanning);
        s.stop();
        assert_eq!(s.state(), ScanState::Idle);
        assert!(released(&released_flag));
    }

    #[test]
    fn dropping_the_scanner_lets_the_camera_go() {
        let cam = FakeCamera::new(vec![blank()]);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::Scanning);
        drop(s);
        assert!(released(&released_flag));
    }

    #[test]
    fn a_form_that_is_no_longer_drawn_ends_the_scan() {
        let cam = FakeCamera::new(vec![blank()]);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::Scanning);
        // No more pump() calls: the heartbeat lapses (400 ms in this test).
        assert!(released(&released_flag), "a hidden form kept the camera on");
    }

    #[test]
    fn no_code_in_time_ends_the_scan() {
        let cam = FakeCamera::new(vec![blank()]);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        let cfg = ScanConfig {
            timeout: Duration::from_millis(300),
            ..fast()
        };
        s.start(Arc::new(cam), cfg, no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::TimedOut);
        assert!(released(&released_flag));
    }

    #[test]
    fn the_default_limits_are_the_stated_ones() {
        let c = ScanConfig::default();
        assert_eq!(c.timeout, Duration::from_secs(60));
        assert_eq!(c.frame_interval, Duration::from_millis(100));
        assert_eq!(c.max_side, 1280);
    }

    #[test]
    fn camera_problems_become_their_own_states() {
        for (err, state) in [
            (CameraError::NoCamera, ScanState::NoCamera),
            (CameraError::Denied, ScanState::Denied),
            (CameraError::Busy, ScanState::Busy),
            (CameraError::Failed, ScanState::Failed),
        ] {
            let mut cam = FakeCamera::new(Vec::new());
            cam.open_error = Some(err);
            let mut s = Scanner::default();
            s.start(Arc::new(cam), fast(), no_repaint());
            pump_until(&mut s, |s| s.state() == state);
            assert!(!s.running());
        }
        // The camera is lost while scanning.
        let mut cam = FakeCamera::new(vec![blank()]);
        cam.then = Some(CameraError::NoCamera);
        let released_flag = cam.released.clone();
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::NoCamera);
        assert!(released(&released_flag));
        // A camera that only ever sends bad pictures gives up.
        let mut cam = FakeCamera::new(Vec::new());
        cam.pace = Duration::from_millis(1);
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::Failed);
    }

    #[test]
    fn a_second_start_does_nothing_and_reset_forgets_the_end() {
        let cam = Arc::new(FakeCamera::new(vec![blank()]));
        let opened = cam.opened.clone();
        let mut s = Scanner::default();
        s.start(cam.clone(), fast(), no_repaint());
        s.start(cam, fast(), no_repaint());
        pump_until(&mut s, |s| s.state() == ScanState::Scanning);
        assert_eq!(opened.load(Ordering::SeqCst), 1);
        s.reset();
        assert_eq!(s.state(), ScanState::Idle);
    }

    #[test]
    fn the_preview_is_small_and_taken_once() {
        let cam = FakeCamera::new(vec![Frame {
            width: 640,
            height: 480,
            luma: vec![90; 640 * 480],
        }]);
        let mut s = Scanner::default();
        s.start(Arc::new(cam), fast(), no_repaint());
        let mut preview = None;
        for _ in 0..500 {
            s.pump();
            preview = s.take_preview();
            if preview.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let p = preview.expect("a preview picture");
        assert!(p.width.max(p.height) <= 160);
        assert_eq!(p.luma.len(), p.width * p.height);
        s.stop();
    }

    #[test]
    fn downscaling_keeps_a_code_readable_and_refuses_bad_sizes() {
        let code = crate::qr_image::tests::fresh_code();
        // A big frame (about 1800 px) is shrunk to at most 1280 and still read.
        let big = frame_of(&crate::contacts::qr_payload(&code), 30);
        assert!(big.width > 1280);
        let (w, h, luma) = qr_image::downscale_luma(big.width, big.height, &big.luma, 1280);
        assert!(w.max(h) <= 1280 && luma.len() == w * h);
        let texts = qr_image::decode_luma_texts(w, h, &luma).unwrap();
        assert_eq!(qr_image::first_contact_code(&texts), Some(code));
        // Small input is returned as it is; wrong sizes give nothing and never panic.
        assert_eq!(
            qr_image::downscale_luma(10, 10, &[7; 100], 1280),
            (10, 10, vec![7; 100])
        );
        assert_eq!(qr_image::downscale_luma(10, 10, &[7; 99], 4).0, 0);
        assert_eq!(qr_image::downscale_luma(0, 0, &[], 4).0, 0);
        assert!(qr_image::decode_luma_texts(100, 100, &[0; 5]).is_err());
        assert!(qr_image::decode_luma_texts(usize::MAX, 2, &[0; 5]).is_err());
    }
}
