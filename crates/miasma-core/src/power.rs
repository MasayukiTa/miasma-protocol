//! Keeps the computer from idling into sleep, and asks the OS to treat this
//! process as doing work the person asked for, while a transfer or an
//! in-flight chat message needs the network.
//!
//! Callers take an [`ActivityGuard`] for the duration of the work and drop it
//! when the work ends. Guards are counted: the platform request is made when
//! the first guard is taken and withdrawn when the last one is dropped, so
//! there is no polling and nothing to clean up if a task panics (the guard is
//! released while unwinding, and a process that exits releases the request
//! by itself).
//!
//! Platform behaviour:
//!
//! * macOS: `NSProcessInfo.beginActivity(options:reason:)` with
//!   `userInitiated | idleSystemSleepDisabled`, ended with `endActivity`.
//! * Windows: `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)`.
//!   The state belongs to the calling thread, so one dedicated thread makes
//!   every call. The display is not kept on.
//! * Other platforms: nothing is requested and [`is_held`] stays `false`.
//!
//! The platform calls run on one small dedicated thread that is started the
//! first time a guard is taken; taking or dropping a guard only increments a
//! counter and queues a message, so it never blocks the caller.

use std::sync::{
    mpsc::{channel, Sender},
    Arc, Mutex, MutexGuard, OnceLock,
};

/// What the platform side has to do. The real implementations are below; the
/// tests use a recording one.
pub trait Backend: Send + Sync + 'static {
    /// The first guard was taken.
    fn engage(&self, reason: &str);
    /// The last guard was dropped.
    fn release(&self);
    /// Whether engaging really asks the OS for something on this platform.
    fn effective(&self) -> bool {
        true
    }
}

/// The reference-counted state shared by all guards.
pub struct Holder {
    count: Mutex<usize>,
    backend: Box<dyn Backend>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic in another holder of the lock must not stop the release.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Holder {
    pub fn new(backend: Box<dyn Backend>) -> Arc<Self> {
        Arc::new(Self {
            count: Mutex::new(0),
            backend,
        })
    }

    /// Take one hold. `reason` is a short fixed label for the first hold (the
    /// OS may show it); never put a peer or file name in it.
    pub fn acquire(self: &Arc<Self>, reason: &'static str) -> ActivityGuard {
        let mut n = lock(&self.count);
        *n += 1;
        if *n == 1 {
            // Under the lock, so engage and release reach the backend in order.
            self.backend.engage(reason);
        }
        ActivityGuard {
            holder: Arc::clone(self),
        }
    }

    /// Holds currently taken.
    pub fn holds(&self) -> usize {
        *lock(&self.count)
    }

    /// At least one hold is taken and the platform really honours it.
    pub fn is_active(&self) -> bool {
        self.holds() > 0 && self.backend.effective()
    }

    fn release_one(&self) {
        let mut n = lock(&self.count);
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.backend.release();
        }
    }
}

/// One hold on the "keep working" request. Released on drop.
#[must_use = "the computer is only kept awake while the guard is alive"]
pub struct ActivityGuard {
    holder: Arc<Holder>,
}

impl ActivityGuard {
    /// Take a hold on the process-wide request.
    pub fn acquire(reason: &'static str) -> ActivityGuard {
        global().acquire(reason)
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.holder.release_one();
    }
}

/// Whether the process currently holds the request (and the platform honours it).
pub fn is_held() -> bool {
    global().is_active()
}

fn global() -> &'static Arc<Holder> {
    static GLOBAL: OnceLock<Arc<Holder>> = OnceLock::new();
    GLOBAL.get_or_init(|| Holder::new(platform_backend()))
}

// ─── Platform side ──────────────────────────────────────────────────────────

/// Per-platform state, created and used only on the dedicated thread (so it
/// need not be `Send`).
#[cfg(any(windows, target_os = "macos"))]
trait Platform {
    fn new() -> Self;
    fn engage(&mut self, reason: &str);
    fn release(&mut self);
}

#[cfg(any(windows, target_os = "macos"))]
enum Cmd {
    Engage(String),
    Release,
}

/// Runs a [`Platform`] on its own thread, started on first use.
#[cfg(any(windows, target_os = "macos"))]
struct ThreadBackend<P: Platform> {
    tx: Mutex<Option<Sender<Cmd>>>,
    _p: std::marker::PhantomData<fn() -> P>,
}

#[cfg(any(windows, target_os = "macos"))]
impl<P: Platform + 'static> ThreadBackend<P> {
    fn new() -> Self {
        Self {
            tx: Mutex::new(None),
            _p: std::marker::PhantomData,
        }
    }

    fn send(&self, cmd: Cmd) {
        let mut slot = lock(&self.tx);
        if slot.is_none() {
            let (tx, rx) = channel::<Cmd>();
            let spawned = std::thread::Builder::new()
                .name("power-activity".into())
                .spawn(move || {
                    let mut platform = P::new();
                    for cmd in rx {
                        match cmd {
                            Cmd::Engage(reason) => platform.engage(&reason),
                            Cmd::Release => platform.release(),
                        }
                    }
                    // The sender is gone: leave nothing held.
                    platform.release();
                });
            if spawned.is_err() {
                // Best effort: without the thread nothing is requested.
                return;
            }
            *slot = Some(tx);
        }
        if let Some(tx) = slot.as_ref() {
            let _ = tx.send(cmd);
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
impl<P: Platform + 'static> Backend for ThreadBackend<P> {
    fn engage(&self, reason: &str) {
        self.send(Cmd::Engage(reason.to_owned()));
    }
    fn release(&self) {
        self.send(Cmd::Release);
    }
}

#[cfg(windows)]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(ThreadBackend::<win::Windows>::new())
}

#[cfg(target_os = "macos")]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(ThreadBackend::<mac::Mac>::new())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(NoBackend)
}

/// Linux and the rest: nothing is requested.
#[cfg(not(any(windows, target_os = "macos")))]
struct NoBackend;

#[cfg(not(any(windows, target_os = "macos")))]
impl Backend for NoBackend {
    fn engage(&self, _reason: &str) {}
    fn release(&self) {}
    fn effective(&self) -> bool {
        false
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::Power::{
        SetThreadExecutionState, ES_CONTINUOUS, ES_SYSTEM_REQUIRED,
    };

    /// `ES_SYSTEM_REQUIRED` keeps the system from idling into sleep; it does
    /// not keep the display on (that would be `ES_DISPLAY_REQUIRED`).
    pub(super) struct Windows;

    impl super::Platform for Windows {
        fn new() -> Self {
            Windows
        }
        fn engage(&mut self, _reason: &str) {
            // SAFETY: plain Win32 call with flag values; it only changes the
            // calling thread's execution state.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
            }
        }
        fn release(&mut self) {
            // SAFETY: as above; ES_CONTINUOUS alone clears the request.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::power::Platform;
        use windows_sys::Win32::System::Power::ES_DISPLAY_REQUIRED;

        /// The previous state is what SetThreadExecutionState returns, so
        /// re-applying the wanted state reads the current one without
        /// changing it.
        fn state_while(want: u32) -> u32 {
            // SAFETY: as above.
            unsafe { SetThreadExecutionState(ES_CONTINUOUS | want) }
        }

        #[test]
        fn system_required_is_set_and_cleared_without_the_display() {
            let mut p = Windows::new();
            p.engage("test");
            let held = state_while(ES_SYSTEM_REQUIRED);
            assert_ne!(held & ES_SYSTEM_REQUIRED, 0, "state {held:#x}");
            assert_eq!(held & ES_DISPLAY_REQUIRED, 0, "state {held:#x}");
            p.release();
            let after = state_while(0);
            assert_eq!(after & ES_SYSTEM_REQUIRED, 0, "state {after:#x}");
            let end = state_while(0);
            assert_eq!(end & ES_SYSTEM_REQUIRED, 0, "state {end:#x}");
        }
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use objc2::{rc::Retained, runtime::ProtocolObject};
    use objc2_foundation::{NSActivityOptions, NSObjectProtocol, NSProcessInfo, NSString};

    /// An open `NSProcessInfo` activity.
    pub(super) struct Mac {
        token: Option<Retained<ProtocolObject<dyn NSObjectProtocol>>>,
    }

    impl super::Platform for Mac {
        fn new() -> Self {
            Mac { token: None }
        }
        fn engage(&mut self, reason: &str) {
            if self.token.is_some() {
                return;
            }
            let options =
                NSActivityOptions::UserInitiated | NSActivityOptions::IdleSystemSleepDisabled;
            let reason = NSString::from_str(reason);
            self.token = Some(
                NSProcessInfo::processInfo().beginActivityWithOptions_reason(options, &reason),
            );
        }
        fn release(&mut self) {
            if let Some(token) = self.token.take() {
                // SAFETY: `token` came from beginActivity on this process and
                // is ended exactly once (it was just taken out).
                unsafe { NSProcessInfo::processInfo().endActivity(&token) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Fake {
        engaged: AtomicUsize,
        released: AtomicUsize,
        effective: bool,
    }

    struct FakeBackend(Arc<Fake>);

    impl Backend for FakeBackend {
        fn engage(&self, _reason: &str) {
            self.0.engaged.fetch_add(1, Ordering::SeqCst);
        }
        fn release(&self) {
            self.0.released.fetch_add(1, Ordering::SeqCst);
        }
        fn effective(&self) -> bool {
            self.0.effective
        }
    }

    fn holder(effective: bool) -> (Arc<Holder>, Arc<Fake>) {
        let fake = Arc::new(Fake {
            effective,
            ..Default::default()
        });
        (Holder::new(Box::new(FakeBackend(fake.clone()))), fake)
    }

    fn counts(f: &Fake) -> (usize, usize) {
        (
            f.engaged.load(Ordering::SeqCst),
            f.released.load(Ordering::SeqCst),
        )
    }

    #[test]
    fn engages_once_for_overlapping_holds_and_releases_with_the_last() {
        let (h, f) = holder(true);
        assert!(!h.is_active());
        let a = h.acquire("a");
        let b = h.acquire("b");
        assert_eq!(counts(&f), (1, 0));
        assert_eq!(h.holds(), 2);
        assert!(h.is_active());
        drop(a);
        assert_eq!(counts(&f), (1, 0));
        assert!(h.is_active());
        drop(b);
        assert_eq!(counts(&f), (1, 1));
        assert!(!h.is_active());
    }

    #[test]
    fn a_new_hold_after_idle_engages_again() {
        let (h, f) = holder(true);
        drop(h.acquire("one"));
        drop(h.acquire("two"));
        assert_eq!(counts(&f), (2, 2));
    }

    #[test]
    fn a_panic_while_holding_still_releases() {
        let (h, f) = holder(true);
        let h2 = h.clone();
        let r = std::thread::spawn(move || {
            let _g = h2.acquire("panics");
            panic!("task failed");
        })
        .join();
        assert!(r.is_err());
        assert_eq!(h.holds(), 0);
        assert_eq!(counts(&f), (1, 1));
    }

    #[test]
    fn a_backend_that_does_nothing_is_not_reported_as_held() {
        let (h, _f) = holder(false);
        let _g = h.acquire("x");
        assert_eq!(h.holds(), 1);
        assert!(!h.is_active());
    }

    #[test]
    fn many_threads_leave_the_count_balanced() {
        let (h, f) = holder(true);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let h = h.clone();
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        let _g = h.acquire("t");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(h.holds(), 0);
        let (e, r) = counts(&f);
        assert_eq!(e, r);
        assert!(e >= 1);
    }

    #[test]
    fn the_process_wide_guard_round_trips() {
        // Other tests in this binary may also hold it, so only compare against
        // our own hold.
        let g = ActivityGuard::acquire("test");
        #[cfg(any(windows, target_os = "macos"))]
        assert!(is_held());
        drop(g);
    }
}
