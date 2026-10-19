//! Quiesce gate for the wipe sequence.
//!
//! A wipe must stop work that can hold key-derived material or write
//! plaintext *before* the root key is zeroized. [`WipeGate`] is the shared
//! switch: operations register through [`WipeGate::enter`] (or run through
//! [`WipeGate::run_result`]), the wipe calls [`WipeGate::begin_wipe`] to refuse
//! new work and cancel running work, then waits with [`WipeGate::drained`]
//! until every registered operation has been dropped.
//!
//! Ordering used by the daemon: quiesce (this gate) -> zeroize the key vault
//! -> crypto-erase the on-disk key -> join remaining tasks -> exit. Quiescing
//! also empties the plaintext buffer pool, and the vault step repeats that
//! (see [`WipeGate::wipe_plaintext_pool`]); neither moves a step. The erase
//! step removes the key file; it does not and cannot promise that old storage
//! blocks are physically overwritten.

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::transfer::PlaintextPool;
use crate::MiasmaError;

/// Returned when new work is refused because a wipe has started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WipeInProgress;

impl std::fmt::Display for WipeInProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wipe in progress; operation refused or cancelled")
    }
}

impl std::error::Error for WipeInProgress {}

impl From<WipeInProgress> for MiasmaError {
    fn from(e: WipeInProgress) -> Self {
        MiasmaError::Storage(e.to_string())
    }
}

#[derive(Clone, Copy, Debug)]
struct GateState {
    wiping: bool,
    in_flight: usize,
}

/// Shared quiesce switch. Cheap to create; owned by the store.
pub struct WipeGate {
    state: watch::Sender<GateState>,
    /// Test hook: when set, [`stall_point`](WipeGate::stall_point) never
    /// returns on its own (only cancellation ends it).
    stall: AtomicBool,
    /// Test hook: how many callers are parked in `stall_point` right now.
    stalled: AtomicUsize,
    /// The pool of reusable plaintext buffers the wipe must empty. Idle
    /// buffers hold only zeros; wiping the pool frees them and stops buffers
    /// that are out right now from being kept. Buffers that are out belong to
    /// work this gate cancels, and are wiped when that work is dropped.
    plaintext_pool: Arc<PlaintextPool>,
}

/// Removes a file on drop unless it was kept. Used so that a cancelled or
/// failed write never leaves partial output behind.
struct PartialOutput<'a> {
    path: &'a Path,
    keep: bool,
}

impl Drop for PartialOutput<'_> {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

struct StallCount<'a>(&'a AtomicUsize);

impl Drop for StallCount<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for WipeGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Registration of one in-flight operation. Dropping it unregisters.
pub struct OperationGuard<'a> {
    gate: &'a WipeGate,
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        self.gate.state.send_modify(|s| {
            s.in_flight = s.in_flight.saturating_sub(1);
        });
    }
}

impl WipeGate {
    pub fn new() -> Self {
        Self::with_pool(PlaintextPool::shared().clone())
    }

    /// A gate that empties `pool` when the wipe runs (the daemon uses the
    /// process-wide pool; a test can pass its own).
    pub fn with_pool(pool: Arc<PlaintextPool>) -> Self {
        let (state, _rx) = watch::channel(GateState {
            wiping: false,
            in_flight: 0,
        });
        Self {
            state,
            stall: AtomicBool::new(false),
            stalled: AtomicUsize::new(0),
            plaintext_pool: pool,
        }
    }

    /// Free every idle plaintext buffer and stop outstanding ones from being
    /// kept. Part of the wipe sequence: called when the wipe begins (so work
    /// that is cancelled hands nothing back) and once more after the key vault
    /// has been zeroized. Idempotent.
    pub fn wipe_plaintext_pool(&self) -> usize {
        self.plaintext_pool.wipe()
    }

    /// Turn the test stall on or off. Off by default; no request can set it.
    #[doc(hidden)]
    pub fn set_stall_for_tests(&self, on: bool) {
        self.stall.store(on, Ordering::SeqCst);
    }

    /// How many operations are currently parked at a stall point.
    #[doc(hidden)]
    pub fn stalled_for_tests(&self) -> usize {
        self.stalled.load(Ordering::SeqCst)
    }

    /// A point where an operation can be held for a test. Returns at once
    /// unless the test stall is on, in which case it waits until the caller's
    /// future is dropped (by a wipe).
    pub async fn stall_point(&self) {
        if !self.stall.load(Ordering::SeqCst) {
            return;
        }
        self.stalled.fetch_add(1, Ordering::SeqCst);
        let _count = StallCount(&self.stalled);
        std::future::pending::<()>().await;
    }

    /// Write `data` to `path` as one gated step, for use inside
    /// [`run_result`](Self::run_result) (so a wipe that lands before the write
    /// drops this future and nothing is written). The file is created only
    /// while no wipe is running, and is removed again if a wipe began while it
    /// was being written or if the write fails part-way.
    ///
    /// Like the streaming `retrieve-to-file` route, an existing target is
    /// replaced. Only a file this call opened is ever removed: when the open
    /// itself fails, whatever is at `path` is left exactly as it was.
    pub async fn write_output(&self, path: &Path, data: &[u8]) -> Result<(), MiasmaError> {
        use std::io::Write;
        // The gap between "the data is in memory" and "the file exists".
        self.stall_point().await;
        if self.is_wiping() {
            return Err(WipeInProgress.into());
        }
        let cannot = |e: std::io::Error| {
            MiasmaError::Storage(format!("cannot write to {}: {e}", path.display()))
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(cannot)?;
        // From here on the file is ours: remove it unless everything succeeds.
        let mut partial = PartialOutput { path, keep: false };
        file.write_all(data)
            .and_then(|()| file.flush())
            .map_err(|e| {
                MiasmaError::Storage(format!("cannot write to {}: {e}", path.display()))
            })?;
        drop(file);
        // The write above does not yield, so a wipe that began meanwhile has
        // not cancelled us: check once more before reporting success.
        if self.is_wiping() {
            return Err(WipeInProgress.into());
        }
        partial.keep = true;
        Ok(())
    }

    /// `true` once [`begin_wipe`](Self::begin_wipe) has been called.
    pub fn is_wiping(&self) -> bool {
        self.state.borrow().wiping
    }

    /// Number of registered operations that have not finished.
    pub fn in_flight(&self) -> usize {
        self.state.borrow().in_flight
    }

    /// Register an operation. Fails once a wipe has begun. The check and the
    /// registration are one atomic step, so an operation can never slip in
    /// after the wipe observed an empty gate.
    pub fn enter(&self) -> Result<OperationGuard<'_>, WipeInProgress> {
        let mut admitted = false;
        self.state.send_if_modified(|s| {
            if s.wiping {
                false
            } else {
                s.in_flight += 1;
                admitted = true;
                true
            }
        });
        if admitted {
            Ok(OperationGuard { gate: self })
        } else {
            Err(WipeInProgress)
        }
    }

    /// Refuse new work and wake every operation waiting in
    /// [`cancelled`](Self::cancelled). Idempotent.
    pub fn begin_wipe(&self) {
        self.state.send_if_modified(|s| {
            if s.wiping {
                false
            } else {
                s.wiping = true;
                true
            }
        });
        // After the flag is set: a buffer handed back in the meantime is freed
        // by this call, and later ones are not kept (new generation).
        self.wipe_plaintext_pool();
    }

    /// Resolves once a wipe has begun (immediately if it already has).
    pub async fn cancelled(&self) {
        let mut rx = self.state.subscribe();
        loop {
            if rx.borrow_and_update().wiping {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Wait until no registered operation is left. Returns `false` if
    /// `timeout` elapsed first (the caller decides whether to proceed).
    pub async fn drained(&self, timeout: Duration) -> bool {
        let mut rx = self.state.subscribe();
        let wait = async {
            loop {
                if rx.borrow_and_update().in_flight == 0 {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.is_ok()
    }

    /// Run `fut` as a registered operation. If a wipe begins first, `fut` is
    /// dropped (so its locals, including `Zeroizing` buffers and file guards,
    /// are released) and a clean error is returned. The operation stays
    /// registered until `fut` has been dropped.
    pub async fn run_result<T>(
        &self,
        fut: impl Future<Output = Result<T, MiasmaError>>,
    ) -> Result<T, MiasmaError> {
        let _guard = self.enter()?;
        tokio::select! {
            biased;
            _ = self.cancelled() => Err(WipeInProgress.into()),
            r = fut => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct SetOnDrop(Arc<AtomicBool>);
    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn enter_is_refused_after_begin_wipe() {
        let gate = WipeGate::new();
        let g = gate.enter().unwrap();
        assert_eq!(gate.in_flight(), 1);
        gate.begin_wipe();
        assert!(gate.is_wiping());
        assert!(gate.enter().is_err());
        drop(g);
        assert_eq!(gate.in_flight(), 0);
        gate.begin_wipe(); // idempotent
    }

    #[tokio::test]
    async fn run_result_cancels_and_drops_the_future_before_drain_completes() {
        let gate = Arc::new(WipeGate::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(tokio::sync::Notify::new());

        let task = {
            let gate = gate.clone();
            let dropped = dropped.clone();
            let started = started.clone();
            tokio::spawn(async move {
                gate.run_result(async move {
                    let _held = SetOnDrop(dropped);
                    started.notify_one();
                    std::future::pending::<()>().await;
                    Ok(())
                })
                .await
            })
        };
        started.notified().await;
        assert_eq!(gate.in_flight(), 1);

        gate.begin_wipe();
        assert!(gate.drained(Duration::from_secs(5)).await);
        assert!(
            dropped.load(Ordering::SeqCst),
            "cancelled work must have been dropped once the gate is drained"
        );
        let res = task.await.unwrap();
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("wipe in progress"));
    }

    #[tokio::test]
    async fn run_result_refuses_new_work_after_wipe_began() {
        let gate = WipeGate::new();
        gate.begin_wipe();
        let ran = AtomicBool::new(false);
        let res: Result<(), MiasmaError> = gate
            .run_result(async {
                ran.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert!(res.is_err());
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn write_output_writes_when_no_wipe_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.bin");
        let gate = WipeGate::new();
        gate.run_result(gate.write_output(&out, b"payload"))
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn write_output_is_cancelled_in_the_gap_before_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.bin");
        let gate = Arc::new(WipeGate::new());
        gate.set_stall_for_tests(true);

        let task = {
            let (gate, out) = (gate.clone(), out.clone());
            tokio::spawn(async move {
                gate.run_result(gate.write_output(&out, b"secret plaintext"))
                    .await
            })
        };
        while gate.stalled_for_tests() == 0 {
            tokio::task::yield_now().await;
        }
        assert!(!out.exists(), "nothing is written while parked in the gap");

        gate.begin_wipe();
        assert!(gate.drained(Duration::from_secs(5)).await);
        assert!(task.await.unwrap().is_err());
        assert!(!out.exists(), "a wipe in the gap must leave no output");
        assert_eq!(gate.stalled_for_tests(), 0);
    }

    #[tokio::test]
    async fn write_output_refuses_once_a_wipe_began_and_removes_a_late_write() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.bin");
        let gate = WipeGate::new();
        gate.begin_wipe();
        assert!(gate.write_output(&out, b"x").await.is_err());
        assert!(!out.exists());
    }

    #[tokio::test]
    async fn write_output_reports_a_failed_write() {
        let dir = tempfile::tempdir().unwrap();
        // A directory cannot be written as a file: the write fails with a
        // clear error and the directory is left alone.
        let out = dir.path().join("sub");
        std::fs::create_dir(&out).unwrap();
        let gate = WipeGate::new();
        let err = gate.write_output(&out, b"x").await.unwrap_err();
        assert!(err.to_string().contains("cannot write to"));
        assert!(out.is_dir());
    }

    #[test]
    fn begin_wipe_empties_the_plaintext_pool() {
        let pool = PlaintextPool::new(1 << 20);
        let (a, b) = (pool.take(4096), pool.take(4096));
        drop(a);
        drop(b);
        assert_eq!(pool.snapshot().idle_buffers, 2);
        let gate = WipeGate::with_pool(pool.clone());
        let out = pool.take(1024); // still out when the wipe begins
        gate.begin_wipe();
        assert_eq!(pool.snapshot().idle_buffers, 0);
        drop(out); // returned after the wipe began: freed, not kept
        let s = pool.snapshot();
        assert_eq!((s.idle_buffers, s.idle_bytes), (0, 0));
        assert_eq!(pool.stats().snapshot().wipe_failures, 0);
        gate.begin_wipe(); // idempotent
    }

    #[tokio::test]
    async fn drained_times_out_while_an_operation_is_held() {
        let gate = WipeGate::new();
        let _g = gate.enter().unwrap();
        gate.begin_wipe();
        assert!(!gate.drained(Duration::from_millis(50)).await);
    }
}
