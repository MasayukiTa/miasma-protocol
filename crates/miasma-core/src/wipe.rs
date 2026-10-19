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
//! -> crypto-erase the on-disk key -> join remaining tasks -> exit. The erase
//! step removes the key file; it does not and cannot promise that old storage
//! blocks are physically overwritten.

use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;

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
        let (state, _rx) = watch::channel(GateState {
            wiping: false,
            in_flight: 0,
        });
        Self { state }
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
    use std::sync::atomic::{AtomicBool, Ordering};
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
    async fn drained_times_out_while_an_operation_is_held() {
        let gate = WipeGate::new();
        let _g = gate.enter().unwrap();
        gate.begin_wipe();
        assert!(!gate.drained(Duration::from_millis(50)).await);
    }
}
