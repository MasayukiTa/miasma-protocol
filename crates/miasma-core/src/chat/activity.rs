//! A small shared counter of chat sends that are in flight right now.
//!
//! Private chat and group chat deliver on their own connections, but share the
//! uplink with the trusted-contact push. The push send loop reads this counter
//! to decide whether to pace itself: while a chat send is in flight the counter
//! is at least one, and the push loop slows down so the chat acknowledgement is
//! not delayed past its deadline.
//!
//! A caller takes a [`SendGuard`] around the part of a send that holds the
//! uplink and drops it when that part ends. The counter is raised when the
//! guard is taken and lowered when it is dropped, including while unwinding
//! from a panic or returning early on an error, so it never stays raised after
//! the work has ended.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Node-wide count of chat sends in flight, shared by private chat, group chat
/// and the push send loop. Cheap to clone (it is an [`Arc`] inside).
#[derive(Clone, Default)]
pub struct ChatActivity {
    inflight: Arc<AtomicUsize>,
}

impl ChatActivity {
    /// A fresh counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many chat sends are in flight right now.
    pub fn active(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    /// Whether at least one chat send is in flight right now.
    pub fn is_active(&self) -> bool {
        self.active() > 0
    }

    /// Mark one chat send as started. The returned guard lowers the count when
    /// it is dropped; keep it for the duration of the send.
    #[must_use = "dropping the guard at once ends the activity immediately"]
    pub fn enter(&self) -> SendGuard {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        SendGuard {
            inflight: self.inflight.clone(),
        }
    }
}

/// Raises the in-flight count while it lives and lowers it on drop. Dropping is
/// guaranteed on every path out of the guarded scope, so an early return or a
/// panic still lowers the count.
pub struct SendGuard {
    inflight: Arc<AtomicUsize>,
}

impl Drop for SendGuard {
    fn drop(&mut self) {
        // `fetch_sub` wraps on overflow; the count is only ever raised by a
        // live guard, so it cannot be lowered below zero here.
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        let a = ChatActivity::new();
        assert_eq!(a.active(), 0);
        assert!(!a.is_active());
    }

    #[test]
    fn guard_raises_then_lowers_on_drop() {
        let a = ChatActivity::new();
        {
            let _g = a.enter();
            assert_eq!(a.active(), 1);
            assert!(a.is_active());
        }
        assert_eq!(a.active(), 0);
        assert!(!a.is_active());
    }

    #[test]
    fn guards_nest_and_each_lowers_once() {
        let a = ChatActivity::new();
        let g1 = a.enter();
        let g2 = a.enter();
        assert_eq!(a.active(), 2);
        drop(g1);
        assert_eq!(a.active(), 1);
        drop(g2);
        assert_eq!(a.active(), 0);
    }

    #[test]
    fn clones_share_one_count() {
        let a = ChatActivity::new();
        let b = a.clone();
        let _g = a.enter();
        // The clone sees the same in-flight send.
        assert_eq!(b.active(), 1);
    }

    #[test]
    fn guard_lowers_when_dropped_on_an_error_path() {
        // A function that returns an error after taking the guard must still
        // lower the count: the guard is dropped as the scope unwinds to the
        // early `return`.
        fn send_that_fails(a: &ChatActivity) -> Result<(), &'static str> {
            let _g = a.enter();
            Err("connection_lost")?;
            Ok(())
        }
        let a = ChatActivity::new();
        assert!(send_that_fails(&a).is_err());
        assert_eq!(a.active(), 0);
    }

    #[test]
    fn guard_lowers_while_unwinding_from_a_panic() {
        let a = ChatActivity::new();
        let a2 = a.clone();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = a2.enter();
            assert_eq!(a2.active(), 1);
            panic!("send blew up");
        }));
        assert!(caught.is_err());
        assert_eq!(a.active(), 0);
    }
}
