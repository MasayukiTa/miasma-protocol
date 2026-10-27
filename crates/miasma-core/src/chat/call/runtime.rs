use super::{
    controller::{CallController, CallError, CallNotice, CallPorts},
    state::State,
};
use crate::chat::{
    ipc::{CallNoticeDto, CallRequest, CallResponse, CallStatusDto},
    service::ChatService,
};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
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
}
impl Inner {
    fn collect(&mut self) {
        for notice in self.controller.take_notices().0 {
            self.notices.push(notice);
        }
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
        let (tx, mut rx) = mpsc::channel(32);
        svc.set_call_sink(tx);
        let inner = Arc::new(Mutex::new(Inner {
            controller: CallController::new(RuntimePorts(svc.clone())),
            notices: NoticeRing::default(),
        }));
        let wake = Arc::new(Notify::new());
        let stop_task = Arc::new(Notify::new());
        let task_inner = inner.clone();
        let task_svc = svc.clone();
        let task_wake = wake.clone();
        let task_stop = stop_task.clone();
        let mut stop = svc.call_shutdown();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            let mut sending = tokio::task::JoinSet::new();
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
                    _ = stop.changed() => break,
                    _ = task_stop.notified() => break,
                }
                let sends = {
                    let mut state = task_inner.lock().unwrap_or_else(|e| e.into_inner());
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
            CallRequest::Status => {
                let s = state.controller.status();
                CallResponse::Status(CallStatusDto {
                    state: state_word(s.state).into(),
                    pending_token: s.pending_token,
                    signalling_connected: s.signalling_connected,
                })
            }
            CallRequest::Events { since } => state.notices.events(since),
        };
        state.collect();
        drop(state);
        self.wake.notify_one();
        response
    }
}
fn dial_result(result: Result<(), CallError>) -> CallResponse {
    match result {
        Ok(()) => CallResponse::Ok,
        Err(CallError::NotAllowed) => CallResponse::Error("not_allowed".into()),
        Err(CallError::Busy) => CallResponse::Error("busy".into()),
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
    use super::*;
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
}
