//! Asks the running daemon whether anything is going on that an update must
//! not interrupt: a transfer, a file push, or chat messages still being
//! delivered. Uses the daemon's existing control interface; no daemon running
//! means idle.

use std::path::PathBuf;
use std::time::Duration;

use super::apply::{Activity, Busy};
use crate::chat::{ChatRequest, ChatResponse};
use crate::push::{PushRequest, PushResponse};
use crate::transfer::TransferState;
use crate::{daemon_request, ControlRequest, ControlResponse};

/// How long one question to the daemon may take.
const ASK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonActivity {
    pub data_dir: PathBuf,
}

enum Ask {
    NoDaemon,
    Reply(ControlResponse),
    Unclear(String),
}

fn is_no_daemon(e: &anyhow::Error) -> bool {
    use std::io::ErrorKind as K;
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                K::NotFound
                    | K::ConnectionRefused
                    | K::ConnectionReset
                    | K::ConnectionAborted
                    | K::NotConnected
            )
        })
    })
}

impl DaemonActivity {
    fn ask(&self, req: ControlRequest) -> Ask {
        let dir = self.data_dir.clone();
        let res = std::thread::scope(|s| {
            s.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| anyhow::anyhow!("runtime: {e}"))?;
                rt.block_on(async {
                    tokio::time::timeout(ASK_TIMEOUT, daemon_request(&dir, req))
                        .await
                        .map_err(|_| anyhow::anyhow!("the daemon did not answer in time"))?
                })
            })
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("worker panicked")))
        });
        match res {
            Ok(r) => Ask::Reply(r),
            Err(e) if is_no_daemon(&e) => Ask::NoDaemon,
            Err(e) => Ask::Unclear(e.to_string()),
        }
    }
}

impl Activity for DaemonActivity {
    fn busy(&self) -> Busy {
        // Transfers (publish and receive by share ID).
        match self.ask(ControlRequest::TransferList) {
            Ask::NoDaemon => return Busy::Idle,
            Ask::Unclear(m) => return Busy::Unknown(m),
            Ask::Reply(ControlResponse::TransferList(list)) => {
                if list.iter().any(|t| t.state == TransferState::Running) {
                    return Busy::Active("a transfer is running".into());
                }
            }
            Ask::Reply(_) => return Busy::Unknown("unexpected answer".into()),
        }
        // Files pushed to contacts.
        match self.ask(ControlRequest::Push(PushRequest::Queue)) {
            Ask::NoDaemon => return Busy::Idle,
            Ask::Unclear(m) => return Busy::Unknown(m),
            Ask::Reply(ControlResponse::Push(PushResponse::Transfers(list))) => {
                if !list.is_empty() {
                    return Busy::Active("a file is being sent".into());
                }
            }
            // A daemon without the push feature has nothing queued.
            Ask::Reply(ControlResponse::Push(PushResponse::Error { .. })) => {}
            Ask::Reply(_) => return Busy::Unknown("unexpected answer".into()),
        }
        // Chat messages that are still waiting to be delivered.
        match self.ask(ControlRequest::Chat(ChatRequest::Status {})) {
            Ask::NoDaemon => Busy::Idle,
            Ask::Unclear(m) => Busy::Unknown(m),
            Ask::Reply(ControlResponse::Chat(ChatResponse::Status(s))) if s.outbox > 0 => {
                Busy::Active("chat messages are being delivered".into())
            }
            // Chat switched off, or an older daemon that does not know the request.
            Ask::Reply(_) => Busy::Idle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_daemon_running_the_install_is_idle() {
        let d = tempfile::tempdir().unwrap();
        let a = DaemonActivity {
            data_dir: d.path().to_path_buf(),
        };
        // No port file, no token: nobody to interrupt.
        assert_eq!(a.busy(), Busy::Idle);
    }
}
