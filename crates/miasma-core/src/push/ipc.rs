//! IPC surface of trusted-contact push: one request and one response enum,
//! carried by the daemon's `ControlRequest::Push` / `ControlResponse::Push`.
//!
//! The daemon reads files itself (`Send` carries a path, never bytes). A GUI
//! polls `Queue` (running/queued) and `Status` (one transfer) like it polls
//! `TransferStatus`; finished transfers stay visible for polling until the
//! 200 newest are exceeded and are kept in `History` (persisted).

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    contact::{extract_contact_code, ContactCode},
    state::{HistoryEntry, PushTransferInfo},
    store::{Contact, ContactError},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PushRequest {
    /// This node's contact code, fingerprint and endpoint ID.
    ContactCode,
    /// Register a contact. `code` may be the whole pasted message: the code
    /// is found inside it. `label` defaults to `contact-<fingerprint>`.
    ContactAdd {
        code: String,
        label: Option<String>,
    },
    ContactList,
    /// `contact` is a label, id, or endpoint ID.
    ContactRemove {
        contact: String,
    },
    /// Change a contact. `max_size` in bytes; `Some(0)` clears the limit.
    ContactUpdate {
        contact: String,
        label: Option<String>,
        allow_send: Option<bool>,
        allow_receive: Option<bool>,
        max_size: Option<u64>,
    },
    /// Queue a file (absolute path on the daemon's machine) for a contact.
    Send {
        contact: String,
        path: String,
    },
    /// Unfinished transfers (queued, preparing, connecting, sending, verifying).
    Queue,
    /// All known transfers (running and recently finished), or one by id.
    Status {
        id: Option<String>,
    },
    Cancel {
        id: String,
    },
    /// Persisted history, newest first.
    History {
        limit: Option<u32>,
    },
    /// The inbox folder path.
    Inbox,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub id: String,
    pub label: String,
    pub endpoint_id: String,
    pub fingerprint: String,
    pub added_at: u64,
    pub allow_send: bool,
    pub allow_receive: bool,
    pub max_file_size: Option<u64>,
    /// Where files from this contact land.
    pub inbox_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PushResponse {
    Code {
        code: String,
        fingerprint: String,
        endpoint_id: String,
    },
    Contact(ContactInfo),
    Contacts(Vec<ContactInfo>),
    Removed,
    Queued {
        id: String,
    },
    Transfers(Vec<PushTransferInfo>),
    Transfer(PushTransferInfo),
    Cancelled,
    History(Vec<HistoryEntry>),
    Inbox {
        dir: String,
    },
    /// `kind` is stable (`unavailable`, `bad_code`, `unknown_contact`,
    /// `already_exists`, `label_taken`, `this_is_me`, `bad_label`, `too_many`,
    /// `send_disabled`, `bad_file`, `queue_full`, `not_found`, `internal`);
    /// `message` is for people.
    Error {
        kind: String,
        message: String,
    },
}

fn err(kind: &str, message: impl Into<String>) -> PushResponse {
    PushResponse::Error {
        kind: kind.to_owned(),
        message: message.into(),
    }
}

pub fn contact_info(c: &Contact, inbox_dir: String) -> ContactInfo {
    ContactInfo {
        id: c.id.clone(),
        label: c.label.clone(),
        endpoint_id: c.endpoint_id.clone(),
        fingerprint: c.fingerprint(),
        added_at: c.added_at,
        allow_send: c.allow_send,
        allow_receive: c.allow_receive,
        max_file_size: c.max_file_size,
        inbox_dir,
    }
}

fn contact_err(e: ContactError) -> PushResponse {
    let kind = match &e {
        ContactError::AlreadyExists(_) => "already_exists",
        ContactError::LabelTaken(_) => "label_taken",
        ContactError::NotFound(_) => "unknown_contact",
        ContactError::ThisIsMe => "this_is_me",
        ContactError::BadLabel => "bad_label",
        ContactError::TooMany => "too_many",
        ContactError::Save(_) => "internal",
    };
    err(kind, e.to_string())
}

/// Handle one push request for the daemon that owns `data_dir`.
pub async fn handle_ipc(data_dir: &Path, req: PushRequest) -> PushResponse {
    #[cfg(feature = "iroh")]
    {
        let Some(svc) = super::service::service_for(data_dir) else {
            return err(
                "unavailable",
                "trusted-contact push is not running: it needs the iroh transport \
                 (transport.iroh_mode must not be \"off\")",
            );
        };
        handle_with(&svc, req)
    }
    #[cfg(not(feature = "iroh"))]
    {
        let _ = (data_dir, req);
        err(
            "unavailable",
            "this build has no iroh transport, so no push",
        )
    }
}

/// The request handler proper, on a running service (tests call it directly).
#[cfg(feature = "iroh")]
pub fn handle_with(
    svc: &std::sync::Arc<super::service::PushService>,
    req: PushRequest,
) -> PushResponse {
    use super::store::ContactUpdate;
    let info =
        |c: &Contact| contact_info(c, svc.contact_dir(&c.label).to_string_lossy().into_owned());
    match req {
        PushRequest::ContactCode => {
            let code = svc.my_code();
            PushResponse::Code {
                fingerprint: code.fingerprint(),
                endpoint_id: hex::encode(code.endpoint_id()),
                code: code.to_string(),
            }
        }
        PushRequest::ContactAdd { code, label } => {
            let text = extract_contact_code(&code)
                .or_else(|| ContactCode::parse(&code).ok().map(|c| c.to_string()));
            let Some(text) = text else {
                let why = ContactCode::parse(code.trim())
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no contact code found in the text".into());
                return err("bad_code", why);
            };
            let Ok(parsed) = ContactCode::parse(&text) else {
                return err("bad_code", "the contact code is not valid");
            };
            match svc.add_contact(&parsed, label.as_deref()) {
                Ok(c) => PushResponse::Contact(info(&c)),
                Err(e) => contact_err(e),
            }
        }
        PushRequest::ContactList => {
            PushResponse::Contacts(svc.contacts().list().iter().map(&info).collect())
        }
        PushRequest::ContactRemove { contact } => match svc.remove_contact(&contact) {
            Ok(_) => PushResponse::Removed,
            Err(e) => contact_err(e),
        },
        PushRequest::ContactUpdate {
            contact,
            label,
            allow_send,
            allow_receive,
            max_size,
        } => match svc.update_contact(
            &contact,
            &ContactUpdate {
                label,
                allow_send,
                allow_receive,
                max_file_size: max_size,
            },
        ) {
            Ok(c) => PushResponse::Contact(info(&c)),
            Err(e) => contact_err(e),
        },
        PushRequest::Send { contact, path } => match svc.queue_send(&contact, Path::new(&path)) {
            Ok(id) => PushResponse::Queued { id },
            Err(m) => {
                let (kind, msg) = m.split_once(": ").unwrap_or(("internal", m.as_str()));
                err(kind, msg)
            }
        },
        PushRequest::Queue => PushResponse::Transfers(svc.queue_snapshot()),
        PushRequest::Status { id } => match id {
            Some(id) => match svc.board().get(&id) {
                Some(t) => PushResponse::Transfer(t),
                None => err("not_found", format!("no transfer {id}")),
            },
            None => PushResponse::Transfers(svc.board().list()),
        },
        PushRequest::Cancel { id } => {
            if svc.board().cancel(&id) {
                PushResponse::Cancelled
            } else {
                err("not_found", format!("no running transfer {id}"))
            }
        }
        PushRequest::History { limit } => {
            PushResponse::History(svc.history().list(limit.unwrap_or(100) as usize))
        }
        PushRequest::Inbox => PushResponse::Inbox {
            dir: svc.inbox_dir().to_string_lossy().into_owned(),
        },
    }
}
