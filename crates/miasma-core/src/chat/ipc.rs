//! IPC surface of chat: one request and one response enum, carried by the
//! daemon's `ControlRequest::Chat` / `ControlResponse::Chat`.
//!
//! A client polls `Events` (with the number it last saw) to follow incoming
//! messages and delivery results, the way the push status is polled. A daemon
//! that predates chat does not know `ControlRequest::Chat`; clients treat the
//! failure of such a request as "not supported".

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatRequest {
    /// Queue a message for a registered contact.
    Send {
        contact: String,
        text: String,
    },
    /// Every conversation, newest first.
    Conversations {},
    /// A page of one conversation: at most `limit` messages (default 50) with
    /// `ord` below `before` (the newest when not given), oldest first.
    History {
        contact: String,
        before: Option<u64>,
        limit: Option<u32>,
    },
    /// Delete one message (`message_id`) or, when it is not given, the whole
    /// conversation, on this device only.
    DeleteLocal {
        contact: String,
        message_id: Option<String>,
    },
    Status {},
    /// Things that happened after event number `since`.
    Events {
        since: u64,
    },
    /// The conversation is on screen and the messages received from `contact`
    /// up to number `up_to_seq` have been seen: send a read receipt (if
    /// receipts are on for both the setting and this contact).
    MarkRead {
        contact: String,
        up_to_seq: u64,
    },
    /// Switch read receipts on or off for one contact.
    SetReadReceipts {
        contact: String,
        enabled: bool,
    },
    /// Group chat (create, add, remove, leave, send, history, list).
    Group(super::group::ipc::GroupRequest),
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageInfo {
    /// Position in the conversation; 0 while the message is still queued.
    pub ord: u64,
    pub id: String,
    pub outgoing: bool,
    pub seq: u64,
    pub text: String,
    /// `queued`, `sending`, `delivered`, `read`, `failed` or `received`.
    pub state: String,
    /// For `failed`: a stable reason; for `queued`: why the last attempt failed.
    pub reason: Option<String>,
    pub sent_ms: u64,
    pub at_ms: u64,
    /// For `queued` / `sending`: when the last delivery attempt started (ms
    /// since the epoch), 0 when none has been made yet. Older daemons do not
    /// send it.
    #[serde(default)]
    pub tried_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationInfo {
    pub endpoint_id: String,
    pub fingerprint: String,
    /// The contact's label, or `None` when the contact has been removed.
    pub label: Option<String>,
    pub contact_id: Option<String>,
    pub messages: u64,
    pub last_ms: u64,
    /// Messages still waiting to be delivered.
    pub pending: u32,
    /// Read receipts are in effect for this contact (the global setting and
    /// the contact's own switch are both on).
    #[serde(default = "default_true")]
    pub read_receipts: bool,
    /// Why the oldest waiting message did not get through on its last attempt
    /// (a stable word such as `no_route` or `peer_no_chat`); `None` when
    /// nothing waits or no attempt has been made. Older daemons omit it.
    #[serde(default)]
    pub pending_reason: Option<String>,
    /// When that attempt started (ms since the epoch), 0 if none.
    #[serde(default)]
    pub pending_tried_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub history_saved: bool,
    pub conversations: u32,
    pub outbox: u32,
    pub outbox_max: u32,
    pub max_message_bytes: u32,
    /// The global read-receipt setting (`chat.read_receipts`).
    #[serde(default = "default_true")]
    pub read_receipts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    pub seq: u64,
    pub endpoint_id: String,
    pub label: Option<String>,
    /// `received`, `delivered`, `read` or `failed`. For `read`, `message.seq`
    /// is the number the contact has read up to.
    pub kind: String,
    pub message: MessageInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatResponse {
    Queued {
        id: String,
    },
    Conversations(Vec<ConversationInfo>),
    History {
        endpoint_id: String,
        label: Option<String>,
        messages: Vec<MessageInfo>,
    },
    Deleted {
        count: u32,
    },
    /// Answer to `MarkRead`: `sent` is true when a receipt was queued;
    /// `disabled` is true when receipts are off (so none will ever be);
    /// `wait` is true when it was too soon after the last one and the caller
    /// should ask again later.
    ReadMarked {
        sent: bool,
        disabled: bool,
        #[serde(default)]
        wait: bool,
    },
    /// Answer to `SetReadReceipts`.
    ReceiptsSet {
        enabled: bool,
    },
    Status(StatusInfo),
    Events {
        /// The number to pass as `since` next time.
        next: u64,
        events: Vec<EventInfo>,
    },
    /// Answer to [`ChatRequest::Group`].
    Group(super::group::ipc::GroupResponse),
    /// `kind` is stable (`unavailable`, `unknown_contact`, `send_disabled`,
    /// `empty`, `too_big`, `outbox_full`, `bad_message_id`, `internal`);
    /// `message` is for people.
    Error {
        kind: String,
        message: String,
    },
}

#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
fn err(kind: &str, message: impl Into<String>) -> ChatResponse {
    ChatResponse::Error {
        kind: kind.to_owned(),
        message: message.into(),
    }
}

/// Handle one chat request for the daemon that owns `data_dir`.
pub async fn handle_ipc(data_dir: &Path, req: ChatRequest) -> ChatResponse {
    #[cfg(feature = "iroh")]
    {
        let Some(svc) = super::service::service_for(data_dir) else {
            return err(
                "unavailable",
                "chat is not running: it needs the iroh transport and chat.enabled",
            );
        };
        handle_with(&svc, req)
    }
    #[cfg(not(feature = "iroh"))]
    {
        let _ = (data_dir, req);
        err(
            "unavailable",
            "this build has no iroh transport, so no chat",
        )
    }
}

#[cfg(feature = "iroh")]
fn info_of(m: &super::store::StoredMessage) -> MessageInfo {
    MessageInfo {
        ord: m.ord,
        id: hex::encode(m.id),
        outgoing: m.outgoing,
        seq: m.seq,
        text: m.text.clone(),
        state: m.state.as_str().to_owned(),
        reason: m.reason.clone(),
        sent_ms: m.sent_ms,
        at_ms: m.at_ms,
        tried_ms: m.tried_ms,
    }
}

/// The request handler proper, on a running service (tests call it directly).
#[cfg(feature = "iroh")]
pub fn handle_with(
    svc: &std::sync::Arc<super::service::ChatService>,
    req: ChatRequest,
) -> ChatResponse {
    use crate::push::{contact::fingerprint, store::Contact};

    // A contact by label, ID or endpoint ID; a removed contact's conversation
    // is still reachable by its endpoint ID.
    let resolve = |sel: &str| -> Option<([u8; 32], Option<Contact>)> {
        if let Some(c) = svc.contacts().find(sel) {
            return c.endpoint_bytes().map(|b| (b, Some(c)));
        }
        let raw = hex::decode(sel.trim()).ok()?;
        let id: [u8; 32] = raw.try_into().ok()?;
        Some((id, svc.contacts().by_endpoint(&id)))
    };
    let unknown = |sel: &str| err("unknown_contact", format!("no contact \"{sel}\""));
    let core = svc.core();

    match req {
        ChatRequest::Group(g) => match svc.groups() {
            Some(gs) => ChatResponse::Group(super::group::ipc::handle_with(gs, g)),
            None => err("unavailable", "group chat is not running"),
        },
        ChatRequest::Send { contact, text } => {
            let Some(c) = svc.contacts().find(&contact) else {
                return unknown(&contact);
            };
            if !c.allow_send {
                return err(
                    "send_disabled",
                    format!("sending to \"{}\" is switched off", c.label),
                );
            }
            match svc.send(&c, &text) {
                Ok(id) => ChatResponse::Queued {
                    id: hex::encode(id),
                },
                Err(super::engine::EnqueueError::Empty) => err("empty", "the message is empty"),
                Err(super::engine::EnqueueError::TooBig) => err(
                    "too_big",
                    format!("a message can hold at most {} bytes", core.max_text()),
                ),
                Err(super::engine::EnqueueError::OutboxFull) => err(
                    "outbox_full",
                    "too many messages are waiting to be delivered",
                ),
                Err(super::engine::EnqueueError::Storage(e)) => err("internal", e),
            }
        }
        ChatRequest::Conversations {} => {
            let mut list: Vec<ConversationInfo> = core
                .store
                .conversations()
                .into_iter()
                // Someone known only from a shared group is not a conversation.
                .filter(|c| c.count > 0 || svc.contacts().by_endpoint(&c.peer).is_some())
                .map(|c| {
                    let contact = svc.contacts().by_endpoint(&c.peer);
                    let waiting = core.outbox.first_for(&c.peer);
                    ConversationInfo {
                        pending_reason: waiting.as_ref().and_then(|e| e.last_error.clone()),
                        pending_tried_ms: waiting.as_ref().map_or(0, |e| e.last_try_ms),
                        endpoint_id: hex::encode(c.peer),
                        fingerprint: fingerprint(&c.peer),
                        label: contact.as_ref().map(|x| x.label.clone()),
                        contact_id: contact.map(|x| x.id),
                        messages: c.count,
                        last_ms: c.last_ms,
                        pending: core.outbox.count_for(&c.peer) as u32,
                        read_receipts: core.receipts_enabled(&c.peer),
                    }
                })
                .collect();
            list.sort_by(|a, b| b.last_ms.cmp(&a.last_ms));
            ChatResponse::Conversations(list)
        }
        ChatRequest::History {
            contact,
            before,
            limit,
        } => {
            let Some((peer, c)) = resolve(&contact) else {
                return unknown(&contact);
            };
            let msgs = core.history(&peer, before, limit.unwrap_or(50) as usize);
            ChatResponse::History {
                endpoint_id: hex::encode(peer),
                label: c.map(|x| x.label),
                messages: msgs.iter().map(info_of).collect(),
            }
        }
        ChatRequest::DeleteLocal {
            contact,
            message_id,
        } => {
            let Some((peer, _)) = resolve(&contact) else {
                return unknown(&contact);
            };
            match message_id {
                Some(mid) => {
                    let Some(id) = hex::decode(mid.trim())
                        .ok()
                        .and_then(|b| <[u8; 16]>::try_from(b).ok())
                    else {
                        return err("bad_message_id", "that is not a message ID");
                    };
                    match core.delete_message(&peer, &id) {
                        Ok(found) => ChatResponse::Deleted {
                            count: u32::from(found),
                        },
                        Err(e) => err("internal", e.to_string()),
                    }
                }
                None => {
                    let n = core.history(&peer, None, 1).len() as u32;
                    match core.delete_conversation(&peer) {
                        Ok(()) => ChatResponse::Deleted { count: n },
                        Err(e) => err("internal", e.to_string()),
                    }
                }
            }
        }
        ChatRequest::Status {} => ChatResponse::Status(StatusInfo {
            history_saved: core.store.settings().history_save,
            conversations: core.store.conversations().len() as u32,
            outbox: core.outbox.text_len() as u32,
            outbox_max: core.store.settings().outbox_max as u32,
            max_message_bytes: core.max_text() as u32,
            read_receipts: core.receipts_global(),
        }),
        ChatRequest::MarkRead { contact, up_to_seq } => {
            let Some(c) = svc.contacts().find(&contact) else {
                return unknown(&contact);
            };
            match svc.mark_read(&c, up_to_seq) {
                Ok(super::engine::MarkOutcome::Queued) => ChatResponse::ReadMarked {
                    sent: true,
                    disabled: false,
                    wait: false,
                },
                Ok(super::engine::MarkOutcome::Nothing) => ChatResponse::ReadMarked {
                    sent: false,
                    disabled: false,
                    wait: false,
                },
                Ok(super::engine::MarkOutcome::TooSoon) => ChatResponse::ReadMarked {
                    sent: false,
                    disabled: false,
                    wait: true,
                },
                Ok(super::engine::MarkOutcome::Disabled) => ChatResponse::ReadMarked {
                    sent: false,
                    disabled: true,
                    wait: false,
                },
                Err(e) => err("internal", e.to_string()),
            }
        }
        ChatRequest::SetReadReceipts { contact, enabled } => {
            let Some((peer, _)) = resolve(&contact) else {
                return unknown(&contact);
            };
            match core.set_receipts(&peer, enabled) {
                Ok(()) => ChatResponse::ReceiptsSet { enabled },
                Err(e) => err("internal", e.to_string()),
            }
        }
        ChatRequest::Events { since } => {
            let (next, events) = core.events_since(since);
            ChatResponse::Events {
                next,
                events: events
                    .into_iter()
                    .map(|e| EventInfo {
                        seq: e.seq,
                        endpoint_id: hex::encode(e.peer),
                        label: svc.contacts().by_endpoint(&e.peer).map(|c| c.label),
                        kind: match e.kind {
                            super::engine::EventKind::Received => "received",
                            super::engine::EventKind::Delivered => "delivered",
                            super::engine::EventKind::Read => "read",
                            super::engine::EventKind::Failed => "failed",
                        }
                        .to_owned(),
                        message: info_of(&e.message),
                    })
                    .collect(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_responses_round_trip_as_json() {
        let r = ChatRequest::History {
            contact: "alice".into(),
            before: Some(7),
            limit: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ChatRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back,
            ChatRequest::History {
                before: Some(7),
                ..
            }
        ));
        let e = serde_json::to_string(&ChatRequest::Conversations {}).unwrap();
        assert!(serde_json::from_str::<ChatRequest>(&e).is_ok());
        let resp = ChatResponse::Error {
            kind: "x".into(),
            message: "y".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(serde_json::from_str::<ChatResponse>(&s).is_ok());
    }
}
