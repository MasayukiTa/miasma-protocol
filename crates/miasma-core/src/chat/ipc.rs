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
    #[cfg(feature = "pqc")]
    Call(CallRequest),
}

/// Call control requests.
#[cfg(feature = "pqc")]
#[derive(Clone, Serialize, Deserialize)]
pub enum CallRequest {
    Dial {
        contact: String,
    },
    Accept {
        token: u64,
    },
    Reject {
        token: u64,
    },
    HangUp,
    SetMuted {
        muted: bool,
    },
    Status,
    Events {
        since: u64,
    },
    /// List the audio input and output devices the host reports, so a client
    /// can show them. The answer is [`CallResponse::AudioDevices`].
    ListAudioDevices,
    /// Choose the input and/or output device by name (or `None` for the host
    /// default). The runtime records the choice; a running call keeps the
    /// devices it already opened and the choice takes effect for the next call.
    /// The answer is [`CallResponse::AudioDevicesSelected`].
    SelectAudioDevices {
        #[serde(default)]
        input: Option<String>,
        #[serde(default)]
        output: Option<String>,
    },
    /// Begin sharing the screen as a second video-like stream. Honoured only
    /// while the call is connected and video was negotiated; never automatic.
    StartScreenShare,
    /// Stop sharing the screen. The camera stream, if any, is unaffected.
    StopScreenShare,
    /// Begin sending the local camera as the video stream. Honoured only while
    /// the call is connected and video was negotiated; never automatic. The
    /// camera device is opened lazily on this request, so nothing captures
    /// before the user presses the button. The screen stream, if any, is
    /// unaffected. Answered with [`CallResponse::Ok`], or
    /// [`CallResponse::Error`] with `not_ready` when video was not negotiated
    /// and `no_camera` when no camera could be opened.
    StartCamera,
    /// Stop sending the local camera and release the device. The screen stream,
    /// if any, is unaffected. Stopping is idempotent.
    StopCamera,
    /// Ask for the latest decoded remote video frame, but only when its frame
    /// counter is above `last_seen`. The caller passes the counter it last
    /// received (0 to always get the current frame); the handler answers with
    /// `CallResponse::RemoteFrame(None)` when nothing newer is available.
    RemoteFrame {
        last_seen: u64,
    },
}

/// The audio devices the host reports, carried in an IPC response. Plain names
/// only; it holds no device handle and no secret.
#[cfg(feature = "pqc")]
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AudioDeviceListDto {
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub default_input: Option<String>,
    #[serde(default)]
    pub default_output: Option<String>,
}

#[cfg(feature = "pqc")]
#[derive(Clone, Serialize, Deserialize)]
pub enum CallResponse {
    Unavailable,
    Ok,
    Status(CallStatusDto),
    Events {
        next: u64,
        gap: bool,
        notices: Vec<CallNoticeDto>,
    },
    Error(String),
    /// Answer to [`CallRequest::ListAudioDevices`]: the devices the host
    /// reports. On a platform without the audio backend the lists are empty.
    AudioDevices(AudioDeviceListDto),
    /// Answer to [`CallRequest::SelectAudioDevices`]: the choice the runtime
    /// now holds (echoed back so a client can confirm what was stored).
    AudioDevicesSelected {
        #[serde(default)]
        input: Option<String>,
        #[serde(default)]
        output: Option<String>,
    },
    /// The latest decoded remote video frame, or `None` when none is newer than
    /// the `last_seen` the request carried (or no frame has been decoded yet).
    RemoteFrame(Option<RemoteFrameData>),
}

#[cfg(feature = "pqc")]
#[derive(Clone, Serialize, Deserialize)]
pub struct CallStatusDto {
    /// One of `idle`, `calling`, `ringing`, or `connected`.
    pub state: String,
    pub pending_token: Option<u64>,
    pub signalling_connected: bool,
    #[serde(default)]
    pub negotiated_video: bool,
    #[serde(default)]
    pub safety_code: Option<String>,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub camera_in_use: bool,
    #[serde(default)]
    pub screen_sharing: bool,
    #[serde(default)]
    pub media_frames_sent: u64,
    #[serde(default)]
    pub media_frames_played: u64,
    #[serde(default)]
    pub media_video_frames_sent: u64,
    #[serde(default)]
    pub media_video_frames_played: u64,
}

#[cfg(feature = "pqc")]
#[derive(Clone, Serialize, Deserialize)]
pub struct CallNoticeDto {
    /// A fixed lowercase notice code, such as `incoming_ringing` or `call_ended`.
    pub code: String,
}

/// The most recent decoded remote video frame handed to the desktop UI: the
/// RGBA pixel bytes, the picture size, and a monotonically increasing frame
/// counter the UI uses to tell a new frame from one it has already drawn.
///
/// Privacy: the pixel bytes are call content. This type does NOT derive
/// `Debug`; the manual implementation below prints only the width, height and
/// byte length so the pixels never reach a log or an error line.
#[cfg(feature = "pqc")]
#[derive(Clone, Serialize, Deserialize)]
pub struct RemoteFrameData {
    pub width: u16,
    pub height: u16,
    /// Tightly packed RGBA bytes, `width * height * 4` long for a full frame.
    pub rgba: Vec<u8>,
    /// Increases by one each time the media task stores a newer frame.
    pub counter: u64,
}

#[cfg(feature = "pqc")]
impl std::fmt::Debug for RemoteFrameData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteFrameData")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes", &self.rgba.len())
            .finish()
    }
}

/// Where the media task stores the latest decoded remote frame and the IPC
/// handler reads it. `None` until the first frame is decoded. The counter in
/// the stored frame only ever increases, so a reader can poll with the counter
/// it last saw and receive a frame only when a newer one exists.
#[cfg(feature = "pqc")]
pub type RemoteFrameStore = std::sync::Arc<std::sync::Mutex<Option<RemoteFrameData>>>;

/// Store `frame` as the latest remote frame, giving it the next counter value
/// (one above whatever is currently held). Used by the media task each time it
/// decodes a remote picture.
#[cfg(feature = "pqc")]
pub fn store_remote_frame(store: &RemoteFrameStore, width: u16, height: u16, rgba: Vec<u8>) {
    let mut slot = store.lock().unwrap_or_else(|e| e.into_inner());
    let counter = slot.as_ref().map_or(0, |f| f.counter).saturating_add(1);
    *slot = Some(RemoteFrameData {
        width,
        height,
        rgba,
        counter,
    });
}

/// Read the latest remote frame, but only when its counter is strictly above
/// `last_seen`; otherwise `None`. Used by the IPC handler to answer
/// [`CallRequest::RemoteFrame`].
#[cfg(feature = "pqc")]
pub fn remote_frame_since(store: &RemoteFrameStore, last_seen: u64) -> Option<RemoteFrameData> {
    let slot = store.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_ref() {
        Some(frame) if frame.counter > last_seen => Some(frame.clone()),
        _ => None,
    }
}

// IPC values may contain untrusted strings or tokens, so never format their contents.
#[cfg(feature = "pqc")]
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(redacted)"))
            }
        }
    )+};
}

#[cfg(feature = "pqc")]
redacted_debug!(
    CallRequest,
    CallResponse,
    CallStatusDto,
    CallNoticeDto,
    AudioDeviceListDto,
);

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
    /// Hybrid post-quantum upgrade of this conversation: `pending`, `hybrid`,
    /// `classical` ("classical only": the contact does not offer it) or
    /// `failed`. `None` when `privacy.pqc_mode` is off and nothing was
    /// negotiated, and in builds without the feature. Older daemons omit it.
    #[serde(default)]
    pub pqc: Option<String>,
    /// Why the state is `classical` or `failed` (a stable word such as
    /// `peer_no_hybrid`, `peer_old_build`, `exchange_failed`).
    #[serde(default)]
    pub pqc_reason: Option<String>,
}

/// What this process did with the hybrid upgrade (numbers only, no peer
/// identifiers).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqcCounts {
    /// Sessions that completed the hybrid exchange.
    #[serde(default)]
    pub hybrid_sessions: u64,
    /// Sessions that stayed classical because the contact did not offer the
    /// hybrid suite (shown as "classical only").
    #[serde(default)]
    pub classical_only: u64,
    /// Of those, decided under `require`: the messages were refused.
    #[serde(default)]
    pub refused: u64,
    /// Exchanges that failed (altered messages, timeout).
    #[serde(default)]
    pub failed: u64,
    #[serde(default)]
    pub offers_sent: u64,
    #[serde(default)]
    pub offers_received: u64,
}

/// `privacy.pqc_mode` as the daemon runs it, and what came of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqcStatus {
    /// `off`, `prefer` or `require`: the mode this daemon started with (the
    /// value in force, i.e. the person's choice or the default).
    #[serde(default)]
    pub mode: String,
    /// `off`, `prefer` or `require`: the mode that applies when nobody set
    /// `privacy.pqc_mode`. `require` in this build. Lets a reader see whether
    /// `mode` is the default or a chosen value.
    #[serde(default)]
    pub default_mode: String,
    /// True when `mode` lowers the guarantee below `require`, so a classical
    /// session is allowed for a contact that does not offer the hybrid
    /// exchange. A reader can warn on this; it is false for the `require`
    /// default. Always false in a build without the `pqc` feature (the mode
    /// has no effect and nothing is offered).
    #[serde(default)]
    pub allows_classical_fallback: bool,
    /// False in a build without the `pqc` cargo feature: the mode has no
    /// effect there and every session stays classical.
    #[serde(default)]
    pub available: bool,
    #[serde(default)]
    pub counts: PqcCounts,
}

/// The hybrid-upgrade status for a daemon that runs in `mode`.
pub fn pqc_status_for(mode: crate::config::PqcMode) -> PqcStatus {
    #[cfg(feature = "pqc")]
    let counts = super::pq::counts();
    #[cfg(not(feature = "pqc"))]
    let counts = PqcCounts::default();
    let available = crate::config::PqcMode::available();
    PqcStatus {
        mode: mode.as_str().to_owned(),
        default_mode: crate::config::PqcMode::DEFAULT.as_str().to_owned(),
        // Without the feature the mode has no effect and no classical fallback
        // is offered, so this is reported as false regardless of the value.
        allows_classical_fallback: available && mode.allows_classical_fallback(),
        available,
        counts,
    }
}

/// The hybrid-upgrade status of the daemon that owns `data_dir`.
pub fn pqc_status(data_dir: &Path) -> PqcStatus {
    #[cfg(feature = "iroh")]
    let mode = super::service::service_for(data_dir)
        .map(|s| s.settings().pqc_mode)
        .unwrap_or_default();
    #[cfg(not(feature = "iroh"))]
    let mode = {
        let _ = data_dir;
        crate::config::PqcMode::Off
    };
    pqc_status_for(mode)
}

/// What to show about one conversation: the state word and its reason.
#[cfg(all(feature = "iroh", feature = "pqc"))]
fn pqc_state_of(
    core: &super::engine::ChatCore,
    peer: &[u8; 32],
) -> (Option<String>, Option<String>) {
    let v = core.pq_view(peer);
    if v.state == "off" {
        return (None, None);
    }
    (Some(v.state.to_owned()), v.reason.map(str::to_owned))
}

#[cfg(all(feature = "iroh", not(feature = "pqc")))]
fn pqc_state_of(
    _core: &super::engine::ChatCore,
    _peer: &[u8; 32],
) -> (Option<String>, Option<String>) {
    (None, None)
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
    /// The hybrid post-quantum upgrade: mode, availability and counters.
    #[serde(default)]
    pub pqc: PqcStatus,
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
    #[cfg(feature = "pqc")]
    Call(CallResponse),
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
    #[cfg(feature = "pqc")]
    if matches!(&req, ChatRequest::Call(_)) {
        #[cfg(feature = "iroh")]
        if let Some(svc) = super::service::service_for(data_dir) {
            return handle_with(&svc, req);
        }
        return ChatResponse::Call(CallResponse::Unavailable);
    }
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
        #[cfg(feature = "pqc")]
        ChatRequest::Call(request) => {
            let Some(runtime) = super::call::runtime::runtime_for_service(svc) else {
                return ChatResponse::Call(CallResponse::Unavailable);
            };
            let peer = match &request {
                CallRequest::Dial { contact } => resolve(contact).map(|(peer, _)| peer),
                _ => None,
            };
            ChatResponse::Call(runtime.handle(request, peer))
        }
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
                    let (pqc, pqc_reason) = pqc_state_of(core, &c.peer);
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
                        pqc,
                        pqc_reason,
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
            pqc: pqc_status_for(svc.settings().pqc_mode),
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

    #[cfg(feature = "pqc")]
    #[test]
    fn call_ipc_json_round_trips() {
        let requests = [
            CallRequest::Dial {
                contact: "alice".into(),
            },
            CallRequest::Accept { token: 1 },
            CallRequest::Reject { token: 2 },
            CallRequest::HangUp,
            CallRequest::SetMuted { muted: true },
            CallRequest::Status,
            CallRequest::Events { since: 3 },
            CallRequest::ListAudioDevices,
            CallRequest::SelectAudioDevices {
                input: None,
                output: None,
            },
            CallRequest::SelectAudioDevices {
                input: Some("Mic A".into()),
                output: Some("Speaker B".into()),
            },
            CallRequest::StartScreenShare,
            CallRequest::StopScreenShare,
            CallRequest::StartCamera,
            CallRequest::StopCamera,
            CallRequest::RemoteFrame { last_seen: 5 },
        ];
        for request in requests {
            let value = serde_json::to_value(ChatRequest::Call(request)).unwrap();
            let decoded: ChatRequest = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
        let responses = [
            CallResponse::Unavailable,
            CallResponse::Ok,
            CallResponse::Status(CallStatusDto {
                state: "ringing".into(),
                pending_token: Some(1),
                signalling_connected: true,
                negotiated_video: false,
                safety_code: None,
                muted: false,
                camera_in_use: false,
                screen_sharing: false,
                media_frames_sent: 0,
                media_frames_played: 0,
                media_video_frames_sent: 0,
                media_video_frames_played: 0,
            }),
            CallResponse::Events {
                next: 4,
                gap: true,
                notices: vec![CallNoticeDto {
                    code: "incoming_ringing".into(),
                }],
            },
            CallResponse::Error("unavailable".into()),
            CallResponse::AudioDevices(AudioDeviceListDto {
                inputs: vec!["Mic A".into(), "Mic B".into()],
                outputs: vec!["Speaker B".into()],
                default_input: Some("Mic A".into()),
                default_output: None,
            }),
            CallResponse::AudioDevices(AudioDeviceListDto::default()),
            CallResponse::AudioDevicesSelected {
                input: Some("Mic A".into()),
                output: None,
            },
            CallResponse::RemoteFrame(None),
            CallResponse::RemoteFrame(Some(RemoteFrameData {
                width: 2,
                height: 2,
                rgba: vec![1, 2, 3, 4],
                counter: 9,
            })),
        ];
        for response in responses {
            let value = serde_json::to_value(ChatResponse::Call(response)).unwrap();
            let decoded: ChatResponse = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
        // An older client that never sent the new keys still parses: a device
        // list DTO from such a client, with only `inputs`, reads with empty
        // defaults for the rest.
        let partial: AudioDeviceListDto = serde_json::from_str(r#"{"inputs":["Mic A"]}"#).unwrap();
        assert_eq!(partial.inputs, vec!["Mic A".to_owned()]);
        assert!(partial.outputs.is_empty());
        assert!(partial.default_input.is_none());
        assert!(partial.default_output.is_none());
        // A select request from an older client that omits a field reads it as
        // `None` (the host default) rather than failing.
        let select: ChatRequest =
            serde_json::from_str(r#"{"Call":{"SelectAudioDevices":{"input":"Mic A"}}}"#).unwrap();
        assert!(matches!(
            select,
            ChatRequest::Call(CallRequest::SelectAudioDevices {
                input: Some(_),
                output: None,
            })
        ));
        let old_status: CallStatusDto = serde_json::from_str(
            r#"{"state":"idle","pending_token":null,"signalling_connected":false}"#,
        )
        .unwrap();
        assert!(old_status.safety_code.is_none());
        assert!(!old_status.muted && !old_status.camera_in_use && !old_status.screen_sharing);
        assert_eq!(old_status.media_frames_sent, 0);
        assert_eq!(old_status.media_frames_played, 0);
        // New video counters also default when an old client omits them.
        assert_eq!(old_status.media_video_frames_sent, 0);
        assert_eq!(old_status.media_video_frames_played, 0);
        // The screen-sharing flag also defaults to false for an old client.
        assert!(!old_status.screen_sharing);
        let old: ChatRequest = serde_json::from_str(r#"{"Conversations":{}}"#).unwrap();
        assert!(matches!(old, ChatRequest::Conversations {}));
    }

    #[cfg(feature = "pqc")]
    #[tokio::test]
    async fn call_ipc_is_unavailable_without_a_controller() {
        let response = handle_ipc(Path::new(""), ChatRequest::Call(CallRequest::Status)).await;
        assert!(matches!(
            response,
            ChatResponse::Call(CallResponse::Unavailable)
        ));
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn remote_frame_store_replaces_and_counts_up() {
        let store: RemoteFrameStore = std::sync::Arc::new(std::sync::Mutex::new(None));
        // Nothing stored yet: no frame is newer than any `last_seen`.
        assert!(remote_frame_since(&store, 0).is_none());
        // First store gets counter 1 and is returned when `last_seen` is below it.
        store_remote_frame(&store, 4, 2, vec![1, 2, 3, 4]);
        let first = remote_frame_since(&store, 0).expect("a frame newer than 0");
        assert_eq!((first.width, first.height, first.counter), (4, 2, 1));
        assert_eq!(first.rgba, vec![1, 2, 3, 4]);
        // Reading again with `last_seen` equal to the current counter yields
        // nothing: only a strictly newer frame is handed back.
        assert!(remote_frame_since(&store, 1).is_none());
        // A second store replaces the frame and advances the counter to 2.
        store_remote_frame(&store, 8, 8, vec![9, 9]);
        assert!(remote_frame_since(&store, 2).is_none());
        let second = remote_frame_since(&store, 1).expect("a frame newer than 1");
        assert_eq!((second.width, second.height, second.counter), (8, 8, 2));
        assert_eq!(second.rgba, vec![9, 9]);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn remote_frame_debug_hides_pixels() {
        // The pixel bytes are call content: the manual Debug prints the size
        // and the byte count, never the pixels themselves.
        let frame = RemoteFrameData {
            width: 3,
            height: 2,
            rgba: vec![0xAB, 0xCD, 0xEF, 0x12, 0x34],
            counter: 7,
        };
        let shown = format!("{frame:?}");
        assert!(shown.contains("width"), "{shown}");
        assert!(shown.contains("height"), "{shown}");
        assert!(shown.contains("bytes"), "{shown}");
        // The byte length is shown, but no pixel value and no `rgba` field.
        assert!(shown.contains('5'), "{shown}");
        assert!(!shown.contains("rgba"), "{shown}");
        assert!(!shown.contains("171") && !shown.contains("AB"), "{shown}");
        assert!(!shown.contains("205") && !shown.contains("CD"), "{shown}");
    }

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

    #[test]
    fn pqc_status_reports_the_default_and_current_mode() {
        use crate::config::PqcMode;
        // `default_mode` is the mode in force when nobody set a value, and
        // equals `PqcMode::DEFAULT` whatever the current mode is.
        for mode in [PqcMode::Off, PqcMode::Prefer, PqcMode::Require] {
            let st = pqc_status_for(mode);
            assert_eq!(st.mode, mode.as_str());
            assert_eq!(st.default_mode, PqcMode::DEFAULT.as_str());
        }
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn pqc_status_flags_a_classical_fallback_only_below_require() {
        use crate::config::PqcMode;
        // With the feature present the mode has effect: `off` and `prefer`
        // lower the guarantee and allow a classical session, `require` does
        // not. This mirrors `PqcMode::allows_classical_fallback`.
        let require = pqc_status_for(PqcMode::Require);
        assert!(require.available);
        assert!(!require.allows_classical_fallback);
        for mode in [PqcMode::Off, PqcMode::Prefer] {
            let st = pqc_status_for(mode);
            assert!(st.available);
            assert!(
                st.allows_classical_fallback,
                "{} should allow a classical fallback",
                mode.as_str()
            );
        }
    }

    #[cfg(not(feature = "pqc"))]
    #[test]
    fn pqc_status_never_flags_a_fallback_without_the_feature() {
        use crate::config::PqcMode;
        // Without the feature the mode has no effect: nothing is offered and no
        // classical fallback is reported, whatever the value says.
        for mode in [PqcMode::Off, PqcMode::Prefer, PqcMode::Require] {
            let st = pqc_status_for(mode);
            assert!(!st.available);
            assert!(!st.allows_classical_fallback);
        }
    }

    #[test]
    fn pqc_status_round_trips_the_new_fields_as_json() {
        use crate::config::PqcMode;
        let st = pqc_status_for(PqcMode::Require);
        let s = serde_json::to_string(&st).unwrap();
        assert!(s.contains("default_mode"), "{s}");
        assert!(s.contains("allows_classical_fallback"), "{s}");
        let back: PqcStatus = serde_json::from_str(&s).unwrap();
        assert_eq!(back, st);
        // A JSON object from an older daemon, without the new keys, still reads
        // (the fields default to empty/false).
        let old = serde_json::json!({
            "mode": "require",
            "available": true,
            "counts": {}
        });
        let parsed: PqcStatus = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.default_mode, "");
        assert!(!parsed.allows_classical_fallback);
    }
}
