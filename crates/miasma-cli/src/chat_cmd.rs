//! `miasma chat ...`: one-to-one chat with registered contacts. Everything goes
//! through the running daemon (`ControlRequest::Chat`); the CLI never touches
//! the network or the message files itself.
//!
//! Messages follow the pattern of `push_cmd.rs` (one `match` per language in one
//! enum, language from `i18n::lang()`).

use std::{path::Path, time::Duration};

use anyhow::{bail, Result};
use clap::Subcommand;
use miasma_core::{
    chat::{
        ipc::{ConversationInfo, MessageInfo},
        ChatRequest, ChatResponse,
    },
    daemon_request, ControlRequest, ControlResponse,
};

use crate::i18n::{lang, Lang};

#[derive(Subcommand)]
pub enum ChatCmd {
    /// Send a message to a registered contact. If they are offline, the message waits and is delivered when they come online.
    Send {
        /// Label, ID or endpoint ID of the contact (see `miasma contact list`).
        contact: String,
        /// The message (several words are joined with spaces).
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Show the latest messages with a contact.
    History {
        contact: String,
        /// How many messages to show (1-200).
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// Keep running and print new messages as they arrive (Ctrl+C to stop).
        #[arg(long)]
        follow: bool,
        /// Show each message's ID (for `miasma chat delete`).
        #[arg(long)]
        ids: bool,
    },
    /// List your conversations.
    List,
    /// Delete messages on this device only (the other person keeps theirs).
    Delete {
        contact: String,
        /// ID of one message to delete (shown by `miasma chat history --ids`).
        message: Option<String>,
        /// Delete the whole conversation with this contact.
        #[arg(long)]
        all: bool,
    },
    /// Show or change read receipts for a contact. They are on by default; a message shows as "read" only when both sides have them on. With neither flag, shows the current state.
    Receipts {
        contact: String,
        /// Send and show read receipts with this contact.
        #[arg(long, overrides_with = "off")]
        on: bool,
        /// Stop sending read receipts to this contact and hide the ones that arrive.
        #[arg(long, overrides_with = "on")]
        off: bool,
    },
}

// ─── Messages ────────────────────────────────────────────────────────────────

enum M<'a> {
    DaemonDown,
    NotSupported,
    Queued(&'a str),
    HistoryNone(&'a str),
    ConversationsNone,
    ConversationRow(&'a ConversationInfo),
    Line(&'a MessageInfo),
    Deleted(u32),
    NeedAllOrId,
    Following,
    TemporaryHistory,
    ApiError(&'a str),
    Hint(&'a str),
    /// A contact's read receipts: label, in effect, global setting on.
    ReceiptsState(&'a str, bool, bool),
    ReceiptsSet(&'a str, bool),
    /// The contact has read our messages up to this number.
    ReadUpTo(u64),
}

impl M<'_> {
    fn t(&self) -> String {
        match lang() {
            Lang::En => self.en(),
            Lang::Ja => self.ja(),
        }
    }

    fn en(&self) -> String {
        match self {
            M::DaemonDown => "The Miasma daemon is not running. Start it first (`miasma daemon`, or open the app), then try again.".into(),
            M::NotSupported => "The running Miasma daemon is older than this command and does not support chat. Restart it after updating.".into(),
            M::Queued(label) => format!("Queued for \"{label}\". It is delivered as soon as they are online."),
            M::HistoryNone(label) => format!("No messages with \"{label}\" yet."),
            M::ConversationsNone => "No conversations yet. Register a contact (`miasma contact add <code>`), then `miasma chat send <contact> <text>`.".into(),
            M::ConversationRow(c) => format!(
                "{}  {} messages{}  last: {}",
                c.label.clone().unwrap_or_else(|| format!("(removed contact {})", c.fingerprint)),
                c.messages,
                if c.pending > 0 { format!(", {} waiting to be delivered", c.pending) } else { String::new() },
                if c.last_ms == 0 { "-".to_owned() } else { stamp(c.last_ms) },
            ),
            M::Line(m) => line(m, false),
            M::Deleted(n) => format!("Deleted {n} message(s) on this device."),
            M::NeedAllOrId => "Give a message ID, or --all to delete the whole conversation.".into(),
            M::Following => "Waiting for new messages (Ctrl+C to stop)...".into(),
            M::TemporaryHistory => "Note: the history is temporary here (chat.history_save is false): it is kept in memory only and is gone when the daemon stops. Messages are saved by default; run `miasma config --key chat.history_save --value auto` and restart the daemon to save them.".into(),
            M::ApiError(e) => format!("error: {e}"),
            M::ReceiptsState(label, on, global) => {
                if !global {
                    format!("Read receipts are off for everyone (chat.read_receipts is false), so none are sent or shown for \"{label}\".")
                } else if *on {
                    format!("Read receipts with \"{label}\" are on. A message shows as read when both sides have them on.")
                } else {
                    format!("Read receipts with \"{label}\" are off: none are sent and the ones that arrive are hidden.")
                }
            }
            M::ReceiptsSet(label, on) => {
                if *on {
                    format!("Read receipts with \"{label}\" are now on.")
                } else {
                    format!("Read receipts with \"{label}\" are now off.")
                }
            }
            M::ReadUpTo(n) => format!("(they have read your messages up to number {n})"),
            M::Hint(kind) => match *kind {
                "unknown_contact" => "No such contact. See `miasma contact list`.".into(),
                "send_disabled" => "Sending to this contact is switched off (`miasma contact set <contact> --allow-send`).".into(),
                "too_big" => "The message is too long (limit 4096 bytes).".into(),
                "empty" => "The message is empty.".into(),
                "outbox_full" => "Too many messages are waiting to be delivered. Try again when some have arrived.".into(),
                "bad_message_id" => "That is not a message ID.".into(),
                "unavailable" => "Chat is not running (it needs the iroh transport and chat.enabled).".into(),
                _ => String::new(),
            },
        }
    }

    fn ja(&self) -> String {
        match self {
            M::DaemonDown => "Miasmaのバックグラウンド機能(デーモン)が起動していません。先に起動(`miasma daemon` またはアプリを開く)してから、もう一度試してください。".into(),
            M::NotSupported => "起動中のMiasmaデーモンが古く、チャットに対応していません。更新してから再起動してください。".into(),
            M::Queued(label) => format!("「{label}」宛てのメッセージを送信待ちにしました。相手がオンラインになりしだい届きます。"),
            M::HistoryNone(label) => format!("「{label}」とのメッセージはまだありません。"),
            M::ConversationsNone => "会話はまだありません。連絡先を追加(`miasma contact add <連絡先コード>`)してから、`miasma chat send <連絡先> <メッセージ>` を実行してください。".into(),
            M::ConversationRow(c) => format!(
                "{}  {}件{}  最後: {}",
                c.label.clone().unwrap_or_else(|| format!("(削除された連絡先 {})", c.fingerprint)),
                c.messages,
                if c.pending > 0 { format!("、未配信 {}件", c.pending) } else { String::new() },
                if c.last_ms == 0 { "-".to_owned() } else { stamp(c.last_ms) },
            ),
            M::Line(m) => line(m, true),
            M::Deleted(n) => format!("この端末のメッセージを{n}件削除しました。"),
            M::NeedAllOrId => "削除するメッセージのIDを指定するか、会話ぜんたいを消すには --all を付けてください。".into(),
            M::Following => "新しいメッセージを待っています(Ctrl+C で終了)...".into(),
            M::TemporaryHistory => "注意: 履歴は一時的です(chat.history_save が false)。メモリにだけ置かれ、デーモンを止めると消えます。既定では保存されます。保存するには `miasma config --key chat.history_save --value auto` を実行してデーモンを再起動してください。".into(),
            M::ApiError(e) => format!("エラー: {e}"),
            M::ReceiptsState(label, on, global) => {
                if !global {
                    format!("既読表示は全体でオフです(chat.read_receipts が false)。「{label}」には送らず、届いても表示しません。")
                } else if *on {
                    format!("「{label}」との既読表示はオンです。双方がオンのときだけ「既読」と表示されます。")
                } else {
                    format!("「{label}」との既読表示はオフです。既読は送らず、届いた既読も表示しません。")
                }
            }
            M::ReceiptsSet(label, on) => {
                if *on {
                    format!("「{label}」との既読表示をオンにしました。")
                } else {
                    format!("「{label}」との既読表示をオフにしました。")
                }
            }
            M::ReadUpTo(n) => format!("(相手が {n} 番目のメッセージまで読みました)"),
            M::Hint(kind) => match *kind {
                "unknown_contact" => "その連絡先はありません。`miasma contact list` で確認してください。".into(),
                "send_disabled" => "この連絡先への送信はオフになっています(`miasma contact set <連絡先> --allow-send`)。".into(),
                "too_big" => "メッセージが長すぎます(上限 4096 バイト)。".into(),
                "empty" => "メッセージが空です。".into(),
                "outbox_full" => "送信待ちのメッセージが多すぎます。いくつか届いてからもう一度試してください。".into(),
                "bad_message_id" => "メッセージIDが正しくありません。".into(),
                "unavailable" => "チャットが動いていません(iroh通信と chat.enabled が必要です)。".into(),
                _ => String::new(),
            },
        }
    }
}

/// `YYYY-MM-DD HH:MM` in UTC.
fn stamp(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn state_word(state: &str, ja: bool) -> &'static str {
    match (state, ja) {
        ("queued", false) => "waiting",
        ("sending", false) => "sending",
        ("delivered", false) => "delivered",
        ("read", false) => "read",
        ("failed", false) => "FAILED",
        ("queued", true) => "送信待ち",
        ("sending", true) => "送信中",
        ("delivered", true) => "届きました",
        ("read", true) => "既読",
        ("failed", true) => "失敗",
        _ => "",
    }
}

fn line(m: &MessageInfo, ja: bool) -> String {
    let when = if m.at_ms == 0 { m.sent_ms } else { m.at_ms };
    let who = match (m.outgoing, ja) {
        (true, false) => "me",
        (false, false) => "them",
        (true, true) => "自分",
        (false, true) => "相手",
    };
    let state = if m.outgoing {
        let w = state_word(&m.state, ja);
        match (&m.reason, m.state.as_str()) {
            (Some(r), "failed") => format!(" [{w}: {r}]"),
            _ => format!(" [{w}]"),
        }
    } else {
        String::new()
    };
    format!(
        "{}  {who}: {}{state}",
        stamp(when),
        m.text.replace('\n', "\n    ")
    )
}

// ─── Plumbing ────────────────────────────────────────────────────────────────

async fn call(data_dir: &Path, req: ChatRequest) -> Result<ChatResponse> {
    match daemon_request(data_dir, ControlRequest::Chat(req)).await {
        Ok(ControlResponse::Chat(r)) => Ok(r),
        // An older daemon answers an unknown request with an error or drops the
        // connection; tell that apart from "no daemon" by asking a request every
        // version knows.
        Ok(ControlResponse::Error(e)) => {
            tracing::debug!("daemon error: {e}");
            bail!("{}", M::NotSupported.t())
        }
        Ok(other) => bail!("unexpected response: {other:?}"),
        Err(e) => {
            tracing::debug!("daemon request failed: {e:#}");
            match daemon_request(data_dir, ControlRequest::Status).await {
                Ok(_) => bail!("{}", M::NotSupported.t()),
                Err(_) => bail!("{}", M::DaemonDown.t()),
            }
        }
    }
}

fn api_error(kind: &str, message: &str) -> anyhow::Error {
    let hint = M::Hint(kind).t();
    if hint.is_empty() {
        anyhow::anyhow!("{}", M::ApiError(message).t())
    } else {
        anyhow::anyhow!("{hint}")
    }
}

/// Say so when the history is only kept in memory.
async fn note_if_temporary(data_dir: &Path) {
    if let Ok(ChatResponse::Status(s)) = call(data_dir, ChatRequest::Status {}).await {
        if !s.history_saved {
            println!("{}", M::TemporaryHistory.t());
        }
    }
}

fn label_of(contact: &str, label: &Option<String>) -> String {
    label.clone().unwrap_or_else(|| contact.to_owned())
}

// ─── Commands ────────────────────────────────────────────────────────────────

pub async fn run_chat(data_dir: &Path, cmd: ChatCmd) -> Result<()> {
    match cmd {
        ChatCmd::Send { contact, text } => {
            let text = text.join(" ");
            match call(
                data_dir,
                ChatRequest::Send {
                    contact: contact.clone(),
                    text,
                },
            )
            .await?
            {
                ChatResponse::Queued { .. } => {
                    println!("{}", M::Queued(&contact).t());
                    Ok(())
                }
                ChatResponse::Error { kind, message } => Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        ChatCmd::List => match call(data_dir, ChatRequest::Conversations {}).await? {
            ChatResponse::Conversations(list) => {
                if list.is_empty() {
                    println!("{}", M::ConversationsNone.t());
                }
                for c in &list {
                    println!("{}", M::ConversationRow(c).t());
                }
                note_if_temporary(data_dir).await;
                Ok(())
            }
            ChatResponse::Error { kind, message } => Err(api_error(&kind, &message)),
            other => bail!("unexpected response: {other:?}"),
        },
        ChatCmd::History {
            contact,
            limit,
            follow,
            ids,
        } => {
            let (endpoint_id, label) = show_history(data_dir, &contact, limit, ids).await?;
            note_if_temporary(data_dir).await;
            if follow {
                follow_events(data_dir, &endpoint_id, &label.unwrap_or(contact)).await?;
            }
            Ok(())
        }
        ChatCmd::Receipts { contact, on, off } => {
            if on || off {
                return match call(
                    data_dir,
                    ChatRequest::SetReadReceipts {
                        contact: contact.clone(),
                        enabled: on,
                    },
                )
                .await?
                {
                    ChatResponse::ReceiptsSet { enabled } => {
                        println!("{}", M::ReceiptsSet(&contact, enabled).t());
                        Ok(())
                    }
                    ChatResponse::Error { kind, message } => Err(api_error(&kind, &message)),
                    other => bail!("unexpected response: {other:?}"),
                };
            }
            let global = match call(data_dir, ChatRequest::Status {}).await? {
                ChatResponse::Status(s) => s.read_receipts,
                ChatResponse::Error { kind, message } => return Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            };
            let sel = contact.to_lowercase();
            let effective = match call(data_dir, ChatRequest::Conversations {}).await? {
                ChatResponse::Conversations(list) => list
                    .iter()
                    .find(|c| {
                        c.endpoint_id == sel
                            || c.contact_id.as_deref() == Some(contact.as_str())
                            || c.label.as_deref().map(str::to_lowercase).as_deref() == Some(&sel)
                    })
                    .map(|c| c.read_receipts),
                _ => None,
            };
            // Without a conversation yet, only the global setting is known.
            let on = effective.unwrap_or(global);
            println!("{}", M::ReceiptsState(&contact, on && global, global).t());
            Ok(())
        }
        ChatCmd::Delete {
            contact,
            message,
            all,
        } => {
            if message.is_none() && !all {
                bail!("{}", M::NeedAllOrId.t());
            }
            match call(
                data_dir,
                ChatRequest::DeleteLocal {
                    contact,
                    message_id: message,
                },
            )
            .await?
            {
                ChatResponse::Deleted { count } => {
                    println!("{}", M::Deleted(count).t());
                    Ok(())
                }
                ChatResponse::Error { kind, message } => Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            }
        }
    }
}

/// Print the newest `limit` messages; returns the contact's endpoint ID and label.
async fn show_history(
    data_dir: &Path,
    contact: &str,
    limit: u32,
    ids: bool,
) -> Result<(String, Option<String>)> {
    match call(
        data_dir,
        ChatRequest::History {
            contact: contact.to_owned(),
            before: None,
            limit: Some(limit.clamp(1, 200)),
        },
    )
    .await?
    {
        ChatResponse::History {
            endpoint_id,
            label,
            messages,
        } => {
            if messages.is_empty() {
                println!("{}", M::HistoryNone(&label_of(contact, &label)).t());
            }
            for m in &messages {
                if ids {
                    println!("{}  {}", m.id, M::Line(m).t());
                } else {
                    println!("{}", M::Line(m).t());
                }
            }
            Ok((endpoint_id, label))
        }
        ChatResponse::Error { kind, message } => Err(api_error(&kind, &message)),
        other => bail!("unexpected response: {other:?}"),
    }
}

/// Poll the daemon's events and print the ones of this contact.
async fn follow_events(data_dir: &Path, endpoint_id: &str, label: &str) -> Result<()> {
    println!("{}", M::Following.t());
    let _ = label;
    // Start after everything that already happened.
    let mut since = match call(data_dir, ChatRequest::Events { since: u64::MAX }).await? {
        ChatResponse::Events { next, .. } => next,
        _ => 0,
    };
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
        }
        match call(data_dir, ChatRequest::Events { since }).await? {
            ChatResponse::Events { next, events } => {
                for e in events {
                    if e.endpoint_id != endpoint_id {
                        continue;
                    }
                    match e.kind.as_str() {
                        "received" => println!("{}", M::Line(&e.message).t()),
                        "read" => println!("{}", M::ReadUpTo(e.message.seq).t()),
                        _ => {}
                    }
                }
                since = next;
            }
            ChatResponse::Error { kind, message } => return Err(api_error(&kind, &message)),
            other => bail!("unexpected response: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(outgoing: bool, state: &str) -> MessageInfo {
        MessageInfo {
            ord: 1,
            id: "00".repeat(16),
            outgoing,
            seq: 1,
            text: "こんにちは".into(),
            state: state.into(),
            reason: None,
            sent_ms: 1_700_000_000_000,
            at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn stamps_are_utc_dates() {
        assert_eq!(stamp(0), "1970-01-01 00:00");
        assert_eq!(stamp(1_700_000_000_000), "2023-11-14 22:13");
        assert_eq!(stamp(951_782_400_000), "2000-02-29 00:00");
    }

    #[test]
    fn every_message_renders_in_both_languages() {
        let conv = ConversationInfo {
            endpoint_id: "e".into(),
            fingerprint: "AAAAA-BBBBB-CCCCC-DDDDD".into(),
            label: Some("Taro".into()),
            contact_id: Some("c".into()),
            messages: 3,
            last_ms: 1_700_000_000_000,
            pending: 1,
            read_receipts: true,
        };
        let removed = ConversationInfo {
            label: None,
            ..conv.clone()
        };
        let m_out = msg(true, "delivered");
        let m_read = msg(true, "read");
        let m_in = msg(false, "received");
        let failed = MessageInfo {
            reason: Some("not_allowed".into()),
            ..msg(true, "failed")
        };
        let all = [
            M::DaemonDown,
            M::NotSupported,
            M::Queued("Taro"),
            M::HistoryNone("Taro"),
            M::ConversationsNone,
            M::ConversationRow(&conv),
            M::ConversationRow(&removed),
            M::Line(&m_out),
            M::Line(&m_read),
            M::ReceiptsState("Taro", true, true),
            M::ReceiptsState("Taro", false, true),
            M::ReceiptsState("Taro", true, false),
            M::ReceiptsSet("Taro", true),
            M::ReceiptsSet("Taro", false),
            M::ReadUpTo(3),
            M::Line(&m_in),
            M::Line(&failed),
            M::Deleted(2),
            M::NeedAllOrId,
            M::Following,
            M::TemporaryHistory,
            M::ApiError("x"),
        ];
        for m in &all {
            assert!(!m.en().is_empty());
            assert!(!m.ja().is_empty());
        }
        for k in [
            "unknown_contact",
            "send_disabled",
            "too_big",
            "empty",
            "outbox_full",
            "bad_message_id",
            "unavailable",
        ] {
            assert!(!M::Hint(k).en().is_empty(), "{k}");
            assert!(!M::Hint(k).ja().is_empty(), "{k}");
        }
        assert!(M::ConversationsNone.ja().contains("連絡先"));
        assert!(M::Line(&m_read).en().contains("[read]"));
        assert!(M::Line(&m_read).ja().contains("[既読]"));
        assert!(M::Line(&m_out).en().contains("[delivered]"));
        assert!(M::Queued("Taro").ja().contains("Taro"));
    }
}
