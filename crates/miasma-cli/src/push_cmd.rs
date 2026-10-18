//! `miasma contact ...`, `miasma push`, `miasma push-status`, `miasma push-inbox`:
//! trusted-contact push. Everything goes through the running daemon
//! (`ControlRequest::Push`); the CLI never touches the network or the files'
//! bytes itself.
//!
//! Messages follow the pattern of `i18n.rs` (one `match` per language in one
//! enum, language from `i18n::lang()`), kept here so the table sits next to
//! the commands that print it.

use std::{
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use miasma_core::{
    daemon_request,
    push::{
        speed_fmt::{format_speed, SpeedShown, SpeedUnit},
        stats::PathKind,
        ContactInfo, Direction, PushRequest, PushResponse, PushState, PushTransferInfo,
    },
    ControlRequest, ControlResponse,
};

use crate::i18n::{lang, Lang};

#[derive(Subcommand)]
pub enum ContactCmd {
    /// Show YOUR contact code and verification code: give the contact code to the other person.
    Code,
    /// Register the other person from their contact code.
    ///
    /// The code can be pasted as a whole message; it is found inside it. After
    /// adding, compare the verification code with theirs over a call.
    Add {
        /// `miasma-contact:...` (or a message that contains it).
        code: String,
        /// A name for this contact (also the inbox folder name).
        #[arg(long)]
        label: Option<String>,
    },
    /// List registered contacts.
    List,
    /// Unregister a contact (cancels its transfers, removes its partial files).
    Remove {
        /// Label, id or endpoint ID.
        contact: String,
    },
    /// Change a contact's permissions.
    Set {
        /// Label, id or endpoint ID.
        contact: String,
        /// New label.
        #[arg(long)]
        label: Option<String>,
        /// Allow sending files to this contact.
        #[arg(long, overrides_with = "no_allow_send")]
        allow_send: bool,
        /// Do not send files to this contact.
        #[arg(long, overrides_with = "allow_send")]
        no_allow_send: bool,
        /// Accept files pushed by this contact.
        #[arg(long, overrides_with = "no_allow_receive")]
        allow_receive: bool,
        /// Refuse files pushed by this contact (cancels running ones).
        #[arg(long, overrides_with = "allow_receive")]
        no_allow_receive: bool,
        /// Largest file accepted from this contact, e.g. 500MB, 20GiB. `0` or
        /// `default` removes the per-contact limit.
        #[arg(long, value_name = "SIZE", value_parser = parse_size)]
        max_size: Option<u64>,
    },
}

#[derive(Args)]
pub struct PushArgs {
    /// Contact label, id or endpoint ID.
    pub contact: String,
    /// Files to send, one after the other.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
    /// Queue the files and return without waiting for them.
    #[arg(long)]
    pub no_wait: bool,
}

/// `500MB`, `20GiB`, `1048576`, `0`/`default` (= no per-contact limit).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    if t == "default" || t == "none" {
        return Ok(0);
    }
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num.parse().map_err(|_| format!("'{s}' is not a size"))?;
    let mult: f64 = match unit.trim() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return Err(format!("'{s}': unknown unit (use KB, MB, GB, TB)")),
    };
    if n < 0.0 || !n.is_finite() {
        return Err(format!("'{s}' is not a size"));
    }
    Ok((n * mult) as u64)
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

// ─── Messages ────────────────────────────────────────────────────────────────

enum M<'a> {
    DaemonDown,
    YourCode,
    YourFingerprint(&'a str),
    ShareCodeHint,
    Added {
        label: &'a str,
        fp: &'a str,
    },
    AddedHint,
    ContactsNone,
    ContactRow(&'a ContactInfo),
    Removed(&'a str),
    Updated(&'a ContactInfo),
    Queued {
        name: &'a str,
        label: &'a str,
    },
    Progress {
        label: String,
    },
    DoneFile {
        name: &'a str,
        label: &'a str,
        saved: &'a str,
    },
    FailedFile {
        name: &'a str,
        err: &'a str,
    },
    RejectedFile {
        name: &'a str,
        text: &'a str,
    },
    CancelledFile(&'a str),
    HintNotAllowed,
    HintUnreachable,
    HintNoSpace,
    HintTooLarge,
    HintBusy,
    SomeFailed(usize),
    QueueEmpty,
    InboxIs(&'a str),
    NotAFile(&'a str),
    ApiError(&'a str),
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
            M::YourCode => "Your contact code (give this to the other person):".into(),
            M::YourFingerprint(f) => format!("Your verification code: {f}\nRead it to the other person, for example over a call, and ask them to compare it with the verification code on their screen."),
            M::ShareCodeHint => "They must also add YOUR contact code (`miasma contact add <code>`) before you can send them files. You must add theirs before they can send to you.".into(),
            M::Added { label, fp } => format!("Added contact \"{label}\"\nVerification code: {fp}"),
            M::AddedHint => "Ask them to read out their \"Your verification code\" over a call, and compare it with the code above. If it differs, remove this contact.".into(),
            M::ContactsNone => "No contacts yet. Add one with `miasma contact add <code>`.".into(),
            M::ContactRow(c) => format!(
                "{:<20} {}  send:{}  receive:{}  max:{}  saved in: {}",
                c.label,
                c.fingerprint,
                if c.allow_send { "yes" } else { "no" },
                if c.allow_receive { "yes" } else { "no" },
                c.max_file_size.map(human_bytes).unwrap_or_else(|| "default".into()),
                c.inbox_dir
            ),
            M::Removed(l) => format!("Removed contact \"{l}\"."),
            M::Updated(c) => format!(
                "Updated \"{}\": send {}, receive {}, max size {}",
                c.label,
                if c.allow_send { "on" } else { "off" },
                if c.allow_receive { "on" } else { "off" },
                c.max_file_size.map(human_bytes).unwrap_or_else(|| "default".into()),
            ),
            M::Queued { name, label } => format!("queued: {name} -> {label}"),
            M::Progress { label } => label.clone(),
            M::DoneFile { name, label, saved } => format!("sent: {name} -> {label} (saved there as {saved})"),
            M::FailedFile { name, err } => format!("FAILED: {name}: {err}"),
            M::RejectedFile { name, text } => format!("REJECTED: {name}: {text}"),
            M::CancelledFile(n) => format!("cancelled: {n}"),
            M::HintNotAllowed => "They have not added you yet. Ask them to run `miasma contact add` with YOUR contact code (`miasma contact code`).".into(),
            M::HintUnreachable => "Could not reach them. Check that their Miasma is running and online. If they are online, run `miasma netcheck` to see what this network allows.".into(),
            M::HintNoSpace => "Their disk is too full for this file. Ask them to free space.".into(),
            M::HintTooLarge => "The file is over their size limit. They can raise it with `miasma contact set <you> --max-size ...` or `push.max_file_size` in config.toml.".into(),
            M::HintBusy => "They are busy receiving other files. Try again in a minute.".into(),
            M::SomeFailed(n) => format!("{n} transfer(s) did not complete."),
            M::QueueEmpty => "No transfers in progress.".into(),
            M::InboxIs(d) => format!("Received files are in: {d}"),
            M::NotAFile(p) => format!("not a file (folders cannot be sent): {p}"),
            M::ApiError(e) => format!("error: {e}"),
        }
    }

    fn ja(&self) -> String {
        match self {
            M::DaemonDown => "Miasmaのバックグラウンド機能(デーモン)が起動していません。先に起動(`miasma daemon` またはアプリを開く)してから、もう一度試してください。".into(),
            M::YourCode => "あなたの連絡先コード(相手に送ってください):".into(),
            M::YourFingerprint(f) => format!("あなたの確認用コード: {f}\n相手に電話などで読み上げて、相手の画面の「確認用コード」と同じか見比べてもらってください。"),
            M::ShareCodeHint => "相手にも、あなたの連絡先コードを登録してもらってください(`miasma contact add <コード>`)。お互いに登録すると、送り合えるようになります。".into(),
            M::Added { label, fp } => format!("連絡先「{label}」を追加しました\n確認用コード: {fp}"),
            M::AddedHint => "相手に電話などで「あなたの確認用コード」を読み上げてもらい、上のコードと同じか見比べてください。違っていたら、この連絡先を削除してください。".into(),
            M::ContactsNone => "連絡先はまだありません。`miasma contact add <コード>` で追加してください。".into(),
            M::ContactRow(c) => format!(
                "{:<20} {}  送信:{}  受信:{}  上限:{}  保存先: {}",
                c.label,
                c.fingerprint,
                if c.allow_send { "可" } else { "不可" },
                if c.allow_receive { "可" } else { "不可" },
                c.max_file_size.map(human_bytes).unwrap_or_else(|| "既定".into()),
                c.inbox_dir
            ),
            M::Removed(l) => format!("連絡先「{l}」を削除しました。"),
            M::Updated(c) => format!(
                "「{}」を更新しました: 送信 {}、受信 {}、最大サイズ {}",
                c.label,
                if c.allow_send { "オン" } else { "オフ" },
                if c.allow_receive { "オン" } else { "オフ" },
                c.max_file_size.map(human_bytes).unwrap_or_else(|| "既定".into()),
            ),
            M::Queued { name, label } => format!("送信待ち: {name} -> {label}"),
            M::Progress { label } => label.clone(),
            M::DoneFile { name, label, saved } => format!("送信しました: {name} -> {label}(相手の保存名: {saved})"),
            M::FailedFile { name, err } => format!("失敗: {name}: {err}"),
            M::RejectedFile { name, text } => format!("断られました: {name}: {text}"),
            M::CancelledFile(n) => format!("中止しました: {n}"),
            M::HintNotAllowed => "相手はまだあなたを登録していません。相手のMiasmaで、あなたの連絡先コード(`miasma contact code`)を `miasma contact add` で追加してもらってください。".into(),
            M::HintUnreachable => "相手に届きませんでした。相手のMiasmaが起動していて、オンラインか確認してください。それでも届かないときは、`miasma netcheck` でこのネットワークの状態を確認してください。".into(),
            M::HintNoSpace => "相手のパソコンの空き容量が足りません。空きを作ってもらってください。".into(),
            M::HintTooLarge => "ファイルが、相手の受け取れるサイズを超えています。相手のMiasmaで `miasma contact set <あなた> --max-size ...` を実行するか、config.toml の `push.max_file_size` を上げてもらってください。".into(),
            M::HintBusy => "相手がほかのファイルを受け取っています。少し待ってから、もう一度試してください。".into(),
            M::SomeFailed(n) => format!("{n} 件の転送が完了しませんでした。"),
            M::QueueEmpty => "実行中の転送はありません。".into(),
            M::InboxIs(d) => format!("受信したファイルの保存先: {d}"),
            M::NotAFile(p) => format!("ファイルではありません(フォルダは送れません): {p}"),
            M::ApiError(e) => format!("エラー: {e}"),
        }
    }
}

// ─── Reasons: stable kinds from the daemon -> words in the person's language ──

/// `(English, Japanese)` for a stable `reject_reason` / `error_kind` of the daemon, worded from the
/// point of view of this machine: `Direction::Out` = we are the sender, `In` = we are the receiver.
/// `None` for a kind this CLI does not know (the daemon's own text is shown then).
fn why_texts(kind: &str, dir: Direction) -> Option<(&'static str, &'static str)> {
    let out = dir == Direction::Out;
    Some(match kind {
        // Refusals (`reject_reason`).
        "not_allowed" if out => (
            "the other side has not registered you: ask them to add your contact code",
            "相手があなたを登録していません。相手に、あなたの連絡先コードを追加してもらってください",
        ),
        "not_allowed" => (
            "this person is not registered with receiving switched on",
            "この相手は、登録されていないか、受信がオフです",
        ),
        "too_large" if out => (
            "the file is larger than the other side accepts",
            "ファイルが、相手の受け取れるサイズを超えています",
        ),
        "too_large" => (
            "the file is larger than your limit",
            "ファイルが、設定した上限を超えているため断りました",
        ),
        "no_space" if out => (
            "the other side does not have enough free disk space",
            "相手のパソコンの空き容量が足りません",
        ),
        "no_space" => (
            "there is not enough free disk space here",
            "このパソコンの空き容量が足りないため断りました",
        ),
        "busy" if out => (
            "the other side is busy receiving other files; try again in a moment",
            "相手がほかのファイルを受け取っています。少し待ってから、もう一度試してください",
        ),
        "busy" => (
            "busy with other transfers; the sender can try again in a moment",
            "ほかの転送中のため断りました。少し待てば、相手が再び送れます",
        ),
        "bad_name" if out => (
            "the other side did not accept the file name",
            "相手が、このファイル名を受け付けませんでした",
        ),
        "bad_name" => (
            "the file name cannot be used here",
            "このファイル名は使えないため断りました",
        ),
        "bad_request" => (
            "the request was not understood (different Miasma versions?)",
            "要求を理解できませんでした。お互いのMiasmaのバージョンが違うのかもしれません",
        ),
        // Endings that are not refusals (`error_kind`).
        "unreachable" => (
            "could not reach the other side (their Miasma is not running, or this network blocks \
             direct connections)",
            "相手に届きませんでした(相手のMiasmaが起動していないか、ネットワークが直接通信を止めています)",
        ),
        "connection_lost" if out => (
            "the connection was lost",
            "通信が途切れました",
        ),
        "connection_lost" => (
            "the connection was lost; if the sender sends it again it continues where it stopped",
            "通信が途切れました。相手が再び送ると、続きから受け取れます",
        ),
        "timed_out" if out => (
            "the other side did not answer in time",
            "相手から時間内に返事がありませんでした",
        ),
        "timed_out" => (
            "the sender stopped sending; if it sends again it continues where it stopped",
            "相手からのデータが止まりました。相手が再び送ると、続きから受け取れます",
        ),
        "peer_cancelled" => (
            "the sender cancelled this transfer",
            "相手が転送を中止しました",
        ),
        "damaged" => (
            "the file arrived damaged (checksum mismatch)",
            "ファイルが壊れて届きました(チェックサムが一致しません)",
        ),
        "file_unreadable" => (
            "the file could not be read (it may have been changed or removed)",
            "ファイルを読み込めませんでした(変更または削除された可能性があります)",
        ),
        "write_failed" if out => (
            "the other side could not save the file",
            "相手のパソコンで保存に失敗しました",
        ),
        "write_failed" => (
            "the file could not be written to the inbox",
            "受信フォルダに書き込めませんでした",
        ),
        "contact_changed" => (
            "the contact was removed or sending to it was switched off",
            "連絡先が削除されたか、送信がオフになりました",
        ),
        "source_changed" => (
            "the file was changed or replaced after it was queued; send it again",
            "ファイルが、送信を予約したあとに変更または差し替えられました。もう一度送ってください",
        ),
        _ => return None,
    })
}

/// The reason line of a finished transfer in the person's language: the refusal, else the kind of
/// ending, else (an ending this CLI has no words for) the daemon's own text.
fn explain(t: &PushTransferInfo) -> Option<String> {
    let kind = t.reject_reason.as_deref().or(t.error_kind.as_deref());
    if let Some((en, ja)) = kind.and_then(|k| why_texts(k, t.direction)) {
        return Some(
            match lang() {
                Lang::En => en,
                Lang::Ja => ja,
            }
            .to_owned(),
        );
    }
    t.error.clone()
}

// ─── Plumbing ────────────────────────────────────────────────────────────────

async fn call(data_dir: &Path, req: PushRequest) -> Result<PushResponse> {
    match daemon_request(data_dir, ControlRequest::Push(req)).await {
        Ok(ControlResponse::Push(r)) => Ok(r),
        Ok(ControlResponse::Error(e)) => bail!("{}", M::ApiError(&e).t()),
        Ok(other) => bail!("unexpected response: {other:?}"),
        Err(e) => {
            tracing::debug!("daemon request failed: {e:#}");
            bail!("{}", M::DaemonDown.t())
        }
    }
}

fn api_error(kind: &str, message: &str) -> anyhow::Error {
    // `kind` is stable; the message is the daemon's English text.
    let _ = kind;
    anyhow::anyhow!("{}", M::ApiError(message).t())
}

// ─── Commands ────────────────────────────────────────────────────────────────

pub async fn run_contact(data_dir: &Path, cmd: ContactCmd) -> Result<()> {
    match cmd {
        ContactCmd::Code => match call(data_dir, PushRequest::ContactCode).await? {
            PushResponse::Code {
                code, fingerprint, ..
            } => {
                println!("{}", M::YourCode.t());
                println!();
                println!("{code}");
                println!();
                println!("{}", M::YourFingerprint(&fingerprint).t());
                println!();
                println!("{}", M::ShareCodeHint.t());
                Ok(())
            }
            PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
            other => bail!("unexpected response: {other:?}"),
        },
        ContactCmd::Add { code, label } => {
            match call(data_dir, PushRequest::ContactAdd { code, label }).await? {
                PushResponse::Contact(c) => {
                    println!(
                        "{}",
                        M::Added {
                            label: &c.label,
                            fp: &c.fingerprint
                        }
                        .t()
                    );
                    println!("{}", M::AddedHint.t());
                    Ok(())
                }
                PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        ContactCmd::List => match call(data_dir, PushRequest::ContactList).await? {
            PushResponse::Contacts(list) => {
                if list.is_empty() {
                    println!("{}", M::ContactsNone.t());
                }
                for c in &list {
                    println!("{}", M::ContactRow(c).t());
                }
                Ok(())
            }
            PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
            other => bail!("unexpected response: {other:?}"),
        },
        ContactCmd::Remove { contact } => {
            match call(
                data_dir,
                PushRequest::ContactRemove {
                    contact: contact.clone(),
                },
            )
            .await?
            {
                PushResponse::Removed => {
                    println!("{}", M::Removed(&contact).t());
                    Ok(())
                }
                PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        ContactCmd::Set {
            contact,
            label,
            allow_send,
            no_allow_send,
            allow_receive,
            no_allow_receive,
            max_size,
        } => {
            let flag = |on: bool, off: bool| {
                if on {
                    Some(true)
                } else if off {
                    Some(false)
                } else {
                    None
                }
            };
            let req = PushRequest::ContactUpdate {
                contact,
                label,
                allow_send: flag(allow_send, no_allow_send),
                allow_receive: flag(allow_receive, no_allow_receive),
                max_size,
            };
            match call(data_dir, req).await? {
                PushResponse::Contact(c) => {
                    println!("{}", M::Updated(&c).t());
                    Ok(())
                }
                PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            }
        }
    }
}

fn state_label(s: PushState) -> &'static str {
    if lang() == Lang::Ja {
        return match s {
            PushState::Queued => "待機中",
            PushState::Preparing => "準備中",
            PushState::Connecting => "接続中",
            PushState::Sending => "転送中",
            PushState::Verifying => "確認中",
            PushState::Done => "完了",
            PushState::Failed => "失敗",
            PushState::Rejected => "断られました",
            PushState::Cancelled => "中止",
            PushState::Waiting => "再試行待ち",
        };
    }
    match s {
        PushState::Queued => "queued",
        PushState::Preparing => "preparing",
        PushState::Connecting => "connecting",
        PushState::Sending => "sending",
        PushState::Verifying => "verifying",
        PushState::Done => "done",
        PushState::Failed => "failed",
        PushState::Rejected => "rejected",
        PushState::Cancelled => "cancelled",
        PushState::Waiting => "waiting to retry",
    }
}

/// "in 2 min" / "in 40 s" / "now", for the time left until `at_ms`.
fn in_words(at_ms: u64, now_ms: u64) -> String {
    let s = at_ms.saturating_sub(now_ms).div_ceil(1000);
    let ja = lang() == Lang::Ja;
    if s == 0 {
        return if ja { "まもなく" } else { "now" }.to_owned();
    }
    if s < 90 {
        return if ja {
            format!("{s}秒後")
        } else {
            format!("in {s} s")
        };
    }
    let m = s.div_ceil(60);
    if m < 120 {
        return if ja {
            format!("{m}分後")
        } else {
            format!("in {m} min")
        };
    }
    let h = m.div_ceil(60);
    if ja {
        format!("{h}時間後")
    } else {
        format!("in {h} h")
    }
}

/// What a waiting send says: that it will try again by itself, when, and (if
/// the other side is simply offline) why. `None` for any other state.
fn waiting_note(t: &PushTransferInfo, now_ms: u64) -> Option<String> {
    if t.state != PushState::Waiting {
        return None;
    }
    let ja = lang() == Lang::Ja;
    let attempt = t.attempt.unwrap_or(1);
    let when = t
        .next_attempt_at_ms
        .map(|at| in_words(at, now_ms))
        .unwrap_or_default();
    let mut s = if ja {
        format!("再試行待ち(次の試行は{when}、{attempt}回目)")
    } else {
        format!("Waiting to retry (next attempt {when}, attempt {attempt})")
    };
    if t.error
        .as_deref()
        .is_some_and(|e| e.contains("not connected to a relay server"))
    {
        // It is this computer's relay link that is down, not the other side.
        s.push_str(if ja {
            "。一時停止中: この PC がリレーサーバに接続できていません"
        } else {
            ". Paused: this computer is not connected to a relay server"
        });
    } else if t.error_kind.as_deref() == Some("unreachable") {
        s.push_str(if ja {
            "。一時停止中: 相手がオフラインです"
        } else {
            ". Paused: the other side is offline"
        });
    }
    Some(s)
}

fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn progress_line(t: &PushTransferInfo) -> String {
    let pct = if t.size == 0 {
        100
    } else {
        (t.bytes as f64 / t.size as f64 * 100.0) as u64
    };
    let dir = match t.direction {
        Direction::Out => "->",
        Direction::In => "<-",
    };
    let mut s = format!(
        "{dir} {} {}: {} {}% ({} / {})",
        t.contact_label,
        t.name,
        state_label(t.state),
        pct,
        human_bytes(t.bytes),
        human_bytes(t.size)
    );
    s.push_str(&live_suffix(
        t,
        speed_unit(),
        speed_shown(),
        lang() == Lang::Ja,
    ));
    if let Some(n) = waiting_note(t, clock_ms()) {
        s.push_str(&format!(" - {n}"));
    }
    s
}

/// `MIASMA_SPEED_UNIT=bytes` leads with the byte units instead of Mbps and
/// `MIASMA_SPEED_UNITS_SHOWN=both|bits_only|bytes_only` picks what is shown
/// (the desktop's `ui.speed_unit` / `ui.speed_units_shown`).
fn speed_unit() -> SpeedUnit {
    std::env::var("MIASMA_SPEED_UNIT")
        .ok()
        .and_then(|v| SpeedUnit::parse(&v))
        .unwrap_or_default()
}

fn speed_shown() -> SpeedShown {
    std::env::var("MIASMA_SPEED_UNITS_SHOWN")
        .ok()
        .and_then(|v| SpeedShown::parse(&v))
        .unwrap_or_default()
}

/// ` 42 Mbps (5.2 MB/s / 5.0 MiB/s), direct, RTT 12 ms` for a running transfer;
/// ` avg 45 Mbps (5.6 MB/s / 5.4 MiB/s), 20 s, direct` for a finished one. An old daemon
/// reports no stats: its byte rate is shown alone.
fn live_suffix(t: &PushTransferInfo, unit: SpeedUnit, shown: SpeedShown, ja: bool) -> String {
    let Some(st) = &t.stats else {
        return if t.rate_bps > 0 {
            format!(
                " {}",
                format_speed(t.rate_bps.saturating_mul(8), unit, shown)
            )
        } else {
            String::new()
        };
    };
    let path = match (st.path, ja) {
        (PathKind::Direct, false) => Some("direct"),
        (PathKind::Direct, true) => Some("直接"),
        (PathKind::Relay, false) => Some("via relay (slower)"),
        (PathKind::Relay, true) => Some("リレー経由(遅い)"),
        (PathKind::Mixed, false) => Some("direct + relay"),
        (PathKind::Mixed, true) => Some("直接+リレー"),
        (PathKind::Unknown, _) => None,
    };
    let mut parts: Vec<String> = Vec::new();
    if t.state.is_finished() {
        if st.avg_bits > 0 {
            let secs = (st.active_ms + 500) / 1000;
            parts.push(if ja {
                format!(
                    "平均 {}, {} 秒",
                    format_speed(st.avg_bits, unit, shown),
                    secs
                )
            } else {
                format!("avg {}, {} s", format_speed(st.avg_bits, unit, shown), secs)
            });
        }
    } else if st.rate_bits > 0 {
        parts.push(format_speed(st.rate_bits, unit, shown));
    }
    if let Some(p) = path {
        parts.push(p.to_owned());
    }
    if !t.state.is_finished() {
        if let Some(r) = st.rtt_ms {
            parts.push(format!("RTT {r} ms"));
        }
        if st.stall_ms >= 1000 {
            parts.push(if ja {
                format!("停止 {} 秒", st.stall_ms / 1000)
            } else {
                format!("stalled {} s", st.stall_ms / 1000)
            });
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" {}", parts.join(", "))
    }
}

fn print_hint(t: &PushTransferInfo) {
    let err = t.error.as_deref().unwrap_or("");
    let hint = match t.reject_reason.as_deref() {
        Some("not_allowed") => Some(M::HintNotAllowed),
        Some("no_space") => Some(M::HintNoSpace),
        Some("too_large") => Some(M::HintTooLarge),
        Some("busy") => Some(M::HintBusy),
        _ if t.direction == Direction::Out
            && (t.error_kind.as_deref() == Some("unreachable")
                || err.contains("cannot reach")
                || err.contains("no connection")) =>
        {
            Some(M::HintUnreachable)
        }
        _ => None,
    };
    if let Some(h) = hint {
        eprintln!("  -> {}", h.t());
    }
}

pub async fn run_push(data_dir: &Path, args: PushArgs) -> Result<()> {
    let mut ids: Vec<(String, String)> = Vec::new();
    for f in &args.files {
        let abs = std::fs::canonicalize(f).unwrap_or_else(|_| f.clone());
        if !abs.is_file() {
            bail!("{}", M::NotAFile(&f.display().to_string()).t());
        }
        let path = abs.to_string_lossy().into_owned();
        // `canonicalize` yields \\?\C:\... on Windows; the daemon accepts it,
        // but a plain path reads better in logs.
        let path = path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned();
        match call(
            data_dir,
            PushRequest::Send {
                contact: args.contact.clone(),
                path,
            },
        )
        .await?
        {
            PushResponse::Queued { id } => {
                let name = f
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                println!(
                    "{}",
                    M::Queued {
                        name: &name,
                        label: &args.contact
                    }
                    .t()
                );
                ids.push((id, name));
            }
            PushResponse::Error { kind, message } => return Err(api_error(&kind, &message)),
            other => bail!("unexpected response: {other:?}"),
        }
    }
    if args.no_wait {
        return Ok(());
    }

    let tty = std::io::stderr().is_terminal();
    let mut failed = 0usize;
    for (id, name) in &ids {
        let mut last_print = std::time::Instant::now() - Duration::from_secs(60);
        loop {
            let t = match call(
                data_dir,
                PushRequest::Status {
                    id: Some(id.clone()),
                },
            )
            .await?
            {
                PushResponse::Transfer(t) => t,
                PushResponse::Error { kind, message } => return Err(api_error(&kind, &message)),
                other => bail!("unexpected response: {other:?}"),
            };
            if t.state.is_finished() {
                if tty {
                    eprint!("\r{:width$}\r", "", width = 100);
                }
                match t.state {
                    PushState::Done => println!(
                        "{}",
                        M::DoneFile {
                            name,
                            label: &t.contact_label,
                            saved: t.saved_as.as_deref().unwrap_or(name),
                        }
                        .t()
                    ),
                    PushState::Rejected => {
                        failed += 1;
                        let why = explain(&t);
                        let text = why.as_deref().unwrap_or("rejected");
                        eprintln!("{}", M::RejectedFile { name, text }.t());
                        print_hint(&t);
                    }
                    PushState::Cancelled => {
                        failed += 1;
                        eprintln!("{}", M::CancelledFile(name).t());
                    }
                    _ => {
                        failed += 1;
                        let why = explain(&t);
                        let err = why.as_deref().unwrap_or("unknown error");
                        eprintln!("{}", M::FailedFile { name, err }.t());
                        print_hint(&t);
                    }
                }
                break;
            }
            let line = M::Progress {
                label: progress_line(&t),
            }
            .t();
            if tty {
                eprint!("\r{line:<100}");
                let _ = std::io::stderr().flush();
            } else if last_print.elapsed() >= Duration::from_secs(5) {
                eprintln!("{line}");
                last_print = std::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    if failed > 0 {
        bail!("{}", M::SomeFailed(failed).t());
    }
    Ok(())
}

pub async fn run_push_status(data_dir: &Path) -> Result<()> {
    match call(data_dir, PushRequest::Status { id: None }).await? {
        PushResponse::Transfers(list) => {
            if list.is_empty() {
                println!("{}", M::QueueEmpty.t());
            }
            for t in &list {
                let mut l = format!("[{}] {}", t.id, progress_line(t));
                if let Some(e) = explain(t) {
                    l.push_str(&format!("  ({e})"));
                }
                println!("{l}");
            }
            Ok(())
        }
        PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
        other => bail!("unexpected response: {other:?}"),
    }
}

/// `miasma push-retry <id>`: a waiting send tries again now.
pub async fn run_push_retry(data_dir: &Path, id: &str) -> Result<()> {
    match call(data_dir, PushRequest::RetryNow { id: id.to_owned() }).await? {
        PushResponse::Retrying => {
            println!(
                "{}",
                if lang() == Lang::Ja {
                    "すぐに再試行します"
                } else {
                    "Trying again now"
                }
            );
            Ok(())
        }
        PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
        other => bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_push_inbox(data_dir: &Path) -> Result<()> {
    match call(data_dir, PushRequest::Inbox).await? {
        PushResponse::Inbox { dir } => {
            println!("{}", M::InboxIs(&dir).t());
            Ok(())
        }
        PushResponse::Error { kind, message } => Err(api_error(&kind, &message)),
        other => bail!("unexpected response: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::push::stats::TransferStats;

    fn info_with(stats: Option<TransferStats>, state: PushState, rate: u64) -> PushTransferInfo {
        PushTransferInfo {
            id: "i".into(),
            direction: Direction::Out,
            contact_id: "c".into(),
            contact_label: "L".into(),
            name: "n".into(),
            size: 1,
            bytes: 0,
            rate_bps: rate,
            state,
            error: None,
            reject_reason: None,
            error_kind: None,
            source_path: None,
            saved_as: None,
            created_at_ms: 0,
            updated_at_ms: 0,
            next_attempt_at_ms: None,
            attempt: None,
            stats,
        }
    }

    #[test]
    fn live_text_running_finished_and_old_daemon() {
        let running = TransferStats {
            rate_bits: 41_943_040,
            path: PathKind::Relay,
            rtt_ms: Some(180),
            stall_ms: 3500,
            ..Default::default()
        };
        let t = info_with(Some(running), PushState::Sending, 5 << 20);
        assert_eq!(
            live_suffix(&t, SpeedUnit::Bits, SpeedShown::Both, false),
            " 42 Mbps (5.2 MB/s / 5.0 MiB/s), via relay (slower), RTT 180 ms, stalled 3 s"
        );
        assert_eq!(
            live_suffix(&t, SpeedUnit::Bytes, SpeedShown::Both, false),
            " 5.2 MB/s / 5.0 MiB/s (42 Mbps), via relay (slower), RTT 180 ms, stalled 3 s"
        );
        let done = TransferStats {
            avg_bits: 45_000_000,
            active_ms: 20_300,
            path: PathKind::Direct,
            ..Default::default()
        };
        let t = info_with(Some(done), PushState::Done, 0);
        assert_eq!(
            live_suffix(&t, SpeedUnit::Bits, SpeedShown::Both, false),
            " avg 45 Mbps (5.6 MB/s / 5.4 MiB/s), 20 s, direct"
        );
        // A daemon that predates the stats: bytes per second only.
        let t = info_with(None, PushState::Sending, 5 << 20);
        assert_eq!(
            live_suffix(&t, SpeedUnit::Bits, SpeedShown::Both, false),
            " 42 Mbps (5.2 MB/s / 5.0 MiB/s)"
        );
        let t = info_with(None, PushState::Queued, 0);
        assert_eq!(
            live_suffix(&t, SpeedUnit::Bits, SpeedShown::Both, false),
            ""
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("500MB").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_size("20GiB").unwrap(), 20 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1.5g").unwrap(), 1610612736);
        assert_eq!(parse_size("1234").unwrap(), 1234);
        assert_eq!(parse_size("default").unwrap(), 0);
        assert_eq!(parse_size("0").unwrap(), 0);
        assert!(parse_size("12 parsecs").is_err());
        assert!(parse_size("-1").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn every_stable_kind_has_words_in_both_languages_from_both_points_of_view() {
        let kinds = [
            "not_allowed",
            "too_large",
            "no_space",
            "busy",
            "bad_name",
            "bad_request",
            "unreachable",
            "connection_lost",
            "timed_out",
            "peer_cancelled",
            "damaged",
            "file_unreadable",
            "write_failed",
            "contact_changed",
            "source_changed",
        ];
        for k in kinds {
            for dir in [Direction::Out, Direction::In] {
                let (en, ja) = why_texts(k, dir).unwrap_or_else(|| panic!("{k}"));
                assert!(!en.is_empty() && !ja.is_empty(), "{k}");
                // Japanese output has no English sentence left in it.
                assert!(
                    ja.chars().any(|c| c as u32 > 0x3000),
                    "{k} {dir:?} is not Japanese: {ja}"
                );
                for bad in ["指紋", "カード", "フィンガープリント"] {
                    assert!(!ja.contains(bad), "{bad} in: {ja}");
                }
                assert!(!en.to_lowercase().contains("fingerprint"), "{en}");
            }
        }
        assert!(why_texts("something_new", Direction::Out).is_none());
        // The sender's perspective never blames "the sender", and an inbound row never tells the
        // person to check that their own Miasma is running.
        for dir in [Direction::Out, Direction::In] {
            for k in kinds {
                let (en, ja) = why_texts(k, dir).unwrap();
                assert!(!en.contains("sender is offline"), "{k}");
                // ("unreachable" only ever happens when sending.)
                if dir == Direction::In && k != "unreachable" {
                    assert!(!ja.contains("相手のMiasmaが起動"), "{k}: {ja}");
                }
            }
        }
        let (_, ja) = why_texts("not_allowed", Direction::Out).unwrap();
        assert!(ja.contains("連絡先コード"));
        let (_, ja) = why_texts("peer_cancelled", Direction::In).unwrap();
        assert_eq!(ja, "相手が転送を中止しました");
    }

    #[test]
    fn unknown_ending_keeps_the_daemons_own_text() {
        let t = PushTransferInfo {
            id: "i".into(),
            direction: Direction::Out,
            contact_id: "c".into(),
            contact_label: "L".into(),
            name: "n".into(),
            size: 1,
            bytes: 0,
            rate_bps: 0,
            state: PushState::Failed,
            error: Some("raw daemon text".into()),
            reject_reason: None,
            error_kind: Some("brand_new_kind".into()),
            source_path: None,
            saved_as: None,
            created_at_ms: 0,
            updated_at_ms: 0,
            next_attempt_at_ms: None,
            attempt: None,
            stats: None,
        };
        assert_eq!(explain(&t).as_deref(), Some("raw daemon text"));
        let mut known = t.clone();
        known.reject_reason = Some("not_allowed".into());
        assert_ne!(explain(&known).as_deref(), Some("raw daemon text"));
    }

    #[test]
    fn every_message_renders_in_both_languages() {
        let c = ContactInfo {
            id: "i".into(),
            label: "Taro".into(),
            endpoint_id: "e".into(),
            fingerprint: "AAAAA-BBBBB-CCCCC-DDDDD".into(),
            added_at: 0,
            allow_send: true,
            allow_receive: false,
            max_file_size: Some(1024),
            default_max_file_size: 0,
            inbox_dir: "/x".into(),
        };
        let msgs = [
            M::DaemonDown,
            M::YourCode,
            M::YourFingerprint("F"),
            M::ShareCodeHint,
            M::Added {
                label: "L",
                fp: "F",
            },
            M::AddedHint,
            M::ContactsNone,
            M::ContactRow(&c),
            M::Removed("L"),
            M::Updated(&c),
            M::Queued {
                name: "n",
                label: "l",
            },
            M::DoneFile {
                name: "n",
                label: "l",
                saved: "s",
            },
            M::FailedFile {
                name: "n",
                err: "e",
            },
            M::RejectedFile {
                name: "n",
                text: "t",
            },
            M::CancelledFile("n"),
            M::HintNotAllowed,
            M::HintUnreachable,
            M::HintNoSpace,
            M::HintTooLarge,
            M::HintBusy,
            M::SomeFailed(2),
            M::QueueEmpty,
            M::InboxIs("d"),
            M::NotAFile("p"),
            M::ApiError("e"),
        ];
        for m in &msgs {
            assert!(!m.en().is_empty());
            assert!(!m.ja().is_empty());
            // Same words as the app: "確認用コード", never the literal "指紋" / "カード".
            let ja = m.ja();
            for bad in ["指紋", "カード", "フィンガープリント"] {
                assert!(!ja.contains(bad), "{bad} in: {ja}");
            }
            assert!(!m.en().to_lowercase().contains("fingerprint"), "{}", m.en());
        }
        assert!(M::YourFingerprint("F").ja().contains("確認用コード"));
        assert!(M::HintUnreachable
            .ja()
            .contains("相手のMiasmaが起動していて"));
    }
}
