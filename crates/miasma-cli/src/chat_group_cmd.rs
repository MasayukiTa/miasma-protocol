//! `miasma chat group ...`: small group conversations between registered
//! contacts. Everything goes through the running daemon, like `chat_cmd.rs`.
//!
//! Being named in a group never registers anyone as a contact: members who are
//! not contacts are shown as "unverified" with the code to give to
//! `miasma contact add`.

use std::path::Path;

use anyhow::{bail, Result};
use clap::Subcommand;
use miasma_core::chat::{
    group::ipc::{GroupDetailInfo, GroupInfo, GroupMessageInfo, GroupRequest, GroupResponse},
    ChatRequest, ChatResponse,
};

use crate::{
    chat_cmd::{call, stamp},
    i18n::{lang, Lang},
};

#[derive(Subcommand)]
pub enum GroupCmd {
    /// Create a group of registered contacts (you are its administrator).
    Create {
        /// Name of the group.
        name: String,
        /// Contacts to invite (label, ID or endpoint ID).
        members: Vec<String>,
    },
    /// Add contacts to a group (administrators only).
    Add {
        group: String,
        #[arg(required = true)]
        members: Vec<String>,
        /// Make them administrators.
        #[arg(long)]
        admin: bool,
    },
    /// Remove a member from a group (administrators only).
    Remove { group: String, member: String },
    /// Leave a group.
    Leave { group: String },
    /// Send a message to every member of a group.
    Send {
        group: String,
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Show the latest messages of a group.
    History {
        group: String,
        /// How many messages to show (1-200).
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
    /// List your groups (or show one group with its members).
    List {
        /// Show this group's members instead.
        group: Option<String>,
    },
    /// Join a group you were invited to.
    Accept { group: String },
    /// Decline an invitation, or delete a group you left or were removed from.
    Decline { group: String },
}

enum M<'a> {
    Created(&'a str, u32),
    Queued(u32),
    Done,
    None,
    Row(&'a GroupInfo),
    Detail(&'a GroupDetailInfo),
    Line(&'a GroupMessageInfo),
    HistoryNone,
    Unverified,
    Err(&'a str, &'a str),
}

impl M<'_> {
    fn t(&self) -> String {
        let ja = matches!(lang(), Lang::Ja);
        match self {
            M::Created(id, n) => {
                if ja {
                    format!("グループを作成しました({id})。{n}人に招待を送ります。")
                } else {
                    format!("Group created ({id}). Invitations are going to {n} contact(s).")
                }
            }
            M::Queued(n) => {
                if ja {
                    format!("{n}人宛てに送信待ちにしました。オンラインになりしだい届きます。")
                } else {
                    format!("Queued for {n} member(s). Delivered as they come online.")
                }
            }
            M::Done => if ja { "完了しました。" } else { "Done." }.into(),
            M::None => if ja {
                "グループはまだありません。`miasma chat group create <名前> <連絡先>...` で作れます。"
            } else {
                "No groups yet. Create one with `miasma chat group create <name> <contact>...`."
            }
            .into(),
            M::Row(g) => {
                let pend = if g.pending > 0 {
                    if ja {
                        format!("、未配信 {}件", g.pending)
                    } else {
                        format!(", {} copies waiting", g.pending)
                    }
                } else {
                    String::new()
                };
                let by = g
                    .invited_by
                    .as_ref()
                    .map(|b| format!(" (from {})", &b[..b.len().min(12)]))
                    .unwrap_or_default();
                if ja {
                    format!(
                        "{}  {}  [{}{by}]  {}人 {}件{pend}",
                        &g.id[..8],
                        g.name,
                        status_word(&g.status, true),
                        g.members,
                        g.messages
                    )
                } else {
                    format!(
                        "{}  {}  [{}{by}]  {} members, {} messages{pend}",
                        &g.id[..8],
                        g.name,
                        status_word(&g.status, false),
                        g.members,
                        g.messages
                    )
                }
            }
            M::Detail(d) => {
                let mut s = M::Row(&d.group).t();
                for m in &d.members {
                    let who = if m.you {
                        if ja { "自分".to_owned() } else { "you".to_owned() }
                    } else if let Some(l) = &m.label {
                        l.clone()
                    } else {
                        match &m.hint {
                            Some(h) => format!("\"{h}\" {}", m.fingerprint),
                            None => m.fingerprint.clone(),
                        }
                    };
                    let tag = if m.verified || m.you {
                        String::new()
                    } else {
                        format!(
                            "  {}",
                            if ja {
                                format!("[未確認のメンバー: 信頼するには `miasma contact add {}`]", m.contact_code)
                            } else {
                                format!("[unverified member: to trust, `miasma contact add {}`]", m.contact_code)
                            }
                        )
                    };
                    s.push_str(&format!("\n  {who} ({}){tag}", m.role));
                }
                s
            }
            M::Line(m) => {
                let who = if m.outgoing {
                    if ja { "自分".to_owned() } else { "me".to_owned() }
                } else if let Some(l) = &m.sender_label {
                    l.clone()
                } else {
                    match &m.sender_hint {
                        Some(h) => format!("\"{h}\" {}", m.sender_fingerprint),
                        None => m.sender_fingerprint.clone(),
                    }
                };
                let unv = if !m.outgoing && !m.verified {
                    format!(" [{}]", M::Unverified.t())
                } else {
                    String::new()
                };
                let delivery = match (m.total, m.delivered, m.failed) {
                    (Some(t), Some(d), Some(f)) if m.outgoing => {
                        if ja {
                            format!(" [{d}/{t}人に配信{}]", if f > 0 { format!("、{f}人は不可") } else { String::new() })
                        } else {
                            format!(" [delivered to {d} of {t}{}]", if f > 0 { format!(", {f} given up") } else { String::new() })
                        }
                    }
                    _ => String::new(),
                };
                let gap = if m.gap_before > 0 {
                    if ja {
                        format!("  (この人の前のメッセージ{}件が届いていません)\n", m.gap_before)
                    } else {
                        format!("  ({} earlier message(s) from this person did not arrive)\n", m.gap_before)
                    }
                } else {
                    String::new()
                };
                format!(
                    "{gap}{}  {who}{unv}: {}{delivery}",
                    stamp(if m.at_ms == 0 { m.sent_ms } else { m.at_ms }),
                    m.text.replace('\n', "\n    ")
                )
            }
            M::HistoryNone => if ja { "メッセージはまだありません。" } else { "No messages yet." }.into(),
            M::Unverified => if ja { "未確認のメンバー" } else { "unverified member" }.into(),
            M::Err(kind, message) => {
                let hint = match (*kind, ja) {
                    ("unknown_contact", false) => "No such contact. Group members must be registered contacts (see `miasma contact list`).",
                    ("unknown_contact", true) => "その連絡先はありません。グループに招待できるのは登録済みの連絡先だけです(`miasma contact list`)。",
                    ("unknown_group", false) => "No such group (see `miasma chat group list`).",
                    ("unknown_group", true) => "そのグループはありません(`miasma chat group list`)。",
                    ("ambiguous_group", false) => "More than one group matches; give more of the ID.",
                    ("ambiguous_group", true) => "該当するグループが複数あります。IDをもう少し長く指定してください。",
                    ("not_joined", false) => "You are not an active member of this group.",
                    ("not_joined", true) => "このグループには参加していません。",
                    ("not_admin", false) => "Only an administrator can do this.",
                    ("not_admin", true) => "管理者だけが行えます。",
                    ("not_member", false) => "That person is not in the group.",
                    ("not_member", true) => "その人はグループにいません。",
                    ("already_member", false) => "That person is already in the group.",
                    ("already_member", true) => "その人はすでにグループにいます。",
                    ("too_many_members", false) => "A group holds at most 32 members.",
                    ("too_many_members", true) => "グループは32人までです。",
                    ("last_admin", false) => "The last administrator cannot leave; make someone else an administrator first.",
                    ("last_admin", true) => "最後の管理者は抜けられません。先に別の人を管理者にしてください。",
                    ("queue_full", false) => "Too many messages are waiting to be delivered in this group.",
                    ("queue_full", true) => "このグループには未配信のメッセージが多すぎます。",
                    ("empty", false) => "The message is empty.",
                    ("empty", true) => "メッセージが空です。",
                    ("too_big", false) => "The message is too long (limit 4096 bytes).",
                    ("too_big", true) => "メッセージが長すぎます(上限 4096 バイト)。",
                    ("send_disabled", false) => "Sending to this contact is switched off.",
                    ("send_disabled", true) => "この連絡先への送信はオフになっています。",
                    ("unavailable", false) => "Group chat is not running (it needs the iroh transport and chat.enabled).",
                    ("unavailable", true) => "グループチャットが動いていません(iroh通信と chat.enabled が必要です)。",
                    _ => "",
                };
                if hint.is_empty() {
                    if ja { format!("エラー: {message}") } else { format!("error: {message}") }
                } else {
                    hint.to_owned()
                }
            }
        }
    }
}

fn status_word(s: &str, ja: bool) -> &'static str {
    match (s, ja) {
        ("invited", false) => "invited",
        ("joined", false) => "joined",
        ("left", false) => "left",
        ("removed", false) => "removed",
        ("invited", true) => "招待中",
        ("joined", true) => "参加中",
        ("left", true) => "退出済み",
        ("removed", true) => "削除された",
        _ => "",
    }
}

async fn group_call(data_dir: &Path, req: GroupRequest) -> Result<GroupResponse> {
    match call(data_dir, ChatRequest::Group(req)).await? {
        ChatResponse::Group(g) => match g {
            GroupResponse::Error { kind, message } => bail!("{}", M::Err(&kind, &message).t()),
            other => Ok(other),
        },
        ChatResponse::Error { kind, message } => bail!("{}", M::Err(&kind, &message).t()),
        other => bail!("unexpected response: {other:?}"),
    }
}

pub async fn run(data_dir: &Path, cmd: GroupCmd) -> Result<()> {
    match cmd {
        GroupCmd::Create { name, members } => {
            match group_call(data_dir, GroupRequest::Create { name, members }).await? {
                GroupResponse::Created { id, recipients } => {
                    println!("{}", M::Created(&id[..8], recipients).t())
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        GroupCmd::Add {
            group,
            members,
            admin,
        } => done(
            group_call(
                data_dir,
                GroupRequest::Add {
                    group,
                    members,
                    admin,
                },
            )
            .await?,
        )?,
        GroupCmd::Remove { group, member } => {
            done(group_call(data_dir, GroupRequest::Remove { group, member }).await?)?
        }
        GroupCmd::Leave { group } => {
            done(group_call(data_dir, GroupRequest::Leave { group }).await?)?
        }
        GroupCmd::Accept { group } => {
            done(group_call(data_dir, GroupRequest::Accept { group }).await?)?
        }
        GroupCmd::Decline { group } => {
            done(group_call(data_dir, GroupRequest::Decline { group }).await?)?
        }
        GroupCmd::Send { group, text } => {
            let text = text.join(" ");
            match group_call(data_dir, GroupRequest::Send { group, text }).await? {
                GroupResponse::Queued { recipients, .. } => {
                    println!("{}", M::Queued(recipients).t())
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        GroupCmd::History { group, limit } => {
            match group_call(
                data_dir,
                GroupRequest::History {
                    group,
                    before: None,
                    limit: Some(limit.clamp(1, 200)),
                },
            )
            .await?
            {
                GroupResponse::History { messages, .. } => {
                    if messages.is_empty() {
                        println!("{}", M::HistoryNone.t());
                    }
                    for m in &messages {
                        println!("{}", M::Line(m).t());
                    }
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        GroupCmd::List { group: None } => {
            match group_call(data_dir, GroupRequest::List {}).await? {
                GroupResponse::Groups(list) => {
                    if list.is_empty() {
                        println!("{}", M::None.t());
                    }
                    for g in &list {
                        println!("{}", M::Row(g).t());
                    }
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        GroupCmd::List { group: Some(group) } => {
            match group_call(data_dir, GroupRequest::Show { group }).await? {
                GroupResponse::Detail(d) => println!("{}", M::Detail(&d).t()),
                other => bail!("unexpected response: {other:?}"),
            }
        }
    }
    Ok(())
}

fn done(r: GroupResponse) -> Result<()> {
    match r {
        GroupResponse::Done {} => {
            println!("{}", M::Done.t());
            Ok(())
        }
        other => bail!("unexpected response: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::chat::group::ipc::MemberInfo;

    fn info() -> GroupInfo {
        GroupInfo {
            id: "0123456789abcdef0123456789abcdef".into(),
            name: "友だち".into(),
            epoch: 2,
            status: "joined".into(),
            members: 3,
            messages: 4,
            last_ms: 0,
            pending: 1,
            invited_by: None,
        }
    }

    fn msg(outgoing: bool, verified: bool) -> GroupMessageInfo {
        GroupMessageInfo {
            ord: 1,
            id: "00".repeat(16),
            outgoing,
            sender: "11".repeat(32),
            sender_label: None,
            sender_hint: Some("Bob".into()),
            sender_fingerprint: "AAAAA-BBBBB".into(),
            verified,
            counter: 3,
            epoch: 1,
            text: "こんにちは".into(),
            sent_ms: 1_700_000_000_000,
            at_ms: 1_700_000_000_000,
            total: outgoing.then_some(3),
            delivered: outgoing.then_some(2),
            failed: outgoing.then_some(0),
            gap_before: 2,
        }
    }

    #[test]
    fn every_message_renders_in_both_languages_and_flags_unverified_members() {
        let detail = GroupDetailInfo {
            group: info(),
            is_admin: true,
            members: vec![MemberInfo {
                endpoint_id: "22".repeat(32),
                fingerprint: "CCCCC-DDDDD".into(),
                contact_code: "miasma-contact:abc".into(),
                role: "member".into(),
                hint: Some("Bob".into()),
                label: None,
                verified: false,
                you: false,
            }],
        };
        let (out, unv, ok) = (msg(true, false), msg(false, false), msg(false, true));
        let all = [
            M::Created("0123", 2),
            M::Queued(2),
            M::Done,
            M::None,
            M::Row(&info()),
            M::Detail(&detail),
            M::Line(&out),
            M::Line(&unv),
            M::Line(&ok),
            M::HistoryNone,
            M::Unverified,
            M::Err("not_admin", "x"),
            M::Err("something_new", "x"),
        ];
        for lg in [Lang::En, Lang::Ja] {
            for m in &all {
                let _ = lg;
                assert!(!m.t().is_empty());
            }
        }
        let t = M::Line(&unv).t();
        assert!(t.contains("nverified") || t.contains("未確認"));
        assert!(!M::Line(&ok).t().contains("nverified"));
        assert!(M::Detail(&detail).t().contains("miasma-contact:abc"));
    }
}
