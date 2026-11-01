//! IPC surface of group chat, carried inside `ChatRequest::Group` /
//! `ChatResponse::Group`.
//!
//! People are named by contact (label, ID or endpoint ID) when they are added
//! to a group: an administrator can only invite their own contacts, because the
//! invitation travels over the private channel to that contact. A member who
//! is not a contact is shown with the contact code and fingerprint, so the
//! user can compare them with the person and add them with `contact add`;
//! nothing here ever adds a contact.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupRequest {
    /// Create a group of the named contacts (and yourself).
    Create {
        name: String,
        members: Vec<String>,
    },
    /// Every group on this device.
    List {},
    /// One group with its member list.
    Show {
        group: String,
    },
    /// Add contacts (admin only).
    Add {
        group: String,
        members: Vec<String>,
        admin: bool,
    },
    /// Remove a member (admin only).
    Remove {
        group: String,
        member: String,
    },
    /// Leave the group.
    Leave {
        group: String,
    },
    Send {
        group: String,
        text: String,
    },
    History {
        group: String,
        before: Option<u64>,
        limit: Option<u32>,
    },
    /// Say yes to an invitation.
    Accept {
        group: String,
    },
    /// Say no to an invitation, or delete a group you left or were removed from.
    Decline {
        group: String,
    },
    /// Read, or with `auto_join` set change, whether an invitation from a
    /// trusted administrator is accepted at once (`chat.group_auto_join`).
    /// The change applies to this running service; the caller saves it in
    /// `config.toml` for the next start.
    Settings {
        #[serde(default)]
        auto_join: Option<bool>,
    },
    /// Offer this device's recent messages to one current member (ADR-012).
    /// Opt-in: nothing is shared unless this is sent. At most one round per
    /// member per membership epoch; a repeat in the same epoch shares nothing.
    ShareHistory {
        group: String,
        member: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub epoch: u32,
    /// `invited`, `joined`, `left` or `removed`.
    pub status: String,
    pub members: u32,
    pub messages: u64,
    pub last_ms: u64,
    /// Copies of your messages still owed to members.
    pub pending: u32,
    /// For `invited`: who invited you.
    pub invited_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    pub endpoint_id: String,
    pub fingerprint: String,
    /// The text to give to `contact add`.
    pub contact_code: String,
    /// `admin` or `member`.
    pub role: String,
    /// What whoever added them calls them; self-declared, not verified.
    pub hint: Option<String>,
    /// The contact label, when this person is a trusted contact.
    pub label: Option<String>,
    /// True only for a trusted contact. False is shown as "unverified member".
    pub verified: bool,
    pub you: bool,
    /// What this device knows of the member's standing: `you`, `joined`,
    /// `invited` (listed, nothing shows yet that they joined), `unreachable`
    /// (see `reason`) or `no_group_support` (their Miasma must be updated).
    /// An older service sends none (read as `joined`).
    #[serde(default)]
    pub status: Option<String>,
    /// For `unreachable`: the delivery word (`no_route`, `connect_failed`,
    /// `connection_lost`, `not_allowed`, `send_disabled`, ...).
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDetailInfo {
    pub group: GroupInfo,
    pub members: Vec<MemberInfo>,
    pub is_admin: bool,
    /// The endpoint ID of the person who added you, when you joined through
    /// an invitation.
    #[serde(default)]
    pub added_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessageInfo {
    pub ord: u64,
    pub id: String,
    pub outgoing: bool,
    pub sender: String,
    pub sender_label: Option<String>,
    pub sender_hint: Option<String>,
    pub sender_fingerprint: String,
    /// The sender is a trusted contact (always false for your own messages).
    pub verified: bool,
    pub counter: u64,
    pub epoch: u32,
    pub text: String,
    pub sent_ms: u64,
    pub at_ms: u64,
    /// Your own message: members it was sent to, reached, and given up on.
    pub total: Option<u32>,
    pub delivered: Option<u32>,
    pub failed: Option<u32>,
    /// Messages of this sender before this one that have not arrived.
    pub gap_before: u64,
    /// Set when this message reached us as a hand-over from a current member
    /// (ADR-012): the endpoint ID of the member who shared it. The `sender`
    /// stays the original author; this names who passed it on. An older service
    /// sends none.
    #[serde(default)]
    pub shared_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupResponse {
    Created {
        id: String,
        recipients: u32,
    },
    Groups(Vec<GroupInfo>),
    Detail(GroupDetailInfo),
    Done {},
    /// The answer to [`GroupRequest::Settings`].
    Settings {
        auto_join: bool,
    },
    Queued {
        id: String,
        recipients: u32,
    },
    /// The answer to [`GroupRequest::ShareHistory`]: how many past messages were
    /// queued to offer (zero when a round was already served this epoch or there
    /// was nothing to share).
    Shared {
        offered: u32,
    },
    History {
        group: GroupInfo,
        messages: Vec<GroupMessageInfo>,
    },
    /// `kind` is stable (`unavailable`, `unknown_contact`, `send_disabled`,
    /// `unknown_group`, `ambiguous_group`, `not_joined`, `not_admin`,
    /// `not_member`, `already_member`, `too_many_groups`, `too_many_members`,
    /// `last_admin`, `queue_full`, `empty`, `too_big`, `bad_request`,
    /// `internal`); `message` is for people.
    Error {
        kind: String,
        message: String,
    },
}

#[cfg(feature = "iroh")]
mod run {
    use std::sync::Arc;

    use super::*;
    use crate::{
        chat::group::{
            engine::{GroupError, GroupSummary, MemberStatus},
            membership::Role,
            service::GroupService,
            state::Status,
        },
        push::{
            contact::{fingerprint, ContactCode},
            store::Contact,
        },
    };

    fn err(kind: &str, message: impl Into<String>) -> GroupResponse {
        GroupResponse::Error {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }

    fn from_error(e: GroupError) -> GroupResponse {
        let kind = match &e {
            GroupError::Empty => "empty",
            GroupError::TooBig => "too_big",
            GroupError::NotFound => "unknown_group",
            GroupError::Ambiguous => "ambiguous_group",
            GroupError::NotJoined => "not_joined",
            GroupError::NotAdmin => "not_admin",
            GroupError::NotMember => "not_member",
            GroupError::AlreadyMember => "already_member",
            GroupError::TooManyGroups => "too_many_groups",
            GroupError::TooManyMembers => "too_many_members",
            GroupError::LastAdmin => "last_admin",
            GroupError::QueueFull => "queue_full",
            GroupError::Invalid => "bad_request",
            GroupError::Storage(_) => "internal",
        };
        err(kind, e.to_string())
    }

    fn info_of(s: &GroupSummary) -> GroupInfo {
        GroupInfo {
            id: hex::encode(s.gid),
            name: s.name.clone(),
            epoch: s.epoch,
            status: s.status.name().to_owned(),
            members: s.members as u32,
            messages: s.messages,
            last_ms: s.last_ms,
            pending: s.pending as u32,
            invited_by: match s.status {
                Status::Pending { invited_by } => Some(hex::encode(invited_by)),
                _ => None,
            },
        }
    }

    /// Contacts named in a request, as `(endpoint id, label)`.
    fn contacts_named(
        svc: &Arc<GroupService>,
        names: &[String],
    ) -> Result<Vec<([u8; 32], String)>, GroupResponse> {
        let mut out: Vec<([u8; 32], String)> = Vec::new();
        for n in names {
            let Some(c) = svc.contacts().find(n) else {
                return Err(err("unknown_contact", format!("no contact \"{n}\"")));
            };
            if !c.allow_send {
                return Err(err(
                    "send_disabled",
                    format!("sending to \"{}\" is switched off", c.label),
                ));
            }
            let Some(id) = c.endpoint_bytes() else {
                return Err(err("unknown_contact", format!("no contact \"{n}\"")));
            };
            if !out.iter().any(|(i, _)| *i == id) {
                out.push((id, c.label));
            }
        }
        Ok(out)
    }

    /// A member of `gid` by contact, endpoint ID, fingerprint prefix or
    /// self-declared label.
    fn member_named(svc: &Arc<GroupService>, gid: &[u8; 16], sel: &str) -> Option<[u8; 32]> {
        let sel = sel.trim();
        let members = svc.core().members_of(gid);
        if let Some(c) = svc.contacts().find(sel) {
            if let Some(id) = c.endpoint_bytes() {
                if members.contains(&id) {
                    return Some(id);
                }
            }
        }
        if let Some(id) = hex::decode(sel)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            if members.contains(&id) {
                return Some(id);
            }
        }
        let flat: String = sel
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        if flat.len() >= 4 {
            let hits: Vec<[u8; 32]> = members
                .iter()
                .copied()
                .filter(|m| {
                    fingerprint(m)
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .collect::<String>()
                        .starts_with(&flat)
                })
                .collect();
            if hits.len() == 1 {
                return Some(hits[0]);
            }
        }
        None
    }

    fn label_of(svc: &Arc<GroupService>, id: &[u8; 32]) -> Option<String> {
        svc.contacts().by_endpoint(id).map(|c: Contact| c.label)
    }

    /// Handle one group request on a running service (tests call this directly).
    pub fn handle_with(svc: &Arc<GroupService>, req: GroupRequest) -> GroupResponse {
        let core = svc.core();
        let trusted = |id: &[u8; 32]| svc.is_trusted(id);
        let group = |sel: &str| core.resolve(sel);
        match req {
            GroupRequest::Create { name, members } => {
                let named = match contacts_named(svc, &members) {
                    Ok(n) => n,
                    Err(e) => return e,
                };
                match core.create(&name, &named, crate::chat::engine::now_ms()) {
                    Ok(gid) => {
                        let others: Vec<[u8; 32]> = named.iter().map(|(i, _)| *i).collect();
                        svc.kick_all(&others);
                        GroupResponse::Created {
                            id: hex::encode(gid),
                            recipients: others.len() as u32,
                        }
                    }
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::List {} => {
                GroupResponse::Groups(core.list().iter().map(info_of).collect())
            }
            GroupRequest::Show { group: sel } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                match core.detail(&gid, &trusted) {
                    Ok(d) => GroupResponse::Detail(GroupDetailInfo {
                        group: info_of(&d.summary),
                        is_admin: d.is_admin,
                        members: d
                            .members
                            .iter()
                            .map(|m| MemberInfo {
                                endpoint_id: hex::encode(m.id),
                                fingerprint: fingerprint(&m.id),
                                contact_code: ContactCode::new(m.id).to_string(),
                                role: match m.role {
                                    Role::Admin => "admin",
                                    Role::Member => "member",
                                }
                                .to_owned(),
                                hint: (!m.hint.is_empty()).then(|| m.hint.clone()),
                                label: label_of(svc, &m.id),
                                verified: m.verified,
                                you: m.you,
                                status: Some(m.status.name().to_owned()),
                                reason: match &m.status {
                                    MemberStatus::Unreachable(r) => Some(r.clone()),
                                    _ => None,
                                },
                            })
                            .collect(),
                        added_by: d.added_by.map(hex::encode),
                    }),
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::Add {
                group: sel,
                members,
                admin,
            } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                let named = match contacts_named(svc, &members) {
                    Ok(n) => n,
                    Err(e) => return e,
                };
                let new: Vec<([u8; 32], String, bool)> =
                    named.into_iter().map(|(i, l)| (i, l, admin)).collect();
                match core.add(&gid, &new) {
                    Ok(notify) => {
                        svc.kick_all(&notify);
                        GroupResponse::Done {}
                    }
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::Remove { group: sel, member } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                let Some(who) = member_named(svc, &gid, &member) else {
                    return err("not_member", format!("\"{member}\" is not in the group"));
                };
                match core.remove(&gid, &who) {
                    Ok(notify) => {
                        svc.kick_all(&notify);
                        GroupResponse::Done {}
                    }
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::Leave { group: sel } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                match core.leave(&gid) {
                    Ok(notify) => {
                        svc.kick_all(&notify);
                        GroupResponse::Done {}
                    }
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::Send { group: sel, text } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                match core.send(&gid, &text, crate::chat::engine::now_ms()) {
                    Ok(o) => {
                        svc.kick_all(&o.recipients);
                        GroupResponse::Queued {
                            id: hex::encode(o.id),
                            recipients: o.recipients.len() as u32,
                        }
                    }
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::History {
                group: sel,
                before,
                limit,
            } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                let own = core.own_id();
                let msgs = match core.history(&gid, before, limit.unwrap_or(50) as usize) {
                    Ok(m) => m,
                    Err(e) => return from_error(e),
                };
                let Some(summary) = core.list().into_iter().find(|s| s.gid == gid) else {
                    return from_error(GroupError::NotFound);
                };
                let members = core
                    .detail(&gid, &trusted)
                    .map(|d| d.members)
                    .unwrap_or_default();
                GroupResponse::History {
                    group: info_of(&summary),
                    messages: msgs
                        .into_iter()
                        .map(|v| {
                            let m = v.msg;
                            let hint = members
                                .iter()
                                .find(|x| x.id == m.sender)
                                .and_then(|x| (!x.hint.is_empty()).then(|| x.hint.clone()));
                            GroupMessageInfo {
                                ord: m.ord,
                                id: hex::encode(m.id),
                                outgoing: m.outgoing,
                                sender: hex::encode(m.sender),
                                sender_label: label_of(svc, &m.sender),
                                sender_hint: hint,
                                sender_fingerprint: fingerprint(&m.sender),
                                verified: m.sender != own && trusted(&m.sender),
                                counter: m.counter,
                                epoch: m.epoch,
                                text: m.text,
                                sent_ms: m.sent_ms,
                                at_ms: m.at_ms,
                                total: v.delivery.map(|d| u32::from(d.0)),
                                delivered: v.delivery.map(|d| u32::from(d.1)),
                                failed: v.delivery.map(|d| u32::from(d.2)),
                                gap_before: v.gap_before,
                                shared_by: m.shared_by.map(hex::encode),
                            }
                        })
                        .collect(),
                }
            }
            GroupRequest::Accept { group: sel } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                match core.accept_invite(&gid) {
                    Ok(wake) => {
                        svc.kick_all(&wake);
                        GroupResponse::Done {}
                    }
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::Settings { auto_join } => {
                if let Some(on) = auto_join {
                    core.set_auto_join(on);
                }
                GroupResponse::Settings {
                    auto_join: core.auto_join(),
                }
            }
            GroupRequest::Decline { group: sel } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                match core.forget(&gid) {
                    Ok(()) => GroupResponse::Done {},
                    Err(e) => from_error(e),
                }
            }
            GroupRequest::ShareHistory { group: sel, member } => {
                let gid = match group(&sel) {
                    Ok(g) => g,
                    Err(e) => return from_error(e),
                };
                let Some(who) = member_named(svc, &gid, &member) else {
                    return err("not_member", format!("\"{member}\" is not in the group"));
                };
                match core.handover(&gid, &who) {
                    Ok(out) => {
                        if let Some(wake) = out.wake {
                            svc.kick_all(&[wake]);
                        }
                        GroupResponse::Shared {
                            offered: out.offered as u32,
                        }
                    }
                    Err(e) => from_error(e),
                }
            }
        }
    }
}

#[cfg(feature = "iroh")]
pub use run::handle_with;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_responses_round_trip_as_json() {
        let r = GroupRequest::Create {
            name: "友だち".into(),
            members: vec!["alice".into(), "bob".into()],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(matches!(
            serde_json::from_str::<GroupRequest>(&s).unwrap(),
            GroupRequest::Create { .. }
        ));
        let l = serde_json::to_string(&GroupRequest::List {}).unwrap();
        assert!(serde_json::from_str::<GroupRequest>(&l).is_ok());
        let e = serde_json::to_string(&GroupResponse::Error {
            kind: "x".into(),
            message: "y".into(),
        })
        .unwrap();
        assert!(serde_json::from_str::<GroupResponse>(&e).is_ok());

        // ShareHistory request and its Shared answer round-trip too (ADR-012).
        let sh = serde_json::to_string(&GroupRequest::ShareHistory {
            group: "g1".into(),
            member: "bob".into(),
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<GroupRequest>(&sh).unwrap(),
            GroupRequest::ShareHistory { .. }
        ));
        let shared = serde_json::to_string(&GroupResponse::Shared { offered: 3 }).unwrap();
        assert!(matches!(
            serde_json::from_str::<GroupResponse>(&shared).unwrap(),
            GroupResponse::Shared { offered: 3 }
        ));
    }
}
