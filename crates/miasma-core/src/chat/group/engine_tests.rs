//! Group engine tests without a network: nodes hand sealed envelopes to each
//! other directly, the way the delivery workers do.

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use tempfile::TempDir;

use super::{
    engine::{GroupCore, GroupError, Work},
    membership::Role,
    record::{encode_descs, GroupText},
    state::Status,
    store::GroupStore,
};
use crate::{
    chat::{
        crypto::Identity,
        engine::ChatCore,
        outbox::Outbox,
        proto::AckStatus,
        store::{ChatStore, StoreSettings},
    },
    state_crypto::StateKeys,
};

struct Node {
    _dir: TempDir,
    path: PathBuf,
    seed: [u8; 32],
    master: [u8; 32],
    chat: Arc<ChatCore>,
    core: GroupCore,
    trust: Mutex<HashSet<[u8; 32]>>,
    online: bool,
}

fn open(path: &std::path::Path, seed: &[u8; 32], master: &[u8; 32]) -> (Arc<ChatCore>, GroupCore) {
    let keys = Arc::new(StateKeys::from_master_key(master).unwrap());
    let id = Identity::from_seed(seed);
    let chat_dir = path.join("chat");
    let s = StoreSettings::default();
    let store = ChatStore::open(&chat_dir, keys.clone(), id.id(), s.clone()).unwrap();
    let (outbox, _) = Outbox::open(
        &crate::paths::chat_outbox_file(&chat_dir),
        keys.clone(),
        s.clone(),
        1,
    );
    let chat = Arc::new(ChatCore::new(store, outbox, id, 4096));
    let gs = GroupStore::open(&chat_dir, keys, chat.own_id(), s).unwrap();
    let core = GroupCore::new(chat.clone(), gs, seed).expect("same identity");
    // Most of these tests are about answering an invitation; the ones about
    // joining at once switch it on.
    core.set_auto_join(false);
    (chat, core)
}

impl Node {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let seed: [u8; 32] = rand::random();
        let master: [u8; 32] = rand::random();
        let path = dir.path().to_path_buf();
        let (chat, core) = open(&path, &seed, &master);
        Self {
            _dir: dir,
            path,
            seed,
            master,
            chat,
            core,
            trust: Mutex::new(HashSet::new()),
            online: true,
        }
    }

    fn id(&self) -> [u8; 32] {
        self.core.own_id()
    }

    fn trusts(&self, other: &Node) {
        self.trust.lock().unwrap().insert(other.id());
    }

    fn is_trusted(&self, id: &[u8; 32]) -> bool {
        self.trust.lock().unwrap().contains(id)
    }

    fn restart(&mut self) {
        self.core.close();
        self.chat.store.close();
        let (chat, core) = open(&self.path, &self.seed, &self.master);
        self.chat = chat;
        self.core = core;
    }

    fn gid_of(&self, name: &str) -> [u8; 16] {
        self.core.resolve(name).unwrap()
    }

    fn texts(&self, gid: &[u8; 16]) -> Vec<String> {
        self.core
            .history(gid, None, 200)
            .unwrap()
            .into_iter()
            .map(|v| v.msg.text)
            .collect()
    }
}

/// Everyone trusts everyone (a group of friends who all registered each other).
fn friends(n: usize) -> Vec<Node> {
    let nodes: Vec<Node> = (0..n).map(|_| Node::new()).collect();
    for a in &nodes {
        for b in &nodes {
            if a.id() != b.id() {
                a.trusts(b);
            }
        }
    }
    nodes
}

/// Deliver everything owed, between online nodes, until nothing moves.
/// Returns every acknowledgement given as (from index, to index, status).
fn pump(nodes: &[Node]) -> Vec<(usize, usize, AckStatus)> {
    let mut log = Vec::new();
    for _ in 0..60 {
        let mut moved = false;
        for (i, from) in nodes.iter().enumerate() {
            if !from.online {
                continue;
            }
            for (j, to) in nodes.iter().enumerate() {
                if i == j || !to.online {
                    continue;
                }
                while let Some(out) = from.core.next_for(&to.id()) {
                    let (wire, _) = from.chat.seal_for(&to.id(), &out.plain).unwrap();
                    let trusted = |id: &[u8; 32]| to.is_trusted(id);
                    let acc = to.core.accept(&from.id(), &wire, 1_000, &trusted);
                    log.push((i, j, acc.status));
                    match acc.status {
                        AckStatus::Stored | AckStatus::Duplicate => {
                            from.core.delivered(&to.id(), &out.work);
                            moved = true;
                        }
                        AckStatus::NotAllowed
                        | AckStatus::TooBig
                        | AckStatus::Unsupported
                        | AckStatus::BadRequest => {
                            from.core.gave_up(&to.id(), &out.work);
                            moved = true;
                        }
                        // Try again after the others have moved.
                        _ => break,
                    }
                }
            }
        }
        if !moved {
            break;
        }
    }
    log
}

/// Create a group on `nodes[0]` of the others and let everyone accept.
fn make_group(nodes: &[Node], name: &str) -> [u8; 16] {
    let members: Vec<([u8; 32], String)> =
        nodes[1..].iter().map(|n| (n.id(), String::new())).collect();
    let gid = nodes[0].core.create(name, &members, 100).unwrap();
    pump(nodes);
    for n in &nodes[1..] {
        assert!(
            matches!(n.core.status_of(&gid), Some(Status::Pending { .. })),
            "invited, not joined"
        );
        n.core.accept_invite(&gid).unwrap();
    }
    pump(nodes);
    gid
}

#[test]
fn create_invite_join_and_everybody_receives() {
    let nodes = friends(3);
    let gid = make_group(&nodes, "friends");
    for n in &nodes {
        assert_eq!(n.core.members_of(&gid).len(), 3);
        assert_eq!(n.core.list()[0].epoch, 1);
    }
    nodes[0].core.send(&gid, "hello all", 200).unwrap();
    nodes[1].core.send(&gid, "こんにちは", 300).unwrap();
    pump(&nodes);
    for n in &nodes {
        let mut t = n.texts(&gid);
        t.sort();
        assert_eq!(t, vec!["hello all".to_owned(), "こんにちは".to_owned()]);
    }
    // The sender sees how far its message got.
    let h = nodes[0].core.history(&gid, None, 10).unwrap();
    let mine = h.iter().find(|v| v.msg.outgoing).unwrap();
    assert_eq!(mine.delivery, Some((2, 2, 0)));
    assert_eq!(nodes[0].core.list()[0].pending, 0);
}

#[test]
fn add_remove_and_leave_advance_the_epoch_for_everyone() {
    let nodes = friends(4);
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let gid = make_group(&nodes[..3], "trio");
    // d was never invited; a adds d.
    a.core.add(&gid, &[(d.id(), "dee".into(), false)]).unwrap();
    pump(&nodes);
    assert_eq!(a.core.list()[0].epoch, 2);
    assert!(matches!(
        d.core.status_of(&gid),
        Some(Status::Pending { .. })
    ));
    d.core.accept_invite(&gid).unwrap();
    pump(&nodes);
    for n in &nodes {
        assert_eq!(n.core.members_of(&gid).len(), 4);
    }
    // a removes c.
    a.core.remove(&gid, &c.id()).unwrap();
    pump(&nodes);
    assert_eq!(c.core.status_of(&gid), Some(Status::Removed));
    for n in [a, b, d] {
        assert_eq!(n.core.members_of(&gid).len(), 3);
        assert_eq!(n.core.list()[0].epoch, 3);
    }
    // b leaves by its own signature.
    b.core.leave(&gid).unwrap();
    pump(&nodes);
    assert_eq!(b.core.status_of(&gid), Some(Status::Left));
    for n in [a, d] {
        assert_eq!(n.core.members_of(&gid).len(), 2);
        assert_eq!(n.core.list()[0].epoch, 4);
    }
    // A plain member cannot remove anyone or add anyone.
    assert_eq!(d.core.remove(&gid, &a.id()), Err(GroupError::NotAdmin));
    assert!(matches!(
        d.core.add(&gid, &[([9; 32], String::new(), false)]),
        Err(GroupError::NotAdmin)
    ));
    // The only admin cannot leave while others remain.
    assert_eq!(a.core.leave(&gid), Err(GroupError::LastAdmin));
}

#[test]
fn a_removed_member_receives_nothing_after_the_removal() {
    let nodes = friends(3);
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let gid = make_group(&nodes, "g");
    a.core.send(&gid, "before", 10).unwrap();
    pump(&nodes);
    assert_eq!(c.texts(&gid), vec!["before".to_owned()]);

    // A message is still waiting for c when c is removed: it is dropped.
    a.core.send(&gid, "queued for everyone", 20).unwrap();
    a.core.remove(&gid, &c.id()).unwrap();
    assert!(a.core.list()[0].pending > 0);
    pump(&nodes);
    assert_eq!(c.core.status_of(&gid), Some(Status::Removed));
    assert_eq!(a.core.list()[0].pending, 0);
    assert_eq!(b.texts(&gid).len(), 2);
    assert_eq!(c.texts(&gid), vec!["before".to_owned()]);

    // Later messages never go to c, and c's replies are refused.
    a.core.send(&gid, "after", 30).unwrap();
    assert!(a.core.next_for(&c.id()).is_none());
    pump(&nodes);
    assert_eq!(c.texts(&gid), vec!["before".to_owned()]);
    assert!(b.texts(&gid).contains(&"after".to_owned()));
    assert!(matches!(
        c.core.send(&gid, "still here?", 40),
        Err(GroupError::NotJoined)
    ));
}

#[test]
fn a_removed_member_that_missed_the_removal_cannot_write() {
    let mut nodes = friends(3);
    let gid = make_group(&nodes, "g");
    nodes[2].online = false;
    nodes[0].core.remove(&gid, &nodes[2].id()).unwrap();
    pump(&nodes);
    // c has not heard of it and writes under the old epoch.
    nodes[2].online = true;
    let wire = {
        let t = GroupText {
            gid,
            epoch: 1,
            counter: 1,
            id: rand::random(),
            sent_ms: 5,
            text: "let me in".into(),
        };
        nodes[2]
            .chat
            .seal_for(&nodes[0].id(), &t.encode().unwrap())
            .unwrap()
            .0
    };
    let a = &nodes[0];
    let acc = a
        .core
        .accept(&nodes[2].id(), &wire, 6, &|id| a.is_trusted(id));
    assert_eq!(acc.status, AckStatus::NotAllowed);
    assert!(!a.texts(&gid).contains(&"let me in".to_owned()));
}

#[test]
fn duplicates_and_out_of_order_delivery_apply_once() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    let gid = make_group(&nodes, "pair");
    for (i, t) in ["one", "two", "three"].iter().enumerate() {
        a.core.send(&gid, t, 100 + i as u64).unwrap();
    }
    // Seal the three copies but hold them back.
    let mut held = Vec::new();
    while let Some(out) = a.core.next_for(&b.id()) {
        let (wire, _) = a.chat.seal_for(&b.id(), &out.plain).unwrap();
        a.core.delivered(&b.id(), &out.work);
        held.push((wire, out.plain));
    }
    assert_eq!(held.len(), 3);
    let trusted = |id: &[u8; 32]| b.is_trusted(id);
    // Third, first, second.
    for k in [2usize, 0, 1] {
        let st = b.core.accept(&a.id(), &held[k].0, 9, &trusted).status;
        assert_eq!(st, AckStatus::Stored, "copy {k}");
    }
    let mut t = b.texts(&gid);
    t.sort();
    assert_eq!(t, vec!["one", "three", "two"]);
    assert_eq!(b.core.vector_of(&gid, &a.id()), Some((3, 3, 0)));
    // The same envelope again is a duplicate.
    assert_eq!(
        b.core.accept(&a.id(), &held[0].0, 10, &trusted).status,
        AckStatus::Duplicate
    );
    // The same record in a new envelope (a resend) is applied once.
    let (again, _) = a.chat.seal_for(&b.id(), &held[1].1).unwrap();
    assert_eq!(
        b.core.accept(&a.id(), &again, 11, &trusted).status,
        AckStatus::Duplicate
    );
    assert_eq!(b.texts(&gid).len(), 3);
}

#[test]
fn a_missing_message_shows_as_a_gap() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    let gid = make_group(&nodes, "pair");
    for t in ["one", "two", "three"] {
        a.core.send(&gid, t, 100).unwrap();
    }
    let trusted = |id: &[u8; 32]| b.is_trusted(id);
    let mut k = 0;
    while let Some(out) = a.core.next_for(&b.id()) {
        let (wire, _) = a.chat.seal_for(&b.id(), &out.plain).unwrap();
        a.core.delivered(&b.id(), &out.work);
        if k != 1 {
            b.core.accept(&a.id(), &wire, 9, &trusted);
        }
        k += 1;
    }
    assert_eq!(b.core.vector_of(&gid, &a.id()), Some((1, 3, 1)));
    let h = b.core.history(&gid, None, 10).unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].gap_before, 0);
    assert_eq!(h[1].gap_before, 1);
}

#[test]
fn a_member_who_is_not_trusted_stays_unverified_and_is_limited() {
    let nodes = friends(3);
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // c does not trust b (never pressed "add" for b).
    c.trust.lock().unwrap().remove(&b.id());
    let gid = make_group(&nodes, "mixed");
    let detail = c.core.detail(&gid, &|id| c.is_trusted(id)).unwrap();
    let seen = |who: &Node| detail.members.iter().find(|m| m.id == who.id()).unwrap();
    assert!(seen(a).verified);
    assert!(!seen(b).verified, "listed, but not a trusted contact");
    assert!(seen(c).you);
    // Being in the group did not touch c's trust.
    assert!(!c.is_trusted(&b.id()));
    // b can write short text, which c shows as from an unverified member.
    b.core.send(&gid, "hi from b", 10).unwrap();
    pump(&nodes);
    assert!(c.texts(&gid).contains(&"hi from b".to_owned()));
    // A long text from an unverified member is refused.
    let long = "x".repeat(super::engine::UNVERIFIED_MAX_TEXT + 1);
    b.core.send(&gid, &long, 20).unwrap();
    let log = pump(&nodes);
    assert!(log.iter().any(|l| l.1 == 2 && l.2 == AckStatus::TooBig));
    assert!(!c.texts(&gid).contains(&long));
    assert!(a.texts(&gid).contains(&long), "a trusts b");
    // Once c adds b for itself, the member is verified.
    c.trusts(b);
    let detail = c.core.detail(&gid, &|id| c.is_trusted(id)).unwrap();
    assert!(
        detail
            .members
            .iter()
            .find(|m| m.id == b.id())
            .unwrap()
            .verified
    );
}

#[test]
fn an_invitation_from_someone_who_is_not_trusted_creates_nothing() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.trust.lock().unwrap().clear();
    a.core
        .create("surprise", &[(b.id(), String::new())], 1)
        .unwrap();
    let log = pump(&nodes);
    assert!(log.iter().all(|l| l.2 == AckStatus::NotAllowed));
    assert!(b.core.list().is_empty());
}

#[test]
fn forged_membership_changes_are_rejected() {
    let nodes = friends(4);
    let (a, b, c, e) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let gid = make_group(&nodes[..3], "g");
    let before = b.core.list()[0].epoch;
    let trusted = |id: &[u8; 32]| b.is_trusted(id);

    // Descriptors signed by a plain member (c) or an outsider (e) that add e.
    for forger in [c, e] {
        let key = ed25519_dalek::SigningKey::from_bytes(&forger.seed);
        let latest = chain_of(a, &gid);
        let mut members = latest.members.clone();
        members.push(super::membership::Member {
            id: e.id(),
            role: Role::Admin,
            hint: String::new(),
        });
        let forged = super::membership::Descriptor {
            gid,
            epoch: latest.epoch + 1,
            name: latest.name.clone(),
            created_ms: latest.created_ms,
            prev_hash: latest.hash(),
            members,
            signer: [0; 32],
            sig: [0; 64],
        }
        .signed(&key);
        let plain = encode_descs(&[forged]).unwrap();
        let (wire, _) = forger.chat.seal_for(&b.id(), &plain).unwrap();
        let st = b.core.accept(&forger.id(), &wire, 5, &trusted).status;
        assert_eq!(st, AckStatus::NotAllowed, "forger accepted");
    }

    // A real descriptor with one byte changed no longer verifies.
    let latest = chain_of(a, &gid);
    a.core.add(&gid, &[(e.id(), String::new(), false)]).unwrap();
    let real = chain_of(a, &gid);
    let mut raw = real.encode();
    let n = raw.len();
    raw[n - 70] ^= 1; // inside the signed part
    if let Ok(tampered) = super::membership::Descriptor::decode(&raw) {
        let plain = encode_descs(&[tampered]).unwrap();
        let (wire, _) = a.chat.seal_for(&b.id(), &plain).unwrap();
        assert_eq!(
            b.core.accept(&a.id(), &wire, 5, &trusted).status,
            AckStatus::NotAllowed
        );
    }
    let _ = latest;
    assert_eq!(b.core.list()[0].epoch, before);
    assert!(!b.core.members_of(&gid).contains(&e.id()));

    // The genuine change is accepted, and replaying it is a duplicate.
    pump(&nodes[..3]);
    assert_eq!(b.core.list()[0].epoch, before + 1);
    let plain = encode_descs(&[real]).unwrap();
    let (wire, _) = a.chat.seal_for(&b.id(), &plain).unwrap();
    assert_eq!(
        b.core.accept(&a.id(), &wire, 6, &trusted).status,
        AckStatus::Duplicate
    );
}

fn chain_of(n: &Node, gid: &[u8; 16]) -> super::membership::Descriptor {
    // The newest descriptor, as it is sent to a peer.
    let _ = (n, gid);
    n.core.latest_descriptor(gid).unwrap()
}

#[test]
fn a_sender_ahead_of_us_asks_for_the_missing_epoch_and_the_text_follows() {
    let mut nodes = friends(3);
    let gid = make_group(&nodes, "g");
    nodes[1].online = false;
    let d = Node::new();
    let (a, b) = (&nodes[0], &nodes[1]);
    a.core.add(&gid, &[(d.id(), String::new(), false)]).unwrap();
    a.core.send(&gid, "news at epoch 2", 10).unwrap();
    // The text reaches b before the descriptor that b is missing.
    let text = GroupText {
        gid,
        epoch: 2,
        counter: 1,
        id: rand::random(),
        sent_ms: 10,
        text: "news at epoch 2".into(),
    };
    let (wire, _) = a.chat.seal_for(&b.id(), &text.encode().unwrap()).unwrap();
    let trusted = |id: &[u8; 32]| b.is_trusted(id);
    let acc = b.core.accept(&a.id(), &wire, 11, &trusted);
    assert_eq!(acc.status, AckStatus::Busy);
    assert_eq!(acc.kick, vec![a.id()]);
    assert!(matches!(
        b.core.next_for(&a.id()).map(|o| o.work),
        Some(Work::Sync { .. })
    ));
    assert!(b.texts(&gid).is_empty());
    // b asks, is brought up to date, and the text follows.
    nodes[1].online = true;
    pump(&nodes);
    assert_eq!(nodes[1].core.list()[0].epoch, 2);
    assert_eq!(nodes[1].texts(&gid), vec!["news at epoch 2".to_owned()]);
}

#[test]
fn thirty_two_members_fit_and_a_thirty_third_does_not() {
    let a = Node::new();
    let others: Vec<([u8; 32], String)> = (0..31)
        .map(|_| (Identity::from_seed(&rand::random()).id(), String::new()))
        .collect();
    let gid = a.core.create("big", &others, 1).unwrap();
    assert_eq!(a.core.members_of(&gid).len(), 32);
    assert_eq!(
        a.core.add(
            &gid,
            &[(
                Identity::from_seed(&rand::random()).id(),
                String::new(),
                false
            )]
        ),
        Err(GroupError::TooManyMembers)
    );
    let mut more = others.clone();
    more.push((Identity::from_seed(&rand::random()).id(), String::new()));
    assert_eq!(
        a.core.create("bigger", &more, 1),
        Err(GroupError::TooManyMembers)
    );
    // One message is queued for 31 members, each with its own copy.
    let o = a.core.send(&gid, "to everyone", 2).unwrap();
    assert_eq!(o.recipients.len(), 31);
    let mut sealed = HashSet::new();
    for (id, _) in &others {
        let out = a.core.next_for(id).unwrap();
        assert!(matches!(out.work, Work::Descs { .. }));
        let (wire, _) = a.chat.seal_for(id, &out.plain).unwrap();
        assert!(sealed.insert(wire), "every copy is sealed separately");
    }
}

#[test]
fn groups_and_pending_messages_survive_a_restart() {
    let mut nodes = friends(3);
    let gid = make_group(&nodes, "keep");
    nodes[0].core.send(&gid, "delivered", 10).unwrap();
    pump(&nodes);
    // c is away; a message waits for it.
    nodes[2].online = false;
    nodes[0].core.send(&gid, "waiting for c", 20).unwrap();
    nodes[1].core.send(&gid, "from b", 30).unwrap();
    pump(&nodes);
    for n in &mut nodes {
        n.restart();
    }
    assert_eq!(nodes[0].gid_of("keep"), gid);
    assert_eq!(nodes[0].core.list()[0].pending, 1);
    assert_eq!(nodes[1].core.vector_of(&gid, &nodes[0].id()).unwrap().0, 2);
    let mut t = nodes[1].texts(&gid);
    t.sort();
    assert_eq!(t, vec!["delivered", "from b", "waiting for c"]);
    // After the restart c comes back and receives what it missed, once.
    nodes[2].online = true;
    pump(&nodes);
    let mut t = nodes[2].texts(&gid);
    t.sort();
    assert_eq!(t, vec!["delivered", "from b", "waiting for c"]);
    assert_eq!(nodes[0].core.list()[0].pending, 0);
    // New messages keep counting from where the old ones stopped.
    nodes[0].core.send(&gid, "after restart", 40).unwrap();
    pump(&nodes);
    assert_eq!(nodes[2].core.vector_of(&gid, &nodes[0].id()).unwrap().0, 3);
}

#[test]
fn history_on_disk_is_encrypted_and_a_group_can_be_forgotten() {
    let nodes = friends(2);
    let gid = make_group(&nodes, "secret group");
    nodes[0]
        .core
        .send(&gid, "GROUP-SECRET-TEXT-98765", 10)
        .unwrap();
    pump(&nodes);
    for n in &nodes {
        n.core.close();
    }
    for n in &nodes {
        for e in std::fs::read_dir(n.path.join("chat")).unwrap().flatten() {
            if e.path().is_file() {
                let bytes = std::fs::read(e.path()).unwrap();
                let s = String::from_utf8_lossy(&bytes);
                assert!(!s.contains("GROUP-SECRET-TEXT"));
                assert!(!s.contains("secret group"));
            }
        }
    }
    // Leaving keeps the history until the group is forgotten.
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.leave(&gid).unwrap();
    assert_eq!(b.core.status_of(&gid), Some(Status::Left));
    assert_eq!(b.texts(&gid), vec!["GROUP-SECRET-TEXT-98765".to_owned()]);
    assert!(b.core.store().history_file_exists(&gid));
    // A group one is still in cannot be forgotten.
    assert!(matches!(a.core.forget(&gid), Err(GroupError::Invalid)));
    b.core.forget(&gid).unwrap();
    assert!(b.core.list().is_empty());
    assert!(!b.core.store().history_file_exists(&gid));
}

// -- Joining without asking, and who has joined -------------------------------

use super::engine::{GroupEventKind, MemberStatus, MAX_GROUPS};

fn status_of_member(viewer: &Node, gid: &[u8; 16], who: &Node) -> MemberStatus {
    viewer
        .core
        .detail(gid, &|id| viewer.is_trusted(id))
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.id == who.id())
        .unwrap()
        .status
}

#[test]
fn an_invitation_from_a_trusted_admin_joins_at_once_by_default() {
    let nodes = friends(3);
    for n in &nodes {
        n.core.set_auto_join(true);
    }
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let members: Vec<([u8; 32], String)> = vec![(b.id(), String::new()), (c.id(), String::new())];
    let gid = a.core.create("friends", &members, 100).unwrap();
    pump(&nodes);
    for n in [b, c] {
        assert_eq!(n.core.status_of(&gid), Some(Status::Joined));
        let d = n.core.detail(&gid, &|id| n.is_trusted(id)).unwrap();
        assert_eq!(
            d.added_by,
            Some(a.id()),
            "the system line needs to know who"
        );
    }
    assert_eq!(a.core.detail(&gid, &|_| true).unwrap().added_by, None);
    // Nobody pressed anything: messages flow both ways.
    a.core.send(&gid, "hello", 200).unwrap();
    b.core.send(&gid, "hi", 210).unwrap();
    pump(&nodes);
    for n in &nodes {
        assert_eq!(n.texts(&gid).len(), 2, "everyone has both");
    }
    // The people who added and were added see each other as joined.
    assert_eq!(status_of_member(a, &gid, c), MemberStatus::Joined);
    assert_eq!(status_of_member(c, &gid, b), MemberStatus::Joined);
}

#[test]
fn joining_at_once_is_announced_and_survives_a_restart() {
    let mut nodes = friends(2);
    nodes[1].core.set_auto_join(true);
    let gid = nodes[0]
        .core
        .create("pair", &[(nodes[1].id(), String::new())], 1)
        .unwrap();
    pump(&nodes);
    let (_, ev) = nodes[1].core.events_since(0);
    assert!(ev
        .iter()
        .any(|e| e.gid == gid && e.kind == GroupEventKind::Joined));
    assert!(!ev.iter().any(|e| e.kind == GroupEventKind::Invited));
    nodes[1].restart();
    let b = &nodes[1];
    assert_eq!(b.core.status_of(&gid), Some(Status::Joined));
    let d = b.core.detail(&gid, &|id| b.is_trusted(id)).unwrap();
    assert_eq!(d.added_by, Some(nodes[0].id()));
}

#[test]
fn an_invitation_from_someone_who_is_not_trusted_is_still_refused_when_joining_at_once() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.set_auto_join(true);
    b.trust.lock().unwrap().clear();
    a.core
        .create("surprise", &[(b.id(), String::new())], 1)
        .unwrap();
    let log = pump(&nodes);
    assert!(log.iter().all(|l| l.2 == AckStatus::NotAllowed));
    assert!(b.core.list().is_empty());
    assert_eq!(a.core.list()[0].pending, 0);
}

#[test]
fn an_invitation_from_a_member_who_is_no_admin_is_refused_when_joining_at_once() {
    let nodes = friends(3);
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    for n in &nodes {
        n.core.set_auto_join(true);
    }
    let gid = a.core.create("g", &[(b.id(), String::new())], 1).unwrap();
    pump(&nodes);
    assert_eq!(b.core.status_of(&gid), Some(Status::Joined));
    // b is a plain member and may not add anyone.
    assert_eq!(
        b.core.add(&gid, &[(c.id(), String::new(), false)]),
        Err(GroupError::NotAdmin)
    );
    pump(&nodes);
    assert!(c.core.status_of(&gid).is_none());
}

#[test]
fn asking_first_keeps_the_invitation_pending_until_it_is_answered() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.set_auto_join(false);
    let gid = a
        .core
        .create("ask me", &[(b.id(), String::new())], 1)
        .unwrap();
    pump(&nodes);
    assert!(matches!(
        b.core.status_of(&gid),
        Some(Status::Pending { invited_by }) if invited_by == a.id()
    ));
    let (_, ev) = b.core.events_since(0);
    assert!(ev.iter().any(|e| e.kind == GroupEventKind::Invited));
    // Nothing about the invitation shows the inviter that b joined.
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Invited);
    // Answering yes makes b a member and tells the others.
    let wake = b.core.accept_invite(&gid).unwrap();
    assert_eq!(wake, vec![a.id()]);
    pump(&nodes);
    assert_eq!(b.core.status_of(&gid), Some(Status::Joined));
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Joined);
    assert_eq!(
        b.core.detail(&gid, &|_| true).unwrap().added_by,
        Some(a.id())
    );
}

#[test]
fn a_message_to_a_member_who_has_not_joined_is_held_and_delivered_when_they_join() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.set_auto_join(false);
    let gid = a
        .core
        .create("held", &[(b.id(), String::new())], 1)
        .unwrap();
    pump(&nodes);
    a.core.send(&gid, "before you joined", 10).unwrap();
    a.core.send(&gid, "me again", 20).unwrap();
    let log = pump(&nodes);
    assert!(
        log.iter().any(|l| l.2 == AckStatus::Busy),
        "the device that has not joined says busy, not refused"
    );
    assert_eq!(a.core.list()[0].pending, 2, "both copies are kept");
    assert!(b.texts(&gid).is_empty());
    // The sender's ledger does not count them as failed while they wait.
    let h = a.core.history(&gid, None, 10).unwrap();
    assert!(h.iter().all(|v| v.delivery == Some((1, 0, 0))));
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Invited);

    b.core.accept_invite(&gid).unwrap();
    pump(&nodes);
    assert_eq!(b.texts(&gid), vec!["before you joined", "me again"]);
    assert_eq!(a.core.list()[0].pending, 0);
    let h = a.core.history(&gid, None, 10).unwrap();
    assert!(h.iter().all(|v| v.delivery == Some((1, 1, 0))));
}

#[test]
fn a_held_message_is_given_up_when_the_invitation_is_declined() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.set_auto_join(false);
    let gid = a.core.create("no", &[(b.id(), String::new())], 1).unwrap();
    pump(&nodes);
    a.core.send(&gid, "anyone?", 10).unwrap();
    pump(&nodes);
    assert_eq!(a.core.list()[0].pending, 1);
    b.core.forget(&gid).unwrap();
    pump(&nodes);
    // b no longer holds the group and refuses, so the copy is not kept for ever.
    assert_eq!(a.core.list()[0].pending, 0);
    let h = a.core.history(&gid, None, 10).unwrap();
    assert_eq!(h[0].delivery, Some((1, 0, 1)));
}

#[test]
fn the_waiting_queue_of_a_group_is_bounded() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.set_auto_join(false);
    let gid = a
        .core
        .create("full", &[(b.id(), String::new())], 1)
        .unwrap();
    pump(&nodes);
    let mut last = Ok(());
    for i in 0..200u64 {
        last = a.core.send(&gid, "x", i).map(|_| ());
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(GroupError::QueueFull));
}

#[test]
fn what_is_known_of_each_member_follows_what_the_network_said() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.core.set_auto_join(false);
    let gid = a
        .core
        .create("status", &[(b.id(), String::new())], 1)
        .unwrap();
    assert_eq!(status_of_member(a, &gid, a), MemberStatus::You);
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Invited);
    // Their software has no groups: the delivery word is "peer_no_group".
    a.core.note_delivery(&b.id(), Some("peer_no_group"));
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::NoGroupSupport);
    a.core.note_delivery(&b.id(), Some("unsupported"));
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::NoGroupSupport);
    // Any other failure is "cannot reach", with the word.
    a.core.note_delivery(&b.id(), Some("no_route"));
    assert_eq!(
        status_of_member(a, &gid, b),
        MemberStatus::Unreachable("no_route".into())
    );
    a.core.note_delivery(&b.id(), Some("not_allowed"));
    assert_eq!(
        status_of_member(a, &gid, b),
        MemberStatus::Unreachable("not_allowed".into())
    );
    // Reaching them again clears it.
    a.core.note_delivery(&b.id(), None);
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Invited);
    // Once they are known to be in, later network trouble does not unjoin them.
    pump(&nodes);
    b.core.accept_invite(&gid).unwrap();
    pump(&nodes);
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Joined);
    a.core.note_delivery(&b.id(), Some("no_route"));
    assert_eq!(status_of_member(a, &gid, b), MemberStatus::Joined);
    assert_eq!(MemberStatus::NoGroupSupport.name(), "no_group_support");
}

#[test]
fn being_added_again_after_leaving_joins_at_once_or_asks_as_set() {
    for auto in [true, false] {
        let nodes = friends(2);
        let (a, b) = (&nodes[0], &nodes[1]);
        b.core.set_auto_join(true);
        let gid = a
            .core
            .create("again", &[(b.id(), String::new())], 1)
            .unwrap();
        pump(&nodes);
        assert_eq!(b.core.status_of(&gid), Some(Status::Joined));
        b.core.leave(&gid).unwrap();
        pump(&nodes);
        assert_eq!(b.core.status_of(&gid), Some(Status::Left));
        b.core.set_auto_join(auto);
        a.core.add(&gid, &[(b.id(), String::new(), false)]).unwrap();
        pump(&nodes);
        if auto {
            assert_eq!(b.core.status_of(&gid), Some(Status::Joined));
            assert_eq!(
                b.core.detail(&gid, &|_| true).unwrap().added_by,
                Some(a.id())
            );
        } else {
            assert!(matches!(
                b.core.status_of(&gid),
                Some(Status::Pending { .. })
            ));
        }
    }
}

#[test]
fn the_limit_on_groups_still_applies_when_joining_at_once() {
    // Two creators invite the same person into more groups than a device holds.
    let nodes = friends(3);
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    c.core.set_auto_join(true);
    let each = MAX_GROUPS / 2 + 1;
    for i in 0..each {
        a.core
            .create(&format!("a{i}"), &[(c.id(), String::new())], 1)
            .unwrap();
        b.core
            .create(&format!("b{i}"), &[(c.id(), String::new())], 1)
            .unwrap();
    }
    pump(&nodes);
    assert_eq!(c.core.list().len(), MAX_GROUPS);
}

// -- Handing recent messages to an added member (ADR-012) ---------------------

use super::engine::MAX_HIST_PER_HANDOVER;

/// A member added after messages were sent sees none of the past by default,
/// and sees it only once a current member explicitly hands it over. The shared
/// copies are attributed to their author but marked as shared by the sharer.
#[test]
fn history_is_handed_over_only_when_a_member_chooses_to() {
    let mut nodes = friends(3);
    let gid = make_group(&nodes[..2], "pair");
    nodes[0].core.send(&gid, "old one", 10).unwrap();
    nodes[1].core.send(&gid, "old two", 20).unwrap();
    pump(&nodes[..2]);
    // A third person is added after those messages; they catch up on the live
    // membership but not the past.
    let d = &nodes[2];
    nodes[0]
        .core
        .add(&gid, &[(d.id(), String::new(), false)])
        .unwrap();
    pump(&nodes);
    nodes[2].core.accept_invite(&gid).unwrap();
    pump(&nodes);
    assert!(
        nodes[2].texts(&gid).is_empty(),
        "the past is not shared on its own"
    );
    // nodes[0] chooses to share its recent history with the new member.
    let out = nodes[0].core.handover(&gid, &nodes[2].id()).unwrap();
    assert_eq!(out.offered, 2, "both past messages are offered");
    assert_eq!(out.wake, Some(nodes[2].id()));
    pump(&nodes);
    let mut t = nodes[2].texts(&gid);
    t.sort();
    assert_eq!(t, vec!["old one".to_owned(), "old two".to_owned()]);
    // The shared copies name who handed them over, and keep their author.
    let h = nodes[2].core.history(&gid, None, 10).unwrap();
    let shared = h.iter().find(|v| v.msg.text == "old two").unwrap();
    assert_eq!(shared.msg.shared_by, Some(nodes[0].id()));
    assert_eq!(shared.msg.sender, nodes[1].id(), "author is preserved");
    let _ = &mut nodes;
}

/// A hand-over runs at most once per target per epoch, and a repeat in the same
/// epoch does nothing.
#[test]
fn a_second_handover_in_the_same_epoch_does_nothing() {
    let nodes = friends(2);
    let gid = make_group(&nodes, "pair");
    nodes[0].core.send(&gid, "one", 10).unwrap();
    pump(&nodes);
    let first = nodes[0].core.handover(&gid, &nodes[1].id()).unwrap();
    assert_eq!(first.offered, 1);
    let again = nodes[0].core.handover(&gid, &nodes[1].id()).unwrap();
    assert_eq!(again.offered, 0, "one round per epoch");
    assert_eq!(again.wake, None);
}

/// Hand-over refuses a non-member and this device itself, and never offers a
/// message back to its own author or passes on a message shared to us.
#[test]
fn handover_refuses_a_non_member_and_skips_the_authors_own_and_reshared() {
    let nodes = friends(3);
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // a and b are members from the start and both hold the two live messages;
    // c is added only afterwards, so c holds none of the past on its own.
    let gid = make_group(&nodes[..2], "trio");
    a.core.send(&gid, "from a", 10).unwrap();
    b.core.send(&gid, "from b", 20).unwrap();
    pump(&nodes[..2]);
    // A non-member and oneself are refused.
    assert_eq!(
        a.core.handover(&gid, &[42u8; 32]),
        Err(GroupError::NotMember)
    );
    assert_eq!(a.core.handover(&gid, &a.id()), Err(GroupError::NotMember));
    // a's offer to b omits b's own message: only "from a" is offered back.
    let to_b = a.core.handover(&gid, &b.id()).unwrap();
    assert_eq!(to_b.offered, 1, "b's own message is not offered back to b");
    pump(&nodes[..2]);
    // c is added after the fact, catches up on live membership only, and holds
    // no past messages until a hands them over.
    a.core.add(&gid, &[(c.id(), String::new(), false)]).unwrap();
    pump(&nodes);
    c.core.accept_invite(&gid).unwrap();
    pump(&nodes);
    assert!(
        c.texts(&gid).is_empty(),
        "the past is not shared on its own"
    );
    // a hands its first-hand history to c: both "from a" and "from b" arrive as
    // shared-in copies attributed to their authors but marked shared by a.
    a.core.handover(&gid, &c.id()).unwrap();
    pump(&nodes);
    let shared_here: Vec<_> = c
        .core
        .history(&gid, None, 50)
        .unwrap()
        .into_iter()
        .filter(|v| v.msg.shared_by.is_some())
        .collect();
    assert!(
        !shared_here.is_empty(),
        "c holds at least one shared-in copy"
    );
    // c now re-shares to b. The copies c holds were themselves handed to it, so
    // they are not forwarded again; b gains no shared-in copy of them.
    let reshared = c.core.handover(&gid, &b.id());
    if let Ok(out) = reshared {
        for _ in 0..out.offered {}
    }
    pump(&nodes);
    let b_shared: Vec<_> = b
        .core
        .history(&gid, None, 50)
        .unwrap()
        .into_iter()
        .filter(|v| v.msg.shared_by.is_some())
        .collect();
    assert!(
        b_shared.is_empty(),
        "a copy that was itself handed to c is not forwarded again"
    );
}

/// A counter the receiver already holds is a duplicate: re-sharing the same
/// past message changes nothing.
#[test]
fn re_sharing_a_message_the_member_already_holds_is_a_duplicate() {
    let nodes = friends(3);
    let (a, _b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let gid = make_group(&nodes, "trio");
    a.core.send(&gid, "shared once", 10).unwrap();
    pump(&nodes);
    // c already received it live. A hand-over of the same counter is a no-op on
    // c's side (a duplicate), so the count does not grow.
    let before = c.texts(&gid).len();
    a.core.handover(&gid, &c.id()).unwrap();
    let log = pump(&nodes);
    assert!(
        log.iter().any(|l| l.2 == AckStatus::Duplicate),
        "the receiver reports the re-shared counter as a duplicate"
    );
    assert_eq!(c.texts(&gid).len(), before, "no new copy is stored");
}

/// The selection is bounded by [`MAX_HIST_PER_HANDOVER`].
#[test]
fn a_handover_offers_at_most_the_bound() {
    let nodes = friends(2);
    let gid = make_group(&nodes, "pair");
    // Send more than the hand-over bound, but drain the outbox between rounds
    // so no single round exceeds [`MAX_PENDING`] (the outbox bound the sender
    // enforces). Every message still lands in the store, so the hand-over
    // selects from more than the bound and must cap itself.
    for i in 0..(MAX_HIST_PER_HANDOVER + 5) {
        nodes[0].core.send(&gid, "m", i as u64).unwrap();
        pump(&nodes);
    }
    let out = nodes[0].core.handover(&gid, &nodes[1].id()).unwrap();
    assert!(
        out.offered <= MAX_HIST_PER_HANDOVER,
        "offered {} exceeds the bound",
        out.offered
    );
}
