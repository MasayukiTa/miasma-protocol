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
    assert!(matches!(d.core.status_of(&gid), Some(Status::Pending { .. })));
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
    assert!(matches!(c.core.send(&gid, "still here?", 40), Err(GroupError::NotJoined)));
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
    let acc = a.core.accept(&nodes[2].id(), &wire, 6, &|id| a.is_trusted(id));
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
    assert!(detail.members.iter().find(|m| m.id == b.id()).unwrap().verified);
}

#[test]
fn an_invitation_from_someone_who_is_not_trusted_creates_nothing() {
    let nodes = friends(2);
    let (a, b) = (&nodes[0], &nodes[1]);
    b.trust.lock().unwrap().clear();
    a.core.create("surprise", &[(b.id(), String::new())], 1).unwrap();
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
        a.core.add(&gid, &[(Identity::from_seed(&rand::random()).id(), String::new(), false)]),
        Err(GroupError::TooManyMembers)
    );
    let mut more = others.clone();
    more.push((Identity::from_seed(&rand::random()).id(), String::new()));
    assert_eq!(a.core.create("bigger", &more, 1), Err(GroupError::TooManyMembers));
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
    nodes[0].core.send(&gid, "GROUP-SECRET-TEXT-98765", 10).unwrap();
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
