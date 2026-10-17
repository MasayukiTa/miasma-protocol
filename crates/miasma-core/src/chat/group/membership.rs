//! Signed group membership.
//!
//! A group is a list of members with an epoch number. Every change of the list
//! produces a new [`Descriptor`] with the next epoch, signed with the Ed25519
//! identity of whoever made the change. A descriptor is accepted only when it
//! extends the descriptors we already hold:
//!
//! * `epoch` is the previous epoch plus one and `prev_hash` is the hash of the
//!   previous descriptor (so a descriptor cannot be moved to another history);
//! * the signature verifies under `signer`;
//! * `signer` is an admin of the **previous** descriptor, or the change is a
//!   member leaving by its own signature (the new list is the old list without
//!   exactly that member);
//! * the new list is well formed (1 to [`MAX_MEMBERS`] distinct valid keys, at
//!   least one admin, bounded names).
//!
//! Two admins may change the group at the same time and produce two
//! descriptors with the same epoch and the same predecessor. Every member
//! settles on the one with the smaller hash.
//!
//! A person who is invited holds no history yet. The first descriptor they get
//! becomes the root of their chain (the caller checks that it comes from the
//! admin that signed it, who is one of their trusted contacts).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::chat::crypto::Rd;

pub const DESCRIPTOR_VERSION: u8 = 1;
/// Members of one group, creator included.
pub const MAX_MEMBERS: usize = 32;
/// Longest group name, in bytes.
pub const MAX_NAME_BYTES: usize = 192;
/// Longest self-declared label of a member, in bytes.
pub const MAX_HINT_BYTES: usize = 24;
/// Descriptors kept per group (the newest ones).
pub const MAX_CHAIN: usize = 8;

const HASH_LABEL: &str = "miasma group v1 descriptor hash";
const SIGN_LABEL: &str = "miasma group v1 descriptor signature";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Member,
    Admin,
}

impl Role {
    fn code(self) -> u8 {
        match self {
            Role::Member => 0,
            Role::Admin => 1,
        }
    }
    fn from_code(c: u8) -> Option<Self> {
        match c {
            0 => Some(Role::Member),
            1 => Some(Role::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: [u8; 32],
    pub role: Role,
    /// What the person who added this member calls them. Not verified; a
    /// display must show it as self-declared next to the fingerprint.
    pub hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DescError {
    #[error("malformed descriptor")]
    Malformed,
    #[error("the signature does not verify")]
    BadSignature,
    #[error("the descriptor belongs to another group")]
    WrongGroup,
    #[error("the descriptor does not follow the one before it")]
    BadChain,
    #[error("the signer may not make this change")]
    NotAuthorized,
    #[error("the group would have no admin")]
    NoAdmin,
    #[error("too many members")]
    TooManyMembers,
    /// The descriptor is ahead of what we hold; earlier ones are missing.
    #[error("earlier descriptors are missing")]
    Gap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub gid: [u8; 16],
    pub epoch: u32,
    pub name: String,
    pub created_ms: u64,
    pub prev_hash: [u8; 32],
    pub members: Vec<Member>,
    pub signer: [u8; 32],
    pub sig: [u8; 64],
}

fn valid_key(id: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(id).is_ok_and(|k| !k.is_weak())
}

impl Descriptor {
    /// Everything the signature covers: the whole encoding up to and
    /// including `signer`.
    fn signed_part(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128 + self.members.len() * 60);
        v.push(DESCRIPTOR_VERSION);
        v.extend_from_slice(&self.gid);
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&self.created_ms.to_be_bytes());
        v.extend_from_slice(&self.prev_hash);
        v.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        v.extend_from_slice(self.name.as_bytes());
        v.push(self.members.len() as u8);
        for m in &self.members {
            v.extend_from_slice(&m.id);
            v.push(m.role.code());
            v.push(m.hint.len() as u8);
            v.extend_from_slice(m.hint.as_bytes());
        }
        v.extend_from_slice(&self.signer);
        v
    }

    fn digest_to_sign(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(SIGN_LABEL);
        h.update(&self.signed_part());
        *h.finalize().as_bytes()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.signed_part();
        v.extend_from_slice(&self.sig);
        v
    }

    /// The identity of this descriptor: what the next one names as `prev_hash`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(HASH_LABEL);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Shape only; no signature and no relation to other descriptors.
    pub fn decode(b: &[u8]) -> Result<Self, DescError> {
        let bad = |_| DescError::Malformed;
        let mut r = Rd::new(b);
        if r.u8().map_err(bad)? != DESCRIPTOR_VERSION {
            return Err(DescError::Malformed);
        }
        let gid = r.arr::<16>().map_err(bad)?;
        let epoch = r.u32().map_err(bad)?;
        let created_ms = r.u64().map_err(bad)?;
        let prev_hash = r.arr::<32>().map_err(bad)?;
        let nl = r.u16().map_err(bad)? as usize;
        if nl == 0 || nl > MAX_NAME_BYTES {
            return Err(DescError::Malformed);
        }
        let name = std::str::from_utf8(r.bytes(nl).map_err(bad)?)
            .map_err(|_| DescError::Malformed)?
            .to_owned();
        let n = r.u8().map_err(bad)? as usize;
        if n == 0 || n > MAX_MEMBERS {
            return Err(DescError::Malformed);
        }
        let mut members = Vec::with_capacity(n);
        for _ in 0..n {
            let id = r.arr::<32>().map_err(bad)?;
            let role = Role::from_code(r.u8().map_err(bad)?).ok_or(DescError::Malformed)?;
            let hl = r.u8().map_err(bad)? as usize;
            if hl > MAX_HINT_BYTES {
                return Err(DescError::Malformed);
            }
            let hint = std::str::from_utf8(r.bytes(hl).map_err(bad)?)
                .map_err(|_| DescError::Malformed)?
                .to_owned();
            members.push(Member { id, role, hint });
        }
        let signer = r.arr::<32>().map_err(bad)?;
        let sig = r.arr::<64>().map_err(bad)?;
        if !r.done() || epoch == 0 {
            return Err(DescError::Malformed);
        }
        let d = Self {
            gid,
            epoch,
            name,
            created_ms,
            prev_hash,
            members,
            signer,
            sig,
        };
        d.check_shape()?;
        Ok(d)
    }

    /// Well-formedness of the member list, independent of any history.
    fn check_shape(&self) -> Result<(), DescError> {
        if self.name.is_empty() || self.name.len() > MAX_NAME_BYTES {
            return Err(DescError::Malformed);
        }
        if self.members.is_empty() {
            return Err(DescError::Malformed);
        }
        if self.members.len() > MAX_MEMBERS {
            return Err(DescError::TooManyMembers);
        }
        for (i, m) in self.members.iter().enumerate() {
            if m.hint.len() > MAX_HINT_BYTES || !valid_key(&m.id) {
                return Err(DescError::Malformed);
            }
            if self.members[..i].iter().any(|o| o.id == m.id) {
                return Err(DescError::Malformed);
            }
        }
        if !self.members.iter().any(|m| m.role == Role::Admin) {
            return Err(DescError::NoAdmin);
        }
        Ok(())
    }

    /// Sign a descriptor with `key` (which becomes `signer`).
    pub fn signed(mut self, key: &SigningKey) -> Self {
        self.signer = key.verifying_key().to_bytes();
        self.sig = key.sign(&self.digest_to_sign()).to_bytes();
        self
    }

    pub fn verify_signature(&self) -> Result<(), DescError> {
        let vk = VerifyingKey::from_bytes(&self.signer).map_err(|_| DescError::BadSignature)?;
        vk.verify_strict(&self.digest_to_sign(), &Signature::from_bytes(&self.sig))
            .map_err(|_| DescError::BadSignature)
    }

    pub fn member(&self, id: &[u8; 32]) -> Option<&Member> {
        self.members.iter().find(|m| &m.id == id)
    }

    pub fn is_member(&self, id: &[u8; 32]) -> bool {
        self.member(id).is_some()
    }

    pub fn is_admin(&self, id: &[u8; 32]) -> bool {
        self.member(id).is_some_and(|m| m.role == Role::Admin)
    }

    /// `new` is `self` with only `who` taken out (same order, same roles).
    fn is_leave_of(&self, new: &Descriptor, who: &[u8; 32]) -> bool {
        if !self.is_member(who) || new.name != self.name {
            return false;
        }
        let expect: Vec<&Member> = self.members.iter().filter(|m| &m.id != who).collect();
        expect.len() == new.members.len() && expect.iter().zip(&new.members).all(|(a, b)| *a == b)
    }

    /// Whether `new` may follow `self`. Does not check the signature.
    fn may_be_followed_by(&self, new: &Descriptor) -> Result<(), DescError> {
        if new.gid != self.gid || new.created_ms != self.created_ms {
            return Err(DescError::WrongGroup);
        }
        if new.epoch != self.epoch.saturating_add(1) || new.prev_hash != self.hash() {
            return Err(DescError::BadChain);
        }
        if self.is_admin(&new.signer) || self.is_leave_of(new, &new.signer) {
            Ok(())
        } else {
            Err(DescError::NotAuthorized)
        }
    }
}

/// What [`Chain::push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// The descriptor extended the chain.
    Advanced,
    /// Already held (or older than what is held).
    Known,
    /// It won a tie against a different descriptor of the same epoch.
    Replaced,
}

/// The newest descriptors of one group, oldest first, consecutive epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    items: Vec<Descriptor>,
}

impl Chain {
    /// Start a chain at `d`: a creation (epoch 1) or the first descriptor an
    /// invited person gets, which must be signed by one of its admins.
    pub fn from_root(d: Descriptor) -> Result<Self, DescError> {
        d.check_shape()?;
        d.verify_signature()?;
        if !d.is_admin(&d.signer) {
            return Err(DescError::NotAuthorized);
        }
        if d.epoch == 1 && d.prev_hash != [0u8; 32] {
            return Err(DescError::BadChain);
        }
        Ok(Self { items: vec![d] })
    }

    /// Rebuild from stored descriptors that were verified when they were
    /// accepted (shape and linkage are checked again, signatures too).
    pub fn from_items(items: Vec<Descriptor>) -> Result<Self, DescError> {
        let mut it = items.into_iter();
        let mut c = Self::from_root(it.next().ok_or(DescError::Malformed)?)?;
        for d in it {
            c.push(d)?;
        }
        Ok(c)
    }

    pub fn latest(&self) -> &Descriptor {
        self.items.last().expect("a chain is never empty")
    }

    pub fn items(&self) -> &[Descriptor] {
        &self.items
    }

    pub fn gid(&self) -> [u8; 16] {
        self.latest().gid
    }

    pub fn epoch(&self) -> u32 {
        self.latest().epoch
    }

    pub fn at_epoch(&self, epoch: u32) -> Option<&Descriptor> {
        self.items.iter().find(|d| d.epoch == epoch)
    }

    /// True when `id` is a member of any descriptor we hold.
    pub fn ever_member(&self, id: &[u8; 32]) -> bool {
        self.items.iter().any(|d| d.is_member(id))
    }

    pub fn push(&mut self, d: Descriptor) -> Result<Pushed, DescError> {
        let latest = self.latest();
        if d.gid != latest.gid {
            return Err(DescError::WrongGroup);
        }
        if d.epoch > latest.epoch.saturating_add(1) {
            return Err(DescError::Gap);
        }
        if d.epoch <= latest.epoch {
            if d.epoch < latest.epoch || d.hash() == latest.hash() {
                return Ok(Pushed::Known);
            }
            // Same epoch, different descriptor: only a competing change on
            // the same predecessor can replace ours, and only when it is
            // valid and its hash is the smaller one.
            if d.prev_hash != latest.prev_hash || d.hash() >= latest.hash() {
                return Ok(Pushed::Known);
            }
            let n = self.items.len();
            if n < 2 {
                return Err(DescError::BadChain);
            }
            d.check_shape()?;
            d.verify_signature()?;
            self.items[n - 2].may_be_followed_by(&d)?;
            self.items[n - 1] = d;
            return Ok(Pushed::Replaced);
        }
        d.check_shape()?;
        d.verify_signature()?;
        latest.may_be_followed_by(&d)?;
        self.items.push(d);
        if self.items.len() > MAX_CHAIN {
            self.items.remove(0);
        }
        Ok(Pushed::Advanced)
    }

    /// Apply descriptors in ascending order; stops at the first one that
    /// cannot be applied. Returns whether the newest epoch changed.
    pub fn push_all(&mut self, ds: Vec<Descriptor>) -> Result<bool, DescError> {
        let before = self.latest().hash();
        let mut res = Ok(());
        for d in ds {
            if let Err(e) = self.push(d) {
                res = Err(e);
                break;
            }
        }
        let changed = self.latest().hash() != before;
        match res {
            Err(e) if !changed => Err(e),
            _ => Ok(changed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&rand::random())
    }

    fn id(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    fn m(k: &SigningKey, role: Role) -> Member {
        Member {
            id: id(k),
            role,
            hint: String::new(),
        }
    }

    fn create(admin: &SigningKey, others: &[&SigningKey]) -> Descriptor {
        let mut members = vec![m(admin, Role::Admin)];
        members.extend(others.iter().map(|k| m(k, Role::Member)));
        Descriptor {
            gid: rand::random(),
            epoch: 1,
            name: "friends".into(),
            created_ms: 1,
            prev_hash: [0; 32],
            members,
            signer: [0; 32],
            sig: [0; 64],
        }
        .signed(admin)
    }

    fn next(prev: &Descriptor, members: Vec<Member>, by: &SigningKey) -> Descriptor {
        Descriptor {
            gid: prev.gid,
            epoch: prev.epoch + 1,
            name: prev.name.clone(),
            created_ms: prev.created_ms,
            prev_hash: prev.hash(),
            members,
            signer: [0; 32],
            sig: [0; 64],
        }
        .signed(by)
    }

    #[test]
    fn encoding_round_trips_and_every_truncation_is_refused() {
        let (a, b) = (key(), key());
        let d = create(&a, &[&b]);
        let bytes = d.encode();
        assert_eq!(Descriptor::decode(&bytes).unwrap(), d);
        for n in 0..bytes.len() {
            assert!(Descriptor::decode(&bytes[..n]).is_err(), "prefix {n}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Descriptor::decode(&longer).is_err());
    }

    #[test]
    fn random_bytes_never_panic_the_decoder() {
        for _ in 0..3000 {
            let n = rand::random::<usize>() % 300;
            let junk: Vec<u8> = (0..n).map(|_| rand::random()).collect();
            let _ = Descriptor::decode(&junk);
        }
    }

    #[test]
    fn an_admin_adds_and_removes() {
        let (a, b, c) = (key(), key(), key());
        let d1 = create(&a, &[&b]);
        let mut chain = Chain::from_root(d1.clone()).unwrap();
        let mut ms = d1.members.clone();
        ms.push(m(&c, Role::Member));
        let d2 = next(&d1, ms, &a);
        assert_eq!(chain.push(d2.clone()), Ok(Pushed::Advanced));
        assert!(chain.latest().is_member(&id(&c)));
        let ms: Vec<Member> = d2
            .members
            .iter()
            .filter(|x| x.id != id(&b))
            .cloned()
            .collect();
        let d3 = next(&d2, ms, &a);
        assert_eq!(chain.push(d3), Ok(Pushed::Advanced));
        assert!(!chain.latest().is_member(&id(&b)));
        assert_eq!(chain.epoch(), 3);
        assert!(chain.ever_member(&id(&b)));
    }

    #[test]
    fn a_forged_add_is_refused() {
        let (a, b, c, evil) = (key(), key(), key(), key());
        let d1 = create(&a, &[&b]);
        let mut chain = Chain::from_root(d1.clone()).unwrap();
        let mut ms = d1.members.clone();
        ms.push(m(&c, Role::Member));
        // Signed by someone who is not in the group.
        assert_eq!(
            chain.push(next(&d1, ms.clone(), &evil)),
            Err(DescError::NotAuthorized)
        );
        // Signed by a plain member.
        assert_eq!(
            chain.push(next(&d1, ms.clone(), &b)),
            Err(DescError::NotAuthorized)
        );
        // A member cannot promote itself or add anyone through the leave path.
        let mut promoted = d1.members.clone();
        promoted[1].role = Role::Admin;
        assert_eq!(
            chain.push(next(&d1, promoted, &b)),
            Err(DescError::NotAuthorized)
        );
        // A valid descriptor with a changed byte.
        let mut forged = next(&d1, ms.clone(), &a);
        forged.members.push(m(&evil, Role::Member));
        assert_eq!(chain.push(forged), Err(DescError::BadSignature));
        // A signature copied onto other content.
        let good = next(&d1, ms, &a);
        let mut other = next(&d1, d1.members.clone(), &a);
        other.name = "other".into();
        other.sig = good.sig;
        assert_eq!(chain.push(other), Err(DescError::BadSignature));
        assert_eq!(chain.epoch(), 1);
    }

    #[test]
    fn wrong_epoch_wrong_predecessor_and_wrong_group_are_refused() {
        let (a, b) = (key(), key());
        let d1 = create(&a, &[&b]);
        let mut chain = Chain::from_root(d1.clone()).unwrap();
        let mut skip = next(&d1, d1.members.clone(), &a);
        skip.epoch = 3;
        let skip = skip.signed(&a);
        assert_eq!(chain.push(skip), Err(DescError::Gap));
        let mut wrong_prev = next(&d1, d1.members.clone(), &a);
        wrong_prev.prev_hash = [9; 32];
        let wrong_prev = wrong_prev.signed(&a);
        assert_eq!(chain.push(wrong_prev), Err(DescError::BadChain));
        let mut other_group = next(&d1, d1.members.clone(), &a);
        other_group.gid = rand::random();
        let other_group = other_group.signed(&a);
        assert_eq!(chain.push(other_group), Err(DescError::WrongGroup));
    }

    #[test]
    fn a_member_can_leave_by_its_own_signature_only_as_itself() {
        let (a, b, c) = (key(), key(), key());
        let d1 = create(&a, &[&b, &c]);
        let mut chain = Chain::from_root(d1.clone()).unwrap();
        let without_b: Vec<Member> = d1
            .members
            .iter()
            .filter(|x| x.id != id(&b))
            .cloned()
            .collect();
        // c cannot remove b by signing.
        assert_eq!(
            chain.push(next(&d1, without_b.clone(), &c)),
            Err(DescError::NotAuthorized)
        );
        // b leaves.
        assert_eq!(chain.push(next(&d1, without_b, &b)), Ok(Pushed::Advanced));
        assert!(!chain.latest().is_member(&id(&b)));
    }

    #[test]
    fn the_last_admin_cannot_leave_and_a_group_cannot_lose_all_admins() {
        let (a, b) = (key(), key());
        let d1 = create(&a, &[&b]);
        let mut chain = Chain::from_root(d1.clone()).unwrap();
        let without_a = vec![m(&b, Role::Member)];
        assert_eq!(
            chain.push(next(&d1, without_a, &a)),
            Err(DescError::NoAdmin)
        );
        // Handing over admin first makes it fine.
        let both = vec![m(&a, Role::Admin), m(&b, Role::Admin)];
        let d2 = next(&d1, both, &a);
        assert_eq!(chain.push(d2.clone()), Ok(Pushed::Advanced));
        let only_b = vec![m(&b, Role::Admin)];
        assert_eq!(chain.push(next(&d2, only_b, &a)), Ok(Pushed::Advanced));
    }

    #[test]
    fn two_changes_of_the_same_epoch_settle_on_the_smaller_hash_everywhere() {
        let (a, b, c, e) = (key(), key(), key(), key());
        let mut d1 = create(&a, &[&b]);
        d1.members[1].role = Role::Admin;
        let d1 = d1.signed(&a);
        let mut add_c = d1.members.clone();
        add_c.push(m(&c, Role::Member));
        let mut add_e = d1.members.clone();
        add_e.push(m(&e, Role::Member));
        let x = next(&d1, add_c, &a);
        let y = next(&d1, add_e, &b);
        let (small, big) = if x.hash() < y.hash() { (x, y) } else { (y, x) };
        let mut one = Chain::from_root(d1.clone()).unwrap();
        one.push(big.clone()).unwrap();
        assert_eq!(one.push(small.clone()), Ok(Pushed::Replaced));
        let mut two = Chain::from_root(d1).unwrap();
        two.push(small.clone()).unwrap();
        assert_eq!(two.push(big), Ok(Pushed::Known));
        assert_eq!(one.latest(), two.latest());
        assert_eq!(one.latest(), &small);
    }

    #[test]
    fn the_chain_is_bounded_and_rebuilds_from_its_items() {
        let a = key();
        let mut d = create(&a, &[]);
        let mut chain = Chain::from_root(d.clone()).unwrap();
        for _ in 0..(MAX_CHAIN + 4) {
            d = next(&d, d.members.clone(), &a);
            chain.push(d.clone()).unwrap();
        }
        assert_eq!(chain.items().len(), MAX_CHAIN);
        assert_eq!(chain.epoch(), (MAX_CHAIN + 5) as u32);
        let again = Chain::from_items(chain.items().to_vec()).unwrap();
        assert_eq!(again, chain);
    }

    #[test]
    fn push_all_applies_a_run_and_reports_a_gap() {
        let (a, b) = (key(), key());
        let d1 = create(&a, &[&b]);
        let d2 = next(&d1, d1.members.clone(), &a);
        let d3 = next(&d2, d2.members.clone(), &a);
        let d4 = next(&d3, d3.members.clone(), &a);
        let mut chain = Chain::from_root(d1).unwrap();
        assert_eq!(chain.push_all(vec![d2.clone(), d3.clone()]), Ok(true));
        assert_eq!(chain.push_all(vec![d2, d3.clone()]), Ok(false));
        let far = next(&d4, d4.members.clone(), &a);
        assert_eq!(chain.push_all(vec![far]), Err(DescError::Gap));
        assert_eq!(chain.push_all(vec![d4]), Ok(true));
        assert_eq!(chain.epoch(), 4);
    }

    #[test]
    fn a_root_must_be_signed_by_one_of_its_own_admins() {
        let (a, b) = (key(), key());
        let d = create(&a, &[&b]);
        let by_member = Descriptor {
            epoch: 1,
            ..d.clone()
        }
        .signed(&b);
        assert_eq!(Chain::from_root(by_member), Err(DescError::NotAuthorized));
        let mut bad = d;
        bad.sig[0] ^= 1;
        assert_eq!(Chain::from_root(bad), Err(DescError::BadSignature));
    }

    #[test]
    fn bounds_on_members_names_and_hints() {
        let a = key();
        let mut d = create(&a, &[]);
        for _ in 0..MAX_MEMBERS {
            d.members.push(m(&key(), Role::Member));
        }
        assert_eq!(d.signed(&a).check_shape(), Err(DescError::TooManyMembers));
        let mut d = create(&a, &[]);
        d.members[0].hint = "x".repeat(MAX_HINT_BYTES + 1);
        assert!(d.signed(&a).check_shape().is_err());
        let mut d = create(&a, &[]);
        d.name = String::new();
        assert!(d.signed(&a).check_shape().is_err());
        let mut d = create(&a, &[]);
        d.members.push(d.members[0].clone());
        assert!(d.signed(&a).check_shape().is_err());
    }
}
