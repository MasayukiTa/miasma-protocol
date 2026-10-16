//! Peers that tried to reach this node without being a contact.
//!
//! Chat and file push both refuse a peer that is not a registered contact. This module keeps a
//! small, memory-only note of who was refused so the Contacts screen can offer to add them. It
//! never accepts anything by itself and never learns a name: all it holds is the endpoint id the
//! transport already proved during the handshake.
//!
//! Bounds: at most [`MAX_ENTRIES`] peers (the newest win), each forgotten [`TTL_MS`] after its
//! last attempt, and at most a few *new* peers per minute so a flood of throw-away ids cannot
//! push a real one out. One peer is one entry however often it knocks. Nothing is written to
//! disk.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::push::contact::{fingerprint, ContactCode};

/// Most peers remembered at once.
pub const MAX_ENTRIES: usize = 16;
/// How long a peer is remembered after its last attempt (24 hours).
pub const TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// New peers admitted at once, then one more per [`NEW_PEER_EVERY_MS`].
const NEW_PEER_BURST: f64 = 4.0;
const NEW_PEER_EVERY_MS: f64 = 60_000.0;
/// Characters of the fingerprint shown as the short id.
pub const SHORT_ID_CHARS: usize = 5;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One refused peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub endpoint: [u8; 32],
    pub first_ms: u64,
    pub last_ms: u64,
    pub attempts: u32,
}

/// A [`Suggestion`] as the IPC and the UI see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestionInfo {
    /// Lower-case hex of the endpoint id.
    pub endpoint_id: String,
    /// First [`SHORT_ID_CHARS`] characters of the fingerprint: enough to recognise, not to identify.
    pub short_id: String,
    /// The contact code that pre-fills the add form.
    pub code: String,
    pub first_ms: u64,
    pub last_ms: u64,
    pub attempts: u32,
}

impl From<&Suggestion> for SuggestionInfo {
    fn from(s: &Suggestion) -> Self {
        let fp = fingerprint(&s.endpoint);
        SuggestionInfo {
            endpoint_id: hex::encode(s.endpoint),
            short_id: fp.chars().take(SHORT_ID_CHARS).collect(),
            code: ContactCode::new(s.endpoint).to_string(),
            first_ms: s.first_ms,
            last_ms: s.last_ms,
            attempts: s.attempts,
        }
    }
}

struct Inner {
    /// Oldest first; the newest is at the back.
    items: VecDeque<Suggestion>,
    tokens: f64,
    refilled_ms: u64,
}

/// The bounded, expiring set. Cheap to share: every method takes `&self`.
pub struct UnknownPeers {
    inner: Mutex<Inner>,
}

impl Default for UnknownPeers {
    fn default() -> Self {
        Self::new()
    }
}

impl UnknownPeers {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                items: VecDeque::new(),
                tokens: NEW_PEER_BURST,
                refilled_ms: 0,
            }),
        }
    }

    /// Note that `endpoint` was refused just now.
    pub fn record(&self, endpoint: [u8; 32]) -> bool {
        self.record_at(endpoint, now_ms())
    }

    /// [`record`](Self::record) at an explicit time (tests drive a fake clock with this).
    /// Returns true when a new entry was created.
    pub fn record_at(&self, endpoint: [u8; 32], now: u64) -> bool {
        let mut g = self.inner.lock().unwrap();
        g.expire(now);
        if let Some(s) = g.items.iter_mut().find(|s| s.endpoint == endpoint) {
            s.last_ms = s.last_ms.max(now);
            s.attempts = s.attempts.saturating_add(1);
            return false;
        }
        g.refill(now);
        if g.tokens < 1.0 {
            return false;
        }
        g.tokens -= 1.0;
        while g.items.len() >= MAX_ENTRIES {
            g.items.pop_front();
        }
        g.items.push_back(Suggestion {
            endpoint,
            first_ms: now,
            last_ms: now,
            attempts: 1,
        });
        true
    }

    /// Who is waiting, newest first.
    pub fn list(&self) -> Vec<Suggestion> {
        self.list_at(now_ms())
    }

    pub fn list_at(&self, now: u64) -> Vec<Suggestion> {
        let mut g = self.inner.lock().unwrap();
        g.expire(now);
        g.items.iter().rev().cloned().collect()
    }

    /// Drop `endpoint` (it became a contact).
    pub fn forget(&self, endpoint: &[u8; 32]) {
        self.inner
            .lock()
            .unwrap()
            .items
            .retain(|s| &s.endpoint != endpoint);
    }
}

impl Inner {
    fn expire(&mut self, now: u64) {
        self.items
            .retain(|s| now.saturating_sub(s.last_ms) < TTL_MS);
    }

    fn refill(&mut self, now: u64) {
        if self.refilled_ms == 0 || now < self.refilled_ms {
            self.refilled_ms = now;
            return;
        }
        let gained = (now - self.refilled_ms) as f64 / NEW_PEER_EVERY_MS;
        self.tokens = (self.tokens + gained).min(NEW_PEER_BURST);
        self.refilled_ms = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    const T0: u64 = 1_000_000;
    const MIN: u64 = 60_000;

    #[test]
    fn one_peer_is_one_entry() {
        let u = UnknownPeers::new();
        assert!(u.record_at(id(1), T0));
        assert!(!u.record_at(id(1), T0 + 5));
        assert!(!u.record_at(id(1), T0 + 10));
        let l = u.list_at(T0 + 10);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].attempts, 3);
        assert_eq!(l[0].first_ms, T0);
        assert_eq!(l[0].last_ms, T0 + 10);
    }

    #[test]
    fn the_set_is_bounded_and_the_newest_win() {
        let u = UnknownPeers::new();
        // One new peer per minute is admitted after the burst, so space them out.
        for n in 0..40u8 {
            u.record_at(id(n), T0 + n as u64 * MIN);
        }
        let now = T0 + 40 * MIN;
        let l = u.list_at(now);
        assert_eq!(l.len(), MAX_ENTRIES);
        assert_eq!(l[0].endpoint, id(39), "newest first");
        assert_eq!(l[MAX_ENTRIES - 1].endpoint, id(24));
        assert!(!l.iter().any(|s| s.endpoint == id(0)));
    }

    #[test]
    fn entries_expire_after_24_hours_with_a_fake_clock() {
        let u = UnknownPeers::new();
        u.record_at(id(1), T0);
        assert_eq!(u.list_at(T0 + TTL_MS - 1).len(), 1);
        assert!(u.list_at(T0 + TTL_MS).is_empty());
        // A repeat attempt keeps it alive from the last attempt.
        u.record_at(id(2), T0);
        u.record_at(id(2), T0 + TTL_MS - 1);
        assert_eq!(u.list_at(T0 + TTL_MS + 5).len(), 1);
        assert!(u.list_at(T0 + 2 * TTL_MS).is_empty());
    }

    #[test]
    fn a_flood_of_new_ids_cannot_push_real_ones_out() {
        let u = UnknownPeers::new();
        let mut created = 0;
        for n in 0..200u8 {
            if u.record_at(id(n), T0 + n as u64) {
                created += 1;
            }
        }
        assert_eq!(
            created, NEW_PEER_BURST as usize,
            "burst only, within 200 ms"
        );
        assert_eq!(u.list_at(T0 + 200).len(), NEW_PEER_BURST as usize);
        // A minute later one more is admitted.
        assert!(u.record_at(id(250), T0 + 200 + MIN));
    }

    #[test]
    fn forget_removes_one_peer() {
        let u = UnknownPeers::new();
        u.record_at(id(1), T0);
        u.record_at(id(2), T0);
        u.forget(&id(1));
        let l = u.list_at(T0);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].endpoint, id(2));
    }

    #[test]
    fn info_shows_a_five_character_id_and_a_code_that_parses_back() {
        let ep = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let s = Suggestion {
            endpoint: ep,
            first_ms: 1,
            last_ms: 2,
            attempts: 1,
        };
        let i = SuggestionInfo::from(&s);
        assert_eq!(i.short_id.chars().count(), SHORT_ID_CHARS);
        assert!(fingerprint(&ep).starts_with(&i.short_id));
        assert_eq!(i.endpoint_id, hex::encode(ep));
        let back = ContactCode::parse(&i.code).unwrap();
        assert_eq!(back.endpoint_id(), &ep);
        let json = serde_json::to_string(&i).unwrap();
        assert_eq!(serde_json::from_str::<SuggestionInfo>(&json).unwrap(), i);
    }
}
