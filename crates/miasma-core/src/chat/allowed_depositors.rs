//! Recipient-scoped, persistent custody introductions.
use crate::state_crypto::{self, Label, StateError, StateKeys};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    recipient: [u8; 32],
    depositor: [u8; 32],
    expires_ms: u64,
}

pub struct AllowedDepositors {
    path: PathBuf,
    keys: StateKeys,
    entries: Vec<Entry>,
}

impl AllowedDepositors {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let keys = StateKeys::open_or_init(data_dir).map_err(|e| e.to_string())?;
        let path = data_dir.join("chat").join("allowed-depositors.doc");
        let entries = match state_crypto::read_document(&keys, Label::Contacts, &path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| format!("invalid depositors: {e}"))?,
            Err(StateError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.to_string()),
        };
        Ok(Self { path, keys, entries })
    }

    /// The authenticated introducer is also the only permitted recipient.
    pub fn introduce(&mut self, recipient: [u8; 32], depositor: [u8; 32], is_contact: bool, now: u64) -> Result<bool, String> {
        if !is_contact || recipient == depositor { return Ok(false); }
        let old = self.entries.clone();
        self.entries.retain(|e| e.expires_ms > now);
        if let Some(entry) = self.entries.iter_mut().find(|e| e.recipient == recipient && e.depositor == depositor) {
            entry.expires_ms = now.saturating_add(LIFETIME_MS);
        } else {
            if self.entries.len() >= 128 || self.entries.iter().filter(|e| e.recipient == recipient).count() >= 16 { return Ok(false); }
            self.entries.push(Entry { recipient, depositor, expires_ms: now.saturating_add(LIFETIME_MS) });
        }
        let result = (|| {
            std::fs::create_dir_all(self.path.parent().ok_or("missing chat directory")?).map_err(|e| e.to_string())?;
            let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&self.entries).map_err(|e| e.to_string())?);
            state_crypto::write_document(&self.keys, Label::Contacts, &self.path, &bytes).map_err(|e| e.to_string())
        })();
        if let Err(e) = result { self.entries = old; return Err(e); }
        Ok(true)
    }

    pub fn allows(&self, recipient: &[u8; 32], depositor: &[u8; 32], now: u64) -> bool {
        self.entries.iter().any(|e| &e.recipient == recipient && &e.depositor == depositor && e.expires_ms > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_contact_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AllowedDepositors::open(dir.path()).unwrap();
        let recipient = rand::random();
        let depositor = rand::random();
        assert!(!store.introduce(recipient, depositor, false, 1).unwrap());
        assert!(!store.allows(&recipient, &depositor, 1));
    }
    #[test]
    fn caps_expiry_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AllowedDepositors::open(dir.path()).unwrap();
        let recipient = rand::random();
        let first = rand::random();
        assert!(store.introduce(recipient, first, true, 1).unwrap());
        for _ in 1..16 { assert!(store.introduce(recipient, rand::random(), true, 1).unwrap()); }
        assert!(!store.introduce(recipient, rand::random(), true, 1).unwrap());
        for _ in 0..7 {
            let other = rand::random();
            for _ in 0..16 { assert!(store.introduce(other, rand::random(), true, 1).unwrap()); }
        }
        assert!(!store.introduce(rand::random(), rand::random(), true, 1).unwrap());
        drop(store);
        let mut store = AllowedDepositors::open(dir.path()).unwrap();
        assert!(store.allows(&recipient, &first, 1));
        assert!(!store.allows(&recipient, &first, 1 + LIFETIME_MS));
        assert!(store.introduce(recipient, rand::random(), true, 1 + LIFETIME_MS).unwrap());
    }
}
