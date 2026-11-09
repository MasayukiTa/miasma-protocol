//! Protected storage for holders introduced by contacts.
use crate::state_crypto::{self, Label, StateError, StateKeys};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntroducedHolder {
    pub endpoint_id: [u8; 32],
    pub introduced_by: [u8; 32],
    pub expires_ms: u64,
    pub file_custody: bool,
    pub chat_custody: bool,
    pub first_seen_ms: u64,
}

pub struct IntroducedHolders {
    path: PathBuf,
    keys: StateKeys,
    entries: Vec<IntroducedHolder>,
    own_id: [u8; 32],
    contacts: Vec<[u8; 32]>,
}
impl IntroducedHolders {
    pub fn open(
        data_dir: &Path,
        own_id: [u8; 32],
        contacts: &[[u8; 32]],
        now: u64,
    ) -> Result<Self, String> {
        let keys = StateKeys::open_or_init(data_dir).map_err(|e| e.to_string())?;
        let path = crate::paths::chat_introduced_holders_file(data_dir);
        let entries: Vec<IntroducedHolder> =
            match state_crypto::read_document(&keys, Label::Contacts, &path) {
                Ok(raw) => serde_json::from_slice(&raw)
                    .map_err(|e| format!("invalid introduced holders: {e}"))?,
                Err(StateError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.to_string()),
            };
        let mut store = Self {
            path,
            keys,
            entries: Vec::new(),
            own_id,
            contacts: contacts.to_vec(),
        };
        for entry in entries {
            store.add_in_memory(entry, now);
        }
        Ok(store)
    }
    fn add_in_memory(&mut self, entry: IntroducedHolder, now: u64) -> bool {
        self.entries.retain(|e| {
            e.expires_ms > now
                && e.endpoint_id != self.own_id
                && !self.contacts.contains(&e.endpoint_id)
        });
        if entry.expires_ms <= now
            || entry.endpoint_id == self.own_id
            || self.contacts.contains(&entry.endpoint_id)
            || self
                .entries
                .iter()
                .any(|e| e.endpoint_id == entry.endpoint_id)
            || self.entries.len() >= 64
            || self
                .entries
                .iter()
                .filter(|e| e.introduced_by == entry.introduced_by)
                .count()
                >= 16
        {
            return false;
        }
        self.entries.push(entry);
        true
    }
    pub fn insert(
        &mut self,
        entry: IntroducedHolder,
        now: u64,
        contacts: &[[u8; 32]],
    ) -> Result<bool, String> {
        let old = self.entries.clone();
        let old_contacts = std::mem::replace(&mut self.contacts, contacts.to_vec());
        let inserted = self.add_in_memory(entry, now);
        let result = (|| {
            std::fs::create_dir_all(self.path.parent().ok_or("missing chat directory")?)
                .map_err(|e| e.to_string())?;
            let bytes = zeroize::Zeroizing::new(
                serde_json::to_vec(&self.entries).map_err(|e| e.to_string())?,
            );
            state_crypto::write_document(&self.keys, Label::Contacts, &self.path, &bytes)
                .map_err(|e| e.to_string())
        })();
        if let Err(e) = result {
            self.entries = old;
            self.contacts = old_contacts;
            return Err(e);
        }
        Ok(inserted)
    }
    pub fn holders_for_deposit(&self, now: u64, exclude: &[[u8; 32]]) -> Vec<[u8; 32]> {
        self.entries
            .iter()
            .filter(|e| {
                e.expires_ms > now
                    && !exclude.contains(&e.endpoint_id)
                    && !self.contacts.contains(&e.endpoint_id)
            })
            .map(|e| e.endpoint_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(introducer: [u8; 32], expires_ms: u64) -> IntroducedHolder {
        IntroducedHolder {
            endpoint_id: rand::random(),
            introduced_by: introducer,
            expires_ms,
            file_custody: true,
            chat_custody: false,
            first_seen_ms: 1,
        }
    }
    #[test]
    fn limits_expiry_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let own = rand::random();
        let contact = rand::random();
        let mut store = IntroducedHolders::open(dir.path(), own, &[contact], 1).unwrap();
        let mut e = entry(contact, 10);
        e.endpoint_id = own;
        assert!(!store.insert(e.clone(), 1, &[contact]).unwrap());
        e.endpoint_id = contact;
        assert!(!store.insert(e, 1, &[contact]).unwrap());
        for _ in 0..16 {
            assert!(store.insert(entry(contact, 10), 1, &[contact]).unwrap());
        }
        assert!(!store.insert(entry(contact, 10), 1, &[contact]).unwrap());
        for _ in 0..3 {
            let introducer = rand::random();
            for _ in 0..16 {
                assert!(store.insert(entry(introducer, 10), 1, &[contact]).unwrap());
            }
        }
        assert!(!store
            .insert(entry(rand::random(), 10), 1, &[contact])
            .unwrap());
        let all = store.holders_for_deposit(1, &[]);
        assert_eq!(all.len(), 64);
        assert_eq!(store.holders_for_deposit(1, &all[..1]).len(), 63);
        drop(store);
        let mut store = IntroducedHolders::open(dir.path(), own, &[contact], 1).unwrap();
        assert_eq!(store.holders_for_deposit(1, &[]), all);
        assert!(store.holders_for_deposit(10, &[]).is_empty());
        assert!(store.insert(entry(contact, 20), 10, &[contact]).unwrap());
        drop(store);
        assert_eq!(
            IntroducedHolders::open(dir.path(), own, &[contact], 10)
                .unwrap()
                .holders_for_deposit(10, &[])
                .len(),
            1
        );
    }
}
