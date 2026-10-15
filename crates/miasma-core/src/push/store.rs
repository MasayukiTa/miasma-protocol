//! The contact list: `{data_dir}/contacts.json`.
//!
//! Default-deny: a node that is not in this list (with `allow_receive`) can
//! push nothing. The file is rewritten atomically (temp file + rename) with
//! owner-only permissions where the platform supports it, has a schema
//! version, ignores fields it does not know, and a corrupt file is moved
//! aside (never deleted) so the list restarts empty rather than the daemon
//! refusing to start.

use std::{
    path::{Path, PathBuf},
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::contact::{fingerprint, ContactCode};
use crate::MiasmaError;

pub const CONTACTS_FILE: &str = crate::paths::CONTACTS.name;
const SCHEMA_VERSION: u32 = 1;
pub const MAX_CONTACTS: usize = 500;
pub const MAX_LABEL_CHARS: usize = 64;

/// One registered contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Stable short id (hex of the first 8 bytes of the endpoint ID).
    #[serde(default)]
    pub id: String,
    /// Human label; also names the inbox sub-folder.
    pub label: String,
    /// The contact's iroh endpoint ID, hex.
    pub endpoint_id: String,
    /// Seconds since the Unix epoch.
    #[serde(default)]
    pub added_at: u64,
    /// Accept files pushed by this contact without asking.
    #[serde(default = "yes")]
    pub allow_receive: bool,
    /// Files may be pushed to this contact.
    #[serde(default = "yes")]
    pub allow_send: bool,
    /// Largest file accepted from this contact, bytes (`None` = config default).
    #[serde(default)]
    pub max_file_size: Option<u64>,
}

fn yes() -> bool {
    true
}

impl Contact {
    pub fn endpoint_bytes(&self) -> Option<[u8; 32]> {
        let v = hex::decode(&self.endpoint_id).ok()?;
        v.try_into().ok()
    }

    pub fn fingerprint(&self) -> String {
        self.endpoint_bytes()
            .map(|b| fingerprint(&b))
            .unwrap_or_default()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    contacts: Vec<Contact>,
}

#[derive(Debug, thiserror::Error)]
pub enum ContactError {
    #[error("this contact is already registered as \"{0}\"")]
    AlreadyExists(String),
    #[error("a contact named \"{0}\" already exists; choose another label")]
    LabelTaken(String),
    #[error("no such contact: {0}")]
    NotFound(String),
    #[error("that is your own contact code; ask the other person for theirs")]
    ThisIsMe,
    #[error("the contact label is empty or too long (1-{MAX_LABEL_CHARS} characters)")]
    BadLabel,
    #[error("too many contacts (limit {MAX_CONTACTS})")]
    TooMany,
    #[error("could not save the contact list: {0}")]
    Save(String),
}

pub struct ContactStore {
    path: PathBuf,
    inner: RwLock<Vec<Contact>>,
}

/// Fields a caller may change.
#[derive(Debug, Default, Clone)]
pub struct ContactUpdate {
    pub label: Option<String>,
    pub allow_send: Option<bool>,
    pub allow_receive: Option<bool>,
    /// `Some(0)` clears the per-contact limit.
    pub max_file_size: Option<u64>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn clean_label(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_owned();
    if s.is_empty() || s.chars().count() > MAX_LABEL_CHARS {
        None
    } else {
        Some(s)
    }
}

impl ContactStore {
    /// Load `{data_dir}/contacts.json` (or start empty).
    pub fn open(data_dir: &Path) -> Self {
        let path = data_dir.join(CONTACTS_FILE);
        let contacts = Self::load(&path);
        Self {
            path,
            inner: RwLock::new(contacts),
        }
    }

    fn load(path: &Path) -> Vec<Contact> {
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                warn!("cannot read the contact list: {e}");
                return Vec::new();
            }
        };
        match serde_json::from_slice::<Document>(&raw) {
            Ok(doc) => {
                if doc.version > SCHEMA_VERSION {
                    warn!(
                        "contacts.json was written by a newer Miasma (schema {}); \
                         unknown fields are ignored",
                        doc.version
                    );
                }
                let mut seen = std::collections::HashSet::new();
                doc.contacts
                    .into_iter()
                    .filter(|c| c.endpoint_bytes().is_some() && seen.insert(c.endpoint_id.clone()))
                    .map(|mut c| {
                        c.endpoint_id = c.endpoint_id.to_ascii_lowercase();
                        if c.id.is_empty() {
                            c.id = c.endpoint_id[..16].to_owned();
                        }
                        c
                    })
                    .collect()
            }
            Err(e) => {
                let aside = crate::paths::contacts_corrupt_aside(path, now_secs());
                warn!(
                    "contacts.json is unreadable ({e}); moved to {}",
                    aside.display()
                );
                let _ = std::fs::rename(path, aside);
                Vec::new()
            }
        }
    }

    fn save_locked(&self, list: &[Contact]) -> Result<(), ContactError> {
        let doc = Document {
            version: SCHEMA_VERSION,
            contacts: list.to_vec(),
        };
        let bytes =
            serde_json::to_vec_pretty(&doc).map_err(|e| ContactError::Save(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        crate::secure_file::atomic_write_restricted(&self.path, &bytes)
            .map_err(|e: MiasmaError| ContactError::Save(e.to_string()))
    }

    pub fn list(&self) -> Vec<Contact> {
        self.inner.read().unwrap().clone()
    }

    /// Find by label (case-insensitive), id, or endpoint ID (full hex).
    pub fn find(&self, selector: &str) -> Option<Contact> {
        let sel = selector.trim();
        let g = self.inner.read().unwrap();
        g.iter()
            .find(|c| c.id == sel || c.endpoint_id.eq_ignore_ascii_case(sel))
            .or_else(|| g.iter().find(|c| c.label.eq_ignore_ascii_case(sel)))
            .cloned()
    }

    /// The contact whose endpoint ID is `id`, whatever its permissions.
    pub fn by_endpoint(&self, id: &[u8; 32]) -> Option<Contact> {
        let hex = hex::encode(id);
        self.inner
            .read()
            .unwrap()
            .iter()
            .find(|c| c.endpoint_id == hex)
            .cloned()
    }

    /// Register a contact. `own_id` is this node's endpoint ID (refused).
    pub fn add(
        &self,
        code: &ContactCode,
        label: Option<&str>,
        own_id: Option<&[u8; 32]>,
    ) -> Result<Contact, ContactError> {
        if own_id == Some(code.endpoint_id()) {
            return Err(ContactError::ThisIsMe);
        }
        let hexid = hex::encode(code.endpoint_id());
        let mut g = self.inner.write().unwrap();
        if let Some(c) = g.iter().find(|c| c.endpoint_id == hexid) {
            return Err(ContactError::AlreadyExists(c.label.clone()));
        }
        if g.len() >= MAX_CONTACTS {
            return Err(ContactError::TooMany);
        }
        let label = match label {
            Some(l) => clean_label(l).ok_or(ContactError::BadLabel)?,
            None => format!("contact-{}", &code.fingerprint()[..5]),
        };
        if g.iter().any(|c| c.label.eq_ignore_ascii_case(&label)) {
            return Err(ContactError::LabelTaken(label));
        }
        let contact = Contact {
            id: hexid[..16].to_owned(),
            label,
            endpoint_id: hexid,
            added_at: now_secs(),
            allow_receive: true,
            allow_send: true,
            max_file_size: None,
        };
        g.push(contact.clone());
        self.save_locked(&g)?;
        Ok(contact)
    }

    pub fn update(&self, selector: &str, up: &ContactUpdate) -> Result<Contact, ContactError> {
        let mut g = self.inner.write().unwrap();
        let sel = selector.trim();
        let idx = g
            .iter()
            .position(|c| c.id == sel || c.endpoint_id.eq_ignore_ascii_case(sel))
            .or_else(|| g.iter().position(|c| c.label.eq_ignore_ascii_case(sel)))
            .ok_or_else(|| ContactError::NotFound(selector.to_owned()))?;
        let mut next = g[idx].clone();
        if let Some(l) = &up.label {
            let l = clean_label(l).ok_or(ContactError::BadLabel)?;
            if g.iter()
                .enumerate()
                .any(|(i, c)| i != idx && c.label.eq_ignore_ascii_case(&l))
            {
                return Err(ContactError::LabelTaken(l));
            }
            next.label = l;
        }
        if let Some(v) = up.allow_send {
            next.allow_send = v;
        }
        if let Some(v) = up.allow_receive {
            next.allow_receive = v;
        }
        if let Some(m) = up.max_file_size {
            next.max_file_size = if m == 0 { None } else { Some(m) };
        }
        g[idx] = next.clone();
        self.save_locked(&g)?;
        Ok(next)
    }

    pub fn remove(&self, selector: &str) -> Result<Contact, ContactError> {
        let mut g = self.inner.write().unwrap();
        let sel = selector.trim();
        let idx = g
            .iter()
            .position(|c| c.id == sel || c.endpoint_id.eq_ignore_ascii_case(sel))
            .or_else(|| g.iter().position(|c| c.label.eq_ignore_ascii_case(sel)))
            .ok_or_else(|| ContactError::NotFound(selector.to_owned()))?;
        let removed = g.remove(idx);
        self.save_locked(&g)?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn code(seed: u8) -> ContactCode {
        ContactCode::new(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    #[test]
    fn round_trip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let s = ContactStore::open(dir.path());
        assert!(s.list().is_empty());
        let c = s.add(&code(1), Some("Taro"), None).unwrap();
        assert!(c.allow_receive && c.allow_send && c.max_file_size.is_none());
        s.add(&code(2), None, None).unwrap();
        drop(s);
        let s2 = ContactStore::open(dir.path());
        assert_eq!(s2.list().len(), 2);
        assert_eq!(s2.find("taro").unwrap().label, "Taro");
        assert!(s2.by_endpoint(code(1).endpoint_id()).is_some());
        assert!(s2.by_endpoint(code(9).endpoint_id()).is_none());
    }

    #[test]
    fn duplicates_self_and_labels() {
        let dir = tempfile::tempdir().unwrap();
        let s = ContactStore::open(dir.path());
        s.add(&code(1), Some("A"), None).unwrap();
        assert!(matches!(
            s.add(&code(1), Some("B"), None),
            Err(ContactError::AlreadyExists(_))
        ));
        assert!(matches!(
            s.add(&code(2), Some("a"), None),
            Err(ContactError::LabelTaken(_))
        ));
        assert!(matches!(
            s.add(&code(3), Some("  "), None),
            Err(ContactError::BadLabel)
        ));
        assert!(matches!(
            s.add(&code(4), Some("me"), Some(code(4).endpoint_id())),
            Err(ContactError::ThisIsMe)
        ));
    }

    #[test]
    fn update_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let s = ContactStore::open(dir.path());
        s.add(&code(1), Some("A"), None).unwrap();
        let u = s
            .update(
                "A",
                &ContactUpdate {
                    allow_receive: Some(false),
                    max_file_size: Some(100),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(!u.allow_receive && u.max_file_size == Some(100));
        let u = s
            .update(
                "A",
                &ContactUpdate {
                    max_file_size: Some(0),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(u.max_file_size.is_none());
        s.remove("A").unwrap();
        assert!(matches!(s.remove("A"), Err(ContactError::NotFound(_))));
    }

    #[test]
    fn corrupt_file_is_moved_aside_and_list_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONTACTS_FILE), b"{ not json").unwrap();
        let s = ContactStore::open(dir.path());
        assert!(s.list().is_empty());
        let n = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .count();
        assert_eq!(n, 1);
        // And it can be written again.
        s.add(&code(1), Some("A"), None).unwrap();
    }

    #[test]
    fn unknown_fields_and_missing_fields_are_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let eid = hex::encode(code(1).endpoint_id());
        let json = format!(
            r#"{{"version":7,"future":1,"contacts":[{{"label":"X","endpoint_id":"{eid}","new_thing":true}},{{"label":"bad","endpoint_id":"zz"}}]}}"#
        );
        std::fs::write(dir.path().join(CONTACTS_FILE), json).unwrap();
        let s = ContactStore::open(dir.path());
        let l = s.list();
        assert_eq!(l.len(), 1);
        assert!(l[0].allow_receive && l[0].allow_send);
        assert_eq!(l[0].id.len(), 16);
    }
}
