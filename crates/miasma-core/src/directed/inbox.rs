//! Local inbox and outbox for directed share envelopes.
//!
//! Envelopes are stored as JSON files in subdirectories of the data dir:
//! - `{data_dir}/directed/incoming/{envelope_id_hex}.json`
//! - `{data_dir}/directed/outgoing/{envelope_id_hex}.json`

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::envelope::{DirectedEnvelope, EnvelopeState};

/// Maximum number of envelopes allowed in a single directory (inbox or outbox).
/// Prevents unbounded disk growth from malicious or excessive invite delivery.
const MAX_ENVELOPES: usize = 10_000;

/// Summary of an envelope for listing (avoids loading full envelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSummary {
    pub envelope_id: String,
    pub sender_pubkey: String,
    pub recipient_pubkey: String,
    pub state: EnvelopeState,
    pub created_at: u64,
    pub expires_at: u64,
    pub retention_secs: u64,
    /// Only set for incoming envelopes where challenge was generated.
    #[serde(default)]
    pub challenge_code: Option<String>,
    /// Original filename if provided.
    #[serde(default)]
    pub filename: Option<String>,
    /// Original file size.
    #[serde(default)]
    pub file_size: u64,
}

/// Local directed share storage.
pub struct DirectedInbox {
    incoming_dir: PathBuf,
    outgoing_dir: PathBuf,
}

impl DirectedInbox {
    /// Open or create the inbox at `data_dir/directed/`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let incoming_dir = data_dir.join("directed").join("incoming");
        let outgoing_dir = data_dir.join("directed").join("outgoing");
        std::fs::create_dir_all(&incoming_dir).context("create incoming dir")?;
        std::fs::create_dir_all(&outgoing_dir).context("create outgoing dir")?;
        Ok(Self {
            incoming_dir,
            outgoing_dir,
        })
    }

    // ─── Outgoing (sender) ──────────────────────────────────────────────

    /// Save an outgoing envelope (sender side).
    pub fn save_outgoing(&self, envelope: &DirectedEnvelope) -> Result<()> {
        let path = self.outgoing_path(&envelope.id_hex());
        let json = serde_json::to_vec_pretty(envelope).context("serialize envelope")?;
        std::fs::write(&path, &json).context("write outgoing envelope")?;
        Ok(())
    }

    /// Load an outgoing envelope by hex ID.
    pub fn load_outgoing(&self, id_hex: &str) -> Result<DirectedEnvelope> {
        let path = self.outgoing_path(id_hex);
        let json = std::fs::read(&path).with_context(|| format!("read outgoing {id_hex}"))?;
        serde_json::from_slice(&json).context("deserialize envelope")
    }

    /// List all outgoing envelopes.
    pub fn list_outgoing(&self) -> Vec<EnvelopeSummary> {
        self.list_dir(&self.outgoing_dir, false)
    }

    /// Delete an outgoing envelope.
    pub fn delete_outgoing(&self, id_hex: &str) -> Result<()> {
        let path = self.outgoing_path(id_hex);
        if path.exists() {
            std::fs::remove_file(&path).context("delete outgoing envelope")?;
        }
        Ok(())
    }

    // ─── Incoming (recipient) ───────────────────────────────────────────

    /// Save an incoming envelope (recipient side).
    ///
    /// Rejects if the inbox already has `MAX_ENVELOPES` items (unless
    /// this is an update to an existing envelope).
    pub fn save_incoming(&self, envelope: &DirectedEnvelope) -> Result<()> {
        let path = self.incoming_path(&envelope.id_hex());
        if !path.exists() {
            self.check_limit(&self.incoming_dir, "inbox")?;
        }
        let json = serde_json::to_vec_pretty(envelope).context("serialize envelope")?;
        std::fs::write(&path, &json).context("write incoming envelope")?;
        Ok(())
    }

    /// Load an incoming envelope by hex ID.
    pub fn load_incoming(&self, id_hex: &str) -> Result<DirectedEnvelope> {
        let path = self.incoming_path(id_hex);
        let json = std::fs::read(&path).with_context(|| format!("read incoming {id_hex}"))?;
        serde_json::from_slice(&json).context("deserialize envelope")
    }

    /// List all incoming envelopes.
    pub fn list_incoming(&self) -> Vec<EnvelopeSummary> {
        self.list_dir(&self.incoming_dir, true)
    }

    /// Delete an incoming envelope.
    pub fn delete_incoming(&self, id_hex: &str) -> Result<()> {
        let path = self.incoming_path(id_hex);
        if path.exists() {
            std::fs::remove_file(&path).context("delete incoming envelope")?;
        }
        Ok(())
    }

    /// Load an incoming envelope, update its state, and save back.
    pub fn update_incoming_state(
        &self,
        id_hex: &str,
        new_state: EnvelopeState,
    ) -> Result<DirectedEnvelope> {
        let mut envelope = self.load_incoming(id_hex)?;
        envelope.state = new_state;
        self.save_incoming(&envelope)?;
        Ok(envelope)
    }

    /// Load an outgoing envelope, update its state, and save back.
    pub fn update_outgoing_state(
        &self,
        id_hex: &str,
        new_state: EnvelopeState,
    ) -> Result<DirectedEnvelope> {
        let mut envelope = self.load_outgoing(id_hex)?;
        envelope.state = new_state;
        self.save_outgoing(&envelope)?;
        Ok(envelope)
    }

    /// Expire all envelopes past their retention period.
    ///
    /// Also cleans up orphaned `.challenge` files for envelopes that have
    /// already reached a terminal state.
    pub fn expire_all(&self, now_secs: u64) {
        for dir in [&self.incoming_dir, &self.outgoing_dir] {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    if let Ok(json) = std::fs::read(&path) {
                        if let Ok(mut env) = serde_json::from_slice::<DirectedEnvelope>(&json) {
                            if env.is_expired(now_secs) && !env.state.is_terminal() {
                                env.state = EnvelopeState::Expired;
                                let _ = std::fs::write(
                                    &path,
                                    serde_json::to_vec_pretty(&env).unwrap_or_default(),
                                );
                            }
                            // Clean up challenge file for terminal envelopes.
                            if env.state.is_terminal() {
                                let challenge_path = path.with_extension("challenge");
                                if challenge_path.exists() {
                                    let _ = std::fs::remove_file(&challenge_path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Clean up the challenge code file for an envelope that has reached
    /// a terminal state. Should be called whenever a terminal transition
    /// happens on an incoming envelope.
    pub fn cleanup_challenge(&self, id_hex: &str) {
        let challenge_path = self.incoming_dir.join(format!("{id_hex}.challenge"));
        if challenge_path.exists() {
            let _ = std::fs::remove_file(&challenge_path);
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    /// Check that the directory has not exceeded `MAX_ENVELOPES` .json files.
    fn check_limit(&self, dir: &Path, name: &str) -> Result<()> {
        let count = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|x| x.to_str())
                            == Some("json")
                    })
                    .count()
            })
            .unwrap_or(0);
        if count >= MAX_ENVELOPES {
            anyhow::bail!(
                "{name} full: {count} envelopes (max {MAX_ENVELOPES})"
            );
        }
        Ok(())
    }

    fn incoming_path(&self, id_hex: &str) -> PathBuf {
        self.incoming_dir.join(format!("{id_hex}.json"))
    }

    fn outgoing_path(&self, id_hex: &str) -> PathBuf {
        self.outgoing_dir.join(format!("{id_hex}.json"))
    }

    fn list_dir(&self, dir: &Path, is_incoming: bool) -> Vec<EnvelopeSummary> {
        let mut summaries = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return summaries;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(json) = std::fs::read(&path) {
                if let Ok(env) = serde_json::from_slice::<DirectedEnvelope>(&json) {
                    // Try to load the challenge code for incoming envelopes.
                    let challenge_code = if is_incoming {
                        let challenge_path = path.with_extension("challenge");
                        std::fs::read_to_string(&challenge_path).ok()
                    } else {
                        None
                    };

                    summaries.push(EnvelopeSummary {
                        envelope_id: env.id_hex(),
                        sender_pubkey: super::envelope::format_sharing_key(&env.sender_pubkey),
                        recipient_pubkey: super::envelope::format_sharing_key(
                            &env.recipient_pubkey,
                        ),
                        state: env.state,
                        created_at: env.created_at,
                        expires_at: env.expires_at,
                        retention_secs: env.retention_secs,
                        challenge_code,
                        filename: None, // Not stored in summary to avoid decryption
                        file_size: 0,
                    });
                }
            }
        }
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries
    }

    /// Store the raw challenge code alongside the incoming envelope.
    /// This is stored separately so it's only on the recipient's machine.
    pub fn save_challenge_code(&self, id_hex: &str, code: &str) -> Result<()> {
        let path = self.incoming_dir.join(format!("{id_hex}.challenge"));
        std::fs::write(&path, code).context("write challenge code")?;
        Ok(())
    }

    /// Load the challenge code for an incoming envelope.
    pub fn load_challenge_code(&self, id_hex: &str) -> Option<String> {
        let path = self.incoming_dir.join(format!("{id_hex}.challenge"));
        std::fs::read_to_string(&path).ok()
    }

    /// Delete the challenge code file.
    pub fn delete_challenge_code(&self, id_hex: &str) {
        let path = self.incoming_dir.join(format!("{id_hex}.challenge"));
        let _ = std::fs::remove_file(&path);
    }

    /// Store the recipient's PeerId alongside an outgoing envelope.
    /// Used to reconnect for challenge confirmation.
    pub fn save_outgoing_peer_id(&self, id_hex: &str, peer_id: &str) {
        let path = self.outgoing_dir.join(format!("{id_hex}.peer"));
        let _ = std::fs::write(&path, peer_id);
    }

    /// Load the recipient's PeerId for an outgoing envelope.
    pub fn load_outgoing_peer_id(&self, id_hex: &str) -> Option<String> {
        let path = self.outgoing_dir.join(format!("{id_hex}.peer"));
        std::fs::read_to_string(&path).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_envelope() -> DirectedEnvelope {
        DirectedEnvelope {
            envelope_id: [0x42u8; 32],
            version: 1,
            sender_pubkey: [0x01u8; 32],
            recipient_pubkey: [0x02u8; 32],
            ephemeral_pubkey: [0x03u8; 32],
            encrypted_payload: vec![0x04; 64],
            payload_nonce: [0x05u8; 24],
            password_salt: [0x06u8; 32],
            expires_at: u64::MAX,
            created_at: 1000,
            state: EnvelopeState::Pending,
            challenge_hash: None,
            password_attempts_remaining: 3,
            challenge_attempts_remaining: 3,
            challenge_expires_at: 0,
            retention_secs: 86400,
        }
    }

    #[test]
    fn outgoing_save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let env = make_test_envelope();
        inbox.save_outgoing(&env).unwrap();

        let loaded = inbox.load_outgoing(&env.id_hex()).unwrap();
        assert_eq!(loaded.envelope_id, env.envelope_id);
        assert_eq!(loaded.state, EnvelopeState::Pending);
    }

    #[test]
    fn incoming_save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let env = make_test_envelope();
        inbox.save_incoming(&env).unwrap();

        let loaded = inbox.load_incoming(&env.id_hex()).unwrap();
        assert_eq!(loaded.envelope_id, env.envelope_id);
    }

    #[test]
    fn list_incoming() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let mut env1 = make_test_envelope();
        env1.envelope_id = [0x01; 32];
        env1.created_at = 100;
        inbox.save_incoming(&env1).unwrap();

        let mut env2 = make_test_envelope();
        env2.envelope_id = [0x02; 32];
        env2.created_at = 200;
        inbox.save_incoming(&env2).unwrap();

        let list = inbox.list_incoming();
        assert_eq!(list.len(), 2);
        // Sorted by created_at descending.
        assert!(list[0].created_at >= list[1].created_at);
    }

    #[test]
    fn update_state() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let env = make_test_envelope();
        inbox.save_incoming(&env).unwrap();

        let updated = inbox
            .update_incoming_state(&env.id_hex(), EnvelopeState::Confirmed)
            .unwrap();
        assert_eq!(updated.state, EnvelopeState::Confirmed);

        let loaded = inbox.load_incoming(&env.id_hex()).unwrap();
        assert_eq!(loaded.state, EnvelopeState::Confirmed);
    }

    #[test]
    fn challenge_code_storage() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let env = make_test_envelope();
        inbox.save_incoming(&env).unwrap();
        inbox
            .save_challenge_code(&env.id_hex(), "ABCD-1234")
            .unwrap();

        let code = inbox.load_challenge_code(&env.id_hex());
        assert_eq!(code, Some("ABCD-1234".to_string()));

        inbox.delete_challenge_code(&env.id_hex());
        assert!(inbox.load_challenge_code(&env.id_hex()).is_none());
    }

    #[test]
    fn expire_all() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let mut env = make_test_envelope();
        env.expires_at = 500;
        inbox.save_incoming(&env).unwrap();

        inbox.expire_all(600);
        let loaded = inbox.load_incoming(&env.id_hex()).unwrap();
        assert_eq!(loaded.state, EnvelopeState::Expired);
    }

    #[test]
    fn delete_envelope() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();

        let env = make_test_envelope();
        inbox.save_incoming(&env).unwrap();
        assert!(inbox.load_incoming(&env.id_hex()).is_ok());

        inbox.delete_incoming(&env.id_hex()).unwrap();
        assert!(inbox.load_incoming(&env.id_hex()).is_err());
    }
}
