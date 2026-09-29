//! Local inbox and outbox for directed share envelopes.
//!
//! Envelopes are stored as JSON files in subdirectories of the data dir:
//! - `{data_dir}/directed/incoming/{envelope_id_hex}.json`
//! - `{data_dir}/directed/outgoing/{envelope_id_hex}.json`

use std::{
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::envelope::{DirectedEnvelope, EnvelopeState};

/// Maximum number of envelopes allowed in a single directory (inbox or outbox).
/// Prevents unbounded disk growth from malicious or excessive invite delivery.
const MAX_ENVELOPES: usize = 10_000;

/// Summary of an envelope for listing (avoids loading full envelope).
#[derive(Clone, Serialize, Deserialize)]
pub struct EnvelopeSummary {
    pub envelope_id: String,
    /// Sender's self-asserted X25519 sharing key from the envelope.
    pub sender_pubkey: String,
    /// Authenticated libp2p PeerId observed on the Invite transport. Present for
    /// new incoming envelopes; legacy/unbound records have `None`.
    #[serde(default)]
    pub sender_peer_id: Option<String>,
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

impl fmt::Debug for EnvelopeSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeSummary")
            .field("envelope_id", &self.envelope_id)
            .field("sender_pubkey", &self.sender_pubkey)
            .field("sender_peer_id", &self.sender_peer_id)
            .field("recipient_pubkey", &self.recipient_pubkey)
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("retention_secs", &self.retention_secs)
            .field(
                "challenge_code",
                &self.challenge_code.as_ref().map(|_| "<redacted>"),
            )
            .field("filename", &self.filename.as_ref().map(|_| "<redacted>"))
            .field("file_size", &self.file_size)
            .finish()
    }
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
        let json =
            Zeroizing::new(serde_json::to_vec_pretty(envelope).context("serialize envelope")?);
        crate::secure_file::atomic_write_restricted(&path, json.as_slice())
            .context("write outgoing envelope")?;
        Ok(())
    }

    /// Load an outgoing envelope by hex ID.
    pub fn load_outgoing(&self, id_hex: &str) -> Result<DirectedEnvelope> {
        let path = self.outgoing_path(id_hex);
        let json = Zeroizing::new(
            std::fs::read(&path).with_context(|| format!("read outgoing {id_hex}"))?,
        );
        serde_json::from_slice(json.as_slice()).context("deserialize envelope")
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
        let json =
            Zeroizing::new(serde_json::to_vec_pretty(envelope).context("serialize envelope")?);
        crate::secure_file::atomic_write_restricted(&path, json.as_slice())
            .context("write incoming envelope")?;
        Ok(())
    }

    /// Load an incoming envelope by hex ID.
    pub fn load_incoming(&self, id_hex: &str) -> Result<DirectedEnvelope> {
        let path = self.incoming_path(id_hex);
        let json = Zeroizing::new(
            std::fs::read(&path).with_context(|| format!("read incoming {id_hex}"))?,
        );
        serde_json::from_slice(json.as_slice()).context("deserialize envelope")
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
        let peer_path = self.incoming_dir.join(format!("{id_hex}.peer"));
        if peer_path.exists() {
            std::fs::remove_file(&peer_path).context("delete incoming peer binding")?;
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
                        let json = Zeroizing::new(json);
                        if let Ok(mut env) =
                            serde_json::from_slice::<DirectedEnvelope>(json.as_slice())
                        {
                            if env.is_expired(now_secs) && !env.state.is_terminal() {
                                env.state = EnvelopeState::Expired;
                                if let Ok(serialized) = serde_json::to_vec_pretty(&env) {
                                    let serialized = Zeroizing::new(serialized);
                                    let _ = crate::secure_file::atomic_write_restricted(
                                        &path,
                                        serialized.as_slice(),
                                    );
                                }
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
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0);
        if count >= MAX_ENVELOPES {
            anyhow::bail!("{name} full: {count} envelopes (max {MAX_ENVELOPES})");
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
                let json = Zeroizing::new(json);
                if let Ok(env) = serde_json::from_slice::<DirectedEnvelope>(json.as_slice()) {
                    // Try to load the challenge code for incoming envelopes.
                    let challenge_code = if is_incoming {
                        let challenge_path = path.with_extension("challenge");
                        std::fs::read_to_string(&challenge_path).ok()
                    } else {
                        None
                    };

                    let id_hex = env.id_hex();
                    summaries.push(EnvelopeSummary {
                        envelope_id: id_hex.clone(),
                        sender_pubkey: super::envelope::format_sharing_key(&env.sender_pubkey),
                        sender_peer_id: if is_incoming {
                            self.load_incoming_peer_id(&id_hex)
                        } else {
                            None
                        },
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
        crate::secure_file::atomic_write_restricted(&path, code.as_bytes())
            .context("write challenge code")?;
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

    /// Bind an incoming envelope to the authenticated libp2p PeerId that sent
    /// the initial Invite. The binding is immutable: a different peer cannot
    /// claim an existing envelope_id later.
    pub fn bind_incoming_peer_id(&self, id_hex: &str, peer_id: &str) -> Result<()> {
        use std::io::Write;

        let path = self.incoming_dir.join(format!("{id_hex}.peer"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => file
                .write_all(peer_id.as_bytes())
                .context("write incoming peer binding"),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read_to_string(&path)
                    .context("read existing incoming peer binding")?;
                if existing.trim() == peer_id {
                    Ok(())
                } else {
                    anyhow::bail!("incoming envelope is already bound to a different peer")
                }
            }
            Err(e) => Err(e).context("create incoming peer binding"),
        }
    }

    /// Load the authenticated sender PeerId for an incoming envelope.
    pub fn load_incoming_peer_id(&self, id_hex: &str) -> Option<String> {
        let path = self.incoming_dir.join(format!("{id_hex}.peer"));
        std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Check whether a follow-up request comes from the PeerId bound by the
    /// original Invite. Missing/corrupt sidecars fail closed.
    pub fn incoming_peer_is_bound(&self, id_hex: &str, peer_id: &str) -> bool {
        self.load_incoming_peer_id(id_hex).as_deref() == Some(peer_id)
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

    #[test]
    fn envelope_summary_debug_redacts_challenge_and_filename() {
        let summary = EnvelopeSummary {
            envelope_id: "env".into(),
            sender_pubkey: "sender".into(),
            sender_peer_id: Some("peer".into()),
            recipient_pubkey: "recipient".into(),
            state: EnvelopeState::ChallengeIssued,
            created_at: 1,
            expires_at: 2,
            retention_secs: 3,
            challenge_code: Some("ABCD-SECRET".into()),
            filename: Some("private-name.txt".into()),
            file_size: 4,
        };
        let rendered = format!("{summary:?}");
        assert!(rendered.contains("EnvelopeSummary"));
        assert!(!rendered.contains("ABCD-SECRET"));
        assert!(!rendered.contains("private-name.txt"));
        assert!(rendered.contains("<redacted>"));
    }
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
    fn incoming_peer_binding_is_immutable() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();
        let id = hex::encode([0x42u8; 32]);

        assert!(!inbox.incoming_peer_is_bound(&id, "peer-a"));
        inbox.bind_incoming_peer_id(&id, "peer-a").unwrap();
        inbox.bind_incoming_peer_id(&id, "peer-a").unwrap();
        assert_eq!(inbox.load_incoming_peer_id(&id).as_deref(), Some("peer-a"));
        assert!(inbox.bind_incoming_peer_id(&id, "peer-b").is_err());
        assert_eq!(inbox.load_incoming_peer_id(&id).as_deref(), Some("peer-a"));
    }

    #[test]
    fn deleting_incoming_envelope_removes_peer_binding() {
        let tmp = TempDir::new().unwrap();
        let inbox = DirectedInbox::open(tmp.path()).unwrap();
        let env = make_test_envelope();
        let id = env.id_hex();
        inbox.save_incoming(&env).unwrap();
        inbox.bind_incoming_peer_id(&id, "peer-a").unwrap();

        inbox.delete_incoming(&id).unwrap();
        assert!(inbox.load_incoming_peer_id(&id).is_none());
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
        inbox
            .bind_incoming_peer_id(&env2.id_hex(), "peer-authenticated")
            .unwrap();

        let list = inbox.list_incoming();
        assert_eq!(list.len(), 2);
        // Sorted by created_at descending.
        assert!(list[0].created_at >= list[1].created_at);
        assert_eq!(
            list[0].sender_peer_id.as_deref(),
            Some("peer-authenticated")
        );
        assert!(list[1].sender_peer_id.is_none());
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

        #[cfg(any(windows, unix))]
        {
            let envelope_path = inbox.incoming_path(&env.id_hex());
            let challenge_path = inbox
                .incoming_dir
                .join(format!("{}.challenge", env.id_hex()));
            assert!(crate::secure_file::verify_restricted(&envelope_path).unwrap());
            assert!(crate::secure_file::verify_restricted(&challenge_path).unwrap());
        }

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
