//! One attempt over the existing authenticated chat channel, without an outbox.

use std::{future::Future, time::Duration};

use super::{proto, AckStatus, ChatService, Frame};
use crate::chat::call::signal::Record;
use tokio::time::{timeout_at, Instant};

/// Maximum time allowed for the entire send attempt, including connection.
pub const CALL_CONTROL_SEND_TTL_MS: u64 = 45_000;

/// Fixed messages keep identifiers and underlying transport errors private.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CallControlError {
    #[error("invalid call control record")]
    InvalidRecord,
    #[error("sending to this contact is not allowed")]
    NotAllowed,
    #[error("peer is unreachable or the connection was lost")]
    Unreachable,
    #[error("call control send deadline expired")]
    DeadlineExpired,
    #[error("could not prepare call control envelope")]
    Prepare,
    #[error("peer did not accept the call control envelope")]
    Rejected,
}

async fn before_deadline<T>(
    deadline: Instant,
    attempt: impl Future<Output = Result<T, CallControlError>>,
) -> Result<T, CallControlError> {
    timeout_at(deadline, attempt)
        .await
        .map_err(|_| CallControlError::DeadlineExpired)?
}

impl ChatService {
    /// Send one encoded call record, once, without storing it in the outbox.
    /// A successful acknowledgement only confirms the envelope was accepted;
    /// call signalling dispatch is not yet connected on the receiver.
    pub async fn send_call_control(
        &self,
        peer: &[u8; 32],
        encoded: &[u8],
    ) -> Result<(), CallControlError> {
        let deadline = Instant::now() + Duration::from_millis(CALL_CONTROL_SEND_TTL_MS);
        Record::decode(encoded).map_err(|_| CallControlError::InvalidRecord)?;
        if !matches!(self.contacts.by_endpoint(peer), Some(c) if c.allow_send) {
            return Err(CallControlError::NotAllowed);
        }
        before_deadline(deadline, async {
            let mut slot = None;
            let (conn, _) = self
                .ensure_conn(&mut slot, peer)
                .await
                .map_err(|_| CallControlError::Unreachable)?;
            let (wire, env_id) = self
                .core
                .seal_for(peer, encoded)
                .map_err(|_| CallControlError::Prepare)?;
            // Sealing writes ratchet state synchronously; do not start a send
            // if that work consumed the remaining time.
            if Instant::now() >= deadline {
                return Err(CallControlError::DeadlineExpired);
            }
            let _activity = self.activity.enter();
            let (mut tx, mut rx) = conn
                .open_bi()
                .await
                .map_err(|_| CallControlError::Unreachable)?;
            proto::write_frame(&mut tx, &Frame::Deliver(wire))
                .await
                .map_err(|_| CallControlError::Unreachable)?;
            let _ = tx.finish();
            match proto::read_frame(&mut rx).await {
                Ok(Frame::Ack(a)) if a.envelope_id == env_id => match a.status {
                    AckStatus::Stored | AckStatus::Duplicate => Ok(()),
                    _ => Err(CallControlError::Rejected),
                },
                _ => Err(CallControlError::Unreachable),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{
        call::signal::{new_call_id, new_call_nonce},
        engine_tests::side,
    };

    #[tokio::test]
    async fn deadline_and_single_attempt() {
        let calls = std::cell::Cell::new(0);
        let result = before_deadline(Instant::now() + Duration::from_secs(1), async {
            calls.set(calls.get() + 1);
            Err::<(), _>(CallControlError::Unreachable)
        })
        .await;
        assert_eq!(result, Err(CallControlError::Unreachable));
        assert_eq!(calls.get(), 1);
        let result = before_deadline(
            Instant::now(),
            std::future::pending::<Result<(), CallControlError>>(),
        )
        .await;
        assert_eq!(result, Err(CallControlError::DeadlineExpired));
    }

    #[test]
    fn expired_offer_is_silently_discarded_without_outbox() {
        let sender = side();
        let receiver = side();
        let record = Record::Offer {
            call_id: new_call_id(),
            call_nonce: new_call_nonce(),
            created_at_ms: 1,
            expires_at_ms: 2,
            capabilities: Vec::new(),
        };
        let body = record.encode().unwrap();
        let (wire, _) = sender.core.seal_for(&receiver.id(), &body).unwrap();
        assert_eq!(sender.core.outbox.len(), 0);
        assert_eq!(
            receiver.core.accept(&sender.id(), &wire, 3).status,
            AckStatus::Stored
        );
        assert!(receiver.texts(&sender.id()).is_empty());
        assert_eq!(receiver.core.outbox.len(), 0);
    }
}
