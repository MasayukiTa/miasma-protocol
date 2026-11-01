//! The concrete transport for the custody verbs over the chat channel.
//!
//! A deposit or collection reaches a holder on the same ALPN chat uses
//! (`miasma/chat/1`), on a bidirectional stream of its own that begins with
//! [`wire::CUSTODY_STREAM_TAG`] so the holder can tell it from a message
//! stream. One stream carries one request and its one answer. The peer is
//! authenticated by the QUIC handshake exactly as a chat message is; the
//! holder checks in addition that the caller is a contact it trusts.
//!
//! The [`client::MailboxTransport`] trait is synchronous, and the collector and
//! depositor run on a blocking task (as the catch-up does), so each exchange is
//! driven to completion on the runtime handle. Nothing here is logged: the
//! bytes exchanged are the sealed envelope.

use std::{sync::Arc, time::Duration};

use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;

use super::{
    client::{MailboxError, MailboxTransport},
    holder::{CustodyError, DepositOutcome},
    ids::{ItemId, RecipientTag},
    wire::{self, Request, Response},
};
use crate::transport::iroh_direct::{IrohNode, CHAT_ALPN};

/// How long one custody exchange (dial excluded) may take.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Dials holders on the chat ALPN and runs one custody request per stream.
pub struct ChatMailboxTransport {
    node: Arc<IrohNode>,
    handle: Handle,
}

impl ChatMailboxTransport {
    /// A transport that dials from `node`. Must be built on a Tokio runtime;
    /// the current handle drives each blocking exchange.
    pub fn new(node: Arc<IrohNode>) -> Self {
        Self {
            node,
            handle: Handle::current(),
        }
    }

    fn exchange(&self, holder: &[u8; 32], req: &Request) -> Result<Response, MailboxError> {
        let node = self.node.clone();
        let holder = *holder;
        let req = req.clone();
        self.handle.block_on(async move {
            let conn = node
                .connect_alpn(&holder, CHAT_ALPN)
                .await
                .map_err(|_| MailboxError::Unreachable)?;
            let out = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
                let (mut tx, mut rx) = conn
                    .open_bi()
                    .await
                    .map_err(|_| MailboxError::Unreachable)?;
                // The stream tag goes first, then the request frame.
                tx.write_all(&[wire::CUSTODY_STREAM_TAG])
                    .await
                    .map_err(|_| MailboxError::Unreachable)?;
                wire::write_request(&mut tx, &req)
                    .await
                    .map_err(|_| MailboxError::Unreachable)?;
                let _ = tx.finish();
                wire::read_response(&mut rx)
                    .await
                    .map_err(|_| MailboxError::Unreachable)
            })
            .await
            .map_err(|_| MailboxError::Unreachable)?;
            // The connection is left to close on its own; it is not reused.
            conn.close(0u32.into(), b"done");
            out
        })
    }
}

/// Turn a holder's refusal frame into the client's error.
fn refused(e: CustodyError) -> MailboxError {
    MailboxError::Refused(e)
}

impl MailboxTransport for ChatMailboxTransport {
    fn deposit(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, MailboxError> {
        let _ = now_ms;
        let req = Request::Deposit {
            tag,
            item,
            blob: blob.to_vec(),
        };
        match self.exchange(holder, &req)? {
            Response::Deposited(o) => Ok(o),
            Response::Refused(e) => Err(refused(e)),
            _ => Err(MailboxError::Unreachable),
        }
    }

    fn list(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, MailboxError> {
        match self.exchange(holder, &Request::List { tag, now_ms })? {
            Response::Listing(v) => Ok(v),
            Response::Refused(e) => Err(refused(e)),
            _ => Err(MailboxError::Unreachable),
        }
    }

    fn fetch(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, MailboxError> {
        match self.exchange(holder, &Request::Fetch { tag, item, now_ms })? {
            Response::Item(o) => Ok(o),
            Response::Refused(e) => Err(refused(e)),
            _ => Err(MailboxError::Unreachable),
        }
    }

    fn delete(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, MailboxError> {
        match self.exchange(holder, &Request::Delete { tag, item })? {
            Response::Deleted(b) => Ok(b),
            Response::Refused(e) => Err(refused(e)),
            _ => Err(MailboxError::Unreachable),
        }
    }
}
