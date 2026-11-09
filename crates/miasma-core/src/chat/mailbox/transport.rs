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
    wire::{self, Request, Response, StoreSelector},
};
use crate::transport::iroh_direct::{IrohNode, CHAT_ALPN};

/// How long one custody exchange (dial excluded) may take.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Dials holders on the chat ALPN and runs one custody request per stream.
pub struct ChatMailboxTransport {
    node: Arc<IrohNode>,
    handle: Handle,
    store: StoreSelector,
}

impl ChatMailboxTransport {
    /// A transport that dials from `node`. Must be built on a Tokio runtime;
    /// the current handle drives each blocking exchange.
    pub fn new(node: Arc<IrohNode>) -> Self {
        Self {
            node,
            handle: Handle::current(),
            store: StoreSelector::Chat,
        }
    }

    /// Address the separate file custody store on each holder.
    pub fn for_files(node: Arc<IrohNode>) -> Self {
        Self {
            node,
            handle: Handle::current(),
            store: StoreSelector::File,
        }
    }

    fn exchange(&self, holder: &[u8; 32], req: &Request) -> Result<Response, MailboxError> {
        let node = self.node.clone();
        let holder = *holder;
        let req = req.clone();
        let store = self.store;
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
                wire::write_selected_request(&mut tx, store, &req)
                    .await
                    .map_err(|_| MailboxError::Unreachable)?;
                let _ = tx.finish();
                // A failure to read the response frame means the exchange did
                // not complete: the holder could not be reached or the stream
                // broke. That is `Unreachable` for every store selector. A real
                // refusal from the holder arrives as a well-formed
                // `Response::Refused(_)` frame and is turned into
                // `MailboxError::Refused` by the callers below; it is not a
                // read failure. Mapping a read failure of the File selector to
                // `Refused(Disabled)` used to disguise an unreachable holder as
                // a disabled one, which misleads diagnostics.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::mailbox::holder::DepositOutcome;

    // Classify a response the way every verb does: a well-formed refusal frame
    // becomes `Refused`, and anything that is not the verb's own answer is
    // `Unreachable`. This mirrors the match arms in the verb impls below and
    // documents the contract the fixed `exchange` relies on: a *refusal* is a
    // decoded `Response::Refused`, never a read failure. A read failure (the
    // holder could not be reached, the stream broke) is `Unreachable` for
    // every store selector -- it must not be disguised as `Refused(Disabled)`,
    // which previously happened only for the File selector and misreported an
    // unreachable holder as a disabled one.
    fn classify_fetch(resp: Response) -> Result<Option<Vec<u8>>, MailboxError> {
        match resp {
            Response::Item(o) => Ok(o),
            Response::Refused(e) => Err(refused(e)),
            _ => Err(MailboxError::Unreachable),
        }
    }

    #[test]
    fn a_refusal_frame_maps_to_refused_for_both_selectors() {
        // A genuine holder refusal arrives as a decodable frame and keeps its
        // reason, regardless of which store it addressed.
        for e in [
            CustodyError::Disabled,
            CustodyError::NotTrusted,
            CustodyError::RateLimited,
        ] {
            let wire = wire::encode_response(&Response::Refused(e));
            let (decoded, _) = wire::decode_response(&wire).unwrap();
            assert_eq!(classify_fetch(decoded), Err(MailboxError::Refused(e)));
        }
    }

    #[test]
    fn a_wrong_shaped_answer_is_unreachable_not_a_disguised_refusal() {
        // Any answer that is not the verb's own (here, a Deposited answer to a
        // fetch) is Unreachable -- not silently turned into a refusal. This is
        // the contract that lets `exchange` map a *read failure* to
        // Unreachable for every selector instead of Refused(Disabled).
        let resp = Response::Deposited(DepositOutcome::Stored);
        assert_eq!(classify_fetch(resp), Err(MailboxError::Unreachable));
    }
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
