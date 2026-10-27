//! Authenticated inbound call signalling.

use super::signal::Record;

/// A signalling record received from an allowed contact.
pub struct CallInbound {
    pub peer: [u8; 32],
    pub signal: Record,
    pub received_at_ms: u64,
}

impl core::fmt::Debug for CallInbound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallInbound")
    }
}

pub(crate) fn dispatch(
    sink: &tokio::sync::mpsc::Sender<CallInbound>,
    peer: [u8; 32],
    allowed: bool,
    body: &[u8],
    now: u64,
) {
    if !allowed {
        return;
    }
    let Ok(signal) = Record::decode(body) else {
        return;
    };
    if matches!(&signal, Record::Offer { expires_at_ms, .. } if *expires_at_ms < now) {
        return;
    }
    let _ = sink.try_send(CallInbound {
        peer,
        signal,
        received_at_ms: now,
    });
}
