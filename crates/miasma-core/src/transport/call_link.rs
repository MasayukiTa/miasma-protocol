//! Bounded datagram adapter for one call connection.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc::{sync_channel, Receiver, TrySendError},
    Arc,
};

use iroh::endpoint::Connection;
use tokio::task::JoinHandle;

use crate::chat::call::session::DatagramLink;

pub struct IrohDatagramLink {
    connection: Connection,
    incoming: Receiver<Vec<u8>>,
    dropped: Arc<AtomicU64>,
    reader: JoinHandle<()>,
}

impl IrohDatagramLink {
    /// Must be constructed inside a Tokio runtime.
    pub fn new(connection: Connection) -> Self {
        let (sender, incoming) = sync_channel(256);
        let dropped = Arc::new(AtomicU64::new(0));
        let reader_dropped = Arc::clone(&dropped);
        let reader_connection = connection.clone();
        let reader = tokio::spawn(async move {
            while let Ok(packet) = reader_connection.read_datagram().await {
                match sender.try_send(packet.to_vec()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        let _ = reader_dropped.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |n| Some(n.saturating_add(1)),
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
        });
        Self {
            connection,
            incoming,
            dropped,
            reader,
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.reader.abort();
        self.connection.close(0u32.into(), b"");
    }
}

impl DatagramLink for IrohDatagramLink {
    fn max_len(&self) -> usize {
        self.connection.max_datagram_size().unwrap_or(0)
    }

    fn send(&mut self, packet: &[u8]) -> bool {
        self.connection
            .max_datagram_size()
            .map_or(false, |max| packet.len() <= max)
            && self
                .connection
                .send_datagram(packet.to_vec().into())
                .is_ok()
    }

    fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.try_recv().ok()
    }
}

impl Drop for IrohDatagramLink {
    fn drop(&mut self) {
        self.close();
    }
}
