//! The two things the push service needs from a network: a way to dial a
//! contact and, on a connection, bidirectional streams. The iroh endpoint is
//! the real implementation; a test can put any other behind the same traits
//! (a link that drops every N MiB, a dial that is refused, a stalled stream)
//! without a network.

use std::{future::Future, pin::Pin, sync::Arc};

use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::transport::iroh_direct::{IrohClientError, IrohNode, PUSH_ALPN};

/// The sending half of a stream.
pub trait TxStream: AsyncWrite + Send + Unpin {
    /// No more bytes will be written.
    fn finish(&mut self);
    /// Resolves once the other side has taken everything or the stream is gone.
    fn stopped<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The receiving half of a stream.
pub trait RxStream: AsyncRead + Send + Unpin {}
impl<T: AsyncRead + Send + Unpin> RxStream for T {}

pub type BoxTx = Box<dyn TxStream>;
pub type BoxRx = Box<dyn RxStream>;

/// How a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseInfo {
    /// The other side (or this one) closed it on purpose with this code.
    App(u64),
    /// Lost, timed out, reset, or closed by the transport.
    Other,
}

/// One connection to a contact.
#[async_trait::async_trait]
pub trait Link: Send + Sync {
    async fn open_bi(&self) -> Result<(BoxTx, BoxRx), String>;
    async fn accept_bi(&self) -> Result<(BoxTx, BoxRx), String>;
    /// The identity proven by the handshake.
    fn remote_id(&self) -> [u8; 32];
    fn close(&self, code: u32, reason: &[u8]);
    /// `None` while the connection is open.
    fn close_info(&self) -> Option<CloseInfo>;
    /// Resolves when the connection has ended.
    async fn closed(&self) -> CloseInfo;
}

/// Opens connections to contacts.
#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, target: &[u8; 32]) -> Result<Arc<dyn Link>, IrohClientError>;
}

// ─── iroh ────────────────────────────────────────────────────────────────────

impl TxStream for SendStream {
    fn finish(&mut self) {
        let _ = SendStream::finish(self);
    }
    fn stopped<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let _ = SendStream::stopped(self).await;
        })
    }
}

/// An iroh connection as a [`Link`].
pub struct IrohLink(pub Connection);

fn info(e: ConnectionError) -> CloseInfo {
    match e {
        ConnectionError::ApplicationClosed(c) => CloseInfo::App(u64::from(c.error_code)),
        _ => CloseInfo::Other,
    }
}

fn boxed(tx: SendStream, rx: RecvStream) -> (BoxTx, BoxRx) {
    (Box::new(tx), Box::new(rx))
}

#[async_trait::async_trait]
impl Link for IrohLink {
    async fn open_bi(&self) -> Result<(BoxTx, BoxRx), String> {
        let (tx, rx) = self.0.open_bi().await.map_err(|e| e.to_string())?;
        Ok(boxed(tx, rx))
    }
    async fn accept_bi(&self) -> Result<(BoxTx, BoxRx), String> {
        let (tx, rx) = self.0.accept_bi().await.map_err(|e| e.to_string())?;
        Ok(boxed(tx, rx))
    }
    fn remote_id(&self) -> [u8; 32] {
        *self.0.remote_id().as_bytes()
    }
    fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(code.into(), reason);
    }
    fn close_info(&self) -> Option<CloseInfo> {
        self.0.close_reason().map(info)
    }
    async fn closed(&self) -> CloseInfo {
        info(self.0.closed().await)
    }
}

/// Dials contacts over the iroh endpoint of this daemon.
pub struct IrohDialer(pub Arc<IrohNode>);

#[async_trait::async_trait]
impl Dialer for IrohDialer {
    async fn dial(&self, target: &[u8; 32]) -> Result<Arc<dyn Link>, IrohClientError> {
        let c = self.0.connect_alpn(target, PUSH_ALPN).await?;
        Ok(Arc::new(IrohLink(c)))
    }
}
