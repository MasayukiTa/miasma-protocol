/// Outbound proxy support (HTTP CONNECT and SOCKS5) for WSS payload transport
/// through corporate/restrictive networks.
///
/// Corporate environments often force all traffic through an HTTP proxy or
/// SOCKS5 gateway.  This module lets Miasma tunnel its WSS payload connections
/// through such proxies, keeping the share-level protocol unchanged.
use serde::{Deserialize, Serialize};
use std::fmt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::payload::TransportPhase;

// ─── Error ──────────────────────────────────────────────────────────────────

/// Error returned by proxy connection attempts.
#[derive(Debug)]
pub struct ProxyError {
    /// Always `Session` — proxy errors occur before payload transfer.
    pub phase: TransportPhase,
    /// Human-readable description of the failure.
    pub message: String,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxy error ({}): {}", self.phase, self.message)
    }
}

impl std::error::Error for ProxyError {}

// ─── Config ─────────────────────────────────────────────────────────────────

/// Proxy configuration for outbound connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyConfig {
    /// SOCKS5 proxy (RFC 1928).
    Socks5 {
        /// Proxy address, e.g. `"127.0.0.1:1080"`.
        addr: String,
        /// Optional username for SOCKS5 authentication.
        username: Option<String>,
        /// Optional password for SOCKS5 authentication.
        password: Option<String>,
    },
    /// HTTP CONNECT proxy (RFC 7231 Section 4.3.6).
    HttpConnect {
        /// Proxy address, e.g. `"proxy.corp.com:8080"`.
        addr: String,
        /// Optional username for Proxy-Authorization Basic.
        username: Option<String>,
        /// Optional password for Proxy-Authorization Basic.
        password: Option<String>,
    },
}

impl ProxyConfig {
    /// Short name for logging/metrics.
    pub fn display_name(&self) -> &'static str {
        match self {
            ProxyConfig::Socks5 { .. } => "socks5",
            ProxyConfig::HttpConnect { .. } => "http-connect",
        }
    }

    /// Establish a TCP connection to `target_host:target_port` through this proxy.
    ///
    /// On success the returned `TcpStream` is already tunnelled — callers can
    /// layer TLS or WebSocket on top without any further proxy negotiation.
    pub async fn connect(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, ProxyError> {
        match self {
            ProxyConfig::Socks5 {
                addr,
                username,
                password,
            } => {
                let target = format!("{target_host}:{target_port}");
                let stream = match (username.as_deref(), password.as_deref()) {
                    (Some(user), Some(pass)) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password(
                            addr.as_str(),
                            target.as_str(),
                            user,
                            pass,
                        )
                        .await
                    }
                    _ => {
                        tokio_socks::tcp::Socks5Stream::connect(
                            addr.as_str(),
                            target.as_str(),
                        )
                        .await
                    }
                };
                match stream {
                    Ok(s) => Ok(s.into_inner()),
                    Err(e) => Err(ProxyError {
                        phase: TransportPhase::Session,
                        message: format!("SOCKS5 connect to {target} via {addr}: {e}"),
                    }),
                }
            }
            ProxyConfig::HttpConnect {
                addr,
                username,
                password,
            } => {
                let mut stream =
                    TcpStream::connect(addr.as_str())
                        .await
                        .map_err(|e| ProxyError {
                            phase: TransportPhase::Session,
                            message: format!("TCP connect to proxy {addr}: {e}"),
                        })?;

                // Build the CONNECT request.
                let target = format!("{target_host}:{target_port}");
                let mut request = format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                );

                // Add Proxy-Authorization if credentials are present.
                if let (Some(user), Some(pass)) = (username.as_deref(), password.as_deref()) {
                    let credentials = format!("{user}:{pass}");
                    let encoded = base64_encode_basic(&credentials);
                    request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
                }
                request.push_str("\r\n");

                stream
                    .write_all(request.as_bytes())
                    .await
                    .map_err(|e| ProxyError {
                        phase: TransportPhase::Session,
                        message: format!("write CONNECT request: {e}"),
                    })?;

                // Read response until we see the header terminator `\r\n\r\n`.
                let mut buf = Vec::with_capacity(512);
                loop {
                    let mut byte = [0u8; 1];
                    let n = stream.read(&mut byte).await.map_err(|e| ProxyError {
                        phase: TransportPhase::Session,
                        message: format!("read CONNECT response: {e}"),
                    })?;
                    if n == 0 {
                        return Err(ProxyError {
                            phase: TransportPhase::Session,
                            message: "proxy closed connection before sending full response"
                                .into(),
                        });
                    }
                    buf.push(byte[0]);
                    if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
                        break;
                    }
                    if buf.len() > 8192 {
                        return Err(ProxyError {
                            phase: TransportPhase::Session,
                            message: "CONNECT response too large".into(),
                        });
                    }
                }

                let header = String::from_utf8_lossy(&buf);
                if !header.contains("200") {
                    return Err(ProxyError {
                        phase: TransportPhase::Session,
                        message: format!(
                            "CONNECT rejected: {}",
                            header.lines().next().unwrap_or("(empty)")
                        ),
                    });
                }

                Ok(stream)
            }
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Minimal Base64 encoder (RFC 4648) — avoids pulling in the `base64` crate
/// just for a single Proxy-Authorization header.
fn base64_encode_basic(input: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// JSON round-trip for both variants.
    #[test]
    fn proxy_config_serde_roundtrip() {
        let socks = ProxyConfig::Socks5 {
            addr: "127.0.0.1:1080".into(),
            username: Some("alice".into()),
            password: Some("s3cret".into()),
        };
        let json = serde_json::to_string(&socks).unwrap();
        let back: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.display_name(), "socks5");

        let http = ProxyConfig::HttpConnect {
            addr: "proxy.corp.com:8080".into(),
            username: None,
            password: None,
        };
        let json = serde_json::to_string(&http).unwrap();
        let back: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.display_name(), "http-connect");
    }

    /// Start a minimal mock HTTP CONNECT proxy on loopback, connect through it
    /// to a simple TCP echo server, and verify bytes pass through end-to-end.
    #[tokio::test]
    async fn http_connect_proxy_mock() {
        use tokio::net::TcpListener;

        // 1. Start a simple TCP echo server.
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut sock, _) = echo_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = sock.read(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        sock.write_all(&buf[..n]).await.unwrap();
                    }
                });
            }
        });

        // 2. Start a minimal HTTP CONNECT proxy.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut client, _) = proxy_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    // Read CONNECT request until \r\n\r\n.
                    let mut hdr = Vec::new();
                    loop {
                        let mut b = [0u8; 1];
                        let n = client.read(&mut b).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        hdr.push(b[0]);
                        if hdr.len() >= 4 && hdr[hdr.len() - 4..] == *b"\r\n\r\n" {
                            break;
                        }
                    }

                    // Parse the target from the CONNECT line.
                    let hdr_str = String::from_utf8_lossy(&hdr);
                    let first_line = hdr_str.lines().next().unwrap_or("");
                    let target = first_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("");

                    // Connect to target.
                    let mut upstream = TcpStream::connect(target).await.unwrap();

                    // Send 200 back to client.
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .unwrap();

                    // Relay bytes bidirectionally.
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });

        // 3. Connect through the proxy.
        let cfg = ProxyConfig::HttpConnect {
            addr: proxy_addr.to_string(),
            username: None,
            password: None,
        };

        let mut stream = cfg
            .connect(&echo_addr.ip().to_string(), echo_addr.port())
            .await
            .unwrap();

        // 4. Send data and verify echo.
        stream.write_all(b"hello proxy").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello proxy");
    }

    /// SOCKS5 connection to a non-existent proxy must fail with Session phase.
    #[tokio::test]
    async fn socks5_proxy_connect_refused() {
        let cfg = ProxyConfig::Socks5 {
            addr: "127.0.0.1:1".into(), // almost certainly not listening
            username: None,
            password: None,
        };

        let err = cfg.connect("example.com", 443).await.unwrap_err();
        assert!(matches!(err.phase, TransportPhase::Session));
        assert!(
            err.message.contains("SOCKS5"),
            "error message should mention SOCKS5: {}",
            err.message
        );
    }

    #[test]
    fn base64_encode_basic_correctness() {
        // Standard test vectors.
        assert_eq!(base64_encode_basic(""), "");
        assert_eq!(base64_encode_basic("f"), "Zg==");
        assert_eq!(base64_encode_basic("fo"), "Zm8=");
        assert_eq!(base64_encode_basic("foo"), "Zm9v");
        assert_eq!(base64_encode_basic("user:pass"), "dXNlcjpwYXNz");
    }
}
