//! The HTTP layer of the updater, behind a trait so tests never touch a network.
//!
//! The real client ([`HttpsClient`]) is small on purpose:
//!
//! * HTTPS only (a redirect to `http://` is refused), certificates checked
//!   against the operating system's store.
//! * No cookies, no credentials, no token, no custom identifiers: the request
//!   carries `Host`, `User-Agent: miasma-update/<version>`, `Accept` and nothing
//!   else.
//! * 15 s limit for connecting and for the answer's headers; a download gives up
//!   when 15 s pass without a byte, and after 20 minutes in all.
//! * Bodies that are read into memory are capped by the caller; downloads go to
//!   a file in 16 KiB pieces and never sit in memory.
//! * Each call builds its own single-thread runtime on a short-lived thread, so
//!   nothing stays resident between checks and it works from any context.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, ACCEPT_ENCODING, CONNECTION, HOST, LOCATION, USER_AGENT};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;

/// Limit for connecting and for receiving the headers of an answer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// A download that receives nothing for this long is abandoned.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// A download that has not finished after this long is abandoned.
pub const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(20 * 60);
/// Redirects followed per request.
pub const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The host could not be reached (no network, DNS, refused, reset).
    Offline(String),
    /// No answer in time.
    Timeout,
    /// More data than the caller allows.
    TooLarge,
    /// The server answered with something the client cannot use.
    Protocol(String),
    /// Writing the download failed.
    Io(String),
    /// A download got a status other than 200.
    Status(u16),
    /// The server says the request limit is reached.
    RateLimited,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline(m) => write!(f, "cannot reach the server: {m}"),
            Self::Timeout => f.write_str("the server did not answer in time"),
            Self::TooLarge => f.write_str("the answer is larger than allowed"),
            Self::Protocol(m) => write!(f, "unusable answer: {m}"),
            Self::Io(m) => write!(f, "cannot write the download: {m}"),
            Self::Status(s) => write!(f, "the server answered {s}"),
            Self::RateLimited => f.write_str("the request limit of the server is reached"),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// 429, or 403 with the limit used up.
    pub rate_limited: bool,
}

pub trait Http: Send + Sync {
    /// GET `url`; the whole body is returned if it is at most `max_bytes`.
    /// Any status is returned as `Ok` (the caller decides what 404 means).
    fn get(&self, url: &str, accept: &str, max_bytes: usize) -> Result<HttpResponse, HttpError>;

    /// GET `url` into the file `dest`, at most `max_bytes`. `progress` gets
    /// (bytes so far, total when announced). Only status 200 is success. On any
    /// error the partial file is removed. Returns the number of bytes written.
    fn download(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<u64, HttpError>;
}

/// The real client.
pub struct HttpsClient {
    user_agent: String,
    /// An extra certificate authority to trust (PEM), for tests with a local
    /// server. `None` in the program: only the operating system's store.
    extra_ca_pem: Option<Vec<u8>>,
    /// The file named by `transport.iroh_extra_ca_pem`, read when a request is
    /// made (so a program that never makes one never opens it). Same meaning as
    /// for the relay: trusted in addition to the operating system's store, and
    /// ignored with a log line when it cannot be used.
    extra_ca_file: Option<String>,
    request_timeout: Duration,
    idle_timeout: Duration,
}

impl Default for HttpsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsClient {
    pub fn new() -> Self {
        Self {
            user_agent: format!("miasma-update/{}", env!("CARGO_PKG_VERSION")),
            extra_ca_pem: None,
            extra_ca_file: None,
            request_timeout: REQUEST_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
        }
    }

    /// A client that also trusts the CA file `transport.iroh_extra_ca_pem` names
    /// (`None`: only the operating system's store). The same TLS configuration
    /// as the relay and `wss://` connections is built from it.
    pub fn with_extra_ca_file(mut self, path: Option<String>) -> Self {
        self.extra_ca_file = path.filter(|p| !p.trim().is_empty());
        self
    }

    /// The extra CA to trust for the next request: the PEM given directly, else
    /// the configured file when it is readable and usable.
    fn extra_ca(&self) -> Option<Vec<u8>> {
        if let Some(pem) = &self.extra_ca_pem {
            return Some(pem.clone());
        }
        let path = self.extra_ca_file.as_deref()?;
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("update: transport.iroh_extra_ca_pem cannot be read: {e}");
                return None;
            }
        };
        match crate::transport::ws_direct::build_tls_connector(Some(&bytes)) {
            Ok(_) => Some(bytes),
            Err(e) => {
                tracing::warn!("update: transport.iroh_extra_ca_pem is not usable: {e}");
                None
            }
        }
    }

    /// A client that also trusts the CA in `pem` (a local test server).
    pub fn with_extra_ca_pem(pem: Vec<u8>) -> Self {
        Self {
            extra_ca_pem: Some(pem),
            ..Self::new()
        }
    }

    /// Shorter limits, for tests.
    pub fn with_timeouts(mut self, request: Duration, idle: Duration) -> Self {
        self.request_timeout = request;
        self.idle_timeout = idle;
        self
    }

    /// Run `fut` to completion on a fresh single-thread runtime, on its own
    /// thread (so it is safe to call from inside another runtime).
    fn run<T: Send>(
        fut: impl std::future::Future<Output = Result<T, HttpError>> + Send,
    ) -> Result<T, HttpError> {
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| HttpError::Io(format!("runtime: {e}")))?;
                rt.block_on(fut)
            })
            .join()
            .unwrap_or_else(|_| Err(HttpError::Protocol("worker panicked".into())))
        })
    }

    /// Connect, send the request, follow redirects, return the final answer.
    async fn open(&self, url: &str, accept: &str) -> Result<(Response<Incoming>, bool), HttpError> {
        let mut url = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            let uri: Uri = url
                .parse()
                .map_err(|_| HttpError::Protocol("bad URL".into()))?;
            if uri.scheme_str() != Some("https") {
                return Err(HttpError::Protocol("only https is used".into()));
            }
            let host = uri
                .host()
                .ok_or_else(|| HttpError::Protocol("URL without host".into()))?
                .to_owned();
            let port = uri.port_u16().unwrap_or(443);
            let host_header = match uri.port_u16() {
                Some(p) if p != 443 => format!("{host}:{p}"),
                _ => host.clone(),
            };
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_else(|| "/".into());

            let tcp = tokio::time::timeout(
                self.request_timeout,
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(|e| HttpError::Offline(e.to_string()))?;
            let extra = self.extra_ca();
            let connector = crate::transport::ws_direct::build_tls_connector(extra.as_deref())
                .map_err(|e| HttpError::Protocol(e.to_string()))?;
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| HttpError::Protocol("bad host name".into()))?;
            let tls = tokio::time::timeout(self.request_timeout, connector.connect(name, tcp))
                .await
                .map_err(|_| HttpError::Timeout)?
                .map_err(|e| HttpError::Protocol(format!("TLS: {e}")))?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tls))
                    .await
                    .map_err(|e| HttpError::Protocol(e.to_string()))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .method(Method::GET)
                .uri(path)
                .header(HOST, host_header.as_str())
                .header(USER_AGENT, self.user_agent.as_str())
                .header(ACCEPT, accept)
                .header(ACCEPT_ENCODING, "identity")
                .header(CONNECTION, "close")
                .body(Empty::<Bytes>::new())
                .map_err(|e| HttpError::Protocol(e.to_string()))?;
            let resp = tokio::time::timeout(self.request_timeout, sender.send_request(req))
                .await
                .map_err(|_| HttpError::Timeout)?
                .map_err(|e| HttpError::Offline(e.to_string()))?;

            let status = resp.status();
            if matches!(
                status,
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) {
                let loc = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| HttpError::Protocol("redirect without Location".into()))?;
                url = if loc.starts_with('/') {
                    format!("https://{host_header}{loc}")
                } else {
                    loc.to_owned()
                };
                continue;
            }
            let limited = status == StatusCode::TOO_MANY_REQUESTS
                || (status == StatusCode::FORBIDDEN
                    && resp
                        .headers()
                        .get("x-ratelimit-remaining")
                        .and_then(|v| v.to_str().ok())
                        == Some("0"));
            return Ok((resp, limited));
        }
        Err(HttpError::Protocol("too many redirects".into()))
    }
}

impl Http for HttpsClient {
    fn get(&self, url: &str, accept: &str, max_bytes: usize) -> Result<HttpResponse, HttpError> {
        Self::run(async {
            tokio::time::timeout(self.request_timeout, async {
                let (mut resp, rate_limited) = self.open(url, accept).await?;
                let status = resp.status().as_u16();
                let mut body = Vec::new();
                while let Some(frame) = resp.body_mut().frame().await {
                    let frame = frame.map_err(|e| HttpError::Offline(e.to_string()))?;
                    if let Some(data) = frame.data_ref() {
                        if body.len() + data.len() > max_bytes {
                            return Err(HttpError::TooLarge);
                        }
                        body.extend_from_slice(data);
                    }
                }
                Ok(HttpResponse {
                    status,
                    body,
                    rate_limited,
                })
            })
            .await
            .map_err(|_| HttpError::Timeout)?
        })
    }

    fn download(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<u64, HttpError> {
        let result = Self::run(async {
            let (mut resp, limited) = self.open(url, "application/octet-stream").await?;
            if limited {
                return Err(HttpError::RateLimited);
            }
            if resp.status() != StatusCode::OK {
                return Err(HttpError::Status(resp.status().as_u16()));
            }
            let total = resp
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            if total.is_some_and(|t| t > max_bytes) {
                return Err(HttpError::TooLarge);
            }
            let mut file = std::fs::File::create(dest).map_err(|e| HttpError::Io(e.to_string()))?;
            let started = Instant::now();
            let mut done: u64 = 0;
            loop {
                if started.elapsed() > DOWNLOAD_DEADLINE {
                    return Err(HttpError::Timeout);
                }
                let next = tokio::time::timeout(self.idle_timeout, resp.body_mut().frame())
                    .await
                    .map_err(|_| HttpError::Timeout)?;
                let Some(frame) = next else { break };
                let frame = frame.map_err(|e| HttpError::Offline(e.to_string()))?;
                if let Some(data) = frame.data_ref() {
                    done += data.len() as u64;
                    if done > max_bytes {
                        return Err(HttpError::TooLarge);
                    }
                    file.write_all(data)
                        .map_err(|e| HttpError::Io(e.to_string()))?;
                    progress(done, total);
                }
            }
            file.flush().map_err(|e| HttpError::Io(e.to_string()))?;
            if total.is_some_and(|t| t != done) {
                return Err(HttpError::Protocol("the download ended early".into()));
            }
            Ok(done)
        });
        if result.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        result
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A scripted HTTP layer for the tests: answers by URL, records requests.

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    pub enum Reply {
        Body(u16, Vec<u8>),
        Limited,
        Fail(HttpError),
    }

    #[derive(Default)]
    pub struct FakeHttp {
        pub routes: Mutex<HashMap<String, Reply>>,
        pub requests: Mutex<Vec<String>>,
    }

    impl FakeHttp {
        pub fn route(&self, url: &str, r: Reply) {
            self.routes.lock().unwrap().insert(url.to_owned(), r);
        }
        pub fn count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl Http for FakeHttp {
        fn get(&self, url: &str, _a: &str, max: usize) -> Result<HttpResponse, HttpError> {
            self.requests.lock().unwrap().push(url.to_owned());
            match self.routes.lock().unwrap().get(url) {
                Some(Reply::Body(s, b)) => {
                    if b.len() > max {
                        return Err(HttpError::TooLarge);
                    }
                    Ok(HttpResponse {
                        status: *s,
                        body: b.clone(),
                        rate_limited: false,
                    })
                }
                Some(Reply::Limited) => Ok(HttpResponse {
                    status: 403,
                    body: b"{}".to_vec(),
                    rate_limited: true,
                }),
                Some(Reply::Fail(e)) => Err(e.clone()),
                None => Ok(HttpResponse {
                    status: 404,
                    body: Vec::new(),
                    rate_limited: false,
                }),
            }
        }

        fn download(
            &self,
            url: &str,
            dest: &Path,
            max: u64,
            progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
        ) -> Result<u64, HttpError> {
            self.requests.lock().unwrap().push(url.to_owned());
            let routes = self.routes.lock().unwrap();
            match routes.get(url) {
                Some(Reply::Body(200, b)) => {
                    if b.len() as u64 > max {
                        return Err(HttpError::TooLarge);
                    }
                    std::fs::write(dest, b).map_err(|e| HttpError::Io(e.to_string()))?;
                    progress(b.len() as u64, Some(b.len() as u64));
                    Ok(b.len() as u64)
                }
                Some(Reply::Body(s, _)) => Err(HttpError::Status(*s)),
                Some(Reply::Limited) => Err(HttpError::RateLimited),
                Some(Reply::Fail(e)) => Err(e.clone()),
                None => Err(HttpError::Status(404)),
            }
        }
    }
}
