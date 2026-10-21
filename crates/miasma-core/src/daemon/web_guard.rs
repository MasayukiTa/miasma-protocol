//! The single request gate of the HTTP bridge.
//!
//! Every request, preflight included, passes [`GuardConfig::admit`] before any
//! route runs, and every response (static file, API reply, error) leaves through
//! [`decorate`], so the header set is the same everywhere.
//!
//! * `Host` must name this computer (`127.0.0.1`, `localhost`, `[::1]`); a port,
//!   when given, must be the port the bridge is bound to.
//! * `Origin`, when present, must be an exact `http://` loopback origin, or one
//!   listed in `MIASMA_WEB_ORIGINS` (comma separated, loopback hosts only).
//!   `null` is never accepted.  A request without `Origin` is a native client
//!   and is not a browser request.
//! * Fetch metadata (`Sec-Fetch-*`), where a browser sends it, is checked too.
//! * Only a validated origin is echoed in `Access-Control-Allow-Origin`.

use hyper::{
    header::{self, HeaderMap},
    Response,
};

/// Environment variable listing extra page origins that may call the bridge.
pub const ORIGINS_ENV: &str = "MIASMA_WEB_ORIGINS";

/// Content-Security-Policy for the client pages the bridge serves.
pub const PAGE_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
connect-src 'self' http://127.0.0.1:* http://localhost:*; manifest-src 'self'; \
worker-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; \
form-action 'self'";

/// Content-Security-Policy for API replies: nothing may load or run.
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), usb=(), serial=(), \
hid=(), bluetooth=(), payment=(), display-capture=(), midi=(), accelerometer=(), \
gyroscope=(), magnetometer=()";

/// Why a request was turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Host,
    Origin,
    FetchMetadata,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::Host => "host not allowed",
            Refusal::Origin => {
                "origin not allowed: serve the page from this bridge, or list its origin in \
                 MIASMA_WEB_ORIGINS"
            }
            Refusal::FetchMetadata => "cross-site request not allowed",
        }
    }
}

/// What the gate learned about an admitted request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admission {
    /// The validated `Origin`, normalised, to be echoed in the CORS reply.
    pub origin: Option<String>,
    /// `true` when the request came from a browser (it carried `Origin` or
    /// fetch metadata).
    pub browser: bool,
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    bound_port: u16,
    extra_origins: Vec<String>,
}

fn is_loopback_host(h: &str) -> bool {
    matches!(h, "127.0.0.1" | "localhost" | "[::1]")
}

/// `host`, `host:port`, `[v6]`, `[v6]:port` -> (host, port text).
fn split_authority(a: &str) -> Option<(String, Option<&str>)> {
    if a.starts_with('[') {
        let end = a.find(']')?;
        let host = &a[..=end];
        let rest = &a[end + 1..];
        let port = match rest {
            "" => None,
            r => Some(r.strip_prefix(':')?),
        };
        Some((host.to_ascii_lowercase(), port))
    } else {
        match a.split_once(':') {
            Some((h, p)) => Some((h.to_ascii_lowercase(), Some(p))),
            None => Some((a.to_ascii_lowercase(), None)),
        }
    }
}

fn parse_port(p: &str) -> Option<u16> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse::<u16>().ok().filter(|n| *n != 0)
}

/// Normalise an origin to `scheme://host[:port]` when it is a loopback origin
/// with nothing else in it.
fn loopback_origin(origin: &str, schemes: &[&str]) -> Option<String> {
    let lower = origin.trim().to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://")?;
    if !schemes.contains(&scheme) {
        return None;
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ', '\\']) {
        return None;
    }
    let (host, port) = split_authority(rest)?;
    if !is_loopback_host(&host) {
        return None;
    }
    if let Some(p) = port {
        parse_port(p)?;
    }
    Some(lower)
}

impl GuardConfig {
    pub fn new(bound_port: u16, extra_origins: &[String]) -> Self {
        let extra_origins = extra_origins
            .iter()
            .filter_map(|o| loopback_origin(o, &["http", "https"]))
            .collect();
        Self {
            bound_port,
            extra_origins,
        }
    }

    /// The extra origins come from [`ORIGINS_ENV`].
    pub fn from_env(bound_port: u16) -> Self {
        let list: Vec<String> = std::env::var(ORIGINS_ENV)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        Self::new(bound_port, &list)
    }

    fn host_ok(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(header::HOST).iter();
        let (Some(v), None) = (values.next(), values.next()) else {
            return false;
        };
        let Ok(v) = v.to_str() else { return false };
        let Some((host, port)) = split_authority(v.trim()) else {
            return false;
        };
        if !is_loopback_host(&host) {
            return false;
        }
        match port {
            None => true,
            Some(p) => parse_port(p) == Some(self.bound_port),
        }
    }

    fn origin_ok(&self, origin: &str) -> Option<String> {
        if let Some(o) = loopback_origin(origin, &["http"]) {
            return Some(o);
        }
        let lower = origin.trim().to_ascii_lowercase();
        self.extra_origins.contains(&lower).then_some(lower)
    }

    /// Decide whether a request may proceed.
    pub fn admit(&self, headers: &HeaderMap) -> Result<Admission, Refusal> {
        if !self.host_ok(headers) {
            return Err(Refusal::Host);
        }

        let mut origins = headers.get_all(header::ORIGIN).iter();
        let origin = match (origins.next(), origins.next()) {
            (None, _) => None,
            (Some(v), None) => {
                let v = v.to_str().map_err(|_| Refusal::Origin)?;
                Some(self.origin_ok(v).ok_or(Refusal::Origin)?)
            }
            _ => return Err(Refusal::Origin),
        };

        let fetch = |name: &str| -> Option<String> {
            headers
                .get(name)
                .map(|v| v.to_str().unwrap_or("?").trim().to_ascii_lowercase())
        };
        let site = fetch("sec-fetch-site");
        let mode = fetch("sec-fetch-mode");
        let dest = fetch("sec-fetch-dest");
        let browser = origin.is_some() || site.is_some() || mode.is_some() || dest.is_some();

        match site.as_deref() {
            None | Some("same-origin") | Some("none") => {}
            // A page on another localhost port (a static server the user runs)
            // is cross-site to the bridge; it is fine once its Origin passed.
            Some("same-site") | Some("cross-site") => {
                if origin.is_none() || mode.as_deref() == Some("no-cors") {
                    return Err(Refusal::FetchMetadata);
                }
            }
            Some(_) => return Err(Refusal::FetchMetadata),
        }
        if matches!(
            dest.as_deref(),
            Some("iframe") | Some("frame") | Some("embed") | Some("object")
        ) {
            return Err(Refusal::FetchMetadata);
        }

        Ok(Admission { origin, browser })
    }
}

/// Which kind of body a response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Page,
    Api,
}

fn put<B>(resp: &mut Response<B>, name: header::HeaderName, value: &'static str) {
    resp.headers_mut()
        .insert(name, header::HeaderValue::from_static(value));
}

/// Give a response the common security headers and, when `origin` is a
/// validated request origin, the CORS grant for exactly that origin.
pub fn decorate<B>(mut resp: Response<B>, kind: Kind, origin: Option<&str>) -> Response<B> {
    put(&mut resp, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    put(&mut resp, header::REFERRER_POLICY, "no-referrer");
    put(&mut resp, header::X_FRAME_OPTIONS, "DENY");
    put(
        &mut resp,
        header::HeaderName::from_static("permissions-policy"),
        PERMISSIONS_POLICY,
    );
    match kind {
        Kind::Page => put(&mut resp, header::CONTENT_SECURITY_POLICY, PAGE_CSP),
        Kind::Api => {
            put(&mut resp, header::CONTENT_SECURITY_POLICY, API_CSP);
            put(&mut resp, header::CACHE_CONTROL, "no-store");
        }
    }
    resp.headers_mut()
        .append(header::VARY, header::HeaderValue::from_static("Origin"));
    if let Some(o) = origin {
        if let Ok(v) = header::HeaderValue::from_str(o) {
            resp.headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            put(
                &mut resp,
                header::ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, OPTIONS",
            );
            put(
                &mut resp,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, Authorization",
            );
            put(&mut resp, header::ACCESS_CONTROL_MAX_AGE, "600");
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn cfg() -> GuardConfig {
        GuardConfig::new(
            17842,
            &[
                "https://localhost:8443".to_owned(),
                "https://evil.example".to_owned(),
            ],
        )
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn host_must_be_loopback_with_the_bound_port() {
        let c = cfg();
        for ok in [
            "127.0.0.1:17842",
            "localhost:17842",
            "[::1]:17842",
            "127.0.0.1",
            "LOCALHOST:17842",
        ] {
            assert!(c.admit(&headers(&[("host", ok)])).is_ok(), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:17842",
            "127.0.0.1:9999",
            "127.0.0.1:0",
            "localhost.evil.example:17842",
            "127.0.0.1.evil.example",
            "127.0.0.1:17842:1",
            "",
        ] {
            assert_eq!(
                c.admit(&headers(&[("host", bad)])),
                Err(Refusal::Host),
                "{bad}"
            );
        }
        assert_eq!(c.admit(&HeaderMap::new()), Err(Refusal::Host));
        assert_eq!(
            c.admit(&headers(&[("host", "127.0.0.1"), ("host", "evil.example")])),
            Err(Refusal::Host)
        );
    }

    #[test]
    fn origin_is_exact_and_null_is_refused() {
        let c = cfg();
        let h = |o: &str| headers(&[("host", "127.0.0.1:17842"), ("origin", o)]);
        for ok in [
            "http://127.0.0.1:17842",
            "http://localhost:17842",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://[::1]:3000",
            "HTTP://LOCALHOST:8080",
            "https://localhost:8443",
        ] {
            let a = c.admit(&h(ok)).unwrap();
            assert_eq!(a.origin.as_deref(), Some(ok.to_ascii_lowercase().as_str()));
            assert!(a.browser);
        }
        for bad in [
            "null",
            "",
            "https://evil.example",
            "http://evil.example",
            "http://localhost.evil.example",
            "http://localhost:80a",
            "http://localhost:0",
            "http://localhost:99999",
            "http://localhost:8080/",
            "http://localhost:8080/x",
            "http://user@localhost:8080",
            "https://localhost",
            "https://localhost:9",
            "file://",
            "http://192.168.1.10:8080",
            "http://localhost:8080 http://evil.example",
        ] {
            assert_eq!(c.admit(&h(bad)), Err(Refusal::Origin), "{bad}");
        }
        // Only loopback origins can be configured, whatever the list says.
        assert_eq!(c.admit(&h("https://evil.example")), Err(Refusal::Origin));
        // Two Origin headers are refused.
        assert_eq!(
            c.admit(&headers(&[
                ("host", "127.0.0.1"),
                ("origin", "http://localhost:1"),
                ("origin", "http://localhost:2")
            ])),
            Err(Refusal::Origin)
        );
    }

    #[test]
    fn no_origin_is_a_native_client() {
        let a = cfg()
            .admit(&headers(&[("host", "127.0.0.1:17842")]))
            .unwrap();
        assert_eq!(
            a,
            Admission {
                origin: None,
                browser: false
            }
        );
    }

    #[test]
    fn fetch_metadata_is_checked_where_present() {
        let c = cfg();
        let h = |extra: &[(&str, &str)]| {
            let mut v = vec![("host", "127.0.0.1:17842")];
            v.extend_from_slice(extra);
            headers(&v)
        };
        // Same-origin and typed-in navigations pass and count as a browser.
        let a = c.admit(&h(&[("sec-fetch-site", "same-origin")])).unwrap();
        assert!(a.browser && a.origin.is_none());
        assert!(c
            .admit(&h(&[
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate")
            ]))
            .is_ok());
        // Cross-site without a validated Origin is refused.
        assert_eq!(
            c.admit(&h(&[("sec-fetch-site", "cross-site")])),
            Err(Refusal::FetchMetadata)
        );
        assert_eq!(
            c.admit(&h(&[
                ("sec-fetch-site", "cross-site"),
                ("sec-fetch-mode", "no-cors")
            ])),
            Err(Refusal::FetchMetadata)
        );
        // A page on another localhost port is cross-site but carries an allowed Origin.
        assert!(c
            .admit(&h(&[
                ("sec-fetch-site", "cross-site"),
                ("sec-fetch-mode", "cors"),
                ("origin", "http://localhost:8080")
            ]))
            .is_ok());
        assert_eq!(
            c.admit(&h(&[("sec-fetch-site", "bogus")])),
            Err(Refusal::FetchMetadata)
        );
        assert_eq!(
            c.admit(&h(&[
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-dest", "iframe")
            ])),
            Err(Refusal::FetchMetadata)
        );
    }

    #[test]
    fn a_response_gets_the_header_set_and_only_a_validated_origin_is_echoed() {
        let plain = decorate(Response::new(()), Kind::Api, None);
        let h = plain.headers();
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("cache-control").unwrap(), "no-store");
        assert!(h.get("content-security-policy").is_some());
        assert!(h.get("permissions-policy").is_some());
        assert!(h.get("access-control-allow-origin").is_none());
        assert_eq!(h.get("vary").unwrap(), "Origin");
        let page = decorate(Response::new(()), Kind::Page, Some("http://localhost:8080"));
        let h = page.headers();
        assert_eq!(
            h.get("access-control-allow-origin").unwrap(),
            "http://localhost:8080"
        );
        assert!(!h
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("'unsafe-eval'"));
        assert!(h.get("cache-control").is_none());
    }
}
