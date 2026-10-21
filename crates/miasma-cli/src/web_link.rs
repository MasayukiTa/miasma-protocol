//! `miasma web`: the launch link for the browser client.
//!
//! The daemon's HTTP bridge only answers a caller that presents the per-start
//! control token (`<data_dir>/daemon.token`).  A page in a browser cannot read
//! that file, and the bridge must never hand the token to a caller that does not
//! already have it.  So the one process that *can* read the file, this CLI,
//! builds a link whose URL *fragment* carries it:
//!
//! ```text
//! http://127.0.0.1:<bridge port>/#token=<64 hex characters>
//! ```
//!
//! A fragment is never sent to a server, never appears in `Referer` and is not
//! logged by the bridge.  The web client reads it once, keeps it in
//! `sessionStorage` (it dies with the tab) and removes it from the address bar.
//!
//! Anyone who obtains the link can control this node until the daemon restarts
//! (the token changes at every start), so it is printed to stdout only, and the
//! explanation goes to stderr.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// Where the web client's own files come from.
pub enum Page<'a> {
    /// The bridge serves the client itself (the default): one origin, one port.
    Bridge,
    /// A static file server the user runs (for example `python -m http.server`
    /// in `web/`). The link then also names the bridge, because the page is on a
    /// different origin from it.
    Static(&'a str),
}

/// The bridge port from `<data_dir>/daemon.http`.
pub fn read_bridge_port(data_dir: &Path) -> Result<u16> {
    let path = data_dir.join(miasma_core::daemon::ipc::HTTP_PORT_FILE);
    let s = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {} (is the daemon running?)", path.display()))?;
    let port: u16 = s
        .trim()
        .parse()
        .with_context(|| format!("{} does not hold a port number", path.display()))?;
    if port == 0 {
        bail!("{} holds port 0", path.display());
    }
    Ok(port)
}

/// Whether `url` is `http(s)://` on a loopback host and has no fragment,
/// whitespace or credentials.  The token is only ever put in a link to this
/// computer, never one to a remote page.
pub fn is_loopback_http_url(url: &str) -> bool {
    let rest = match url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    {
        Some(r) => r,
        None => return false,
    };
    if url
        .chars()
        .any(|c| c.is_whitespace() || c == '#' || c == '@')
    {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let host = if let Some(v6) = authority.strip_prefix('[') {
        // [::1]:8080
        match v6.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        authority.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build the launch link.
pub fn launch_url(bridge_port: u16, token: &str, page: &Page<'_>) -> Result<String> {
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("the control token is not a hex string");
    }
    match page {
        Page::Bridge => Ok(format!("http://127.0.0.1:{bridge_port}/#token={token}")),
        Page::Static(base) => {
            if !is_loopback_http_url(base) {
                bail!(
                    "--web-url must be an http(s) URL on this computer \
                     (localhost, 127.0.0.1 or [::1]); the link carries the control token"
                );
            }
            Ok(format!(
                "{}/#token={token}&bridge=http://127.0.0.1:{bridge_port}",
                base.trim_end_matches('/')
            ))
        }
    }
}

/// What the bridge at `port` says it accepts (`web_auth` in `GET /api/ping`).
/// `None`: nothing answered with a usable reply.  `Some(vec![])`: it answered
/// but lists nothing (a daemon from before browser sessions).
pub fn ping_web_auth(port: u16) -> Option<Vec<String>> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
    let req =
        format!("GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    let mut out = Vec::new();
    // A reply larger than a ping can ever be is not a ping.
    s.take(64 * 1024).read_to_end(&mut out).ok()?;
    let text = String::from_utf8(out).ok()?;
    if !text.starts_with("HTTP/1.1 200") {
        return None;
    }
    let body = text.split_once("\r\n\r\n")?.1;
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v.get("ok") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    Some(
        v.get("web_auth")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// The origin the page will run at, for the daemon to bind a session to:
/// the bridge itself, or the scheme and authority of the `--web-url` page.
pub fn page_origin(bridge_port: u16, page: &Page<'_>) -> Result<String> {
    match page {
        Page::Bridge => Ok(format!("http://127.0.0.1:{bridge_port}")),
        Page::Static(base) => {
            if !is_loopback_http_url(base) {
                bail!(
                    "--web-url must be an http(s) URL on this computer \
                     (localhost, 127.0.0.1 or [::1])"
                );
            }
            let (scheme, rest) = base.split_once("://").unwrap_or(("http", base));
            let authority = rest.split(['/', '?']).next().unwrap_or("");
            Ok(format!("{scheme}://{authority}").to_ascii_lowercase())
        }
    }
}

/// Build the launch link that carries a one-time session bootstrap value
/// instead of the control token.
pub fn launch_boot_url(bridge_port: u16, boot: &str, page: &Page<'_>) -> Result<String> {
    if boot.is_empty()
        || !boot
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("the bootstrap value is not base64url text");
    }
    match page {
        Page::Bridge => Ok(format!("http://127.0.0.1:{bridge_port}/#boot={boot}")),
        Page::Static(base) => {
            page_origin(bridge_port, page)?;
            Ok(format!(
                "{}/#boot={boot}&bridge=http://127.0.0.1:{bridge_port}",
                base.trim_end_matches('/')
            ))
        }
    }
}

/// Open `url` with the OS default handler without showing a console window.
pub fn open_in_default_browser(url: &str) -> Result<()> {
    use std::process::{Command, Stdio};

    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        // rundll32 hands the URL to the shell without `cmd`'s parsing of `&`;
        // CREATE_NO_WINDOW keeps a console from flashing up.
        let mut c = Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x0800_0000);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start the system browser")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn bridge_link_puts_the_token_in_the_fragment() {
        let u = launch_url(17842, TOKEN, &Page::Bridge).unwrap();
        assert_eq!(u, format!("http://127.0.0.1:17842/#token={TOKEN}"));
        // Nothing of the secret may sit before the '#': that part is sent to the server.
        assert!(!u.split('#').next().unwrap().contains(TOKEN));
    }

    #[test]
    fn static_link_names_the_bridge_and_only_for_loopback_pages() {
        let u = launch_url(9000, TOKEN, &Page::Static("http://localhost:8080/")).unwrap();
        assert_eq!(
            u,
            format!("http://localhost:8080/#token={TOKEN}&bridge=http://127.0.0.1:9000")
        );
        for bad in [
            "https://example.com",
            "http://127.0.0.1.evil.example",
            "http://localhost@evil.example",
            "http://evil.example/#localhost",
            "http://[::2]:80",
            "ftp://localhost",
            "localhost:8080",
            "http://localhost:80 80",
        ] {
            assert!(
                launch_url(9000, TOKEN, &Page::Static(bad)).is_err(),
                "{bad} must be refused"
            );
        }
        assert!(is_loopback_http_url("http://[::1]:8080/app"));
        assert!(is_loopback_http_url("https://localhost"));
    }

    #[test]
    fn boot_links_carry_only_the_one_time_value() {
        let boot = "abcDEF_-0123456789abcDEF_-0123456789abcdefgh";
        assert_eq!(
            launch_boot_url(17842, boot, &Page::Bridge).unwrap(),
            format!("http://127.0.0.1:17842/#boot={boot}")
        );
        assert_eq!(
            launch_boot_url(9000, boot, &Page::Static("http://localhost:8080/app/")).unwrap(),
            format!("http://localhost:8080/app/#boot={boot}&bridge=http://127.0.0.1:9000")
        );
        assert!(launch_boot_url(1, "", &Page::Bridge).is_err());
        assert!(launch_boot_url(1, "a&b", &Page::Bridge).is_err());
        assert!(launch_boot_url(1, boot, &Page::Static("https://example.com")).is_err());
    }

    #[test]
    fn the_session_origin_is_the_scheme_and_authority_of_the_page() {
        assert_eq!(
            page_origin(17842, &Page::Bridge).unwrap(),
            "http://127.0.0.1:17842"
        );
        assert_eq!(
            page_origin(1, &Page::Static("HTTP://LocalHost:8080/a/b?c")).unwrap(),
            "http://localhost:8080"
        );
        assert!(page_origin(1, &Page::Static("http://evil.example")).is_err());
    }

    /// A one-shot HTTP server on loopback answering with `reply`.
    fn serve_once(reply: &'static str) -> u16 {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let _ = s.write_all(reply.as_bytes());
            }
        });
        port
    }

    #[test]
    fn ping_reads_the_advertised_ways_to_sign_in() {
        let new = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true,\"web_auth\":[\"bearer\",\"sig-v1\"]}",
        );
        assert_eq!(
            ping_web_auth(new),
            Some(vec!["bearer".to_owned(), "sig-v1".to_owned()])
        );
        let old = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}",
        );
        assert_eq!(ping_web_auth(old), Some(Vec::new()));
        let not_a_ping = serve_once("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n{}");
        assert_eq!(ping_web_auth(not_a_ping), None);
        // Nothing listening.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert_eq!(ping_web_auth(closed), None);
    }

    #[test]
    fn a_token_that_is_not_hex_is_refused() {
        assert!(launch_url(1, "", &Page::Bridge).is_err());
        assert!(launch_url(1, "abc&x=1", &Page::Bridge).is_err());
    }

    #[test]
    fn port_file_is_parsed_and_zero_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_bridge_port(dir.path()).is_err());
        let f = dir.path().join(miasma_core::daemon::ipc::HTTP_PORT_FILE);
        std::fs::write(&f, "17842\n").unwrap();
        assert_eq!(read_bridge_port(dir.path()).unwrap(), 17842);
        std::fs::write(&f, "0").unwrap();
        assert!(read_bridge_port(dir.path()).is_err());
        std::fs::write(&f, "nope").unwrap();
        assert!(read_bridge_port(dir.path()).is_err());
    }
}
