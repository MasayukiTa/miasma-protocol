//! `miasma tunnel`: expose the daemon's WebSocket share server through
//! `cloudflared`, an outbound-only tunnel, and print the URL a receiver uses.
//!
//! This only *runs* a `cloudflared` that is already installed and on PATH. It
//! never downloads, installs or fetches anything; if the program is missing it
//! says how to install it and stops.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use crate::i18n::Msg;

/// How long to wait for cloudflared to report its public URL.
const URL_WAIT: Duration = Duration::from_secs(60);

/// `CREATE_NO_WINDOW`: the helper must not open a console window on Windows.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The `cloudflared` executable on `path_var` (the PATH value), if any.
pub fn find_on_path(path_var: Option<OsString>) -> Option<PathBuf> {
    // Only a real executable: never a script that a shell would interpret.
    let names: &[&str] = if cfg!(windows) {
        &["cloudflared.exe"]
    } else {
        &["cloudflared"]
    };
    let path_var = path_var?;
    std::env::split_paths(&path_var)
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|candidate| candidate.is_file())
}

/// The `wss://` URL for a quick tunnel, if `line` (cloudflared's log output)
/// announces one: `https://<random-words>.trycloudflare.com`. cloudflared also
/// mentions `api.trycloudflare.com` while it registers; that is not the tunnel.
pub fn find_trycloudflare_url(line: &str) -> Option<String> {
    let start = line.find("https://")? + "https://".len();
    let host: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    let label = host.strip_suffix(".trycloudflare.com")?;
    if label.is_empty() || label == "api" || label.contains('.') {
        return None;
    }
    Some(format!("wss://{host}"))
}

pub async fn run(data_dir: &Path, port: Option<u16>) -> Result<()> {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let exe = match find_on_path(std::env::var_os("PATH")) {
        Some(p) => p,
        None => bail!("{}", Msg::TunnelCloudflaredMissing.t()),
    };

    let port = match port {
        Some(p) => p,
        None => match daemon_request(data_dir, ControlRequest::Status).await? {
            ControlResponse::Status(s) if s.wss_port > 0 => {
                if s.wss_tls_enabled {
                    bail!(
                        "the daemon's WebSocket server has TLS enabled; a tunnel forwards plain \
                         WS and terminates TLS itself (set transport.wss_tls_enabled to false)"
                    );
                }
                s.wss_port
            }
            ControlResponse::Status(_) => bail!("{}", Msg::TunnelNoPort.t()),
            ControlResponse::Error(e) => bail!("daemon error: {e}"),
            _ => bail!("unexpected response from the daemon"),
        },
    };

    eprintln!("{}", Msg::TunnelStarting { port }.t());
    let mut cmd = Command::new(&exe);
    cmd.args(["tunnel", "--url", &format!("http://127.0.0.1:{port}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start {}", exe.display()))?;
    let stderr = child.stderr.take().context("no stderr from cloudflared")?;
    let mut lines = BufReader::new(stderr).lines();

    let found = tokio::time::timeout(URL_WAIT, async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(url) = find_trycloudflare_url(&line) {
                return Some(url);
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    let Some(url) = found else {
        let _ = child.kill().await;
        bail!("{}", Msg::TunnelNoUrl.t());
    };

    println!("{url}");
    eprintln!("{}", Msg::TunnelReady { url }.t());
    eprintln!("{}", Msg::TunnelRunning.t());

    // Keep draining cloudflared's output so it never blocks on a full pipe.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = child.wait() => {}
    }
    let _ = child.kill().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quick_tunnel_url_is_found_in_cloudflareds_banner() {
        let line = "2026-09-30T01:02:03Z INF |  https://random-words-here.trycloudflare.com  |";
        assert_eq!(
            find_trycloudflare_url(line).as_deref(),
            Some("wss://random-words-here.trycloudflare.com")
        );
    }

    #[test]
    fn other_urls_and_the_api_host_are_not_the_tunnel() {
        for line in [
            "INF Requesting new quick Tunnel on trycloudflare.com...",
            "ERR failed to request quick Tunnel: Post \"https://api.trycloudflare.com/tunnel\"",
            "INF https://developers.cloudflare.com/cloudflare-one/",
            "INF https://evil.example.com/x.trycloudflare.com",
            "INF https://a.b.trycloudflare.com",
            "INF https://.trycloudflare.com",
            "",
        ] {
            assert_eq!(find_trycloudflare_url(line), None, "{line:?}");
        }
    }

    #[test]
    fn a_missing_cloudflared_is_not_found_and_nothing_is_started() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_on_path(Some(path)), None);
        assert_eq!(find_on_path(None), None);

        // Present: found by its platform name.
        let name = if cfg!(windows) {
            "cloudflared.exe"
        } else {
            "cloudflared"
        };
        std::fs::write(dir.path().join(name), b"").unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_on_path(Some(path)), Some(dir.path().join(name)));
    }
}
