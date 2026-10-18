//! The updater's real HTTP client, run against a local HTTPS server (a
//! throw-away CA; no real network): what it sends, what it follows, what it
//! refuses, and that a download goes to a file in pieces.

mod common;

use std::time::{Duration, Instant};

use common::update_server::{start, TlsServer};
use miasma_core::update::http::{Http, HttpError, HttpsClient};

fn client(s: &TlsServer) -> HttpsClient {
    HttpsClient::with_extra_ca_pem(s.ca_pem.clone())
}

#[test]
fn update_http_a_plain_get_returns_status_and_body() {
    let s = start();
    let r = client(&s)
        .get(&s.url("/json"), "application/json", 1 << 20)
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body, br#"[{"tag_name":"v1.0.0"}]"#);
    assert!(!r.rate_limited);
}

#[test]
fn update_http_the_request_carries_nothing_that_identifies_the_user() {
    let s = start();
    let r = client(&s)
        .get(&s.url("/headers"), "application/vnd.github+json", 1 << 20)
        .unwrap();
    let head = String::from_utf8(r.body).unwrap();
    let mut lines = head.lines();
    assert_eq!(lines.next().unwrap(), "GET /headers HTTP/1.1");
    let names: Vec<String> = lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
        .collect();
    // Exactly these headers, nothing else: no cookie, no authorization, no
    // referer, no custom id.
    let allowed = [
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "connection",
    ];
    for n in &names {
        assert!(
            allowed.contains(&n.as_str()),
            "unexpected header {n}: {head}"
        );
    }
    for must in allowed {
        assert!(names.iter().any(|n| n == must), "missing {must}");
    }
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains(&format!(
        "user-agent: miasma-update/{}",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(lower.contains("accept: application/vnd.github+json"));
    assert!(lower.contains("accept-encoding: identity"));
    assert!(!lower.contains("cookie") && !lower.contains("authorization"));
}

#[test]
fn update_http_https_redirects_are_followed_and_http_ones_refused() {
    let s = start();
    let c = client(&s);
    let r = c.get(&s.url("/redirect"), "*/*", 1 << 20).unwrap();
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("v1.0.0"));

    match c.get(&s.url("/redirect-http"), "*/*", 1 << 20) {
        Err(HttpError::Protocol(m)) => assert!(m.contains("https"), "{m}"),
        other => panic!("{other:?}"),
    }
    match c.get(&s.url("/loop"), "*/*", 1 << 20) {
        Err(HttpError::Protocol(m)) => assert!(m.contains("redirect"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn update_http_not_found_and_rate_limit_are_answers_not_failures() {
    let s = start();
    let c = client(&s);
    let nf = c.get(&s.url("/nothing-here"), "*/*", 1 << 20).unwrap();
    assert_eq!(nf.status, 404);
    assert!(!nf.rate_limited);
    let lim = c.get(&s.url("/limited"), "*/*", 1 << 20).unwrap();
    assert_eq!(lim.status, 403);
    assert!(lim.rate_limited);
}

#[test]
fn update_http_a_certificate_from_an_unknown_ca_is_refused() {
    let s = start();
    // No extra CA: the operating system's store does not know the test CA.
    let r = HttpsClient::new().get(&s.url("/json"), "*/*", 1 << 20);
    assert!(
        matches!(r, Err(HttpError::Protocol(ref m)) if m.contains("TLS")),
        "{r:?}"
    );
}

#[test]
fn update_http_the_configured_extra_ca_file_is_trusted_like_for_the_relay() {
    let s = start();
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("inspection-ca.pem");
    std::fs::write(&ca, &s.ca_pem).unwrap();
    let path = ca.to_string_lossy().into_owned();

    // The file named by transport.iroh_extra_ca_pem makes the server trusted.
    let r = HttpsClient::new()
        .with_extra_ca_file(Some(path))
        .get(&s.url("/json"), "*/*", 1 << 20)
        .unwrap();
    assert_eq!(r.status, 200);

    // A missing file or a file without a certificate is ignored (as for the
    // relay): the operating system's store alone decides, and it refuses.
    for bad in [
        Some(d.path().join("missing.pem").to_string_lossy().into_owned()),
        {
            let junk = d.path().join("junk.pem");
            std::fs::write(&junk, b"not a certificate").unwrap();
            Some(junk.to_string_lossy().into_owned())
        },
        Some("   ".to_owned()),
        None,
    ] {
        let r = HttpsClient::new()
            .with_extra_ca_file(bad)
            .get(&s.url("/json"), "*/*", 1 << 20);
        assert!(
            matches!(r, Err(HttpError::Protocol(ref m)) if m.contains("TLS")),
            "{r:?}"
        );
    }
}

#[test]
fn update_http_nothing_listening_is_offline_and_a_silent_server_times_out() {
    let s = start();
    // A port with no listener.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let c = HttpsClient::with_extra_ca_pem(s.ca_pem.clone());
    let r = c.get(&format!("https://localhost:{dead}/x"), "*/*", 1024);
    assert!(matches!(r, Err(HttpError::Offline(_))), "{r:?}");

    let quick = HttpsClient::with_extra_ca_pem(s.ca_pem.clone())
        .with_timeouts(Duration::from_millis(800), Duration::from_millis(800));
    let t = Instant::now();
    let r = quick.get(&s.url("/hang"), "*/*", 1024);
    assert_eq!(r.unwrap_err(), HttpError::Timeout);
    assert!(t.elapsed() < Duration::from_secs(5));
}

#[test]
fn update_http_an_answer_bigger_than_the_cap_is_cut_off() {
    let s = start();
    let r = client(&s).get(&s.url("/big?bytes=2000000"), "*/*", 1_000_000);
    assert_eq!(r.unwrap_err(), HttpError::TooLarge);
    let r = client(&s).get(&s.url("/bigopen?bytes=2000000"), "*/*", 1_000_000);
    assert_eq!(r.unwrap_err(), HttpError::TooLarge);
}

#[test]
fn update_http_a_download_goes_to_a_file_and_reports_progress() {
    let s = start();
    let d = tempfile::tempdir().unwrap();
    let dest = d.path().join("a.bin");
    let mut last = 0u64;
    let mut calls = 0u32;
    let n = client(&s)
        .download(
            &s.url("/big?bytes=3000000"),
            &dest,
            10_000_000,
            &mut |done, total| {
                assert!(done >= last, "progress goes backwards");
                assert_eq!(total, Some(3_000_000));
                last = done;
                calls += 1;
            },
        )
        .unwrap();
    assert_eq!(n, 3_000_000);
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), 3_000_000);
    assert_eq!(last, 3_000_000);
    assert!(calls > 3, "progress arrives in pieces, not once ({calls})");
}

#[test]
fn update_http_a_failed_download_leaves_no_file() {
    let s = start();
    let d = tempfile::tempdir().unwrap();
    let c = client(&s);
    let mut noop = |_: u64, _: Option<u64>| {};

    // Too big by the announced length.
    let p = d.path().join("big.bin");
    assert_eq!(
        c.download(&s.url("/big?bytes=3000000"), &p, 1_000_000, &mut noop)
            .unwrap_err(),
        HttpError::TooLarge
    );
    assert!(!p.exists());
    // Too big while streaming (no announced length).
    let p = d.path().join("open.bin");
    assert_eq!(
        c.download(&s.url("/bigopen?bytes=3000000"), &p, 1_000_000, &mut noop)
            .unwrap_err(),
        HttpError::TooLarge
    );
    assert!(!p.exists());
    // The connection ends before the announced length.
    let p = d.path().join("short.bin");
    assert!(c
        .download(&s.url("/short"), &p, 1_000_000, &mut noop)
        .is_err());
    assert!(!p.exists());
    // Not found.
    let p = d.path().join("nf.bin");
    assert_eq!(
        c.download(&s.url("/missing"), &p, 1_000_000, &mut noop)
            .unwrap_err(),
        HttpError::Status(404)
    );
    assert!(!p.exists());
    // Rate limited.
    let p = d.path().join("lim.bin");
    assert_eq!(
        c.download(&s.url("/limited"), &p, 1_000_000, &mut noop)
            .unwrap_err(),
        HttpError::RateLimited
    );
    assert!(!p.exists());
}
