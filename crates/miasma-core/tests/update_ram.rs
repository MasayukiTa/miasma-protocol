//! Memory cost of the updater: a download of 96 MiB streams to disk without the
//! process growing by more than 8 MiB, and 300 full cycles of
//! check / download / verify / apply (with a 40 KiB release list each) leave
//! the process where it was (at most 2 MiB over the baseline, with a flat
//! curve), so nothing stays resident between checks.
//!
//! How it is measured: the private (commit) bytes of this process (`VmRSS` on
//! Linux; `GetProcessMemoryInfo` private usage on Windows). A warm-up faults in
//! the code and allocator arenas first and is taken out of the baseline. The
//! test is alone in this file so no other test shares the process. On other
//! systems it only checks the data.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::update_server::start;
use miasma_core::update::apply::{Activity, Busy, Prober};
use miasma_core::update::config::UpdateConfig;
use miasma_core::update::http::{Http, HttpError, HttpResponse, HttpsClient};
use miasma_core::update::release::{Os, REPO};
use miasma_core::update::verify::sha256_bytes;
use miasma_core::update::{CheckOutcome, Engine};

#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: u64 = s
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb * 1024)
}

#[cfg(windows)]
fn resident_bytes() -> Option<u64> {
    #[repr(C)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(p: isize, c: *mut Counters, cb: u32) -> i32;
    }
    // SAFETY: valid pointer to a correctly laid out struct of the stated size.
    unsafe {
        let mut c: Counters = std::mem::zeroed();
        c.cb = std::mem::size_of::<Counters>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) == 0 {
            return None;
        }
        Some(c.pagefile_usage as u64)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn resident_bytes() -> Option<u64> {
    None
}

const LIST_URL: &str =
    "https://api.github.com/repos/MasayukiTa/miasma-protocol/releases?per_page=10";
const ZIP_URL: &str = "https://dl.invalid/miasma-9.9.9-windows-x64.zip";
const SUMS_URL: &str = "https://dl.invalid/SHA256SUMS.txt";
const ZIP_NAME: &str = "miasma-9.9.9-windows-x64.zip";
const NEW_CLI: &str = "miasma 9.9.9 (ram000000)\n";

/// A 40 KiB release list: ten releases, the newest one installable.
fn release_list() -> Vec<u8> {
    let mut items = Vec::new();
    for i in 0..10 {
        let tag = if i == 0 {
            "v9.9.9".to_string()
        } else {
            format!("v0.{i}.0")
        };
        let assets: Vec<String> = (0..40)
            .map(|k| {
                format!(
                    r#"{{"name":"file-{i}-{k}.bin","browser_download_url":"https://dl.invalid/file-{i}-{k}.bin","size":{k}}}"#
                )
            })
            .chain([
                format!(r#"{{"name":"{ZIP_NAME}","browser_download_url":"{ZIP_URL}","size":300}}"#),
                format!(r#"{{"name":"SHA256SUMS.txt","browser_download_url":"{SUMS_URL}","size":100}}"#),
            ])
            .collect();
        items.push(format!(
            r#"{{"tag_name":"{tag}","draft":false,"prerelease":false,"assets":[{}]}}"#,
            assets.join(",")
        ));
    }
    format!("[{}]", items.join(",")).into_bytes()
}

fn zip_bytes() -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let o = zip::write::SimpleFileOptions::default();
        z.start_file("miasma.exe", o).unwrap();
        z.write_all(NEW_CLI.as_bytes()).unwrap();
        z.start_file("miasma-desktop.exe", o).unwrap();
        z.write_all(b"new desktop").unwrap();
        z.finish().unwrap();
    }
    buf.into_inner()
}

struct OfflineGithub {
    list: Vec<u8>,
    zip: Vec<u8>,
    sums: Vec<u8>,
}

impl Http for OfflineGithub {
    fn get(&self, url: &str, _a: &str, max: usize) -> Result<HttpResponse, HttpError> {
        let body = match url {
            LIST_URL => self.list.clone(),
            SUMS_URL => self.sums.clone(),
            _ => Vec::new(),
        };
        assert!(body.len() <= max);
        Ok(HttpResponse {
            status: if body.is_empty() { 404 } else { 200 },
            body,
            rate_limited: false,
        })
    }
    fn download(
        &self,
        url: &str,
        dest: &Path,
        _max: u64,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<u64, HttpError> {
        assert_eq!(url, ZIP_URL);
        std::fs::write(dest, &self.zip).map_err(|e| HttpError::Io(e.to_string()))?;
        progress(self.zip.len() as u64, Some(self.zip.len() as u64));
        Ok(self.zip.len() as u64)
    }
}

struct TextProber;
impl Prober for TextProber {
    fn version(&self, exe: &Path, _t: Duration) -> Result<String, String> {
        std::fs::read_to_string(exe).map_err(|e| e.to_string())
    }
}
struct Idle;
impl Activity for Idle {
    fn busy(&self) -> Busy {
        Busy::Idle
    }
}

#[test]
fn update_download_streams_to_disk_and_nothing_stays_resident() {
    // ── 1. A 96 MiB download is written in pieces, never held in memory ──
    let server = start();
    let client = HttpsClient::with_extra_ca_pem(server.ca_pem.clone());
    let dir = tempfile::tempdir().unwrap();
    let mut sink = |_: u64, _: Option<u64>| {};
    // Warm-up: the TLS stack, the runtime and the allocator arenas.
    client
        .download(
            &server.url("/big?bytes=1048576"),
            &dir.path().join("warm.bin"),
            1 << 30,
            &mut sink,
        )
        .unwrap();
    let base = resident_bytes().unwrap_or(0);
    let mut peak = base;
    const BIG: u64 = 96 * 1024 * 1024;
    let mut next_sample = 0u64;
    let big = dir.path().join("big.bin");
    let n = client
        .download(
            &server.url(&format!("/big?bytes={BIG}")),
            &big,
            1 << 30,
            &mut |done, _| {
                if done >= next_sample {
                    next_sample = done + 4 * 1024 * 1024;
                    if let Some(r) = resident_bytes() {
                        peak = peak.max(r);
                    }
                }
            },
        )
        .unwrap();
    assert_eq!(n, BIG);
    assert_eq!(std::fs::metadata(&big).unwrap().len(), BIG);
    std::fs::remove_file(&big).unwrap();
    if resident_bytes().is_some() {
        let growth = peak.saturating_sub(base);
        println!(
            "download of {} MiB: baseline {:.2} MiB, peak growth {:.2} MiB",
            BIG / 1048576,
            base as f64 / 1048576.0,
            growth as f64 / 1048576.0
        );
        assert!(
            growth <= 8 * 1024 * 1024,
            "a 96 MiB download made the process grow by {growth} bytes: it is held in memory"
        );
    }
    drop(client);
    drop(server);

    // ── 2. 300 check / download / verify / apply cycles leave nothing behind ──
    let zip = zip_bytes();
    let sums = format!("{}  {ZIP_NAME}\n", sha256_bytes(&zip)).into_bytes();
    let http = Arc::new(OfflineGithub {
        list: release_list(),
        zip,
        sums,
    });
    assert!(
        http.list.len() > 30 * 1024,
        "the list should be about 40 KiB"
    );

    struct Shared(Arc<OfflineGithub>);
    impl Http for Shared {
        fn get(&self, u: &str, a: &str, m: usize) -> Result<HttpResponse, HttpError> {
            self.0.get(u, a, m)
        }
        fn download(
            &self,
            u: &str,
            d: &Path,
            m: u64,
            p: &mut (dyn FnMut(u64, Option<u64>) + Send),
        ) -> Result<u64, HttpError> {
            self.0.download(u, d, m, p)
        }
    }

    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let install = root.path().join("install");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&install).unwrap();
    std::fs::write(install.join("miasma.exe"), "miasma 0.3.2 (old000000)\n").unwrap();
    std::fs::write(install.join("miasma-desktop.exe"), "old desktop").unwrap();

    let cycle = || {
        let engine = Engine {
            http: Box::new(Shared(http.clone())),
            prober: Box::new(TextProber),
            activity: Box::new(Idle),
            os: Os::Windows,
            cfg: UpdateConfig::default(),
            current: semver::Version::parse("0.3.2").unwrap(),
            build_id: "old000000".into(),
            exe: install.join("miasma-desktop.exe"),
            data_dir: data.clone(),
            keys: Vec::new(),
            repo: REPO.to_owned(),
            health_timeout: Duration::from_secs(1),
            packaged: false,
        };
        let CheckOutcome::Available(offer) = engine.check() else {
            panic!("the fake release is newer");
        };
        let mut j = engine.prepare(&offer, &mut |_, _| {}).unwrap();
        engine.apply(&mut j).unwrap();
    };

    for _ in 0..20 {
        cycle();
    }
    let baseline = resident_bytes().unwrap_or(0);
    let mut peak = baseline;
    let mut curve: Vec<(u32, u64)> = Vec::new();
    for k in 1..=300u32 {
        cycle();
        if k % 50 == 0 {
            if let Some(r) = resident_bytes() {
                peak = peak.max(r);
                curve.push((k, r.saturating_sub(baseline)));
            }
        }
    }
    // Every cycle really installed: the program is the new one, one backup kept.
    assert_eq!(
        std::fs::read_to_string(install.join("miasma.exe")).unwrap(),
        NEW_CLI
    );
    assert!(install.join("miasma.exe.prev").exists());
    assert!(!install.join("miasma.exe.new").exists());
    match resident_bytes() {
        Some(_) => {
            let growth = peak.saturating_sub(baseline);
            println!(
                "300 update cycles: baseline {:.2} MiB, growth {:.2} MiB",
                baseline as f64 / 1048576.0,
                growth as f64 / 1048576.0
            );
            for (k, over) in &curve {
                println!(
                    "  {k:>4} cycles: {:.2} MiB over baseline",
                    *over as f64 / 1048576.0
                );
            }
            assert!(
                growth <= 2 * 1024 * 1024,
                "the updater leaves {growth} bytes resident after 300 cycles"
            );
            let first = curve.first().map(|c| c.1).unwrap_or(0);
            let last = curve.last().map(|c| c.1).unwrap_or(0);
            assert!(
                last.saturating_sub(first) <= 512 * 1024,
                "the curve keeps rising: {first} -> {last}"
            );
        }
        None => println!("no memory probe on this platform; data checks only"),
    }
}
