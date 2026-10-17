//! Memory cost of the reachability matrix: running it 6 000 times in one
//! process (every probe answered by a fake, the report serialised each time)
//! may grow the process by at most 3 MiB, and the second half of the run by at
//! most 1 MiB: nothing accumulates between runs.
//!
//! Measured as in `chat_ram.rs`: private (commit) bytes of this process
//! (`VmRSS` on Linux, private usage on Windows), after a warm-up that faults in
//! the code and the allocator. The test is alone in this file so no other test
//! shares the process. On other systems it only checks the data.

#![cfg(feature = "iroh")]

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use miasma_core::{
    config::IrohMode,
    transport::{
        iroh_direct::IrohSettings,
        reach::{
            run_matrix, DnsResult, LanEvent, MatrixOptions, Net, RelayEvent, Target, TcpEvent,
            TlsEvent, UdpEvent, UserProbe, WsEvent,
        },
    },
};

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

/// Every path works, instantly.
struct AllWorks;

#[async_trait]
impl Net for AllWorks {
    async fn system_dns(&self, _h: &str, _l: Duration) -> DnsResult {
        Ok(vec![IpAddr::from([203, 0, 113, 5])])
    }
    async fn udp_dns(&self, _r: SocketAddr, _h: &str, _l: Duration) -> DnsResult {
        Ok(vec![IpAddr::from([203, 0, 113, 5])])
    }
    async fn tcp(&self, _a: SocketAddr, _l: Duration) -> TcpEvent {
        TcpEvent::Connected
    }
    async fn tls(&self, _a: SocketAddr, _s: &str, _l: Duration) -> TlsEvent {
        TlsEvent::Cert {
            issuer: "Public Root".into(),
            public_ca: true,
            trusted: true,
        }
    }
    async fn udp(&self, _l: Duration) -> UdpEvent {
        UdpEvent {
            udp_v4: true,
            udp_v6: false,
            nat_varies: Some(false),
            quic_relays: 2,
            failed: false,
        }
    }
    async fn relay_path(&self, _l: Duration) -> RelayEvent {
        RelayEvent::Done {
            rtt_ms: 40,
            kib_per_s: Some(900),
        }
    }
    async fn websocket(&self, _a: SocketAddr, _t: &Target, _l: Duration) -> WsEvent {
        WsEvent::Upgraded { rtt_ms: Some(30) }
    }
    async fn lan(&self, _l: Duration) -> LanEvent {
        LanEvent::Seen
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn running_the_matrix_over_and_over_does_not_grow_memory() {
    let settings = IrohSettings {
        mode: IrohMode::N0,
        relay_urls: vec![],
        discovery: true,
        lan_discovery: true,
        connect_timeout: Duration::from_secs(5),
        ca_pem: None,
        proxy_from_env: false,
    };
    let opts = MatrixOptions::from_settings(
        &settings,
        vec![UserProbe::parse("wss://ep.example/x").unwrap()],
    );
    let run = || async {
        let r = run_matrix(&AllWorks, &opts).await;
        assert!(r.probes.iter().all(|p| p.ok));
        serde_json::to_string(&r).unwrap().len()
    };
    for _ in 0..300 {
        run().await;
    }
    let baseline = resident_bytes();
    let mut samples = Vec::new();
    for i in 1..=6_000 {
        run().await;
        if i % 1_000 == 0 {
            samples.push(resident_bytes());
        }
    }
    let (Some(base), Some(&Some(last))) = (baseline, samples.last()) else {
        return; // not measurable here; the data checks above ran
    };
    let mid = samples[2].unwrap();
    let growth = last.saturating_sub(base);
    let late = last.saturating_sub(mid);
    assert!(
        growth <= 3 * 1024 * 1024,
        "grew {growth} bytes: {samples:?}"
    );
    assert!(
        late <= 1024 * 1024,
        "still growing: {late} bytes: {samples:?}"
    );
}
