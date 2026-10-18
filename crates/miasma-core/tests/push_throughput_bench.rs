//! Push throughput benchmark: two in-process iroh nodes on loopback, with and
//! without an injected one-way delay. Nothing here runs in CI by default: every
//! test is `#[ignore]`. Run it in release mode, one test at a time:
//!
//! ```text
//! cargo test --release -p miasma-core --test push_throughput_bench -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! `MIASMA_BENCH_MIB` sets the file size (default 256).
//!
//! How the delay is injected: the receiver's endpoint binds only `[::1]` and the
//! sender's only `127.0.0.1`, so they cannot reach each other directly. A UDP
//! shim bridges the two address families and holds every datagram for
//! `one_way` before forwarding it. The sender is told (through an in-memory
//! address lookup) that the receiver lives at the shim. No relay is used. The
//! shim's byte counter is printed: it must be at least the file size, which
//! proves the data went through it. Timer granularity of the host (about 1 ms
//! with tokio, up to 15 ms on a Windows host without a raised timer
//! resolution) rounds the delay, so the RTT printed is measured by the shim
//! with real packets, not assumed.

#![cfg(feature = "iroh")]

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use iroh::{address_lookup::memory::MemoryLookup, tls::CaTlsConfig, EndpointAddr, RelayMode};
use miasma_core::{
    config::{IrohMode, PushConfig},
    push::{
        service::{PushService, PushSettings},
        ContactCode, PushState,
    },
    transport::iroh_direct::{endpoint_builder, IrohNode, IrohServerLimits, IrohSettings},
    LocalShareStore,
};
use tempfile::TempDir;
use tokio::{net::UdpSocket, sync::mpsc};

// ─── CPU time of this process ────────────────────────────────────────────────

#[cfg(windows)]
fn cpu_time() -> Duration {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime {
        lo: u32,
        hi: u32,
    }
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(
            h: isize,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let (mut c, mut e, mut k, mut u) = (
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
    );
    // SAFETY: the four pointers are valid for writes for the duration of the call.
    let ok = unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
    assert!(ok != 0, "GetProcessTimes failed");
    let t = |f: FileTime| ((f.hi as u64) << 32 | f.lo as u64) * 100; // 100 ns units
    Duration::from_nanos(t(k) + t(u))
}

#[cfg(unix)]
fn cpu_time() -> Duration {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is a valid out-pointer.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

// ─── The delay shim ──────────────────────────────────────────────────────────

struct Shim {
    front: SocketAddr,
    bytes: Arc<AtomicU64>,
    /// Smallest and largest delay a datagram actually spent in the shim, ns.
    max_hold_ns: Arc<AtomicU64>,
}

fn big_udp(addr: &str) -> UdpSocket {
    let a: SocketAddr = addr.parse().unwrap();
    let s =
        socket2::Socket::new(socket2::Domain::for_address(a), socket2::Type::DGRAM, None).unwrap();
    s.set_recv_buffer_size(16 << 20).unwrap();
    s.set_send_buffer_size(16 << 20).unwrap();
    s.set_nonblocking(true).unwrap();
    s.bind(&a.into()).unwrap();
    UdpSocket::from_std(s.into()).unwrap()
}

/// `a_real` is the receiver's real `[::1]` socket.
async fn start_shim(a_real: SocketAddr, one_way: Duration) -> Shim {
    let front = Arc::new(big_udp("127.0.0.1:0"));
    let back = Arc::new(big_udp("[::1]:0"));
    let front_addr = front.local_addr().unwrap();
    let b_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let bytes = Arc::new(AtomicU64::new(0));
    let max_hold_ns = Arc::new(AtomicU64::new(0));

    // sender -> receiver
    let (up_tx, up_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    {
        let (front, b_addr, bytes) = (front.clone(), b_addr.clone(), bytes.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match front.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        *b_addr.lock().unwrap() = Some(from);
                        bytes.fetch_add(n as u64, Ordering::Relaxed);
                        let _ = up_tx.send((Instant::now() + one_way, buf[..n].to_vec()));
                    }
                    Err(_) => continue, // Windows reports ICMP unreachable here
                }
            }
        });
    }
    tokio::spawn(pump(
        up_rx,
        back.clone(),
        Dest::Fixed(a_real),
        max_hold_ns.clone(),
    ));

    // receiver -> sender
    let (down_tx, down_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    {
        let back = back.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match back.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        let _ = down_tx.send((Instant::now() + one_way, buf[..n].to_vec()));
                    }
                    Err(_) => continue,
                }
            }
        });
    }
    tokio::spawn(pump(
        down_rx,
        front,
        Dest::Learned(b_addr),
        max_hold_ns.clone(),
    ));

    Shim {
        front: front_addr,
        bytes,
        max_hold_ns,
    }
}

enum Dest {
    Fixed(SocketAddr),
    Learned(Arc<Mutex<Option<SocketAddr>>>),
}

async fn pump(
    mut rx: mpsc::UnboundedReceiver<(Instant, Vec<u8>)>,
    out: Arc<UdpSocket>,
    dest: Dest,
    max_hold_ns: Arc<AtomicU64>,
) {
    while let Some((due, data)) = rx.recv().await {
        let now = Instant::now();
        if due > now {
            tokio::time::sleep(due - now).await;
        }
        let held = Instant::now().saturating_duration_since(due);
        max_hold_ns.fetch_max(held.as_nanos() as u64, Ordering::Relaxed);
        let to = match &dest {
            Dest::Fixed(a) => Some(*a),
            Dest::Learned(m) => *m.lock().unwrap(),
        };
        if let Some(to) = to {
            let _ = out.send_to(&data, to).await;
        }
    }
}

// ─── Peers ───────────────────────────────────────────────────────────────────

struct Peer {
    node: Arc<IrohNode>,
    svc: Arc<PushService>,
    dir: TempDir,
}

/// `bind` is the only IP socket the endpoint gets. No relay.
async fn peer(bind: &str, lookup: &MemoryLookup) -> Peer {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(store_dir.path(), 10).unwrap());
    let s = IrohSettings {
        mode: IrohMode::N0,
        relay_urls: vec![],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(30),
        ca_pem: None,
        proxy_from_env: false,
    };
    let seed: [u8; 32] = rand::random();
    let builder = endpoint_builder(Some(&seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr(bind)
        .unwrap()
        .address_lookup(lookup.clone());
    let node = IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap();
    std::mem::forget(store_dir);
    let mut settings = PushSettings::from_config(&PushConfig::default(), dir.path());
    settings.min_free_bytes = 0;
    settings.idle_timeout = Duration::from_secs(60);
    let svc = PushService::start(dir.path(), node.clone(), settings);
    Peer { node, svc, dir }
}

fn write_file(path: &std::path::Path, mib: usize) {
    use std::io::Write;
    let mut block = vec![0u8; 1 << 20];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    for i in 0..mib {
        for c in block.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
        }
        block[..8].copy_from_slice(&(i as u64).to_le_bytes());
        f.write_all(&block).unwrap();
    }
}

fn mib() -> usize {
    std::env::var("MIASMA_BENCH_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

/// Push one file from `tx` to `rx` and print the numbers. `rtt` is the
/// injected round trip (zero: direct loopback without the shim when `shim` is
/// false, shim with no hold when true).
async fn run(
    label: &str,
    shim_rtt: Option<Duration>,
    mib: usize,
) -> (
    miasma_core::push::PushTransferInfo,
    miasma_core::push::PushTransferInfo,
) {
    let lookup = MemoryLookup::new();
    // Without the shim both nodes share plain IPv4 loopback. With it, the
    // receiver is IPv6-only and the sender IPv4-only: the shim is the only way across.
    let rx_bind = if shim_rtt.is_some() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let rx = peer(rx_bind, &lookup).await;
    let tx = peer("127.0.0.1:0", &lookup).await;
    let a_real = rx
        .node
        .endpoint()
        .bound_sockets()
        .into_iter()
        .next()
        .expect("receiver has a socket");
    let a_real = if a_real.is_ipv6() {
        SocketAddr::new("::1".parse().unwrap(), a_real.port())
    } else {
        SocketAddr::new("127.0.0.1".parse().unwrap(), a_real.port())
    };
    let shim = match shim_rtt {
        Some(rtt) => Some(start_shim(a_real, rtt / 2).await),
        None => None,
    };
    let reach = shim.as_ref().map(|s| s.front).unwrap_or(a_real);
    lookup.add_endpoint_info(EndpointAddr::new(rx.node.endpoint().id()).with_ip_addr(reach));
    tx.svc
        .add_contact(&ContactCode::new(rx.node.endpoint_id()), Some("rx"))
        .unwrap();
    rx.svc
        .add_contact(&ContactCode::new(tx.node.endpoint_id()), Some("tx"))
        .unwrap();

    let src = tx.dir.path().join("bench.bin");
    write_file(&src, mib);
    let total = (mib as u64) << 20;

    let cpu0 = cpu_time();
    let wall0 = Instant::now();
    let id = tx.svc.queue_send("rx", &src).unwrap();
    let (mut t_send0, mut t_send1) = (None, None);
    let last = loop {
        let t = tx.svc.board().get(&id).expect("on the board");
        let now = Instant::now();
        if t.state == PushState::Sending && t_send0.is_none() {
            t_send0 = Some(now);
        }
        if matches!(t.state, PushState::Verifying) || t.state.is_finished() {
            t_send1.get_or_insert(now);
        }
        if t.state.is_finished() {
            break t;
        }
        assert!(
            wall0.elapsed() < Duration::from_secs(1800),
            "timed out in {:?}",
            t.state
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let wall = wall0.elapsed();
    let cpu = cpu_time() - cpu0;
    assert_eq!(last.state, PushState::Done, "{:?}", last.error);

    let send = t_send1.unwrap() - t_send0.unwrap();
    let mb = total as f64 / 1e6;
    println!(
        "BENCH {label}: {mib} MiB | send phase {:.2} s = {:.1} MB/s ({:.0} Mbps) | end to end {:.2} s = {:.1} MB/s | CPU {:.2} s ({:.0}% of one core)",
        send.as_secs_f64(),
        mb / send.as_secs_f64(),
        mb * 8.0 / send.as_secs_f64(),
        wall.as_secs_f64(),
        mb / wall.as_secs_f64(),
        cpu.as_secs_f64(),
        100.0 * cpu.as_secs_f64() / wall.as_secs_f64(),
    );
    if let Some(s) = &shim {
        let moved = s.bytes.load(Ordering::Relaxed);
        println!(
            "BENCH {label}: shim carried {:.1} MB toward the receiver (file {:.1} MB); worst extra hold {:.1} ms",
            moved as f64 / 1e6,
            mb,
            s.max_hold_ns.load(Ordering::Relaxed) as f64 / 1e6,
        );
        assert!(moved >= total, "the data did not go through the shim");
    }
    // The receiver's row finishes just after the sender's.
    let end = Instant::now() + Duration::from_secs(30);
    let inbound = loop {
        if let Some(i) = rx
            .svc
            .board()
            .list()
            .into_iter()
            .find(|i| i.state.is_finished())
        {
            break i;
        }
        assert!(Instant::now() < end, "no finished inbound row");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (last, inbound)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark"]
async fn bench_loopback_direct() {
    run("loopback direct", None, mib()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark"]
async fn bench_shim_rtt_0ms() {
    run("shim rtt 0 ms", Some(Duration::ZERO), mib()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark"]
async fn bench_shim_rtt_30ms() {
    run("shim rtt 30 ms", Some(Duration::from_millis(30)), mib()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark"]
async fn bench_shim_rtt_150ms() {
    run("shim rtt 150 ms", Some(Duration::from_millis(150)), mib()).await;
}

/// Not a benchmark: a real push over loopback fills the live statistics on both
/// sides. Runs in CI (a few MiB, loopback only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finished_push_carries_live_statistics_on_both_sides() {
    use miasma_core::push::stats::PathKind;
    let (out, inc) = run("stats", None, 24).await;
    for (side, t) in [("sender", &out), ("receiver", &inc)] {
        let st = t
            .stats
            .as_ref()
            .unwrap_or_else(|| panic!("{side}: no stats"));
        assert_eq!(
            st.rate_bits, 0,
            "{side}: rate is zero once the data phase ended"
        );
        assert!(st.avg_bits > 0, "{side}: average speed missing");
        assert!(st.active_ms > 0, "{side}: active time missing");
        // Both nodes have only a loopback IP socket and no relay: the only path is direct.
        assert_eq!(st.path, PathKind::Direct, "{side}");
        assert!(st.rtt_ms.is_some(), "{side}: rtt missing");
        assert_eq!(st.bytes_relay, Some(0), "{side}");
    }
}
