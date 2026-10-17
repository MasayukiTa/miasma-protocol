//! Trusted-contact push over a bad network, with no network: both services
//! run in this process over an in-memory link that a test can cut after N
//! bytes, stall, or refuse to dial. Time is virtual (`start_paused`), so a
//! 10-minute backoff costs nothing.
//!
//! What is asserted: the file arrives with the right hash however the link
//! misbehaves, every attempt resumes where the receiver stopped (a connection
//! never re-sends what the receiver already holds), the transfer's state walks
//! Waiting -> Sending -> Waiting -> Done, the queue survives a restart, and
//! fatal conditions end at once instead of retrying.

#![cfg(feature = "iroh")]

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use miasma_core::{
    config::PushConfig,
    push::{
        link::{BoxRx, BoxTx, CloseInfo, Dialer, Link, TxStream},
        proto::{self, Done, Header, Reply, PROTOCOL_VERSION},
        service::{PushService, PushSettings},
        ContactCode, Direction, PushState, PushTransferInfo,
    },
    transport::iroh_direct::IrohClientError,
};
use tempfile::TempDir;
use tokio::{
    io::{duplex, AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{mpsc, watch},
    time::Instant,
};

const CHUNK: u64 = 256 * 1024;
/// The in-memory pipe holds this much; bytes in it die with a cut.
const PIPE: usize = 64 * 1024;
const MIB: usize = 1024 * 1024;

// ─── The fake network ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum FaultKind {
    /// The connection dies.
    Drop,
    /// Writes never complete (the link is up but nothing moves).
    Stall,
}

#[derive(Clone, Copy)]
struct ConnFault {
    after_bytes: u64,
    kind: FaultKind,
}

struct Conn {
    closed: watch::Sender<Option<CloseInfo>>,
    wakers: Mutex<Vec<Waker>>,
    /// Bytes the dialing side may still write, and what happens at zero.
    fault: Mutex<Option<(u64, FaultKind)>>,
}

impl Conn {
    fn new(fault: Option<ConnFault>) -> Arc<Self> {
        Arc::new(Self {
            closed: watch::channel(None).0,
            wakers: Mutex::new(Vec::new()),
            fault: Mutex::new(fault.map(|f| (f.after_bytes, f.kind))),
        })
    }
    fn info(&self) -> Option<CloseInfo> {
        *self.closed.borrow()
    }
    fn close(&self, info: CloseInfo) {
        self.closed.send_if_modified(|v| {
            if v.is_none() {
                *v = Some(info);
                true
            } else {
                false
            }
        });
        for w in self.wakers.lock().unwrap().drain(..) {
            w.wake();
        }
    }
    fn register(&self, w: &Waker) {
        let mut g = self.wakers.lock().unwrap();
        if !g.iter().any(|x| x.will_wake(w)) {
            g.push(w.clone());
        }
    }
}

struct GTx {
    inner: DuplexStream,
    conn: Arc<Conn>,
    /// Set on the dialing side's data direction only.
    faulty: bool,
    counter: Arc<AtomicU64>,
}

impl AsyncWrite for GTx {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.conn.info().is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let mut take = buf.len();
        if self.faulty {
            let mut f = self.conn.fault.lock().unwrap();
            if let Some((left, kind)) = f.as_mut() {
                if *left == 0 {
                    match kind {
                        FaultKind::Drop => {
                            drop(f);
                            self.conn.close(CloseInfo::Other);
                            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                        }
                        FaultKind::Stall => {
                            self.conn.register(cx.waker());
                            return Poll::Pending;
                        }
                    }
                }
                take = take.min(*left as usize);
            }
        }
        self.conn.register(cx.waker());
        let me = &mut *self;
        match Pin::new(&mut me.inner).poll_write(cx, &buf[..take]) {
            Poll::Ready(Ok(n)) => {
                if me.faulty {
                    if let Some((left, _)) = me.conn.fault.lock().unwrap().as_mut() {
                        *left -= n as u64;
                    }
                    me.counter.fetch_add(n as u64, Ordering::SeqCst);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TxStream for GTx {
    fn finish(&mut self) {}
    fn stopped<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct GRx {
    inner: DuplexStream,
    conn: Arc<Conn>,
}

impl AsyncRead for GRx {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.conn.info().is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
        }
        self.conn.register(cx.waker());
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct FakeLink {
    conn: Arc<Conn>,
    remote: [u8; 32],
    dialer_side: bool,
    to_peer: mpsc::UnboundedSender<(BoxTx, BoxRx)>,
    from_peer: tokio::sync::Mutex<mpsc::UnboundedReceiver<(BoxTx, BoxRx)>>,
    counter: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl Link for FakeLink {
    async fn open_bi(&self) -> Result<(BoxTx, BoxRx), String> {
        if self.conn.info().is_some() {
            return Err("connection closed".into());
        }
        let (a_w, b_r) = duplex(PIPE);
        let (b_w, a_r) = duplex(PIPE);
        let mine: (BoxTx, BoxRx) = (
            Box::new(GTx {
                inner: a_w,
                conn: self.conn.clone(),
                faulty: self.dialer_side,
                counter: self.counter.clone(),
            }),
            Box::new(GRx {
                inner: a_r,
                conn: self.conn.clone(),
            }),
        );
        let theirs: (BoxTx, BoxRx) = (
            Box::new(GTx {
                inner: b_w,
                conn: self.conn.clone(),
                faulty: !self.dialer_side,
                counter: Arc::new(AtomicU64::new(0)),
            }),
            Box::new(GRx {
                inner: b_r,
                conn: self.conn.clone(),
            }),
        );
        self.to_peer.send(theirs).map_err(|_| "peer gone")?;
        Ok(mine)
    }
    async fn accept_bi(&self) -> Result<(BoxTx, BoxRx), String> {
        let mut rx = self.from_peer.lock().await;
        let mut closed = self.conn.closed.subscribe();
        tokio::select! {
            s = rx.recv() => s.ok_or_else(|| "peer gone".to_owned()),
            _ = closed.wait_for(|v| v.is_some()) => Err("connection closed".to_owned()),
        }
    }
    fn remote_id(&self) -> [u8; 32] {
        self.remote
    }
    fn close(&self, code: u32, _reason: &[u8]) {
        self.conn.close(CloseInfo::App(u64::from(code)));
    }
    fn close_info(&self) -> Option<CloseInfo> {
        self.conn.info()
    }
    async fn closed(&self) -> CloseInfo {
        let mut rx = self.conn.closed.subscribe();
        let v = rx.wait_for(|v| v.is_some()).await.unwrap();
        v.unwrap()
    }
}

/// A connected pair: (the dialer's end, the listener's end, the connection).
fn link_pair(
    dialer_id: [u8; 32],
    listener_id: [u8; 32],
    fault: Option<ConnFault>,
    counter: Arc<AtomicU64>,
) -> (Arc<FakeLink>, Arc<FakeLink>, Arc<Conn>) {
    let conn = Conn::new(fault);
    let (a_to_b, b_from_a) = mpsc::unbounded_channel();
    let (b_to_a, a_from_b) = mpsc::unbounded_channel();
    let dialer = Arc::new(FakeLink {
        conn: conn.clone(),
        remote: listener_id,
        dialer_side: true,
        to_peer: a_to_b,
        from_peer: tokio::sync::Mutex::new(a_from_b),
        counter: counter.clone(),
    });
    let listener = Arc::new(FakeLink {
        conn: conn.clone(),
        remote: dialer_id,
        dialer_side: false,
        to_peer: b_to_a,
        from_peer: tokio::sync::Mutex::new(b_from_a),
        counter: Arc::new(AtomicU64::new(0)),
    });
    (dialer, listener, conn)
}

#[derive(Default)]
struct Plan {
    refuse_next: usize,
    refuse_all: bool,
    /// One entry per connection that is let through (`None` = healthy).
    faults: VecDeque<Option<ConnFault>>,
}

/// Dials from `from_id` to a service in this process.
struct FakeNet {
    from_id: [u8; 32],
    to_id: [u8; 32],
    target: Mutex<Option<Arc<PushService>>>,
    inbox: PathBuf,
    plan: Mutex<Plan>,
    dials: AtomicUsize,
    dial_times: Mutex<Vec<Instant>>,
    /// Bytes written by the sender on each connection that was let through.
    conn_bytes: Mutex<Vec<Arc<AtomicU64>>>,
    /// Length of the receiver's partial file when each connection was made.
    part_at_dial: Mutex<Vec<u64>>,
}

impl FakeNet {
    fn new(from_id: [u8; 32], to_id: [u8; 32], inbox: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            from_id,
            to_id,
            target: Mutex::new(None),
            inbox,
            plan: Mutex::new(Plan::default()),
            dials: AtomicUsize::new(0),
            dial_times: Mutex::new(Vec::new()),
            conn_bytes: Mutex::new(Vec::new()),
            part_at_dial: Mutex::new(Vec::new()),
        })
    }
    fn set_target(&self, t: Arc<PushService>) {
        *self.target.lock().unwrap() = Some(t);
    }
    fn refuse(&self, n: usize) {
        self.plan.lock().unwrap().refuse_next = n;
    }
    fn refuse_all(&self, on: bool) {
        self.plan.lock().unwrap().refuse_all = on;
    }
    fn faults(&self, f: Vec<Option<ConnFault>>) {
        self.plan.lock().unwrap().faults = f.into();
    }
    fn dial_count(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }
    fn written(&self) -> Vec<u64> {
        self.conn_bytes
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.load(Ordering::SeqCst))
            .collect()
    }
}

fn part_len(inbox: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(inbox) {
        for d in rd.flatten() {
            if let Ok(files) = std::fs::read_dir(d.path()) {
                for f in files.flatten() {
                    if f.file_name().to_string_lossy().ends_with(".part") {
                        total += f.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
            }
        }
    }
    total
}

#[async_trait::async_trait]
impl Dialer for FakeNet {
    async fn dial(&self, _target: &[u8; 32]) -> Result<Arc<dyn Link>, IrohClientError> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        self.dial_times.lock().unwrap().push(Instant::now());
        let fault = {
            let mut p = self.plan.lock().unwrap();
            if p.refuse_all {
                return Err(IrohClientError::Unreachable("test: refused".into()));
            }
            if p.refuse_next > 0 {
                p.refuse_next -= 1;
                return Err(IrohClientError::Unreachable("test: refused".into()));
            }
            p.faults.pop_front().flatten()
        };
        let target = self.target.lock().unwrap().clone().expect("target set");
        let counter = Arc::new(AtomicU64::new(0));
        let (d, l, _conn) = link_pair(self.from_id, self.to_id, fault, counter.clone());
        self.conn_bytes.lock().unwrap().push(counter);
        self.part_at_dial
            .lock()
            .unwrap()
            .push(part_len(&self.inbox));
        tokio::spawn(async move { target.serve_link(l).await });
        Ok(d)
    }
}

/// A dialer for a service that never sends.
struct NoDial;

#[async_trait::async_trait]
impl Dialer for NoDial {
    async fn dial(&self, _t: &[u8; 32]) -> Result<Arc<dyn Link>, IrohClientError> {
        Err(IrohClientError::Unreachable("no route".into()))
    }
}

// ─── Fixtures ───────────────────────────────────────────────────────────────

struct Pair {
    alice: Arc<PushService>,
    bob: Arc<PushService>,
    net: Arc<FakeNet>,
    adir: TempDir,
    _bdir: TempDir,
    id_a: [u8; 32],
    id_b: [u8; 32],
    states: Arc<Mutex<Vec<(String, PushState)>>>,
}

fn settings(dir: &Path, tweak: impl FnOnce(&mut PushSettings)) -> PushSettings {
    let mut s = PushSettings::from_config(&PushConfig::default(), dir);
    s.min_free_bytes = 0;
    s.retry.jitter = 0.0;
    s.retry.min_gap = Duration::ZERO;
    tweak(&mut s);
    s
}

fn follow(svc: &PushService) -> Arc<Mutex<Vec<(String, PushState)>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut rx = svc.board().subscribe();
    let l = log.clone();
    tokio::spawn(async move {
        while let Ok(ev) = rx.recv().await {
            let mut g = l.lock().unwrap();
            if g.last() != Some(&ev) {
                g.push(ev);
            }
        }
    });
    log
}

async fn pair_with(
    tweak_a: impl FnOnce(&mut PushSettings),
    tweak_b: impl FnOnce(&mut PushSettings),
) -> Pair {
    let adir = tempfile::tempdir().unwrap();
    let bdir = tempfile::tempdir().unwrap();
    let id_a: [u8; 32] = rand::random();
    let id_b: [u8; 32] = rand::random();
    let bob = PushService::start_with_dialer(
        bdir.path(),
        id_b,
        Arc::new(NoDial),
        settings(bdir.path(), tweak_b),
    );
    let net = FakeNet::new(id_a, id_b, bob.inbox_dir().to_path_buf());
    net.set_target(bob.clone());
    let alice = PushService::start_with_dialer(
        adir.path(),
        id_a,
        net.clone(),
        settings(adir.path(), tweak_a),
    );
    alice
        .add_contact(&ContactCode::new(id_b), Some("bob"))
        .unwrap();
    bob.add_contact(&ContactCode::new(id_a), Some("alice"))
        .unwrap();
    let states = follow(&alice);
    Pair {
        alice,
        bob,
        net,
        adir,
        _bdir: bdir,
        id_a,
        id_b,
        states,
    }
}

async fn pair() -> Pair {
    pair_with(|_| {}, |_| {}).await
}

fn content(len: usize, seed: u32) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn write_src(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

async fn until<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn finished(svc: &PushService, id: &str, secs: u64) -> PushTransferInfo {
    until("the transfer to finish", secs, || {
        let t = svc.board().get(id)?;
        t.state.is_finished().then_some(t)
    })
    .await
}

async fn in_state(svc: &PushService, id: &str, st: PushState, secs: u64) -> PushTransferInfo {
    until(&format!("state {st:?}"), secs, || {
        let t = svc.board().get(id)?;
        (t.state == st).then_some(t)
    })
    .await
}

fn received(p: &Pair, name: &str) -> PathBuf {
    p.bob.inbox_dir().join("alice").join(name)
}

fn parts_left(p: &Pair) -> u64 {
    part_len(p.bob.inbox_dir())
}

fn sequence(p: &Pair, id: &str) -> Vec<PushState> {
    let mut out: Vec<PushState> = Vec::new();
    for (i, s) in p.states.lock().unwrap().iter() {
        if i == id && out.last() != Some(s) {
            out.push(*s);
        }
    }
    out
}

/// No connection re-sent what the receiver already held when it was made.
fn assert_resumed_each_time(net: &FakeNet, size: u64) {
    let written = net.written();
    let at_dial = net.part_at_dial.lock().unwrap().clone();
    assert_eq!(written.len(), at_dial.len());
    for (i, (w, have)) in written.iter().zip(&at_dial).enumerate() {
        // 4 KiB covers the header frame.
        assert!(
            *w <= size.saturating_sub(*have) + 4096,
            "connection {i} wrote {w} bytes but the receiver already had {have} of {size}"
        );
    }
}

// ─── Interrupted connections ────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn dropped_connections_resume_at_the_right_offset_until_the_hash_matches() {
    let p = pair().await;
    let data = content(6 * MIB + 12345, 1);
    let src = write_src(p.adir.path(), "big.bin", &data);
    // Every connection dies after a different number of bytes.
    let cuts = [1_300_000u64, 900_000, 2_000_000, 700_000];
    p.net.faults(
        cuts.iter()
            .map(|c| {
                Some(ConnFault {
                    after_bytes: *c,
                    kind: FaultKind::Drop,
                })
            })
            .collect(),
    );
    let id = p.alice.queue_send("bob", &src).unwrap();
    let t = finished(&p.alice, &id, 3600).await;
    assert_eq!(t.state, PushState::Done, "{:?} {:?}", t.error, t.error_kind);
    assert_eq!(std::fs::read(received(&p, "big.bin")).unwrap(), data);
    assert_eq!(parts_left(&p), 0);

    // One connection per cut plus the one that finished.
    let written = p.net.written();
    assert_eq!(written.len(), cuts.len() + 1, "{written:?}");
    assert_resumed_each_time(&p.net, data.len() as u64);
    // Bytes sent are the file plus, per interruption, what was in flight.
    let total: u64 = written.iter().sum();
    let bound = data.len() as u64 + cuts.len() as u64 * (CHUNK + PIPE as u64) + 4096;
    assert!(total <= bound, "sent {total}, bound {bound}");

    // Waiting -> Sending -> Waiting -> ... -> Done.
    let seq = sequence(&p, &id);
    let waits = seq.iter().filter(|s| **s == PushState::Waiting).count();
    assert_eq!(waits, cuts.len(), "{seq:?}");
    let first_wait = seq.iter().position(|s| *s == PushState::Waiting).unwrap();
    assert!(
        seq[..first_wait].contains(&PushState::Sending),
        "sending came first: {seq:?}"
    );
    assert!(
        seq[first_wait..].windows(3).any(|w| w
            == [
                PushState::Waiting,
                PushState::Connecting,
                PushState::Sending
            ]),
        "Waiting -> Sending again: {seq:?}"
    );
    assert_eq!(*seq.last().unwrap(), PushState::Done);
    // The queue is empty again.
    assert!(p.alice.queue_snapshot().is_empty());
}

#[tokio::test(start_paused = true)]
async fn refused_dials_wait_on_the_ladder_and_then_the_transfer_goes_through() {
    let p = pair().await;
    let data = content(700_000, 2);
    let src = write_src(p.adir.path(), "late.bin", &data);
    p.net.refuse(4);
    let t0 = Instant::now();
    let id = p.alice.queue_send("bob", &src).unwrap();

    let w = in_state(&p.alice, &id, PushState::Waiting, 60).await;
    assert_eq!(w.attempt, Some(1));
    assert_eq!(w.error_kind.as_deref(), Some("unreachable"));
    let at = w.next_attempt_at_ms.expect("a next attempt time");
    assert!(at > w.updated_at_ms.saturating_sub(1000));

    let t = finished(&p.alice, &id, 3600).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(received(&p, "late.bin")).unwrap(), data);

    // 5 s, 15 s, 45 s, 120 s between the five dials (jitter is off here).
    let times = p.net.dial_times.lock().unwrap().clone();
    assert_eq!(times.len(), 5);
    let gaps: Vec<u64> = times.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
    assert_eq!(gaps, vec![5, 15, 45, 120], "{gaps:?} after {:?}", t0.elapsed());
    let seq = sequence(&p, &id);
    assert!(seq.contains(&PushState::Waiting));
    assert_eq!(*seq.last().unwrap(), PushState::Done);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_link_is_closed_after_thirty_seconds_and_resumed() {
    let p = pair().await;
    let data = content(3 * MIB, 3);
    let src = write_src(p.adir.path(), "stuck.bin", &data);
    p.net.faults(vec![Some(ConnFault {
        after_bytes: 1_000_000,
        kind: FaultKind::Stall,
    })]);
    let id = p.alice.queue_send("bob", &src).unwrap();
    // The stall begins once the pipe is full; note when the sender notices.
    let w = in_state(&p.alice, &id, PushState::Waiting, 600).await;
    assert_eq!(w.error_kind.as_deref(), Some("timed_out"));
    let stall_seen = Instant::now();
    let t = finished(&p.alice, &id, 3600).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(received(&p, "stuck.bin")).unwrap(), data);
    assert_resumed_each_time(&p.net, data.len() as u64);
    // The sender had already waited its 30 s when it showed Waiting; the next
    // dial is the first rung of the ladder (5 s) later.
    let times = p.net.dial_times.lock().unwrap().clone();
    assert_eq!(times.len(), 2);
    let gap = (times[1] - times[0]).as_secs();
    assert!((30..=40).contains(&gap), "second dial {gap} s after the first");
    let _ = stall_seen;
}

#[tokio::test(start_paused = true)]
async fn a_flapping_link_still_delivers_and_progress_resets_the_backoff() {
    let p = pair().await;
    let data = content(4 * MIB, 4);
    let src = write_src(p.adir.path(), "flap.bin", &data);
    // Up for 400 KB, down; two refusals in between.
    let mut plan = Vec::new();
    for _ in 0..12 {
        plan.push(Some(ConnFault {
            after_bytes: 400_000,
            kind: FaultKind::Drop,
        }));
    }
    p.net.faults(plan);
    let id = p.alice.queue_send("bob", &src).unwrap();
    let t = finished(&p.alice, &id, 7200).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(received(&p, "flap.bin")).unwrap(), data);
    assert_resumed_each_time(&p.net, data.len() as u64);
    // Bytes moved between failures, so no wait ever grew past the first rung.
    let times = p.net.dial_times.lock().unwrap().clone();
    let longest = times
        .windows(2)
        .map(|w| (w[1] - w[0]).as_secs())
        .max()
        .unwrap();
    assert!(longest <= 6, "longest gap {longest} s");
}

// ─── Restart, cancel, give up, fatal ────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_queue_survives_a_restart_and_resumes_from_the_receivers_partial() {
    let mut p = pair().await;
    let data = content(3 * MIB, 5);
    let src = write_src(p.adir.path(), "restart.bin", &data);
    // The first connection dies mid-file, then nothing gets through.
    p.net.faults(vec![Some(ConnFault {
        after_bytes: 1_200_000,
        kind: FaultKind::Drop,
    })]);
    let id = p.alice.queue_send("bob", &src).unwrap();
    in_state(&p.alice, &id, PushState::Waiting, 120).await;
    p.net.refuse_all(true);
    tokio::time::sleep(Duration::from_secs(20)).await;
    let have = parts_left(&p);
    assert!(have > 0 && have < data.len() as u64, "partial {have}");

    // The daemon stops; a new one starts on the same data dir.
    p.alice.shutdown();
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(std::mem::replace(
        &mut p.alice,
        PushService::start_with_dialer(
            p.adir.path(),
            p.id_a,
            Arc::new(NoDial),
            settings(p.adir.path(), |_| {}),
        ),
    ));
    // It found the job again, under the same id and with the progress shown.
    let again = p.alice.board().get(&id).expect("the send was restored");
    assert_eq!(again.direction, Direction::Out);
    assert!(!again.state.is_finished());
    p.alice.shutdown();

    // The network is back for the third service.
    let net2 = FakeNet::new(p.id_a, p.id_b, p.bob.inbox_dir().to_path_buf());
    net2.set_target(p.bob.clone());
    p.alice = PushService::start_with_dialer(
        p.adir.path(),
        p.id_a,
        net2.clone(),
        settings(p.adir.path(), |_| {}),
    );
    let t = finished(&p.alice, &id, 600).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(received(&p, "restart.bin")).unwrap(), data);
    assert_eq!(parts_left(&p), 0);
    // The new run sent only what was missing.
    let sent: u64 = net2.written().iter().sum();
    assert!(
        sent <= data.len() as u64 - have + 4096,
        "sent {sent} but the receiver already had {have}"
    );
    // Done: nothing is left to restore.
    p.alice.shutdown();
    let fourth = PushService::start_with_dialer(
        p.adir.path(),
        p.id_a,
        Arc::new(NoDial),
        settings(p.adir.path(), |_| {}),
    );
    assert!(fourth.queue_snapshot().is_empty());
    fourth.shutdown();
}

#[tokio::test(start_paused = true)]
async fn cancel_while_waiting_ends_it_and_removes_it_from_the_queue() {
    let p = pair().await;
    let src = write_src(p.adir.path(), "never.bin", &content(100_000, 6));
    p.net.refuse_all(true);
    let id = p.alice.queue_send("bob", &src).unwrap();
    in_state(&p.alice, &id, PushState::Waiting, 60).await;
    assert!(p.alice.board().cancel(&id));
    let t = finished(&p.alice, &id, 60).await;
    assert_eq!(t.state, PushState::Cancelled);
    let dials = p.net.dial_count();
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(p.net.dial_count(), dials, "it kept dialing after the cancel");
    // And after a restart it does not come back.
    p.alice.shutdown();
    let again = PushService::start_with_dialer(
        p.adir.path(),
        p.id_a,
        Arc::new(NoDial),
        settings(p.adir.path(), |_| {}),
    );
    assert!(again.board().get(&id).is_none());
    again.shutdown();
}

#[tokio::test(start_paused = true)]
async fn when_the_window_is_used_up_it_fails_with_a_kind() {
    let p = pair_with(
        |s| s.retry.window = Some(Duration::from_secs(30 * 60)),
        |_| {},
    )
    .await;
    let src = write_src(p.adir.path(), "gone.bin", &content(100_000, 7));
    p.net.refuse_all(true);
    let id = p.alice.queue_send("bob", &src).unwrap();
    let t = finished(&p.alice, &id, 4 * 3600).await;
    assert_eq!(t.state, PushState::Failed);
    assert_eq!(t.error_kind.as_deref(), Some("unreachable"));
    assert!(t.error.as_deref().unwrap_or("").contains("gave up"), "{:?}", t.error);
    assert!(
        t.updated_at_ms >= t.created_at_ms,
        "sanity: {} {}",
        t.updated_at_ms,
        t.created_at_ms
    );
    // Retried for roughly the window and then stopped.
    let n = p.net.dial_count();
    assert!(n >= 5, "{n} dials");
    tokio::time::sleep(Duration::from_secs(4 * 3600)).await;
    assert_eq!(p.net.dial_count(), n);
    let seq = sequence(&p, &id);
    assert!(seq.contains(&PushState::Waiting));
    assert_eq!(*seq.last().unwrap(), PushState::Failed);
}

#[tokio::test(start_paused = true)]
async fn a_window_of_none_keeps_trying_for_days() {
    let p = pair_with(|s| s.retry.window = None, |_| {}).await;
    let src = write_src(p.adir.path(), "days.bin", &content(100_000, 8));
    p.net.refuse_all(true);
    let id = p.alice.queue_send("bob", &src).unwrap();
    tokio::time::sleep(Duration::from_secs(3 * 24 * 3600)).await;
    assert_eq!(p.alice.board().get(&id).unwrap().state, PushState::Waiting);
    // Then the other side comes back and it goes through by itself.
    p.net.refuse_all(false);
    let t = finished(&p.alice, &id, 3600).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
}

#[tokio::test(start_paused = true)]
async fn fatal_conditions_end_at_once_and_are_not_retried() {
    // The receiver refuses: not retried, one dial.
    let p = pair_with(|_| {}, |s| s.max_file_size = 1000).await;
    let src = write_src(p.adir.path(), "toobig.bin", &content(50_000, 9));
    let id = p.alice.queue_send("bob", &src).unwrap();
    let t = finished(&p.alice, &id, 600).await;
    assert_eq!(t.state, PushState::Rejected);
    assert_eq!(t.reject_reason.as_deref(), Some("too_large"));
    assert_eq!(p.net.dial_count(), 1);

    // The file changes after it was queued: nothing is sent.
    let src = write_src(p.adir.path(), "edited.bin", &content(50_000, 10));
    let id = p.alice.queue_send("bob", &src).unwrap();
    std::fs::write(&src, content(60_000, 11)).unwrap();
    let before = p.net.dial_count();
    let t = finished(&p.alice, &id, 600).await;
    assert_eq!(t.state, PushState::Failed);
    assert_eq!(t.error_kind.as_deref(), Some("source_changed"));
    assert_eq!(p.net.dial_count(), before);

    // The file disappears.
    let src = write_src(p.adir.path(), "vanished.bin", &content(50_000, 12));
    let id = p.alice.queue_send("bob", &src).unwrap();
    std::fs::remove_file(&src).unwrap();
    let t = finished(&p.alice, &id, 600).await;
    assert_eq!(t.state, PushState::Failed);
    assert_eq!(t.error_kind.as_deref(), Some("file_unreadable"));
    assert_eq!(p.net.dial_count(), before);

    // The contact is removed while the send waits.
    let src = write_src(p.adir.path(), "orphan.bin", &content(50_000, 13));
    p.net.refuse_all(true);
    let id = p.alice.queue_send("bob", &src).unwrap();
    in_state(&p.alice, &id, PushState::Waiting, 60).await;
    p.alice.remove_contact("bob").unwrap();
    let t = finished(&p.alice, &id, 60).await;
    assert_eq!(t.state, PushState::Cancelled);
}

// ─── Waking a waiting send ──────────────────────────────────────────────────

fn slow_ladder(s: &mut PushSettings) {
    s.retry.ladder = vec![Duration::from_secs(3600)];
    s.retry.then_every = Duration::from_secs(3600);
}

#[tokio::test(start_paused = true)]
async fn try_now_and_a_relay_that_comes_back_skip_the_timer() {
    let p = pair_with(slow_ladder, |_| {}).await;
    let data = content(200_000, 14);
    let src = write_src(p.adir.path(), "wake.bin", &data);
    p.net.refuse_all(true);
    let id = p.alice.queue_send("bob", &src).unwrap();
    in_state(&p.alice, &id, PushState::Waiting, 60).await;
    let n = p.net.dial_count();

    // Nothing happens by itself for a long while.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(p.net.dial_count(), n);

    // "Try now" dials at once (and fails again: still refused).
    assert!(p.alice.retry_now(&id));
    until("a dial after Try now", 5, || {
        (p.net.dial_count() > n).then_some(())
    })
    .await;
    in_state(&p.alice, &id, PushState::Waiting, 60).await;
    assert!(!p.alice.retry_now("no-such-id"));

    // The relay comes back: another dial, and this time the network works.
    let n = p.net.dial_count();
    p.net.refuse_all(false);
    p.alice.notify_relay_connected();
    let t = finished(&p.alice, &id, 60).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert!(p.net.dial_count() > n);
    assert_eq!(std::fs::read(received(&p, "wake.bin")).unwrap(), data);
}

#[tokio::test(start_paused = true)]
async fn a_network_change_and_a_connection_from_the_contact_skip_the_timer() {
    let p = pair_with(slow_ladder, |_| {}).await;
    let src = write_src(p.adir.path(), "wake2.bin", &content(150_000, 15));
    p.net.refuse_all(true);
    let id = p.alice.queue_send("bob", &src).unwrap();
    in_state(&p.alice, &id, PushState::Waiting, 60).await;

    let n = p.net.dial_count();
    p.alice.notify_network_change();
    until("a dial after the network change", 5, || {
        (p.net.dial_count() > n).then_some(())
    })
    .await;
    in_state(&p.alice, &id, PushState::Waiting, 60).await;

    // Bob opens a connection to alice: he is online, so alice tries now.
    let n = p.net.dial_count();
    p.net.refuse_all(false);
    let (bob_end, alice_end, _c) = link_pair(p.id_b, p.id_a, None, Arc::new(AtomicU64::new(0)));
    let alice = p.alice.clone();
    tokio::spawn(async move { alice.serve_link(alice_end).await });
    let _keep = bob_end;
    let t = finished(&p.alice, &id, 60).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert!(p.net.dial_count() > n);
}

// ─── The receiver ───────────────────────────────────────────────────────────

struct Raw {
    tx: BoxTx,
    rx: BoxRx,
    link: Arc<FakeLink>,
}

async fn raw_open(p: &Pair, h: &Header) -> (Raw, Reply) {
    let (d, l, _c) = link_pair(p.id_a, p.id_b, None, Arc::new(AtomicU64::new(0)));
    let bob = p.bob.clone();
    tokio::spawn(async move { bob.serve_link(l).await });
    let (mut tx, mut rx) = d.open_bi().await.unwrap();
    proto::write_frame(&mut tx, h).await.unwrap();
    let reply: Reply = proto::read_frame(&mut rx).await.unwrap();
    (Raw { tx, rx, link: d }, reply)
}

fn header_for(name: &str, data: &[u8]) -> Header {
    Header {
        v: PROTOCOL_VERSION,
        name: name.to_owned(),
        size: data.len() as u64,
        hash: blake3::hash(data).to_hex().to_string(),
        note: None,
    }
}

#[tokio::test(start_paused = true)]
async fn a_newer_connection_for_the_same_file_takes_over_and_nothing_is_corrupted() {
    let p = pair().await;
    let data = content(3 * MIB, 16);
    let h = header_for("takeover.bin", &data);

    // First attempt: sends 1 300 000 bytes and then goes quiet, connection
    // open. (The receiver writes to disk in 1 MiB steps.)
    let (mut one, r1) = raw_open(&p, &h).await;
    assert_eq!(r1, Reply::Accept { offset: 0 });
    one.tx.write_all(&data[..1_300_000]).await.unwrap();
    until("the receiver to write the bytes", 30, || {
        (parts_left(&p) >= MIB as u64).then_some(())
    })
    .await;

    // Second attempt on a new connection, while the first is still open.
    let (mut two, r2) = raw_open(&p, &h).await;
    let Reply::Accept { offset } = r2 else {
        panic!("not accepted: {r2:?}");
    };
    assert!(
        (MIB as u64..=1_300_000).contains(&offset),
        "resumed at {offset}"
    );
    // The first connection was told it was replaced.
    let info = tokio::time::timeout(Duration::from_secs(30), one.link.closed())
        .await
        .expect("the old connection was closed");
    assert_eq!(info, CloseInfo::App(409));

    two.tx.write_all(&data[offset as usize..]).await.unwrap();
    let done: Done = proto::read_frame(&mut two.rx).await.unwrap();
    assert!(done.ok, "{done:?}");
    assert_eq!(std::fs::read(received(&p, "takeover.bin")).unwrap(), data);
    assert_eq!(parts_left(&p), 0);
}

#[tokio::test(start_paused = true)]
async fn the_receiver_keeps_the_partial_when_the_sender_goes_quiet_for_good() {
    let p = pair().await;
    let data = content(MIB, 17);
    let h = header_for("quiet.bin", &data);
    let (mut raw, r) = raw_open(&p, &h).await;
    assert_eq!(r, Reply::Accept { offset: 0 });
    raw.tx.write_all(&data[..400_000]).await.unwrap();
    // Longer than the receiver's idle timeout, and than the whole ladder.
    tokio::time::sleep(Duration::from_secs(20 * 60)).await;
    let t = p
        .bob
        .board()
        .list()
        .into_iter()
        .find(|i| i.direction == Direction::In)
        .unwrap();
    assert_eq!(t.state, PushState::Failed);
    assert_eq!(t.error_kind.as_deref(), Some("timed_out"));
    assert!(parts_left(&p) >= 300_000, "progress was deleted");
    // Much later, a sender resumes from it and the bytes are identical.
    drop(raw);
    let (mut again, r) = raw_open(&p, &h).await;
    let Reply::Accept { offset } = r else {
        panic!("{r:?}")
    };
    assert!(offset >= 300_000);
    again.tx.write_all(&data[offset as usize..]).await.unwrap();
    let done: Done = proto::read_frame(&mut again.rx).await.unwrap();
    assert!(done.ok);
    assert_eq!(std::fs::read(received(&p, "quiet.bin")).unwrap(), data);
}

#[tokio::test(start_paused = true)]
async fn a_resumed_partial_with_wrong_bytes_is_caught_and_sent_again_from_scratch() {
    let p = pair().await;
    let data = content(900_000, 18);
    let dir = p.bob.inbox_dir().join("alice");
    std::fs::create_dir_all(&dir).unwrap();
    let h = blake3::hash(&data).to_hex().to_string();
    std::fs::write(
        dir.join(format!(".{}-{}.part", &h[..32], data.len())),
        vec![0u8; 300_000],
    )
    .unwrap();
    let src = write_src(p.adir.path(), "healed.bin", &data);
    let id = p.alice.queue_send("bob", &src).unwrap();
    let t = finished(&p.alice, &id, 600).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(received(&p, "healed.bin")).unwrap(), data);
}

// ─── Old peers and old readers ──────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_wire_is_the_old_one_a_stub_peer_of_the_old_protocol_gets_header_then_bytes() {
    // A receiver written against the old protocol, by hand: header frame,
    // Accept{offset}, raw bytes, Done. The new sender must speak exactly that,
    // including a non-zero offset.
    let adir = tempfile::tempdir().unwrap();
    let id_a: [u8; 32] = rand::random();
    let id_b: [u8; 32] = rand::random();
    struct Stub {
        link: Mutex<Option<Arc<FakeLink>>>,
        got: Arc<Mutex<Vec<u8>>>,
        header: Arc<Mutex<Option<Header>>>,
        from_id: [u8; 32],
        to_id: [u8; 32],
        have: Vec<u8>,
        ok: AtomicBool,
    }
    #[async_trait::async_trait]
    impl Dialer for Stub {
        async fn dial(&self, _t: &[u8; 32]) -> Result<Arc<dyn Link>, IrohClientError> {
            let (d, l, _c) = link_pair(self.from_id, self.to_id, None, Arc::new(AtomicU64::new(0)));
            *self.link.lock().unwrap() = Some(l.clone());
            let got = self.got.clone();
            let header = self.header.clone();
            let have = self.have.clone();
            let ok = self.ok.load(Ordering::SeqCst);
            let _ = ok;
            tokio::spawn(async move {
                let (mut tx, mut rx) = l.accept_bi().await.unwrap();
                let h: Header = proto::read_frame(&mut rx).await.unwrap();
                *header.lock().unwrap() = Some(h.clone());
                proto::write_frame(
                    &mut tx,
                    &Reply::Accept {
                        offset: have.len() as u64,
                    },
                )
                .await
                .unwrap();
                let mut buf = vec![0u8; h.size as usize - have.len()];
                tokio::io::AsyncReadExt::read_exact(&mut rx, &mut buf)
                    .await
                    .unwrap();
                *got.lock().unwrap() = buf;
                proto::write_frame(
                    &mut tx,
                    &Done {
                        ok: true,
                        saved_as: Some("x".into()),
                        error: None,
                    },
                )
                .await
                .unwrap();
                // Keep the connection until the sender has read the answer.
                let _ = l.closed().await;
            });
            Ok(d)
        }
    }
    let data = content(500_000, 19);
    let stub = Arc::new(Stub {
        link: Mutex::new(None),
        got: Arc::new(Mutex::new(Vec::new())),
        header: Arc::new(Mutex::new(None)),
        from_id: id_a,
        to_id: id_b,
        have: data[..123_456].to_vec(),
        ok: AtomicBool::new(true),
    });
    let alice =
        PushService::start_with_dialer(adir.path(), id_a, stub.clone(), settings(adir.path(), |_| {}));
    alice
        .add_contact(&ContactCode::new(id_b), Some("bob"))
        .unwrap();
    let src = write_src(adir.path(), "old.bin", &data);
    let id = alice.queue_send("bob", &src).unwrap();
    let t = finished(&alice, &id, 60).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    let h = stub.header.lock().unwrap().clone().unwrap();
    assert_eq!(h.v, PROTOCOL_VERSION);
    assert_eq!(h.name, "old.bin");
    assert_eq!(h.size, data.len() as u64);
    assert_eq!(h.hash, blake3::hash(&data).to_hex().to_string());
    assert_eq!(*stub.got.lock().unwrap(), data[123_456..].to_vec());
}
