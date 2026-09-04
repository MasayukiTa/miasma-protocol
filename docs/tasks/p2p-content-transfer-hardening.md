Next task: make the actual content-transfer layer (publish → DHT → retrieve, and the BitTorrent bridge) work as reliably as it's claimed to, instead of leaving it at the state it was left in when this project was first built.

Current state (as of this investigation, 2026-09-04):
- The crypto/bypass-design layer (BBS+, AEAD, onion routing) has been reviewed separately and is solid.
- The actual content-transfer layer has serious, previously-undiagnosed gaps that undermine the project's core "censorship-resistant" claim:
  - `dissolve_and_publish` currently makes the publishing node the sole holder of every shard. There is no distribution to other peers. Taking the publisher offline makes its content unavailable -- no better than a regular server. Not listed anywhere in README's own "Does NOT resist" section until this was found (now moved there, see README.md).
  - DHT PUT returns success as soon as the record is written to the *local* Kademlia store, without waiting for network propagation -- a real publish/query race for any retriever not colocated with the publisher.
  - GET/retrieve has no retry or backoff at all (single pass, immediate failure below k shares), asymmetric with the real exponential-backoff engine that already exists for publish-side re-announcement (`daemon/replication.rs::RetryPolicy`).
  - Kademlia is running on 100% upstream library defaults -- no query timeout, replication factor, record TTL, or publication interval has ever been set.
  - The one test that actually validates end-to-end publish/retrieve over the DHT, `p2p_kademlia_full_roundtrip`, is `#[ignore]`d as flaky and has been since it was written. Root cause fully diagnosed (not "DHT is inherently flaky" -- it's a fixed-sleep race in the test itself, see below).
  - `StreamingRetrievalCoordinator` (100GB files, ~64MiB peak RAM, fully implemented, fully tested in isolation) is never called from the real coordinator/daemon/CLI retrieve path. Retrieval always buffers the whole reconstructed file in memory.
  - The BitTorrent bridge's only integration point with the desktop app is broken and has never worked: the desktop spawns `miasma-bridge.exe --magnet <uri>` but the bridge's own CLI dispatcher doesn't recognize `--magnet`/`--torrent` as anything and exits with "Unknown command". Confirmed via code (zero matches for either flag anywhere in the bridge crate) and via `docs/validation-report-0.3.0.md`, which independently lists real-torrent import as "not validated on this device."
  - All 31 of the bridge crate's tests are synthetic unit tests (bencode round-trips, SHA1 KATs, mock DHT/tracker byte parsing). Zero of them exercise a real or even loopback BitTorrent transfer.

Important execution guidance:
- This is being done because a stronger model (Sonnet 5) than what originally built this layer (Opus 4.5-era) is now available, and the user wants the actual core value proposition of this project -- content genuinely surviving on the network without depending on one node -- to be true, not just claimed.
- Full investigation and a phased implementation plan already exist: see `C:\Users\M118A8586\.claude\plans\binary-wiggling-sky.md` for the plan that was approved, and the two Explore-agent reports it was built from for exact file:line references (not reproduced in full here -- the plan file is the source of truth for what to do, this file is the running log of what's been done).
- Before writing the shard-distribution code (the highest-risk piece), the design was reviewed with a second AI advisor (codex 5.6 sol / claude fable) per explicit user instruction -- see the "External design review" section below once that happens.
- Reuse existing, already-tested infrastructure wherever it exists rather than rebuilding it: `ShareDistributor`/`ShareSink` (`dissolution/distributor.rs`) for shard distribution, `RetryPolicy` (`daemon/replication.rs`) for retrieve-side retry, `StreamingRetrievalCoordinator` (`retrieval/streaming.rs`) for large-file retrieval. All three already exist, fully implemented, and are simply unwired from the real path.
- Do not present a de-flaked test as proof the underlying race is fixed unless the actual root cause (fire-and-forget PUT, no readiness primitive) is what was fixed -- a longer sleep is not a fix.
- Do not claim shard distribution works until a test proves content survives the *original publisher* going offline (this is the one test that actually matters for the censorship-resistance claim; a test that only proves retrieval still works with the publisher online proves nothing new).

Goal:
Get to the point where README's "Resists: Content seizure via single node compromise" line is true and tested, `p2p_kademlia_full_roundtrip` runs unignored and green 20/20, and the BitTorrent bridge's desktop Import actually imports something for the first time.

## Phase 0 -- prep
- [x] Baseline test counts recorded before any change: `miasma-core` 701 passed / 10 ignored (4 test binaries: 453+194+54+0), `miasma-bridge` 31 passed / 0 ignored. Both via `cargo test -p <crate> --locked`.
- [x] README's "Resists" claim moved to "Does NOT resist" until Phase 2 makes it true again.
- [x] This doc created; cross-reference added to `remaining-tasks-prioritized.md`.

## Phase 1 -- fix what's broken, minimal new surface (DONE, 2026-09-04)
- [x] 1.1 DHT PUT waits for real network ack (`node.rs`'s already-half-built `pending_puts` map). Also had to handle the zero-connected-peers case explicitly: `put_record`'s `Quorum::One` fails immediately with `QuorumFailed { success: [], .. }` when there's nobody to replicate to yet -- this broke `cli_smoke_loopback` (which publishes before any peer exists, by design) until fixed to reply `Ok` immediately when `connected_peers().next().is_none()` rather than waiting on a quorum that cannot be met.
- [x] 1.2 Kademlia config made explicit (`set_query_timeout`=20s, `set_replication_factor`=8, `set_publication_interval`/`set_provider_publication_interval`=20min, `set_record_ttl`=24h) instead of silent upstream defaults.
- [x] 1.3 `wait_until_peer_connected` readiness primitive added on `DhtHandle` and `MiasmaCoordinator` (poll-based, zero new event-loop state).
- [x] 1.4 `p2p_kademlia_full_roundtrip` un-ignored, fixed sleeps replaced with 1.3's primitive + 1.1's real PUT-ack. **20/20 green** in local repeat runs (was quarantined at "~80% locally" before this fix).
- [x] 1.5 `SHARE_MSG_MAX` vs segment-size/shard-count interaction fixed via dynamic clamp (`max_segment_size_for` in `coordinator.rs`).
- New test `dht_put_blocks_until_acked` (integration_test.rs): 20/20 green.
- Full suite: `cargo test -p miasma-core --locked` -- 706 passed / 9 ignored / 0 failed (was 701/10/0 baseline; net +5 passed from 4 new tests + 1 un-ignored, -1 ignored).

## Phase 2 -- wire in what already exists
- [ ] 2.1 Shard distribution to remote peers via existing `ShareDistributor`/`ShareSink`, pushed over an enum-extended `/miasma/share/1.0.0`. **External design review checkpoint -- see below.**
- [ ] 2.2 Retrieve-side retry/backoff via existing `RetryPolicy`.
- [ ] 2.3 `StreamingRetrievalCoordinator` wired into the real network retrieve path.
- [ ] 2.4 IPC `Get`/`Retrieved` fixed to be file-path-based like `PublishFile`/`DirectedSendFile` already are.
- [ ] README's "Resists" line moved back once 2.1's two censorship-resistance tests are green.

## Phase 3 -- bridge dispatcher fix + real round-trip test
- [ ] 3.1 `--magnet`/`--torrent` argv mismatch fixed in `miasma-bridge/src/main.rs`'s dispatcher.
- [ ] 3.2 MID stdout-parsing bug in `worker.rs` fixed (`.trim()` missing, would have silently swallowed 3.1's fix).
- [ ] 3.3 Real two-process loopback test added (`crates/miasma-bridge/tests/cli_import_roundtrip.rs`) -- the first test in this crate that actually moves BitTorrent bytes.

Explicitly out of scope this pass (tracked here, not forgotten): base32 magnet info-hash parsing (`pipeline.rs`, narrow impact, hex already works), the reverse Miasma→BitTorrent re-seed stub (`main.rs cmd_retrieve`, no current caller depends on it), real internet-scale validation (roadmap's P2-6, a much bigger separate effort).

## External design review
(Fill in once the Phase 2.1 checkpoint conversation with codex 5.6 sol / claude fable actually happens -- record what was asked, what came back, and what changed in the plan as a result.)
