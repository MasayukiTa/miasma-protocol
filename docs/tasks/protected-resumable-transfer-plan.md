# Protected, resumable large-file transfer — plan and running log

Branch: `work/resumable-protected-transfer` (based on `work/large-file-release-gate`).
Started: 2026-09-29. Status: **Phases 1-6 done on this machine. Nothing has yet been run between two physical machines, and `miasma-cli` has not been built on macOS.** See §6 for what was actually run and §7b for what was left.

## 0. 要約 (Japanese summary for the owner)

依頼された要件(2026-09-29):

| # | 要件 | 決定 |
|---|---|---|
| ① | 分割し、各ピースが個別の ID を持ち、確実に検証されること(torrent の強み)。**MID とパスワードの2つで縛る。パスワードは暗号化の一要素** | ピース ID = 各シェアの BLAKE3。全ピース ID を載せた**マニフェスト**を導入。パスワードは Argon2id → HKDF で**セグメント鍵に混ぜる**(MID と全シェアを持っていても、パスワード無しでは復号できない) |
| ③ | 冗長度が高すぎる。下げる余地を試す | `k`/`n` を公開時に指定可能にし、**受信側は k/n をレコードから自動取得**。`n == k`(冗長ゼロ)を許す専用経路を追加。プリセットの実測ハーネスを用意 |
| ④ | 最初に index が渡り、どこまで受けたか分かる。**再開できること** | マニフェスト = index。受信・送信の両方に進捗(セグメント/バイト/速度/ETA)と再開(`.part` + ジャーナル)を実装 |
| ② | 速度は実走してから | 今は最適化しない。**計測できるように**フェーズ別タイミングと速度を状態に出す |
| — | テスト規模 | 送信側 macOS(外付け SSD 2 TB)→ 受信側 Windows。逆方向は 100 MB 程度 |

方針: 他セッションが同じ領域(IPC・daemon・CLI・desktop)を編集中のため、**新機能は新モジュール `transfer/` に閉じ込め**、既存ファイルへの変更は「バリアント追加と呼び出し1行」に限定する(§8)。

## 1. Why (measured / read from code at `21075cd`)

Nothing in this section was run; every item is from reading the code.

1. **Retrieval has no progress and no resume.** `daemon/mod.rs` `GetToFile` writes straight to
   the output path, returns one response at the very end, and on *any* error — including the final
   whole-file MID mismatch — deletes the output. A failure at 99 GB restarts from zero.
2. **A segment that cannot reach `k` valid pieces ends the transfer, and there is no retry at that
   level.** `retrieval/streaming.rs` walks the candidate list once; `FallbackShareSource::fetch`
   turns a failed transport into `Ok(None)` (so one dead holder does not abort — `?` only fires
   on a malformed locator), but if fewer than `k` valid pieces turn up the stream yields
   `InsufficientShares` and `GetToFile` deletes the output. *(Corrected 2026-09-29: an earlier
   version of this line said a single transport error aborts the stream; reading
   `retrieval/transport_source.rs` shows it does not.)*
   Also read from that file, unmeasured: `list_candidates_for_segment` calls `self.dht.get(mid)`
   every time, so a 1600-segment transfer performs 1600 DHT GETs of a ~8 MB record. The new receive
   engine fetches the record once.
3. **Pieces are not individually identified by the receiver.** Each `MiasmaShare` carries its own
   `shard_hash`, but the receiver has no list of *expected* piece IDs, so a holder can serve any
   self-consistent junk and it is only caught after RS decode + AEAD fail.
4. **The content is bound to nobody.** The MID is the capability: anyone who learns it and can
   reach a holder can fetch and decrypt. The recipient-bound path (`directed`) encrypts the whole
   plaintext in one AEAD call from a `&[u8]`, so it cannot carry 100 GB.
5. **Redundancy is fixed by default at 2.0×** (`k=10, n=20`). For a 100 GiB file that is
   205,051 MiB (200.24 GiB) of owned-share quota; the sender needs ≈300 GiB free.
   `rs_encode` rejects `n <= k`, so redundancy cannot go below `n = k + 1`.
7. **Serving one piece cost O(pieces in the store) full decryptions.** *(Found by measurement while
   building Phase 3; see §6.)* `search_by_mid_prefix` decrypted every stored share to read its header,
   the serving handler then decrypted candidates again, and each `get` rewrote the whole index file.
   For a 100 GiB publish that is 32,000 shares — about 200 GiB of decryption per fetch request on the
   sender. Nothing else in this plan can matter until that is gone.
6. **The receiver must already know `k` and `n`.** The MID is `BLAKE3(plaintext ‖ "k=..,n=..,v=1")`
   and the MID string does not carry them; `GetToFile` takes them from CLI flags (default 10/20).
   Changing redundancy is therefore unusable until the receiver can learn it from the record.

Not in this plan (recorded, deliberately deferred): shard distribution to third peers is inert in
production because the hosted-share quota is 0 and has no config key; the sender must stay online
for the whole transfer. That is a separate fix and does not block a 1:1 transfer.

## 2. Design

### 2.1 Vocabulary

- **Segment**: 64 MiB of plaintext (`DEFAULT_SEGMENT_SIZE`), independently encrypted.
- **Piece**: one shard of one segment. **Piece ID** = `shard_hash` = `BLAKE3(shard_data)`.
- **Manifest** (the "index", analogous to a `.torrent`): everything a receiver needs *before*
  fetching any data.

### 2.2 Manifest

```text
TransferManifest {
    version:      u8,                    // 1
    mid:          [u8; 32],              // must equal the record's mid_digest
    data_shards:  u8,   total_shards: u8,
    segment_size: u32,  total_bytes:  u64,
    protection:   Protection,            // None | Password { argon2: {m_kib,t,p}, salt:[u8;16], key_check:[u8;16] }
    segments:     Vec<SegmentEntry>,     // ordered by index
}
SegmentEntry { index: u32, plaintext_len: u32, plain_hash: [u8;32], piece_ids: Vec<[u8;32]> /* n */ }
```

Size: `32 + 4 + 4 + n*32` per segment ⇒ ≈ 0.7 KB at `n = 20`; 1600 segments ≈ 1.1 MB.

**Placement.** Appended to the signed DHT record value as a framed trailer
(`"MNFT" ‖ u8 version ‖ u32 LE length ‖ payload`) after the bincode `DhtRecord`.
Reasons: (a) `bincode::deserialize` ignores trailing bytes, so old readers still decode the record;
(b) the record and its manifest arrive in one signed PUT/GET, so there is no window in which one
exists without the other; (c) the GET-side validator (`decode_signed_dht_record`) stays untouched —
a separate manifest key would be *rejected* by it (fail-closed on non-`DhtRecord` values).
Budget: record ≈ 3–8 MB + manifest 1.1 MB must stay below `DHT_INNER_RECORD_MAX_BYTES` (16 MiB −
64 KiB); the existing 100 GiB budget test is extended to include the trailer.

**Trust.** The manifest is not an independent root of trust. The root remains the whole-file MID,
checked at the end. The manifest gives early, per-piece rejection and lets each segment be
verified independently (for resume). A lying manifest can waste bandwidth; it cannot make a wrong
file pass the final MID check.

### 2.3 Password as an encryption factor

```text
pw_key      = Argon2id(password, salt, m=64 MiB, t=3, p=1)          // same cost as directed sharing
K_seg       = HKDF-SHA256( ikm = K_enc, salt = pw_key,
                           info = "miasma-seg-key-v1" ‖ mid ‖ segment_index )
ciphertext  = AES-256-GCM(K_seg, nonce, segment_plaintext)
```

`K_enc` is still random per segment and Shamir-split across the shards exactly as today, so
everything that works on shards is unchanged. Without the password, holding the MID and all shards
yields nothing decryptable. `key_check` = first 16 bytes of `HKDF(pw_key, "miasma-pw-check-v1")`
in the manifest lets the receiver reject a wrong password **before downloading any data**.
It does not weaken anything: the AEAD tag on segment 0 is already an offline password oracle for
anyone holding the ciphertext, and Argon2id is what bounds that.

MID stays `BLAKE3(plaintext ‖ param_bytes)`. Note (existing property, unchanged): the MID is a
plaintext hash, so it is a confirmation oracle for a *guessed* plaintext. Not addressed here.

Passwords never appear in `Debug` output, logs, argv or the journal. CLI reads
`--password-file` or prompts without echo; the IPC request follows the existing `DirectedSend`
redaction pattern.

### 2.4 Redundancy

- `k` and `n` become publish parameters (CLI `--data-shards/--total-shards`, `--redundancy <preset>`).
- Receiver takes `(k, n)` from the record, not from flags. Flags remain as overrides for legacy
  records that have no manifest.
- Allow `n == k`: `rs_encode`/`rs_decode` gain a no-parity path (plain split, zero recovery
  shards). `reed-solomon-simd` cannot be asked for zero recovery shards, so this is a separate branch.
- Presets to evaluate (storage factor ⇒ shards a segment can lose): `10/10` 1.0× ⇒ 0,
  `10/11` 1.1× ⇒ 1, `10/12` 1.2× ⇒ 2, `10/15` 1.5× ⇒ 5, `10/20` 2.0× ⇒ 10 (today).
- **Reasoning to check, not assume:** in a 1:1 transfer there is a single holder, so parity only
  protects against corruption of the holder's own files; transport faults are handled by piece-ID
  verification plus re-fetch. This is why very low redundancy may be viable — the experiment in
  Phase 5 exists to confirm or refute it.
- `max_segment_size_for(k)` already clamps segment size for small `k`; verify it for every preset.

### 2.5 Resume (receiver)

Files: `<out>.part` and `<data_dir>/transfers/<mid-b58>.json`.

```text
Journal { mid, output_path, part_path, k, n, segment_count, total_bytes,
          next_segment, bytes_done, manifest_hash, protection_salt,
          state, started_at, updated_at, last_error }
```

- Segments are written **in order**, so the completed set is a prefix: `next_segment` + `bytes_done`.
- After each segment: `write_all` → `sync_data` → atomic journal replace (tmp + rename).
- On resume: validate the journal against the fetched manifest (`manifest_hash`, `mid`, `k/n`);
  truncate `.part` to `bytes_done`; **re-read the prefix**, rebuilding the BLAKE3 hasher and
  checking each segment against `plain_hash`; continue at the first bad or missing segment.
  (A BLAKE3 `Hasher` cannot be serialized; re-reading costs one sequential disk pass.)
- Completion: final MID check → `sync_all` → rename `.part` → output → remove journal.
- Failure policy: a bad piece ⇒ mark that holder/slot bad for this segment and try the next
  candidate; a segment that cannot reach `k` valid pieces ⇒ retry with backoff, then state
  `Paused` with `.part` and journal **kept**. Final MID mismatch ⇒ state `Failed`, `.part`
  removed (resume cannot fix it). `--restart` discards a paused transfer explicitly.

### 2.6 Resume and progress (sender)

`<data_dir>/transfers/publish-<mid-b58>.json` records, per completed segment: `plain_hash`,
piece IDs, store addresses and locations, plus `(file_len, mtime)` of the source and the protection
salt. Shares already in the local store stay valid (their addresses are content hashes), so a
restart skips completed segments after checking the addresses still exist. Re-hashing the source to
recompute the MID is skipped only if `(len, mtime)` match the journal.

### 2.7 Progress surface

One registry of transfer jobs inside the daemon; jobs run as background tasks, so a CLI
disconnect does not abort them (torrent-client behaviour).

```text
TransferStatus { id, kind: Send|Receive, phase: Preparing|Hashing|Verifying|Transferring|Finalizing,
                 state: Running|Paused|Complete|Failed, segments_done, segments_total,
                 bytes_done, bytes_total, rate_bps (EMA), eta_secs, elapsed_secs,
                 fetch_ms, decode_ms, write_ms,   // for the speed experiment
                 last_error, resumable }
```

IPC additions only (existing `GetToFile`/`PublishFile` keep their behaviour):
`TransferStart`, `TransferStatus`, `TransferList`, `TransferCancel`. New fields on existing
requests use `#[serde(default)]`. CLI: `network-get` polls and renders one updating line;
`network-publish` likewise; `miasma transfers` lists jobs. Desktop UI and FFI are out of scope
for this plan and get a follow-up entry.

## 3. Phases, acceptance criteria, tests

Every phase ends with: workspace builds, new tests green, existing tests green, commit, push,
CI checked before the next phase starts.

**Phase 1 — pure primitives (no network).**
1a `transfer::manifest`: types, trailer framing, builder, `manifest_hash`.
1b password protection in `dissolution::segment` (`*_with` variants; the old functions call them
with `None`, so behaviour is byte-identical when no password is used).
1c `n == k` in RS.
*Accept:* round-trip for every preset; wrong password fails and `key_check` catches it without
touching segment data; same password + different MID or segment index ⇒ different key; legacy
`dissolve_segment` output still decodes; manifest for 100 GiB / `n = 20` stays under the DHT budget
together with a worst-case record; trailer is ignored by the current `DhtRecord` decoder (test uses
today's decode path).

**Phase 2 — publish side.** `dissolve_and_publish_file_*` builds the manifest, applies protection,
appends the trailer; `DhtHandle::get_record_with_manifest`; `PublishFile` gains
`password`/`data_shards`/`total_shards`.
*Accept:* 2-node loopback publish → record carries the manifest; legacy get still works.

**Phase 3 — receive engine.** New module `transfer/receive.rs`; piece-ID verification; segment-level
retry with backoff; `.part`/journal/resume; progress; IPC + CLI (`--password-file`,
`--resume`/`--restart`). The engine is generic over a `PieceSource` trait so it is unit-tested
with a fault-injecting source (junk pieces, dead holders, a source that dies mid-transfer, a
corrupted `.part`), and it fetches the record and manifest **once** rather than per segment.
*Accept (loopback, 2 daemons):* wrong password rejected before data transfer; junk piece rejected
and the next candidate used; kill the receiver mid-transfer → resume completes with a byte-identical
file and does **not** re-fetch completed segments (asserted via a fetch counter); MID mismatch ⇒
`Failed` and no output file; progress fields monotonic and reach 100 %.

**Phase 4 — sender progress and resume.** *Accept:* stop the publisher mid-publish → restart
skips completed segments and produces a record whose manifest matches the file. *(Met; see §6.
Stopped by cancel, not by killing the process: a hard kill is covered only by the journal's
half-written-line handling in unit tests, not by an end-to-end test.)*

**Phase 5 — redundancy experiment.** `#[ignore]` harness printing, for each preset, on a
fixed-size buffer: stored bytes, dissolve MiB/s, recover MiB/s, and loss tolerance verified by
deleting `n−k` shards and by deleting `n−k+1` (must fail cleanly). Results are written into §6.
*Accept:* table committed with the machine and commit id it was measured on.

**Phase 6 — runbook and docs.** macOS build steps, the 1 GiB → 4 GiB → 20 GiB → 100 GiB ramp
(quota, `--data-dir` on the external SSD, expected disk per step), what to record at each step
(MB/s from `TransferStatus`, hash on both ends). Update `readme.md`, `docs/tasks/`, ADR for the
password/manifest design.

## 4. Test environment constraints (this machine, 2026-09-29)

C: is 237 GB total with ~5 GB free; a normal debug build of this workspace is 10–17 GB. Builds
here use `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0` and the `vcvars64` wrapper (Git's GNU
`link.exe` shadows MSVC's otherwise). **Measured:** with those two settings the whole
`miasma-core` test build is **0.93 GB** in `target/`, against 10-17 GB for a default debug build. A build failure with `os error 1455` / `LNK1102` /
`LNK1140` means the disk is full, not that the code is wrong. Tests that need real volume run on
the owner's Mac + external SSD, not here.

### Phase 2 — publish side (2026-09-29)

- `publish_file_inner` always emits a manifest (piece IDs + per-segment hashes) alongside the
  record; `dissolve_and_publish_file_protected` adds the password. New IPC `PublishFileProtected`
  (a separate variant so existing `PublishFile` callers are untouched); CLI `network-publish
  --password-file FILE | --password-stdin` (never argv). `DhtHandle::put_with_manifest` /
  `get_record_with_manifest`; a damaged trailer refuses the whole record instead of reading as
  "unprotected".
- **Measured** (unit test `hundred_gib_record_plus_manifest_fits_the_dht_value_cap`): for a 100 GiB
  file at `k=10, n=20`, worst-case record 6,912,051 B + manifest 1,100,868 B = **8,012,919 B**
  value (8,013,071 B signed envelope) against caps of 16,711,680 B and 16,777,216 B.
- **Ran, two real nodes on loopback:** the manifest read back from the *second* node matches every
  share the publisher stored (piece ID = shard hash, per slot); a pre-manifest decoder still reads
  the record; a protected publish is unreadable through the ordinary read path and, with the
  password, reassembles byte-identical from the stored shares; an empty password is refused.

### Phase 3 — receive engine (2026-09-29)

- `transfer::receive` (engine over a `PieceSource` trait), `progress`, `journal`, `jobs`
  (background jobs, one registry per data directory), `network` (real transport adapter,
  record + manifest fetched **once**). IPC `TransferStartReceive / TransferStatus /
  TransferList / TransferCancel`; CLI `network-get -o` now starts a job and draws a progress line,
  with `--password-file/--password-stdin/--restart/--no-wait`, plus `miasma transfers` and
  `miasma transfer-cancel`.
- **Ran, fault-injecting source (14 engine tests):** completes byte-for-byte with and without a
  password; wrong password refused with **zero** pieces fetched; junk pieces (self-consistent and
  inconsistent) rejected by ID and the next holder used; a segment with too few good pieces
  pauses with the partial file and journal kept; resume does **not** re-fetch segments already
  on disk; a byte flipped inside a partial segment is detected and only from that segment on is
  redone; a journal for a different manifest is ignored; `--restart` discards; cancel stops at a
  safe point and resumes; a publisher that lies about the MID (every piece and segment check
  passes) never gets an output file, part file or journal; a record with no manifest still
  transfers and resumes but refuses a password; empty file, exact multiples of the segment size,
  and `n == k` all work.
- **Ran, two real nodes over the network:** wrong password refused; cancel after segment 0
  (`Cancelled{next_segment: 1}`), then the second run reports `resumed_from_segment == 1` and the
  output is byte-identical. **Ran, two real daemons over IPC:** start/status/list/cancel, a failed
  job ends `Failed` (not `Running` forever), an unknown or finished id cannot be cancelled.
- **Ran:** the full `miasma-core` suite (lib, adversarial, integration, and the new files) and
  the CLI tests, all green.

### Phase 4 — sender progress and resume (2026-09-29)

- `transfer::publish` is the send engine (the old streaming publish moved into it; the
  blocking `dissolve_and_publish_file*` now delegate with no journal, so their behaviour is
  unchanged). With a journal directory it reports progress, honours cancel, and resumes.
  `transfer::publish_journal` is an **append-only** log — one line per finished segment, never a
  rewrite — that tolerates a half-written last line. IPC `TransferStartPublish`; `network-publish`
  now starts a background transfer, draws the same progress line (hashing, dissolve, store+push),
  and gains `--restart` / `--no-wait`.
- What a resume trusts: nothing unchecked. The source must have the same length and modification
  time; every finished segment is re-read and compared with its recorded hash; every one of its
  shares must still be in the local store; a wrong or missing password fails before any work.
  The first segment that fails a check, and everything after it, is done again. Locations of the
  publisher's own copies are rebuilt from the daemon's *current* addresses (they can change on
  restart); only pieces another peer accepted are journalled.
- **Ran, two real nodes:** cancel after segment 0 (`Cancelled{next_segment: 1}`); a wrong password
  on resume is refused; the resumed run reports `resumed_from_segment == 1`, does not redo segment 0
  (its shares are exactly the ones already stored, 6 in all afterwards), removes its journal, and
  the second node then receives the file byte-for-byte. A changed source file, and a deleted local
  share, each make the resume start over (`resumed_from_segment == 0`).
- **A correction to my own earlier tests.** The first version of these cancel tests stopped a
  transfer by polling from another task, which can lose a race with a fast segment; two of them
  passed while checking nothing (one did not assert the cancel outcome at all, so "the changed file
  is not resumed" held only because there was nothing to resume). The receive-side cancel/resume
  test committed in `e28a26b` had the same race and passed by luck. All of them now use
  `TransferProgress::stop_after_segments`, which cancels deterministically, and every one asserts
  its cancel outcome.
- **Wasted upload stopped.** A peer that answers "quota exceeded" is no longer offered the rest of
  the shares (`PushState`, 10-minute memory). Measured on a 6-share publish with a connected peer
  that has no hosted quota: **1 push attempted, 1 refused** (before: every share was pushed and
  refused after the whole payload had been sent).

### Phase 5 — redundancy experiment (2026-09-29)

`miasma redundancy-bench [--size-mib N] [--preset k/n ...] [--store-dir DIR]` runs the real dissolve
and recover code in memory for each setting and prints a table. **Two columns are exact on any
machine and build, and were measured here** (64 MiB per setting, 6.4 MiB shards at `k=10`):

| k/n | stored per byte, nominal / measured | lost pieces tolerated | `n-k` lost recovers, `n-k+1` fails cleanly |
|---|---|---|---|
| 10/10 | 1.00x / 1.000x | 0 | verified |
| 10/11 | 1.10x / 1.100x | 1 | verified |
| 10/12 | 1.20x / 1.200x | 2 | verified |
| 10/15 | 1.50x / 1.500x | 5 | verified |
| 10/20 | 2.00x / 2.000x | 10 | verified |

Per-share overhead (headers, hashes, key share) does not show at this shard size. **Throughput was
not measured meaningfully:** this machine's build is unoptimized (about 3 MiB/s, of which AES-GCM
alone took 17-24 s per 64 MiB), so those figures say nothing about a release build. Reed-Solomon
time does grow with the number of parity pieces (55 ms at 10/10 which is a plain split, against
4.3 s at 10/20, same unoptimized build), which is the only trend worth carrying over. Run it in
release on the sending machine — with `--store-dir` on the external SSD to include local disk and
at-rest encryption — before choosing a default.

### Phase 6 — runbook and a real-binary check (2026-09-29)

- `docs/tasks/macos-to-windows-large-transfer-runbook.md` (Japanese): disk arithmetic per size and
  `k/n`, build and self-check on each machine, the redundancy measurement, connecting the two, the
  256 MiB -> 4 GiB -> 20 GiB -> 100 GiB ramp with an interruption drill, a results table, known
  limits, troubleshooting. `scripts/transfer-e2e.ps1` (ran) and `scripts/transfer-e2e.sh` (macOS
  default bash 3.2; **syntax-checked only, not run on a Mac**).
- **Ran, the real `miasma.exe` (debug build), two daemons on loopback, 40 MB at `k=2, n=3` (three
  segments), password-protected — all 20 checks passed in 212 s:** publish prints a MID; a wrong and a
  missing password are each refused with a clear message and leave no output or `.part` file; the
  receiver's daemon was **killed (`Stop-Process -Force`) after the first segment**, restarted,
  `miasma transfers` then showed the transfer paused and resumable with one segment safe on disk,
  the same `network-get` finished it and the SHA256 matched, and the `.part` file was gone; the
  same was then done to the **sender's** daemon mid-publish (restart, `transfers` shows the send
  paused, the same `network-publish` completes) and the second node received that file with a
  matching SHA256.
- **Found by that run and fixed:** `miasma transfers` did not show a send's file name, so nothing
  could tell which line was which. It now heads each entry `receive <mid> -> <path>` or
  `send <path> (<mid>)` and prints the command that resumes it. The first run of the script sat in
  its wait loop for exactly this reason.
- What the CLI prints (debug build, so the rate says nothing about a release build):
  `[####################----] 80.0%  seg 2/3  32.0 MiB / 40.0 MiB  963.4 KiB/s  ETA 00:00:09  (store+push 72% dissolve 28%)`
  for a send and `(fetch 71% decode 28% write 1%)` for a receive, then a final line with elapsed
  time and the average.
- **A correction to something I told the owner earlier:** `miasma config` takes flags, so the quota is
  set with `miasma config --key storage.quota_mb --value <MiB>`, not the positional form I wrote.

### Finding: one fetch cost seconds, and would cost hours at 100 GiB (2026-09-29)

Measured with `measure_single_piece_fetch_latency_on_loopback` (two nodes, loopback, **debug
build**), a single piece fetch took **15.6-22.7 s regardless of size** — 17.8-22.7 s for a 32 KiB
shard, 15.6-18.3 s for an 8 MiB shard — while the record lookup took 20-26 ms. A cost that ignores
the size is not bandwidth. Cause (read in `store.rs` and the serving handler in `node.rs`): serving
a request called `search_by_mid_prefix`, which decrypts **every** stored share to read its header,
then decrypted candidates again, and each `get` rewrote the index. Cost per request grew with the
number of shares in the store.

Fix: each index entry now records its piece key `(mid_prefix, segment, slot)`; the handler uses
`find_piece` (index lookup, no decryption, parsed index cached against the file's stamp, newest
generation wins) and `get_untouched` (no index rewrite). Stores written before this get their keys
filled in once, lazily. **After**, same probe: **26-61 ms** for the 32 KiB shard and **4.9-5.6 s**
for the 8 MiB shard. The remaining ~5 s is one 8 MiB share through unoptimized decrypt + hash +
bincode in a debug build (~1.5 MB/s); a release build was **not** measured. Side effect, measured:
`integration_test` went from 212 s to 75 s and `transfer_publish_test` from 124 s to 78 s.

Still open in the same file, **not** changed (the owner wants to measure speed on a real run first):
`put` re-parses and rewrites the whole JSON index per share, so publishing is quadratic in the
share count. **Measured** (`measure_put_cost_growth`, debug build, 64-byte shares so the index
dominates): average cost of one `put` was 26 ms with 250 shares stored, 46 ms at 1,000, 74 ms at
2,000 and 123 ms at 4,000, while the index file grew 0.06 -> 0.98 MB — cost per put rising in
proportion to the store size. At 32,000 shares (a 100 GiB publish at `k=10, n=20`) the index is
about 8 MB and a put would cost roughly 8x the 4,000-share figure in the same build. A release
build is much faster and was **not** measured; if it still matters on a real run, the fix is an
append-only index log (the send journal above is the same shape), not a bigger cache.

### Incident: the Windows Search index filled the disk (2026-09-29, 20:1x)

While a clippy build ran, free space on C: fell from 3.8 GB to under 0.6 GB in a few minutes
(about 17 MB/s) although this worktree's `target/` was only ~1.1 GB. `searchindexer` was the
writer. Its database, `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db`,
is **18.45 GB** (measured). The indexer was stopped through an elevated, user-approved
`Stop-Service WSearch` (start type left `Automatic`); free space went from ~0.6 GB back to
4.68 GB and stayed flat. `target/` is marked not-content-indexed (`attrib +I`) here.
**Not done, needs the owner's decision:** exclude the repo folders (and every `target`) from
Indexing Options, and whether to rebuild the 18 GB index. `Start-Service WSearch` restores it.

## 5. Not measured yet

- Throughput at any size on HEAD (owner will run it; the status fields in §2.7 exist so it can
  be read off rather than timed by hand).
- Whether macOS builds and runs `miasma-cli` at all (CI builds only core/ffi/wasm on macOS).
- Whether a ~9 MB DHT record actually replicates over Kademlia in practice; only its serialized
  size is unit-tested today.
- Whether corporate LAN/VPN passes mDNS/QUIC between the two machines.

## 6. Results log

Each entry says what was actually run. Machine: Windows 11, slim debug profile (§4).

### Phase 1 — primitives (2026-09-29)

- Added `transfer::protection` (Argon2id + HKDF, `key_check`, bounds on untrusted Argon2
  parameters), `transfer::manifest` (`TransferManifest`, `SegmentEntry`, record trailer
  framing), `dissolve_segment_with` / `retrieve_segment_with` (the old functions now call
  them with `None`), and `n == k` (no parity) in `rs_encode`/`rs_decode` and in the
  publish-preflight estimator.
- **Ran:** `cargo test -p miasma-core --lib` — 516 passed, 0 failed, 1 ignored (the ignored one
  is a measurement of the default Argon2id cost; a debug build is not representative, so it is
  not reported here). 34 of those are new.
- **Measured:** the manifest for 100 GiB at `k=10, n=20` (1600 segments x 20 pieces) encodes
  to **1,100,859 bytes**, matching the 1.1 MB estimate in §2.2.
- Behavioural facts now pinned by tests: a protected segment cannot be read with the MID and
  every shard but no password (AEAD failure); it cannot be replayed as another segment index;
  loss tolerance is exactly `n - k` for `k=10` and `n` in {10, 11, 12, 15, 20}, and one more
  loss fails as `InsufficientShares`; a damaged or spliced trailer is an error, never a
  silent downgrade to "unprotected"; a pre-manifest decoder still reads a record that carries a
  trailer.
- **clippy** (`cargo clippy -p miasma-core --all-targets -- -D warnings`): no findings in any file this
  phase touched. It reports 8 findings in files this work does not touch — `daemon/mod.rs`
  (4x `explicit_auto_deref` on `&**secret`), `network/node.rs` (`question_mark` at ~1623,
  `clone_on_copy` on `IpPrefix` at ~5405), `transport/obfuscated.rs`, `transport/reality.rs`.
  They are not from this branch and were left alone: other sessions are editing `daemon/mod.rs`
  and `node.rs`, and CI runs clippy advisory-only. Worth a separate cleanup commit.
- **Not yet run:** integration tests (`cargo test -p miasma-core --tests`), the wasm crate (it has its own copy of the RS code and still rejects `n == k`; deliberately
  left alone — the browser build is not part of this transfer path).

## 7. Decisions and open questions

- D1 Manifest lives in the record trailer, not a second DHT key. (Reason in §2.2.)
- D2 Password binds encryption only; it does not gate who may *fetch* shards. Anyone with the MID can
  still download ciphertext. Recipient-key (ECDH) binding is **not** part of this plan; the owner
  asked for MID + password.
- D3 Sender resume needs the password again on restart; it is never stored.
- Open: default preset for `network-publish` once Phase 5 has data (kept at 10/20 until then).
- Open: whether shard distribution to third peers (hosted quota) is wanted for this use case.
- **Requested 2026-09-29, deferred ("later is fine"): Japanese text.** Scope not yet stated;
  assumed to cover the user-facing strings this work adds — CLI progress line and errors
  (`wrong password`, `paused, run again to resume`, ...), desktop locale entries, and the runbook.
  The strings are kept in one place per surface so this is a translation pass, not a refactor.
  To confirm with the owner which surfaces are wanted before doing it.

## 7b. Follow-ups this work found but did not do

Each has a reason it was left; none blocks a first cross-machine transfer.

1. **Hosted-share quota has no configuration key** (`with_hosted_quota_mb` is called only from
   tests), so peers refuse every pushed share and the sender is the sole holder. A config key, a
   default, and a test that runs with the *default* config are needed before the readme's
   "resists content seizure via single-node compromise" line can be relied on. The readme now
   carries a caveat pointing here.
2. **The local share store's index is rewritten in full on every `put`** — cost per put grew from
   26 ms (250 shares) to 123 ms (4,000) in a debug build. Fix: an append-only index log (the send
   journal is the same shape). Left until a real run shows it matters.
3. **`ShareFetchRequest` carries no expected piece ID**, so if the same content was published twice
   (fresh key each time) the holder serves the newest generation and a receiver holding the older
   manifest would reject it with no way to ask for the other. `find_piece` picks the newest;
   republishing is the workaround. Fixing it means extending the wire request.
4. **Recipient-key binding.** The owner asked for MID + password; the password binds only the
   *encryption*, so anyone with the MID can still download ciphertext. `directed`'s ECDH binding is
   not in the streaming path.
5. **Desktop UI and FFI** still use `PublishFile` / `GetToFile` and show no progress or resume. The
   IPC they need already exists (`TransferStart*`, `TransferStatus`, `TransferList`,
   `TransferCancel`).
6. **Sequential fetch.** The receive engine still fetches one piece at a time and does not overlap
   decode with the network. Deliberately not optimised: the owner will measure first, and the
   per-phase timings are in `TransferStatus` for that.
7. **CI does not run on work branches** (`push` is `main`/`develop` only; PRs into `main` are
   covered). Everything here was run locally (`cargo test -p miasma-core -p miasma-cli`, fmt,
   clippy); the first CI run happens when a PR is opened.
8. **macOS.** `miasma-cli` has never been built or run on macOS in CI. `scripts/transfer-e2e.sh`
   is written for the macOS default bash (3.2) and was syntax-checked here but **not run on a Mac**.
9. **Japanese text** (requested, deferred): CLI messages and the desktop locale for the strings this
   work adds. The macOS-to-Windows runbook is written in Japanese.

## 8. Working rules for this branch

- Other sessions are editing IPC/daemon/CLI/desktop concurrently. New logic goes in
  `crates/miasma-core/src/transfer/`; edits to existing shared files are limited to adding enum
  variants and one dispatch call so merges stay mechanical.
- Stage files explicitly (never `git add -A`); commit small; push after each phase; read CI.
- No commit trailer attributing Claude (owner's standing rule).

## 9. GUI, Japanese and theme (decided with the owner 2026-09-30)

Owner decisions (answers to the three questions asked after §7b):

1. CI: add a macOS job that builds `miasma-cli` + `miasma-desktop` and runs `transfer-e2e.sh`. Done
   in `.github/workflows/ci.yml` (job `macos-cli-transfer`, commit de83d98). It only runs on a PR into
   `main`; **the PR itself could not be opened from this session (the tool permission was denied), so
   the owner opens it** or allows `gh pr create`.
2. GUI on **both** sides (macOS sender and Windows receiver). The desktop app is the same egui binary,
   so the transfer screen must work on macOS too. Corollary: `configure_fonts` hard-codes
   `C:\Windows\Fonts`, so on macOS every Japanese glyph is a tofu box — a font discovery per OS is part
   of this work, not an extra.
3. Theme: **whole app**, not just the new screen.

Requested language and look:

- Japanese, and the font is **Meiryo** (owner's preference). Meiryo ships with Windows and cannot be
  redistributed, so it is read from the system, never bundled. macOS has no Meiryo by default; the
  chain falls back to Hiragino Sans, then the egui default. Proportional chain becomes
  Meiryo → Yu Gothic → Microsoft YaHei → MS Gothic (Windows) / Hiragino Sans → PingFang (macOS).
  Segoe UI is no longer first (Meiryo has its own Latin glyphs). Monospace: Consolas → MS Gothic /
  Menlo → Hiragino.
- Look: **uTorrent's layout with the m365-copilot-companion-mcp palette** (`ui/Theme.cs` there).
  Layout: transfer list on top (name, direction, progress bar, speed, ETA, state chip); detail pane
  below (segment strip showing which segments are done / in flight / pending, fetch/decode/write
  split, resume position, last error, Pause/Resume/Cancel). Palette: warm neutrals, accent orange
  **only** on the single primary action, status as a small chip and as text colour — **never a coloured
  left rail or a full-card fill** (Theme.cs says the owner has disliked that repeatedly). Only the colour
  values are used; no code is copied.

Token table (light / dark), from Theme.cs:

| token | light | dark | use |
|---|---|---|---|
| bg | #F7F6F2 | #111111 | app background |
| surface | #FFFFFF | #181818 | cards, panels |
| surface_subtle | #F4F4F2 | #202020 | inputs, selected row base |
| selected | #E7E5DE | #2C2C2C | selected row |
| border | #D8D6CF | #2E2E2E | 1 px borders |
| border_strong | #D4D4D0 | #3A3A3A | hover / active border |
| text | #18181B | #F4F4F5 | body |
| muted | #5F5F66 | #A1A1AA | secondary text |
| faint | #6B6B73 | #71717A | meta text |
| accent | #C4400D | #F97316 | the primary action only |
| accent_fill | #C4400D | #C2410C | fill carrying white text |
| success | #15803D | #22C55E | done |
| warning | #B45309 | #F59E0B | paused / needs attention |
| danger | #B91C1C | #EF4444 | error |
| info | #2563EB | #60A5FA | running |

Stages (each ends with a build, `cargo test -p miasma-desktop`, and a look at the running window):

- **A. Theme + fonts** (`crates/miasma-desktop`): a `theme` module with the tokens, light/dark/system
  selectable in Settings and persisted with the other prefs; replace the `const` colours and the
  ~20 inline `Color32::from_rgb` in `app.rs`; per-OS font discovery with the chains above; log which
  fonts loaded.
- **B. Transfers screen**: worker commands over the existing IPC (`TransferStartReceive`,
  `TransferStartPublish`, `TransferList`, `TransferCancel`), polled about once a second while a
  transfer is active; password entry never logged (Debug redaction like `DirectedSend`); k/n picker
  with the measured redundancy table; resume shown as the default action for paused jobs.
- **C. Japanese for CLI messages**: language from `MIASMA_LANG`, else the OS locale; English stays
  the default; one message table.
- **D. Japanese for the new desktop strings** (En/Ja/ZhCn entries for everything in B). CLAUDE.md:
  "a string table is not finished localization" — the check is the running window with Meiryo, not
  the table.

Blocker found before starting: C: had 1.4 GB free (target 3.5 GB, Windows Search running again), too
little to build the desktop. Cleanup was handed to a sonnet subagent under the runbook rules (never
Windows logs, never sibling worktrees).
