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
    version:      u8,                    // 2 (see Security fixes 1)
    mid:          [u8; 32],              // must equal the record's mid_digest
    data_shards:  u8,   total_shards: u8,
    segment_size: u32,  total_bytes:  u64,
    protection:   Protection,            // None | Password { argon2: {m_kib,t,p}, salt:[u8;16], key_check:[u8;16] }
    segments:     Vec<SegmentEntry>,     // ordered by index
}
SegmentEntry { index: u32, plaintext_len: u32, plain_hash: [u8;32], piece_ids: Vec<[u8;32]> /* n; v2: whole-share commitment, not BLAKE3(shard_data) */ }
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

### Stage A — theme and fonts, `miasma-desktop` (2026-09-30)

- `theme.rs` (tokens from §9, `ThemeMode` System/Light/Dark in `desktop-prefs.toml`, missing field = System,
  selector in Settings), `fonts.rs` (per-OS discovery, Meiryo first, never bundled), all `const` colours and
  inline literals in `app.rs` replaced; status is chip + text colour, no full-card fills, accent only on primary
  buttons. New `--data-dir <path>` launch flag so a throwaway instance never touches real data.
- **Ran:** `cargo test -p miasma-desktop` — 45 passed, 0 failed (theme: token table, WCAG contrast text/muted >= 4.5
  on bg/surface/surface_subtle/selected in both modes, white on accent_fill >= 4.5; fonts: tempdir discovery; prefs
  from an old file load as System).
- **Saw in the running window:** the log shows Meiryo (`C:\WINDOWS\Fonts\meiryo.ttc`) first in the proportional chain.
  A GL window cannot be captured with `PrintWindow` from a private desktop (white frame), so the app itself renders
  screenshots: cargo feature `ui-tour` (developer only, `src/app/tour.rs`, env `MIASMA_UI_TOUR=<dir>`) walked
  theme x En/Ja x all 7 tabs plus 3 connection states (40 frames) with no tofu and no clipped buttons. Real
  mouse messages on the Settings selector wrote `locale = "ja"`, `theme = "dark"` and `theme = "system"` to the prefs
  file; System resolved to light, matching the OS.
- Not verified: macOS (no Mac here; the discovery tables are data + a tempdir test), Meiryo vs. the fallback chain
  when Meiryo is absent, the `Import` tab (needs a magnet/torrent launch argument).

### Stage C — Japanese CLI messages (2026-09-30)

- All text of the transfer commands (progress line, `transfers`, publish/receive/cancel messages,
  the two password errors, the redundancy-bench table and hints) is in one table,
  `crates/miasma-cli/src/i18n.rs` (`Msg`, each variant has `en` and `ja`). English is the default
  and byte-identical to before (a golden test pins every message).
- Language: `--lang en|ja`, else env `MIASMA_LANG` (`ja`/`ja_JP`/`ja-JP`, any case; another value
  means English), else the OS UI language (Windows `GetUserDefaultUILanguage`, declared directly
  against kernel32, no new dependency), else `LC_ALL`/`LC_MESSAGES`/`LANG`, else English.
- **Consequence for scripts:** on a Japanese-UI machine the CLI now answers in Japanese by default,
  so anything that greps the English wording must pin it. `scripts/transfer-e2e.{sh,ps1}` set
  `MIASMA_LANG=en` (they grep `wrong password`, `password`, `Paused`, `resumable`, `^send`,
  `seg N/M`). `smoke-loopback.*` and `validate-bridge-connectivity.ps1` match only `miasma:...`
  and `MID: ...`, which Japanese keeps.
- Only the two password errors coming from the daemon are translated (matched on `miasma-core`'s
  message text; a test ties the needles to `MiasmaError`). Other daemon errors and tracing logs stay
  English. The `Error:` prefix that anyhow prints for a failing command is not translated.
- Console: Rust's std writes to a real console as UTF-16, and to a pipe or file as UTF-8, so no
  `SetConsoleOutputCP` call is made (it would change the user's console after the program exits).
  A reader that decodes a pipe as cp932 (Windows PowerShell 5.1 with the default code page) will
  garble Japanese output; that is the reader's decoding, not the bytes.

### Stage B + D — Transfers tab, `miasma-desktop` (2026-09-30)

- **Built.** `WorkerCmd::{TransferStartReceive, TransferStartPublish, TransferResumePublish, TransferPoll,
  TransferCancel}` over the existing IPC (the same requests the CLI issues; passwords and paths are
  redacted in `Debug`, passwords are `Zeroizing` in the worker and zeroized in the form after submit;
  `TransferResumePublish` reads `k/n` from the send journal so a resume passes the parameters the
  transfer began with). `src/transfers.rs` is the screen: list (running first; arrow, name, bar,
  percent, bytes, rate, ETA, state chip), detail pane (segment strip with a marker at the resume
  position, MID with copy, phase, timing split, pieces, retries, last error), buttons *Stop (keep
  progress)* / *Resume* (asks for the password again, then re-issues the start request) / *Start over*
  (two-step, `restart: true`), and a Receive form and a Send form (one primary button each). Send has
  the k/n table with the measured storage factor and tolerated losses and the CLI default (10/20)
  preselected; Easy shows Fastest / Balanced / Safest = 10/10, 10/12, 10/20. The honest hint under
  the Send form says the receiver must reach the sender and the sender must stay online. Polling is
  once a second only while the tab is visible or a job runs (one poll to learn the state after
  connecting); a poll that finds the daemon down says so on the screen and asks the worker to
  reconnect. Strings: `TransferStrings` in `locale.rs`, En/Ja/ZhCn, tested field by field.
- **Ran.** `cargo test -p miasma-desktop`: **76 passed** (was 45): byte/rate/ETA formatting incl. zero,
  NaN, `u64::MAX`; percent with unknown total; strip bucketing (1600 segments -> 400 cells of 4, partial
  bucket in flight, resume marker only when consistent, `u32::MAX`); chip mapping; sort order; preset
  table equals the section 6 phase 5 table; Easy mapping; resume re-issues the same request; poll
  gating; every locale string non-empty and placeholders kept; Debug redaction of the new commands.
  A test caught a real `u32` overflow in the strip for a huge `segments_total`. `cargo test -p
  miasma-core --lib transfer::` still passes (74). `cargo fmt --all -- --check` is clean for the crate
  (CI's lint job had failed on formatting only). clippy: only the two known `worker.rs` dead-code warnings.
- **Saw (ui-tour, mock data, both modes x dark/light x En/Ja, 56 frames of the Transfers tab):** Meiryo
  everywhere, no tofu, no clipped text or buttons, chips and the strip legible, calm layout in the
  m365 palette; the 100 GiB job at 37 % with a 1600-segment strip and a resume marker, paused with the
  password prompt, failed with the error text, stopped, complete, empty list. Fixed after looking: form
  labels were centred against tall rows (now top-aligned fixed column), a selected row's bar track
  vanished in dark mode, the *stopped* chip was too dim, the list showed only 4 rows, redundancy rows
  were too tall.
- **Ran for real, through the desktop window** (real `miasma-desktop.exe` on the private desktop,
  real mouse and key messages via bgdesk, `--data-dir` throwaway, node A = CLI daemon, node B = the
  desktop's own auto-launched daemon; 40 MB, `k=2 n=3`, three segments, password-protected; the
  window's own frames were saved with the new `MIASMA_UI_SNAP` mode of the `ui-tour` feature):
  typed MID, path and password into the Receive form and pressed *Start receiving*; the list showed
  `gui_recv.bin` running at 39.9 % / 15.9 MiB of 40.0 MiB, 837 KiB/s, ETA, one green cell and one blue
  cell in the strip; **killed B's daemon after segment 1**; the window said the background service is
  not running and dimmed the last state, the worker relaunched the daemon, and the row became *Paused*
  at 39.9 % with the resume marker; *Resume*, the password, *Resume* again: it ran on, finished, and
  **the SHA256 of the output equals the input** (`246F3340...986608`), the `.part` file gone. Done twice
  (the second time with the final build; times 08:00-08:06 JST, about 42 s of transfer after the resume).
  Also from the Send form: 20 MiB with a password and 10/12 went hashing -> segment -> *Complete*, MID
  shown and copyable. The received file of the send was **not** verified (see below).
- **Found through the GUI and fixed** (each would have passed every unit test):
  1. `worker.rs`: `get_status` returns the *rewritten* "Not connected..." text and the `GetStatus`
     handler tested it with `is_daemon_down`, which only knew the raw wording. A dead daemon was never
     noticed: no relaunch, the header stayed "Connected". Fixed at the source (one constant, matched
     by `is_daemon_down`, with a round-trip test).
  2. `miasma-core/src/transfer/jobs.rs`: `start_receive` never set the status `name` (documented as
     the output path), so a live receive showed an empty path in `miasma transfers` and a blank row in
     the window until a journal existed. One line; confirmed in the running window.
  3. Layout and wording found by looking: see the ui-tour paragraph.
- **Not verified.** macOS (no Mac). A real ~100 GB transfer (the 100 GiB job in the tour is mock data).
  The Browse buttons (native file dialogs cannot be driven on the private desktop; paths were typed).
  That a receiver can fetch what the *GUI's Send form* published (node A never reached node B in the
  minute I tried). **Loopback connectivity is flaky in this build and it matters to whoever tests:**
  between the 30 s bootstrap redials two loopback nodes were connected only for about ten seconds
  (`Connected peers` 1 then 0), and a receive started while disconnected failed after 6 lookup attempts
  with `no record found` (seen in the window as a *Failed* row with that text). The runs above started
  the transfer while the peer was up (a script waited for `Connected peers >= 1` and then clicked).
  Once a transfer is fetching pieces the link held; after a daemon restart the same window applies.
  Not investigated in this stage; root-caused and fixed afterwards, see "Connection stability" below. Also seen: `elapsed_secs` keeps growing for a failed
  job (the daemon reports time since the job began, not since it stopped).

### Connection stability (2026-09-30)

- **Symptom** (from the real GUI run above): two loopback nodes, receiver dials sender, were connected
  ~10 s per 30 s redial cycle; a receive started while disconnected failed with `no record found`
  after 6 lookups; once pieces were flowing the link held.
- **Measured, before** (`target\debug\miasma.exe` at `8e87222`, two CLI daemons, `MIASMA_LOG=miasma_core=debug,libp2p_swarm=debug`,
  `Connected peers` sampled every ~2.8 s for 200 s, three topologies): the link came up at 23:44:47.3 and was
  closed **by both sides at the same instant, 23:45:31.85, `Connection closed with error KeepAliveTimeout`**
  (44.5 s after it came up = the last request, an AutoNAT probe at 15 s, plus the 30 s idle timeout).
  The redials that followed: 23:45:47, 23:46:17, 23:46:31, 23:47:17 all failed at once with
  `os error 10048 (AddrInUse)` on a dial logged as `port_use: Reuse`; the next success was at 23:48:01, **149.5 s after the close**.
  Both-bootstrap and receiver-only-bootstrap behaved the same (25.4 % and 25.7 % of samples connected; a third
  run 70 %, with one 3 s reconnect at t=59 s that dropped again at t=90 s). A receive started at t=102 s
  (no peer): `network-get` exited 1 after **30.3 s**, the six-lookup budget (1+2+4+8+15 s of backoff), with the
  link still down.
- **Root cause, three parts** (each with the evidence above):
  1. `build_swarm` set `idle_connection_timeout` to 30 s and nothing on a quiet connection asks to keep it
     (libp2p 0.57's ping and Kademlia handlers do not), so every idle link was closed ~30-45 s after its last
     request.
  2. The redial could not succeed: libp2p dials with `PortUse::Reuse` (bind to the listen port). On Windows
     the closed 4-tuple stays in TIME_WAIT for 120 s and a `connect` from the same local port fails with
     10048. Reproduced without libp2p (a 15-line socket test: second dial from the same port -> 10048,
     `netstat` shows `TIME_WAIT`, a fresh port connects). The same holds after a daemon is killed and restarted.
     Even without that, the periodic redial ran only every 30 s and only when *no* peer was connected.
  3. `fetch_record_and_manifest` never looked at the link: with an empty routing table a lookup answers "not
     found" at once, so six attempts were spent inside the ~30 s the link was down.
- **Fix** (`crates/miasma-core`, `network/node.rs`, `transfer/network.rs`):
  1. `IDLE_CONNECTION_TIMEOUT` = 1 h. Dead peers are still detected: ping (30 s, 20 s reply timeout) closes a
     connection whose peer stops answering, and its packets keep NAT mappings warm.
  2. Outbound TCP dials use a fresh local port (`NewPortOnDial`, a transport wrapper; hole-punch dials with
     `role == Listener` keep `Reuse`, the one case that needs it).
  3. A lost bootstrap peer is redialed by a 1 s tick with its own backoff (1, 2, 4 ... 30 s, never abandoned,
     independent of how many *other* peers are connected). The generic `ReconnectionScheduler` was not reused: its
     factor is cast `as u32`, which wraps to 0 from the 33rd consecutive failure (a dial every tick for a
     permanently unreachable peer; only its 10-failure circuit breaker hides it). Left alone, noted.
  4. `DhtHandle::ensure_connected(timeout)`: if no peer is connected, dial the bootstrap peers now and wait
     (bounded, re-dialing every 0.5 s); no bootstrap configured = nothing to wait for. Every record-lookup
     attempt calls it first (60 s wait). If the bootstrap stays unreachable, one last lookup runs (the record may
     be local) and the error reads `not connected to any peer, bootstrap <addr>/p2p/<id> unreachable (waited 60 s)`
     instead of `no record found`.
- **Tests** (`tests/integration_test.rs`, `network::node::connection_lifetime_tests`):
  `idle_link_to_bootstrap_peer_outlives_the_old_idle_timeout` (**fails before**: "dropped 44.6 s after it came up";
  passes after, 50 s idle), `record_lookup_waits_for_a_sender_that_becomes_reachable` (path comes up 50 s in;
  **fails before**: `no record found` at 43 s; passes after, found at 50.5 s), `unreachable_bootstrap_is_reported...`,
  and three unit tests (backoff schedule incl. no wrap at 32+ failures, backoff reset, idle timeout floor).
  `cargo test -p miasma-core --lib` 572 passed / 2 ignored (569 + 3); `--tests`: adversarial 186, integration
  67 passed / 7 ignored (64 + 3), transfer_ipc 1, transfer_publish 8 / 1 ignored; fmt clean; no new clippy warning.
- **Measured, after** (same harness, `target\debug\miasma.exe` at the fix): both topologies **71 of 71
  samples connected (100 %)** over 200 s, one connection, no `KeepAliveTimeout`. Receive started at t=102 s:
  **exit 0 in 1.1 s** (before: failed at 30.3 s). Sender daemon killed and restarted 2 s later: receiver sees it
  again after **1.1 s** (before: 5.9 s; that case is a reset, not a TIME_WAIT close, so it improves less).
  Seconds connected per 30 s window: **~7.7 (25.7 %) before, 30 (100 %) after**. `scripts/transfer-e2e.ps1` with the
  fix and the script changes below: `=== PASS ===` four times in a row (200, 200, 183, 182 s; debug build).
- **Scripts.** `scripts/transfer-e2e.{sh,ps1}` now wait for `Connected peers >= 1` on B before the first transfer,
  after B is restarted, and before B receives from a restarted A (what the runbook tells the user to do).
  Step 4 (kill the sender mid-publish) was flaky on a fast macOS runner: the 40 MB send can complete between the
  poll that sees segment 1 and the kill, leaving no journal, so `transfers` shows nothing paused and the
  re-run is a fresh publish; the CI log shows the first segment seen at 23:43:13.22 and the kill 30 ms later, on
  a machine that receives 40 MB in ~1.3 s (step 3). That reading is inferred from the timestamps, not from the
  daemon logs (the script prints none). The step now retries with a file twice as large (up to 4 tries) until
  the kill provably landed mid-send. The same race exists in step 3 in principle (not changed: it passed).
- **Not verified.** A real NAT between two networks (macOS sender, Windows receiver); the macOS behaviour of
  `PortUse::Reuse` after a close (the CI flake is consistent with the Windows mechanism but macOS was not
  reproduced here); a peer that keeps a connection open without answering ping is closed by ping (30 s + 20 s),
  not by the idle timeout, and that path is not exercised by a test. No inbound connection limit exists; with a
  1 h idle timeout a public node holds idle inbound connections for an hour (`libp2p::connection_limits` is the
  follow-up if that matters).

### Security fixes 1 (2026-09-30, branch `security/fix-transfer-layer`)

Three findings from the adversarial review of the transfer layer, fixed at the root.

**1. Unbounded record counts (C-02, medium).** A manifest-less DHT record (any peer that knows a MID can
sign one) made the receiver compute `segment_count = max(segment_index) + 1` and allocate a table of
that size: `u32::MAX - 1` asked for about 103 GB and aborted the daemon, `u32::MAX` overflowed, tens of
millions burned hundreds of MB.
- Fix: `DhtRecord::validate()` (`network/types.rs`) runs before any count is used. Checked
  `segment_index` below `MAX_SEGMENTS = 65_536` (64 MiB segments x 65 536 = 4 TiB), `0 < k <= n`,
  shard index `< n`, locations bounded by `min(2^20, MAX_SEGMENTS * n)` (one DHT value is 16 MiB and the
  smallest location ~22 bytes, so 2^20 is above any genuine record), address count/length and peer-id
  length bounded. Rejects, never clamps; error is `InvalidManifest("invalid record: ...")`.
- Called at every boundary: `decode_signed_dht_record` and `decode_signed_record_and_manifest` in
  `network/node.rs` (a bad record is refused as `InvalidInnerRecord`), `run_receive`, both
  `retrieve_from_network*` segment-count sites in `network/coordinator.rs` (the same `max() + 1` pattern),
  and `encode_record_value` (never publish what receivers refuse).
- Other unbounded numbers found and bounded: `TransferManifest.segment_size` (now `<= 64 MiB`,
  it sized the per-segment decode buffer) and segment count (`<= MAX_SEGMENTS`); on the manifest-less
  path a piece's `original_len` (a holder could claim 4 GiB, which `retrieve_segment_with` turned into a
  buffer) is refused above 64 MiB.
- Not changed: `retrieval/coordinator.rs`, `streaming.rs` take their counts from callers that now validate.

**2. Piece commitment did not cover the key material (C-07, low-medium).** `PieceId = BLAKE3(shard_data)`,
so a holder could flip `key_share`, `nonce` or `original_len`; the piece still passed verification, the
receiver stopped at `k` accepted pieces, decryption failed and no spare holder was tried: one hostile
holder per segment killed the transfer.
- (a) Fix: `MiasmaShare::piece_commitment(mid)` = domain-separated BLAKE3
  (`derive_key("miasma-piece-commitment-v2")`) over `version | MID | segment | slot | original_len |
  len+shard_data | len+key_share | nonce`. The manifest lists it per slot (`SegmentEntry::from_dissolved`
  now takes the MID) and the receiver checks it on arrival (`ShareVerification::verify_piece`).
- **Manifest version 1 -> 2, no compatibility.** Beta software: a v1 manifest (trailer or struct) is
  refused with `InvalidManifest("manifest version 1 is no longer supported ... publish the file again")`;
  only one format is kept. The publish-journal version is bumped too (its saved entries hold v1 IDs), so an
  old journal restarts the publish. Records published by an older build must be published again.
- (b) Resilience: if the first `k` verified pieces still fail to decode (only possible without a manifest,
  or from a lying publisher) the receiver fetches up to 4 spare pieces and retries with one piece swapped
  at a time, at most 16 decode attempts per segment; the piece swapped out of the combination that decodes
  is recorded as suspect (segment, slot, holder) and is not reused in the run. Otherwise the first error
  is returned. Two simultaneous bad pieces are not searched for beyond that cap. The unprotected
  `dissolve_segment_with` / `retrieve_segment_with` path is unchanged.

**3. Argon2 ceiling (low).** The untrusted-manifest ceiling was 256 MiB / t=10 / p=4. `create` produces
64 MiB / t=3 / p=1 and nothing in the CLI or desktop picks another cost, so the ceiling is now
128 MiB / t=6 / p=2, refused before any KDF work.

**Tests.** New `crates/miasma-core/tests/adversarial_transfer_test.rs` (14 tests): tampered key_share /
nonce (protected) / original_len are refused and a spare holder completes the transfer, commitment
covers every field, legacy-record recovery from spares and its bound, hostile segment indexes
(`u32::MAX - 1`, `u32::MAX`, 10 000 000, `MAX_SEGMENTS`) rejected in milliseconds, malformed records,
v1 manifest refused with the clear message, segment_size bound, unchecked `original_len`, Argon2 cap
before KDF work. Plus one unit test in `transfer/protection.rs`. Passwords are generated at run time.
Still open from the same review (not transfer layer or design work): DHT records are not publisher-
authenticated (a MID holder can sign a record), the protection mode is not part of the MID, unauthenticated
daemon IPC, hosted-share tuple replacement.

### Security fixes 2 (2026-09-30, branch `security/fix-transfer-layer`)

Share hosting and the onion replay cache.

**1. Hosted-share replacement by any peer (C-03, high).** The `(mid_prefix, segment, slot)` tuple is public,
so `put_hosted` deleting "the older generation" let any admitted peer replace another publisher's share with
self-consistent garbage. Fix (`store.rs`, `network/node.rs`): a hosted entry records the authenticated
principal (the libp2p `PeerId` of the sender) in the store index (`hosted_principal`, `#[serde(default)]`, so
an old `store_index.json` loads with principal = unknown). `LocalShareStore::put_hosted_by(share, principal)`
replaces an existing entry of the same tuple only for the same principal; anyone else, and any unknown
owner, is refused with `HostedRefusal::NotOwner`, which reaches the pusher as
`StoreRejectReason::NotOwner`. Pushing identical bytes is acknowledged without touching the entry, so it can
neither take over nor evict. `put_hosted(share)` stays as the no-principal entry point (unknown owner; it
cannot replace or be replaced). The pusher's `PushState` remembers a `NotOwner` answer per (peer, piece) and
stops offering that piece to that peer, without blacklisting the peer. Legacy hosted entries (unknown owner)
cannot be repaired by a new push; the old copy has to be removed first.

**2. Hosted quota monopoly (C-08, medium).** Under the global cap, one principal may hold at most
`max(25% of the hosted quota, min(quota, 16 MiB))` (`HOSTED_PRINCIPAL_SHARE_PERCENT`,
`HOSTED_PRINCIPAL_FLOOR_BYTES`, `hosted_principal_budget_bytes()`); unknown/legacy entries share one bucket.
Over budget gives `HostedRefusal::PrincipalBudgetExceeded` / `StoreRejectReason::PrincipalBudgetExceeded`
(a standing refusal in `PushState`). Default hosted quota is still 0. No new config key. Note that the floor
means a quota of 16 MiB or less gives a single principal the whole pool; the fairness only bites above that.

**3. Onion replay cache poisoning (C-10, medium).** `onion_is_replay` is now read-only and runs before
decryption; the fingerprint is recorded (`onion_record_authenticated`) only after the AEAD peel succeeds, at
both the relay and the delivery site. Failed authentications are counted per sender
(64 per 10 s, at most 1024 tracked senders); past that, that sender's layers are dropped before any
decryption. Invalid ciphertext can no longer mutate the replay state.

**Tests.** New `crates/miasma-core/tests/adversarial_storage_test.rs` (9 tests): other principal cannot
replace or evict, unknown principal neither replaces nor is replaced, same principal can republish,
identical bytes do not transfer ownership, per-principal budget stops one peer while another still stores,
unknown owners share a bucket, small quota stays usable, default quota refuses, a pre-principal
`store_index.json` loads. In `network/node.rs`: a valid layer is processed once, 5000 unique invalid layers
follow, and the replay is still rejected; a single sender's failed decryptions are capped.

### Security fixes 3 (2026-09-30, branch `security/fix-transfer-layer`)

The local control channel (C-05 / F3, S-02). Before this, any process that could open a loopback TCP
connection was served: a raw client got `Status` and then `Wipe` (master key erased) with no secret, and
`PublishFile` / `TransferStartReceive` let it choose file paths. The HTTP bridge treated a missing `Origin`
as "not a browser, allow".

- **Token.** At each start the daemon draws a 256-bit token from `OsRng` and writes it to
  `<data_dir>/daemon.token` before it writes `daemon.port`. A stale file is unlinked and replaced; the file is
  deleted at clean shutdown (and by `cleanup_stale_state`). Unix: created with mode 0600 (no
  widen-then-narrow). Windows: created empty, then `icacls` drops inheritance and grants the current user
  only, then the secret is written; if `icacls` fails the daemon warns and keeps going with the data
  directory's own ACL (not verified by the daemon). New module `daemon/control_auth.rs`.
- **IPC.** The first frame of every connection is a `ControlAuth { token }` frame (max 4 KiB, 5 s timeout),
  compared in constant time. Anything else, or a wrong token, gets an `unauthorized` error and a close before
  any request is deserialised. Failures are delayed 100 ms doubling to 3 s, reset by a success.
  `daemon_request` reads the token file itself, so the CLI, desktop worker, FFI and tests needed no change
  beyond `Wipe`.
- **Wipe.** `Wipe` now only returns `WipeChallenge { nonce }` (single use, 30 s, replaced by a newer one);
  `WipeConfirm { nonce }` wipes. `daemon_wipe()` performs both; CLI, desktop, FFI and the integration test
  use it.
- **HTTP bridge.** Everything except `GET /api/ping` needs `Authorization: Bearer <token>` regardless of
  `Origin`; `POST /api/wipe` is two-step (`{"confirm": <challenge>}`). `web/js/bridge.js` sent the token
  from `localStorage['miasma_control_token']`, pasted by hand (**superseded**: `miasma web` prints a launch
  link, see "Web client" below). Mobile bridge clients do not send it yet (see P1-9 in
  `remaining-tasks-prioritized.md`).
- **S-02.** `ControlRequest::zeroize` now wipes the passwords of `PublishFileProtected`,
  `TransferStartReceive`, `TransferStartPublish` (and the `WipeConfirm` nonce). `daemon_request` zeroizes the
  request after writing it.
- **Path policy.** `TransferStartReceive` output paths must be absolute and free of `..`
  (`PathPolicyError`, returned as `output path rejected: ...`). CLI and desktop resolve paths lexically first
  (`absolutize_lexical`). This is not a sandbox.
- **Tests.** `crates/miasma-core/tests/adversarial_ipc_test.rs` (11 tests) plus unit tests in
  `control_auth.rs`.
- **Limits.** Any process running as the same user can read the token. Not done: OS-authenticated IPC
  (named pipe / Unix socket with peer credentials), a token for the mobile bridge clients.

### Web client (2026-09-30, branch `feature/web-transfers`)

Three changes to the browser client (`web/`, a PWA), asked for together. Commits: `8634e68` (token flow),
`55ea70f` (design), and the Transfers screen (this section is committed with it).

**1. Token flow — the client was broken by the IPC hardening above.** Every `/api` call except `/api/ping`
needs `Authorization: Bearer <daemon.token>`, and a page cannot read that file, so the client only worked
after a hand-pasted token. Now:

- `miasma web [--open] [--web-url URL]` (crates/miasma-cli, `web_link.rs`) reads `daemon.http` and
  `daemon.token` and prints `http://127.0.0.1:<bridge port>/#token=<token>` on stdout (the link alone;
  the explanation goes to stderr, EN/JA). The token is in the URL *fragment*, which a browser never sends
  to a server, so it is not in the bridge's request path, logs or `Referer`. `--open` hands the link to the
  OS (Windows `rundll32 url.dll,FileProtocolHandler` with `CREATE_NO_WINDOW`, so no console flashes and
  `&` in a `--web-url` link is not parsed by `cmd`; macOS `open`; Linux `xdg-open`).
- The page reads the fragment once (`bridge.js`, at module load), keeps the token in `sessionStorage` (dies
  with the tab, not shared with other tabs, not on disk; an old `localStorage` copy is deleted) and strips it
  from the address bar with `history.replaceState`. A `bridge=` address in the fragment is honoured only if it
  is loopback, and `miasma web --web-url` only accepts a loopback page: the token is never put in a link to
  another computer.
- Auth is unchanged: the bridge does not serve the token to a caller without it, the Origin gate is
  unchanged, wipe stays two-step. A 401 shows a banner (EN/JA/ZH): "run `miasma web` and open the link it
  prints" (`missing` = page not opened from a link; `rejected` = the token changed because the daemon
  restarted). Publish/retrieve no longer fall back silently to local-only shares when the token is refused.

Topologies (all found in the code, none assumed):

| Topology | Works? | How |
|---|---|---|
| **Daemon serves the client itself** (new; `daemon/web_assets.rs` compiles `web/` into the daemon, public, no token; `GET /` is the app) | yes, the default | `miasma web`; one origin, one port, no CORS; the service worker is same-origin |
| **Your own static server on localhost** (`python -m http.server` in `web/`, any port) | yes | `miasma web --web-url http://localhost:8080` puts `&bridge=http://127.0.0.1:<port>` in the fragment; the page is cross-origin to the bridge, allowed because the Origin gate accepts any localhost port and the CORS preflight allows `Authorization` (CSP `connect-src` now allows loopback ports) |
| **Hosted static site** (GitHub Pages, any https origin) | **no** | the bridge refuses non-localhost origins (403), so the page falls back to local-only WASM mode. That is deliberate: loosening the Origin gate would let any web page drive the daemon. Not changed |
| Android/iOS WebView bridge (`window.miasma`) | unchanged, not exercised | has no transfer calls; the Transfers screen says it needs the daemon |

Desktop "Open web view" action: **skipped** (not trivial: a button in `app.rs`, three locale tables and the
completeness tests for a launcher that `miasma web --open` already is).

**2. Design.** Same tokens as the desktop (§9), light / dark / system in Settings (remembered in
`localStorage`, guarded; `js/theme.js` is a classic script in `<head>` so there is no flash; System follows
`prefers-color-scheme`); dark redefined with `:root:not([data-theme="light"])` under the media query and
again for `[data-theme="dark"]`. Font stack `Meiryo, "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Yu Gothic",
"Microsoft YaHei", "PingFang SC", system-ui, sans-serif`, nothing bundled or linked. Accent orange only on
the primary action (Dissolve / Retrieve / Send / Start receiving, and a modal's confirm); status is a chip and
coloured text; no coloured rails, no status-filled cards (the old `scope-notice` left rail and the filled
security notice are gone); the particle animation and glows are removed. `--faint` and `--danger` are lighter
in dark than the desktop's #71717A / #EF4444 because those are 3.9:1 and 4.3:1 as text; the desktop keeps its
values. `web/tests/contrast.test.mjs` (`node --test web/tests/*.test.mjs`, also in the Web/WASM CI job)
pins the palette to the §9 table and checks 4.5:1 for every text/background pair in both themes.

**3. Transfers screen.** Authenticated bridge endpoints (`http_bridge.rs`, same Bearer token, same
`process_request` handlers as the CLI/desktop, same output-path policy):

| Endpoint | |
|---|---|
| `GET /api/transfers` | `TransferList`, each entry with an `id` (MID for a receive, `send:<path>` for a send) |
| `GET /api/transfers/<id>` | `TransferStatus` (id percent-encoded) |
| `POST /api/transfers/receive` | `{mid, output_path, password?, restart?}`; `output_path` is on the **daemon's** computer; absolute, no `..` |
| `POST /api/transfers/<id>/cancel` | stop at the next safe point, keeping the partial file |

Errors map to 400 (bad body, MID or path), 404 (no such transfer), 409 (nothing running to stop). The
password is redacted in `Debug`, moved into the request that zeroizes it, the body buffer is overwritten when
the bridge is its only owner (best effort: hyper may hold other copies), a serde error never quotes the body,
and it is not in any response or log line (asserted with a capture of the daemon's own `trace` output). GET
transfers are a `ReadApi` for the rate limiter (120/min): the screen polls once a second, so two tabs fit.

The screen (`js/transfers.js`, pure helpers in `js/format.js` with `web/tests/format.test.mjs`) mirrors the
desktop tab: rows with direction, name, progress bar, bytes, speed, ETA and a state chip; a detail pane with
MID and copy, the segment strip (done / in progress striped / waiting, a tick where this session resumed, cells
bucketed above 400 segments), fetch/decode/write split, pieces received/rejected, retries and the last error;
Stop; Resume (the same receive again, asking for the password again) and Start over (confirmed); a Receive
form. It does **not** start large publishes (a browser has no file path to give the daemon) and says: use the
desktop app or the CLI to send large files. Polling is once a second while the screen is open and the tab
visible, every 3 s / 5 s only while a job runs elsewhere / in a hidden tab, and not at all otherwise. Sizes go
through BigInt (u64 up to 2^53 exact in JSON), a zero total or rate never divides. Strings are in `i18n.js`
(EN/JA/ZH), Japanese wording reused from the desktop's `TransferStrings`. A Windows path is drawn in the
monospace font because Meiryo shows a backslash as a yen sign.

**What was checked, and in what.** A real headless Edge (the private `bgedge`, Edge 154 on Windows 11; nothing
on the owner's screen), two throwaway nodes on loopback (debug build), a 60 MB password-protected file
(k=2, n=3, 4 segments):

- token flow without a paste: launch link -> connected chip, URL back to `/`, no banner; a tab opened without
  the link -> "not opened with its link" banner; a wrong token -> "no longer accepts" banner; the
  `--web-url` topology from `http://localhost:<port>` -> connected (CORS + `Authorization` preflight);
- Transfers: a real running receive, progress advancing (0 -> 53.3 % -> 79.9 %), speed 0.4-0.7 MiB/s, ETA;
  Stop (state `Cancelled`, 3/4 segments, 47.9 MiB kept in `.part`); Resume with a wrong password ->
  `Failed`, "Wrong password."; Resume with the right one -> `Complete`, `resumed_from_segment = 3`, 22 s;
  **SHA256 of the result equals the source** (`B30DA73D...5DF3E`);
- themes: all six combinations of OS scheme x chosen mode resolve as intended (computed `--bg`, body colour,
  `color-scheme`, `<meta theme-color>`); light, dark, Japanese and English screenshots looked at, at 1280 px
  and at 390 px (the phone width is an emulated viewport in desktop Edge, not a phone). On all eight screens at
  390, 320 and 1280 px no element sticks out of the viewport and `scrollWidth == clientWidth` (measured over
  CDP with Playwright against the same headless Edge, with a transfer listed);
- last, on the *shipped* form of the page (the assets compiled into the daemon; SHA256 of the served files equals
  the working tree): a 34 MB protected receive through the form, Complete, **SHA256 equal**;
- fonts: computed `font-family` is the chain above; the font that actually drew Japanese text was Meiryo,
  and with Meiryo removed from the chain Yu Gothic, then Microsoft YaHei (CDP `getPlatformFontsForNode`).

Tests: `miasma-core` lib 586 passed / 2 ignored (582 + 3 in `web_assets` + 1 in `rate_limit`),
`web_bridge_test` 8 (new: client served without a token, no traversal, foreign origin refused, token never
offered, every transfers endpoint 401 without it, bad requests refused and nothing started, a protected
transfer received over HTTP with wrong / missing / right password and no password in any response or log line,
a running receive stopped), `adversarial_test` 186, `integration_test` 71 / 7 ignored,
`adversarial_transfer_test` 13, `adversarial_storage_test` 9, `adversarial_ipc_test` 11, `transfer_ipc_test`
1, `transfer_publish_test` 8 / 1 ignored, `miasma-cli` 35 + 5 (`web_command`: link on stdout, fragment only,
JA, `--web-url`, refuses a remote page, no daemon), `miasma-desktop` 76, `miasma-wasm` 30 + 4 and its
`wasm32-unknown-unknown` build, JS `node --test` 25 (palette and contrast 9, formatters 16), `cargo fmt --all
-- --check` clean, and no clippy warning in any file this work touched (the ones clippy reports are old).

**Not verified.** Safari and iOS (nothing of the client was run there); Firefox; a real phone, touch, and the Hiragino / PingFang fallbacks on macOS (only
proven that the chain falls through on Windows); System mode against a real OS dark-mode toggle (media query
emulated); **the service worker after an upgrade**: the cache name is bumped to `miasma-web-v5` and the worker
skips `/api/` and other origins, but no browser that held `v4` was tried, and a tab that is already open
keeps running the old script until it is reloaded; a link opened with `miasma web --open` on macOS and
Linux (Windows only reasoned about; the daemon-served page was checked by opening the link with `bgedge`);
the Android/iOS WebView bridges; receives of many GiB (the screen was exercised on 60 MB; the strip and the
formatters have unit tests for 100 000 segments and 2^64-1 bytes). Known limits: anyone who has the link
controls the node until the daemon restarts (it is printed, and with `--open` it is briefly on the
`rundll32` command line, readable by the same user who can read `daemon.token` anyway); the token sits in
`sessionStorage` where any script on the bridge's origin can read it (same trust as the page itself).

### Direct receive over WSS (2026-09-30, branch `feature/direct-wss-receive`)

**Problem.** A receiver on a managed network (GlobalProtect) blocks QUIC and raw TCP, so the DHT lookup for the
record and manifest fails before a single share is fetched; and the sender has no open port. The WebSocket
share server the daemon already runs was proven reachable through an outbound `cloudflared tunnel` from such a
machine (`scripts/wss-probe-windows.ps1`, 2026-03-31), but it carried shares only.

**What was built.**

- **Protocol** (`transport/websocket.rs`). One versioned request/response pair per message:
  `[WS_WIRE_VERSION = 1] ++ bincode(WsRequest::{Share(ShareFetchRequest), Record{mid_digest}})` and
  `WsResponse::{Share, Record{value: Option<Vec<u8>>}}`. `Record` returns exactly the value
  `transfer::decode_record_value` reads (record + manifest trailer), `None` for an unknown MID (no detail).
  The old unversioned single-request format is **replaced** (beta; both ends must be the same build family);
  the legacy `WssPayloadTransport` (used by the daemon's own fallback chain, Shadowsocks and Tor) speaks the new
  format through the same `wss_request_response`, and its tests pass unchanged. A connection carries up to
  512 requests one after another; the server then closes it and the client dials again.
- **Sender side.** The daemon already starts a plain-WS server on 127.0.0.1 (no TLS: the tunnel terminates it).
  New: `miasma daemon --wss-port N` / config key `transport.wss_port` (fixed port; default stays a free port),
  the daemon prints the exact command (`cloudflared tunnel --url http://127.0.0.1:<port>`) at start, and the
  server answers `Record` from the daemon's own DHT record store (`DhtHandle::local_record_value`: local store
  only, signature and key checked, no network query). `miasma tunnel` runs an *already installed* `cloudflared`
  (found on PATH; `CREATE_NO_WINDOW` on Windows), reads the printed `https://*.trycloudflare.com` from its
  stderr and prints `wss://...` (stdout) for the receiver. It never downloads or installs anything; if the
  program is missing it prints the install hint and stops.
- **Receiver** (`transfer/direct.rs`, `transport/ws_direct.rs`). `network-get <MID> -o FILE --via URL
  [--via URL2] [--ca-cert FILE]`. The daemon reads the record and manifest from the first endpoint that has
  them, then asks the endpoint for every piece by `(MID, segment, slot)` and feeds the **unchanged** receive
  engine through the `PieceSource` trait: pieces are verified against the manifest commitments as they arrive,
  the journal, resume, spare-piece retry and progress are the production ones. No DHT lookup, no libp2p peer,
  no bootstrap is needed. A wrong password is refused before any piece is fetched, as before.
- **Connection reuse.** One small pool of open connections per endpoint (a share is up to 8 MiB), so the TCP +
  TLS + upgrade cost is paid once, not per piece; a connection the server closed is replaced transparently
  once before an error is reported.
- **TLS trust.** `wss://` is verified by the operating system's own verifier (`rustls-platform-verifier`
  0.7, already in `Cargo.lock` through quinn, now a direct dependency of `miasma-core`; CryptoAPI on Windows)
  plus the optional `--ca-cert` PEM added as an extra root (sent to the daemon as text, so the daemon never
  opens a path a client names). There is **no** switch to turn verification off in this path. (First tried:
  loading the OS roots into a rustls store with `rustls-native-certs`. A real run through a Cloudflare quick
  tunnel failed with `UnknownIssuer` on this machine: Windows keeps its public roots out of the enumerable
  root store until a chain needs them, and distributes a corporate inspection root by policy; only the OS
  verifier sees both. Replaced. Android has no JVM handle in this library and uses the bundled Mozilla roots
  plus the extra CA.) A corporate TLS-inspection CA is normally already in the OS store;
  otherwise pass it with `--ca-cert`. A refused certificate fails at once (no retries) with a message naming
  both fixes. Whoever does terminate the TLS (Cloudflare, an inspecting proxy) sees AES-GCM ciphertext,
  the MID and request metadata only; piece commitments and the whole-file MID check are unchanged.
- **Surfaces.** IPC `TransferStartReceive` gains `via: Vec<String>` and `via_ca_pem: Option<String>` (both
  `serde(default)`: older clients parse and behave as before); `POST /api/transfers/receive` accepts them
  (a bad list is a 400); the desktop Transfers receive form has a "Via URL" field in Technical mode only (EN/JA/ZH;
  Easy mode shows nothing new; Resume in the same session goes back to the same endpoint); the web receive
  form has the same field. CLI text is in `i18n.rs` (EN/JA); no existing English string changed.

**Hostile-reviewer pass (own change).**

- *Record oracle / amplifier.* A `Record` request is a few dozen bytes and can be answered with up to
  `WS_RECORD_MAX_BYTES` (16 MiB - 64 KiB, the DHT's own publish bound); a share request with up to 8 MiB.
  The MID is the capability (same as the DHT): without it every answer is the same tiny `None`; with it, the
  cost is bandwidth, bounded per connection (512 requests) and overall (64 connections, over the cap the
  connection is closed at once, nothing is queued). No per-IP limit is possible behind a tunnel (every
  connection comes from 127.0.0.1); a leaked MID + URL is a bandwidth cost, not a data leak beyond the
  ciphertext the DHT would hand out anyway.
- *A pre-existing amplifier fixed on the way.* The WS server found a share with `search_by_mid_prefix` + `get`,
  which decrypts **every share in the store** to read its header on **each request** (the libp2p path was
  fixed for this, see the finding above; the WS path was not). It now uses `find_piece` (index) + one
  decryption. Measured on the sender's store in a debug build: 8 MiB share fetch went from ~19 s to ~5 s
  with 6 shares stored, and no longer grows with the store.
- *Attacker-controlled sizes.* The server's WebSocket frame and message limits are the request size (1 KiB),
  so an oversized frame is refused on its header before any of it is buffered (tungstenite's default is 16 / 64
  MiB); the client's are 17 MiB. bincode runs with a byte limit and `reject_trailing_bytes`, so a declared
  length cannot size an allocation (regression test: a `Vec<u8>` claiming `u64::MAX` bytes). The HTTP upgrade
  is bounded by tungstenite's 64 KiB header check and by our timeout; TLS handshake, upgrade and every idle wait
  are time-limited; ping/pong frames do not keep a connection alive for ever.
- *No path to control.* The server is built from a share store and a `RecordProvider` and nothing else: no
  IPC port, no token, no daemon handle. Anything that is not a well-formed binary request (text such as a JSON
  control request, garbage, wrong version, trailing bytes, unknown variant) ends the connection with no reply
  and no echo of the input. Errors the client shows never contain server-supplied text.
- *Passwords.* Never on this wire: the manifest carries only the Argon2 parameters and verifier as before; the
  IPC `Debug` for the new fields prints counts only.
- *Client side.* `--via` URLs are `ws://` / `wss://` only, at most 4, no credentials in the URL (refused and
  not echoed), length-bounded; a hostile endpoint can send at most 17 MiB per message, and everything it says
  goes through the same record validation and piece verification as a DHT answer. The daemon dials whatever
  URL a *token-holding* control client gives it, which is no new power (that client can already publish and
  fetch through the daemon).
- Tests for these are in `transport/websocket.rs::protocol_tests` and `tests/direct_wss_receive_test.rs`.

**Measured (this machine, debug build, loopback; a debug build's crypto is ~20x slower than release).**

- Whole receive, 16.8 MB, 2 segments, k=2 n=3, sender and receiver in one process over `ws://127.0.0.1`:
  15.3 s = 1.1 MB/s. The time is the sender's store read + decrypt (3.0 s per 8 MiB share in this debug
  build) and per-byte serde of `Vec<u8>` in an unoptimised build, not the socket. Empty request/response on
  a pooled connection: 0.8 ms. A release build was not measured (no room for a second target directory).
- The wire alone (an 8 MiB answer, no store behind it): 1.9 s pooled vs 2.05 s with a new connection each time
  in the debug build, so reuse saved about 0.16 s per piece there and the difference is mostly noise next to
  the serde cost. Reuse is kept because over a tunnel it also saves a TLS handshake and an upgrade round trip
  per piece (each an RTT to Cloudflare); that part was not isolated.
- **Through a real Cloudflare quick tunnel** (`miasma tunnel` -> cloudflared 2026 build from Program Files,
  `wss://<random-words>.trycloudflare.com`, sender and receiver both on this Windows machine, debug build,
  24 MiB password-protected file, 2 segments): `network-get --via` completed in 40.9 s, 814.7 KiB/s average
  this session (fetch 20.3 s, decode 8.8 s, write 0.5 s), **SHA256 equal**. Most of that is the debug build's
  crypto on both ends; the tunnel itself was not the limit. The first attempt of the same run failed with
  `UnknownIssuer` (above) and is what led to the platform verifier.

**Checked with the real binary.** `scripts/transfer-e2e.ps1` with the new step 5 (a third node with no bootstrap, `Connected peers: 0`,
receives with `--via ws://127.0.0.1:<port>`; wrong/missing password refused, no output left):
`=== PASS ===` on the first complete run (debug build, 40 MB, k=2 n=3), no flake in step [4] that time.
Also found by running the real binary: the debug `miasma.exe` died with a stack overflow on **every command,
even `--version`**, once the new options were added (the 4 `web_command` tests failed with it). Windows gives
the main thread 1 MiB and a debug build's `clap` parse plus `main` needs just over that; `crates/miasma-cli/build.rs`
now reserves 8 MiB (`/STACK`) for the binary on MSVC targets. Measured with `editbin`: 1.125 MiB was enough
for the commands tried, so the margin before was a few KiB. Unit tests could not have caught this (they run
on 2 MiB threads).

**Tests.** Green on the final code: `miasma-core` lib 597 passed / 2 ignored (586 + 11: 8 protocol and hardening
tests in `transport/websocket.rs`, 3 in `transport/ws_direct.rs`); the new `direct_wss_receive_test` 10 passed / 1
ignored (the measurement above); `web_bridge_test` 9 (8 + one for `via`); `adversarial_storage_test` 9;
`adversarial_ipc_test` 11; `transfer_ipc_test` 1; `node --test web/tests/*.test.mjs` 25; `cargo fmt --all --
--check` clean. Written and compiled, but **not run to completion on the final commit**: `miasma-cli` (7 new unit
tests: the flags, the URL scan, the PATH lookup; its 42 unit tests passed before the stack fix, the 5 `web_command`
tests failed then with the stack overflow above and were not re-run after it) and `miasma-desktop` (1 new test).
**Never run in this session**: `adversarial_test` (186), `integration_test` (71 / 7 ignored, the one holding the
old WSS fallback tests), `adversarial_transfer_test` (13), `transfer_publish_test` (8 / 1), `miasma-wasm`, and
`cargo clippy --workspace --all-targets`. Reason: C: went from 2.7 GB to under 100 MB free in minutes for reasons
outside this work, the build directory of this worktree was emptied while builds were running (`error writing
dependencies ... os error 3`), and a rebuild needs about 4 GB. They need one run on a machine with room before
merge; nothing in the diff is known to break them, but that is not the same as having run them.

**Not verified.** GlobalProtect with real corporate TLS inspection and the owner's PC (the Cloudflare run above was on this
machine, which is itself managed, but that does not prove the owner's GlobalProtect path or its inspection
root); a Mac sender (`miasma daemon` + `cloudflared`, no macOS build was run); a release-build throughput
figure; concurrent pieces (the engine fetches one piece at a time, so a high-latency tunnel is latency-bound:
about 1 RTT + size/bandwidth per piece); a second full e2e run; the desktop and web
forms were compiled and unit-tested (Debug redaction, resume goes back to its endpoint) but not driven in a
window or browser. Known limits: the sender's DHT record store is in memory, so after a sender daemon restart
its older records are gone for `--via` exactly as for the DHT (the e2e step 5 uses the record published after
the restart); a `miasma tunnel` process that is force-killed leaves `cloudflared` running (Ctrl-C stops it; a
Windows job object would fix that, not done); `--via` is not remembered across a desktop restart (the daemon
journal has no field for it, so re-issue the same command to resume); no HTTP proxy support in the direct
client (the daemon's SOCKS5/HTTP-CONNECT proxy settings are not applied to `--via`).

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

1. **Hosted-share quota has no configuration key** — **DONE 2026-09-30 (key added; default follows main: 1024 MiB).**
   `storage.hosted_quota_mb` (`StorageConfig`, `#[serde(default = ...)]` so old `config.toml` files still
   load with the default) is read/written by `miasma config --key ...`, reaches the store through
   `LocalShareStore::open_configured` at daemon start, and is printed by `miasma status` when the
   daemon is not running. **The default is `DEFAULT_HOSTED_QUOTA_MB` = 1024 (main's "enable hosted share quota by default", merged into this branch's earlier opt-in-0 wiring)**; 0 opts out. Accepting other
   people's shares still costs disk up to that cap (storage-exhaustion bound), which the readme caveat notes. Tests:
   `zero_hosted_quota_node_refuses_pushed_shares` (`hosted_quota_mb = 0`: push attempted and refused, nothing
   hosted) and `default_config_accepts_remote_distribution` (default config accepts) and `node_with_hosted_quota_key_holds_shares_and_serves_after_publisher_leaves` (B has the
   key in `config.toml`, A pushes, A shuts down, C retrieves from B; k=1 because A places one share
   per peer and B is the only host). **Still not designed:** eviction of hosted shares when the quota
   is full (a full quota just refuses), and per-peer limits (one publisher can fill the whole hosted
   quota). Not verified across real machines. The running daemon's status has no quota field, so it is
   not shown there.
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
4. Test scope (2026-09-30): the owner has no drive with >= 100 GiB free on the Windows receiver and
   judges a 256 MB test enough to prove a split transfer is received. The cross-machine ramp is now
   256 MiB -> 1 GiB -> 4 GiB; the 20/100 GiB steps and their disk arithmetic are kept in the runbook's
   appendix A ("if more disk becomes available"). 100 GiB behaviour therefore stays **unmeasured**.

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
