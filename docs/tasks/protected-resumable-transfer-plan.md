# Protected, resumable large-file transfer — plan and running log

Branch: `work/resumable-protected-transfer` (based on `work/large-file-release-gate`).
Started: 2026-09-29. Status: **Phase 0 (plan) — nothing below is implemented yet.**

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
2. **One bad fetch kills the transfer.** `retrieval/streaming.rs` does `source.fetch(addr).await?`
   inside the per-segment loop, so the first transport error aborts the whole stream.
3. **Pieces are not individually identified by the receiver.** Each `MiasmaShare` carries its own
   `shard_hash`, but the receiver has no list of *expected* piece IDs, so a holder can serve any
   self-consistent junk and it is only caught after RS decode + AEAD fail.
4. **The content is bound to nobody.** The MID is the capability: anyone who learns it and can
   reach a holder can fetch and decrypt. The recipient-bound path (`directed`) encrypts the whole
   plaintext in one AEAD call from a `&[u8]`, so it cannot carry 100 GB.
5. **Redundancy is fixed by default at 2.0×** (`k=10, n=20`). For a 100 GiB file that is
   205,051 MiB (200.24 GiB) of owned-share quota; the sender needs ≈300 GiB free.
   `rs_encode` rejects `n <= k`, so redundancy cannot go below `n = k + 1`.
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

**Phase 3 — receive engine.** New module `transfer/receive.rs`; piece-ID verification; per-piece
error tolerance; retries; `.part`/journal/resume; progress; IPC + CLI (`--password-file`,
`--resume`/`--restart`).
*Accept (loopback, 2 daemons):* wrong password rejected before data transfer; junk piece rejected
and the next candidate used; kill the receiver mid-transfer → resume completes with a byte-identical
file and does **not** re-fetch completed segments (asserted via a fetch counter); MID mismatch ⇒
`Failed` and no output file; progress fields monotonic and reach 100 %.

**Phase 4 — sender progress and resume.** *Accept:* kill the publisher mid-publish → restart
skips completed segments and produces a record whose manifest matches the file.

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
`link.exe` shadows MSVC's otherwise). A build failure with `os error 1455` / `LNK1102` /
`LNK1140` means the disk is full, not that the code is wrong. Tests that need real volume run on
the owner's Mac + external SSD, not here.

## 5. Not measured yet

- Throughput at any size on HEAD (owner will run it; the status fields in §2.7 exist so it can
  be read off rather than timed by hand).
- Whether macOS builds and runs `miasma-cli` at all (CI builds only core/ffi/wasm on macOS).
- Whether a ~9 MB DHT record actually replicates over Kademlia in practice; only its serialized
  size is unit-tested today.
- Whether corporate LAN/VPN passes mDNS/QUIC between the two machines.

## 6. Results log

(empty — filled as phases complete; each entry carries the commit id and what was actually run.)

## 7. Decisions and open questions

- D1 Manifest lives in the record trailer, not a second DHT key. (Reason in §2.2.)
- D2 Password binds encryption only; it does not gate who may *fetch* shards. Anyone with the MID can
  still download ciphertext. Recipient-key (ECDH) binding is **not** part of this plan; the owner
  asked for MID + password.
- D3 Sender resume needs the password again on restart; it is never stored.
- Open: default preset for `network-publish` once Phase 5 has data (kept at 10/20 until then).
- Open: whether shard distribution to third peers (hosted quota) is wanted for this use case.

## 8. Working rules for this branch

- Other sessions are editing IPC/daemon/CLI/desktop concurrently. New logic goes in
  `crates/miasma-core/src/transfer/`; edits to existing shared files are limited to adding enum
  variants and one dispatch call so merges stay mechanical.
- Stage files explicitly (never `git add -A`); commit small; push after each phase; read CI.
- No commit trailer attributing Claude (owner's standing rule).
