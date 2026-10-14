# ADR-013: Stealth mode, emergency wipe and deletion

- **Status**: Proposed, owner decisions recorded 2026-10-14 (design only; no code in this PR)
- **Date**: 2026-10-14
- **Appendix**: [`ADR-013-artifact-inventory.md`](ADR-013-artifact-inventory.md) (every artifact, with file:line)

## 要約 (日本語)

**目的**: 検閲下で秘密裏に通信する利用者のために、「Miasma を使った痕跡のうち、アプリ自身が消せるものはすべて消せる」ようにする。同時に、普段の使用でも痕跡を残さない。ただしアプリにできないこと(OS の履歴、SSD の残留、ハイバネーション、バックアップ、AV/EDR のテレメトリなど)は、できると主張せず、明記する。

**現状の問題**(調査結果):
- 今の緊急ワイプ (`distress_wipe`) は `master.key` を消して `config.toml` の秘密項目を消すだけ。ログ(ピア ID・LAN の IP・受信フォルダのパス・コンテンツ ID・使用日が入っている)、受信ファイル、履歴、連絡先、転送ジャーナル、一時ファイル、レジストリの URL スキームは残る。
- ログはデスクトップもデーモンも常にファイルへ書く(`desktop.log.<日付>` は回転もしない)。
- 復号済みの受信ファイルが `%TEMP%\miasma-retrieve-*.tmp` に平文で残りうる。
- ブリッジの既定データフォルダは、デーモンとは別の場所(Roaming 側)にある。

**決定の要点**:
1. **秘匿モードを既定 ON にする(既存インストールもアップグレード後に ON)**。ログはメモリ上のリングバッファだけ(既定 2 MiB、1 行 512 バイトまで)。GUI/CLI で見る・書き出すことはできる。ファイルへ書くのは、警告付きの「診断ログ」スイッチを明示的に入れたときだけ(その場合も暗号化し、日付を名前に入れない)。アップグレード後の初回起動で「今後ログは書かれません」という通知を 1 回表示し、旧ログは通知のあと自動削除する(通知で「残す」を明示的に選べる)。
2. **永続化するものはすべて、マスター鍵から HKDF で導出した「状態鍵」で暗号化する**(store_index、複製 WAL、転送ジャーナル、contacts、履歴、directed の封筒、設定、台帳)。マスター鍵を壊せば、ファイルの削除に失敗しても読めなくなる(「まず暗号消去、次に上書き+削除」)。
3. **正直な限界**: 既定のプロファイルでは `master.key` が同じフォルダに平文であるので、暗号化は「ワイプ後の復元を防ぐ」ものであり、「ワイプ前に端末を調べられる」ことには効かない。それに効くのは、パスフレーズで鍵を包む「高セキュリティプロファイル」だけで、これは**オプトインとして今回の範囲に含める(段階 3b)**。
4. **保存ファイル台帳**: Miasma が自分のストア外へ書いたファイル(受信箱、名前を付けて保存、`.part`、一時ファイル)を、暗号化した台帳に必ず記録する。ワイプは台帳のファイルを上書きして削除する。通常の削除は「履歴だけ消す/ファイルも消す」を 1 件ごとに聞く。移動・コピーされたファイルは追えない。
5. **ワイプ v2**: 実行は確認付きのボタン(GUI、確認フレーズの入力)と CLI `miasma wipe` だけ。確認なしのグローバルホットキーは作らない。順序は「鍵 → ログ → 台帳のファイル → 状態 → 共有 → レジストリ → (任意)自己削除」。ロックされたファイルは再試行し、最後の手段としての再起動時削除はユーザが明示的に選んだときだけ(その行為自体がレジストリに痕跡を残すため)。「次回起動時に再試行する」ための失敗マーカーは作らない(それ自体が痕跡になる)。ワイプ報告は画面表示のみで、ファイルには書かない。失敗は隠さず「消せなかったもの」を一覧で表示し、失敗時は fail-closed(鍵を先に壊し、その後は起動させない)。自己削除の既定は、インストール版は OFF、ポータブル版は ON。
6. **通常の削除**を 7 種類に整理した(共有 1 件、受信ファイル、履歴/ログ、連絡先、転送、自分が公開したものの取り消し、「鍵を残して全データ削除」)。ネットワーク上の他ノードにあるコピーは**強制削除できない**。署名付きの「撤回」メッセージは、ベストエフォートのプロトコルとして**最後の段階(段階 7)に回し、優先度は低い**。
7. **実装は小さな PR の連なり**(段階 1: 成果物の棚卸しと永続パスのレジストリ → 段階 2: 秘匿ログ → 段階 3: 状態の暗号化 → 段階 3b: 高セキュリティプロファイル → 段階 4: 台帳 → 段階 5: ワイプ v2 → 段階 6: 通常削除 UI・ポータブル版・ネットワークプリセット → 段階 7: ネットワーク撤回)。それぞれにテストがある(ワイプ後にデータフォルダを走査して何も残らないこと、秘匿モードでログファイルが 0 件であること、など)。
8. **メモリ(RAM)は必須要件(目標値はオーナー承認済み)**: 新設する全てに上限を決めた。リングバッファ 2〜4 MiB、暗号化状態は件数上限+上限付き LRU、台帳・履歴はディスク側でページング(履歴の既定上限 1 万件、最大 100 万件)、ファイルの転送・暗号化・上書きは 256 KiB〜1 MiB の定数バッファ。機密メモリは Zeroize し、`mlock`/`VirtualLock` は鍵だけに使う(限界も明記)。受け入れ基準は「1 GiB 転送中・履歴 100 万件・ログ満杯でも、現状(デーモン約 35 MB、デスクトップ約 40〜240 MB)から +12 MiB 以内」。測定手順は段階ごとのテストに入れた。
9. **その他の決定**: ポータブル版(exe の隣にデータ、中立な名前、レジストリ不使用)は正式な成果物。`miasma-share:` URL スキームの登録は秘匿モードで既定 OFF(「Miasma でリンクを開く」ボタンで明示的に ON にしたときだけ登録。既定ではリンクのクリックで開けなくなる。登録はワイプでも削除する)。ネットワークの「最大秘匿」プリセット(`iroh_mode=off` またはカスタムリレー、LAN 探索 OFF、ホスティング OFF)は任意で提供し、既定にはしない。他人の共有のホスティングは、通常プロファイルはコードの既定(1024 MiB)のまま、秘匿プリセットとポータブル版は 0。SECURITY.md の記述を実際の既定値に合わせて直す。ブリッジの `.processed/` 原本は既定で削除する。

**未解決の確認事項はなし**(オーナー決定は下の "Decisions (owner, 2026-10-14)" に記録した)。

---

## Decisions (owner, 2026-10-14)

The owner resolved all questions that were open in the first draft. They are
binding for the sections below; where a section changes because of one, it says
so.

| # | Decision | Where it lands |
|---|---|---|
| O1 | **High-security profile** (passphrase-wrapped master key, never stored unwrapped on disk) is **in scope as an opt-in**, phase 3b. | 5.4, 11 |
| O2 | **Stealth mode is ON by default, also for existing installs after upgrade.** The first start after upgrade shows a one-time notice that logs are no longer written; diagnostic logging is the explicit opt-in. | 4.1, 4.4, 11 |
| O3 | The **portable build** (data next to the exe, neutral names, no registry) is an **official artifact**. | 8.5, 11 (phase 6) |
| O4 | **Old log files** are deleted automatically after the notice; the notice offers **Keep** as an explicit choice. | 4.4 |
| O5 | **No failure marker** for "retry wipe on next start" (it would be a trace). Delete-on-reboot only if the user explicitly chooses it after a failure. | 8.3 |
| O6 | Emergency wipe is triggered **only by a confirmed button (typed phrase) and the CLI `miasma wipe`**. No unconfirmed global hotkey. | 8.1 |
| O7 | **RAM targets accepted**: baseline +12 MiB; history default cap 10 000 items (max 1 000 000); per-component caps as written in section 10. | 10 |
| O8 | **Self-delete**: default OFF for the installed build, default ON for the portable build. | 8.5 |
| O9 | **`miasma-share:` URL-scheme registration**: default OFF in stealth mode; registered only by an explicit "Open links in Miasma" button. Consequence: click-to-open of links does not work by default. The wipe removes the registration. | 4.1, 8.2 |
| O10 | **Network presets**: an optional "maximum stealth" preset (`iroh_mode=off` or a custom relay, LAN discovery off, hosting off). Not the default. | 4.5 |
| O11 | **Signed Retract** is deferred to the last phase, low priority. | 7.3, 11 (phase 7) |
| O12 | **Hosting other people's shares**: the normal profile keeps the code default (1024 MiB); the stealth preset and the portable build default to hosting 0. `SECURITY.md` is corrected so docs and code agree (it must state the real defaults). | 4.5, 11 |
| O13 | **Bridge `.processed/` originals** are deleted by default. | 6, 11 |
| O14 | The **wipe report is shown on screen only** and is never written to a file. | 8.1, 8.4 |

---

## 1. Context

Miasma is a censorship-resistant file transfer tool in the Freenet tradition.
Part of its audience must communicate under conditions where possession of the
tool, or evidence of having used it, is itself dangerous. Two things follow:

1. A device may be physically inspected (seized, border control, a visit).
   What the application leaves on disk, in the registry and in temp
   directories matters as much as the wire protocol.
2. The user needs a fast, honest way to remove what the application can
   remove, and an honest statement of what it cannot.

An investigation of `origin/main` (commit `e91471e`, appendix) found:

- The **emergency wipe is only a key wipe**. `LocalShareStore::distress_wipe`
  (`crates/miasma-core/src/store.rs:910-975`) zeroes and unlinks `master.key`
  and scrubs transport secrets in `config.toml`; the FFI wipe
  (`crates/miasma-ffi/src/lib.rs:465-540`) additionally handles
  `master.key.enc/.iv`. The CLI (`miasma-cli/src/main.rs:1439-1480`) and the
  daemon (`daemon/mod.rs:1565-1595`, two-step nonce confirmation) call the same
  thing. This is the right *first* step (it makes `shares/*.ms` unreadable) but
  it leaves every other artifact: logs, received files, history, contacts,
  journals, temp copies, registry keys.
- **Everything is written in plaintext except the share blobs** (which are
  AEAD under per-file keys derived from the master key, `store.rs:301-308`).
  `store_index.json`, `replication_wal.jsonl`, `contacts.json`,
  `push_history.jsonl`, `transfers/*`, `directed/*` and `config.toml` are
  readable JSON/TOML. Some use an owner-only ACL (`secure_file.rs`); an ACL does
  not help once the disk is read offline.
- **Logs are always on** and are sensitive (appendix section 4): they contain
  peer ids, the LAN IP, the inbox path, content ids and the dates of use, and
  the desktop log is never rotated.
- **Plaintext of received files leaks into `%TEMP%`**
  (`miasma-retrieve-*.tmp`) and to wherever the user saves.
- **Registry**: the GUI registers `HKCU\Software\Classes\miasma-share` on every
  start through `reg.exe` (`link.rs:186-247`); the MSI is per-machine.
- There is **no mechanism that records where Miasma wrote files**, so nothing
  could remove them even if it wanted to.
- Normal deletions are partial: `LocalShareStore::delete`
  (`store.rs:918-925`) exists but is not reachable from IPC, CLI or GUI;
  `DirectedRevoke` changes envelope state only; contact removal and transfer
  removal are done (PR #42, `push/service.rs:292-318`, `transfer/jobs.rs:317`).

## 2. Threat model

| Adversary | Capability we design against | Capability we do NOT claim to defeat |
|---|---|---|
| **A1. Local inspector of a device** (border, raid, a person with the unlocked machine) | Sees the file system, can run recovery tools on the live volume, reads application folders, logs, history, registry, temp | Forensic recovery from SSD remnants / wear-levelled blocks, a full disk image analysed by a specialist, volume shadow copies, backups, cloud sync of the folder, OS artifacts (appendix R9-R10), EDR/AV telemetry already shipped, memory acquisition of a running machine |
| **A2. Remote network observer** | Sees which hosts and ports the machine talks to, SNI, volume, timing | Traffic analysis with global visibility; n0 as a party that learns endpoint id and IPs in `n0` mode. Mitigations are configuration (appendix section 7), not part of this work |
| **A3. Coercion** | The user is made to unlock, reveal passwords or run the app | We provide a fast, confirmed wipe and (opt-in) a passphrase profile; we do **not** provide a duress passphrase or hidden volumes |

### Explicit non-goals

- **Not a replacement for full-disk encryption.** Recommend BitLocker / FileVault
  / LUKS with a pre-boot PIN, and disabling hibernation and clearing the
  pagefile on shutdown (policy, admin only). The wipe reduces what remains on a
  *decrypted, running* system; it does not make an unencrypted disk safe.
- **No defence against forensic recovery on SSD/flash.** Overwriting a file
  does not overwrite the physical cells (wear levelling, TRIM timing, copy-on-
  write file systems, NTFS `$LogFile`/USN journal, resident data in the MFT).
  That is why crypto-erase comes first: unreadable data, not "erased" data.
- **No claim of plausible deniability.** The binary, the installer entry,
  Prefetch, the Start Menu shortcut, the dependence of the encrypted files on a
  Miasma-specific layout, and the high-entropy `master.key` all say "Miasma was
  here". After a wipe the directory is gone, which is itself suspicious only if
  someone knew it existed. What *does* help: the **portable build** (no
  installer, no ARP entry, no HKLM keys, a neutral folder and exe name) and
  **self-delete** at wipe (section 8; default on for the portable build). Neither gives deniability against an
  inspector who finds Prefetch/USN records.
- **Never touch OS or Windows event logs** or any state not created by Miasma.
  The wipe report lists OS artifacts as *not removed* and tells the user how to
  clear them by hand.
- **No network-side erasure**: copies on other nodes cannot be forced away
  (section 7).

## 3. Decisions (summary)

| # | Decision |
|---|---|
| D1 | One **persisted-paths registry** in `miasma-core` (`paths.rs`): every file or directory the product writes is created through it, with a class (`State`, `Secret`, `UserVisible`, `Runtime`, `Diagnostic`), a treatment (`Encrypt`/`Plain`/`NoWriteInStealth`) and a wipe method. A CI test fails if a new `fs::write/File::create/create_dir_all` appears outside it. |
| D2 | **Stealth mode is the default** (`privacy.stealth = true`), including existing installs after upgrade (with a one-time notice). Logs: in-memory ring buffer only; no files, no stderr, no panic text, no crash dump. |
| D3 | **Diagnostic logging** is an explicit opt-in (`privacy.diagnostic_logging`), with a warning shown at the switch and in the status line while on. Logs are encrypted at rest, rotate by size not by day, and never carry file names. |
| D4 | **State encryption**: `state_key = HKDF-SHA256(master_key, info="miasma/state/v1")`; per-document subkeys by label. Record-oriented (streaming) format. "Crypto-erase first, then overwrite and delete." |
| D5 | **Saved-file ledger** (encrypted, record log): every file Miasma writes outside its store is registered **before** the write. |
| D6 | **Emergency wipe v2** with a fixed order, a verification pass, an on-screen-only report of what could not be removed, and fail-closed behaviour. Triggered only by a confirmed button (typed phrase) or the CLI `miasma wipe`; no unconfirmed hotkey. |
| D7 | **Optional self-delete** at wipe (portable and installed builds, per OS), selectable; default OFF for the installed build, ON for the portable build. |
| D8 | **Normal deletion** taxonomy N1-N7 with per-item semantics (section 7). |
| D9 | **Network retraction** is best-effort, publisher-signed, and honest about being unenforceable (section 7.3). Last phase, low priority. |
| D10 | **High-security profile (opt-in, phase 3b)**: passphrase-wrapped master key (Argon2id), no unwrapped key on disk. Not the default profile. |
| D11 | **Every new mechanism has a RAM budget** (section 10) and an acceptance test; no unbounded growth path may be added. |
| D12 | **Portable build** is an official artifact; **optional "maximum stealth" network preset**; hosting defaults per profile (4.5). |

## 4. Stealth mode and logging

### 4.1 Behaviour

`privacy.stealth` (default **true**, stored in the encrypted config; the flag
itself must be readable before the key is, so it lives in the process
environment/CLI for headless use: `MIASMA_STEALTH=0`, `--no-stealth`).

When on:

| Surface | Behaviour |
|---|---|
| `tracing` | A custom layer writes formatted lines to a bounded ring buffer in memory. No `tracing_appender`, no stderr layer (today: `miasma-cli/src/main.rs:497-513`, `miasma-desktop/src/main.rs:93-110`, `miasma-bridge/src/main.rs:36-52`). |
| Startup banner of `miasma daemon` | One line ("daemon started"); peer id, bootstrap addresses and paths are available through `miasma status`. Today `main.rs:1735-1745` prints them to the console (scrollback). |
| Panic | A panic hook (none exists today) writes a fixed text without payload or location to the ring buffer and aborts. `RUST_BACKTRACE` is ignored. |
| Crash dumps | Windows: `SetErrorMode`, silent unhandled-exception filter. Unix: `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`. WER/DiagnosticReports already written are OS state (not removable). |
| Version stamp, `pending-link.txt`, `url-scheme-registered.txt`, `desktop.lock` | Not written (appendix D3, D9-D11); link hand-off goes through the loopback IPC. |
| Registry | `miasma-share:` is **not** registered in stealth mode (and the registration the GUI does on every start today, `link.rs:186-247`, is skipped) unless the user presses the explicit **"Open links in Miasma"** button (`register_url_scheme`). Consequence, stated in the UI: by default, clicking a `miasma-share:` link does not open Miasma; the user pastes the link instead. The wipe removes the registration (8.2). |
| Browser | `miasma web` prints the URL instead of launching the browser. |
| Temp files | Decrypted downloads go to `<data>/tmp` (registry-managed), not `%TEMP%`. |

### 4.2 The ring buffer

- Fixed capacity in **bytes** (default 2 MiB, configurable 1 to 8 MiB). A line is
  truncated at 512 bytes. When full, the oldest lines are dropped (overwrite in
  place, no reallocation after start-up). Stored as `Box<[u8]>` + index of line
  starts (`VecDeque<u32>` bounded by capacity/32).
- Each process has its own buffer (daemon, desktop, bridge, CLI). The daemon's
  buffer is read over IPC (`LogsTail { since_seq, max_bytes <= 256 KiB }`, a new
  `ControlRequest`) so the GUI and `miasma logs [--follow]` show it without a
  file. The reply size is bounded.
- **Export on demand** writes a plain text file to a path the user picks. That
  file is a trace the user knowingly creates: it is recorded in the ledger (so a
  wipe removes it) and the dialog says so.
- Content policy: no file names, no paths, no contact labels, no share ids or
  links in log fields (ids are shortened to 8 hex characters where a correlation
  is needed). A lint test greps `tracing` call sites for `path`, `name`,
  `filename`, `label` arguments and fails the build; today
  `push/service.rs:222` (inbox path) and `fonts.rs:287-291` (font paths) would
  fail it.
- The buffer is cleared (zeroed) by the wipe and by an explicit "Clear log" action.

### 4.3 Diagnostic logging (opt-in)

- Switch in Settings and `miasma config privacy.diagnostic_logging true`, with
  the text: *"Diagnostic logs are written to disk. They show that Miasma was
  used and when. Turn this on only to troubleshoot, and turn it off afterwards;
  the log is removed when you turn it off."* While on, the status bar and
  `miasma status` show "logging to disk".
- Files: `<data>/lg/0.dat`, `1.dat` (fixed names, no dates), rotated by size
  (default 4 MiB each), encrypted with the `logs` subkey as a streaming record
  log (so an inspector sees noise, and crypto-erase covers them). `miasma logs
  --decrypt` and the GUI "Export" produce plain text.
- The level is `info` by default; `debug` needs a second explicit switch.
- Turning the switch off deletes the files (OW + RM).

### 4.4 Migration of existing logs

Existing installs have `daemon.log.*`, `desktop.log.*`, `bridge.log.*` (plaintext,
dated names). Stealth mode turns ON for them at upgrade (O2). On the first start
of the new version the GUI shows a one-time notice: *"Miasma no longer writes log
files. Old log files were found; they show when Miasma was used and will be
removed securely. [OK, remove] [Keep them]"*. Removal is automatic after the
notice (O4); **Keep** is an explicit choice and leaves the files untouched (they
are then listed as plaintext leftovers in the wipe plan and removed by a wipe).
The notice also explains that diagnostic logging is the explicit opt-in for
writing logs again. Headless daemons (no GUI to show a notice) remove the old
logs after the state migration succeeded, unless `MIASMA_KEEP_OLD_LOGS=1` is
set, and print one line to stdout saying so. The removal is OW + RM and is
recorded nowhere.

### 4.5 Network presets and hosting defaults

- **"Maximum stealth" preset** (optional, never the default): `iroh_mode = off`
  or a user-supplied custom relay, `iroh_lan_discovery = false`, hosting off
  (`hosted_quota_mb = 0`) (appendix section 7). It costs connection paths
  (fewer ways to reach peers, no LAN discovery) and the UI says so when it is
  selected. Selectable in Settings > Privacy and `miasma config --preset
  max-stealth`.
- **Hosting other people's shares** (O12): the *normal* profile keeps the code
  default of 1024 MiB (`config.rs:78`). The **stealth preset and the portable
  build default to 0**. `SECURITY.md` currently says the default quota is zero;
  that statement is corrected in phase 1 to state the real defaults (1024 MiB
  normal; 0 for the maximum-stealth preset and the portable build) so that docs
  and code agree.

## 5. Encryption of persisted state

### 5.1 Keys

```
master_key (32 B, master.key)              -- unchanged: identity + share blob keys
  state_key = HKDF-SHA256(ikm=master_key, salt=none, info="miasma/state/v1")
    doc_key(label) = HKDF-SHA256(ikm=state_key, salt=none, info="miasma/state/v1/doc/" || label)
```

Labels (domain separation): `config`, `prefs`, `store-index`, `repl-wal`,
`transfer-journal`, `publish-journal`, `contacts`, `push-history`,
`directed-envelope`, `directed-sidecar`, `ledger`, `logs`, `bridge-index`.
The existing `blake3::derive_key` / HKDF patterns in `crypto/keyderive.rs` are
reused; labels are added there, next to `LABEL_NODE_ID` etc., so the
domain-separation list stays in one place.

Destroying `master.key` therefore destroys the share blobs *and* all state.
Because the node identity is derived from the same key (`keyderive.rs:31-47`),
crypto-erase also changes the identity: a re-initialised node is a new person
on the network. That is intended for a wipe; the "keep identity" deletion (N7)
therefore keeps `master.key` and removes everything else.

### 5.2 Format

Two shapes, both AEAD (XChaCha20-Poly1305, already a dependency):

1. **Document** (small, rewritten whole: `config`, `prefs`, `contacts`, one
   directed envelope, one transfer journal): `magic "MSD1" | version u8 | label
   id u8 | nonce[24] | ciphertext+tag`. AAD = `magic|version|label`. Written with
   the existing atomic-replace pattern. Size limit enforced on read (default
   4 MiB; contacts are capped at 500 entries today, `push/store.rs:24`).
2. **Record log** (append-only, may be large: `store-index`, `repl-wal`,
   `push-history`, `publish-journal`, `ledger`, `logs`): `magic "MSL1" | version |
   label | file_salt[16]`, then records `len u32 | nonce[24] | ciphertext+tag`.
   AAD includes `file_salt` and the **record sequence number**, so reordering,
   splicing between files, and replay of an old record at a new position are
   rejected; truncation at the tail is detectable only against the last
   checkpoint record (a periodic sealed `count`), which is acceptable for local
   state. A record is a small JSON line (<= 16 KiB). Compaction rewrites the log
   through a temporary file in the same directory and renames it.

Reads **stream** records; nothing loads the whole file (section 10). File
names become opaque (`HKDF(state_key, "name/"||label)[..8]` as 16 hex characters,
suffix `.dat`) so a partial copy does not say `contacts.json`. The data
directory name `miasma` stays unless a portable build overrides it.

### 5.3 What is encrypted, what is not

| Item | Treatment | Why |
|---|---|---|
| `store_index.json` | Encrypt, record log | Reveals what I hold, for whom, and access times |
| `replication_wal.jsonl` | Encrypt, record log | Reveals what I published |
| `transfers/*` journals | Encrypt | Hold source and destination paths |
| `contacts.json` (+ corrupt copies) | Encrypt, document | The social graph |
| `push_history.jsonl` | Encrypt, paged record log | Names, labels, `saved_as` paths |
| `directed/*` envelopes + sidecars | Encrypt, document | Sharing keys, sender/recipient, state |
| Saved-file ledger | Encrypt, record log | Paths of the user's files |
| `config.toml` (whole) | Encrypt, document | `iroh_mode`, transports, proxy and secrets, inbox path. "Initialised" is decided by the presence of `master.key` (today `worker.rs:840` also requires `config.toml`) |
| `desktop-prefs.toml` | Encrypt | Locale/theme: minor, but cheap and removes a Miasma-named plaintext file |
| `bridge` index | Encrypt | Maps torrent info-hashes to MIDs |
| Diagnostic logs | Encrypt | See 4.3 |
| `shares/*.ms` | Already ciphertext | Keep as is |
| **Stays plaintext** | | |
| `master.key` | Default profile: raw 32 bytes (needed to start). High-security profile: wrapped (5.4) | Chicken-and-egg: the key cannot protect itself |
| `daemon.token`, `daemon.port`, `daemon.http` | Plain, owner-only ACL, removed on exit | Another process must read them before it can authenticate. They carry no history. Stale files after a crash are swept at next start and by the wipe |
| `desktop.lock` | Plain/empty (or an OS mutex) | Lock |
| Files the user received | Plain | The user must be able to open them; tracked by the ledger |
| `*.part` | Plain | Written in place at the user's destination; tracked by the ledger |

### 5.4 Key custody and the honest limit of at-rest encryption

In the **default profile** `master.key` sits next to the data. An inspector who
copies the folder *before* a wipe gets the key and everything else.
Encryption at rest in this profile gives exactly two things: (a) after the key
is destroyed, leftover state is unreadable even if deletion failed or the disk
holds old copies; (b) it removes plaintext, Miasma-named, human-readable
documents from the folder. It does **not** protect against pre-wipe inspection.

The optional **high-security profile** (`security.profile = "high"`) closes that
gap:

- `master.key` is replaced by `vault.dat`: `Argon2id(passphrase, salt)` (the
  Argon2 code already exists for share protection, `transfer/protection.rs`)
  wraps the 32-byte key with XChaCha20-Poly1305. The key is held only in memory
  (page-locked, section 10.4). The user types the passphrase at start. Wrong
  passphrase attempts are not throttled on disk (there is no secure counter
  without hardware); Argon2 cost is the only brake.
- Optional hardware factor (Windows DPAPI/TPM, macOS Keychain/Secure Enclave,
  Android Keystore which already exists in `KeystoreHelper.kt`) as a second
  wrapping layer: documented, not designed here.
- Cost: no unattended start (the daemon cannot auto-start after reboot), a lost
  passphrase is data loss. **Decision O1: included in scope as an opt-in,
  built as phase 3b right after the default-profile state encryption (phase 3).**
  The user chooses it at first run or later via Settings > Privacy (switching
  re-wraps the key; the old `master.key` is overwritten and removed). The
  wipe (8.2 step 2) overwrites `vault.dat` like `master.key`.

### 5.5 Alternatives considered

| Option | For | Against | Decision |
|---|---|---|---|
| **A. One encrypted container file** (e.g. `vault.dat` holding everything incl. share blobs) | One artifact to wipe; no names or sizes leak; hides count of shares | Whole-file rewrite or a custom allocator for 1 GiB+ of shares; hard to stay within the RAM budget; corruption risk concentrates; mmap interacts badly with overwrite | Rejected for shares; small state may later move into one `state.dat` |
| **B. Many encrypted files** (this ADR) | Streams, fits the existing layout and the RAM budget, incremental migration, partial-corruption isolation | File count, sizes and mtimes leak; opaque names only partially help | **Chosen** |
| **C. Passphrase-derived key only, never on disk** | Defeats pre-wipe inspection; real crypto-erase by forgetting | No unattended daemon, lost passphrase = loss, UX burden for the many users who do not need it | Opt-in profile (D10, phase 3b) |
| **D. Key on disk (today)** | Works unattended | See 5.4 | Default, with the limit stated |
| **E. OS key store only (DPAPI/Keychain)** | Binds to the user login | Inspector with the login (A1/A3) gets it; roaming and backup semantics; not portable | Documented as an extra layer in the high profile |

## 6. Saved-file ledger

**What is recorded.** Every file Miasma creates or moves outside its own
`shares/` store, **before** the write starts (so a crash cannot leave an
untracked file): push inbox files and their `.part` (`push/service.rs:798-840,
1168-1175`), received files and `.part` at user-chosen outputs
(`transfer/receive.rs`, `transfer/journal.rs:53`), Save-As targets from the
GUI (`app.rs:446,1070`, `transfers.rs:753`), CLI `-o` outputs (`main.rs:828`),
decrypted temp downloads (appendix T1, T2), exported logs and diagnostics
reports (`app.rs:1551,2271`), bridge `.processed/` originals and torrent
downloads (D23, D24). Decision O13: the bridge **deletes the `.processed/`
original by default** after a successful import (a setting `bridge.keep_originals
= true` keeps it, and then the original is ledger-tracked as `bridge`).

**Entry** (record log, `ledger` subkey):
`{id, path, kind (inbox|received|part|temp|export|bridge), size, created_ms, source (push contact id | transfer id | envelope id | share id), state (planned|written|moved|removed), hash8}`. `hash8`
(first 8 bytes of BLAKE3 of the file) lets a later scan notice that the file at
that path is no longer the same file; a changed file is **not** deleted by
"also delete the file" without a second confirmation.

**Operations.**
- `plan(path)` writes `planned` first; `commit(id, size)` after the rename.
- Normal delete of a history entry offers per entry: **"Remove from history
  only"** (ledger entry becomes `removed`, file stays) or **"Also delete the
  file"** (OW + unlink, then `removed`).
- Emergency wipe iterates the whole ledger (`planned` and `written`).
- The ledger has a count cap (default 100 000 entries) with oldest-`removed`
  eviction on disk; never an unbounded in-memory list.

**Limits (documented in the UI and the wipe report).**
- Files the user **moved, copied, renamed, opened in another app, synced, or
  attached elsewhere** are not tracked (after a move the path is gone; `moved`
  state only exists when Miasma did the move).
- Applications that opened the file create their own temp/recovery copies
  (Office autosave, PDF viewers, thumbnails, indexers).
- Overwrite is one random pass on the live volume: it is meaningless on SSD,
  copy-on-write or journalled volumes beyond making the logical content
  unavailable to the file system.
- Antivirus/EDR may have scanned or uploaded the file.
- A path on a removable or network volume that is not mounted cannot be
  reached; it is listed in the report.

## 7. Deletion taxonomy (normal deletes)

Every item states what Miasma can and cannot do.

### 7.1 Local deletions

| # | Action | Semantics | Can | Cannot |
|---|---|---|---|---|
| N1 | **Delete one stored share / one published content** | New IPC `StoreDelete { mid }`: removes all `shares/*.ms` of that MID (owned), their index records, the replication WAL item (stops re-announcing), and the DHT record cache entry. Wiring `LocalShareStore::delete` (`store.rs:918`) is not enough: it takes one share address and ignores the WAL and DHT record. Hosted shares (kept for others) are deleted by the same call or by `hosted_quota_mb = 0` + `StorePurgeHosted`. | Free the disk and stop serving | Remove copies on other nodes; un-publish the DHT record from nodes that hold it (24 h TTL, `network/node.rs:5402`, but nodes re-publish) |
| N2 | **Delete received inbox files** | Per file, via ledger: "history only" or "also delete". "Delete" has two flavours: plain unlink (fast, default for normal use) and **secure** (OW 1 pass + unlink; used by wipe and offered as a checkbox). | Remove the file at the recorded path | Copies elsewhere; SSD remnants |
| N3 | **Delete history / logs** | History: single entry or all (`push_history`, transfer list `TransferClearFinished` already exists, `ipc.rs:195`). Logs: ring buffer clear (always), disk diagnostic log delete (OW + RM). | Remove local records | Records the peer keeps of what you sent |
| N4 | **Delete a contact** | Already implemented by PR #42 (`push/service.rs:292-318`): cancels in-flight transfers with that contact and removes their `.part` files. Add: history rows of that contact removable on request, and ledger-tracked files from them offered for deletion. | Local contact, transfers, partials | Make the other side forget you |
| N5 | **Cancel a transfer** | `TransferCancel` + `TransferRemove { discard_partial }` (`transfer/jobs.rs:290-352`): stop, delete journal and `.part`; extended to OW the `.part` through the ledger and to delete the journal securely. | Stop and clean locally | Whatever the peer already received |
| N6 | **Retract something I published/sent** | See 7.2 / 7.3 | Mark, stop serving, ask others | Force deletion on other nodes or recipients' disks |
| N7 | **Delete all stored data, keep identity** | Keep `master.key` (and the passphrase vault); remove shares, state, ledger files, logs, history, contacts, journals, directed envelopes, inbox, temp. Equivalent to wipe v2 without the key and registry steps; the node identity (publisher key in existing share IDs) stays valid, so `miasma-share:` links already handed out still identify the same publisher. | Fresh empty node under the same identity | Identity is not rotated (cannot be rotated yet, SECURITY.md) |

### 7.2 What `DirectedRevoke` actually does today

Read from `daemon/mod.rs:2041-2115` and `network/node.rs:4745-4766`:

- **Sender side** (`outgoing/<id>.json`): if the envelope is not terminal, state
  becomes `SenderRevoked`, the stored challenge code is deleted, and a
  `DirectedRequest::SenderRevoke` is sent over libp2p to the recorded recipient
  peer id, **best-effort** (failure only logs "recipient may be offline").
- **Recipient side**: on `SenderRevoke` from a peer bound to that envelope
  (`node.rs:4745`) the incoming envelope is marked revoked; a later retrieve is
  refused.
- **Recipient delete** (`RecipientDeleted`) is a state change of the local
  envelope only.
- **It does not delete the shares** that carry the content (they stay in the
  sender's store and in the DHT/other holders), does not remove the WAL item
  (replication continues), does not delete files the recipient already
  retrieved, and does not remove the envelope file. Revoking after the recipient
  has retrieved has no effect on their copy.

Therefore N6 for directed sharing is: *"stop the recipient from retrieving
through the protocol, if they are online and honest"*. Proposed fix in phase 6:
revoke also performs N1 on the content (for the sender's owned shares) and
removes the replication item, and the UI says what it cannot do.

### 7.3 Retracting network-published content (best-effort)

**What exists.** Nothing retracts. Public content (`miasma publish`) is
dissolved into shares stored in the publisher's store and replicated to other
nodes (`store.put_hosted_by`) with a DHT record that carries a 24 h Kademlia
TTL (`node.rs:5402`) and is re-announced by the replication engine. Hosted
shares are **never evicted by pushes** (`store.rs` `put_hosted_by`: "rejects
rather than evicts") and have no expiry; they persist at the host until that
host's operator deletes them. There is no tombstone, no TTL on shares, and the
index does not even store the publisher key for a hosted share, only the
transport peer id of the pusher (`hosted_principal`).

**Honest statement.** Other people's copies cannot be forcibly deleted. A
recipient who downloaded the file keeps it. Any retraction is a request that
honest hosts may honour.

**Proposal (phase 7, the last phase, low priority: decision O11).** It can be
dropped or postponed without affecting any other phase. A signed `Retract` message:

```
Retract {
  version: 1,
  mid_digest: [u8;32],            // BLAKE3 of MID, not the MID itself
  publisher: [u8;32],             // Ed25519 publisher key (the share-ID key)
  not_before: u64,                // unix secs; retraction applies to records/shares published before this
  expires: u64,                   // tombstone lifetime hint (<= 30 days)
  sig: [u8;64],                   // Ed25519 over "miasma/retract/v1" || fields
}
```

- **Who may retract**: only the key that signs the DHT record. Hosts must verify
  the signature **and** that their stored record/shares were published by that
  key. This requires a prerequisite: record the publisher key per hosted share
  (new field in the index). A bare-MID publication has no authenticated
  publisher (SECURITY.md): a retraction cannot be honoured for it, and anyone
  who knows the MID could otherwise retract someone else's content; hence the
  rule *"no signed publisher, no retraction"*.
- **Propagation**: sent to the peers recorded in the publisher's replication
  locations (`ShardLocation`), and placed in the DHT under a derived key so
  later hosts see it. Best effort, retried by the replication queue.
- **Host behaviour**: on a valid message, delete matching shares/index
  records/WAL items (N1) and keep a tombstone `(mid_digest, publisher, not_before)`
  for `expires` to refuse re-replication of older copies. Hosts that ignore it
  are indistinguishable from offline.
- **Abuse risks and limits**: (1) *replay*: tombstones are idempotent and
  `not_before` stops a retraction from killing a later honest re-publication;
  (2) *key compromise*: whoever holds the publisher key can retract (and
  publish); the key cannot be rotated today; (3) *denial of service*: tombstone
  storage is bounded (default 10 000 entries, oldest evicted) and verification
  is one Ed25519 check; (4) *information leak*: the tombstone proves that this
  publisher published that content; it uses the digest of the MID, but anyone
  who knows the MID can confirm it, and sending retractions reveals the
  publisher is online; (5) *it does not reach* downloaded copies, other
  mirrors outside Miasma, backups of the hosts.
- The UI must show "Requested" not "Deleted", and the count of peers that
  acknowledged.

## 8. Emergency wipe v2

### 8.1 Triggers (never silent)

- **GUI**: Settings > Privacy > "Emergency wipe...". Opens a dialog with the
  list of what will happen and the options (checkboxes: *also remove the
  application files* (pre-checked in the portable build only), *also remove the URL-scheme registration*
  (shown only if it was registered)). Confirmation
  is by **typing a short phrase** (`WIPE`), not just a button, to avoid
  accidents. The existing daemon-side two-step nonce (`WipeChallenge`/
  `WipeConfirm`, `control_auth.rs:141-160`) stays and is used between the GUI/CLI and
  the daemon.
- **CLI**: `miasma wipe` prompts for the phrase; `miasma wipe --confirm` keeps
  working for scripts (it already exists, `main.rs:1439`) and gains `--self-delete`
  and `--no-registry`. There is **no** option to write the report to a file
  (O14): the report is shown on screen / printed to stdout only; the user may
  redirect stdout at their own risk.
- **No global hotkey** (O6). The wipe is triggered only by a confirmed button
  (typed phrase) and by the CLI `miasma wipe`. A hotkey that wipes without a
  prompt is a data-loss hazard, and on Windows it requires registering a system
  hotkey and keeping the process alive. Instead: a **"panic" button on the main
  window** that opens the same confirmation dialog (one click + the typed
  phrase).
- **When the app is not running**: `miasma wipe` works without a daemon (today it
  already falls back to a disk-only wipe when `daemon.port` is absent,
  `main.rs:1450-1480`). The GUI executable accepts `--wipe`.
- The Android/iOS app exposes the existing wipe with the same confirmation;
  Android additionally deletes the Keystore key (`MiasmaViewModel.kt:124-136`).

### 8.2 Order

Ordered so that the most damaging exposure ends first and the remainder is
safe to interrupt:

1. **Quiesce**: set the daemon `WIPING` flag; stop accepting requests and
   shut down transports and the replication task; cancel transfers.
2. **Crypto-erase**: zero in-memory keys (`Zeroizing`), overwrite `master.key`
   (and `master.key.enc/.iv`, `vault.dat`) with random bytes, fsync, unlink; on
   Android delete the Keystore key. From here every encrypted state file and every
   share is unreadable. Nothing below can be "undone".
3. **Ring buffer and in-memory caches**: zero them.
4. **Plaintext user-visible files**: iterate the ledger; for every `planned/
   written` entry OW + unlink (streamed 256 KiB chunks). Then sweep `<data>/tmp`,
   `inbox/`, `%TEMP%\miasma-retrieve-*.tmp` (legacy names), `.part` files named by
   journals before the journals are removed.
5. **Diagnostic logs and legacy logs**: `lg/*`, `daemon.log*`, `desktop.log*`,
   `bridge.log*`.
6. **State files**: everything registered by the persisted-paths registry as
   `State`/`Secret`/`Runtime` (OW for files <= 8 MiB, plain unlink for larger,
   since they are already unreadable).
7. **Shares**: unlink `shares/*.ms` in LRU order is unnecessary; remove the
   directory. Overwrite only if the user chose "thorough" (time bound: stop
   overwriting after 30 s, unlink the rest).
8. **Remove directories** the app created (data dir, inbox, tmp) if empty.
9. **Registry / shell** (Windows): delete `HKCU\Software\Classes\miasma-share`
   (the URL-scheme registration, if present) via the registry API (not `reg.exe`, whose command line is logged by process
   auditing). MSI-owned HKLM keys are not touched (report them).
10. **Verification pass**: re-scan the registered paths and the data dir
    (`read_dir` recursion bounded to 100 000 entries); anything that still
    exists is retried once, then listed.
11. **Self-delete** (if selected; default off for the installed build, on for the portable build), after the report is shown and the user acknowledged, because a failed self-delete must not hide the report.

### 8.3 Locked files and failure handling (Windows)

- Open child processes first: stop the daemon and bridge we spawned (PIDs are
  known to the GUI; for a standalone wipe, use `daemon.port` + IPC, then wait
  for the process to exit, as `cmd_wipe` already does with a 5 s deadline).
- On `ERROR_SHARING_VIOLATION`/`ERROR_ACCESS_DENIED`: retry 5 times with 100,
  200, 400, 800 ms back-off; then try to **rename to a random name in the same
  directory** and delete with POSIX-semantics disposition
  (`FileDispositionInfoEx` with `FILE_DISPOSITION_POSIX_SEMANTICS`, Windows 10
  1709+), which unlinks even while another process holds the file open with
  `FILE_SHARE_DELETE`.
- If it still fails, the file is **listed as not removed** in the report with
  the reason, and the wipe continues with the rest. It does not stop at the
  first error and it does not roll back.
- **Delete on reboot** (`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`) is offered
  only as an explicit choice after a failure (O5); it is never automatic. It writes the path into
  `HKLM\...\Session Manager\PendingFileRenameOperations`, i.e. a registry trace
  of the very path, it needs administrator rights (so it usually fails for a
  normal user), and the entry survives until the next reboot. The dialog says so.
- **Fail-closed**: the key is destroyed first (step 2), so a half-finished wipe
  leaves nothing readable under the master key. After step 2 the process refuses
  to start the node again in this data dir: with no `master.key` the app behaves
  as a fresh install (and would create a *new* key when the user initialises).
  A "wipe incomplete" state is **not** persisted (O5: a marker would be a
  trace, so there is no "retry at next start" option at all); the report is
  shown now, and `miasma wipe` can simply be run again, because it works from
  the registered paths and from a scan, not from saved state.
- If step 2 itself fails (the key file cannot be overwritten), the wipe aborts
  immediately and says so, and the in-memory keys are still zeroed (this is
  what `distress_wipe` does today: the in-process key is dropped first).

### 8.4 What the user sees

- A progress list with the 11 steps and per-step counts; the elapsed time (the
  key step is expected to finish in well under a second; the existing SLO is
  5 s for the key).
- A final screen: **"Removed"** (counts by class), **"Could not remove"**
  (path class, reason, e.g. "in use", "access denied", "volume not mounted";
  paths are shown on screen only and never saved, O14), and **"Not removable by Miasma"**: a fixed,
  honest list (OS recent files and Jump Lists, Prefetch, search index, thumbnail
  cache, pagefile/hibernation, backups and cloud sync, antivirus/EDR copies,
  SSD remnants, files you moved or copied elsewhere, installer/Add-Remove-
  Programs entry unless self-delete/uninstall was used).
- After the user closes the dialog the app exits (it does not stay open with an
  empty node). A relaunch shows the first-run screen.

### 8.5 Self-delete (optional; default off installed, on portable)

Selectable in the wipe dialog and via `--self-delete` (portable build: on unless
`--keep-app`). Deferred until after the process has finished the report.

| OS | Approach | Notes |
|---|---|---|
| Windows (portable / unzip) | **Rename the running image's default stream** to an alternate stream (`SetFileInformationByHandle(FileRenameInfo)` to `:x`), then set delete disposition (`FileDispositionInfoEx`). Works on a running exe without a helper process on Windows 10 1709+ (the technique is the one used by installers for self-removal). Then delete the (now empty) folder. | No `cmd /c ping ... & del` helper: that would put a command line into process-creation auditing, Sysmon and EDR. Fallback only if the API fails: a one-shot `powershell`-free helper is **not** used; the report asks the user to delete the folder. |
| Windows (MSI install) | Not self-removable: files are under `Program Files`, registration is per-machine, removal needs `msiexec /x` with elevation. The wizard offers to start the uninstaller (UAC prompt), then the report states the ARP entry is gone only after uninstall. | MSI uninstall leaves `C:\Windows\Installer` cache cleaned, but installer logs and event log entries remain (not touched). |
| macOS | `unlink` of the executable and `rm -rf` of the `.app` bundle while running is allowed. | LaunchServices cache and Spotlight may keep the name; not touched. |
| Linux | `unlink` of the executable (running images stay valid) and the install directory. | Package-manager installs are removed by the user's package manager; shell history is outside the app. |
| Android | Cannot silently uninstall; open the system uninstall intent after wipe. | User must confirm. |
| iOS | Not possible. | Wipe only. |

The **portable build** (zip; data directory beside the exe, neutral folder and
exe name, no registry writes at all, no URL scheme, no installer) is an
**official artifact** (O3) and the recommended distribution for users in the
threat model; it makes self-delete clean. Its defaults: self-delete ON, hosting
0 (4.5), URL scheme never registered (the "Open links in Miasma" button is
hidden). The data directory is found relative to the exe, so no `%APPDATA%`
folder is created. It is built and released by the same packaging scripts as the
other variants (`scripts/package-release.ps1`, phase 6).

## 9. Normal-deletion UI / API surface

New or extended IPC (`ControlRequest`), all with bounded replies:

`StoreList { cursor, limit<=200 }`, `StoreDelete { mid }`, `HistoryList { cursor, limit<=200 }`,
`HistoryDelete { ids | all, delete_files: bool }`, `LedgerList { cursor, limit }`,
`LedgerDelete { ids, secure }`, `LogsTail { since_seq, max_bytes }`,
`LogsClear`, `WipePlan` (dry run: the counts per class), `WipeRun { opts }`
(replaces `Wipe`/`WipeConfirm` semantics but keeps the nonce).

GUI: a **Storage** tab (list of my published/stored content with Delete and, once
phase 7 exists, a retraction request), the existing Inbox/History gets per-row "Remove from
history" / "Also delete file", Settings > Privacy (stealth, diagnostic
logging, URL scheme, wipe). CLI: `miasma rm <mid>`, `miasma history rm|clear`,
`miasma inbox rm`, `miasma logs [--follow|--clear|--decrypt]`, `miasma wipe`,
`miasma reset --keep-identity` (N7).

## 10. Memory (RAM) budget

**Requirement (owner): RAM management is a must.** Every mechanism introduced or
changed by this ADR has an upper bound, and no path may grow with file size,
history length or time. Baseline measured today (owner): daemon about 35 MB,
desktop 40-240 MB (Private), unchanged by a 1 GiB transfer (the transfer path
streams). The design must not worsen that.

### 10.1 Budgets

| Component | Budget (steady) | Policy when full | Notes |
|---|---|---|---|
| Log ring buffer (per process) | **2 MiB** default, 1-8 MiB configurable; one line <= 512 B | Drop oldest lines | Allocated once at start; `LogsTail` reply <= 256 KiB |
| State read/write (encrypted records) | <= 1 record (16 KiB) + 64 KiB I/O buffer per open file | Stream; never `read_to_string` of a state file | Replaces `load_index` that reads the whole `store_index.json` on each call (`store.rs:228-234`), `History::read_all` (`push/state.rs:296`), WAL replay into a full map |
| Decrypted-state cache (index, contacts, envelopes) | **<= 1 MiB** total, LRU by bytes | Evict least-recently used; reload from disk by key | Index lookups by content address use an on-disk sorted segment + a small Bloom filter (<= 256 KiB) instead of a full `HashMap` |
| Push history | Disk cap **default 10 000 entries** (configurable up to 1 000 000); memory: 1 page of 256 entries + 4 cached pages (<= 256 KiB) | Evict oldest segment on disk | Today: trim at 2000 lines (`state.rs:17-20`) but `read_all` loads everything; paged segment files fix that |
| Ledger | Disk cap 100 000 entries; memory: 1 page (<= 64 KiB) + prefix filter | Oldest `removed` evicted first, then oldest | |
| Transfer queue / finished list | Already capped: 500 active (`MAX_ACTIVE`), 200 finished (`FINISHED_KEEP`) | Existing behaviour | Keep |
| Replication queue | Existing items map + WAL; cap items at 100 000 | Refuse new publish with an error rather than grow | Today unbounded; the cap and the streaming replay are phase 3 |
| Tombstones (phase 7) | 10 000 entries | Evict oldest | |
| File transfer / encrypt / decrypt / hash | **256 KiB-1 MiB chunk buffers**; segment size is already 4 MiB for erasure coding | Stream | Directed retrieve currently holds the whole plaintext (`daemon/mod.rs:1751-1760`, `Zeroizing<Vec>` + `fs::write`) and `DirectedSend` carries `data: Vec` over IPC; CLI `get` holds `plaintext` (`main.rs:826`). Phase 3/6 move these to the segment streaming already used by `GetToFile` |
| Wipe overwrite | **One 256 KiB buffer**, reused; no per-file allocation | Sequential | A 20 GiB file is overwritten in 80 000 writes, memory unchanged |
| Wipe directory scan | Iterator with a visited-count limit; collect only failures (cap 10 000 reported paths) | Report "and N more" | |
| Key vault (mlock'd) | 4 KiB page: master + derived keys | n/a | See 10.4 |

Total added by this ADR at steady state: **<= 12 MiB** per process
(2 + 1 + 0.25 + 0.25 + 0.25 + 1 buffer + allocator slack), of which the ring
buffer is the largest, configurable down to 1 MiB.

### 10.2 Acceptance targets (accepted by the owner, O7)

Peak "Private Bytes" (Windows) / RSS (Linux), measured as `peak - baseline`
where `baseline` is the same build idle before the scenario:

| Scenario | miasma (daemon) | miasma-desktop |
|---|---|---|
| Idle, stealth on | <= 40 MiB absolute | no more than today's measured value + 4 MiB |
| 1 GiB transfer in progress, log buffer full, 1 000 000-entry history on disk, ledger at cap | **<= baseline + 12 MiB** (about 50 MiB absolute at today's 35-38 MB) | **<= baseline + 12 MiB** |
| Wipe of 20 GiB of shares and 100 000 ledger files | <= baseline + 4 MiB | n/a (GUI only shows progress) |
| History list/scroll through 1 000 000 entries | <= baseline + 2 MiB | <= baseline + 4 MiB |

### 10.3 How it is measured (included in each phase's tests)

- A test helper `mem_probe` (core, `#[cfg(test)]` + a `--features mem-probe`
  integration binary): Windows `GetProcessMemoryInfo(PROCESS_MEMORY_COUNTERS_EX).PrivateUsage`,
  Linux `/proc/self/status` `VmRSS` and `RssAnon`, macOS `task_info` resident size. Samples every
  100 ms on a thread; the test asserts `max(samples) - baseline <= budget`.
- Scenarios scripted in `scripts/mem-budget.ps1` / `.sh` and run in CI on Linux
  and, nightly, on a Windows runner: (a) 1 GiB sparse-file push and receive with
  logging at `debug` and the ring buffer full; (b) generate 1 000 000 history
  records (synthetic writer, not through the network) and page through them;
  (c) fill the ledger and run `WipePlan`; (d) wipe a data dir with 20 GiB of
  sparse share files.
- A micro-test per structure: ring buffer never exceeds its byte cap after 10 M
  appends; LRU cache never exceeds its byte cap; a reader of a 1 GiB record log
  holds one record at a time (allocation counter via a counting global allocator
  in the test binary).
- Desktop: run `miasma-desktop` with `MIASMA_UI_SNAP`-style automation is
  *not* used (it writes screenshots); instead sample the process from the
  harness.

### 10.4 Sensitive memory

- All key material and decrypted secrets use `Zeroizing`/`zeroize` (already
  true for the master key, directed secrets, IPC request secrets and tokens). New
  rule: a `KeyVault` struct owns the master key and derived keys in one
  `Zeroizing<[u8; ...]>` on a page-locked allocation; everything else borrows
  derived keys for one operation.
- `mlock` (Unix) / `VirtualLock` (Windows) **on the key vault page only**, never
  on file buffers: limits are small (`RLIMIT_MEMLOCK` 64 KiB-8 MiB, Windows
  working-set quota requires `SetProcessWorkingSetSize` for a few pages). Failure
  is non-fatal and reported by `miasma status`.
- **Limits to state honestly**: locking keeps the page out of the pagefile
  during normal operation, but it does not prevent leakage through hibernation
  (the whole RAM is written to `hiberfil.sys`), crash dumps, a memory
  acquisition tool, cold-boot, or the stack/heap copies a library made before
  we zeroed them. Plaintext of files in transit passes through ordinary heap
  buffers (256 KiB) and the OS page cache.

## 11. Implementation phases

Each phase is one independently mergeable PR (or a small series), in this order
because each makes the next smaller or safer. All keep existing behaviour for
the `--no-stealth` / not-yet-migrated paths until their phase lands. Note that
because stealth is ON by default also for upgraded installs (O2), phase 2 ships
the one-time upgrade notice and the old-log removal together with the ring
buffer.

| Phase | Content | Value delivered | Tests (besides unit tests) | RAM acceptance |
|---|---|---|---|---|
| **1. Inventory + persisted-paths registry** | `miasma-core::paths` with classes/treatments; route every existing write through it (no behaviour change); CI lint "no raw `fs::write`/`File::create`/`create_dir_all`/`temp_dir` outside the registry"; fix the bridge default data dir to the shared one; move `%TEMP%` downloads to `<data>/tmp`; doc comment fix at `config.rs:456`; **correct `SECURITY.md`** so its hosted-quota statement matches the real defaults (4.5, O12); make the bridge delete `.processed/` originals by default (O13) | Nothing can be written outside a known place; wipe has a complete list; docs and code agree on hosting defaults | Lint test; "registry lists every path the daemon creates in a run of the smoke test" by diffing the data dir against the registry; test that the bridge removes the original after import and keeps it with `keep_originals` | n/a (no new buffers) |
| **2. Stealth logging** | Ring buffer layer, `LogsTail`/`logs` CLI/GUI viewer + export, opt-in diagnostic file logging (size-rotated, no dates), stderr/banner/panic/crash-dump handling, scrubbing lint, one-time upgrade notice + automatic removal of old logs with a "Keep" choice (4.4), `miasma-share:` registration off by default with the explicit "Open links in Miasma" button (4.1) | Largest practical leak closed; default ON for new and upgraded installs | `stealth_writes_zero_log_files`: run a daemon + desktop-worker session at `debug` in a temp data dir and assert the directory has **no** `*.log*`/`lg/` file and stderr is empty; `diagnostic_logging_on_creates_only_lg_files`; panic test (child process panics, assert no stderr text, no core file); lint on tracing arguments; migration test (old `daemon.log.*` removed after the notice, kept when "Keep" is chosen); upgraded-install test (stealth reads as ON with no stored flag); no `HKCU\...\miasma-share` key after a default run, key created only after the button | ring buffer cap test (10 M appends <= cap); `mem_probe` run with full buffer |
| **3. State encryption** | `StateCrypto` (HKDF labels, document + record-log formats), page-locked `KeyVault`, migrate `store_index`, WAL, journals, contacts, history, envelopes, config, prefs; opaque names; startup migration of plaintext state (read old, write new, overwrite+delete old, verify, in that order) | Crypto-erase protects all state | Round trip each store; corruption/truncation/reorder/replay rejection; **migration from a fixture of the previous release's data dir** (including `.corrupt-*`, `.tmp` leftovers); "after deleting only `master.key`, no state file is decodable" test; startup with a half-migrated dir | streaming test (1 GiB record log, one record resident); LRU cap; `mem_probe` 1 000 000 history records |
| **3b. High-security profile (opt-in)** | `vault.dat` (Argon2id-wrapped master key), passphrase prompt in GUI/CLI at start, switch default <-> high with re-wrap and overwrite of the old `master.key`, no unattended start in this profile, wipe overwrites `vault.dat` | Pre-wipe inspection no longer yields the key | Wrong passphrase fails closed; no unwrapped key file exists on disk after switching; switch-back round trip; state encrypted in phase 3 opens only with the unwrapped key; wipe removes `vault.dat` | key page stays one `mlock`'d page |
| **4. Saved-file ledger** | Ledger store; hook `plan/commit` into push receive, transfer receive/`.part`, GUI Save-As/CLI `-o`, temp downloads, log export, bridge originals when kept; history rows get "remove from history only / also delete file" | Everything the app writes outside the store is findable | Crash between `plan` and `commit` leaves a deletable entry; ledger-driven delete removes the file, refuses when `hash8` differs without confirmation; moved-file case reports "not found" | ledger at cap = bounded memory |
| **5. Wipe v2** | Ordered pipeline (8.2), verification pass, report, fail-closed, locked-file handling, registry removal, optional self-delete (default per build, O8), on-screen-only report (O14), confirmed button + `miasma wipe` only (O6), no failure marker (O5), CLI/GUI/FFI entry points | The headline feature | **`wipe_leaves_nothing`**: populate a temp data dir through the real daemon/desktop-worker code (publish, push receive, directed send, history, logs on, ledger files), wipe, then walk the dir and the ledger paths and assert nothing remains except an empty/absent directory; locked-file test on Windows (a handle held open without `FILE_SHARE_DELETE`); interrupted-wipe test (kill after step 2, rerun, assert complete and idempotent); report contains the fixed "not removable" list; registry test with a throwaway key name; **no-trace test**: after a wipe (including a failing one) no report file, no `.w`/retry marker and no `PendingFileRenameOperations` entry exists unless delete-on-reboot was explicitly chosen; self-delete default is off for the installed layout and on for the portable layout | wipe of 20 GiB sparse files stays within +4 MiB |
| **6. Normal deletion, portable build, network preset** | N1-N5, N7 IPC + GUI tabs + CLI; `DirectedRevoke` also performs N1 and drops the WAL item; **portable build** packaging (data beside exe, neutral names, no registry, self-delete on, hosting 0); optional "maximum stealth" preset (4.5) | Day-to-day control; a distribution that leaves no installer trace | Each N-op: removes what it says and leaves what it must; N4 cancels in-flight and removes `.part` (already tested in `transfer_remove_test.rs`); portable run in a temp dir creates no files outside that dir and no registry keys; preset sets exactly `iroh_mode=off`, LAN discovery off, hosting 0 and is not applied by default | paged list through 1 000 000 entries |
| **7. Network retraction (last, low priority)** | Publisher key stored per hosted share; `Retract` message, tombstones, honouring, UI "Requested" state | Best-effort take-down | Forged signature rejected; bare-MID record not retractable; replay after re-publish ignored; tombstone cap eviction; two-node integration test | tombstone cap |

**Migration of existing installs.** Order inside the first start of a build
containing phases 2-3: (1) take the instance lock; (2) read plaintext state
with the old readers; (3) write encrypted files under new names; (4) fsync and
verify by re-reading; (5) overwrite and remove the old files **only after** (4)
succeeds, one by one; (6) remove old logs (4.4); (7) never leave both. A crash
between (3) and (5) leaves both versions; the next start finishes the job (the
old plaintext is removed once the encrypted copy verifies). `.corrupt-*`
contacts copies and `store_index.json.bak*` files found by the scan are removed
too (a developer machine inspected for this ADR had a manual
`store_index.json.bak-*`).

## 12. Consequences

- Positive: the default install stops leaving a readable record of use; a wipe
  becomes real and verifiable; users can delete things normally with a clear
  statement of what that means.
- Negative: more moving parts in persistence (formats, migration); support
  becomes harder because logs are off by default (mitigated by the in-memory
  buffer and the diagnostic switch); the high-security profile costs
  convenience.
- Risks: a bug in the migration can lose state (hence verify-then-delete and a
  fixture-based test); the lint "no raw writes" will initially fail in test
  code (tests are exempt, `#[cfg(test)]`); opaque file names hinder manual
  support (the `miasma doctor` command prints the mapping from the running
  process).

## 13. Open questions

None. All questions of the first draft were decided by the owner on 2026-10-14
(see "Decisions (owner, 2026-10-14)" near the top). Items that remain *design
details* to settle in the implementing PRs, not owner decisions: the exact
wording of the upgrade notice, the key-wrap parameters (Argon2id cost) of the
high-security profile, and the `Retract` wire format in the last phase.
