# ADR-013 appendix: artifact inventory

Companion to `ADR-013-stealth-mode-emergency-wipe-and-deletion.md`. This is the
exhaustive list of everything Miasma (as of `origin/main` at commit `e91471e`)
writes, registers or leaves outside the process, with the proposed treatment
under ADR-013. Line numbers refer to that commit and will drift; the grep
patterns in "How this list was made" reproduce it.

Legend for **Treatment**: `ENC` = encrypt at rest under a key derived from the
master key; `PLAIN` = must stay plaintext (reason given); `NOWRITE` = not
written at all in stealth mode; `WIPE` = nothing to encrypt, but the wipe
removes it; `REG` = goes through the persisted-paths registry (phase 1).
`Wipe method` abbreviations: `X` = crypto-erase (destroy master key, which makes
`ENC` items unreadable); `OW` = overwrite once with random bytes (streamed in
256 KiB chunks) then unlink; `RM` = unlink / remove directory; `REGDEL` =
registry delete.

"Reveals use of Miasma" = the mere existence of the artifact tells an
inspector that Miasma was installed or run. Almost every file does, because of
its name or location; the column says whether the **content** adds more.

## How this list was made

```
grep -rnE "fs::write|File::create|create_dir_all|OpenOptions::new|atomic_write|write_restricted|fs::rename|NamedTempFile|temp_dir" crates/*/src
grep -rnE "master\.key|store_index|replication_wal|daemon\.(port|http|token|log)|desktop\.(lock|log)|pending-link|url-scheme-registered|push_history|contacts\.json|\.part"
grep -rnE "tracing_appender|APPDATA|ProjectDirs|reg\.exe|Command::new" crates scripts installer
grep -rn "RegistryValue|Shortcut|Environment" installer/miasma.wxs
```
plus a read of `android/`, `ios/`, `scripts/` and of the data directory of a
real install. Files that exist only under `#[cfg(test)]` are excluded.

---

## 1. Data directory

**Where it is.** `default_data_dir()` (`crates/miasma-core/src/config.rs:457`)
uses `ProjectDirs::from("", "", "miasma").data_local_dir()`, which is
`%LOCALAPPDATA%\miasma\data` on Windows (note the extra `data`; the doc comment
at `config.rs:456` says `%APPDATA%\miasma` and is wrong),
`~/Library/Application Support/miasma` on macOS, `~/.local/share/miasma` on
Linux. `--data-dir` overrides it for the CLI (`miasma-cli/src/main.rs:481`) and
the desktop (`miasma-desktop/src/main.rs:77`). Android/iOS use `filesDir` /
Application Support (section 9).

**A second, different default exists:** `miasma-bridge` computes its default
as `ProjectDirs::from("dev", "miasma", "miasma").data_dir()`
(`miasma-bridge/src/main.rs:383`), i.e. `%APPDATA%\miasma\miasma\data` (the
**Roaming** profile) on Windows. A bridge started without `--data-dir` keeps
its own `bridge.log` and (via `LocalShareStore::open`) its own `master.key`
there, in a directory that the daemon/desktop wipe never looks at and that a
domain roaming profile may copy to a server.

| # | Artifact | Path pattern | Created by | Content sensitivity | Treatment | Wipe |
|---|---|---|---|---|---|---|
| D1 | master key | `<data>/master.key` (32 raw bytes, owner-only ACL) | `store.rs:258-290` (`atomic_write_restricted`); read at `daemon/mod.rs:220`, `miasma-cli/src/main.rs:1704`, `miasma-ffi/src/lib.rs:225,609,722` | Root secret. Identity (libp2p/iroh keys and the publisher key all derive from it, `crypto/keyderive.rs:31-47`). Name alone reveals Miasma | PLAIN in the default profile (must be readable at start); wrapped by passphrase in the high-security profile (ADR section "Key custody") | OW (random, fsync) then RM. First thing destroyed. The temp file `master.sec.tmp` from `secure_file.rs:31` is removed too |
| D2 | config | `<data>/config.toml` | `config.rs:395-420` (`std::fs::write`, or `write_restricted` if it holds secrets) | Listen address, bootstrap peers, quotas, `iroh_mode`, proxy host/credentials, REALITY/obfs secrets, Shadowsocks password, cert paths, `push.inbox_dir` (a path the user chose). Reveals which circumvention transports are configured | ENC (whole file; "is initialised" check moves to "master.key exists", `desktop/worker.rs:840`) | X + OW + RM. Today only the secret fields are scrubbed (`store.rs:950-962`, `ffi:478-496`); the rest of the file remains |
| D3 | version stamp | `<data>/version` | `config.rs:467` (every start: CLI `main.rs:~520`, desktop `main.rs:~120`) | Miasma version string | NOWRITE in stealth (upgrade detection moves into the encrypted state) | RM |
| D4 | store index | `<data>/store_index.json` (+ `store_index.tmp` on crash) | `store.rs:236-241`, `atomic_write` `store.rs:245-254` | For every stored share: content address, size, last-access time, origin (owned/hosted), `hosted_principal` = remote peer id, `PieceKey` = (mid_prefix, segment, slot). Reveals **what I published, what I host for whom, and when I last read it** | ENC (record-per-line AEAD log, so listing needs no whole-file load) | X + OW + RM |
| D5 | share blobs | `<data>/shares/<blake3>.ms` (+ `.tmp` on crash) | `store.rs:594,727` | Already XChaCha20-Poly1305 under a per-file HKDF key from the master key (`store.rs:301-308`). File **names** are content addresses; count and sizes are visible; mtime shows when stored | PLAIN (already ciphertext). Optionally a fixed-size padding is out of scope | X is sufficient for confidentiality; OW + RM for the "files exist" trace, bounded by the time budget (largest shares last) |
| D6 | replication WAL | `<data>/replication_wal.jsonl` (+ `.jsonl.tmp`) | `daemon/replication.rs:155-156,357-390` (append + fsync, compaction by rename) | Full DHT records (MID, publisher key, shard locations incl. remote peer ids/addresses, timestamps). Reveals what I published and to whom it was replicated | ENC (streaming record log) | X + OW + RM. Old compacted copies are unrecoverable by the app (FS) |
| D7 | control token | `<data>/daemon.token` | `daemon/control_auth.rs:174-219` (ACL via `icacls`) | Local control credential only; reveals that a daemon runs/ran | PLAIN (must be readable by CLI before it can talk to the daemon). Removed on clean exit (`control_auth.rs:272`) | RM (+OW 64 bytes). Stale copy possible after a crash: covered by the registry and by wipe |
| D8 | IPC / HTTP port files | `<data>/daemon.port`, `<data>/daemon.http` | `daemon/ipc.rs:1085-1101` | Port numbers; presence = daemon running | PLAIN (discovery). Removed on exit; stale after crash (`self_heal.rs:246`) | RM |
| D9 | instance lock | `<data>/desktop.lock` | `miasma-desktop/src/link.rs:58` | Empty; presence = GUI ran | PLAIN (lock). Could move to the OS lock namespace (named mutex / `flock` on a temp-less path) in stealth | RM |
| D10 | pending link | `<data>/pending-link.txt` (+ `.<pid>.tmp`) | `link.rs:85-86` | A `miasma-share:` link (MID + publisher key + protection flag) for <= 60 s (`PENDING_MAX_AGE`, `link.rs:35`) | NOWRITE in stealth: hand the link over through the loopback IPC port instead | RM |
| D11 | URL-scheme marker | `<data>/url-scheme-registered.txt` | `link.rs:187,245` | Path of the exe the scheme was registered for (a full install path, possibly a user folder) | NOWRITE in stealth and with `register_url_scheme = false` (see R1) | RM |
| D12 | desktop prefs | `<data>/desktop-prefs.toml` | `miasma-desktop/src/variant.rs:40,68-71` | UI mode, theme, locale (language of the user) | ENC | X + OW + RM |
| D13 | contacts | `<data>/contacts.json` (+ `.corrupt-<unix-time>` copies) | `push/store.rs:22,183-196`; corrupt copy kept deliberately `push/store.rs:175-179` | Labels the user gave to people, their iroh endpoint IDs, permissions, add times. The social graph | ENC. The "never deleted" `.corrupt-*` policy is changed: encrypted too, and removed by wipe | X + OW + RM (all `contacts.json*`) |
| D14 | push history | `<data>/push_history.jsonl` (+ `.jsonl.tmp`) | `push/state.rs:17,324-330,371` (capped to 1000 lines, trimmed at 2000) | Per file: name, size, direction, contact id + label, **`saved_as` full path**, error text, finish time. The best single "what was sent/received" record | ENC (paged segments; count cap enforced on disk) | X + OW + RM |
| D15 | push inbox | `<data>/inbox/` or `push.inbox_dir` (any user path, `config.rs:70-75`) | `push/service.rs:798,839,1168-1175` | **The received files themselves, plaintext** (and `.<hash>-<size>.part` while receiving, `service.rs:802`) | Ledger (L1): every file listed in the saved-file ledger. Not encrypted (the user must be able to open it) | OW + RM per file via ledger; the directory is removed if the app created it and it is empty. Files moved/copied away are NOT reachable |
| D16 | partial receives | `<output>.part` next to the user-chosen output path | `transfer/journal.rs:53-58`; `transfer/receive.rs:668` | Plaintext (or ciphertext-then-verified) partial file at a user path | Ledger (L2) entry written **before** the `.part` is created | OW + RM via ledger; also by `TransferRemove` (`transfer/jobs.rs:317,405`) |
| D17 | transfer journals | `<data>/transfers/recv-<mid>.json`, `send-<hash>.jsonl` | `transfer/journal.rs:45,72`; `transfer/publish_journal.rs:62`; dir `transfer/jobs.rs:89-90` | `output_path`, `part_path`, MID, share id, segment progress; send journal holds the **source file path**, size, mtime, MID | ENC (small docs: whole-file AEAD; send journal: record log) | X + OW + RM (`transfers/` is removed as a tree) |
| D18 | directed envelopes | `<data>/directed/incoming/<id>.json`, `directed/outgoing/<id>.json` | `directed/inbox.rs:78-79,91-136,196-230` (`atomic_write_restricted`) | Sender/recipient sharing keys, state, MID, retention, password-attempt counter, filename. Plus sidecars `.challenge`, `.peer`, `.peer_id` (`inbox.rs:319-390`) | ENC | X + OW + RM (tree) |
| D19 | diagnostic daemon log | `<data>/daemon.log.<YYYY-MM-DD>` | `miasma-cli/src/main.rs:495-498` (`tracing_appender::rolling::daily`); only 3 files kept by `cleanup_old_logs` | See section 4 | NOWRITE in stealth; opt-in diagnostic logging writes size-rotated, encrypted `d0/d1` files | OW + RM (`daemon.log*`) |
| D20 | desktop log | `<data>/desktop.log.<YYYY-MM-DD>` | `miasma-desktop/src/main.rs:93` | See section 4. **Never rotated** (a real install had files from March to October). The file **names carry the dates the app was used** | NOWRITE in stealth | OW + RM (`desktop.log*`) |
| D21 | bridge log | `<bridge data>/bridge.log.<date>` | `miasma-bridge/src/main.rs:36` | Imported file names/hashes, BitTorrent info-hashes | NOWRITE in stealth | OW + RM |
| D22 | bridge index | `<bridge data>/...` BT info-hash -> MID table | `miasma-bridge/src/index.rs:82` (append) | **Maps torrent info-hashes to MIDs** (what was imported) | ENC | X + OW + RM |
| D23 | bridge inbox | user-chosen `--inbox-dir` with marker `.miasma-bridge-inbox` and `.processed/` | `bridge.rs:474-490,1707-1745` (moves imported originals into `.processed/`) | **Plaintext originals of everything imported are kept** in `.processed/` | Ledger (L3); the retention of originals becomes opt-in | OW + RM via ledger |
| D24 | bridge torrent downloads | `%TEMP%\miasma-bridge-downloads` | `miasma-bridge/src/torrent.rs:44,108-112` | Downloaded torrent payloads, plaintext | Ledger (L3); wipe also removes the directory | OW + RM |
| D25 | smoke-script logs | `<data>/stdout.log`, `<data>/stderr.log` | **Not the product.** Only `scripts/smoke-installed.ps1:192-193`, `smoke-windows.ps1:119-120`, `smoke-loopback.ps1:103,145`, `bridge-validation.ps1:211-212` (`Start-Process -RedirectStandard*`) | Daemon stdout/stderr (peer ids, addresses, paths). They exist because those scripts launch `miasma daemon` with redirected output. On an inspected developer machine they were found at **`%APPDATA%\miasma\stdout.log|stderr.log`** (Roaming) next to `%APPDATA%\miasma\miasma\data` (the bridge default, D-section header) | None in product. Scripts must write to a throwaway temp dir and delete it; documented as a test-only artifact | RM if found under the data dir; Roaming copies are listed in the wipe report as "outside registry, found by scan" |
| D26 | UI snapshots (dev) | `$MIASMA_UI_SNAP` directory | `miasma-desktop/src/app/tour.rs:241-269` | Screenshots of the GUI (dev/QA only, env-gated) | Refuse to run when stealth mode is on | n/a |

## 2. Temp directory and files outside the data directory

| # | Artifact | Path | Created by | Sensitivity | Treatment | Wipe |
|---|---|---|---|---|---|---|
| T1 | decrypted directed-share download | `%TEMP%\miasma-retrieve-<envelope_id>.tmp` | `miasma-desktop/src/worker.rs:1366`; CLI `miasma-cli/src/main.rs:1975` (then renamed/copied to the final name) | **Plaintext of the received file in the shared temp dir**, named with the envelope id. Removed only if the user finishes the Save dialog (`app.rs:341-356,399,466,2876`); a crash or an abandoned dialog leaves it | Move into `<data>/tmp/` (REG), create with owner-only ACL, register in ledger (L2) before the daemon writes it, remove with OW | OW + RM via ledger; plus scan of `<data>/tmp` |
| T2 | decrypted public-share download | `%TEMP%\miasma-retrieve-<pid>-<nonce>.tmp` | `miasma-desktop/src/worker.rs:1049-1056,1366` (`GetToFile`, `daemon/mod.rs:1222-1240` streams into it) | Same | Same | Same |
| T3 | user Save-As targets | any path the user picks | `miasma-desktop/src/app.rs:446-466,1070-1100,1556,2276`; `transfers.rs:743-753`; CLI `-o` (`miasma-cli/src/main.rs:828`) | Plaintext received files. `app.rs:1551,2271` also write a **diagnostics report** to a user path | Ledger (L2) on the successful write; the GUI records the final path when the rename/copy succeeds | OW + RM via ledger |
| T4 | copy fallback residue | source temp file after `fs::copy` | `app.rs:447-450,1075-1077` (rename, falling back to copy + remove) | A cross-volume save copies, then removes the temp with plain `remove_file` (`ok()`) | Use OW on the temp | n/a |
| T5 | atomic-write temp files | `<name>.tmp`, `<name>.sec.tmp` next to the target | `store.rs:245-254`, `secure_file.rs:31`, `push/state.rs:369-371` | Partial copies of the same sensitive documents if the process dies between write and rename | REG: startup sweep deletes `*.tmp` older than boot (`store.rs:350` already does it for shares/) | OW + RM (`*.tmp`, `*.sec.tmp`) |
| T6 | tunnel helper output | none on disk (`cloudflared` stderr is piped) | `miasma-cli/src/tunnel.rs:87-93` | `cloudflared` itself may create `~/.cloudflared` and its own logs, outside Miasma's control | Documented limit | not reachable |
| T7 | browser history from `miasma web` | browser history: `http://127.0.0.1:<port>/#...` | `miasma-cli/src/web_link.rs:111-124` (`rundll32 url.dll`, `open`, `xdg-open`) | The default browser records the URL, titles, and caches the web UI | In stealth, `miasma web` prints the URL instead of opening the browser, unless `--open` | not reachable (browser data) |

## 3. Windows registry and shell integration

| # | Artifact | Key | Created by | Sensitivity | Treatment | Wipe |
|---|---|---|---|---|---|---|
| R1 | URL scheme `miasma-share:` | `HKCU\Software\Classes\miasma-share` (`(Default)`, `URL Protocol`, `shell\open\command` = `"<exe>" "%1"`) | **At every GUI start**, by `reg.exe` from `miasma-desktop/src/link.rs:186-247` (spawned in `main.rs:~115`) | Permanent proof of use, full exe path, survives uninstall (HKCU is not managed by the MSI) | Config `register_url_scheme` (default **off** in stealth, on otherwise); registered only when the user asks | `reg delete HKCU\...\miasma-share /f` (REGDEL), done via the Win32 registry API, not `reg.exe` (command lines are logged by EDR/Sysmon/4688) |
| R2 | MSI product registration | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{...}` (Add/Remove Programs), Windows Installer database `C:\Windows\Installer\<id>.msi`, `HKLM\SOFTWARE\Classes\Installer\Products\...` | `installer/miasma.wxs:13-17` (`Scope="perMachine"`, needs admin) | App name, version, install date, publisher, install folder | Not removable by the app (needs elevation and MSI). Documented. Offer a portable zip build (no registry, no installer cache) | Only through the MSI uninstall; the wipe report lists it as "not removed" |
| R3 | Start Menu shortcuts + HKCU shortcut keys | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Miasma Protocol\*.lnk`; `HKCU\Software\Miasma Protocol` | `miasma.wxs:110-160` | Named shortcuts | MSI-managed | MSI uninstall |
| R4 | PATH entry | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path` | `miasma.wxs:163-177` (`Environment`) | Install folder in PATH | MSI-managed | MSI uninstall |
| R5 | magnet / .torrent handlers | `HKLM\SOFTWARE\Classes\Miasma.Magnet*`, `Miasma.TorrentFile`, `...\Capabilities`, `RegisteredApplications\Miasma`, `...\.torrent\OpenWithProgids` | `miasma.wxs:187-260` | Same | MSI-managed | MSI uninstall |
| R6 | Firewall rules | none found in the repo (`grep -i firewall installer scripts` = no matches). The OS may still show a first-run "allow access" prompt which creates `HKLM\...\FirewallRules` entries | n/a | A Windows Defender Firewall prompt is an OS-level trace of the first listen | Document; recommend loopback-only listen for WSS (already default `127.0.0.1`) | not reachable |
| R7 | Run keys / services / scheduled tasks | none found | n/a | n/a | n/a | n/a |
| R8 | delete-on-reboot entry (created by the wipe itself) | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations` | `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, **only as an explicit last resort** (ADR section "Locked files") | Lists the paths still to delete: a trace **of the wipe** | Off by default; asks first; needs admin and usually fails for a normal user | cleared by the OS after reboot |
| R9 | OS "recent files" entries for files Miasma writes | `HKCU\...\Explorer\RecentDocs`, `OpenSavePidlMRU`/`LastVisitedPidlMRU` (common dialog MRU: written by the **Save As dialog** `rfd::FileDialog`), `%APPDATA%\Microsoft\Windows\Recent\*.lnk`, Jump Lists `...\Recent\AutomaticDestinations` | Written by Windows, not Miasma, when `rfd` opens the common dialog (`app.rs:446,903,1070,1187,1551,2271`; `contacts.rs:1270`; `transfers.rs:743,1676`) and when Explorer opens the saved file | Names of folders and files the user chose; **the saved file name appears here even after the app wipes the file** | Not removable by Miasma without touching OS state (forbidden by the owner). Mitigation: stealth mode offers an in-app save into a Miasma-managed folder and an in-app opener, and the docs list what the user must clear by hand (Settings > Privacy, Jump Lists) | not touched (listed in the wipe report as "OS artifact, not removed") |
| R10 | Prefetch, Amcache/ShimCache, UserAssist, BAM, SRUM, Windows Search index, thumbnail cache, `$MFT`/USN journal, shellbags, ETW/Event Log, Defender/EDR telemetry | `C:\Windows\Prefetch\MIASMA-DESKTOP.EXE-*.pf`, `HKCU\...\UserAssist`, `Amcache.hve`, `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`, ... | Written by the OS for **any** executable that ran | Name of the exe, run count, last 8 run times, files touched in the first 10 s (prefetch) | Out of scope. Not touched. Renaming the exe before first run (portable build with a neutral name) reduces what is recorded | not touched |

## 4. What the logs contain (why D19-D21 are sensitive)

Taken from `info!`/`warn!` call sites and from a real `daemon.log`:

- local peer id and iroh endpoint id (stable identity; `daemon.log` line "Miasma node: peer_id=...", "iroh direct transport started endpoint=...");
- every bootstrap address including the **LAN IP** (`daemon/mod.rs` startup banner, `network/node.rs` "bootstrap addr");
- the full **inbox path** and the user's own fingerprint (`push/service.rs:222`);
- that n0 discovery and mDNS are on (`transport/iroh_direct.rs`, quoted in SECURITY.md);
- **content ids** at publish and replication time (`daemon/mod.rs:2171`, `replication.rs:408,499`);
- directed-share envelope ids with remote peer ids and verbs ("received", "challenge confirmed", "retrieved successfully", "sender-revoked", "recipient-deleted"; `daemon/mod.rs:1886-2252`, `network/node.rs:4547-4800`);
- contact removal and cancelled transfers (`push/service.rs:296`), push refusals with the remote fingerprint (`service.rs:1000`);
- timing: every line is timestamped; the **file name carries the date**;
- `miasma status`/diagnostics (`app.rs:1551,2537-2542`) print the log location, and the GUI's "export diagnostics" writes a report to a user path.

File names of transferred files are mostly **not** logged by the core (the
history file has them, D14). The ring buffer must keep it that way: a lint test
(phase 2) fails the build if a `tracing` macro argument is a path, file name or
contact label.

## 5. Process outputs and crash artifacts

| # | Artifact | Where | Created by | Treatment |
|---|---|---|---|---|
| P1 | stderr of `miasma daemon` (console scrollback, redirected files, systemd journal) | terminal / launcher | `miasma-cli/src/main.rs:497-513` always adds a stderr layer; startup banner `main.rs:1735-1745` prints peer id, bootstrap addresses, control port, log path | In stealth the stderr layer is off and the banner is reduced to one line; `--log-stderr` re-enables it explicitly |
| P2 | stdout/stderr of child processes | none: desktop spawns the daemon with null stdio (`desktop/worker.rs:949-952`); bridge import pipes both and logs stderr text into the UI (`worker.rs:1229-1260`) | Keep null; never persist piped text |
| P3 | Rust panic message and backtrace | stderr; `RUST_BACKTRACE` honoured | no `panic::set_hook` anywhere in the repo (verified by grep) | Install a hook that writes only to the ring buffer and aborts, with a fixed text; strip payload and location in stealth |
| P4 | Windows Error Reporting / crash dumps | `%LOCALAPPDATA%\CrashDumps` (if `LocalDumps` is configured), `C:\ProgramData\Microsoft\Windows\WER\ReportArchive` | OS, on unhandled exception / fail-fast | At start: `SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS)`, an unhandled-exception filter that terminates silently. WER reports already created are OS state: not removable |
| P5 | Unix core dumps | `core`, `/var/lib/systemd/coredump`, macOS `~/Library/Logs/DiagnosticReports` | OS | `setrlimit(RLIMIT_CORE, 0)` and `prctl(PR_SET_DUMPABLE, 0)` on Linux; `PT_DENY_ATTACH` is not used (breaks debuggers, no benefit offline) |
| P6 | memory: keys and plaintext | process RAM, pagefile, hibernation file, crash dump | `Zeroizing` is used for the master key (`store.rs`), directed secrets (`daemon/mod.rs:1028,1751`), tokens (`control_auth.rs`), IPC request secrets (`ipc.rs:474`). **No `mlock`/`VirtualLock`** anywhere (grep) | Phase 3 adds a page-locked key vault; limits in the ADR |

## 6. macOS, Linux, Android, iOS

| # | Artifact | Path | Notes / treatment |
|---|---|---|---|
| M1 | macOS app bundle | `/Applications/Miasma.app` with `Info.plist` (`scripts/build-macos.sh:21-36`, `CFBundleIdentifier org.miasma-protocol.desktop`) | URL scheme is *not* registered by the code (`link.rs:170` comment: needs `CFBundleURLTypes`; not present in the generated plist); LaunchServices and `~/Library/Preferences/org.miasma-protocol.desktop.plist` entries may appear via the OS |
| M2 | macOS user data | `~/Library/Application Support/miasma` (same files as section 1), unified log entries from the OS | Same treatment; the app does not write `~/Library/Logs` |
| L1 | Linux user data | `~/.local/share/miasma` | Same. No `.desktop` file is installed by the code. Shell history (`miasma wipe`) is outside the app: documented |
| L2 | systemd / launchd units | none in the repo | n/a |
| A1 | Android data | `filesDir` (`MainActivity.kt:59`, `MiasmaService.kt:38`, `MiasmaViewModel.kt:31`): `master.key`, plus `master.key.enc`, `master.key.iv` (`KeystoreHelper.kt:78-95`; `ffi/src/lib.rs:500`), `Prefs` SharedPreferences (`Prefs.kt:7,48`) | `allowBackup="false"` (`AndroidManifest.xml:22`) good. Wipe already deletes the Keystore entry (`MiasmaViewModel.kt:124-136`) = crypto-erase of the wrapped key. `SharedPreferences` XML is not covered by the FFI wipe |
| A2 | Android FileProvider | `res/xml/file_paths.xml` (scoped so `master.key` is not shareable) | Shared files copied by other apps are out of reach |
| A3 | Android logcat | `Log.*` in Kotlin; Rust `tracing` has no Android layer wired | Keep it that way; lint |
| I1 | iOS data | Application Support (`MiasmaViewModel.swift:43-62`, `WebBridgeView.swift:99-101`) | iOS backup (iTunes/iCloud) may include it unless `isExcludedFromBackup` is set: phase 3 sets it on the data dir. No self-delete possible |

## 7. Network-side traces (documentation of limits; no task)

What a remote observer (ISP, state firewall, network operator on the LAN) can
see, by feature. Source: `config.rs:176-200`, `transport/iroh_direct.rs:8-27,
95-205`, `SECURITY.md` "Known security limits", `network/node.rs` (mDNS
`3423`, Kademlia record TTL `5402`).

| Feature | Observer sees | Reduced by |
|---|---|---|
| iroh `n0` mode (default) | DNS/HTTPS to n0's discovery (pkarr, `dns.iroh.link`-style names) and relay hostnames; TLS SNI; your IP; **n0 itself learns your endpoint id (= publisher key), home relay and IPs** | `transport.iroh_mode = off`, or `custom` with your own relay and `iroh_discovery = false` |
| iroh LAN discovery (mDNS, default on) | Everyone on the LAN sees an announcement with the endpoint id and LAN addresses | `iroh_lan_discovery = false` |
| libp2p QUIC (Kademlia DHT, UDP) | UDP/QUIC flows to many peers, fixed protocol ids in the handshake, bootstrap peer addresses | obfuscated QUIC, WSS transport, Shadowsocks, Tor (`config.rs:219-250`) |
| WSS via tunnel (`miasma tunnel`) | Connection to a Cloudflare edge: looks like ordinary HTTPS to that CDN | n/a. The tunnel's own metadata is Cloudflare's |
| Traffic volume and timing | Bulk transfers have a recognisable shape; relay is ~1 MiB/s | none (padding/cover traffic is a separate roadmap item: `cover_traffic.rs`) |
| Hosting shares for others | Inbound connections and disk growth on this machine | `hosted_quota_mb = 0`. SECURITY.md says this is the default, but the code default is 1024 MiB (`config.rs:78`); the ADR corrects the doc and sets 0 for the maximum-stealth preset and the portable build |

A stealth-oriented profile (`iroh_mode=off`, `iroh_lan_discovery=false`,
`hosted_quota_mb=0`, WSS-over-tunnel or Tor) is a **configuration preset**
offered by the ADR as an optional "maximum stealth" preset (section 4.5, owner
decision O10); it is not the default and not part of the wipe work.

## 8. The ten artifacts the current wipe misses (summary)

Current wipe (`store.rs:910-975` `distress_wipe`, `ffi/src/lib.rs:465-540`,
`miasma-cli/src/main.rs:1439-1480`) zeroes and removes `master.key` and scrubs
secret fields in `config.toml`. It removes nothing else. Missed:

1. `daemon.log.*` / `desktop.log.*` / `bridge.log.*` (D19-D21) with peer ids, LAN IP, inbox path, MIDs, envelope ids and usage dates.
2. The received files in `inbox/` and in `push.inbox_dir` (D15), plaintext.
3. `push_history.jsonl` (D14) with names, labels and `saved_as` paths.
4. `contacts.json` (D13) and its `.corrupt-*` copies: the social graph.
5. `store_index.json` and `shares/` (D4, D5): which content, what was hosted for whom.
6. `replication_wal.jsonl` (D6): what was published.
7. `transfers/*.json(l)` (D17): source and destination paths of every transfer.
8. `directed/incoming|outgoing/*` (D18).
9. `%TEMP%\miasma-retrieve-*.tmp` (T1, T2): plaintext copies.
10. `HKCU\Software\Classes\miasma-share` + `url-scheme-registered.txt` (R1, D11), `desktop-prefs.toml`, `version`, `desktop.lock`, `daemon.*` files (D3, D7-D12).

Also missed and surprising: the bridge's separate default data dir in Roaming
(section 1) and `.processed/` originals in the bridge inbox (D23).
