# Local 2-Node P2P Smoke Runbook

Manual smoke test for the full `network-publish → network-get` path using two
local processes on 127.0.0.1.

## Prerequisites

```
cargo build --release
# Binaries land in: target/release/miasma
```

Set an alias for convenience (optional):
```
alias miasma="./target/release/miasma"
```

---

## Terminal 1 — Node A (publisher / share holder)

```sh
# 1. Initialise Node A's data directory.
miasma --data-dir /tmp/miasma-a init

# 2. Dissolve a file and publish it to the P2P network.
#    This node stays alive (Ctrl-C to stop) so Node B can fetch shares.
echo "hello from the other side" > /tmp/hello.txt
miasma --data-dir /tmp/miasma-a network-publish /tmp/hello.txt
```

Expected output (ports/IDs differ each run):

```
Publishing /tmp/hello.txt (26 bytes) k=10 n=20 …

✓ Published MID: miasma:3xfGhR...

Bootstrap addresses for this node (copy one for `--bootstrap`):
  /ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooWxxxx
  /ip4/192.168.1.5/udp/54321/quic-v1/p2p/12D3KooWxxxx

Retrieve command for Node B:
  miasma network-get miasma:3xfGhR... \
      --bootstrap /ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooWxxxx -o output.bin

Serving shares. Press Ctrl-C to stop.
```

**Leave this terminal running.**

---

## Terminal 2 — Node B (retriever)

Copy the MID and bootstrap address printed by Terminal 1, then:

```sh
# 1. Initialise Node B's data directory (separate from Node A).
miasma --data-dir /tmp/miasma-b init

# 2. Retrieve the content from the network.
miasma --data-dir /tmp/miasma-b network-get miasma:3xfGhR... \
    --bootstrap /ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooWxxxx \
    -o /tmp/retrieved.txt

cat /tmp/retrieved.txt
# → hello from the other side
```

Expected output:

```
Waiting for DHT bootstrap…
Retrieving miasma:3xfGhR... from network…
✓ Written to /tmp/retrieved.txt
```

---

## How it works

```
Node A (network-publish)          Node B (network-get)
─────────────────────────         ────────────────────────
  dissolve(file)
  store shares locally
  DHT.put(DhtRecord)              connect → bootstrap Node A
  ← Kademlia FIND_NODE ──────────────────────────────────
  ──── routing table exchange ────────────────────────────
                                  DHT.get(MID) → DhtRecord
                                    (fetched from Node A)
                                  for each shard:
  ←── ShareFetchRequest ─────────────────────────────────
  ShareFetchResponse ────────────────────────────────────→
                                  reconstruct(shares)
                                  → plaintext
```

Key design points:
- `network-publish` stores the DHT record **locally first** so Node B's
  `GET_VALUE` query succeeds even before any remote replication quorum.
- Node B bootstraps AFTER Node A is serving; the 2-second post-bootstrap
  sleep gives Kademlia routing tables time to converge.
- All share transport uses `/miasma/share/1.0.0` request-response over QUIC.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `network-publish` prints no bootstrap addresses | Port 0 binding took >300ms | Run with `MIASMA_LOG=debug` and check `NewListenAddr` events |
| `retrieve_from_network` returns `DhtRecord not found` | Bootstrap sleep too short or Node A shut down | Keep Node A running; increase sleep if needed |
| `OutboundFailure::DialFailure` in Node B logs | Wrong bootstrap addr or Node A not up | Double-check the addr printed by Node A |
| `InsufficientShares: need 10, found 0` | DHT record found but share fetch to Node A failed | Check Node A is still running; verify listen addr is reachable |

## Daemon mode alternative

If you want Node A to be a long-running daemon **separate** from the publish step:

```sh
# Terminal 1: start daemon, observe bootstrap addr in output
miasma --data-dir /tmp/miasma-a init
miasma --data-dir /tmp/miasma-a daemon
# prints one line; `miasma status` shows the Peer ID + Bootstrap addresses

# Terminal 1 (second shell): dissolve and start serving
#   Currently: use network-publish (combines dissolve + DHT publish + serve)
#   Future: daemon will support hot-publish via IPC
```

The `daemon` command is best suited for a node that participates in the network
as a passive relay/store; use `network-publish` when you want to dissolve and
immediately serve a specific file.


---

## Logs: memory only by default

Miasma does not write log files by default (stealth mode, `privacy.stealth_mode`
= true, also after an upgrade). The daemon, the desktop app and the bridge keep
their log lines in a memory buffer of 2 MiB each (1-8 MiB with
`privacy.log_buffer_mib`; one line is cut at 512 bytes and the oldest lines are
dropped when it is full). Library code prints nothing to the console, and a panic
leaves one fixed line in the buffer instead of a message or backtrace.

```sh
miasma logs                 # newest 200 lines of the running daemon
miasma logs --lines 1000 --follow
miasma status               # shows whether logs go to memory only or to files
```

The desktop app shows the same buffers under Settings > Logs, with a **Copy**
button (clipboard only; nothing is exported to a file).

To troubleshoot with files, turn on diagnostic logging in Settings > Logs or with
`miasma config --key privacy.diagnostic_logging --value true`. Files are
written to the `lg` folder of the data directory (neutral names, no dates, 5
files of 2 MiB per program, file names, paths, contacts and addresses
shortened or removed). The desktop app shows a warning while this is on, and so does
`miasma status`. Turning it off deletes the files (overwritten with zeros first).
With `privacy.stealth_mode = false` (or `MIASMA_STEALTH=0` for one run) log lines
also go to the console and the log files are written as in earlier versions.

**Old log files** (`daemon.log.*`, `desktop.log.*`, `bridge.log.*` and, on
Windows, console-output files of the old test scripts in the per-user
application folder) are no longer written. After an upgrade the desktop app
asks once whether to delete them now (default) or keep them. A daemon without a
window prints one line on its first start and removes the files on a later start;
set `MIASMA_KEEP_OLD_LOGS=1` or run `miasma logs --keep-old` to keep them, or
`miasma logs --delete-old` to remove them at once.

What this cannot do: Windows Error Reporting and the operating system's own
crash-dump settings (core dumps, `systemd-coredump`, crash reporters) are
machine-wide policy. Miasma turns off the error dialog and core dumps for its own
processes where the system allows it, but dumps written earlier, the page file and
hibernation files, and records the operating system keeps about any program that
ran (Prefetch, event logs, endpoint-security tools) are outside its control.

## Updates (check at start, update in place)

Miasma can look for a newer build and install it. Everything is off the data
path: the only connection it makes for this is one HTTPS request to the public
GitHub API (`api.github.com`, then `github.com` for the download), with no
token, no cookie and no identifier beyond `User-Agent: miasma-update/<version>`.

### Settings (`config.toml`, `[update]`)

```
miasma config --key update.mode --value notify    # off | notify (default) | auto
miasma config --key update.channel --value beta   # stable | beta (default)
miasma config --key update.check_at_start --value true
miasma config --key update.local_build_dir --value C:\build\release   # developers
```

| mode     | what happens                                                                 |
|----------|------------------------------------------------------------------------------|
| `off`    | Nothing. No connection, no program is started to look at a build folder.     |
| `notify` | One check after the start; the window shows a banner (Update now / Later / Skip this version). Nothing is installed until you agree. |
| `auto`   | One check after the start; the update is downloaded, verified and installed by itself, but only while no transfer, push or chat send is running. The window then restarts itself. |

The check never runs in the first 60 seconds after start (plus up to 60 seconds
of random delay), only once per start, and a failed check (offline, rate limit)
is silent in the window and is reported as `failed`, never as "up to date".
The Settings page has an Updates section with the same mode switch, a
**Check now** button (at most one answer per 30 seconds) and the status.

### Command line

```
miasma update check    # prints available / none / failed, exit code tells them apart
miasma update apply    # download, verify, install (nothing while a transfer is running)
miasma update status   # settings, running build, any update in progress
```

Exit codes: `0` nothing newer (or installed), `10` available, `11` a newer
release exists but cannot be installed here (no file for this platform, or no
`SHA256SUMS.txt`), `20` the check failed, `30` updates are off, `40` busy,
`41` refused (did not verify), `42` the new version did not start and the old
one was restored, `43` this installation cannot be updated in place, `44` other
error.

### What is checked before anything is replaced

* Releases are ordered by semantic version (a pre-release such as
  `0.4.0-beta.2` is below `0.4.0`); the `stable` channel ignores pre-releases.
* The release must contain `SHA256SUMS.txt`, and the downloaded archive must
  match its line. A release without it is refused.
* If public keys are pinned in the program, `SHA256SUMS.txt.sig` (a detached
  Ed25519 signature over `SHA256SUMS.txt`) must verify under one of them. No key
  is pinned yet, so only the SHA-256 check applies (integrity, not who
  published).
* The archive is read as untrusted: unsafe paths (`..`, absolute, drive
  letters, links) refuse the whole archive; only the Miasma programs are
  extracted. The download lives in `<data dir>/update/` and is deleted after.

### How the swap works, and the way back

A running program cannot be overwritten on Windows but can be renamed:

```
miasma.exe          -> miasma.exe.old.<id>
miasma.exe.new      -> miasma.exe
miasma.exe --version must answer within 10 s       (else everything is renamed back)
miasma.exe.old.<id> -> miasma.exe.prev             (the one backup that is kept)
```

The same is done for `miasma-desktop.exe` and `miasma-bridge.exe`. Only
`miasma.exe` is started for the check, never the desktop program. A small
journal (`update/journal.json`) records the phase, so an update interrupted by a
crash or a power cut is finished or undone at the next start. On macOS the
`.app` bundle is replaced the same way (`Miasma.app.prev` is the backup); if
the folder is not writable the update is not attempted and the window says so.
To go back by hand, stop Miasma and rename `<program>.prev` over `<program>`.

Restart Miasma after an update. A background service the window started stops
when the window closes, so the new one starts with it; a service you started
yourself keeps running the old version until you stop and start it. Launcher
scripts such as `Miasma.cmd` are not touched.

The GitHub requests use the same certificate trust as the relay connections: the
operating system's store, plus the file named by `transport.iroh_extra_ca_pem`
when a network re-signs HTTPS. If GitHub cannot be reached the status says it
could not check (never "up to date") and Miasma keeps working as before.

### Developer rebuild flow

With `update.local_build_dir` set to a build folder, a build there whose
`miasma --version` build id differs from the running one and whose file is newer
is offered like a release (no network, no checksum file: the folder is trusted
because you chose it). To copy a fresh build into an install folder without the
app, from outside it:

```
.\scripts\dev-update.ps1 -BuildDir target\release -InstallDir C:\Tools\miasma
.\scripts\dev-update.ps1 -InstallDir C:\Tools\miasma -StopOwn   # stop only processes running from that folder
```

It does the same rename-swap and `.prev` rotation, refuses while a Miasma
process runs from the install folder (unless `-StopOwn`, which stops exactly the
processes whose path is inside it, by process id), and puts the old files back if
the new `miasma.exe` does not answer `--version`.

## State files are encrypted at rest

Miasma's own records (the contact list, the transfer history and transfer
progress files, the replication queue, the directed-share inbox, the share
index and the desktop preferences) are stored encrypted with a key derived from
your master key (`master.key` in the data directory). Files from an earlier
version are converted automatically the first time the new version starts; the
old plaintext copy is overwritten and removed.

- Deleting `master.key` makes these files unreadable, even if the files
  themselves are still on the disk.
- **Back up `master.key`** if you need your contacts and history after
  reinstalling the operating system or moving to a new computer. Without it
  Miasma starts with an empty contact list and a new identity.
- Miasma never overwrites an encrypted file it cannot open. A file that cannot
  be opened with the current key (for example after `master.key` was replaced)
  is kept next to the others with `.corrupt-<time>` in its name instead of being
  deleted, and it opens again if the original `master.key` is put back and the
  suffix is removed.
- `master.key` itself, `config.toml`, the received files and the share blobs
  are not covered by this: the key must be readable to start, the configuration
  is read before the key is available, and received files are yours to open.
  This protects the records on a disk you no longer have the key for; it does not
  protect a computer that is running and unlocked, or a copy of the whole data
  directory that includes `master.key`.

### 保存データの暗号化(日本語)

連絡先、転送履歴・転送の進行記録、複製キュー、宛先指定共有の受信箱、共有インデックス、
デスクトップの設定は、マスター鍵(データフォルダの `master.key`)から作った鍵で暗号化して
保存されます。旧バージョンのファイルは、新しいバージョンの初回起動時に自動で変換され、
元の平文ファイルは上書きしてから削除されます。

- `master.key` を削除すると、ファイルが残っていても読めなくなります。
- OS の再インストールや PC の入れ替えのあとも連絡先や履歴を使いたい場合は、
  **`master.key` をバックアップ**してください。なければ連絡先は空、ID は新しくなります。
- Miasma は、開けない暗号化ファイルを上書きしません。現在の鍵で開けないファイル
  (たとえば `master.key` を差し替えた場合)は、削除せず名前に `.corrupt-<時刻>` を付けて
  残します。元の `master.key` を戻して名前の末尾を外せば、再び開けます。
- `master.key` 自体、`config.toml`、受信したファイル、共有ブロブは対象外です。
  動作中でロック解除済みの PC や、`master.key` を含むデータフォルダの丸ごとコピーは
  この暗号化では守られません。

## Push files to a registered contact (no Share ID, no password)

Two people who trust each other add each other as contacts **once**, then send
file after file. Both Miasma daemons must be running and online.

Words used here and in the app (Japanese in brackets):

- **contact code** (連絡先コード): the long `miasma-contact:...` text. Public by
  design, not a password.
- **verification code** (確認用コード): the short `XXXXX-XXXXX-...` code derived
  from a contact code. Read it aloud over a call to check that the contact
  code was not changed on its way.
- **invitation message** (招待メッセージ): the text you paste into chat or
  e-mail. It holds your contact code and verification code, never a secret.

```sh
# On each machine: start the daemon (leave it running)
miasma init          # first time only
miasma daemon

# On each machine: show YOUR contact code and verification code
miasma contact code

# Send your contact code to the other person (chat is fine) and add theirs.
# Do this on BOTH sides - the receiver accepts only registered contacts.
miasma contact add "miasma-contact:..." --label taro

# Compare the verification code printed by `contact add` with the one the other
# person sees for you, over a call. If they differ, `miasma contact remove taro`.

# Send (several files are sent one after the other; Ctrl-C only stops waiting,
# the daemon keeps sending)
miasma push taro report.pdf photos.zip

# Progress / history, and where received files go (<inbox>/<contact label>/)
miasma push-status
miasma push-inbox
```

Useful: `miasma contact list`, `miasma contact set taro --no-allow-receive`
(stop accepting from them), `miasma contact set taro --max-size 5GiB`.
Settings in `config.toml`: `[push] inbox_dir`, `max_file_size`,
`min_free_bytes`. If a push says "cannot reach", run `miasma netcheck`.

### Contacts in the desktop app (3 steps)

The desktop app has a **Contacts** (連絡先) tab that does the same without the
command line. The background service must be running (the app starts it).

1. **Send your invitation message.** Contacts > *Send your contact to someone*
   (あなたの連絡先を相手に送る) > **Copy invitation message**
   (招待メッセージをコピー), and send that message to the other person (chat or
   e-mail). *Copy contact code* copies only the code. *Show QR code* shows the
   same code for a phone camera.
2. **Add theirs.** Contacts > *Add a contact* (連絡先を追加): paste the whole
   message you received, type a name, press **Add** (追加). Ask them to read out
   *Your verification code* (あなたの確認用コード) over a call and compare it
   with the code shown after adding; if it differs, press **Remove** (削除).
   **Both people must do this**: the receiver only accepts files from contacts
   it has registered.
3. **Send files.** Press **Send files** (ファイルを送る) on their row and pick
   files (or drop files onto their row). Progress, speed and time left appear
   under *File transfers* (ファイルの転送); received files are listed there too,
   with **Open file** / **Show in folder**, and the *Received files* card has
   **Open folder**. A notice and a count on the tab appear when a file arrives.
   Received files are never opened automatically.

Folders cannot be sent. A contact
row says **They have not added you yet** (相手はまだあなたを登録していません)
when the last push to them was refused with `not_allowed`: ask them to add your
invitation message. "Could not reach the other person": check their Miasma is
running, then run `miasma netcheck`.

#### Manual test: Windows PC <-> Mac (GUI)

Both machines: start Miasma desktop (it starts its own daemon), open
**Contacts**. Expect the "How to start" help card while the list is empty.

1. Windows: *Copy invitation message*, send to the Mac by chat. Mac: same,
   send to Windows.
2. Each side: paste the other's message into *Add a contact*, type a name,
   press **Add**. A green "Added <name>" with a big verification code must
   appear. Compare the two codes aloud (each side's *Your verification code*
   equals what the other side shows after adding).
3. Windows: **Send files** on the Mac's row, pick a small file. Mac: a notice
   "<name> sent you <file>" appears (also on the tab title if another tab is
   open); the file is under *File transfers* as "Done" with **Show in folder**.
4. Repeat Mac -> Windows. Send a file with a Japanese name, then a 1 GiB+ file
   (progress bar, rate and time left must move; **Cancel** works).
5. Negative checks: on one side **Remove** the other contact and send from the
   other: the sender's row for that contact shows **They have not added you
   yet** and the transfer says "Refused". Quit Miasma on one side and send:
   the error says to check that the other Miasma is running (with `netcheck`).
   Drop a folder on a row: a clear "Folders cannot be sent" message.

## Chat between registered contacts (CLI)

Chat works between two people who have registered each other as contacts (the
same step as for pushing files: `miasma contact add` on **both** sides). Text
only, up to 4096 bytes per message. Messages are end-to-end encrypted and go
straight to the other person's Miasma; there is no server in between.

```sh
# Send. Several words are one message.
miasma chat send taro "See you at 3"

# Read the latest messages (--limit N, --ids shows message IDs,
# --follow keeps running and prints new messages as they arrive).
miasma chat history taro --limit 20

# Your conversations, and how many messages still wait to be delivered.
miasma chat list
```

**If the other person is offline**, the message waits in an encrypted outbox on
your computer and is sent again automatically (after 5 s, 30 s, 2 min, 10 min,
then every 15 minutes, and at once when their Miasma connects to yours). In
`history` it is marked *waiting* until it arrives and *delivered* afterwards. A
message can fail for good only when the other person has not registered you
(`not_allowed`), removed you, or when you removed or switched off the contact;
it then stays in the history marked *failed*. Up to 500 messages can wait.
Removing a contact keeps the conversation but you cannot write to them anymore.

**History.** Messages are stored encrypted (with the state key derived from
`master.key`), one file per contact in `<data dir>/chat/`. **The history is saved
by default** and stays on disk until you delete it (stealth mode, which only
concerns logs, does not change that). To keep it in memory only, run
`miasma config --key chat.history_save --value false` and restart the daemon:
the history is then temporary (a few MiB, the oldest messages are dropped, all
gone when the daemon stops) and nothing of it is written to disk; messages
waiting to be delivered and the keys of the conversation are still stored
encrypted. `--value auto` removes the setting (back to the default: saved).
`chat.retention_days` removes saved messages older than that many days
(0 = keep); other keys: `chat.enabled`, `chat.max_message_bytes`,
`chat.outbox_max`. They take effect when the daemon starts.

**Read receipts.** They are on by default. When you have a conversation open and
in front, your Miasma tells the other side which of their messages you have
seen, and `history` then marks your own messages *read* once the other side did
the same. A message shows as read only when both sides have receipts on:
`chat.read_receipts` (default `true`, applied when the daemon starts) switches
them for everyone, and `miasma chat receipts <contact> --off` (or `--on`; no
flag shows the state) switches them for one contact right away. With them off,
nothing is sent and what arrives is not shown. Receipts are small and are
padded like any message; an undelivered one is dropped after a day.

**Group invitations.** When a trusted contact who administers a group adds you,
you join at once and the group shows "you were added by ...". Set
`chat.group_auto_join` to `false` (`miasma config --key chat.group_auto_join
--value false`, or the Settings page of the desktop app) to be asked first: the
invitation then waits at the top of the Chat tab until you accept or decline
it. An invitation from someone who is not a trusted contact is refused either
way. `miasma chat group list <group>` shows, for every member, whether they
joined, are invited and have not answered, cannot be reached (with the reason),
or run a Miasma that does not support groups yet. Messages to a member who has
not joined are kept and delivered when they do.

**Delete (on this device only; the other person keeps their copy).**

```sh
miasma chat history taro --ids        # shows the ID of each message
miasma chat delete taro <message-id>  # one message (or cancel one still waiting)
miasma chat delete taro --all         # the whole conversation, waiting messages included
```

Times are shown in UTC. If `chat` says the daemon does not support it, restart
the daemon after updating.

## Chat in the desktop app

The **Chat** tab (チャット, next to Contacts) is the same chat with a window.

- **Start.** Register the other person on the Contacts tab (both sides), then
  press **New conversation** (新しい会話) and choose the contact. Only
  registered contacts are listed; with none yet, the tab points to Contacts.
- **List.** One row per conversation: name, the start of the last message
  ("You: " in front of your own; a file you sent from here is shown as "Sent a
  file: name"), the time, and a number for unread messages. The Chat tab shows
  how many messages arrived while you were elsewhere.
- **Write.** Enter sends, Shift+Enter starts a new line. The counter follows the
  size limit of a message (in bytes, so about a third as many Japanese
  characters as ASCII ones); a message that is too long cannot be sent. Each
  of your messages says *Sending*, *Sent (waiting for them to receive it)*,
  *Delivered* or *Could not send* with **Send again**.
- **Send a file** uses the Contacts tab's own file sending; follow it there.
- **Delete this conversation's history** removes it from this device only,
  after a confirmation (it cannot be undone; the other person keeps theirs).
- When the history is kept in memory only (`chat.history_save` off), the tab
  says so at the top.
- Only the newest few hundred messages of the open conversation are held in
  memory; older ones load as you scroll up.
- Unread counts live in the window: they start from zero when the app starts.

## Restricted networks

Some networks block or degrade parts of the internet: name lookups that fail,
ports that are closed, UDP that does not get out, TLS handshakes that are cut,
or HTTPS that is re-signed by a gateway. Miasma can tell you which of these you
are standing in, so that you can choose a configuration from what was observed
instead of guessing. Everything below uses ordinary connection attempts only.

### Read the matrix

```
miasma netcheck --matrix
miasma netcheck --matrix --json --out matrix.json
miasma netcheck --matrix --probe wss://my-relay.example/ --probe wss://other.example:8443/x
```

The matrix tries each path one by one, at most four at a time and in under 40
seconds, and prints one row per path: `OK` or `NG`, the kind of path, what it
was for, the host that was probed, and a classified reason. Add `--lang ja` for
Japanese. No user data is sent. The JSON report (stable `schema` number) names
only the probed hosts: no address of this computer, no endpoint ID, no resolved
address, and for `--probe` only the host, not the path.

| Row | What it does | Reasons you may see |
| --- | --- | --- |
| DNS | Resolves each host with the system resolver, and asks two public resolvers directly over UDP | `works`, `name does not exist (NXDOMAIN)`, `no answer in time`, `answer differs from the public resolvers'`, `system DNS works; UDP DNS ... gets no answer` |
| TCP | Connects to the first two addresses of each host | `works`, `connection refused`, `connection reset`, `no answer in time` (packets vanish), `no route` |
| TLS | One handshake with the real server name | `works`, `cut during the TLS / upgrade handshake`, `no answer in time`, `certificate comes from a CA that is not a public one` (the issuer's name is shown), `certificate refused` |
| SNI | The same address with the real name and with a neutral name; says whether the two were treated differently | `works` (same result), `treated differently` (both results are shown) |
| UDP, QUIC | iroh's net report: does UDP get out, and does QUIC reach a relay | `works`, `UDP does not get out` |
| Relay | A small round trip and a 1 MiB transfer through the relay, between two short-lived endpoints that can only use the relay; for `--probe` endpoints, a WebSocket upgrade and a ping | `works` with the round trip in ms and the rate in KiB/s, or where it stopped |
| LAN | Whether local-network discovery (mDNS) finds a second endpoint on this computer | `works`, `no answer in time` |

Rows that cannot work because an earlier step failed are marked `not tried`
with the reason (no address, no reachable relay).

Reading it, in this order:

1. **DNS rows.** `name does not exist` or `answer differs` for the relay hosts
   means the names themselves are the problem, not the connection. A relay
   you run yourself (below) does not depend on n0's names. When the system
   resolver fails but a public resolver answers, the TCP rows use that address
   and say so, so a name problem and a path problem are not mixed up.
2. **TCP, then TLS rows.** `refused` or `no route`: that port or network is
   closed. TCP `works` but TLS `cut during the handshake` or `no answer in
   time`: the connection is accepted and then interfered with. Compare the
   SNI row: if the neutral name gets through and the real one does not, the
   network treats the two names differently.
3. **A certificate from a non-public CA.** The network re-signs HTTPS. The row
   shows the issuer's name and whether this computer trusts it (`trusted=true`
   or `trusted=false`). If you trust that CA, install it in the operating
   system's certificate store, or save it as a PEM or DER file and run
   `miasma config --key transport.iroh_extra_ca_pem --value <file>`.
4. **UDP and QUIC.** If they do not work, transfers go through the relay only,
   which is slower (about 1 MiB/s on a public relay). The relay row shows the
   rate measured here.
5. **LAN.** If it works, two computers on the same local network can find each
   other without the internet (`transport.iroh_lan_discovery`).

The last section, "Suggested configuration", maps what was observed to the
configuration keys that exist (`transport.iroh_mode`,
`transport.iroh_relay_urls`, `transport.iroh_discovery`,
`transport.iroh_extra_ca_pem`, `transport.iroh_lan_discovery`) and to the
tunnel. It says what was observed to work and what was not; it does not promise
that a path will keep working.

### Run your own relay

When the public relays are not reachable, or you want the traffic to stay on a
machine you control, run iroh's relay server on a machine whose address you can
reach, and point Miasma at it. The relay carries only encrypted traffic and the
metadata a relay always sees (which endpoint talks to which).

On the machine you control, with a certificate for a host name that points at
it (shown with Let's Encrypt; ports 80 and 443 must be reachable from outside):

```
cargo install iroh-relay --version 1.3.0 --features server --locked
```

Save this as `relay.toml`:

```toml
enable_relay = true
http_bind_addr = "[::]:80"

[tls]
hostname = "relay.example.org"
cert_mode = "LetsEncrypt"
contact = "you@example.org"
https_bind_addr = "[::]:443"
```

and start it:

```
iroh-relay --config-path relay.toml
```

With a certificate you already have, use `cert_mode = "Manual"` with
`cert_dir = "/path/to/dir"` (the files `default.crt` and `default.key` are read
from it) in the `[tls]` table instead.

For a trial on a trusted local network only, `iroh-relay --dev` runs the relay
over plain HTTP on port 3340 with no certificate; use `http://<its address>:3340`
as the URL below. Do not expose that mode to the internet.

On every computer that should use it (sender and receiver both):

```
miasma config --key transport.iroh_mode --value custom
miasma config --key transport.iroh_relay_urls --value https://relay.example.org
```

Each call to `transport.iroh_relay_urls` adds one URL; an empty value clears the
list. Restart the daemon: the setting is read at start. In `custom` mode only
your relays are used. n0's discovery service is still used unless you turn it
off with `miasma config --key transport.iroh_discovery --value false`; with it
off, a receiver reaches a sender only through the relay URLs, so give both sides
the same `transport.iroh_relay_urls`. Run `miasma netcheck --matrix` again: the
relay row now probes your relay, and you can add another with
`--probe wss://relay.example.org/`.

A relay in `custom` mode may be reached through a certificate from a private CA;
set `transport.iroh_extra_ca_pem` to that CA's file on every computer.

### Same local network only

Two computers on one local network can find each other with mDNS, without the
internet:

```
miasma config --key transport.iroh_lan_discovery --value true
miasma config --key transport.iroh_discovery --value false
```

The announcement carries the endpoint ID and the LAN addresses and is visible to
everyone on that network; turn it off (`false`) on a network you do not trust.
The LAN row of the matrix says whether mDNS works on the network you are on. To
keep the daemon from contacting n0's relays at all, use `transport.iroh_mode =
custom` with a relay on that network, as above (`iroh-relay --dev` is enough for
a trusted LAN).

### Tunnel

If only outbound HTTPS gets out, the sender can expose its WebSocket share
server through a tunnel instead. `cloudflared` must already be installed:

```
miasma daemon --wss-port 8443
miasma tunnel
```

`miasma tunnel` prints a `wss://...` URL; the receiver uses it with
`miasma network-get <share-id> -o <file> --via wss://...`. The matrix tells you
whether the tunnel service's API host was reached from where you are (the
`tunnel` rows). A tunnel makes the sender's share server reachable by anyone who
has the URL; share the URL only with the person who should have the file.
