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
`master.key`), one file per contact in `<data dir>/chat/`. While **stealth mode**
is on (`privacy.stealth_mode`, the default) and `chat.history_save` is not set,
the history is kept in memory only (a few MiB, the oldest messages are dropped)
and is gone when the daemon stops; messages waiting to be delivered and the keys
of the conversation are still stored encrypted. Set
`miasma config --key chat.history_save --value true` to save the history on disk
in any case (`false` to never save it, `auto` to go back to the rule above).
`chat.retention_days` removes saved messages older than that many days
(0 = keep); other keys: `chat.enabled`, `chat.max_message_bytes`,
`chat.outbox_max`. They take effect when the daemon starts.

**Delete (on this device only; the other person keeps their copy).**

```sh
miasma chat history taro --ids        # shows the ID of each message
miasma chat delete taro <message-id>  # one message (or cancel one still waiting)
miasma chat delete taro --all         # the whole conversation, waiting messages included
```

Times are shown in UTC. If `chat` says the daemon does not support it, restart
the daemon after updating.
