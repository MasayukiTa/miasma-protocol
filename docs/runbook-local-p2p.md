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
# prints: Peer ID + Bootstrap addresses

# Terminal 1 (second shell): dissolve and start serving
#   Currently: use network-publish (combines dissolve + DHT publish + serve)
#   Future: daemon will support hot-publish via IPC
```

The `daemon` command is best suited for a node that participates in the network
as a passive relay/store; use `network-publish` when you want to dissolve and
immediately serve a specific file.


---

## Push files to a registered contact (no Share ID, no password)

Two people who trust each other register **once**, then send file after file.
Both Miasma daemons must be running and online (ADR-012).

```sh
# On each machine: start the daemon (leave it running)
miasma init          # first time only
miasma daemon

# On each machine: show YOUR contact code and fingerprint
miasma contact code

# Send your code to the other person (chat is fine) and add theirs.
# Do this on BOTH sides - the receiver accepts only registered contacts.
miasma contact add "miasma-contact:..." --label taro

# Compare the fingerprint printed by `contact add` with the one the other
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

1. **Copy my card.** Contacts > *My contact card* > **Copy invitation message**,
   and send that message to the other person (chat or e-mail). It holds only
   your public contact code and fingerprint, never a secret. *Show QR* shows
   the same code for a phone camera.
2. **Paste theirs.** Contacts > *Add a contact*: paste the whole message you
   received, type a name, press **Add**. Compare the fingerprint shown with the
   one on their card (read it aloud over a call); if it differs, press
   **Remove**. **Both people must do this**: the receiver only accepts files
   from contacts it has registered.
3. **Send files.** Press **Send files...** on their row and pick files (or drop
   files onto their row). Progress, speed and time left appear under *File
   transfers*; received files are listed there too, with **Open file** /
   **Show in folder**, and the *Received files* card has **Open folder**. A
   notice and a count on the tab appear when a file arrives. Received files are
   never opened automatically.

Files can only be sent while the other person is online (direct delivery for
now). Folders cannot be sent yet. A contact row says **They have not
registered you** when the last push to them was refused with `not_allowed`:
ask them to add your card. "Could not reach the other person": check their
Miasma is running, then run `miasma netcheck`.

#### Manual test: Windows PC <-> Mac (GUI)

Both machines: start Miasma desktop (it starts its own daemon), open
**Contacts**. Expect "How to start" help card while the list is empty.

1. Windows: *Copy invitation message*, send to the Mac by chat. Mac: same,
   send to Windows.
2. Each side: paste the other's message into *Add a contact*, type a name,
   press **Add**. A green "Added: <name>" with a big fingerprint must appear.
   Compare the two fingerprints aloud (each side's *My fingerprint* equals what
   the other side shows after adding).
3. Windows: **Send files...** on the Mac's row, pick a small file. Mac: a notice
   "<name> sent you <file>" appears (also on the tab title if another tab is
   open); the file is under *File transfers* as "Done" with **Show in folder**.
4. Repeat Mac -> Windows. Send a file with a Japanese name, then a 1 GiB+ file
   (progress bar, rate and time left must move; **Cancel** works).
5. Negative checks: on one side **Remove** the other contact and send from the
   other: the sender's row for that contact shows **They have not registered
   you** and the transfer says "Refused". Quit Miasma on one side and send:
   the error says to check that the other Miasma is running (with `netcheck`).
   Drop a folder on a row: a clear "Folders cannot be sent yet" message.
