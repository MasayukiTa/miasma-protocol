# ADR-012: Trusted-contact push

(Requested as "ADR-011"; that number is already taken by
`011-sss-crate-swap.md`, so this is 012.)

- **Status**: Accepted (implemented in `crates/miasma-core/src/push/`)
- **Date**: 2026-10-14

## Context

Share IDs (publish + `network-get`) and Directed Sharing (ADR-006/010) are
built for strangers: every file needs a Share ID or a password plus a
confirmation code, and Directed Sharing travels over libp2p with the DHT and
relay fallbacks that go with it. Two people who already trust each other and
want to exchange many files (a Windows PC and a Mac, say) should be able to
register once and then just send files.

## Decision

**Register each other once, then `miasma push <contact> <file>`.** No per-file
ID, password or confirmation code. The receiver auto-accepts only from
registered contacts.

### Identity and trust

- A contact is the other node's **iroh endpoint ID** (an Ed25519 public key;
  equal to the publisher key in that node's share IDs). Its text form is
  `miasma-contact:<base58(version || endpoint id || 4-byte checksum)>`,
  modelled on `ShareId` (prefix + keyed BLAKE3 checksum). The extractor finds a
  code inside pasted text, rejects a corrupt checksum, and never returns a
  share ID or MID.
- A short **fingerprint** (`ABCDE-FGHJK-MNPQR-STVWX`, 100 bits of a keyed
  BLAKE3 of the endpoint ID, Crockford base32) is shown next to every contact.
  Trust = *mutual registration* + *verifying the fingerprint over a second
  channel* (a call). A code exchanged over chat can be swapped by whoever
  controls the chat; the fingerprint check detects it.
- **The only identity of a peer is the endpoint ID proven by the QUIC/TLS
  handshake** (`Connection::remote_id()`). No identity, name or key in a message
  is believed.

### Transport

iroh (QUIC, hole punching, relay fallback, n0 discovery, LAN mDNS) on the
**same endpoint** the daemon already runs for Share ID receive. A second ALPN,
`miasma/push/1`, is added next to `miasma/direct/1`; the accept loop dispatches
on the negotiated ALPN. Nothing is added to what the endpoint publishes to n0.

Why not libp2p / Directed Sharing: those need the DHT, bootstrap peers or a
relay-stored envelope, a per-file password and a confirmation code, and
buffer the file in memory. The iroh path already needs only an endpoint ID, and
streams.

### Protocol (`miasma/push/1`)

One transfer = one bidirectional stream; one connection carries the files of a
queue one after another.

1. sender -> `Header {v, name, size, hash(BLAKE3 hex), note?}` (length-prefixed
   JSON, max 16 KiB, name <= 1024 bytes)
2. receiver -> `Accept {offset}` or `Reject {reason}` with `reason` one of
   `too_large | no_space | not_allowed | busy | bad_name | bad_request`
3. sender -> raw bytes `[offset, size)`, then finishes its side
4. receiver -> `Done {ok, saved_as, error}`

Receiver: writes to `<inbox>/<contact label>/.<hash>-<size>.part`, hashes while
writing, verifies the BLAKE3 before the final rename, and renames **without
overwriting** (`name (1).ext`). The part file is keyed by content, not name, so
a resume finds it whatever the name is and no name can be too long. If a part
exists the receiver hashes it and answers `Accept {offset = its length}`; the
sender seeks. After a connection drop the sender retries with resume
(2 s, 5 s, 10 s); a hash mismatch deletes the part and is retried once from
scratch.

A dialer that is not a contact with `allow_receive` has its connection closed
with application error 403 right after the handshake and a debug-level log
line only (per-id token bucket, bounded memory). The sender maps that close
code to "rejected: not_allowed" so a user is told to ask the other side to
register them. This tells a *dialer* whether it is registered; it is not
visible to anyone else, and an unregistered dialer learns nothing else.

### Limits

- `push.max_file_size` default 20 GiB; per-contact `max_file_size` overrides.
- Free-space check before `Accept` (`push.min_free_bytes` reserve, default
  2 GiB). Both reject before any byte is written.
- Inbound transfers served at once: 2 (`push.max_concurrent_inbound`);
  further ones get `busy`. Outbound: strictly sequential per contact; at most
  500 unfinished transfers.
- 60 s without a byte moving abandons a transfer (the part is kept for resume);
  QUIC keep-alive detects dead peers. Header and reply frames are capped; the
  declared length is checked before any buffer is sized.
- Streaming everywhere (256 KiB chunks); a multi-GB file is never held in
  memory.

### Storage

- `{data_dir}/contacts.json`: versioned, atomic write (temp + rename),
  owner-only permissions through `secure_file`, unknown fields ignored,
  corrupt file moved aside and the list restarts empty (default-deny).
  Never in the repository.
- `{data_dir}/push_history.jsonl`: inbound and outbound results, capped at
  1000 lines.
- `push.inbox_dir` (default `<data_dir>/inbox`), one sub-folder per contact.
- Names are sanitised with the same function as the Share ID receive path
  (`transfer::manifest::sanitize_file_name`): path stripped, `..`, control and
  bidi characters, Windows device names, length cap keeping the extension.

### Surface

Daemon IPC `ControlRequest::Push(PushRequest)` / `ControlResponse::Push(PushResponse)`
(one additive variant each; documented in `push/ipc.rs`); CLI
`miasma contact code|add|list|remove|set`, `miasma push`, `miasma push-status`,
`miasma push-inbox`.

## Threat model

| Threat | Handling |
|---|---|
| Stranger pushes files | Default-deny; closed at handshake; rate-limited. |
| Contact code swapped in transit | Fingerprint comparison over a call; `contact remove` if it differs. |
| Impersonating a contact | Needs their Ed25519 secret key; identity is the TLS-proven endpoint ID. |
| Path traversal / device names / bidi tricks in a name | Shared sanitiser; files only inside `<inbox>/<label>/`. |
| Overwriting existing files | `create_new` reservation, suffix on collision. |
| Corrupted or tampered stream | BLAKE3 verified before the final rename; part deleted on mismatch. |
| Disk exhaustion | Size limit, free-space reserve, concurrency cap, sequential sender. |
| Memory exhaustion / hostile headers | Frame cap, bounded buffers, bounded maps, timeouts. |
| Removed contact keeps a transfer running | Removal cancels in-flight transfers and deletes partial files. |
| A malicious *registered* contact | Out of scope beyond size/space limits and revocation: a contact may send you any file, so treat it like any download (do not open what you did not expect). |

## Non-goals

- No groups, no relay store-and-forward, no offline delivery: **both sides must
  be online** (a failed attempt is retried a few times, then reported).
- No anonymity: the contact knows your endpoint ID, and in `n0` mode your ID
  and addresses are published to n0 discovery (the notice the daemon already
  logs). Use `transport.iroh_mode = off` to disable push together with it.
- No end-to-end encryption beyond QUIC/TLS between the two endpoints (relay
  servers see only ciphertext).
- No per-file confirmation prompt (the point of the feature). A GUI may add an
  optional "notify on arrival".

## Known gaps

- `http_bridge` (browser/PWA) does not expose push.
- A stale `.part` (never resumed) stays until the contact is removed.
- Verification of a multi-GB resumed prefix happens before `Accept`, so a very
  large resume waits for the hash of what is already on disk.
