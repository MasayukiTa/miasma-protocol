# Hybrid key exchange for private conversations

**Status: beta, on by default (`require`: a message is sent only after the
hybrid exchange with that contact has completed; there is no classical
fallback). This wiring has not been reviewed by an outside cryptographer.** The primitives come from a maintained library (see
`dependency-review-mlkem.md`); the way they are combined with the existing
conversation sessions is new code written for this project and is subject to
external cryptographic review before anyone relies on it.

## What it does

A private conversation is protected by a double-ratchet session whose first
flight is an X25519 agreement. This feature adds, inside an established
session, a second key exchange that mixes X25519 with ML-KEM-768 (FIPS 203).
Once both sides finished it, every later message is protected by the ratchet
message key **and** the hybrid key. An attacker has to break both.

It does not change how a conversation starts, and it never touches the
ratchet: the session stays a valid classical session at every moment. That is
what lets every build keep talking to every other build.

## Settings

`privacy.pqc_mode` in `config.toml`:

| value     | behaviour |
|-----------|-----------|
| `require` | Default. Send messages to a contact only after the upgrade with that contact finished. If the contact cannot do it (or the exchange fails), the messages fail on this device with a stated reason. Nothing is sent in the classical session. The contact's own settings are not affected. |
| `prefer`  | Advanced only (see below). Offer the upgrade. Use it when the contact agrees; otherwise keep the classical session and show "classical only". Messages are never held back. Allowing this classical fallback lowers the guarantee to the contact's level, so `miasma status` warns while it is in force. |
| `off`     | Advanced only (see below). The build offers nothing and answers nothing. Bytes on the wire are those of a build without the feature. Like `prefer`, it allows a classical fallback and `miasma status` warns while it is in force. |

* The default is `require`. The key is written to `config.toml` only after a
  person has chosen a value; a file without it means "never chosen". Settings
  and `miasma status` then say the upgrade is required and that this is the
  default.
* `off` and `prefer` lower the guarantee below `require` by allowing a
  classical fallback. They are **not offered in the normal settings**: they are
  honoured only when written into `config.toml` by hand or passed to an advanced
  command-line option, and `miasma status` and desktop Settings warn while one
  is in force. See [`PqcMode::allows_classical_fallback`] in the code.
* A contact whose build does not offer the hybrid suite cannot be sent to under
  the `require` default: the messages fail on this device with the reason
  `pqc_peer_no_hybrid`, shown in the chat in the three languages, and the person
  is told to ask the contact to update to the latest version. Nothing is sent in
  the classical session.
* Turning the setting off stops new upgrades and the answers to offers. A
  session that was already upgraded keeps using its key (dropping it would only
  weaken the messages, and the contact still sends layered ones); the key goes
  when the session is reset or the conversation is deleted. The document is
  sealed with the same state keys as the session, so the existing erase of the
  master key makes it unreadable as well.
* `miasma config --key privacy.pqc_mode --value require` (and `--key` alone to
  read it). A change applies the next time the background service starts. The
  `require` default needs no setting; lowering it to `off` or `prefer` is an
  advanced step (set the key here or pass the advanced command-line option) and
  the status then warns that a classical fallback is allowed.
* Desktop: Settings, "Advanced encryption" (English, Japanese,
  Simplified Chinese). The required upgrade is the standard, shown as the
  default; `off` and `prefer` are moved out of the ordinary choices into an
  advanced area, and a warning is shown while a classical fallback is allowed.
* `miasma status` shows the mode and the counters; the daemon status carries
  `pqc: { mode, available, counts }`; each conversation reports `pqc`
  (`pending`, `hybrid`, `classical`, `failed`) and `pqc_reason`
  (`peer_no_hybrid`, `peer_old_build`, `exchange_failed`, `exchange_timeout`,
  `confirm_mismatch`). The chat header shows it in words ("Standard protection
  only", "Advanced encryption is on").
* Under `require`, a refused message ends as failed with the reason
  `pqc_peer_no_hybrid` or `pqc_failed`, shown in the chat in the three
  languages.

Counters (numbers only, no peer identifiers): `hybrid_sessions`,
`classical_only`, `refused`, `failed`, `offers_sent`, `offers_received`. In
addition every capability downgrade is counted by the existing
`capability_downgrades` counters (`offer_missing`, `suites_unavailable`, ...).

## Build default

The cargo feature `pqc` of `miasma-core` (passed through as `pqc` by
`miasma-cli`, `miasma-desktop` and `miasma-ffi`) is **on by default for the
desktop and command-line programs** and off for `miasma-ffi` (the mobile
library) and for `miasma-core` on its own. The setting `privacy.pqc_mode`
defaults to `require`, so a release build requires the upgrade for every
contact until a person sets `off` or `prefer`. A desktop or CLI build can leave
it out with `--no-default-features`; Settings then shows the choices switched
off. The
mobile library does not run the chat service and does not enable the feature
(see "Mobile" below).

The dependency adds `ml-kem` and a second `rand_core`
version to the tree, and binary size and build time could not be measured
here (local builds are restricted on the development machine). The wasm and
android builds were checked:

* `miasma-wasm` does not link `miasma-core` (it is a dev-dependency only), so
  the feature cannot reach it.
* `cargo check --package miasma-ffi --features pqc` and the same without the
  feature both compile (the Android library is built from this crate).

With the feature off the negotiation and exchange code is not compiled and the
daemon behaves exactly as before. One small, always compiled piece is shared:
the message-key layering helper in `chat/crypto.rs`, which is never given a
key in such a build. A build without the feature that finds
`privacy.pqc_mode = off|prefer|require` set by a person says so (log line,
`miasma config`, `miasma status`, desktop Settings) and stays classical; it does
not pretend. The untouched default is not reported as a setting it ignores:
`miasma status` says "off (not in this build ...)".

## Existing configuration files

Before the default first changed, every save of `config.toml` wrote
`pqc_mode = "off"`, chosen or not, so a plain change of the default would never
have reached existing installs. The file carries
`privacy.pqc_default_version` (written by every save; a file without it counts
as 0), and `pqc_mode` is written only when set. The default has moved twice:
version 1 made it `prefer`, and **this release (beta.12) raises it to
`require`** as version 2. Each step is applied once, when the file is first read
under an older version, and the file is then rewritten by the next save:

* version 0 with `pqc_mode = "off"` (or without the key): the version-0 default
  wrote that `off`, so it was never chosen. It is cleared, and the current
  default (`require`) applies;
* the `prefer` default that version 1 left in force was never written to the
  file (it was the unset default), so a version-1 file with no `pqc_mode` moves
  to the `require` default as well;
* any `off`, `prefer` or `require` a person wrote at version 1 or later is a
  choice and is kept as it is.

So the migration to `require` happens **once, on the first start under beta.12**:
an install that never chose a value moves from the old default to `require`,
and an install that did choose keeps its choice (including `off` or `prefer`,
which then warn about the classical fallback). No manual step is needed. Known
limit: a version-0 file cannot show whether `off` was chosen or only saved as
the old default (for example someone who tried a value and went back), so those
people get `require` and can set `off` or `prefer` again by hand or with
`miasma config --key privacy.pqc_mode --value off`. A choice made after the
migration is kept. If an older build rewrites the file, it drops the version
key and writes `off` again, and the next start of this build reads it as never
chosen (so `require` applies).

## Mobile

`miasma-ffi` keeps the feature off. It does not start the chat service (the
only reference to chat there is a default `ChatConfig`), so the setting would
change nothing, and CI only runs `cargo check -p miasma-ffi --features pqc` on
the host: there is no Android or iOS target build in CI that includes `ml-kem`.
Enabling it needs, first, a chat service in the mobile library, and an
Android and iOS target build with the feature checked in CI.

## Design

### Why inside the session

The first message of a conversation is sealed while the contact may be
offline, so a key exchange that needs an answer cannot be part of it. The
upgrade therefore runs after the session exists, as ordinary sealed records.

### Records

Four record kinds travel inside the sealed envelope (`0x20..=0x23`; the pair
chat uses 1 and 2, group chat `0x10..=0x12`):

1. `OFFER`: the capability offer of `protocol::capability`.
2. `INIT` / `RESP`: the two messages of `protocol::hybrid` (X25519 value plus
   the ML-KEM encapsulation key of 1184 bytes, and X25519 plus the 1088-byte
   ciphertext), cut by `protocol::fragment` into fragments of at most 400
   bytes, one fragment per record, so no record outgrows the smallest padding
   bucket (512 bytes) and no frame becomes large.
3. `CONFIRM`: the 32-byte key-confirmation tag. A one-byte body tells the peer
   that this side gave up (so it does not wait).

Each side sends its offer first. When both offers are known and agree on the
hybrid suite (and on fragmentation), the side with the smaller endpoint ID
starts the exchange. The transcript includes the capability binding digest
(both offers and the agreed result), both endpoint IDs and the ID of the
session (so the key belongs to one session), the X25519 values, the
encapsulation key and the ciphertext. Both sides send their tag; a side starts
layering only after it verified the peer's tag, so the peer is known to hold
the key.

### Layering

A message key becomes `HKDF-SHA256(salt = label, ikm = ratchet_key || hybrid_key,
info = ratchet_public_key || message_number)`. Nothing about the envelope
changes: same header, same lengths. The receiver tries the layered key first
and the plain one second (the sender may not have switched yet); the AEAD tag
decides, so a forged message opens under neither. Skipped-message keys and
out-of-order delivery work as before.

### Persistence, memory, wipe

* One small encrypted document per contact (`<stem>.pq`, same state keys as the
  session documents) holds the session ID, the decision, both offers, and once
  derived the hybrid key and the two tags. A build without the feature ignores
  the file; the session documents are byte-identical either way, so switching
  the build back and forth loses nothing.
* The unfinished exchange (decapsulation key, fragments, queue) is memory only;
  a restart starts it again. Timeouts: 15 s for the peer's offer, 120 s for the
  next message of the exchange, 5 starts, then `failed`. A classical decision is
  taken again after an hour, a failed exchange after ten minutes.
* Bounds: reassembly is capped by the fragment module (total length at most the
  largest exchange message, 8 messages in assembly per contact); 64 contacts in
  memory; a replay guard of 64 first messages; offers of at most 268 bytes; a
  declared length is checked before anything is sized.
* The hybrid key lives in a wipe-on-drop container; the service drops all keys
  from memory on shutdown, a reset or deleted conversation removes its
  document (overwritten, then deleted), and `PqState::wipe` removes everything.

## Compatibility

The owner's rule: the wire stays compatible with builds of any version, and a
downgrade is visible, never silent. Under the `require` default the *content*
to a contact that cannot do the upgrade is held back by design (the message
fails on this device rather than drop to the classical session); the bytes that
do go on the wire are still the ones an old build reads. Lowering the setting to
`prefer` or `off` restores classical delivery to such a contact.

* The bytes sent to a contact with the setting off or an older build do not
  change beyond the one record described next, whatever this side's mode.
* Old builds: the envelope, frame and acknowledgement bytes are those they
  always read. The only new thing a build with the upgrade enabled
  (`require`, `prefer`) sends to a contact that does not know the upgrade is one
  sealed record of kind `0x20`. A build that sets unknown records aside
  acknowledges it; the oldest chat release answers "bad request" for it and
  keeps its session unchanged. Either way the next envelope is an ordinary
  message. Under `prefer` the contact is then shown as "classical only"
  (`peer_no_hybrid` after a short wait, or `peer_old_build` at once); under the
  `require` default the messages to that contact fail on this device with the
  reason `pqc_peer_no_hybrid`, and the person is asked to have the contact
  update to the latest version.
* `tests/pqc_old_peer_compat_test.rs` runs this build against **frozen copies
  of the old decoders** (strict envelope, frame and message readers, taken from
  the release sources, as `wire_compat_test.rs` does), for both kinds of old
  peer, and checks that texts arrive in order, replies open, no hybrid key
  exists, and a layered envelope has exactly the common shape. The frozen-bytes
  tests `wire_compat_*` are unchanged and still pass.
* Newer builds: unknown suite bits, feature bits and capability extension
  bytes are ignored by the negotiation. Known limit: a peer whose capability
  structure is a newer version than 1 may have fields this build drops when it
  re-encodes the offer for the transcript; the two transcripts then differ, the
  key confirmation fails, the exchange ends as `failed` (visible), and the
  conversation continues classical. It does not break messaging.
* The acknowledgement frame is **not** extended: the oldest release reads it
  strictly, so no capability information rides on it.

## Failure behaviour

| situation | result |
|-----------|--------|
| contact has the setting off, or an older build | `require` (default): messages fail locally with the reason `pqc_peer_no_hybrid`, and the person is asked to have the contact update; nothing is sent in the classical session. `prefer`/`off` (advanced): classical only, shown |
| offer altered or stripped on the way | cannot happen inside the authenticated session except by the peer itself; the transcript binding makes an altered offer fail the confirmation (`failed`); a missing offer counts as `offer_missing` and ends classical |
| exchange message altered | decapsulation yields an unrelated key (implicit rejection); the tags differ; both sides end `failed`; no layered message is ever sent |
| restart in the middle | the exchange starts again; a finished one is read from the document |
| contact lost its session | the key belonged to the old session and is dropped with it |
| the peer's tag never arrives after the key exists | the key is kept (the peer may already use it) and the tag is awaited |

## Not covered, not verified

* No outside cryptographic review of this wiring.
* The hybrid key protects messages sent **after** both sides finished. The
  first messages of a session, and anything sent before that, are protected by
  the classical agreement only; an attacker who records traffic and later
  breaks X25519 can read those.
* The hybrid key is fixed for the life of a session (there is no post-quantum
  ratchet); it adds a second key to every message but does not heal after a
  device compromise.
* It protects message content only. Who talks to whom and when is visible to
  the transport as before.
* Binary size, memory and CPU impact were not measured.
* A real old binary was not run; the old readers are copies from the sources.
* The `capability` version skew case above is reasoned and covered by the
  failure path, but no peer with a newer structure exists to test against.

## Tests

`cargo test --package miasma-core --features pqc --lib chat::` and
`--lib protocol::` (state machine, layering, bounds, wipe, restart, tampering,
stripped offer, all policy combinations), `--test pqc_old_peer_compat_test`
(frozen old decoders), `--test chat_pqc_net_test` (real service and workers
over a local relay), plus the unchanged `wire_compat_*`, `r18_gate_test`,
`adversarial_test` and `persisted_paths_lint`, with and without the feature.
