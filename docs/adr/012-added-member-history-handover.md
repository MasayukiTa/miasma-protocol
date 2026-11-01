# ADR-012: History hand-over to a newly added member or device

## Status: Accepted (implemented in the chat/group and desktop layers; the custody transport for an offline target is a separate job, left as the named seam `GroupCore::custody_offers_for`)

## Date: 2026-11-01

---

## Context

When a participant is added to a group, or a contact links a new device, that
endpoint starts with no past content. Two kinds of past content exist:

1. **Chat history** — messages others already applied.
2. **Shared files** — content a custody holder keeps on behalf of an offline
   endpoint.

This ADR designs how a newly added member or device *may* receive such past
content from an existing member who chooses to hand it over, and how that
hand-over survives the new device being offline when it is sent. It composes
with, and does not replace, the existing custody layer.

Every statement about current code below cites a file:line that was read.

### What the code does today

**Group delivery is pairwise, not group-keyed.** A group message is sealed
again for every member on the pairwise ratchet session this device already has
with that member; there is no group-wide key, no sender key, and no epoch-keyed
message key (`crates/miasma-core/src/chat/group/engine.rs:5-10`;
`crates/miasma-core/src/chat/group/record.rs:3-6`). The "epoch" is the
membership descriptor's version number, not a key generation
(`crates/miasma-core/src/chat/group/membership.rs:3-9`).

**Adding a member does not backfill anything.** `add` advances the descriptor
chain and owes every current member a copy of the newest descriptors
(`CtrlKind::Descs`); it queues no past messages
(`crates/miasma-core/src/chat/group/engine.rs:616-657`). `send` computes its
recipient set from the *current* member list at send time
(`engine.rs:823-829`), so a member added later is never in the `to` list of an
earlier message and is never sent it.

**A newly invited device starts empty.** On receiving an invitation, the
receiver builds a fresh `GroupState::new(...)` with no messages
(`engine.rs:1224-1239`); `become_member` only owes each other member a sync
request so presence converges — it moves no history
(`engine.rs:755-771`). The membership module states the same: "A person who is
invited holds no history yet" (`membership.rs:21-23`).

**The existing `Sync` record is membership-only.** When a text arrives at an
epoch ahead of the receiver, the receiver owes the sender a `CtrlKind::Sync`
and replies `Busy`; the sync exchange carries *descriptors*, not message bodies
(`engine.rs:1058-1067`; `record.rs:9-12`, `KIND_SYNC`). The separate catch-up
in `chat/sync.rs` reconciles a sender's own undelivered messages by id with one
contact; it is not third-party and not history-to-a-new-member
(`crates/miasma-core/src/chat/sync.rs:1-15`).

**The custody layer is Case-A only and unwired.** The mailbox holds a sealed
envelope for a known recipient who is merely offline, tagged by
`RecipientTag::for_recipient(recipient)`
(`crates/miasma-core/src/chat/mailbox/ids.rs:12-19`;
`crates/miasma-core/src/chat/mailbox/client.rs:105-133`). The holder learns
nothing a relay would not (`crates/miasma-core/src/chat/mailbox/mod.rs:9-14`).
It has hard ceilings — 4 MiB total, 1024 items, 30-day TTL — and is off by
default, with no transport, listener, disk persistence, or service call site
(see the custody audit report, section 1, which cites `holder.rs:22-28`,
`config.rs:361,389`, and a negative `custody` search of `chat/service.rs`). A
freshly added device that was never a party to the original send is not
modelled by it (custody audit report, section 2).

**Directed async delivery was deferred.** ADR-006 requires sender and recipient
to be mutually reachable
(`docs/adr/ADR-006-directed-private-sharing.md:314-317`), and ADR-010 lists an
asynchronous mailbox for directed sharing as out of scope and deferred
(`docs/adr/010-directed-sharing-transport-architecture.md:109-115,183-190`).
This ADR therefore keeps directed-sharing async delivery out of scope and
restricts itself to the chat/group layer plus the chat custody layer.

---

## Goals

- Let a member voluntarily hand a bounded slice of past chat history to a newly
  added member or a newly linked device of a contact.
- Let that hand-over be deposited with a custody holder when the target device
  is offline, and collected when it comes online, reusing the existing mailbox
  shapes.
- Keep the holder oblivious to content (it already is: it holds sealed bytes).
- Add no group-wide key and no change to the pairwise cipher.
- Version the wire so an older peer that does not understand the new record is
  unaffected and keeps working.

## Non-goals

- No automatic, mandatory backfill. History hand-over is always an explicit act
  by a member; the default is that a new member sees only content sent after it
  joined.
- No group-wide re-key, sender keys, or MLS-style tree. Pairwise sealing stays
  (`engine.rs:5-10`).
- No directed-sharing async/mailbox delivery (deferred by ADR-010:109-115).
- No change to who may add or remove members, or to descriptor validation
  (`membership.rs:264-311`).
- No disk persistence for the holder in this ADR (the holder is RAM-only today,
  `holder.rs` per the custody audit; persistence is a separate decision).
- No shared-file (DHT share / directed envelope) hand-over in this ADR; only the
  *pointer* form is discussed under open questions.

---

## Threat model

Parties: the **new member/device** N; an existing member **H** who hands over;
other members; a **custody holder** C that may store a sealed item for N while N
is offline; a **removed** former member R; network observers.

Properties this design must keep:

1. **A removed member must not read later content.** After the descriptor that
   removes R, no member sends group records to R, and receivers refuse records
   from anyone the newest descriptor does not list
   (`engine.rs:1068-1072`, the `is_member` check; removal path
   `engine.rs:661-698`). History hand-over must obey the same rule: a hand-over
   is addressed to a current member only, and N must be listed in the newest
   descriptor H holds before H hands anything over.

2. **A newly added member must not read earlier content unless a member hands it
   over.** Because delivery is pairwise and recipient sets are fixed at send
   time (`engine.rs:823-829`), N cannot derive or request earlier message
   bodies from the protocol itself. The only path to earlier bodies is an
   explicit hand-over by some H. There is no group key whose exposure would give
   N the past, so this property holds structurally and the ADR must not
   introduce one.

3. **Holders learn nothing.** The hand-over item deposited with C is a sealed
   pairwise envelope from H to N, exactly as a direct message would be
   (`mod.rs:9-14`). C sees a `RecipientTag`, an `ItemId`, length, and timing —
   the same metadata a connection relay sees — and no plaintext.

4. **A holder cannot inject history.** N applies a handed-over item through the
   same pairwise-open path as a direct delivery; a holder that alters bytes
   produces an AEAD failure, and a holder that supplies an item N did not expect
   still yields content sealed by H, authenticated as from H. N must treat
   handed-over messages as *claims by H about the past*, shown as such, not as
   authenticated original-sender messages (see Open Questions Q3).

5. **Replay / duplication is bounded.** Items are de-duplicated by `ItemId`
   during collection (`client.rs:148-171,196-199`) and by per-sender counter
   vectors when applied (`state.rs:60-108`, `SenderVec`). A replayed hand-over
   is a duplicate and is dropped.

Out of model: a member H who is itself malicious and hands over fabricated
"history" — N can only trust H to the extent it trusts H as a contact; the ADR
marks handed-over content as attributed-by-H, not as verified original.

---

## Design

### 1. A new, versioned group record kind: history offer

Today group records are `KIND_TEXT 0x10`, `KIND_DESCS 0x11`, `KIND_SYNC 0x12`
(`record.rs:21-23`). A peer that does not recognise a kind returns
`AckStatus::Unsupported` and is otherwise unharmed: `handle` maps an unknown
kind to `Unsupported` (`engine.rs:1008-1012`), and the group runs on its own
ALPN so a peer without groups never receives these frames on the private-chat
connection (`group/mod.rs:11-17`). This is the wire-versioning lever: a new
kind is transparently ignorable by an older app.

Introduce **`KIND_HIST_OFFER = 0x13`**: a single past message that H offers to
N, carried inside the ordinary pairwise sealed envelope from H to N, so the
bytes on the wire and in custody are indistinguishable from any other pairwise
envelope. Proposed plaintext layout, mirroring `GroupText` but marked as a
quoted/attributed record:

```text
HistOffer = 0x13 | [16] gid | u32 origin_epoch | [32] original_sender
                 | u64 original_counter | [16] original_id | u64 original_sent_ms
                 | u16 len | utf-8
```

`original_sender`/`original_counter`/`original_id`/`original_sent_ms` are copied
from the message H is quoting (fields already present on `GroupText` /
`GroupMsg`, `record.rs:36-44`, `state.rs:110-119`). This lets N show the message
in the right place and attribute it to its original author **as claimed by H**,
without letting H forge an *authenticated* message from that author (the outer
seal authenticates H, not the original author — see threat model item 4).

Why a distinct kind rather than reusing `KIND_TEXT`: a plain `KIND_TEXT` from H
with someone else's counter would either be rejected by the `SenderVec` /
`is_member` logic or, worse, be mis-attributed. A distinct kind keeps the
existing text path unchanged and keeps attribution honest.

### 2. Who sends what, and when

- **Trigger is explicit.** A member H decides to hand over history to N (for
  example when H adds N, or on an explicit "share history" action). Nothing is
  automatic; `add` stays as it is (`engine.rs:616-657`) and this ADR does not
  change it.
- **Eligibility check before sending.** H may hand over to N only if N is listed
  in the newest descriptor H holds (`Chain::latest().is_member(N)`,
  `membership.rs:248-250`) and N is not removed. This reuses the exact predicate
  that gates ordinary sends/receives (`engine.rs:1070`).
- **Selection is bounded** (see limits below): H selects the newest K messages,
  or a caller-chosen window, from its own stored log (`store.page`, used by
  `history`, `engine.rs:1262`).
- **Each selected message becomes one `HistOffer`**, sealed on H→N's pairwise
  session via the existing `ChatCore` seal path (the same path `send` uses,
  `engine.rs:851-864`), and delivered either directly or, if N is offline, via
  custody deposit (next section).
- **N applies each `HistOffer`** by recording it as an incoming, attributed
  history item, de-duplicated by `original_id` so a message N already has (from
  a later direct send, or from another H) is not shown twice. This reuses the
  idempotence already present for text (`SenderVec`, `state.rs:60-108`; id-based
  dedup mirrors `chat/sync.rs:56-77`).

### 3. Composition with the custody layer (offline new device)

When N is offline, H deposits each sealed `HistOffer` with trusted holders using
the existing client unchanged:

- `MailboxClient::deposit(holders, sender=H, recipient=N, item=ItemId(env.id),
  wire=sealed_env, now)` (`client.rs:105-133`). The item is tagged
  `RecipientTag::for_recipient(N)` (`ids.rs:12-19`), and `ItemId` is the sealed
  envelope's own id (`ids.rs:22-28`; `crypto.rs:356-358` `Envelope.id:[u8;16]`).
- N, on coming online, runs `MailboxClient::collect(holders, me=N, now, apply)`
  (`client.rs:139-201`); `apply` opens each `(sender, wire)` on N's pairwise
  session with H and feeds the plaintext to the group `handle` path
  (`engine.rs:1000-1012`), where the new `KIND_HIST_OFFER` branch records it.
- The holder stays oblivious and bounded by its hard ceilings
  (4 MiB / 1024 items / 30-day TTL; custody audit section 1, citing
  `holder.rs:22-28`). No change to the holder contract (`holder.rs:104-138`).

This is the "handover item held for an offline new device" requirement: it is
the existing Case-A mechanism, now also carrying `KIND_HIST_OFFER` items,
because the holder neither knows nor cares what kind a sealed envelope contains.

### 4. Size and rate limits (every number justified)

- **`MAX_HIST_OFFER_TEXT` = `MAX_TEXT_BYTES`.** A history offer carries one
  message body; reusing the existing per-message text ceiling
  (`record.rs:56`, `state.rs` uses `MAX_TEXT_BYTES`) means no new padding or
  envelope-size assumption and keeps `HistOffer` within the 16 KiB padded
  plaintext budget already stated for records (`record.rs:25-26`).
- **`MAX_HIST_PER_HANDOVER` = 100 messages per hand-over round.** Matches
  `MAX_PENDING = 100` (`state.rs:25-26`), the existing cap on group messages
  in flight, so one hand-over cannot queue more than the engine already allows
  to be outstanding at once.
- **Custody footprint is already capped** at 4 MiB total and 1024 items by the
  holder's hard ceilings (`holder.rs:22-28`, custody audit section 1); a
  hand-over that exceeds what a holder will take simply gets a partial deposit
  and the rest is delivered directly when N is online. No new ceiling is needed;
  stating a second, smaller one would only duplicate `holder.rs` and could drift
  from it.
- **Per-target rate: at most one hand-over round to a given N per
  descriptor epoch**, tracked in `GroupState` (new `ctrl`-like marker). Reason:
  N's membership is defined per epoch (`membership.rs:3-9`); bounding by epoch
  ties the rate to a real state change rather than wall-clock, and prevents a
  loop of repeated hand-overs when N and H reconnect repeatedly. The existing
  `owe` de-duplicates one owed item per `(to, kind)` and is the model for this
  (`state.rs:211-224`).
- **`MAX_COLLECT` = 128** per collection is unchanged (`client.rs:16`); it
  already bounds how many items N pulls in one pass.

### 5. Failure and replay handling

- **Direct send fails / N offline:** fall back to custody deposit (section 3);
  if no holder takes it, the offer waits and is retried like any pending item.
  This mirrors the existing "otherwise they wait in the outbox and are retried"
  behaviour (`chat/mod.rs:7-9`).
- **Duplicate offers:** two H's may hand over the same original message. N
  de-duplicates by `original_id`; the second is dropped before display
  (model: `chat/sync.rs:56-77` id matching; `SenderVec` idempotence
  `state.rs:60-108`).
- **Replay by a holder:** `collect` de-duplicates by `ItemId` within a round and
  deletes taken copies (`client.rs:148-171,196-199`); a re-presented item is a
  known duplicate.
- **N removed between offer and collection:** when N applies the offer, the
  `is_member` check on the newest descriptor N holds still governs the live
  group; a `HistOffer` is attributed history, not a live post, so applying it
  does not reopen membership. If N has been removed, N may still read what it
  legitimately received while a member; it gains nothing later because no new
  offers are addressed to a non-member (eligibility check, section 2).
- **Malformed / unknown kind at an older peer:** returns `Unsupported`
  (`engine.rs:1010`) and the connection is not harmed; the sender records a
  non-delivery for that target and does not retry a kind the peer rejects.

### 6. Wire versioning (older peers keep working)

- The only wire addition is `KIND_HIST_OFFER = 0x13`. An older app's `Record`
  decoder returns `UnknownKind(0x13)` -> `handle` -> `AckStatus::Unsupported`
  (`record.rs:111-168`, `engine.rs:1008-1012`), so it neither applies nor
  crashes, and the group connection stays open because these frames only travel
  on the group ALPN that an older-but-group-aware peer already tolerates
  (`group/mod.rs:11-17`).
- No change to `DESCRIPTOR_VERSION` (`membership.rs:29`), to `STATE_VERSION`
  (`state.rs:23-24`, already v2 with a v1 read path), or to `ENVELOPE_VERSION`
  (`crypto.rs:383`). If `GroupState` needs a new per-epoch hand-over marker,
  bump `STATE_VERSION` to 3 and keep reading v1/v2 exactly as the current code
  reads v1 under v2 (`state.rs:301-430`), so a downgrade still parses.
- The custody wire is unchanged: deposit/list/fetch/delete already carry opaque
  blobs (`client.rs:30-61`), so a holder needs no update to carry `HistOffer`
  items.

---

## PR-sized implementation steps (each with its test)

1. **Add the `HistOffer` record type and codec.** New `KIND_HIST_OFFER = 0x13`,
   `encode`/`decode` in `record.rs`. Test: round-trip including multibyte text
   and every-prefix-is-refused, mirroring
   `record.rs:218-236`; and that `0x13` is `UnknownKind` for a decoder built
   without it (mirror `record.rs:238-245`).
2. **Record and display attributed history on apply.** Extend `handle` with a
   `Record::HistOffer` branch that records an incoming, attributed item,
   de-duplicated by `original_id`. Test: an offer from H is shown attributed to
   `original_sender`, a second identical offer is a no-op, and an offer for an
   unknown group is `NotAllowed` (mirror `engine_tests` patterns).
3. **Eligibility + selection on the sender.** A `handover(gid, to, window)`
   method that checks `latest().is_member(to)`, selects ≤
   `MAX_HIST_PER_HANDOVER` from `store.page`, and produces sealed offers. Test:
   refuses a non-member and a removed member; selects at most the cap; selects
   newest-first.
4. **Per-epoch rate marker in `GroupState`.** Add the marker, bump
   `STATE_VERSION` to 3 with a v1/v2 read path. Test: round-trip, and that a
   pre-v3 document still decodes (mirror `state.rs:573-584`).
5. **Custody carriage of offers.** Wire `handover` to `MailboxClient::deposit`
   when the direct send reports the target offline, and apply via `collect`.
   Test: a simulation like `mailbox/sim_tests.rs:174-222` but the deposited item
   is a `HistOffer`; N offline, then online, applies it once; holder drops it.
6. **Non-delivery / unknown-kind handling.** Ensure an `Unsupported` from an
   older peer records non-delivery and is not retried as that kind. Test: a
   stub peer that rejects `0x13` yields a recorded failure and no retry loop.

Each new test file must be added to the CI manifest
(`.github/workflows/ci.yml`) and verified with
`python scripts/check_ci_test_manifest.py`; tests must be platform-neutral.

---

## Resolved by the owner

The open questions were decided as follows, and this change implements those
decisions.

1. **Policy default: opt-in.** History is handed over only when a current member
   explicitly chooses to; there is no automatic backfill and no admin-forced
   backfill. A member starts a round through the user-facing action only
   (`GroupRequest::ShareHistory`); nothing is shared otherwise.
2. **Message bodies only.** A round hands over message *bodies* only. File
   hand-over (a share pointer or a directed envelope) is out of scope and is
   left to a possible later ADR, so ADR-006's anti-misdirection property is not
   reopened here.
3. **Attribution: attributed-by-H display is acceptable.** A handed-over message
   keeps the original author in `sender` and names the member who passed it on
   in `shared_by` (`ipc.rs` `GroupMessageInfo.shared_by`). Author-signed history
   is not required and is not introduced.
4. **Any current member may hand over.** Eligibility gates on the target being a
   current member, not on the sender's role; admins have no special rights here.
5. **Holder persistence: RAM-only, best-effort.** Offers are kept in memory and
   do not survive a holder restart. Disk persistence for a long-offline new
   device is explicitly not in this change.
6. **Retention sweep wins.** Hand-over is best-effort over what the member still
   holds; if `sweep_retention` has removed old messages, they are simply not
   offered. This is accepted.

The custody transport for an offline target (step 5) is a separate job. This
change leaves it as the named seam `GroupCore::custody_offers_for`, which direct
pairwise delivery does not depend on.

---

## Relationship to other ADRs

- **ADR-006 / ADR-010:** directed-sharing async delivery stays out of scope and
  deferred (`010...md:109-115,183-190`). This ADR touches only the chat/group
  layer and the chat custody layer.
- **Custody audit (internal report):** this ADR is the Case-B design that the
  audit's section 2 identified as missing; it reuses the Case-A custody
  machinery the audit's section 1 documented as implemented but unwired.
