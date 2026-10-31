# Custody / store-and-forward audit: "file kept on another node, delivered on reconnect"

Branch: `call/custody-audit` (from `main`). Read-only investigation; every claim below cites a file:line that was read directly. Line numbers are 1-based as read.

## Scope recap

Owner's question: when a new device joins (a participant is added), can a file be left with another node and handed over once that device is back online? How far is this designed and implemented?

Two distinct cases must be kept apart, because the code treats them differently:

- **Case A — offline *recipient*** (a known contact who is simply not online right now).
- **Case B — newly *added device / participant*** (a member/device that did not exist, or held no history, at the time the content was sent).

---

## 1. What exists for 'file kept on another node and delivered on reconnect'

There is a working **custody / mailbox** layer for the one-to-one chat channel. It is store-and-forward for **Case A only**, and it is **not wired into the running node** yet.

### 1.1 The custody store (holder side) — IMPLEMENTED (in-memory, library-level)

- `crates/miasma-core/src/chat/mailbox/mod.rs:1-21` — module doc states plainly: "Holding a sealed message for a contact who is offline... This is the in-memory part only... **No network protocol uses it yet and nothing here listens for connections**; a node that holds nothing (the default, `chat.custody_enabled = false`) refuses every deposit." It declares `pub mod client; pub mod holder; pub mod ids;` and a `#[cfg(test)] mod sim_tests;`.
- `crates/miasma-core/src/chat/mailbox/holder.rs:1-10` — doc: "The custody store: sealed envelopes held for contacts who are offline. Everything is bounded and nothing is written to disk".
- `holder.rs:104-138` — `trait CustodyStore` with `deposit` / `list` / `fetch` / `delete` / `sweep` / `stats`. This is the full holder contract.
- `holder.rs:185-341` — `MemoryCustody` implements that trait entirely in RAM (`holder.rs:184` "Contents are lost when the process ends."). Trust-gating (`trust`/`revoke`, `holder.rs:210-227`), the disabled-by-default gate (`check`, `holder.rs:229-237`), per-item / per-depositor / total caps and TTL expiry (`deposit`, `holder.rs:241-286`) are all present and unit-tested (`holder.rs:373-564`).
- Hard ceilings that settings cannot raise: `holder.rs:22-28` (`HARD_MAX_TOTAL_BYTES = 4 MiB`, `HARD_MAX_ITEMS = 1024`, `HARD_MAX_TTL_MS = 30 days`), enforced by `clamped` (`holder.rs:66-72`).
- What is held is **the sealed envelope exactly as it would go on the wire**, so the holder learns nothing a connection relay would not (`mod.rs:10-14`). One copy per holder; no fragment splitting (`mod.rs:13-14`).

### 1.2 The depositor / collector (client side) — IMPLEMENTED (library-level)

- `crates/miasma-core/src/chat/mailbox/client.rs:1-6` — doc: "deposit a copy of a sealed envelope with some trusted contacts, and collect what is waiting for us from them... **Nothing is sent anywhere by this crate yet: the only transport is the one the tests build.**"
- `client.rs:30-61` — `trait MailboxTransport` (the network is abstracted away; no concrete impl ships).
- `client.rs:105-133` — `MailboxClient::deposit`: puts a copy with up to `copies` holders, skips the recipient itself, prepends the sender id to the sealed bytes.
- `client.rs:139-201` — `MailboxClient::collect`: lists/fetches from each holder, de-duplicates by item id, hands each item to a callback, and deletes taken copies from the holders.
- Recipient addressing is a derived tag, not a plaintext id: `crates/miasma-core/src/chat/mailbox/ids.rs:12-19` (`RecipientTag::for_recipient` = BLAKE3 derive_key). `ItemId` is the sealed envelope id (`ids.rs:22-29`).

### 1.3 Proof it delivers on reconnect — IMPLEMENTED as a simulation test only

- `crates/miasma-core/src/chat/mailbox/sim_tests.rs:1-9` — "Three nodes in one process: a sender, a recipient who is offline, and a third trusted contact that holds the sealed envelope in between. The 'network' is a table of in-memory stores".
- `sim_tests.rs:174-222` — `a_message_reaches_an_offline_recipient_through_a_third_trusted_node`: A deposits with holder C while B is offline; B comes back online, collects from C, and applies the message; the holder then drops it. This is exactly the "left with another node, handed over when back online" shape — **for an offline contact**.
- Further tests cover de-dup vs. a later direct send (`sim_tests.rs:224-247`), two holders applied once (`sim_tests.rs:249-268`), skipping a down/disabled holder (`sim_tests.rs:270-317`), expiry then direct delivery (`sim_tests.rs:319-349`), flood limits (`sim_tests.rs:351-416`), and junk rejection (`sim_tests.rs:418-443`).
- The whole simulation runs on `#[cfg(test)]` test scaffolding: `Side`/`side()` live in `crates/miasma-core/src/chat/offline_tests.rs:18-50`, gated `#[cfg(test)] pub(crate) mod offline_tests;` at `crates/miasma-core/src/chat/mod.rs:36-37`.

### 1.4 The complementary catch-up path — IMPLEMENTED, but it is sender-held, not third-party

- `crates/miasma-core/src/chat/sync.rs:1-15` — after a pause, **the sender** compares what it still holds for a contact against what the contact has applied, by message id, so nothing is re-sent. Three plain functions: `request_for` (`sync.rs:24-37`), `answer` (`sync.rs:42-51`), `apply_reply` (`sync.rs:56-77`).
- This is the normal "both sides online again" reconciliation; the sealed message waits in the sender's own outbox, not on a third node (`crates/miasma-core/src/chat/mod.rs:7-9`: "otherwise they wait in the outbox and are retried").

### 1.5 Wiring status — NOT wired into the node/service

- `custody_enabled` exists only as a config flag, default off: `crates/miasma-core/src/config.rs:361` (`pub custody_enabled: bool`) and `config.rs:389` (`custody_enabled: false`). It is read only by `CustodyLimits::from_config` (`holder.rs:57-64`).
- The chat service does not reference custody/mailbox at all: a `custody` search of `crates/miasma-core/src/chat/service.rs` returned no matches. The crate root does not re-export it either: a `custody|mailbox` search of `crates/miasma-core/src/lib.rs` returned no matches, so it is an internal `pub mod` (`chat/mod.rs:19`) with no live caller.
- Conclusion for §1: the holder + client + recipient-tag + bounded-store machinery is **implemented and tested in RAM**, but there is **no transport, no listener, no disk persistence, and no service call site**; it is off by default.

---

## 2. What is missing for the added-device case (Case B)

Nothing in the repository implements "hold a file for a device/participant that was just **added**, and hand it over when that device first comes online." The pieces that look adjacent are all about Case A (an existing contact that is merely offline) or about something else.

- **The custody layer targets a *recipient contact*, not a new device.** The held item is tagged by `RecipientTag::for_recipient(recipient)` (`ids.rs:12-19`; `client.rs:114`), and delivery assumes the recipient already shares the sealed-envelope key path (`collect` applies it "exactly as a direct delivery", `sim_tests.rs:158-172`). A freshly added device that was never a party to the original send is not modelled.
- **Group membership has no history hand-over on add.** `crates/miasma-core/src/chat/group/membership.rs:1-23` describes a signed, epoch-numbered descriptor chain; `membership.rs:21-23`: "A person who is invited holds no history yet. The first descriptor they get becomes the root of their chain." That is membership/authorisation only — there is **no mechanism here to backfill past messages or files to the new member**, and no re-key-then-redistribute step. (`Member`/`Role` at `membership.rs:42-71`.)
- **Directed (private) sharing has no asynchronous/held delivery at all.** ADR-006 and ADR-010 require both parties to be mutually reachable: `docs/adr/ADR-006-directed-private-sharing.md:314-317` ("Connectivity requirement: the sender and recipient must be mutually reachable") and `docs/adr/010-directed-sharing-transport-architecture.md:57-59` ("Directed sharing requires bidirectional P2P reachability"). The asynchronous mailbox option was explicitly **deferred**: `010...md:183-190` ("Asynchronous mailbox/inbox layer... Deferred as a potential future protocol extension, not a near-term implementation") and listed out-of-scope at `010...md:113-114`. A search of `crates/miasma-core/src/directed/inbox.rs` for custody/mailbox/offline/store-and-forward returned no matches.
- **The directed "retention node" is not a holding node.** Despite the name, `crates/miasma-core/tests/directed_retention_node_test.rs:1-9` only tests that a *receiving* node caps the sender-chosen retention window (`expires_at`, `retention_secs`) and refuses a nonsensical one; it does not store a file on behalf of an absent device. The capping logic it exercises is `normalize_received_retention` in `crates/miasma-core/src/directed/envelope.rs:280-296`.
- **Release scope does not mention it.** Current release is `v0.3.2-beta.13` (`RELEASE-NOTES.md:1`), whose theme is contact calls (`RELEASE-NOTES.md:3-11`); a search of `RELEASE-NOTES.md` for custody/mailbox/offline/"new device"/"added device" returned no matches. `beta.12` (`RELEASE-NOTES.md:31-60`) likewise does not mention it.

So the gap for Case B is: (a) no backfill-on-add in group membership; (b) no held/async delivery for directed sharing (deferred by ADR-010); (c) the one store-and-forward layer that does exist is recipient-scoped, RAM-only, and unwired.

---

## 3. Minimal design sketch for the missing part, and beta.13 scope

### 3.1 Smallest thing that would satisfy the owner's literal request

The owner's request ("a file can be left with another node and handed over when that device is back online") is **already matched by the existing chat custody layer for Case A** — it only needs to be *wired up*, not redesigned. A minimal, in-scope-shaped increment:

1. **A concrete `MailboxTransport` over the existing chat transport.** Implement `MailboxTransport` (`client.rs:30-61`) as request/response over the same channel chat already uses (`chat/mod.rs:1` ALPN `miasma/chat/1`), carrying the four verbs `deposit/list/fetch/delete`. No new crypto: the blob is the already-sealed envelope (`mod.rs:10-14`).
2. **A listener + store instance behind the flag.** When `custody_enabled` is true (`config.rs:361`), the service (`chat/service.rs`) constructs a `MemoryCustody` (`holder.rs:192`), seeds `trust` from the contact list (`holder.rs:210`), and answers the four verbs; keep it off by default.
3. **Call deposit on outbound-while-offline and collect on reconnect.** Hook `MailboxClient::deposit` when a direct send fails and `collect` on connect, alongside the existing sender-held catch-up (`sync.rs:24-77`) so the two do not double-deliver (already proven compatible in `sim_tests.rs:224-247`).

That is Case A only. It does **not** solve Case B (added device / new member backfill), which needs a separate design: a re-key event on member-add in `membership.rs`, plus a decision on whether past content is redistributed to the new member at all (a policy question, not just a transport one). Directed-sharing async delivery would additionally reopen ADR-006's anti-misdirection property, which ADR-010 flags as the reason it was deferred (`010...md:186-189`).

### 3.2 Does it belong in beta.13?

- **beta.13 is already released** and its theme is calls (`RELEASE-NOTES.md:1-11`); it is not an open scope to add to.
- **Case A wiring (3.1):** small and self-contained, off by default, no protocol/crypto change — a reasonable candidate for a **later beta (beta.14+)**, not a retrofit into the shipped beta.13.
- **Case B (added-device backfill / directed async):** **later, and ADR-gated.** It touches group re-keying and reopens a property ADR-010 deliberately deferred (`010...md:183-190`); it should not be slipped in without its own ADR. Not beta.13, and not a quick follow-on.

---

## Appendix — files read for this audit

- `docs/adr/ADR-006-directed-private-sharing.md` (full)
- `docs/adr/010-directed-sharing-transport-architecture.md` (full)
- `crates/miasma-core/src/chat/mailbox/mod.rs`, `holder.rs`, `client.rs`, `ids.rs`, `sim_tests.rs` (full)
- `crates/miasma-core/src/chat/sync.rs` (full), `chat/offline_tests.rs:1-70`, `chat/mod.rs` (full)
- `crates/miasma-core/src/chat/group/membership.rs:1-90`
- `crates/miasma-core/tests/directed_retention_node_test.rs` (full)
- `crates/miasma-core/src/config.rs:361,389` (via grep); `src/lib.rs`, `src/chat/service.rs`, `src/directed/inbox.rs` (via grep — negative results)
- `RELEASE-NOTES.md:1-60`
- Confirmed absent: `docs/research` (not found); working tree clean on `call/custody-audit` (`git status`).
