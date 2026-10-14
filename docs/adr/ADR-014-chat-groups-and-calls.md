# ADR-014: Chat, groups, read receipts and voice calls (no operator)

- **Status**: Proposed (design only; no code in this PR)
- **Date**: 2026-10-15
- **Depends on**: ADR-012 (trusted-contact push, implemented), ADR-013 (state
  encryption, ledger, stealth, RAM budget: **designed, not yet implemented**; see 3.4)
- **Related**: ADR-006 / ADR-010 (Directed Sharing; ADR-010 deferred a mailbox layer,
  this ADR is that layer for contacts), ADR-008 (transport strategy)

## 要約 (日本語)

**目的**: Miasma に「チャット」を足します。登録済みの連絡先との 1 対 1 のチャット、グループチャット、音声通話、既読表示です。絵文字リアクションは作りません。サーバは使いません。運営者もいません。ファイルと同じく「小さな暗号化された断片を、みんなが少しずつ持つ」考え方で、相手がオフラインでも届くようにします。

**先に結論(いちばん大事な 3 点)**:
1. **今の利用者は 2 人だけなので、2 人でも成り立つ設計にしました。** 相手がオンラインなら、今ある iroh の直接接続(ファイル送信と同じ道)でそのまま届けます。相手がオフラインなら、メッセージは送り手の端末の暗号化された「送信待ち箱」に残り、相手がオンラインになったら自動で再送します。ノードが 3 台以上に増えたら、暗号化した断片を他のノードにも預けられるようになり、送り手も相手もオフラインでも届くようになります(段階 4)。
2. **小さなメッセージに「ファイル用の断片化」をそのまま使うのは不向きです。** いまの仕組みは 1 つの共有を 20 個に分け、1 個ごとに鍵の断片や索引を持つため、1 KiB のメッセージが約 4.5 KiB になり、さらに 20 台に 20 個のファイルを作ります。しかも個人の PC は半分の時間しかオンラインでないので、「k 個そろわないと読めない」方式は、同じ個数のコピーをばらまく方式より届きにくくなります(計算は 8.4)。そこで、メッセージ用に**「宛先専用の郵便受け」**(相手ごと・日ごとに変わる見えない ID)を別に作り、中身は端末間で暗号化済みの小さな封筒を定型サイズに水増しして、複数のノードに**コピー**を預けます。断片の形式は将来 k>1 の分割にも使えるようにしておきますが、v1 の既定はコピー方式です。
3. **預かるノードは、誰と誰の会話かを中身からは知れません。** ただし、預ける人と取りに来る人が同じノードに接続するため、「そのノードが 2 つの接続を結びつけられる」という漏れは残ります。これを正直に書き、段階 7 で緩和策(経由ノードを 1 つ挟む等)を検討します。

**決定済みの事項(オーナー)**: グループは自動で信頼しません(参加時に他のメンバーの連絡先コードを見せ、各自が「追加」を押す。既定は拒否のまま)。履歴は既定で保存し、ADR-013 の状態鍵で暗号化します。秘匿プリセットとポータブル版は保存しません。実装順は 1 対 1、グループ、通話と既読の順です。運営者は置かず、中央サーバも中央ログもなく、第三者のリレーだけを使います。

**暗号**: 端末間暗号化は、相手の連絡先コード(= 公開鍵)だけから始められる「Double Ratchet」型です。盗まれた端末から過去のメッセージを読まれにくくします(前方秘匿)。初回の数通だけは相手の長期鍵が漏れたときの保護が弱い、という限界も書きました。

**グループ**: 管理者が署名したメンバー表(世代番号つき)を使い、メンバー変更のたびに世代を上げ、メンバーを外すときは全員が鍵を作り直します。20 人までを想定します(メンバーを外すたびに、残った全員が互いに鍵を送り直すので、19 人が残る場合で約 340 通の短い鍵メッセージ)。参加すると、他のメンバーの連絡先コードと確認用コードが表示され、各自が自分で「連絡先に追加」を押すまでは、そのメンバーは「未登録」として文字のみ・低頻度に制限されます。

**通話**: 既存の iroh の QUIC 接続の上で、Opus 音声を暗号化したデータグラムで送ります。呼び出しは連絡先だけが可能です。リレー経由になったら「音質が悪い場合があります」と表示します。ビデオ、グループ通話、画面共有は v1 の対象外です。

**RAM(必須要件)**: チャット追加分は、待機時 +12 MiB 以内、通話中 +30 MiB 以内(プロセスごと)。部品ごとの上限を 13 章に、測り方を各段階のテストに入れました。

**段階**: 0 土台(状態の暗号化と計測) → 1 メッセージ保存とワイヤ・送信待ち箱(1 対 1、CLI) → 2 GUI の「チャット」タブ → 3 配達・既読 → 4 郵便受け(オフライン配送) → 5 グループ → 6 音声通話 → 7 強化(水増し、鍵の更新、撤回)。それぞれ小さな PR で、テストと受け入れ基準があります。

**法的な注意**: 運営者を置かない設計でも、日本の電気通信事業法の対象になるか、他人の暗号化データを預かるノードの扱いなどは、私には判断できません。広く配る前に専門家に確認することを勧めます(18 章。法的助言ではありません)。段階 4(他人の断片を預かる機能)は、確認が済むまで既定オフで出すことを推奨します。

**オーナーに決めてほしいこと**は 19 章(10 件、それぞれ推奨つき)、**確認できなかったこと**は 20 章にあります。

---

## Decisions already taken (owner, 2026-10-15)

| # | Decision | Lands in |
|---|---|---|
| D1 | 1:1 chat with **registered contacts** and **group chat**, plus **voice calls** and **read receipts**. **No emoji reactions.** | 5 to 12 |
| D2 | Miasma/Freenet model: **no server, nobody operates anything**, small encrypted fragments held by many nodes, "P2P like LINE" for calls. | 4, 8, 12 |
| D3 | **Groups are not auto-trusted.** On joining, the other members' contact codes are shown; each person presses "add" themselves. Default-deny stays. | 11.3 |
| D4 | **History is saved by default**, encrypted at rest with the ADR-013 state key. The stealth preset and the portable build switch to ephemeral (no save). | 5.8, 14 |
| D5 | **Order**: 1:1 first, groups second, then calls and read receipts "as designed". (Phases below keep receipts before groups only because receipts are tiny and a prerequisite for outbox correctness; see 15.) | 15 |
| D6 | The owner **operates no server**; users are private individuals. The design must stay "no operator": no central server, no central logging, third-party relays only. | 2, 18 |
| D7 | **Only 2 users today.** With fewer than 3 nodes the system is direct delivery plus a sender-side encrypted outbox with retry; it gets better (offline delivery through fragments on other nodes) as nodes appear. | 4.3, 7, 8 |
| D8 | **RAM management is a must**: idle +12 MiB, in a call +30 MiB over baseline. | 13 |

## 1. Context

Contacts and file push (ADR-012) already give two people a mutually registered,
authenticated, default-deny channel over iroh. ADR-010 explicitly deferred an
asynchronous mailbox ("Sender deposits envelope to a relay node; recipient
polls", `docs/adr/010-directed-sharing-transport-architecture.md:183-190`) and
ADR-012 lists "no groups, no relay store-and-forward, no offline delivery" as
non-goals. This ADR adds text chat, groups, receipts and calls on top of the
same identity and the same endpoint, and defines the one new thing the earlier
ADRs avoided: an offline store-and-forward layer that has no operator.

### Goals

1. A message between two registered contacts arrives when both are online, and
   arrives later when one is not, without any server.
2. The design works with 2 nodes and improves with more.
3. Message content and (as far as possible) the social graph are hidden from
   the nodes that carry or store fragments.
4. Everything at rest follows ADR-013 (state key, crypto-erase, ledger, stealth).
5. Every new buffer, cache, queue and store has a byte or count cap.

### Non-goals (v1)

- Anonymity. Like ADR-012, the peer knows your endpoint ID; in `n0` mode your ID
  and addresses go to n0 discovery (`transport/iroh_direct.rs:932` privacy notice).
- Multi-device for one identity (5.9).
- Video, group calls, screen share, voice messages, stickers, emoji reactions,
  typing indicators, online/last-seen presence, link previews, message editing.
- Phone-number or e-mail based discovery. Contacts are added only by code
  (ADR-012).
- Moderation, abuse reporting to an operator, takedown. There is no operator.

## 2. Principles: "no operator"

The owner runs nothing and users are private individuals. Therefore:

1. **No central server** of any kind: no account service, no push-notification
   relay run by the project, no directory, no "message server", no TURN server.
2. **No central logging or telemetry.** Nodes keep no logs by default (ADR-013
   section 4 stealth logging: in-memory ring buffer only). Chat adds no
   analytics.
3. **Third parties only for what iroh already uses**: n0 public relays and n0
   discovery in `n0` mode, or the user's own `custom` relay (`IrohMode`,
   `config.rs:124-129`). The project does not run or fund them; this ADR does
   not add new third-party dependencies for the data path.
4. **Every node may be a holder, nobody is a custodian.** A holder stores
   opaque, padded, end-to-end encrypted fragments for a bounded time and cannot
   read, authenticate or attribute them.
5. **Defaults are safe if nothing is configured**: unknown senders are refused,
   holders have a quota, hosting is off in the stealth preset.

## 3. What exists today, what can be reused, what does not fit

All citations are to `origin/main` at `bdf3cd1` (2026-10-14).

### 3.1 Identity, transport, trust (reused as is)

| Fact | Where | Use in this ADR |
|---|---|---|
| A contact is the other node's iroh endpoint ID = Ed25519 public key = the publisher key of its share IDs; text form `miasma-contact:<base58(version, id, checksum)>`; fingerprint shown beside it | `push/contact.rs:15-28,74-140`; ADR-012 "Identity and trust" | Chat identity. No new directory, no new code format. |
| The libp2p PeerId key and the iroh endpoint key are the same Ed25519 seed (`dht_signing_key`, an HKDF output of `master.key`) | `network/node.rs:2116-2130`; `transport/iroh_direct.rs:1-9`; `crypto/keyderive.rs:7-11,30-37` | A DHT peer's ID is a dialable iroh endpoint ID. This is what lets the mailbox plane find holders from the existing routing table (8.3). |
| Allow-list default-deny: unknown dialers are closed with application error 403 right after the handshake; the gating is re-checked for every stream; per-id token bucket with bounded memory | `push/service.rs:983-1032`, `push/service.rs:121-163`, `push/proto.rs:85-89` | The chat ALPN uses the same pattern, the same close codes, the same limiter shape. |
| Contacts store: versioned JSON, atomic write, 500 entries, per-contact switches (`allow_send`, `allow_receive`, `max_file_size`) | `push/store.rs:22-52,213` | Chat adds per-contact `allow_chat`, `allow_call`, `read_receipts` (defaults in 14). Same store, additive fields (`#[serde(default)]`). |
| The remote identity is `Connection::remote_id()`, proven by the QUIC/TLS handshake; nothing inside a message is believed | `push/service.rs:992`; ADR-012 | Transport authentication is free. The message layer adds E2E on top (5). |
| Several ALPNs on one endpoint; accept loop dispatches on `conn.alpn()`; `connect_alpn` / `dial_alpn` dial any ALPN; the ALPN list is fixed where the builder is made | `transport/iroh_direct.rs:64,67,69-75,242,350,529,828` | New ALPNs `miasma/chat/1`, `miasma/mbx/1`, `miasma/call/1` are added at the same three places. |
| `IrohDirectClient::path_kind()` reports `direct` or `relay` for the selected path | `transport/iroh_direct.rs:721-738` | "relayed: quality may be poor" warning in calls (12.5). |
| Accept-side hardening: connection cap 64, handshake timeout, declared-length checks before any buffer is sized | `transport/iroh_direct.rs:251-275,585-600` | Same discipline for chat frames. |
| The push module is injectable for tests (`free_space` function slot) and has a loopback test with a local relay | `push/service.rs:51-66`; `tests/push_test.rs`; `Cargo.toml:69-71` (`iroh-relay` `test-utils`) | Test plan (16) reuses the pattern: no traffic to public services. |

### 3.2 The file path: dissolution, shares, store, DHT (what a "tiny object as fragments" would cost)

| Fact | Where |
|---|---|
| One content item: AES-256-GCM encrypt (random key and nonce) -> Reed-Solomon (default k=10, n=20) -> Shamir split of the content key into n key shares -> one `MiasmaShare` per shard | `pipeline.rs:28-38,60-110`; `dissolution/segment.rs:51-100`; `crypto/aead.rs:1-35`; `crypto/rs.rs:7-9`; `crypto/sss.rs:15` |
| A share carries: version, `mid_prefix` (8 B), segment index, slot, `shard_data`, `key_share` (about 33 B), `shard_hash` (32 B), nonce (12 B), `original_len`, `timestamp` | `share.rs:33-72` |
| Shard length is rounded up to an even number and the data is zero-padded to k shards | `crypto/rs.rs:34-47` |
| Segments are 64 MiB by default; the design target is files of "1 KB to 100 GB" | `dissolution/manifest.rs:12`; `dissolution/mod.rs:1-6` |
| Pieces are addressed by `BLAKE3(bincode(share))`; each is one encrypted `.ms` file | `store.rs:562-566`; ADR-013 appendix D5 |
| Finding pieces: the receiver needs the MID (and, in a share ID, the publisher key) and asks the DHT for the signed `DhtRecord` listing `ShardLocation`s (peer, shard, segment, addresses), then fetches each piece from the named holder | `transfer/share_id.rs:1-25`; `network/types.rs:23-55`; `retrieval/source.rs:14-60`; `network/node.rs:58-65` |
| Pushing a piece to a stranger: libp2p `StoreRequest`, only from admission-verified (PoW) peers, into a separate hosted quota (default 1024 MiB), per-principal budget (25 percent, floor 16 MiB), **never evicts**, **no expiry** | `network/node.rs:86-145,5177-5230`; `store.rs:43-58,630-660,745-753`; `config.rs:78`; ADR-013 7.3 ("no TTL on shares") |
| DHT records live 24 h and are re-announced by the replication engine | `network/node.rs:5402`; `daemon/replication.rs` |
| Directed Sharing: recipient-bound ECDH envelope (ephemeral X25519 -> recipient key), HKDF labels `miasma-directed-content-v1` / `-envelope-v1`, retention periods 10 min to 30 days, **needs a live libp2p handshake** and a password + confirmation code per envelope | `directed/envelope.rs:1-37,91-110,259-345`; ADR-006 sections 4, 7 |

### 3.3 What can be reused and where it does not fit

**Reusable pieces** (as code or as a pattern):

- `crypto/rs.rs` (`rs_encode` / `rs_decode`): works for any k and n including
  `k == n` and tiny inputs. Reused as is if k > 1 is ever used.
- The hosted-store *policy*: separate quota from owned data, per-principal
  budget, reject rather than evict (`store.rs:630-660`). Reused as a policy for
  a new, separate mailbox store.
- The Directed Sharing key-agreement pattern (ephemeral X25519 + HKDF with a
  versioned label, non-contributory check at `directed/envelope.rs:286`).
- Push's contact gate, limiter, close codes, and length-prefixed JSON framing
  with a hard frame cap (`push/proto.rs:21-27`).
- `ContactStore` and the contact code / fingerprint as the only identity.

**Where "message = a tiny object dissolved like a file" does NOT fit** (the
estimates below are by hand from the field lists above, not measured):

1. **Overhead.** A 1 KiB message padded and encrypted is about 1040 B. With the
   default k=10, n=20 each shard is 104 B; each share adds about 120 B of
   fields and serialization (key share, hashes, nonce, lengths), so a message
   becomes about 20 x 224 B = **4.5 KB**, then each share is wrapped again as
   an encrypted `.ms` file at the holder (24 B nonce + 16 B tag) and costs one
   file-system entry (4 KiB cluster on most volumes: about **80 KB of disk for a
   1 KiB message across the 20 holders**). The signed `DhtRecord` with 20
   locations and addresses adds several KB more, and the replication queue and
   WAL add a persisted item per message. Fixed costs dominate under about 16 KiB.
2. **The Shamir key share is redundant.** For files the key is not known to the
   recipient, so it is split among holders. For chat the key comes from the
   pairwise ratchet; there is nothing to split.
3. **Latency.** Publishing is dissolve + DHT put + replication, retrieval is
   DHT get + k fetches. That is seconds to minutes, and it needs the libp2p
   DHT and PoW admission to be up. Chat needs sub-second on the direct path.
4. **Discoverability and metadata.** The DHT key is the MID: stable for the
   life of the object, readable by every DHT node on the lookup path, and the
   record names the holders. A mailbox needs identifiers that are unlinkable to
   people and rotate. The share ID model (publisher key + MID in a typed
   string) has no counterpart for "recipient polls for anything addressed to
   me".
5. **Lifetime.** Hosted pieces never expire (`store.rs:630`; ADR-013 7.3). A
   message store must expire by itself, otherwise a holder's quota fills with
   dead messages.
6. **Availability math.** Erasure coding with k > 1 *lowers* availability when
   holders are personal PCs that are online about half the time (8.4).
7. **Request/response admission.** `StoreRequest` is libp2p-only and gated by
   PoW admission; contacts live on iroh. A second transport for the same
   feature would double the connection and memory cost on small machines.

**Conclusion.** Reuse the identity, the transport, the quota *policy*, and the
RS codec. Do **not** route messages through `pipeline::dissolve`, `MiasmaShare`,
`DhtRecord` or the replication queue. A new, small mailbox protocol (8) is
cheaper and has the properties chat needs. The fragment format is general
enough (k, n in the header) that the same mechanism can carry larger objects
later.

### 3.4 What does not exist yet (dependencies)

`git grep -i -E 'StateCrypto|mem_probe|KeyVault|stealth'` over `crates/*.rs` at
`bdf3cd1` finds **nothing**: ADR-013 is a design. Chat needs from it:

- the state key and document / record-log formats (ADR-013 5.1, 5.2);
- the saved-file ledger for attachments (ADR-013 6);
- the stealth flag and the portable-build flag (ADR-013 4, 8.5);
- the `mem_probe` helper (ADR-013 10.3).

**Decision**: phase 0 (15) extracts the smallest useful slice (`StateCrypto`
doc + record log, the label registry, `mem_probe`) as its own PR that ADR-013's
phase 3 later adopts, instead of chat inventing a private format. If the owner
prefers to wait for ADR-013 phase 3, chat phase 1 slips behind it; the chat
code is written against a `ChatStateStore` trait either way.

## 4. Architecture

Four planes, all inside the existing daemon and the existing iroh endpoint.
The GUI and CLI talk to the daemon over IPC, as they do for push (one additive
`ControlRequest::Chat(ChatRequest)` / `ControlResponse::Chat(ChatResponse)`
pair next to `Push`, `daemon/ipc.rs:207,540`).

```
                 GUI "チャット" tab / CLI `miasma chat ...`
                                  | IPC (ChatRequest)
   +------------------------------v------------------------------------+
   | ChatService (daemon)                                                |
   |   ChatStore (encrypted, per-conversation record logs, ADR-013)      |
   |   Sessions (ratchet state)   Outbox (sealed envelopes + retry)      |
   |   Groups (descriptors, sender keys)   Prefs                         |
   +---+----------------+-------------------+------------------+--------+
       |                |                   |                  |
  A. direct plane   B. outbox         C. mailbox plane    D. call plane
  ALPN miasma/chat/1  (local, sender)  ALPN miasma/mbx/1   ALPN miasma/call/1
  contact/member-     retry + backoff  holders keep opaque  contacts only,
  gated, 1 stream     + flush on       padded fragments     QUIC datagrams,
  per request         inbound contact  under rotating ids   Opus, E2E keys
       \________________ iroh endpoint (QUIC, hole punch, relay) ________/
```

- **A. Direct plane.** The default. Both ends online: the sender dials the
  contact's endpoint ID and delivers the sealed envelope on a stream; the
  receiver stores it durably and answers `Ack`. No third party sees anything but
  QUIC ciphertext (relay and discovery see which endpoint IDs talk, as for push).
- **B. Outbox.** Anything not acknowledged stays in a sender-side encrypted
  queue with capped size, retried with backoff and whenever the contact shows up.
  This alone makes 2-node chat usable: it is "email when the other side is
  offline" with the sender as the post office.
- **C. Mailbox plane.** Optional, switched on automatically when enough other
  nodes exist (4.3). The sender deposits copies of the same sealed envelope,
  inside a second encryption layer, at holders chosen by a rotating
  rendezvous ID; the recipient polls for those IDs when it comes online (8).
- **D. Call plane.** A separate ALPN, contacts only, QUIC datagrams (12).

### 4.1 Process placement

Chat state, sessions, outbox, holder store and the call media pipeline live in
the **daemon**, because it owns the iroh endpoint and the state key. The
desktop GUI renders and sends commands. Audio capture/playback runs in the
daemon so PCM never crosses IPC (what this implies for how the daemon is
started is in 20).

### 4.2 New modules (names are proposals)

`crates/miasma-core/src/chat/`: `proto.rs` (frames), `crypto.rs` (ratchet,
KDFs), `store.rs` (history), `outbox.rs`, `service.rs` (ALPN handler + sender
workers, modelled on `push/service.rs`), `ipc.rs`, `group.rs`, `mailbox/`
(`ids.rs`, `fragment.rs`, `holder.rs`, `client.rs`), `call/` (`signal.rs`,
`media.rs`, `audio.rs` behind a `calls` cargo feature). Nothing in `push/`,
`store.rs`, `pipeline.rs`, `dissolution/` is modified except: three ALPN
registration points in `transport/iroh_direct.rs` (4), one contacts-store field
set (`push/store.rs`), one IPC enum variant each (`daemon/ipc.rs`).

### 4.3 Graceful degradation by node count

"Holders" are nodes other than the two conversation partners that accept
`miasma/mbx/1` deposits. The sender's own outbox is always a copy.

| Reachable nodes | Both online | One offline | Both offline at different times |
|---|---|---|---|
| **2 (today)** | Direct stream, `Ack`, state "届きました" | Message waits in the sender's outbox, auto-retried; state "送信中" | Works if the sender stays running until the recipient appears, or the sender's app is started again later (outbox is persistent). If the sender goes offline first and never overlaps with the recipient, the message waits for the overlap. |
| **3 (1 holder)** | same | 1 copy at the holder; state "送信済み" | Delivered via the holder if it is up when the recipient polls. Availability = that holder's uptime. |
| **4 to 5 (2 to 4 holders)** | same | 2 to 4 copies | Availability 1 - (1-u)^n (8.4) |
| **6+ (5+ holders)** | same | 5 copies (cap) | About 97 percent at 50 percent holder uptime |

The switch is automatic: the mailbox plane is used only when the number of
eligible holders `N >= 1` *and* the user's profile allows it (hosting and
using holders are both off in the stealth preset unless the user enables them,
14.6). Below that the code path is simply the outbox.

## 5. Identity and cryptography

### 5.1 Keys, derivations, labels

Existing (unchanged): `master.key` -> `dht_signing_key` (Ed25519 seed; this is
the iroh endpoint key and the contact ID) and `sharing key` (a separate X25519
key used by Directed Sharing, `crypto/keyderive.rs:7-11,30-37,46`).

New, all derived on demand and zeroized after use (`Zeroizing`):

| Name | Definition | Notes |
|---|---|---|
| `IK_sign` | The Ed25519 key behind the contact ID | Signs descriptors, group messages, call offers/answers |
| `IK_dh` | X25519 key with secret `clamp(SHA-512(seed)[0..32])` and public `to_montgomery(IK_sign.public)` (the standard Ed25519-to-X25519 map used by libsodium and Signal's XEdDSA) | Lets either side compute the shared root **from the contact code alone**, so a first message can be sealed while the peer is offline. Uses a key that also signs; domain-separated KDFs below, and no signature is ever made over DH output. *The exact dalek call (`VerifyingKey::to_montgomery`, scalar from seed) must be confirmed in phase 1.* |
| `pair_root(A,B)` | `HKDF-SHA256(salt = "miasma/chat/v1/pair", ikm = X25519(IK_dh_me, IK_dh_peer), info = "root" ‖ min(idA,idB) ‖ max(idA,idB))` | Symmetric, known only to the two parties. Root of all mailbox derivations and of the session bootstrap. |
| `state_key` subkeys | ADR-013 5.1: `doc_key(label)` with labels `chat-msgs`, `chat-sessions`, `chat-outbox`, `chat-groups`, `chat-prefs`, `chat-drafts`, `chat-holder` | The HKDF label registry lives next to `LABEL_NODE_ID` in `crypto/keyderive.rs` (ADR-013 5.1 rule). |

All chat labels share the prefix `miasma/chat/v1/` and are listed in
Appendix A. The existing labels use the style `miasma-v1-...` and ADR-013 uses
`miasma/state/v1/...`; chat follows ADR-013's slash style because the labels are
hierarchical. Labels are fixed byte strings; a label is never constructed from
user input.

### 5.2 Session bootstrap and ratchet (recommended: Double Ratchet, suite 2)

Per 1:1 pair there is one **session** (plus a replaced one during a reset).

**Bootstrap (X3DH without a server and without one-time prekeys).** Every
peer's `IK_dh` is derivable from its contact ID, so it acts as the responder's
signed prekey and no prekey server exists or is needed.

```
initiator A, responder B (A has B's contact code; B has A's)
EK_a = fresh X25519
SK   = HKDF(salt="miasma/chat/v1/x3dh",
            ikm = X25519(IK_dh_a, IK_dh_b) ‖ X25519(EK_a, IK_dh_b),
            info = idA ‖ idB ‖ EK_a.public)
RK   = SK;   responder initial ratchet key pair = IK_dh_b
A performs a DH-ratchet step with a fresh ratchet key R_a:
   (RK, CKs) = KDF_RK(RK, X25519(R_a, IK_dh_b))
every message from A carries { dh_pub = R_a, pn, n } and, until A has received
any message from B in this session, also EK_a (header field has_init).
```

**Ratchet (Signal's Double Ratchet, unchanged in structure).**

```
KDF_RK(rk, dh)  = HKDF(salt=rk, ikm=dh, info="miasma/chat/v1/rk") -> 64 B = (rk', ck)
KDF_CK(ck)      = ck'        = HKDF-Expand(ck, info="miasma/chat/v1/ck")      -> 32 B
                  mk ‖ nonce = HKDF-Expand(ck, info="miasma/chat/v1/msgkey") -> 32 B + 24 B
                  (Signal uses HMAC for this step; `hmac` is not a current dependency of
                   miasma-core, `hkdf` is, and HKDF-Expand is a PRF with the same security
                   role. Use HMAC instead if the crate is added for another reason.)
AEAD            = XChaCha20-Poly1305(mk, nonce, padded_plaintext, aad)
aad             = ver ‖ suite ‖ kind ‖ envelope_id ‖ header ‖ idSender ‖ idRecipient
```

- **Out-of-order tolerance.** The receiver derives and stores skipped message
  keys: at most `MAX_SKIP = 256` per chain advance and `MAX_STORED_SKIPPED =
  1024` per session (about 100 KB worst case on disk, never all in RAM);
  stored skipped keys are deleted after the mailbox TTL (30 days max). A message
  needing more skips is rejected and surfaced as a gap.
- **Nonce.** One message key is used for exactly one message and the nonce is
  derived with it, so there is no nonce-reuse path and no nonce on the wire.
- **Simultaneous initiation.** Each side may start a session. The session whose
  initial ephemeral public key `EK` is lexicographically smaller wins; the loser
  is discarded. Messages the loser sent are re-sealed under the winner if
  their plaintext is still available (save mode); in `ephemeral`/`strict` modes
  (5.8) they are marked "再送できません" and shown to the user as failed.
- **Session loss / reset.** If a receiver gets a message for an unknown session
  without `has_init`, it answers `Ack{no_session}`; the sender starts a new
  bootstrap (new `EK_a`). The identity did not change, so the UI shows a quiet
  "セッションを作り直しました" line, not a security warning. A *changed contact
  ID* is a different person and must be re-registered (ADR-012, ADR-013 5.1).
- **Forward secrecy / post-compromise security.** Forward secrecy per message
  after the chain advances and the key is deleted. Post-compromise security
  after the next DH-ratchet step (needs one reply in each direction).

**Honest limits.**

1. **First flight.** Until B replies, messages from A are protected against a
   later compromise of A's keys but not against a later compromise of B's
   `IK_dh` (which is as long-lived as B's identity). Anyone who recorded A's
   first messages and later obtains B's `master.key` can read them. After the
   first full round trip this stops applying to later messages.
2. **Saved history defeats forward secrecy on the device.** With history saved
   by default (D4), a seized unlocked device in the default ADR-013 profile
   yields the plaintext history itself (`master.key` is next to the data,
   ADR-013 5.4). Forward secrecy protects what is **not** on the device: traffic
   an adversary recorded earlier, fragments copied from holders, messages the
   user deleted or never saved.
3. **No deniability claim** for 1:1 beyond what the ratchet MACs give; **groups
   are signed** (11.4) and therefore non-deniable.
4. **Metadata** is not protected by the ratchet (5.6).

**Alternative considered, and the fallback.** *Suite 1: sealed box per
message* (ephemeral X25519 to the recipient's `IK_dh` with the pairwise static
DH mixed in for sender authentication; no state). It is stateless (no reset
problem, out-of-order trivially), about 150 lines, but any recorded ciphertext
is readable forever by whoever gets the recipient's master key. The header
carries a `suite` byte (1 or 2) so both can coexist. **Recommendation: ship
suite 2 from phase 1**; keep suite 1 only as a documented schedule-pressure
fallback, and upgrade path = new sessions use suite 2, old suite 1 messages
stay readable.

*Implementation guidance*: build the ratchet from the primitives already in the
tree (`x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`; `Cargo.toml`
lists them) following the Signal Double Ratchet specification; do **not**
invent variants; test vectors from the specification are part of phase 1's
acceptance. An external audit of this module is recommended before wide
distribution (open question 5).

### 5.3 Envelope layout (direct plane and mailbox objects)

```
Envelope (binary)
  u8   ver        = 1
  u8   suite      = 2            (1 = sealed box, fallback)
  u8   kind       = 1 pair | 2 group
  [16] envelope_id               random; transport-level dedup, not secret
  Header (suite 2)
    [32] dh_pub
    u32  pn
    u32  n
    u8   has_init                1 -> [32] ek_pub follows
  u32  ct_len                    <= 16384 + 16
  ct   AEAD output (tag included)
```

Inner plaintext (before padding), UTF-8 JSON, versioned like push frames
(`push/proto.rs:21-27`):

```
{"k":"text","id":"<16 B b64>","seq":123,"hlc":1760000000000,"conv":"<8 B b64>","body":"..."}
```

`k` is one of `text`, `retract`, `receipt`, `attach`, `ginvite`, `gdesc`,
`gkey`, `gleave`, `callmissed`, `hello` (Appendix B). Unknown `k` with the
"optional" prefix `x-` is stored as an opaque placeholder and ignored by the UI;
unknown fields are ignored (as `contacts.json`, ADR-012).

### 5.4 Padding, nonces, replay, ordering

- **Padding.** ISO/IEC 7816-4 style (`0x80` then zeros) to the next bucket of
  512 B * 2^i, i = 0..5 (512, 1 KiB, 2 KiB, 4 KiB, 8 KiB, 16 KiB). Applied
  on the direct plane too (cheap) so size does not distinguish "ok" from
  "hello". A receipt pads to 512 B, a text almost always to 512 B or 1 KiB.
  Maximum text is 4096 bytes; the maximum padded envelope is 16 KiB.
- **Nonces.** Message AEAD: derived (above). Mailbox outer layer: random 24 B
  (XChaCha). At rest: ADR-013 format (random 24 B per record). Call media: 12 B
  = 4 B per-direction salt + 8 B counter, with direction-separated keys
  (12.3). Never reuse; never derive from time.
- **Replay.** (1) ratchet message keys are one-time; (2) `envelope_id` seen-set
  with an on-disk index and a 4096-entry in-memory LRU; (3) application-level
  idempotence on `msg_id` (unique index in the history store), so a retransmit
  with a different ciphertext still applies once; (4) holders reject a repeated
  `frag_id`; (5) call packets use a 128-packet replay window.
- **Ordering.** Each sender keeps a per-conversation `seq` (persisted,
  monotonic) and a hybrid logical clock `hlc = max(wall_ms, last_hlc + 1)`,
  advanced on receive but never beyond `now + 5 min` (a sender cannot pin the
  conversation into the future). Display order is `(hlc, sender_id, seq)`. Gaps
  in `seq` from a peer are shown as nothing (they may be retractions or
  dropped messages) but trigger a `Sync` (6.4) when the peer is next
  connected.

### 5.5 Who can do what (authenticity)

- A 1:1 message is authenticated by the ratchet AEAD (only the two parties can
  produce a valid tag) and by the QUIC identity on the direct plane.
- Group messages are authenticated by an Ed25519 signature of the sender over
  `(gid, epoch, sender, seq, ciphertext)` because the sender key is shared by
  all members (11.4).
- A holder authenticates nothing about content; it checks only the capability
  signature on deposits (8.6).

### 5.6 What each adversary learns

| Adversary | Learns | Does not learn |
|---|---|---|
| Passive network observer on the path | That a host talks QUIC to an iroh relay or peer; packet sizes and timing | Content; (QUIC TLS) |
| iroh relay / n0 discovery (third party) | Which endpoint IDs connect, when, how much (as for push, ADR-012 "Non-goals"); in a relayed call, packet timing | Content |
| One mailbox holder | `rdv` (pseudonymous, changes daily), padded size bucket, deposit and fetch times, the endpoint ID and IP of whoever deposits or fetches, number of fragments per `rdv` | Content, sender/recipient identity from the fragment itself, which two people the `rdv` belongs to **unless it sees both the depositor and the fetcher** (see next row) |
| One holder that sees both the deposit and the later fetch of the same `rdv` | **That endpoint X deposited for something endpoint Y collected**, i.e. a link between X and Y, with timing | Content. This is the main metadata leak of the mailbox plane (open question 3; mitigation options in 8.9) |
| Colluding holders | More of the above, correlated across `rdv`s of the same day | Links across days (ids rotate) unless they also correlate IPs |
| The contact peer | Everything it was sent, your endpoint ID and IP (as push); read state if receipts are on | Whether you also use other contacts |
| Seized device, default profile | The history in the clear (D4; `master.key` beside the data, ADR-013 5.4) | Nothing if the master key was wiped first (crypto-erase) |
| Seized device, high-security profile (ADR-013 5.4) | Encrypted state only, until the passphrase is obtained | |
| Master key stolen + recorded traffic/fragments | Everything addressed to the identity from the first flight of each session; later messages only if no DH-ratchet round trip happened since | Messages after a completed round trip (post-compromise) |
| Malicious group member | Everything sent in the group during its membership; can forge nothing (signatures) | Pairwise chats |
| Removed group member | Messages up to the epoch change | Messages from the new epoch (new sender keys) |

### 5.7 Replay and abuse of keys

- A malicious contact can send any valid message; defences are the normal ones
  (mute, remove contact). Removing a contact (ADR-012 `remove_contact`)
  also closes its sessions, drops its outbox entries after a confirmation, and
  stops polling its `rdv`s.
- Non-contributory X25519 public keys are rejected (`was_contributory()`, as
  `directed/envelope.rs:286`).

### 5.8 At rest: ADR-013 compatibility, history modes, wipe

| Item | Class (ADR-013 appendix legend) | Notes |
|---|---|---|
| Conversation history | ENC, record log per conversation (`chat-msgs`), opaque file name | Paged reads of 50 messages; deleting a message appends a tombstone, compaction rewrites |
| Sessions (ratchet state) | ENC, document (`chat-sessions`) | Small; the hot set is cached (13) |
| Outbox | ENC, record log (`chat-outbox`) | Holds **sealed envelopes**, not plaintext (7.2) |
| Group descriptors, sender keys | ENC, document (`chat-groups`) | |
| Prefs, drafts | ENC, document | Drafts are memory-only in `ephemeral` / `strict` |
| Holder store (other people's fragments) | blobs: already ciphertext, random names; index: ENC record log (`chat-holder`) | `rdv` ids and times are metadata about third parties, so the index is encrypted too |
| Received attachments | PLAIN files, tracked in the saved-file ledger (kind `inbox`, source = contact id) | Exactly as push (ADR-013 6); "remove from history only / also delete file" |
| Notifications | not stored by Miasma | OS notification history is outside our control (14.7) |
| Search index, thumbnails, link previews | none in v1 | Avoids new plaintext artifacts |
| Call audio | never recorded, no temp files | |

**History modes** (setting, 14.6; owner decision D4):

| Mode | Message bodies | Sessions | Outbox | Default for |
|---|---|---|---|---|
| `save` | encrypted on disk, per-conversation cap 10 000, retention setting | on disk (ENC) | on disk (ENC), sealed envelopes | normal profile |
| `ephemeral` | RAM only (cap 2 MiB, wiped on exit) | on disk (ENC) so mailbox messages still decrypt | on disk (ENC), entries deleted at ack | stealth preset, portable build |
| `strict` | RAM only | RAM only | RAM only | opt-in |

`strict` costs: offline delivery through holders is off (a restart loses the
sessions and every undelivered mailbox message becomes unreadable), unsent
messages vanish when the app closes (the UI says so before sending). `ephemeral`
costs: unsent messages sit in the encrypted outbox until delivered or expired,
so a seized device can reveal them; sessions persisting means a seized device
holds current chain keys (it can read in-flight stored ciphertexts, not
delivered ones).

**Emergency wipe (ADR-013 8).** Destroying `master.key` makes `state_key`,
hence history, sessions, outbox, group keys and holder index unreadable. The
wipe then overwrites holder blobs (random-named files in a dedicated
directory registered in the persisted-paths registry, ADR-013 phase 1) and the
ledger-listed attachment files. Wipe also closes call/chat connections first.
Because the identity is derived from `master.key`, a re-initialised node is a
new person: every contact must re-add it (ADR-013 5.1). The wipe report is on
screen only (ADR-013 O14).

### 5.9 Multi-device (v1: single device per identity)

One identity = one `master.key` = one device. Copying `master.key` to a second
device would make two devices share ratchet state and corrupt it; the UI and
docs say unsupported, and a restored backup of state is detected by the
session-loss path (5.2) and recovers by re-bootstrap.

*What changes later*: a device certificate (device Ed25519 key signed by
`IK_sign`) per device; one ratchet session per (peer device, own device);
fan-out of each message to every device of the recipient and to the sender's
other devices; device list published in a signed, versioned `hello`; history
transfer between devices over a direct, QR-confirmed channel. Group sender
keys and the mailbox ids become per-device. None of this changes the wire
format of v1 except that `hello` gains a `devices` field (ignored by v1 peers).

## 6. Direct plane: protocol `miasma/chat/1`

### 6.1 Admission

On every accepted connection (looked up again for each stream, like
`push/service.rs:995-1006`):

1. `remote_id` is a contact with `allow_chat` -> **full**.
2. else `remote_id` is a member of a group I have joined (descriptor verified)
   -> **group-limited**: only frame types `GroupMsg`, `GroupKey`, `GroupDesc`,
   `GroupSync`; anything else closes the connection with 403.
3. else close with application error 403 (`CLOSE_NOT_ALLOWED`) right after the
   handshake, debug-level log only, per-id token bucket (`Limiter` shape,
   `push/service.rs:121-163`).

A dialer learns only "rejected: not_allowed" (as in ADR-012). A removed contact
or an `allow_chat = false` switch takes effect at the next stream.

### 6.2 Framing

One request = one bidirectional stream: `u32 len (big endian) | u8 type |
payload`, `len <= MAX_CHAT_FRAME = 16 KiB + 512`, the declared length is checked
before any buffer is sized (the rule at `transport/iroh_direct.rs:591`). JSON
for control frames, the binary envelope (5.3) for `Deliver`. Limits per
connection: 4 concurrent streams, 64 streams total, 60 s idle timeout, 30 s
read timeout per frame. Concurrent chat connections: 8 (least recently used
closed), because a QUIC connection costs memory (13).

| Type | Direction | Payload | Reply |
|---|---|---|---|
| `0x01 Hello` | both, first stream | `{v, caps[], max_frame, now_ms}` | `Hello` |
| `0x02 Deliver` | sender to receiver | Envelope | `Ack` |
| `0x03 Ack` | reply | `{id, status}`; status in `stored`, `dup`, `no_session`, `not_allowed`, `too_big`, `rate`, `busy`, `bad_request`, `unsupported` | |
| `0x04 Sync` | either | `{conv, have:[(sender, max_seq, missing_ranges)]}` (<= 20 senders, 4 KiB) | `SyncReply` |
| `0x05 SyncReply` | reply | the list of envelopes the peer is able to resend, capped (6.4) | |
| `0x11..0x14` | group frames | 11 | |
| `0x80..0xFF` | optional extension types | ignored with `Ack{unsupported}` | |

`Ack{stored}` is sent only **after the record is durably committed** (fsync of
the group-committed batch, at most 20 ms later). Receiver limits: 30 messages
per minute per contact (burst 20), 300 per minute total, 8 pending
unacknowledged frames.

### 6.3 Versioning

ALPN major version `/1` is the compatibility boundary. Inside, `Hello.v` is the
minor version and `caps` lists optional features (`rcpt`, `grp`, `mbx`,
`call`). Rules: unknown JSON fields ignored; unknown types >= 0x80 ignored;
unknown types < 0x80 close with 400. A breaking change = new ALPN `/2`
served side by side for at least two releases (the accept loop dispatches on
ALPN, `transport/iroh_direct.rs:529`). See 17.

### 6.4 Sync (digest exchange)

On connect, if either side has unacknowledged state for the other, it sends
`Sync` with its per-sender highest contiguous `seq` and missing ranges. The peer
answers with envelopes it still can resend (from its **outbox**; in `save`
mode also from history re-sealed under the current session), at most 200
messages / 256 KiB per reply, oldest first, and the requester continues with
another `Sync` until empty. This covers lost `Ack`s and mailbox gaps without a
global log.

## 7. Message lifecycle

### 7.1 States (sender view; Japanese labels in 14)

| State | Meaning | Becomes |
|---|---|---|
| 送信中 (`pending`) | In the outbox; no peer, no holder has it | 届きました (direct `Ack`), 送信済み (deposit), 失敗 (expiry/rejection) |
| 送信済み (`deposited`) | At least one holder accepted a copy; the recipient's device has not fetched it | 届きました |
| 届きました (`delivered`) | The recipient's device durably stored it (`Ack{stored}`, or a delivery receipt, 9.1) | 既読 |
| 既読 (`read`) | A read receipt arrived (only if both sides allow it, 9.2) | |
| 失敗 (`failed`) | TTL (default 30 days outbox, 14 days mailbox) ended or a permanent rejection | manual "もう一度送る" |

### 7.2 Outbox

- **Entry**: `{out_id, conv, msg_id, sealed envelope (<= 16 KiB), created_ms,
  attempts, next_at, deposited_to[ <= 5 holder ids ]}`. The outbox stores the
  **sealed envelope**, not the plaintext: the ratchet message key is consumed
  once, at send time, and the same ciphertext is used for the direct attempt and
  for every mailbox copy. (Cost: after a session reset the message cannot be
  re-sealed unless the plaintext is still in the history store; see 5.2.)
- **Caps**: 500 entries and 4 MiB total, 100 entries per contact. At the cap the
  compose box is disabled with "送信待ちがいっぱいです" rather than dropping
  anything. Bodies are on disk; only a small header (about 100 B) per entry is
  in memory.
- **Retry**: immediate, then 5 s, 30 s, 2 min, 10 min, then every 15 min while
  the daemon runs, with +/-20 percent jitter. Also on: daemon start, network
  change, **an inbound connection from that contact** (they just came online:
  the same connection is used to flush, in both directions), manual "もう一度送る".
- **Expiry**: 30 days (configurable down to 1 day).
- **Group commit**: outbox and history writes are batched (<= 20 ms) so a burst
  is one fsync.

### 7.3 The 2-node walk-through (today)

1. A types "hello". The daemon seals it (ratchet), appends it to its history
   (save mode) and to the outbox: **送信中**.
2. The sender worker dials B's endpoint ID on `miasma/chat/1` (iroh finds the
   address through n0 discovery, LAN mDNS or relay).
3. B online: B's handler checks `allow_chat`, decrypts, commits, `Ack{stored}`:
   A shows **届きました**. B's UI shows the message and an unread badge.
4. B offline: dial fails (`describe_dial_error`-style message, as
   `push/service.rs:1076`), the entry stays **送信中**, backoff runs. A sees
   "相手がオフラインです。メッセージは相手がオンラインになったら届きます".
5. B starts later, dials its own contacts to flush its outbox; A (still
   running) accepts, receives, and flushes A's outbox over the same connection.
   If A is not running, A's next start does the same.

### 7.4 The many-node walk-through (>= 3 reachable nodes)

1. Steps 1 and 2 as above; the dial to B fails (or no response in 8 s).
2. The sender computes today's `rdv` for A->B (8.2), picks `n = min(holders,5)`
   holders by XOR distance of their endpoint IDs to `rdv` (8.3), builds the
   padded, outer-encrypted object, and deposits one copy at each holder
   (`miasma/mbx/1`). State **送信済み** after the first accepted deposit.
   The entry stays in the outbox (the direct attempt continues to be retried,
   because a direct delivery is better and gives the real **届きました**).
3. B comes online, polls the `rdv`s it has not yet drained (8.5), decrypts,
   commits, and tells A via the direct path or, if A is offline, via a
   *delivery receipt* object in B->A's mailbox (9.1). B also deletes the
   fragments at the holders (8.7).
4. A comes online later, collects the receipt, shows **届きました**.

## 8. Mailbox plane (offline delivery by fragments held by other nodes)

### 8.1 Idea in one paragraph

A message is a tiny object. It is sealed end to end (5), padded to a bucket
(512 B to 16 KiB), wrapped once more with a key only the two partners know, and
stored as **fragments** at several nodes under a **rendezvous ID** (`rdv`) that
only the two partners can compute and that changes every day. Holders cannot
read it, cannot tell who it is for, and forget it after a TTL. The recipient,
when online, recomputes the `rdv`s of its contacts, asks the holders that
`rdv` points to, collects whatever is there, decrypts and deletes it. No
registry, no directory, no server.

### 8.2 Identifiers (derived from the pair, unlinkable to people)

```
epoch   = floor(unix_seconds / 86400)                 (UTC day, u32)
rdv     = HKDF(pair_root, info = "miasma/chat/v1/mbx/rdv" ‖ idSender ‖ idRecipient ‖ epoch_be)   32 B
cap_sk  = Ed25519 seed = HKDF(pair_root, info = "miasma/chat/v1/mbx/cap" ‖ idSender ‖ idRecipient ‖ epoch_be)
obj_key = HKDF(pair_root, info = "miasma/chat/v1/mbx/obj" ‖ rdv)                                  32 B
```

- The `rdv` is direction-specific (A->B differs from B->A), so a holder cannot
  match "the reply" to "the message".
- Without `pair_root` (which needs one party's secret key) the `rdv` is not
  computable or guessable. A holder sees an opaque 32-byte string that changes
  daily.
- `obj_key` encrypts the **whole envelope including the ratchet header** with
  XChaCha20-Poly1305 and a random 24 B nonce, so a holder cannot see ratchet
  public keys or counters (which would otherwise fingerprint a session). This
  layer is the header encryption that the ratchet itself omits.
- `cap_sk` signs deposits and deletes (8.6, 8.7). Both parties can compute it;
  that is acceptable because the `rdv` is directional and anything either party
  deposits is authenticated again by the ratchet.
- Group inboxes use the same construction from the group's root key (11.6).

### 8.3 Who holds fragments, and how a recipient finds them without a registry

- **Candidates**: nodes in the daemon's libp2p routing table. Their peer ID's
  public key is the same Ed25519 key as their iroh endpoint ID
  (`network/node.rs:2116-2130`), so each candidate is directly dialable on
  `miasma/mbx/1`. A node that does not speak the ALPN refuses at negotiation;
  refusals go into a one-hour negative cache. Contacts that are not partners in
  the conversation are also candidates. (Phase 4 adds a read-only
  `DhtCommand::ListPeers`; no existing command lists the table, `network/node.rs:742`.)
- **Ranking** (Kademlia-like closeness, but computed locally and tolerant of
  different views): `rank(c) = BLAKE3("miasma/chat/v1/mbx/holder" ‖ rdv) XOR
  BLAKE3(c.endpoint_id)` compared as a 256-bit number; smaller is closer.
- **Deposit**: walk the ranked list, ask each candidate in turn, stop after
  `n` acceptances or `3n` attempts. A holder that is offline, full, or
  rejects is skipped.
- **Fetch**: walk the same ranking from the top, asking each candidate for the
  `rdv`; stop after `n` candidates have *answered* (empty or not) or `3n`
  attempts. Walking deeper than the depositor placed copies is what absorbs
  differences between the two nodes' views and holders that were offline at
  deposit time.
- This is **probabilistic delivery**. A copy can land where the recipient does
  not look. That is why the sender's outbox stays the backstop and why `Sync`
  (6.4) exists. With few nodes (N <= 10) both sides simply ask everyone, and the
  ranking is irrelevant.
- No node ever learns a list of "all fragments for a person": holders are
  different per `rdv`, and `rdv`s are different per day.

### 8.4 Why the default is copies, not erasure coding (the availability math)

Personal PCs are not servers. For holder uptime `u`, the probability that at
least `k` of `n` holders are online when the recipient polls is `P(X >= k)`,
`X ~ Binomial(n, u)` (exact values, computed by hand):

| (k, n) | Stored bytes per message (x bucket) | u = 0.5 | u = 0.8 |
|---|---|---|---|
| (1, 3) copies | 3.0 | 0.875 | 0.992 |
| (1, 5) copies | 5.0 | 0.969 | 0.9997 |
| (2, 3) | 1.5 | 0.500 | 0.896 |
| (2, 4) | 2.0 | 0.688 | 0.973 |
| (3, 5) | 1.67 | 0.500 | 0.942 |
| (4, 8) | 2.0 | 0.637 | 0.990 |

Erasure coding saves storage and loses availability when holders are flaky;
and for objects <= 16 KiB the storage saved is a few KiB per message while the
fixed per-fragment overhead (about 170 B) does not shrink. The extra
confidentiality of splitting (no single holder has the whole ciphertext) is
marginal because the ciphertext is already end-to-end encrypted with forward
secrecy.

**Decision**: v1 mailbox objects use `k = 1`, `n = min(N_holders, 5)` (plain
copies). The fragment header carries `k`, `n`, `idx`, so `crypto/rs.rs`
(`rs_encode` / `rs_decode`) can be used unchanged for larger objects or
when measured holder uptime is high (> 0.9), without a format change. The owner
asked for "like how files are stored"; this is the same *principle* (opaque
pieces at many nodes, found by derived addresses, no server) with the right
parameters for tiny objects. Open question 4 asks whether to still use k > 1.

### 8.5 Protocol `miasma/mbx/1`

Same framing rules as 6.2 (length-prefixed, declared length checked first).
Requests (one stream each):

| Request | Payload | Reply |
|---|---|---|
| `Hello` | `{v, accepting, pow_bits}`; **no** free-space number (avoid fingerprinting) | same |
| `Deposit` | `{rdv[32], frag_id[16], k, n, idx, ttl_secs, cap_pk[32] (first deposit for this rdv only), pow_nonce u64, sig[64], data}`; `data <= 16 KiB + 64` | `Stored`, or `Rejected{quota, principal_budget, rdv_full, bad_pow, bad_sig, cap_mismatch, too_big, rate, not_accepting}` |
| `Fetch` | `{rdv[] (<= 16)}` | `{items:[{rdv, frag_id, k, n, idx, ttl_left, data}], more}`, reply <= 256 KiB; a second `Fetch` with `after = last frag_id` continues |
| `Delete` | `{rdv, frag_ids[] (<= 32), sig}` | `Deleted{n}` |

- `sig = Ed25519(cap_sk)` over `BLAKE3("miasma/chat/v1/mbx/deposit" ‖ rdv ‖
  frag_id ‖ k ‖ n ‖ idx ‖ ttl ‖ BLAKE3(data) ‖ pow_nonce)`; delete signs
  `("miasma/chat/v1/mbx/delete" ‖ rdv ‖ frag_ids)`.
- The holder binds `cap_pk` to `rdv` at the first deposit and requires the same
  key afterwards (`cap_mismatch` otherwise).
- `data` is: `u8 ver | u24 object_len | nonce[24] | ciphertext | tag[16]` for
  `k = 1`; for `k > 1` it is the RS shard plus `shard_hash` (32 B, as
  `share.rs:52` for a coarse integrity check before reconstruction).
- Per-fragment overhead on the wire: about 170 B (rdv 32, frag_id 16, k/n/idx
  3, ttl 4, cap_pk 32 on first, nonce 8, sig 64, framing ~12).

### 8.6 Holder policy (quotas, TTL, anti-spam) and the honest limits

Holder behaviour (modelled on the hosted-share policy, `store.rs:43-58,
630-660,745-753`, but a separate store with expiry):

| Limit | Default | Notes |
|---|---|---|
| Total mailbox store | 16 MiB (`mailbox.host_quota_mb`) | **0 in the stealth preset and the portable build** (ADR-013 O12 pattern); phase 4 ships **off by default** until legal review (18) |
| Per depositing principal (endpoint ID) | 1 MiB, never more than 25 percent of the total | Contacts of the holder get 4x |
| Per `rdv` | 64 fragments and 256 KiB | A hostile contact can only fill its own direction |
| Entries | 16 384, `rdv`s 4 096 | Bounds the index in RAM (13) |
| TTL | requested `ttl` clamped to [1 h, 14 days]; hard maximum 30 days, by the holder's own clock from receipt | A fragment past TTL is dropped by a sweep at start and every 10 min |
| Full store | **reject** new deposits; never evict unexpired fragments | Same rule as `put_hosted_by` |
| Rate | 10 deposits/min and 60 fetch requests/min per principal (token bucket, bounded map, shape of `push/service.rs:121-163`) | |
| Proof of work | `pow_bits = 20` per deposit (about 10^6 BLAKE3 hashes, about 0.1 s on a desktop, under 1 s on a phone); 24 under load; contacts of the holder skip it | The libp2p admission PoW is 8 bits (`network/sybil.rs:49`, `DEFAULT_POW_DIFFICULTY`), too weak to rely on here |

**Abuse limits, stated plainly.**

1. **Holders cannot verify membership.** They never learn pair secrets, so they
   cannot know whether a deposit is "from a registered contact". The capability
   signature only proves that a depositor knows `cap_sk` for that `rdv`.
2. **Third parties cannot target your mailbox.** They would need the `rdv`,
   which they can only learn by being a holder. A hostile *holder* can squat
   (bind its own `cap_pk` to your `rdv` at other holders by depositing there
   first): the effect is a denial of service for that `rdv` at that holder for
   that day; the sender sees `cap_mismatch`, uses the next holder, and the `rdv`
   changes tomorrow.
3. **Storage exhaustion by many identities is not preventable without an
   operator.** Keys cost nothing, so an attacker with M endpoint IDs can use
   M x 1 MiB of a holder's quota with junk under random `rdv`s. PoW and rate
   limits make it expensive and slow, not impossible. Consequence: mailbox
   hosting degrades (availability), confidentiality is unaffected, and the
   sender's outbox still delivers when both are online. A holder prefers its own
   contacts (4x budget, no PoW), which is the incentive for people to add
   each other.
4. **A hostile contact** can flood your inbox on the direct plane (30 msg/min
   limit, 6.2) and on the mailbox plane (64 fragments per `rdv` per holder); the
   remedy is to mute or remove the contact.
5. **Unregistered senders** have no `rdv` at all: you only poll `rdv`s of your
   contacts (and of your groups), so there is nothing for a stranger to send to.

### 8.7 Polling, receiving, deleting

- **When**: at daemon start; every 10 min while running (adaptive: 2 min for
  15 min after something arrived; 15 min when the GUI is not in front); on
  network change; never when `mailbox.use` is off.
- **Which `rdv`s**: for each contact, every epoch from
  `last_drained_epoch[contact]` to today (plus tomorrow when UTC time is within
  1 h of the rollover, for clock skew), at most `TTL_days + 1 = 15` per contact.
  Typical: 1 to 2 ids per contact. 20 contacts: about 20 to 40 ids.
- **Per holder**: ids are batched 16 per request; connections are reused
  (60 s idle); one holder at a time per `rdv` walk, at most 4 holders in
  parallel; the response buffer is at most 256 KiB (13).
- **Receive**: outer-decrypt with `obj_key`, parse the envelope, ratchet-decrypt,
  commit (idempotent on `msg_id`), then `Delete` the fragments at the holders
  with the cap signature and emit a delivered receipt (9.1).
- **Cost (estimate, not measured)**: 40 ids x 32 B x up to 5 holders = about 6 KB
  upstream per cycle; 144 cycles/day = about 0.9 MB/day upstream plus small
  replies. The CPU and radio cost of waking up up to a dozen connections every 10
  minutes is the real price on a laptop on battery; hence the adaptive cadence and a
  "battery saver" setting (poll only on start and when the app is opened).

### 8.8 Holder storage format

Not one file per fragment (a 1 KiB fragment would cost a 4 KiB cluster, and
file names would enumerate `rdv`s). A log-structured store of 1 MiB segment
files with random names under a dedicated directory:
`[len u32 | rdv | frag_id | expiry | data]` records, an in-RAM index
`rdv -> [(segment, offset, len, expiry)]` (<= 16 384 entries, about 1 MiB), a
sweep that rewrites a segment when more than half of it has expired, and a
rebuild of the index by scanning segments at start (streamed, one record in
memory at a time). The index is persisted only as part of the segment scan, so
the encrypted `chat-holder` record log of 5.8 is the *list of segment files* and
their sealing, and the blob content is already ciphertext.

### 8.9 Metadata leaks of the mailbox plane and options

The leak in 5.6 (a holder seeing both the depositor and the fetcher) cannot be
removed by encryption. Options, in the order I would take them:

1. **v1 (phase 4)**: accept and document. Mitigations that cost nothing:
   daily `rdv` rotation; padded buckets; jittered polls; deposits only when the
   direct attempt has failed (so most traffic never touches a holder); holders
   that are contacts of the sender are preferred, because the sender already
   trusts them.
2. **Phase 7**: *decoy ids* in fetch requests (3 random 32-byte ids per real
   one: costs 96 B and hides which ids are real from a curious holder, not from a
   colluding one).
3. **Research, not committed**: (a) a per-epoch ephemeral iroh identity used
   only for mailbox operations, so the holder cannot link the operation to the
   contact ID (costs a second endpoint's memory; unverified whether iroh makes
   a second endpoint cheap); (b) one relay hop by reusing the onion
   machinery (`onion/mod.rs:1-25`, 2-hop packets; today in-process for
   most paths and real-network for retrieval only); (c) relay-only paths so the
   holder never sees the IP. Each hides identity from holders but adds latency
   and relay cost.

### 8.10 Reuse summary

| Piece | Reused? |
|---|---|
| `crypto/rs.rs` RS codec | Yes, unchanged, only if k > 1 |
| Hosted-store policy: separate quota, per-principal budget, reject-not-evict | Policy yes; code no (new store with expiry) |
| `push` contact gate, limiter shape, close codes, framing rules | Yes (copied pattern) |
| Kademlia routing table as a source of candidate holders | Yes (read-only listing) |
| `pipeline::dissolve`, `MiasmaShare`, Shamir, `DhtRecord`, replication queue, libp2p `StoreRequest` | **No** |
| `share_id`-style typed strings | No (no new string is shown to users) |

## 9. Receipts and retraction

### 9.1 Delivery receipts

On the direct plane, delivery is the transport `Ack{stored}` (6.2). On the
mailbox plane the recipient sends `receipt{kind:"delivered", up_to_seq}`
(cumulative per sender and conversation) as an ordinary small message, through
the direct plane if the sender is reachable, else into the B->A mailbox. They
are always on: the outbox cannot know when to stop retrying otherwise. They
are coalesced: at most one per conversation per 2 s.

### 9.2 Read receipts (owner: default ON for 1:1)

- `receipt{kind:"read", up_to_seq}`, sent when the conversation is open **and
  the window is in front and the messages were in view**, not on arrival.
- Per-contact setting `read_receipts` (default **on** in the normal profile, **off**
  in the stealth preset and the portable build). Global switch in Settings.
- **Reciprocal** (recommended): if I do not send read receipts I also do not see
  yours, so the setting is not a one-way lookout. (Open question 6.)
- No wall-clock time in a receipt; the sender displays its own arrival time. At
  most one read receipt per conversation per 5 s.
- Groups: **no read receipts in v1**; a group message shows 送信済み and
  "N人に届きました" from delivery acks only (11.7).
- Receipts are never acknowledged by receipts, never shown as messages, and
  never create a conversation.

### 9.3 Retraction ("削除を依頼する")

- `retract{target: msg_id}` is accepted only if the author of the target is the
  sender of the retract (the ratchet/signature authentication already proves who
  sent it). The recipient replaces the body with a tombstone
  ("このメッセージは削除されました") and drops the plaintext from the store.
- For a message not yet fetched, the sender also issues cap-signed `Delete`s at
  the holders that accepted it (best effort).
- It is a **request**: a modified client can ignore it; copies in screenshots,
  backups and notification history stay (14.7). The UI says 依頼しました, never
  "削除しました" (the wording rule of ADR-013 7.3). Attachment files are the
  recipient's files; a retract does not delete them (ledger offers "also delete
  the file" to the recipient, ADR-013 6).
- **Local delete** (my copy only) is immediate and in phase 2. **Delete
  conversation** destroys that conversation's data key (each conversation log
  has its own random data key, wrapped by `state_key`), which is a per-conversation
  crypto-erase, then unlinks the file.
- Network-wide retraction as in ADR-013 O11 is the last, lowest-priority phase;
  chat retraction goes in phase 7 together with it.

## 10. Attachments

Chat does not carry files. It reuses trusted-contact push (ADR-012; module
`crates/miasma-core/src/push/`, merged as PR #42) end to end:

1. The user picks a file in the conversation. The daemon calls the existing
   `PushService::queue_send(contact, path)` (`push/service.rs:328`); all of
   ADR-012's limits apply (per-contact `allow_send`, `max_file_size`, 20 GiB
   default, resume, BLAKE3 verification, sanitized names, no overwrite).
2. Chat sends an `attach` message `{name, size, blake3, push_id}` (a pointer, a
   few hundred bytes) so the file appears in the conversation in order, with the
   push state (送信中 / 届きました) shown on it.
3. The receiver's file lands in `<inbox>/<contact label>/` and is recorded in
   the saved-file ledger (ADR-013 6, kind `inbox`, source = contact id) by the
   hooks ADR-013 phase 4 adds to the push receive path. Chat adds no second
   location and writes no file of its own.
4. The conversation's message menu offers "履歴から消す" and "ファイルも消す"
   (ADR-013 6 "Normal delete of a history entry").
5. No previews, no thumbnails, no inline rendering in v1 (no new decoder
   attack surface, no thumbnail cache artifact). "開く" hands the file to the OS.

**Offline attachments** are out of scope: push requires both sides online
(ADR-012 non-goal) and the sender sees "相手がオンラインのときに送れます".
*Where erasure coding does fit* (later): large attachments through the existing
file path (`dissolve` + shares + a share ID), with the share ID and key sent as
a chat message; contacts are already authenticated, so the password and
confirmation code of Directed Sharing are not needed. That is a separate ADR.

## 11. Groups

### 11.1 Model

A group is a **signed member list with an epoch**, plus per-member **sender
keys**. There is no group server and no group-wide shared secret that outlives a
membership change.

```
GroupDescriptor (fixed binary encoding; signed; delivered only through pairwise E2E channels)
  v = 1, gid[16] random, epoch u32, name (<= 64 chars), created_ms,
  prev_hash[32]                        BLAKE3 of the previous accepted descriptor (zero for epoch 1)
  group_secret[32]                     fresh at every epoch; root of the group inboxes (11.5)
  members[<= 20] = { id[32], role (admin|member), hint_label (<= 32 chars, UNTRUSTED) }
  signer[32] (an admin of the previous descriptor), sig[64] = Ed25519 over
      BLAKE3("miasma/chat/v1/grp/desc" ‖ all fields above)
```

About 1.5 KB for 20 members. `hint_label` is a suggestion from whoever added
the member; it is always displayed together with the fingerprint and the word
"名乗り" (self-declared), never as a verified name.

### 11.2 Roles, validity, forks

- The creator is the first admin. **Admins** add, remove, rename, promote and
  demote. **Members** may leave. There is always at least one admin; the last
  admin must name a successor before leaving or dissolve the group.
- A descriptor is accepted iff `epoch = previous.epoch + 1`, `prev_hash` matches,
  and the signer is an admin in the **previous** accepted descriptor. A peer behind
  by several epochs fetches them in order (`GroupDesc` frame).
- **Concurrent changes** by two admins produce two descriptors with the same
  epoch: the one with the smaller hash wins; the loser's author notices at the
  next sync and re-applies its change on top. (Rare; documented, tested.)
- Maximum 20 members in v1 (`group.max_members`, hard limit 20). Reason: rekey
  is O(n^2) pairwise messages and fan-out is O(n) (11.5).

### 11.3 Join flow and the "press add" rule (owner decision D3)

1. An admin picks people **from their own contacts** and creates or updates the
   group. For each new member the admin's daemon sends `ginvite{descriptor}`
   through the pairwise 1:1 channel (the invitee must have the admin as a
   contact, because that is the only channel the invitation can travel; this also
   means nobody can be pulled into a group by a stranger).
2. The invitee sees **a confirmation screen** (14.4): group name, who invited
   them, and **the full member list, each member with 連絡先コード, 確認用コード
   and a status "登録済み" (already my contact) or "未登録"**. Buttons:
   「参加する」「断る」. Joining adds nothing to the contact list.
3. After joining, each "未登録" member has a button **「連絡先に追加」** that opens
   the normal add-contact flow pre-filled with that member's code. The user adds
   (and should compare the 確認用コード with the person through another channel,
   ADR-012). **Nobody is added automatically, by anyone, ever.** Default-deny
   for everything outside the group is unchanged.
4. Leaving: 「グループを退出」 sends a signed `gleave`, deletes the group's keys
   and (asking) its history.

**What an unregistered ("未登録") member can and cannot do** (exact rule,
enforced in the chat handler, 6.1):

| Allowed (inside this group only) | Not allowed |
|---|---|
| Send **text** messages, <= 2 KiB, <= 6 per minute | 1:1 chat with me |
| Be shown in the member list and in message headers with a "未登録" badge and the fingerprint | Attachments, push, calls, ringing |
| Connect on `miasma/chat/1` **only** for the group frame types | Appear in my contact list, send me files, have a mailbox `rdv` with me |
| Receive my group messages (I am a member) | Any frame other than the four group types: the connection is closed (403) |

Joining a group is therefore consent to receive *text from its members inside
that group*; it is not trust. Removing the group removes the allowance.
(Stricter alternative: hold messages from unregistered members hidden until
added; open question 7.)

### 11.4 Keys: sender keys, signed messages

- Each member `M` keeps, per group, a **sender chain** `CK_M` (32 random bytes)
  that ratchets forward per message with the same `KDF_CK` as 5.2
  (`mk ‖ nonce`), index `i`. Message AEAD uses `mk`, AAD =
  `gid ‖ epoch ‖ sender ‖ i`, and carries an Ed25519 signature by the sender over
  `AAD ‖ ciphertext` (the symmetric key is shared by all members, so the signature
  is what prevents one member from forging another's message). Cost: 64 B and
  one verify per message. Consequence: group messages are not deniable.
- `CK_M` is sent to every other member as `gkey{gid, epoch, ck, i}` inside the
  **pairwise** E2E channel. Members who are not contacts of each other still have
  a pairwise channel: `IK_dh` derives from the endpoint IDs in the descriptor, so
  `pair_root` and a session can be bootstrapped; that session is flagged
  *group-limited* and may carry only the group frame types until the user adds
  the other person as a contact.
- **Add**: epoch + 1, new `group_secret`, no re-key of existing chains. Each
  existing member sends its **current** chain state to the newcomer (so the
  newcomer cannot read earlier messages) and the newcomer sends its chain to
  everyone: 2(n-1) small messages. **History for late joiners: none** (v1).
- **Remove or leave**: epoch + 1, new `group_secret`, **every remaining member
  generates a new `CK` and sends it to all remaining members**: with r remaining
  members that is r(r-1) messages: 342 when 19 remain after a removal from a
  group of 20 (380 for a full re-key of 20), about 175 KB in total (each `gkey`
  pads to 512 B). The removed member
  keeps old keys (can read what it already could), and nothing from the new epoch.
- **Rotation** (phase 7): a member re-keys its own chain every 1000 messages
  or 7 days (n-1 messages), to bound the damage of a device compromise.
- Message size and padding as 5.4; envelope `kind = 2`.

### 11.5 Fan-out: pairwise delivery with per-member group inboxes (decision)

| Option | Cost per group message (n = 20) | Privacy | Verdict |
|---|---|---|---|
| **A. Encrypt once; deliver the same ciphertext to each member over its pairwise channel, direct if online, else into that member's group inbox mailbox** | online: up to 19 parallel direct streams; offline: m offline members x 3 to 5 copies, e.g. 10 offline = 30 to 50 deposits of about 1.2 KB | Holders see one `rdv` per member per day; no `rdv` is shared by two members, so a holder cannot see "these N endpoints poll the same id"; depositor-to-fetcher link as in 5.6 | **Chosen** |
| B. One shared group mailbox `rdv` that every member polls | 3 to 5 deposits | Every member polls the same id: a holder links all members of the group | Rejected for privacy |
| C. Group message as a push of files | | | Not applicable |

Group inbox ids: `rdv_g(M, day) = HKDF(group_secret, "miasma/chat/v1/grp/inbox" ‖
M ‖ epoch_day)`, capability key from `group_secret` the same way (any current
member may deposit; a removed member cannot after the epoch change). A member
polls **its own** inbox only: one `rdv` per group per day (plus its 1:1 `rdv`s),
independent of group size.

Bounds: group sends are limited to 20 per minute per member; the outbox keeps
**one** sealed envelope per message with a small per-recipient delivery mark
(the 500-entry cap counts messages, not recipients), so a 20-member group does
not multiply the 4 MiB outbox cap.
If many members are unreachable and no holders exist (the 2-node world has no
groups anyway), the state shows "N人に届きました".

### 11.6 Convergence on reconnect

Peers exchange `GroupSync{gid, epoch, per_sender:[(sender, max_i_contiguous,
last_64_bitmap)]}` (about 1 KB at n = 20) when a pairwise connection opens or a
poll finds a gap. The peer returns the messages it still has (history in `save`
mode, outbox otherwise) that the requester lacks and that are not older than the
requester's join epoch, at most 200 messages / 256 KiB per reply, oldest first.
Descriptors converge by epoch (highest valid epoch wins; a peer that sees a
higher epoch in `Hello`/`GroupSync` pulls the chain). Messages are applied
idempotently on `(gid, sender, i)`.

### 11.7 Receipts and state in groups

Delivery acks only: the sender's message shows 送信済み, then "N人に届きました"
(count of members with a delivered mark). No read receipts in v1. Message
retraction works as in 9.3, authored by the original sender.

## 12. Voice calls

### 12.1 Scope

1:1 audio only. Out of scope in v1: video, group calls, screen share, call
recording, voice messages, PSTN. (How they could come: 12.8.)

### 12.2 Transport and signalling

- **Media** travels as **QUIC datagrams** (unreliable, unordered, congestion
  controlled) on a connection with its own ALPN **`miasma/call/1`**, dialled
  with the existing `connect_alpn` (`transport/iroh_direct.rs:350`) and accepted
  by a new dispatch branch (`:529`). A separate ALPN gives a separate admission
  policy (contacts with `allow_call` only), separate buffer bounds, and a hang-up
  that closes one connection without disturbing chat.
  *Not verified*: `git grep -i datagram` finds no datagram use in the repository,
  so iroh's `send_datagram` / `max_datagram_size` behaviour (enabled by
  default? effective size on relay paths?) must be confirmed in the phase 6
  spike; and whether the second connection reuses the hole-punched path of the
  first (it should, iroh keeps paths per endpoint pair, but this was not read).
- **Signalling** is carried as chat control frames on the direct plane
  (`miasma/chat/1`, types 0x20 to 0x25): `Offer`, `Ringing`, `Answer`, `Decline`,
  `Cancel`, `Hangup`. It is **never** carried by the mailbox: a ring that arrives
  hours later is useless. If the callee cannot be reached, the caller sees
  "相手がオフラインです" and a `callmissed` message (normal path, 24 h TTL) is queued
  so the callee later sees 「不在着信」.
- No ICE/STUN/TURN: iroh already does hole punching and relay fallback; the
  signalling needs no addresses.

```
caller                                           callee
  |-- Offer{call_id, eph_pk, nonce, codec, sig} -->|  (chat plane, E2E, signed)
  |<-- Ringing ------------------------------------|  callee UI rings, 30 s timer
  |<-- Answer{call_id, eph_pk, nonce, sig} --------|  (or Decline{busy|declined|dnd})
  |== dial miasma/call/1, first datagram carries call_id (AEAD) ==>|
  |<=============== Opus datagrams both ways ===============>|
  |-- Hangup --> / <-- Hangup --                     either side
```

### 12.3 Media keys (E2E)

```
transcript = BLAKE3("miasma/chat/v1/call/transcript" ‖ call_id ‖ Offer ‖ Answer)
dh         = X25519(eph_a, eph_b)                               fresh per call
exporter   = HKDF(session.root_key_snapshot, info = "miasma/chat/v1/call/export" ‖ call_id)
             (read, without advancing the ratchet; binds the call to the pair's ratchet state)
media_secret = HKDF(salt = transcript, ikm = dh ‖ exporter, info = "miasma/chat/v1/call/media")
k_a2b ‖ salt_a2b = HKDF(media_secret, "miasma/chat/v1/call/a2b") (32 + 4 B)
k_b2a ‖ salt_b2a = HKDF(media_secret, "miasma/chat/v1/call/b2a")
```

`Offer` and `Answer` are signed with `IK_sign` over the transcript fields, so
the ephemeral keys are bound to the two identities (no unauthenticated DH).
Forward secrecy comes from `eph_*`; the exporter ties the key to the pairwise
state so a man in the middle without the pair's session cannot complete the call.
If no session exists yet the exporter is omitted and the signatures alone
authenticate (documented). Keys are zeroized at hang-up.

### 12.4 Media format and processing

- **Codec**: Opus, 48 kHz mono, 20 ms frames, `application = voip`, **constant
  bitrate 24 kbps** (16 kbps on a relayed path), in-band FEC on, **DTX off**.
  *Why CBR and no DTX*: with variable bitrate the packet sizes of an
  encrypted stream leak speech content (published length-based attacks on VBR
  VoIP); constant sizes and a constant packet cadence remove that channel at a
  fixed bandwidth cost.
- **Packet**: `u8 type/flags | u48 seq | ciphertext (Opus frame, 60 B at 24 kbps)
  | tag 16 B` = about 83 B, plus QUIC and UDP overhead of about 45 B, 50 packets per
  second: about 6.4 KB/s (about 51 kbps) each way.
- **AEAD**: ChaCha20-Poly1305, nonce = `salt(4 B) ‖ seq(8 B)`, key per direction,
  AAD = header. Re-key before `seq` reaches 2^40 (never in practice; asserted
  in tests). Replay window: 128 packets.
- **Jitter buffer**: adaptive, target = 2 x measured jitter + one frame, clamped
  to [40 ms, 200 ms]; hard cap 10 frames; late packets dropped; Opus packet-loss
  concealment on gaps; clock drift handled by a +/-0.5 percent resampler.
- **Echo cancellation**: v1 ships **no software echo canceller**. A verified
  pure-Rust canceller is not known to me, and the C++ options (WebRTC audio
  processing) add a toolchain and installer burden that conflicts with
  ADR-013's "works on a fresh general PC with no extra install" constraint (not
  verified either way). Mitigation: first-call advice to use a headset
  (14.5); request the platform communications stream category where reachable
  (WASAPI communications role / `VoiceProcessingIO` on macOS), which engages
  driver-level AEC (cpal may not expose this; a thin platform shim is possible).
  Speaker-phone quality is explicitly not promised.
- **Audio I/O**: `cpal` for desktop (WASAPI, CoreAudio, ALSA). Capture callback
  -> lock-free SPSC ring (4 frames) -> encode task -> datagram send; receive task
  -> jitter buffer -> playout callback. Opus through a libopus binding (`opus` /
  `audiopus`, to be chosen in the spike for build simplicity on Windows). Android
  (AAudio/Oboe through cpal) and iOS (CoreAudio, `AVAudioSession`, CallKit) are
  later; see the push-notification limit in 12.8.
- **Budgets** (estimates, to be measured in phase 6): encode CPU about 1 to 3
  percent of one core; mouth-to-ear latency 120 to 250 ms on a direct path (20 ms
  frame + 2 ms encode + network one-way + 40 to 100 ms jitter buffer + 10 to 20 ms
  device); acceptance in 13.

### 12.5 NAT traversal, relays, quality warnings

Reuse iroh hole punching and relay fallback as is. The call task polls
`IrohDirectClient::path_kind()` (`transport/iroh_direct.rs:721`) every 2 s:
`direct` shows no banner; `relay` shows **「中継経由のため、音質が悪くなる場合があります」**
and drops to 16 kbps. Relay datagrams ride a TCP/HTTPS tunnel (head-of-line
blocking, extra RTT), hence the warning. Loss above 20 percent or RTT above
400 ms for 5 s shows **「通信が不安定です」**. A call over a relay moves about 0.8
MB per minute (both directions, about 50 MB per hour) through a **third party's**
public relay infrastructure; whether that fits the relay operator's fair-use
terms is not verified (20), and users who call a lot should use their own
`iroh_mode = custom` relay.

### 12.6 States

`Idle -> Calling(呼び出し中) -> Connecting(接続中) -> Active(通話中) ->
Ended(reason)`, and `Idle -> Incoming(着信) -> Connecting -> Active`.
`Active -> Reconnecting(再接続中)` for up to 10 s, then ended. Reasons:
`hangup`, `declined`, `busy`, `no_answer` (30 s), `offline`, `failed`,
`mic_unavailable`, `network`. One call at a time (a second incoming ring gets
`Decline{busy}`).

### 12.7 Abuse

Only registered contacts with `allow_call` can ring (the call ALPN and the
`Offer` frame are both gated by the contact store; group-limited members cannot,
11.3). At most 3 rings per minute and 10 per hour per contact; ring timeout 30 s;
a 「おやすみモード」 switch declines everything with `Decline{dnd}`. A contact
that rings repeatedly can be muted or removed (ADR-012 flow). Calls are
unavailable when `iroh_mode = off`.

### 12.8 Out of scope in v1 and how they could come

- **Video**: another media track on the same datagram connection, with an
  adaptive-bitrate controller and key frames; a separate decision (CPU/RAM far
  above the call budget).
- **Group calls**: small groups as a full mesh (each pair is a 1:1 media
  connection: 3 participants = 2 uplinks of about 51 kbps), keys from the group
  epoch; larger groups would need a forwarding member (a selected participant
  acting as an SFU, media still E2E under a per-call sender key). Not designed
  here.
- **Mobile**: without an operator there is no push-notification sender
  (APNs/FCM require a server), so a suspended phone app **cannot receive calls
  or messages in the background**; mobile chat is "while the app is running or
  polling on its own schedule". This is a structural consequence of D6 and is
  stated in the UX.
- **Screen share, call recording**: not planned.

## 13. Resource budgets (RAM management is a must)

**Targets (owner D8)**: chat and calls add **<= +12 MiB** resident over the
baseline when idle and **<= +30 MiB during a call**, **per process** (daemon and
desktop each), measured as `peak - baseline` of Private Bytes (Windows) / RSS
(Linux), the metric and tooling of ADR-013 10.2 and 10.3. Nothing may grow with
message count, history length, uptime or group size.

### 13.1 Per-component caps

| Component | Cap | Policy when full | Notes |
|---|---|---|---|
| Message text | 4096 bytes (about 1300 Japanese characters) | Reject in the composer and in the receiver (`too_big`) | |
| Envelope on the wire | 16 KiB + header | Declared length checked before allocation | |
| Frame buffers | 16 KiB x 4 streams x 8 connections = 512 KiB hard bound | Streams beyond the cap are refused | Typical use is a few KiB |
| Chat connections kept | 8 (LRU close), idle 60 s | Close oldest | A QUIC connection's memory is not measured here; phase 1 measures it and lowers the cap if one connection costs more than 250 KB |
| History page | 50 messages | n/a | Scrolling loads another page, never the whole log |
| Decrypted-message cache | 1 MiB total, LRU by bytes (ADR-013 10.1 "decrypted-state cache" pattern) | Evict least recently used | Holds the open conversation's pages |
| Ephemeral message ring (mode `ephemeral`/`strict`) | 2 MiB | Drop oldest | Replaces the cache above for bodies |
| Session state hot set | 32 sessions x 8 KiB = 256 KiB | LRU; the rest on disk | Skipped keys (<= 1024/session) stay on disk |
| Seen-`envelope_id` set | 4096 entries, about 256 KiB | LRU; authoritative index on disk | |
| Outbox | 500 entries, 4 MiB on disk, 100 per contact; in RAM only a 100 B header per entry and <= 4 bodies of 16 KiB being sent | Compose disabled with a message; nothing dropped | |
| Mailbox client | 4 parallel fetches x 256 KiB reply cap = 1 MiB transient; id list <= 20 KiB | Serialize more work | Poll cost is counted in 8.7 |
| Mailbox holder (only if hosting is on) | disk 16 MiB; index 16 384 entries x 64 B = 1 MiB; I/O buffer 64 KiB | Reject deposits, never evict | Segment scan streams one record at a time |
| Group state | descriptor <= 1.5 KB; 20 chains; hot cache 8 groups <= 0.5 MiB | LRU | |
| Pending notifications | 100 x about 200 B | Drop oldest | |
| Call (daemon, only during a call) | Opus encoder + decoder about 0.2 MiB; jitter buffer <= 200 ms PCM (19 KB) + 10 packets; capture/playout rings 4 frames (8 KB); datagram buffers 64 KiB; resampler 64 KiB; 3 thread stacks about 3 MiB (committed lazily) | Hard caps; late packets dropped | Planned about 4 MiB; the 30 MiB budget leaves room for the audio driver stack and libopus, which are measured, not guessed |
| Desktop GUI | one conversation page (50 messages) of laid-out text <= 2 MiB; list of <= 1000 conversations, text row cache <= 0.5 MiB | Drop off-screen layouts | Target <= +6 MiB idle in the GUI process |

Planned idle total in the daemon (save mode, hosting on): cache 1.0 + sessions
0.25 + seen set 0.25 + outbox 0.12 + connections 2.0 + frames 0.5 + mailbox
client 1.0 + holder 1.0 + groups 0.5 + notifications 0.02 + allocator slack 1.0 =
**about 7.6 MiB**, leaving margin to the 12 MiB target. These are a plan, not a
measurement.

Persistent limits (disk, with ADR-013 O7's pattern): messages per conversation
10 000 by default (configurable to 1 000 000), 100 000 overall, retention setting
(14.6). Group members 20. Contacts 500 (`push/store.rs:24`).

### 13.2 How it is measured (in every phase's tests)

Using the `mem_probe` of ADR-013 10.3 (phase 0 provides it if ADR-013 has not):
sample every 100 ms on a thread, assert `max(samples) - baseline <= budget`.

| Scenario | Phase | Asserted |
|---|---|---|
| S1 idle with 100 contacts and 1000 conversations loaded from disk | 1, 2 | daemon <= +12 MiB; GUI <= +6 MiB |
| S2 **soak: 100 000 messages** sent and received between two nodes over loopback with the outbox, receipts and a full cache | 1, 3 | peak <= baseline + 12 MiB, and the growth between the first and last 10 percent of the run <= 1 MiB (no leak) |
| S3 page through a 1 000 000-record conversation log | 1 | one record resident (counting allocator in the test binary), <= +2 MiB |
| S4 holder at quota (16 MiB, 16 384 entries) while serving 8 pollers | 4 | holder part <= +4 MiB |
| S5 poll of 40 ids against 5 simulated holders, repeated 1000 times | 4 | no growth |
| S6 20-member group: re-key, sync, 1000 messages | 5 | <= +12 MiB |
| S7 10-minute synthetic call with 5 percent loss and 80 ms jitter injected | 6 | <= +30 MiB; growth between minute 2 and minute 10 <= 256 KiB |

Micro-tests: the LRU never exceeds its byte cap; the jitter buffer never holds
more than 10 frames; the outbox refuses entry 501.

## 14. User experience (UI text in Japanese)

Terms follow the Contacts tab: 連絡先, 連絡先コード, 確認用コード. "チャット" is a
new tab (a `Chat` variant of the `Tab` enum, `miasma-desktop/src/app.rs:40`),
placed right after 連絡先, built with the same UI kit.

### 14.1 Conversation list

Rows: name (連絡先の名前 or グループ名), last message (preview can be hidden,
14.7), time, **unread badge** (number; 99+), a small state mark for the last
outgoing message. Pinned: none in v1. Buttons: 「新しいチャット」(pick a 連絡先),
「グループを作る」. Empty state: 「連絡先を追加すると、ここでチャットできます」 with a
link to the 連絡先 tab. A conversation can only start with a registered 連絡先.

### 14.2 Conversation view and message states

Header: name, short 確認用コード, a connection hint (「直接つながっています」/
「中継経由です」/「オフライン」), buttons 「通話」「ファイルを送る」. Messages in
bubbles, day separators, own messages show a state:

| Internal | Shown | Detail (on hover) |
|---|---|---|
| `pending` | 送信中 | 「相手がオンラインになるまで、この端末で待っています」 |
| `deposited` | 送信済み | 「相手の端末にはまだ届いていません。暗号化して預けてあります」 |
| `delivered` | 届きました | |
| `read` | 既読 | only if both sides allow it |
| `failed` | 送れませんでした + 「もう一度送る」 | |

Message menu: 「コピー」「自分の端末から削除」「削除を依頼する」(own messages),
「ファイルも消す」(attachments). A retracted message shows
「このメッセージは削除されました」. Drafts are kept per conversation in `save`
mode and not at all otherwise.

### 14.3 Error and information texts

| Situation | Text |
|---|---|
| Partner offline | 「相手がオフラインです。メッセージは相手がオンラインになったら届きます」 |
| Partner has not registered me (`not_allowed`) | 「相手があなたを連絡先に登録していないため、届きません。相手に登録を頼んでください」 |
| Outbox full | 「送信待ちがいっぱいです。相手がオンラインになるまでお待ちください」 |
| Too long | 「1 通は約 1300 文字までです」 |
| Session rebuilt | 「安全な通信を作り直しました」 (information, not a warning) |
| Cannot resend after rebuild (`ephemeral`) | 「この端末ではもう再送できません。もう一度入力してください」 |
| No network | 「ネットワークに接続できません。つながったら自動で送ります」 |
| Offline delivery not available yet (2 nodes) | shown only in Settings: 「オフライン配送は、参加するノードが増えると使えるようになります」 |
| Chat disabled for a contact | 「この連絡先とのチャットは止めてあります」 |

### 14.4 Groups

- **Create**: name, tick 連絡先 to invite (up to 19 others), 「作成」.
- **Invitation received (the "add" rule, D3)**: a confirmation screen:
  「『{グループ名}』に招待されました(招待した人: {名前})」, then the member list
  with columns 名前(本人の名乗り) / 連絡先コード / 確認用コード / 状態
  (「登録済み」「未登録」), then the notice
  「参加しても、メンバーが連絡先に自動で追加されることはありません。『未登録』の人は、
  このグループの中で短い文字のメッセージを送るだけで、ファイルや通話はできません。
  知っている人は、確認用コードを本人と照らし合わせてから『連絡先に追加』を押して
  ください。」 Buttons 「参加する」「断る」.
- **Inside a group**: member list with a 「連絡先に追加」 button on each 未登録
  member; admins see 「メンバーを追加」「外す」; everyone sees 「退出」. Messages
  from 未登録 members carry a small 「未登録」 tag; tapping it shows the
  fingerprint.
- Group message state: 送信済み, 「N人に届きました」. No 既読 in groups (v1).

### 14.5 Call screen

Phone button in the conversation header. Outgoing: 「{名前}を呼び出し中…」
[キャンセル]. Incoming: a window/toast 「{名前}から着信」 [応答] [拒否]. Active:
name, elapsed time, a quality mark (「良好」「不安定」「中継経由(音質が悪くなる場合が
あります)」), [ミュート] [終了], a gear for input/output devices. First call
only: 「イヤホンやヘッドセットの使用をおすすめします。スピーカーだと、自分の声が
相手に回り込むことがあります」. Errors: 「相手がオフラインです」「相手は通話中です」
「応答がありません」「マイクが使えません。OS のプライバシー設定でマイクを許可して
ください」「通信が不安定なため終了しました」.

### 14.6 Settings (設定 > チャット) and presets

| Setting | Normal profile (default) | Stealth preset / portable build |
|---|---|---|
| 既読を送る・見る | ON (per contact override in 連絡先) | **OFF** |
| 履歴の保存 | 保存する (`save`) | 保存しない (`ephemeral`), 「完全に保存しない」(`strict`) is a separate opt-in |
| 保存期間 | 無期限 (choices: 1年 / 90日 / 30日 / 7日 / 24時間) | 24時間 for what is held in memory/outbox |
| 通知 | 送信者と内容を表示 | **内容を隠す** (「新着メッセージ」 only), no unread count in the title bar or taskbar |
| 着信を受ける / おやすみモード | 受ける | 受ける (ring shows no name if 内容を隠す) |
| 他の人の暗号化された断片を預かる (holder), 容量 | phase 4 ships **OFF**; 16 MiB when on | **0** |
| オフライン配送を使う (use holders) | ON when available | OFF until chosen |
| 電池を節約 (poll less) | OFF | OFF |

Explanation next to the holder switch: 「他の人のメッセージの暗号化された断片を
一時的に預かります。中身は読めません。最長 14 日で自動的に消えます」. Selecting
`strict` shows: 「アプリを閉じると、未送信のメッセージと、まだ受け取っていない預け
メッセージは失われます」.

The ADR-013 "maximum stealth" preset with `iroh_mode = off` disables push and
therefore **chat and calls entirely** (no transport); with a `custom` relay they
work. The preset screen says so.

### 14.7 Traces outside Miasma (stated, not solved)

Operating-system notification centres (for example the Windows notification
database, macOS notification history) can keep notification text; unread counts
in the title bar or taskbar reveal use; clipboard history tools keep copied
messages. Miasma cannot erase these. The mitigation is the content-hiding
notification setting, off-by-default previews in stealth, and these sentences in
the settings help and the wipe report's "not removable" list (ADR-013 8.4).

## 15. Implementation phases

Small, independently mergeable PRs, each with tests and acceptance criteria.
Order follows the owner's decision (1:1, then groups, then calls); receipts come
in phase 3 because they are tiny and complete the 1:1 feature. Every phase
adds its `mem_probe` scenario (13.2). Everything before phase 4 works with
2 nodes.

| Phase | Content | Tests (besides unit tests) | Acceptance criteria |
|---|---|---|---|
| **0. Prerequisites** | `StateCrypto` slice (document + record-log formats, ADR-013 5.2), label registry in `crypto/keyderive.rs`, `mem_probe` helper, `chat` cargo feature, additive contact fields `allow_chat`, `allow_call`, `read_receipts` (`#[serde(default)]`), the three ALPN registration points | Round trip, tamper/reorder/truncation rejection, old `contacts.json` still loads | No user-visible change; ADR-013 phase 3 can adopt the slice unchanged |
| **1. Message store, wire protocol, outbox, 1:1 over iroh direct** | `chat::crypto` (X3DH-lite + Double Ratchet, suite 2), `proto`, `store`, `outbox`, `service` (`miasma/chat/1`), IPC `ChatRequest`, CLI `miasma chat send / list / read / status` | Ratchet: Signal-spec test vectors, 1000 random out-of-order/duplicate/drop schedules (proptest); framing: declared-length checks, oversize, truncation; loopback 2 nodes with a local relay (pattern of `tests/push_test.rs`, `tests/iroh_direct_test.rs`); contact gate (non-contact gets 403, removed contact stops at the next stream); fault injection (kill between commit and `Ack`, drop the connection mid-frame, disk full, clock skew); **fuzz** the frame and envelope decoders; **soak: 100k messages** | 100 000 messages round trip with zero loss and zero duplicate in the store; messages sent while the peer is down arrive after it starts, in order; the data directory contains no plaintext of a marker string; S1/S2/S3 within budget; fuzz runs clean for 10 min in CI nightly |
| **2. GUI "チャット" tab (1:1)** | List, conversation view, unread badges, composer, drafts, message states 送信中/届きました, attachments via push (10), local delete, history modes `save`/`ephemeral`, retention, settings page, error texts (14.3) | `ui-tour`-style fixture screens for the new tab (as for Contacts, commit `9ed2b18`); IPC contract tests; paging test; attachments land in the ledger path | All texts in 14 present; offline state shows the right message; GUI idle <= +6 MiB with 1000 conversations; local delete leaves no plaintext (record-log compaction test) |
| **3. Delivery and read receipts** | Cumulative delivered/read receipts, per-contact toggle, reciprocity, coalescing, defaults per preset; states 既読 | Receipts never create messages; with receipts off zero receipt frames are emitted (counter in test); coalescing bound; 2-node end-to-end | Default ON in normal profile and OFF in stealth; state machine of 7.1 verified by a table-driven test |
| **4. Mailbox / fragment offline delivery** (ships **dark**: off by default until legal review) | `mailbox::ids`, `fragment`, holder store (log-structured), client (deposit, fetch, delete), `DhtCommand::ListPeers`, `miasma/mbx/1`, PoW, quotas, TTL sweep, polling cadence, delivered receipts through the mailbox | **Simulated nodes in-process**: a `MailboxTransport` trait with an in-memory implementation runs N = 0..50 nodes with scripted uptime (u = 0.5 / 0.8), loss and delay; delivery-rate test against 1 - (1-u)^n (1000 trials, tolerance 3 percent); a real-iroh test with 4 to 5 endpoints and a local relay; holder quota, per-principal, per-`rdv`, TTL expiry, `cap_mismatch` squatting, bad PoW, replayed `frag_id`; "no holder-visible plaintext" scan of holder segments; flood test | N = 0 behaves exactly as phase 3; with 3 or more nodes and sender and recipient never online together, delivery works; S4/S5 within budget; holder store survives kill -9 (index rebuilt from segments) |
| **5. Groups** | Descriptor, admin chain, sender keys, join confirmation screen, "press add" rule, unregistered-member limits, re-key on remove/leave, group inboxes, `GroupSync`, GUI screens | Descriptor validity and fork tests; n = 20 simulated re-key counts (342/380 messages); late joiner cannot decrypt earlier messages; removed member cannot decrypt new epoch; contact store unchanged after join (**no auto-add test**); unregistered member rejected for non-group frames, over-size, over-rate; mailbox group inbox | S6 within budget; the confirmation screen lists every member with both codes; fuzz the descriptor decoder |
| **6. Voice calls** | Spike first (datagram behaviour, path reuse, cpal/Opus build on a clean machine), then signalling frames, media keys, Opus CBR pipeline, jitter buffer, call UI, relay warning, abuse limits | Lossy/jittery in-process datagram channel (5 percent loss, 80 ms jitter, reordering); media key vectors; replay window; ring limits; no files created during a call; two-machine manual checklist including a relayed run through a local relay | Mouth-to-ear <= 300 ms on a direct path in the lab; S7 within budget; hang-up frees all buffers; a non-contact cannot ring |
| **7. Hardening** | Padding audit, sender-key rotation, decoy ids, chat retraction and holder `Delete`, optional link to network retraction (ADR-013 O11), back-pressure review, external review of crypto | Property test: every sent size is a bucket size; rotation does not lose messages; retract flows; extra fuzz corpus; adversarial tests of 16 | No size outside the buckets on the wire; review findings closed or accepted in writing |

Coordination with ADR-013: chat's persisted paths register in the persisted-paths
registry (ADR-013 phase 1); `wipe_leaves_nothing` (ADR-013 phase 5) is extended
with a chat-populated data directory; attachments use the ledger (ADR-013 phase 4).

## 16. Test plan

1. **Unit and property tests**: ratchet (spec vectors, random schedules),
   KDF label uniqueness (no two labels equal, none a prefix of another), padding,
   framing, outbox state machine, quota arithmetic, descriptor validation.
2. **Loopback multi-node tests**: two to five real iroh endpoints in one test
   process with the `iroh-relay` `test-utils` local relay (`Cargo.toml:69-71`), as
   `tests/push_test.rs` and `tests/iroh_direct_test.rs` do: no traffic to public
   services.
3. **Simulated nodes**: an in-memory `MailboxTransport` and a virtual clock for
   N up to 50 with scripted uptime, drop and delay; deterministic seeds so a
   failing run is replayable.
4. **Fault injection**: process kill between commit and `Ack`, between deposit
   and outbox update, mid-compaction; disk full; clock jumps of +/- 1 day around the
   epoch boundary; corrupted record in the middle of a log (the log is cut at the
   bad record, earlier records stay; a `.prev` generation is kept for the
   sessions document); holder restarts with a stale index.
5. **Fuzzing** (`cargo fuzz`, targets run 60 s in CI, 10+ min nightly):
   `chat::proto::decode_frame`, `chat::envelope::decode`, `mailbox::fragment::decode`,
   `group::descriptor::decode`, `call::signal::decode`, the call datagram parser,
   JSON inner payload with unknown fields. Properties: no panic, no allocation
   larger than the declared cap, decode(encode(x)) = x.
6. **Adversarial tests** (the style of `tests/adversarial_*_test.rs`): replayed
   envelope, reordered and withheld messages, truncated tags, wrong
   recipient, suite downgrade attempt, non-contributory X25519 key, stripped or
   re-attached signature in a group message, forged descriptor, stale epoch,
   `cap_pk` squatting, oversize declared lengths, many connections from one id.
7. **Soak**: 100 000 messages (13.2 S2) in CI nightly, 1 000 000-record paging.
8. **At-rest checks**: scan the data directory after a session for a marker
   string (must not appear in any file other than user-visible attachments); after
   deleting only `master.key` no chat file decodes (ADR-013 5.3 test pattern).
9. **Manual**: two machines (Windows and macOS), one behind a NAT/relay, including
   a call over a relayed path; sleep/wake; network switch.

## 17. Versioning, migration, failure modes

### 17.1 Versioning

- **Wire**: ALPN major (`/1`) is the break boundary; `Hello.v` minor and `caps`
  for optional features; unknown fields ignored; optional types >= 0x80 ignored.
  A breaking change ships a new ALPN served in parallel for >= 2 releases.
- **Envelope**: `ver` and `suite` bytes. Suite 1 (sealed box) and suite 2
  (ratchet) may coexist for a peer; a new session uses the highest suite both
  advertise in `Hello.caps`; a downgrade (peer advertises suite 2 but sends suite
  1) is rejected.
- **Mailbox**: `Deposit.ver`; holders ignore objects of an unknown version
  (they cannot read them anyway) and expire them normally.
- **At rest**: ADR-013 headers (`MSD1` / `MSL1`, version byte) plus a `schema`
  field in `chat-prefs`. A newer schema opens read-only in an older binary with an
  explicit message, never silently truncated. Migrations are forward-only and
  verified before the old copy is overwritten (the ADR-013 migration rule:
  read old, write new, verify, then remove the old one).
- **Group descriptors**: `v` byte inside the signed bytes; an unknown version is
  stored but not applied.

### 17.2 Failure modes

| Failure | Behaviour |
|---|---|
| Peer offline | Outbox + backoff (7.2); with holders, deposit (8) |
| `Ack` lost after commit | Sender retransmits; receiver answers `dup` (idempotent on `msg_id` and `envelope_id`) |
| Crash between commit and `Ack` | Same |
| Session state lost or restored from backup | `no_session` -> new bootstrap (5.2); messages in `ephemeral`/`strict` cannot be re-sealed and are marked failed |
| Simultaneous session initiation | Smaller `EK` wins (5.2) |
| Disk full | Compose disabled; incoming messages answered `busy`/`no_space` (not acknowledged), so the sender keeps them; holders reject deposits |
| History log corrupted | Cut at the bad record; earlier history readable; sessions document keeps a previous generation; conversation shows 「一部の履歴を読み込めませんでした」 |
| Clock skew | HLC clamp (+5 min); epoch skew absorbed by polling the neighbouring epoch; call signatures include `call_id`, not time |
| Holder offline / full / hostile | Next holder in rank; probabilistic delivery with outbox backstop (8.3) |
| Flood from a contact | Per-contact rate limits, then mute/remove |
| `iroh_mode = off`, relay unreachable | Chat unavailable; UI shows the transport state (as the status page does for push) |
| Contact removed then re-added | Fresh session; old history stays attached to the old contact entry |
| Low memory | Caps in 13 apply; the daemon refuses new work (`busy`) rather than allocate |

## 18. Regulatory note (not legal advice)

I am not a lawyer and this section states questions, not conclusions. The
design goal "no operator" (D6) was chosen partly to keep the project and its
users outside the position of a communications service provider, but whether it
does is a legal question I cannot answer.

Why it matters for this feature in Japan: chat and calls are communications.
The Telecommunications Business Act (電気通信事業法) regulates parties that
provide telecommunications services to others, with notification or
registration duties that depend on the kind of service and facilities, and its
confidentiality-of-communications rules (通信の秘密) bind such parties; the
Constitution (Article 21) protects the secrecy of communications generally.
Questions to put to a specialist before wide public distribution:

1. Is distributing peer-to-peer messaging and calling software, with no
   operator-run server, itself a "telecommunications business", for the
   publisher? For a user who runs the daemon?
2. Does a user's node **storing or relaying other people's encrypted
   fragments** (the holder role of phase 4) count as mediating others'
   communications, and with what consequences for that private individual?
3. Does the use of third-party relays and discovery (n0 in the default mode)
   change the analysis, and are there duties towards or about those third
   parties?
4. What does the law say about voice calls in this model (no telephone numbers,
   no connection to the public telephone network), and about emergency-call
   duties, if any, for a non-PSTN voice feature?
5. Duties around abuse reports, log retention or lawful requests, given that
   nobody can read, retain or take down content in this design.
6. Personal-information handling of contact codes and message metadata held on
   users' devices (APPI), and export/distribution rules for encryption software
   in the jurisdictions where releases are downloaded.
7. Platform-store policies if mobile apps are released.

**Recommendations.** (a) Obtain this review **before** wide public distribution
and at the latest before turning phase 4 on by default; (b) ship phase 4
**dark** (off by default, hosting 0) until then; (c) keep the "no logs, no
operator, nothing readable by holders" properties as hard requirements, because
every answer above is easier with them; (d) document for users that their node
only ever holds encrypted, expiring fragments and that they can switch hosting
off (14.6).

## 19. Open questions for the owner (with recommendations)

1. **Prerequisite slice.** Extract ADR-013's `StateCrypto` (documents + record
   log + labels) and `mem_probe` as chat phase 0, or wait for ADR-013 phase 3?
   *Recommend: extract phase 0*, so chat does not invent a private format and ADR-013
   adopts the same one.
2. **Holder hosting default.** Should a node store other people's fragments by
   default once phase 4 lands? *Recommend: ship dark (off), decide after the legal
   review (18); keep 0 in stealth/portable.*
3. **Metadata leak at holders** (5.6, 8.9): accept "a holder that sees both the
   deposit and the fetch can link the two endpoints" in v1? *Recommend: accept,
   document in the UI help, add decoy ids in phase 7, and study a relay hop or
   per-epoch identity as research; do not delay phase 4 for it.*
4. **Copies or erasure coding in the mailbox.** *Recommend: plain copies
   (k = 1, n <= 5)* because personal PCs have low uptime and the objects are tiny
   (8.4); keep k, n in the format.
5. **Ratchet from the start.** *Recommend: Double Ratchet (suite 2) in phase 1*,
   with the sealed-box suite only as a fallback if the schedule slips; plan an
   external review of the crypto code.
6. **Read receipts.** Reciprocal (if I do not send, I do not see yours) and no
   read receipts in groups for v1? *Recommend: yes to both.*
7. **Messages from unregistered group members.** Show them (text only, tagged
   「未登録」, rate-limited) or hide them until added? *Recommend: show with limits*
   (a group where you cannot read most members is not usable); the stricter
   option is a one-line policy change.
8. **Calls by default.** `allow_call` on for every registered contact, with
   おやすみモード and ring limits? *Recommend: on*, since mutual registration is
   already the trust boundary (ADR-012).
9. **Echo cancellation.** No software AEC in v1 and a headset recommendation,
   or bundle a C++ AEC? *Recommend: no AEC in v1* (build and installer cost, ADR-013
   fresh-PC constraint); revisit after the phase 6 spike.
10. **Mobile.** Accept that without a push-notification server a suspended phone
    app cannot receive messages or calls (12.8)? *Recommend: accept and say it in
    the mobile UX; do not add a push relay, which would be an operator.*

## 20. What I could not verify

- **Nothing was built or run.** This is a design-only change; every size,
  latency, CPU, RAM and bandwidth figure is a hand estimate (arithmetic from the
  field lists cited), not a measurement. The availability table is exact
  binomial arithmetic under an independence assumption that real holders will
  violate (correlated outages: same ISP, same time zone).
- **ADR-013 is unimplemented**, so every integration with `StateCrypto`, the
  ledger, the wipe and `mem_probe` is on paper.
- **Crypto API details**: the exact `ed25519-dalek` / `x25519-dalek` calls for the
  Ed25519-to-X25519 conversion; that `hmac` is absent (HKDF-Expand is proposed
  instead); the Double Ratchet details are written from my knowledge of the Signal
  specification and must be re-checked against the published text and its test
  vectors.
- **iroh behaviour**: datagram send API, its default enablement and maximum size
  on direct vs relay paths; whether a second connection (another ALPN) reuses the
  hole-punched path; relay-only connection options; the memory cost of a second
  endpoint or of an idle QUIC connection; whether `n0` discovery lets arbitrary
  routing-table peers be dialled by endpoint ID (peers in `custom` or `off` modes
  will not resolve).
- **Peer discovery for holders**: whether any existing `DhtCommand` lists
  routing-table peers (none found, `network/node.rs:742`); how many peers a 3 to 10
  node network actually has in that table.
- **Audio**: how the daemon is started on Windows (a process outside the
  interactive session cannot open audio devices); whether `cpal` exposes the
  communications stream category; whether `opus` / `audiopus` build on a clean
  Windows machine without a C toolchain at install time (they are built at
  development time, but the CI image and licences were not checked); AEC options.
- **Third parties**: the fair-use terms of the n0 public relays for sustained
  call traffic; notification-database behaviour of Windows and macOS (what text
  persists).
- **Law**: nothing in 18 was researched against the statute text; it is a list
  of questions for a specialist.
- **UX wording**: the Japanese strings are drafted by me, not reviewed by a
  native UX writer or tested with users.
- **Line numbers** are from `origin/main` at `bdf3cd1` and will drift; the grep
  patterns of Appendix D reproduce the list.

## 21. Consequences

- Positive: chat and calls without any operator, working with two nodes today and
  improving as nodes appear; one identity, one trust list, one set of at-rest
  rules; every buffer bounded; every phase shippable.
- Negative: a new crypto module (ratchet, group keys) that needs expert review; a
  new store with expiry that holds other people's data (legal question, phase 4);
  the unavoidable holder-side metadata link; no background delivery on mobile;
  no software AEC in v1.
- Risks (top): (1) privacy leaks through holder correlation and
  notification/OS traces; (2) abuse by many cheap identities filling holder
  quotas; (3) RAM and battery cost of polling and of audio stacks on small
  machines; (4) legal exposure of ordinary users hosting fragments and of the
  publisher; (5) crypto implementation errors in ratchet/group code.

## Appendix A. Label registry (HKDF / BLAKE3 domain separation)

All are fixed byte strings in `crypto/keyderive.rs` next to the existing labels
(ADR-013 5.1). None is built from user input.

| Label | Use |
|---|---|
| `miasma/chat/v1/pair` | `pair_root` salt |
| `miasma/chat/v1/x3dh` | session bootstrap |
| `miasma/chat/v1/rk`, `.../ck`, `.../msgkey` | ratchet KDFs |
| `miasma/chat/v1/mbx/rdv`, `.../cap`, `.../obj`, `.../holder`, `.../deposit`, `.../delete`, `.../pow` | mailbox ids, capability key, object key, ranking, signatures, PoW |
| `miasma/chat/v1/grp/desc`, `.../grp/inbox` | descriptor signature, group inbox ids |
| `miasma/chat/v1/call/transcript`, `.../export`, `.../media`, `.../a2b`, `.../b2a` | call keys |
| `miasma/state/v1/doc/chat-msgs`, `chat-sessions`, `chat-outbox`, `chat-groups`, `chat-prefs`, `chat-drafts`, `chat-holder` | ADR-013 state subkeys |

## Appendix B. Message kinds (inner `k`)

`text`, `retract`, `receipt` (`delivered` | `read`), `attach`, `ginvite`,
`gdesc`, `gkey`, `gleave`, `callmissed`, `hello`. Frame types: 6.2 and 12.2.

## Appendix C. Constants (defaults)

| Constant | Value |
|---|---|
| Max text | 4096 bytes |
| Padding buckets | 512, 1024, 2048, 4096, 8192, 16384 bytes |
| Max frame | 16 KiB + 512 B |
| History page | 50 messages |
| Messages per conversation / overall | 10 000 / 100 000 (configurable) |
| Outbox | 500 entries, 4 MiB, 100 per contact; expiry 30 days |
| Retry | 5 s, 30 s, 2 min, 10 min, then 15 min, +/-20 percent jitter |
| `MAX_SKIP` / stored skipped keys | 256 / 1024 per session |
| Epoch / mailbox TTL | 1 day / 14 days default, 30 hard |
| Mailbox copies `n` | min(holders, 5) |
| Holder store / per principal / per `rdv` | 16 MiB / 1 MiB / 64 fragments, 256 KiB |
| Deposit PoW | 20 bits (24 under load) |
| Poll cadence | 10 min (2 min after activity, 15 min background) |
| Group size | 20 |
| Unregistered member in a group | text only, <= 2 KiB, <= 6 per minute |
| Call | Opus 48 kHz mono, 20 ms, CBR 24 kbps (16 on relay), ring 30 s, 3 rings/min |

## Appendix D. How the code survey was made

```
git fetch origin; git worktree add ... origin/main            # bdf3cd1
git grep -n -i -E "StateCrypto|mem_probe|KeyVault|stealth" -- "crates/*.rs"     # nothing: ADR-013 not implemented
git grep -n -i datagram -- "crates/*.rs"                        # no datagram use outside reality.rs comments
git grep -n -E "ALPN|alpn" crates/miasma-core/src/transport/iroh_direct.rs
git grep -n -E "pub (struct|enum|fn|const)" crates/miasma-core/src/push/*.rs
git grep -n "put_hosted_by|hosted_principal|HOSTED_PRINCIPAL" crates/miasma-core/src
git grep -n -E "DEFAULT_POW_DIFFICULTY|set_record_ttl" crates/miasma-core/src
```
