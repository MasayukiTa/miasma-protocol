# ADR-006: Directed Private Sharing Protocol

## Status: Accepted

## Context

Miasma's existing sharing model is anonymous broadcast: content is dissolved
into shards, published to the DHT, and retrievable by anyone with the MID.
This works well for public or semi-public distribution but does not address
a common use case: sending a file to a specific person.

Recipient-targeted sharing requires:

1. **Recipient binding** — only the intended recipient can decrypt the content,
   even if the envelope is intercepted or delivered to the wrong peer.
2. **Password second factor** — a shared secret known out-of-band, so that
   compromising the recipient's long-term key alone is not sufficient.
3. **Anti-misdirection** — a mechanism for the sender to confirm they are
   targeting the correct recipient before the content becomes retrievable.
4. **Forward secrecy** — compromise of long-term keys does not expose past
   directed shares.
5. **Honest deletion** — sender revocation and expiry render content
   cryptographically unrecoverable, even though encrypted shards may persist
   on the network.

The existing anonymous trust layer (ADR-005) provides the transport
infrastructure (onion routing, relay circuits, descriptor-based peer
discovery) but has no concept of sender-to-recipient encrypted delivery.

## Decision

### 1. Cryptographic design

Directed sharing uses a double-encryption scheme with two key derivation
paths:

```
envelope_key = HKDF-SHA256(
    ikm  = ECDH(sender_ephemeral, recipient_pubkey),
    info = "miasma-directed-envelope-v1"
)

directed_key = HKDF-SHA256(
    ikm  = ECDH(sender_ephemeral, recipient_pubkey) || Argon2id(password, salt),
    info = "miasma-directed-content-v1"
)

envelope_payload  = XChaCha20-Poly1305(envelope_key, nonce, payload)
protected_content = XChaCha20-Poly1305(directed_key, nonce, plaintext)
```

**Double encryption**: The envelope payload (MID, Reed-Solomon parameters,
content nonce, filename, file size) is encrypted with `envelope_key` derived
from ECDH alone. This allows the recipient to preview envelope metadata
without entering the password. The actual file content is encrypted with
`directed_key`, which requires both the ECDH shared secret and the
Argon2id-hashed password.

**Argon2id parameters**: t_cost=3, m_cost=64 MiB, p_cost=1, output=32 bytes.
Salt is 32 bytes of random, stored in the envelope.

**Ephemeral keys**: Each envelope generates a fresh X25519 keypair. The
ephemeral public key is included in the envelope; the ephemeral secret is
not persisted after envelope creation. This provides forward secrecy —
compromise of the sender's long-term sharing key does not expose past
envelopes.

### 2. Envelope structure

`DirectedEnvelope` contains:

| Field | Type | Purpose |
|-------|------|---------|
| `envelope_id` | `[u8; 32]` | Random unique identifier |
| `version` | `u8` | Protocol version (currently 1) |
| `sender_pubkey` | `[u8; 32]` | Sender's X25519 sharing public key |
| `recipient_pubkey` | `[u8; 32]` | Recipient's X25519 sharing public key |
| `ephemeral_pubkey` | `[u8; 32]` | Per-envelope ephemeral X25519 public key |
| `encrypted_payload` | `Vec<u8>` | ECDH-encrypted `EnvelopePayload` |
| `payload_nonce` | `[u8; 24]` | XChaCha20 nonce for payload encryption |
| `password_salt` | `[u8; 32]` | Argon2id salt for password hashing |
| `expires_at` | `u64` | Expiry timestamp (Unix seconds) |
| `created_at` | `u64` | Creation timestamp (Unix seconds) |
| `state` | `EnvelopeState` | Current lifecycle state |
| `challenge_hash` | `Option<[u8; 32]>` | BLAKE3 hash of confirmation code |
| `password_attempts_remaining` | `u8` | Password attempts left (default 3) |
| `challenge_attempts_remaining` | `u8` | Challenge attempts left (default 3) |
| `challenge_expires_at` | `u64` | Challenge TTL timestamp |
| `retention_secs` | `u64` | Retention duration for display |

The inner `EnvelopePayload` (decryptable with ECDH only, no password) contains:
- `mid`: MID of the double-encrypted content on the network
- `data_shards` / `total_shards`: Reed-Solomon parameters (k, n)
- `content_nonce`: XChaCha20 nonce for the directed content encryption
- `filename`: optional original filename
- `file_size`: original plaintext size in bytes

### 3. Envelope lifecycle and state machine

```
Pending → ChallengeIssued → Confirmed → Retrieved
                          ↘ ChallengeFailed (terminal, max 3 attempts)
Pending → SenderRevoked (terminal)
Any non-terminal → Expired (terminal, past retention period)
Confirmed → RecipientDeleted (terminal)
Any non-terminal → PasswordFailed (terminal, max 3 password attempts)
```

Terminal states: `Retrieved`, `SenderRevoked`, `RecipientDeleted`, `Expired`,
`ChallengeFailed`, `PasswordFailed`. No further transitions are allowed from
terminal states.

Content is retrievable only in the `Confirmed` state.

### 4. Confirmation challenge

The recipient generates a one-time confirmation code to prevent misdirected
sends.

**Format**: 8 characters from a 31-character alphabet (`23456789ABCDEFGHJKMNPQRSTUVWXYZ`),
displayed as `XXXX-XXXX`. Ambiguous characters (`0/O`, `1/I/L`) are excluded.

**Security properties**:
- ~40 bits of entropy (31^8 possibilities)
- Stored as a BLAKE3 hash; verification uses constant-time comparison (`subtle::ct_eq`)
- TTL: 5 minutes (`CHALLENGE_TTL_SECS = 300`)
- Maximum 3 attempts (`CHALLENGE_MAX_ATTEMPTS = 3`)
- Fails closed: exceeding attempts or TTL → `ChallengeFailed` (terminal)

**Normalization**: Input is trimmed, uppercased, non-alphanumeric characters
stripped, and the `XXXX-XXXX` format is reconstructed before hashing. This
allows the sender to enter the code with or without the hyphen, in any case.

The raw challenge code is stored in a separate `.challenge` file alongside
the incoming envelope on the recipient's machine. It is never transmitted
over the wire — the sender must communicate the code out-of-band (voice,
messaging, etc.) and submit it via the `Confirm` protocol message.

### 5. Sharing contact format

Peers are identified for directed sharing by their X25519 sharing public key
and libp2p PeerId:

```
msk:<base58(x25519_pubkey)>@<PeerId>
```

Example: `msk:4vJ9...xK2@12D3KooWTestPeerId`

The `msk:` prefix (Miasma Sharing Key) disambiguates from other identifiers.
The `@PeerId` suffix provides the network address for P2P delivery.

Standalone key format (without PeerId): `msk:<base58(x25519_pubkey)>`

### 6. P2P protocol

Protocol ID: `/miasma/directed/1.0.0`

Wire format: bincode serialization with 4-byte little-endian length prefix.
Maximum message size: 32 KiB (`DIRECTED_MSG_MAX`).

**Request types** (`DirectedRequest`):

| Variant | Fields | Purpose |
|---------|--------|---------|
| `Invite` | `envelope: DirectedEnvelope` | Sender delivers envelope to recipient |
| `Confirm` | `envelope_id`, `challenge_code` | Sender submits confirmation code |
| `SenderRevoke` | `envelope_id` | Sender revokes a previously sent share |
| `StatusQuery` | `envelope_id` | Query current state of an envelope |

**Response types** (`DirectedResponse`):

| Variant | Fields | Purpose |
|---------|--------|---------|
| `InviteAccepted` | `envelope_id` | Recipient accepted; challenge displayed on their screen |
| `Confirmed` | `envelope_id` | Challenge verified; content now retrievable |
| `ChallengeFailed` | `envelope_id`, `attempts_remaining` | Wrong code; attempts decremented |
| `Revoked` | `envelope_id` | Revocation acknowledged |
| `Status` | `envelope_id`, `state` | Current envelope state |
| `Error` | `String` | Error message |

The challenge code itself is never included in any wire message. The
`InviteAccepted` response tells the sender that the recipient has generated
a challenge and is displaying it locally. The sender obtains the code
out-of-band and submits it via `Confirm`.

### 7. Retention periods

Sender-configurable retention periods:

| Variant | Duration |
|---------|----------|
| `TenMinutes` | 600s |
| `OneHour` | 3,600s |
| `OneDay` | 86,400s |
| `SevenDays` | 604,800s |
| `ThirtyDays` | 2,592,000s |
| `Custom(secs)` | arbitrary |

Envelopes past their retention period automatically transition to the
`Expired` terminal state. The `expire_all()` method scans both incoming and
outgoing directories and updates expired envelopes.

### 8. Inbox storage model

Envelopes are stored as JSON files on the local filesystem:

```
{data_dir}/directed/incoming/{envelope_id_hex}.json   (recipient side)
{data_dir}/directed/outgoing/{envelope_id_hex}.json   (sender side)
{data_dir}/directed/incoming/{envelope_id_hex}.challenge  (challenge code, recipient only)
```

`DirectedInbox` provides:
- Save/load/delete/list for both incoming and outgoing envelopes
- State update helpers (`update_incoming_state`, `update_outgoing_state`)
- Challenge code storage (separate file, recipient-only)
- Bulk expiry sweep (`expire_all`)
- Listings sorted by creation time (newest first)
- `EnvelopeSummary` for listing without decrypting envelope payloads

### 9. Sender workflow

1. Sender calls `create_envelope()` with recipient's X25519 pubkey, password,
   retention period, plaintext, and optional filename.
2. The function generates an ephemeral X25519 keypair, performs ECDH, derives
   both `envelope_key` and `directed_key`, encrypts the payload and content
   separately, and returns `(envelope, protected_data, envelope_key)`.
3. The `protected_data` (double-encrypted content) is dissolved into the
   network via the standard share mechanism, producing a MID.
4. Sender calls `finalize_envelope()` to write the MID and Reed-Solomon
   parameters into the envelope payload (decrypt-update-re-encrypt cycle).
5. Sender delivers the finalized envelope via `DirectedRequest::Invite`.
6. Sender enters the challenge code (received out-of-band) via
   `DirectedRequest::Confirm`.

### 10. Recipient workflow

1. Recipient receives `DirectedRequest::Invite`, stores the envelope, generates
   a confirmation challenge, saves the challenge code locally, and returns
   `InviteAccepted`.
2. Recipient displays the challenge code on their screen for out-of-band
   communication to the sender.
3. On `DirectedRequest::Confirm`, recipient verifies the challenge code
   (constant-time). On success, transitions the envelope to `Confirmed`.
4. To retrieve: recipient calls `decrypt_envelope_payload()` (ECDH only) to
   preview metadata (filename, size, MID). Then enters the password, calls
   `derive_content_key()` (ECDH + Argon2id), fetches the protected content
   from the network using the MID, and calls `decrypt_directed_content()`.

### 11. Deletion semantics

Deletion in a distributed system is honest but not absolute:

- **Sender revoke** (`SenderRevoke`): transitions envelope to `SenderRevoked`,
  published to recipient. Prevents future retrieval. Does NOT guarantee
  physical deletion of encrypted shards from all network nodes.
- **Recipient delete**: removes local envelope and key material. Cannot
  revoke network-side shards.
- **Expiry**: automatic transition to `Expired` based on retention period.
  Expired envelopes are no longer retrievable.
- **What "deletion" really means**: cryptographic deletion. The key material
  needed to decrypt the content is discarded. The encrypted shards may still
  exist on the network but are computationally infeasible to decrypt without
  the directed key (which requires both the ECDH shared secret and the
  password).

## Consequences

### What this enables

- **Recipient-targeted sharing**: files can be sent to a specific person,
  not broadcast to the network. Only the holder of the recipient's X25519
  private key can compute the ECDH shared secret needed for decryption.
- **Two-factor protection**: even with a compromised recipient private key,
  the attacker still needs the password to derive the content key. Argon2id
  makes brute-force expensive (64 MiB memory-hard).
- **Anti-misdirection**: the confirmation challenge prevents sending to the
  wrong recipient. The sender must verify (out-of-band) that the person
  displaying the challenge code is the intended recipient.
- **Forward secrecy**: each envelope uses a fresh ephemeral X25519 keypair.
  Compromise of a peer's long-term sharing key does not retroactively expose
  previously sent envelopes, because the ephemeral secret is not persisted.
- **Sender revocability**: senders can invalidate envelopes before retrieval.
  Combined with retention-based expiry, this provides lifecycle control.

### Security properties

- **Recipient binding**: ECDH with recipient's static X25519 key. Wrong
  recipient cannot derive the envelope key (AEAD fails on payload decryption).
- **Password second factor**: directed content key requires both ECDH output
  and Argon2id(password). Neither factor alone is sufficient.
- **Challenge integrity**: BLAKE3 hash with constant-time comparison prevents
  timing attacks. 5-minute TTL and 3-attempt limit bound the attack window.
- **Attempt limiting**: both challenge (3 attempts) and password (3 attempts)
  have hard limits that transition to terminal failure states, preventing
  brute-force.

### Limitations

- **Honest deletion is cryptographic, not physical**: encrypted shards may
  persist on DHT peers after revocation or expiry. Security relies on the
  computational infeasibility of decrypting without the key material.
- **Password verification is deferred**: in protocol version 1, password
  correctness is verified at content decryption time (AEAD tag check), not
  at entry time. This means a wrong password is detected only when the
  recipient attempts to decrypt the retrieved content.
- **Connectivity requirement**: the sender and recipient must be mutually
  reachable via the libp2p network for the invite and confirm handshake.
  The actual content retrieval uses the standard DHT and may go through
  relay/onion paths per the configured anonymity policy.
- **Tor SOCKS5 is not used for the directed sharing control plane**: the
  directed sharing protocol (`/miasma/directed/1.0.0`) uses libp2p
  request-response, which requires bidirectional P2P reachability. Tor
  SOCKS5 is an outbound-only proxy and cannot satisfy this requirement.
  Directed sharing works over direct libp2p connections and relay circuits
  (relay circuit fallback implemented per ADR-010 Part 2, 2026-04-01), but
  NOT over Tor SOCKS5. See ADR-010 for the full architectural analysis.
- **Out-of-band channel required**: the confirmation challenge requires a
  separate communication channel (voice, messaging) between sender and
  recipient. The protocol does not provide this channel.

### Connectivity model per surface

- **CLI**: sender specifies recipient contact (`msk:...@PeerId`), enters
  password, receives challenge code out-of-band, submits via CLI command.
- **Desktop**: directed sharing UI with contact entry, password input,
  challenge display (recipient) / challenge entry (sender), and status
  tracking through the envelope lifecycle.
- **Mobile (future)**: same protocol over libp2p; credential-backed
  admission (ADR-005) reduces re-admission cost on reconnect.

## Relationship to other ADRs

- **ADR-003 (Share Integrity)**: directed content is dissolved using the
  same Reed-Solomon erasure coding and MID-addressed shard storage. The
  directed layer adds an outer encryption envelope on top of the standard
  share mechanism.
- **ADR-005 (Anonymous Trust)**: share content retrieval uses the relay/onion
  infrastructure from ADR-005. The directed sharing control plane uses raw
  libp2p request-response; relay circuit fallback for the control plane is
  implemented per ADR-010 Part 2.
- **ADR-010 (Directed Sharing Transport Architecture)**: defines the product
  boundary (Tor SOCKS5 not supported for control plane) and the concrete relay
  circuit fallback implementation plan. The sharing key (`msk:`) is separate
  from the node's onion key and peer identity.
