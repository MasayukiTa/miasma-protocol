## What

Adds PR0 of the call feature: the transport path only.

- A new ALPN `miasma/call/1` is registered on the iroh endpoint, alongside the existing push/chat/group ALPNs.
- `connect_call` dials a peer on that ALPN and returns the open connection; `CallConnectionHandler` + `set_call_handler` serve inbound call connections.
- An integration test drives one round trip of an encrypted dummy datagram between two in-process nodes over a local relay, asserts the datagram budget (`max_datagram_size`) holds the 90-byte voice total, and checks that a single flipped bit is rejected by the AEAD.
- Served call connections are bounded by a dedicated cap (`MAX_CALL_CONNECTIONS = 16`), separate from the endpoint-wide cap, so a flood of call dials cannot starve chat/push; a connection over the cap is closed cleanly (code 3 `unavailable`), never queued.

No signalling, no media key schedule, no UI. No real media send path ships: `connect_call` only opens the connection.

## Design sections

- §8.2 row PR0 (transport reachability: new ALPN `miasma/call/1`, one encrypted dummy datagram round trip).
- §4.1 choice A (iroh unreliable datagram over the new ALPN).
- §8.3 PR0 merge gates.

The test-only dummy uses the AES-256-GCM `crypto::encrypt` helper (fresh random key + internal nonce, zeroized on drop). This is explicitly NOT the production media path: §4.1.1 bans AES-256-GCM for real media; PR1 will seal frames with XChaCha20-Poly1305 and the §4.1.2 deterministic nonce. The test carries a comment to that effect so the helper is not copied into the media path.

## Which chapter-7 gate it proves

- §7.13 (transport part): one datagram round trip succeeds over the call ALPN.
- §7.9: `max_datagram_size()` holds the 90-byte voice total.
- §7.1 (reduced): a tampered encrypted dummy fails to open (AEAD tag check).
- Clean ALPN refusal: a peer that does not list `miasma/call/1` refuses the handshake, the caller sees `is_alpn_refused()` (not a generic network failure), and the peer's chat ALPN is unaffected.

## CI collection

The new integration test is collected and run by CI without any change to the `--test` enumeration: the `test-core` job runs `cargo test -p miasma-core --tests --locked` (ci.yml line 62), and `--tests` builds and runs every integration test file in the crate, including `crates/miasma-core/tests/call_transport_pr0_test.rs`; the `iroh` feature the file gates on (`#![cfg(feature = "iroh")]`) is on by default (`default = ["iroh"]` in crates/miasma-core/Cargo.toml), so the file compiles and its tests run in that job. The per-job `--test` enumeration in the `test-core-pqc` job (ci.yml lines 82-86) is only for the hybrid-feature suite and does not govern this test.

## What is NOT done

- The §8.2 PR0 row asks for the datagram to arrive over both the **direct** (hole-punched) and **relay** paths. Only the relay path is exercised here: the in-process harness builds both nodes on one local iroh relay with discovery and LAN/mDNS turned off, so the only address the ends learn is the relay URL and no direct socket address can be hole-punched inside one test process. The direct path is recorded as an OPEN gate item for PR0, not claimed as covered. It needs two real network endpoints (or a discovery service) to assert.
- No media key derivation, no framing, no signalling, no state machine, no UI. Those are PR1 and later.
