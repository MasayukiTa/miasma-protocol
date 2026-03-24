# ADR-009: Native Tunnel Decision — Shadowsocks and Tor

**Status**: Revised (2026-03-24)
**Date**: 2026-03-24

## Context

The bridge connectivity superhardening task asked whether to add native Shadowsocks tunnel support and embedded Tor support, or to keep the current external SOCKS5 proxy approach.

**Original decision (2026-03-24 morning):** Rejected both native SS and embedded Tor.

**Revision (2026-03-24):** `shadowsocks-crypto` v0.6.2 discovered to be pure-Rust with AEAD-2022 support via `aes-gcm` + `blake3` + `chacha20poly1305` — all already in our workspace. Native Shadowsocks implemented. Tor decision unchanged.

## Decision

### Shadowsocks: Native AEAD-2022 — Implemented

**`shadowsocks-crypto` v0.6.2** (cipher-only crate, NOT the full `shadowsocks` relay crate) provides pure-Rust AEAD-2022 encryption with zero OpenSSL dependency. Its transitive deps (`aes-gcm`, `blake3`, `chacha20poly1305`, `aes`, `cfg-if`, `bytes`) are almost entirely already in the workspace.

**Implementation:**
- `shadowsocks-crypto = { version = "0.6", default-features = false, features = ["v2"] }` added to workspace
- Native AEAD-2022 TCP relay protocol implemented in `transport/shadowsocks.rs` (~300 LOC)
- Uses `shadowsocks_crypto::v2::tcp::TcpCipher` for per-stream AEAD encryption
- Client handshake: salt + encrypted fixed header (type, timestamp, var header length) + encrypted variable header (SOCKS5 address, padding)
- Bidirectional relay via `tokio::io::duplex` + spawned encrypt/decrypt tasks
- WebSocket upgrade + bincode ShareFetchRequest/Response over the encrypted tunnel
- External ss-local SOCKS5 mode preserved as fallback

**Why the original rejection was wrong:**
- The `shadowsocks` crate (full relay implementation) requires OpenSSL — but `shadowsocks-crypto` (cipher-only) does NOT
- `shadowsocks-crypto` with `features = ["v2"]` is pure Rust, using `aes-gcm` and `blake3` which we already depend on
- Only 1 new crate added to dependency tree
- No binary size increase measurable beyond what we already have

**Dual-mode configuration:**
```toml
[transport.shadowsocks]
enabled = true
# Native mode: direct AEAD-2022 tunnel (no ss-local needed)
server = "1.2.3.4:8388"
password = "base64-encoded-32-byte-PSK"
cipher = "2022-blake3-aes-256-gcm"
# External mode (fallback): ss-local SOCKS5 proxy
local_addr = "127.0.0.1:1080"
```

Native is tried first. If native fails (or is not configured), external SOCKS5 is tried. Both can coexist in the same config.

### Tor: External SOCKS5 — Unchanged (Still Rejected)

`arti-client` remains pre-1.0, adds ~50+ transitive crate dependencies, ~10MB binary size increase, and is untested on iOS. The external SOCKS5 approach (user runs Tor separately) remains correct.

**Rejected because:**
- Pre-1.0 stability — API may change between releases
- ~50+ additional crate dependencies (massive supply-chain surface)
- ~10MB binary size increase
- Untested on iOS (Arti's documentation explicitly notes this)
- Windows support is "best effort" in Arti's own assessment

**Current approach (external SOCKS5) is correct because:**
- Users who need Tor already run Tor Browser or standalone Tor daemon
- Tor's SOCKS5 interface (default 127.0.0.1:9050) is the standard integration point
- Same `tokio-socks` + WSS protocol path — proven and lightweight
- Works on all platforms where Tor itself runs

## Consequences

1. **Shadowsocks users no longer need ss-local** — Miasma connects directly to SS servers using native AEAD-2022
2. External ss-local SOCKS5 mode is preserved as fallback and for legacy ciphers
3. Tor users still need external Tor daemon
4. 1 new crate (`shadowsocks-crypto`) added — pure Rust, minimal incremental deps
5. If Arti reaches 1.0 with confirmed Windows + iOS support, the Tor decision should be revisited

## Alternatives Considered

| Alternative | Status |
|---|---|
| `shadowsocks` crate (full relay) | Rejected: requires OpenSSL |
| `shadowsocks-crypto` (cipher layer) | **ACCEPTED**: pure-Rust AEAD-2022, minimal deps |
| Custom SS protocol impl | Superseded by `shadowsocks-crypto` |
| `arti-client` (embedded Tor) | Rejected: pre-1.0, huge dependency tree, untested iOS |
| Tor via C FFI (`tor-sys`) | Rejected: even larger dependency, C build chain |
