# Censorship Resistance Posture

**Date**: 2026-03-24
**Version**: 0.3.1-beta.1+bridge

This document honestly states what Miasma's transport layer can and cannot do regarding censorship resistance.

---

## What Miasma Can Do Today

### Without user configuration
- **Survive UDP filtering**: Automatic fallback from QUIC to TCP/WSS transports
- **Survive port filtering**: WSS transport on port 443 (looks like normal HTTPS)
- **Resist basic DPI**: ObfuscatedQuic (REALITY-style) mimics real browser TLS fingerprints (Chrome 124, Firefox 125, Safari 17), with BLAKE3-MAC authentication and active-probe resistance
- **Survive NAT**: AutoNAT + DCUtR hole-punching + relay circuits + rendezvous with introduction points
- **Self-heal on network flap**: Exponential backoff, flap damping, stale address pruning, partial failure detection
- **Detect hostile environments**: Identify TLS inspection (Zscaler, Netskope, Palo Alto, etc.), captive portals, VPN presence, port/protocol filtering
- **Adapt transport strategy**: Automatically select the most appropriate transport based on detected network conditions

### With user configuration
- **Shadowsocks proxy traversal**: Route through user-provided Shadowsocks server (AEAD-2022 ciphers). Effective against many DPI implementations including partial GFW bypass
- **Tor anonymity**: Route through Tor network (external SOCKS5 or embedded Arti). Provides IP anonymity and censorship circumvention where Tor is accessible
- **Tor bridges**: Support for bridge lines (obfs4, etc.) for networks that block Tor directory authorities
- **Custom proxy**: SOCKS5 and HTTP CONNECT proxy support for enterprise environments

### Runtime control
All transports (including Shadowsocks and Tor) are **always compiled into the binary** — no feature flags or separate builds required. Each transport can be enabled or disabled at runtime via `config.toml`:

```toml
[transport.shadowsocks]
enabled = false  # Set to true and configure server/password/cipher to activate

[transport.tor]
enabled = false  # Set to true and configure mode/bridges to activate
```

Users in jurisdictions where specific transports are restricted can disable them via configuration. This is the legal compliance mechanism — the user controls which capabilities are active.

---

## What Miasma Cannot Do

### Technical limitations
- **ZTNA full TLS termination**: When a zero-trust product (Zscaler, Netskope) terminates ALL TLS connections and re-encrypts them, the interceptor sees plaintext. No transport can bypass this. ObfuscatedQuic REALITY works only if the ZTNA allows unknown QUIC traffic through (some do, some don't).
- **Captive portal auto-bypass**: Miasma detects captive portals but cannot automatically authenticate to arbitrary identity providers. The user must complete authentication in a browser.
- **Full GFW bypass guarantee**: China's Great Firewall uses active probing, traffic analysis, and machine learning. While Shadowsocks AEAD-2022 and ObfuscatedQuic REALITY resist many detection methods, the GFW has demonstrated ability to detect and block some Shadowsocks patterns. No single tool guarantees bypass.
- **Domain fronting**: Not implemented. Would require CDN cooperation (most CDNs have banned this practice).
- **Meek/Snowflake bridges**: Not implemented. Would complement Tor bridges for extreme censorship environments.

### Deployment limitations
- **No built-in relay infrastructure**: Miasma's relay and Tor capabilities require the user to have access to external infrastructure (Shadowsocks server, Tor network, relay peers)
- **No built-in bridge distribution**: Unlike Tor Browser, Miasma does not bundle bridge addresses or use BridgeDB
- **Binary fingerprinting**: The Miasma binary itself could be identified by its file hash. No binary obfuscation is implemented

---

## Threat Model

| Adversary | Can Miasma resist? | How |
|---|---|---|
| Coffee shop WiFi filtering | Yes | Automatic fallback to WSS/443 |
| Corporate proxy with port filtering | Yes | WSS on 443, proxy support (SOCKS5/HTTP CONNECT) |
| Corporate ZTNA with TLS inspection | Partial | ObfuscatedQuic if QUIC allowed; detected and reported |
| ISP-level DPI (non-state) | Yes | ObfuscatedQuic REALITY, Shadowsocks |
| Nation-state DPI (GFW-class) | Partial | Shadowsocks AEAD-2022 + Tor bridges. Not guaranteed |
| Nation-state full traffic control | No | No transport technology can guarantee bypass |
| Network with blocked UDP | Yes | TCP/WSS fallback automatic |
| Tor-blocking network | Partial | Tor bridges (obfs4). Some networks block all known bridges |

---

## Validation Status

All claims in this document are backed by the test suite (675 tests) and the validation matrix in `docs/validation/bridge-connectivity-validation-report.md`.

Claims marked "Partial" or "Not guaranteed" reflect honest assessment of capabilities that have not been validated against the specific adversary in production. We do not claim resistance we have not tested.

---

## Future Work

1. **Pluggable transport framework**: Allow third-party transports to be loaded at runtime
2. **Meek/Snowflake bridges**: For extreme censorship where even Tor bridges are blocked
3. **Bridge distribution**: Built-in mechanism to discover and distribute relay/bridge addresses
4. **Traffic padding**: Constant-rate cover traffic to resist traffic analysis
5. **Binary obfuscation**: Make the Miasma binary harder to fingerprint
