# Bridge Connectivity 窶・Live Validation Results

**Date**: 2026-03-24 13:25:29
**Platform**: Windows 11 (10.0.22631.0)
**Script**: `scripts/validate-bridge-connectivity.ps1`

## Results

| Test | Transport | Latency (ms) | Fallback | Result | Notes |
|---|---|---|---|---|---|| Same-LAN loopback | unknown | 0 | False | FAIL | Node A has no listen address |
| Diagnostics fields | n/a | 0 | False | FAIL | Status query failed |
| Shadowsocks proxy | skipped | 0 | False | SKIP | ss-local not running on 127.0.0.1:1080 窶・SKIPPED |
| Tor proxy | skipped | 0 | False | SKIP | Tor not running on 127.0.0.1:9050 窶・SKIPPED |
| Partial failure field | n/a | 0 | False | FAIL | Field present in status JSON |

## Prerequisites

- **Shadowsocks**: Run `ss-local` on `127.0.0.1:1080` pointing at your SS server
- **Tor**: Run Tor (or Tor Browser) with SOCKS5 on `127.0.0.1:9050`
- Both are optional 窶・tests are skipped if the proxy is not running

## What This Proves

- **Same-LAN loopback**: Base transport path works (DirectLibp2p QUIC+TCP)
- **Diagnostics**: Runtime status fields are populated and queryable
- **Shadowsocks**: Real traffic routes through ss-local SOCKS5 proxy
- **Tor**: Real traffic routes through Tor SOCKS5 proxy
- **Partial failures**: Relay-only / no-peers detection is live

## What This Does Not Prove

- Cross-network (VPN, filtered) transport fallback
- Nation-state DPI bypass
- ObfuscatedQuic REALITY under real DPI
- Mobile platform transport paths
