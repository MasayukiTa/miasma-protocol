# result_A (offline/A)

State: reflected in PR #261 (origin/offline/A).

## Achieved (OFFLINE DELIVERY, Part A)
Sender-side custody path implemented:
1. When the contact is offline and PQ is not yet established, the send is not blocked; the outbox records the state (waiting for the contact; not deposited). Once the PQ session exists, a sealed copy is deposited with a trusted holder. Nothing is sent in a weaker session; a holder only sees ciphertext.
2. DiskCustody persists custody across restarts, sealed under Label::ChatCustody. Write failure falls back to memory; restore re-applies current limits and drops expired items. config.rs adds 3 ceiling keys (defaults 2MiB/256/14d, hard caps 4MiB/1024/30d).
3. Deposit result is observable: custody_status records "Deposited with N holder(s); awaiting delivery" vs "Not deposited with any holder", and never reads as delivered/read.

## NOT implemented (Gap1) -- requirement #1 partially met
The direct-deposit-to-the-contact path is deferred; only deposit-with-a-trusted-holder is implemented. Reason: sealing under the contact receive key plus replay protection is not yet designed; depositing in plaintext or unverified risks disclosure/double-apply, so it cannot be done safely. The sub-path "sender deposits directly to an offline contact" is out of scope for this PR.

## Tests (added; CI manifest consistent)
- holder.rs disk_tests x5 (restart/wrong-key/tightened-ceiling/expiry/revoke); limits_come_from_config_and_are_clamped x1.
- service.rs custody_status_tests x3; sim_tests x1 (no holder is never a delivery).
- tests/chat_custody_net_test.rs x2 (delivery via holder to offline recipient; no-holder reported not delivered).
- ci.yml adds --test chat_custody_net_test; check_ci_test_manifest.py consistent (15 tests).

## Open (real tests NOT run) -- build blocked on this host (re-verified 2026-11-07)
No real cargo pass/fail counts could be produced on this host. Both available toolchains were tried and both fail before any test binary links:
- MSVC (default, x86_64-pc-windows-msvc): no MSVC C/C++ toolchain present. `where cl` returns nothing, so C-dependent build scripts (aws-lc-sys etc.) cannot link.
- GNU (x86_64-pc-windows-gnu): disk was no longer the blocker (C: had ~5.6 GiB free this run). With MinGW gcc 16.2.0 on PATH and a dedicated CARGO_TARGET_DIR, `cargo +stable-x86_64-pc-windows-gnu test -p miasma-core --locked --lib chat::mailbox::holder` compiled the full dependency graph but failed to link `aws-lc-rs`: "undefined reference to `__security_cookie`" (collect2/ld, exit 1); cargo exit 101. This is a known GNU-ABI vs aws-lc incompatibility, not a disk or code problem; the crate graph compiles up to the final link.
Net: the cryptography dependency (aws-lc-rs) does not link under either toolchain available here, so `-p miasma-core` test binaries cannot be built on this machine. The Part A changes themselves were not the cause (they compiled). Documented in PR #261 Honest limits. Do not merge until the suite runs on a host with a working MSVC toolchain (or an aws-lc/GNU-compatible setup).
- Fixed the Label::ChatCustody comment to match the implementation (stealth governs logs, not chat state) in this follow-up commit.
