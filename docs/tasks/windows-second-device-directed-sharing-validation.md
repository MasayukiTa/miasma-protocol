Next task: prove that directed sharing really works between Windows and a second device before expanding scope any further.

Current state:
- The directed-sharing protocol and state machine are heavily tested in Rust.
- Windows has the strongest real client surface today.
- Android has build, daemon, and UI foundations, but real-device proof is still pending.
- iOS is retrieval-first and remains a secondary validation target.
- The highest-value next step is not new feature work. It is proving the full directed-sharing flow on a real network between Windows and another device.

Important execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed to finish it properly.
- It is also acceptable to use multiple sub-agents aggressively if that improves speed or thoroughness.
- Do not move on to broader platform claims until this validation is actually observed.
- Prefer real device results over simulated confidence.

Goal:
Verify that Windows can connect to a second device, complete the full challenge/password directed-sharing flow, revoke/delete correctly, and survive larger payloads without crashing or corrupting state.

Track A: Connectivity proof first
1. Establish real connectivity between Windows and the second device.
- same-network peer discovery if possible
- manual bootstrap fallback if needed
- both sides show connected peers or otherwise prove network path is alive

2. Record the exact environment.
- Windows build/version
- second device type (Windows or Android)
- OS version
- same-network / VPN / other path
- whether mDNS or manual bootstrap was required

3. Do not proceed to sharing tests until basic connectivity is proven.

Track B: Directed-sharing flow validation
1. Windows -> second device
- sender enters recipient contact/public key
- sender enters password
- sender enters retention period
- recipient receives the envelope
- recipient sees the challenge code
- sender enters the challenge code correctly
- recipient enters the password correctly
- retrieval succeeds
- content matches byte-for-byte

2. Second device -> Windows
- repeat the same flow in reverse if the second device supports sending
- if the second device is iOS retrieval-first, record that asymmetry honestly

3. Validate failure cases.
- wrong challenge code
- wrong password
- three failures fail closed
- no action buttons remain after terminal states

Track C: Deletion and invalidation proof
1. Sender-side revoke/delete
- sender revokes before retrieval
- recipient can no longer retrieve
- UI reflects revoked state honestly

2. Recipient-side delete
- recipient deletes an envelope
- envelope disappears or becomes non-actionable as designed
- it cannot be resurrected through refresh/restart

3. Dummy/test file cleanup
- use disposable test files/messages
- verify that after revoke/delete/terminal failure the test artifact is no longer retrievable
- distinguish clearly between cryptographic invalidation and physical network garbage collection

Track D: Large-file and robustness validation
1. Run size tiers, not just tiny strings.
- tiny: a few KB
- medium: a few MB
- large: at least one meaningfully large file (for example 100 MB class) if the device/storage/network allows it

2. Observe stability.
- app does not crash
- daemon does not wedge
- progress or wait states remain understandable
- failure leaves the system recoverable

3. If large-file limits are hit, document them honestly.
- memory pressure
- timeout
- battery/thermal issues
- retrieval failure modes

Track E: Lifecycle and recovery
1. Validate restart behavior.
- restart Windows app/daemon
- restart second device app/daemon
- verify stale state does not break inbox/outbox

2. Validate interrupted flow behavior.
- revoke during pending/challenge/confirmed where possible
- network drop during send or retrieve
- app background/foreground around retrieval on mobile if applicable

Track F: Evidence and reporting
1. Produce a concrete validation record.
- what exact pair of devices was used
- what exact files were sent
- what exact steps passed
- what failed
- screenshots/logs if useful

2. Give a clear recommendation after the run.
- ready to advance to Android beta hardening
- still blocked on Windows↔device reliability
- specific bugfixes required before broader testing

Completion bar:
Do not call this complete unless all of the following are true:
- Windows and a second device have actually connected over a real network path
- at least one full directed-sharing exchange has succeeded end to end
- revoke/delete behavior has been exercised successfully
- at least one larger file has been tested or a hard blocker has been documented
- the result is written down honestly with exact environment details

Expected final output:
1. Which devices and network path were used
2. Whether connectivity was proven
3. Whether the challenge/password flow worked end to end
4. Whether revoke/delete worked
5. Whether larger files remained stable
6. What bugfixes or next milestone should follow from observed reality
