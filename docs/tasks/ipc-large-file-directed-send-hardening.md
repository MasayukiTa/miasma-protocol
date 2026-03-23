Next task: remove the current IPC size bottleneck so directed sharing can handle meaningfully large files without transport failure.

Current state:
- Directed sharing now works end to end between Windows nodes.
- Challenge, password, revoke, delete, and restart survival are proven.
- The main blocking weakness is the CLI/daemon IPC path for `DirectedSend`.
- Raw file bytes currently expand too much over JSON framing, causing practical failure around the 4 MiB range.

Important execution guidance:
- It is acceptable if this milestone takes a long time.
- Spend as much time as needed to finish it properly.
- It is also acceptable to use multiple sub-agents aggressively if that improves speed or thoroughness.
- Do not ship a cosmetic workaround. Fix the bottleneck honestly.

Goal:
Raise the practical directed-send size limit well beyond the current ~4 MiB bottleneck and validate the new limit with real file tiers.

Track A: Choose the transport fix
1. Evaluate the credible options:
- base64 payload in JSON
- file-path based IPC where the daemon reads the file directly
- streaming or chunked IPC
- another bounded approach if it is clearly better

2. Choose one primary implementation for this milestone.
- explain why it is the right near-term choice
- explain why the rejected options are deferred

3. Keep the interface honest.
- no silent truncation
- no undefined size ceiling
- clear errors if limits still exist

Track B: Implement the fix
1. Update CLI <-> daemon directed-send transport.
2. Preserve security boundaries.
- no accidental temp-file leaks
- no broader file access than intended
- filenames and paths handled safely

3. Preserve compatibility where practical.
- existing small-file flows should continue to work
- desktop and web paths should not regress

Track C: Validate by size tier
1. Re-run directed-send validation with file tiers such as:
- 4 KB
- 1 MB
- 5 MB
- 10 MB
- 25 MB
- 50 MB if practical

2. Record:
- whether send succeeds
- whether retrieve succeeds
- whether byte-for-byte match holds
- whether daemon or CLI memory usage becomes problematic

3. If a hard upper limit still exists, document it precisely and honestly.

Track D: Failure and recovery behavior
1. Validate oversized or interrupted sends.
- clean error instead of crash
- daemon remains operational
- partial sends do not corrupt inbox/outbox state

2. Validate revoke/delete and restart behavior still work after large-file sends.

Track E: Docs and release honesty
1. Update validation reports and any docs that currently imply large files work more broadly than proven.
2. State the new practical limit clearly if one still exists.

Completion bar:
Do not call this complete unless all of the following are true:
- the root cause of the current ~4 MiB failure is removed or materially improved
- at least one file well above 5 MiB succeeds end to end
- byte-for-byte validation still holds
- error handling remains clean under failure
- docs state the practical file-size reality honestly

Expected final output:
1. Which IPC fix was chosen and why
2. What changed in the transport path
3. Which file sizes succeeded
4. What the new practical limit is
5. What remains as future work
