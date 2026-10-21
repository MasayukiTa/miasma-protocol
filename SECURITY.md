# Security Policy

## Supported Versions

Miasma is in beta. Only the latest beta release (the current version line is
v0.3.2-beta.x) receives security fixes. Older betas are not patched; update to
the latest release.

## Known security limits (beta)

Miasma is beta software and has not been externally audited. Read these limits
before relying on it:

- The protocol is beta and externally unaudited. Do not use it for material
  whose exposure would be serious.
- MID + password protect the confidentiality of file content. A bare MID does
  not bind whether a file is password-protected, nor which publication of it a
  record refers to (no publication generation); the share ID
  (`miasma-share:...`) binds the protection state, the MID and the publisher.
- DHT records are authenticated to the publisher only when the receiver uses
  the share ID: it accepts just a record signed by the publisher key inside
  the ID. A receiver that uses a bare MID is not protected: anyone who knows a
  MID can publish a competing record for it (the client then says "publisher
  not authenticated"). The final whole-file MID check stops an attacker from
  substituting different content, but availability can still be attacked (a
  record held by peers can be replaced by another signer, and a bare-MID
  receiver can be pointed at unavailable or junk locations). The publisher key
  is the node identity key and cannot be rotated or revoked yet.
- The iroh direct transport (receive by share ID and password alone, no address
  or open port) uses n0's public discovery service and relays by default
  (`transport.iroh_mode = n0`). While the daemon runs, n0 learns this node's
  endpoint ID (which is its publisher key, so also what its share IDs contain),
  its home relay and its IP addresses, and anyone who holds a share ID can look
  the node up the same way; n0's relay sees connection metadata and ciphertext
  only. Nothing else is sent to n0. The relay and discovery HTTPS connections
  are verified against the operating system certificate store plus `--ca-cert`,
  so a TLS-inspecting proxy whose CA is installed in the OS can see the
  connection's metadata (host names, the WebSocket upgrade, traffic pattern)
  but not the encrypted content. Turn it off with
  `miasma config --key transport.iroh_mode --value off` (or `miasma daemon
  --no-iroh`), or use your own relay with `transport.iroh_mode = custom`. A
  public relay is for reaching the sender, not for bulk transfer (measured about
  1 MiB/s); large files need a direct path or a self-hosted relay.
- Hosted-share storage (keeping shares for other peers) is **on by default**: the
  hosted quota (`storage.hosted_quota_mb`) defaults to 1024 MiB, so a default node
  accepts shares pushed by authenticated peers (so it uses disk for them and
  receives inbound connections). Set it to 0
  (`miasma config --key storage.hosted_quota_mb --value 0`, takes effect at the
  next daemon start) to refuse every pushed share.
- The obfuscated QUIC and REALITY transports do not authenticate the server and
  do not resist replay. Do not rely on them for resistance to active probing or
  for confidentiality against an active interceptor. Content encryption still
  applies on top of them.
- Local control: the daemon's IPC and HTTP bridge require a random per-start
  token stored in `daemon.token` in the data directory. It is created owner-only
  from the first byte (Unix: mode 0600; Windows: a security descriptor with a
  single entry for the current user) and then verified; if that fails the daemon
  does not start. Any
  process running as the same user can read the token and control the daemon;
  the token protects against other users and against unauthenticated loopback
  clients, not against malware in your own account. The bridge's `/api/ping`
  stays unauthenticated. Wipe needs a second, confirming request.

## Reporting a Vulnerability

Please report vulnerabilities privately. Do not open a public issue or pull
request for a security problem.

Use GitHub's private vulnerability reporting:
<https://github.com/MasayukiTa/miasma-protocol/security/advisories/new>

Please include:

- the affected version (for example the output of `miasma --version`) and
  platform;
- a description of the problem and its impact;
- steps or a minimal input that reproduces it;
- whether you believe it is already being exploited, and any disclosure
  deadline you are working to.

What to expect: we will acknowledge and assess each report as soon as we can,
and tell you whether it is accepted or declined. Accepted issues are fixed in
the latest beta and, once a fix is released, credited in the release notes if
you wish. Issues that match a limit listed under "Known security limits (beta)"
above are already documented, but are still welcome as reports if you can show
a worse impact than described.
