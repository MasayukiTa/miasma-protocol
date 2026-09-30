# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

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
- Hosted-share storage (keeping shares for other peers) is opt-in; the default
  quota is 0.
- The obfuscated QUIC and REALITY transports do not authenticate the server and
  do not resist replay. Do not rely on them for resistance to active probing or
  for confidentiality against an active interceptor. Content encryption still
  applies on top of them.
- Local control: the daemon's IPC and HTTP bridge require a random per-start
  token stored in `daemon.token` in the data directory. It is created owner-only
  on Unix (mode 0600). On Windows the daemon asks `icacls` to restrict the file
  to the current user and logs a warning, then continues, if that fails. Any
  process running as the same user can read the token and control the daemon;
  the token protects against other users and against unauthenticated loopback
  clients, not against malware in your own account. The bridge's `/api/ping`
  stays unauthenticated. Wipe needs a second, confirming request.

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.
