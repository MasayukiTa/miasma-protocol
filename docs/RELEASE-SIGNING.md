# Release signing

Every release carries `SHA256SUMS.txt` and a detached Ed25519 signature
`SHA256SUMS.txt.sig` over the exact bytes of that file. The update client
(`crates/miasma-core/src/update/verify.rs`) checks the archive against the
sums file, then checks the signature against the public keys compiled into the
build (`UPDATE_PUBKEYS`). The tool in `tools/release-sign` creates the keys,
signs, and verifies. It is a separate Cargo project: it is not part of the
main workspace and is not built into any shipped app. It has no network code.

Two keys are used: a primary key and a spare. Both public keys are pinned.
Private keys are never stored in CI, in a repository, or in chat.

## Key ceremony (once)

Use a computer that is offline for the whole ceremony.

1. Build the tool: `cargo build --release --manifest-path tools/release-sign/Cargo.toml --locked`.
2. Insert an encrypted USB drive (not a synchronised folder, not inside a git
   work tree; the tool refuses both).
3. Run `release-sign keygen --out-dir <usb>/primary`. Type a passphrase of at
   least 12 characters twice (it is read from the terminal, never from
   arguments or the environment). The tool writes `miasma-release-<id>.key`
   and prints the public key as hex and as a Rust array.
4. Repeat with `--out-dir <other usb>/spare` and a different passphrase.
5. Check each file: `release-sign pubkey --key <file> --check`.
6. Store the spare key and its passphrase in a different place from the primary
   (separate drive, separate location). Keep a paper copy of each passphrase
   apart from the drives. A lost key file cannot be recovered.
7. Record the two public keys. Public keys are not secret.

Pinning (a normal code change, reviewed like any other): add both arrays to
`UPDATE_PUBKEYS` in `verify.rs`. Do this only after at least one release has
been published with a `.sig` file, because a build that pins keys refuses a
release without a signature (older builds, which pin nothing, ignore it).

## Release day

1. Build the release artifacts.
2. Compute `SHA256SUMS.txt`: one line per artifact, `<sha256 hex>  <file name>`.
   Do not edit the file after this point; any change, including line endings,
   invalidates the signature.
3. On the offline machine, sign:
   `release-sign sign --key <primary key file> SHA256SUMS.txt`
   (writes `SHA256SUMS.txt.sig`, 128 hex characters; `--format base64` is also
   accepted by the client). Enter the passphrase when asked.
4. Verify with the public keys, from the files that will be uploaded:
   `release-sign verify --pubkey <primary hex> --pubkey <spare hex> SHA256SUMS.txt SHA256SUMS.txt.sig`
5. Upload the artifacts, `SHA256SUMS.txt` and `SHA256SUMS.txt.sig`.
6. Download the published files again and repeat step 4 on the downloaded
   copies.
7. On a machine with a fresh install of the previous release, run the update
   and confirm it is accepted. Also confirm that a release without the `.sig`
   file is refused by a build that pins keys.

CI also publishes a GitHub build-provenance attestation for the macOS
artifacts built on `main` (`gh attestation verify <file> --repo <owner>/<repo>`).
It shows where an artifact was built; it does not replace the signature.

## Rotation or loss of a key

- Primary key lost or exposed: sign the next release with the spare key. Ship
  a build that pins the spare key and a new key (old compromised key removed),
  signed by the spare. Then generate a new spare.
- Planned rotation: ship a build that trusts old and new keys; once users have
  moved to it, ship a build that trusts only the new key. The client accepts a
  signature by any pinned key.
- If both keys are lost, clients cannot be updated automatically; users must
  install a new build by hand.

## What an update client does

| Situation | Result |
| --- | --- |
| No key pinned in the build | Signature is not checked; the SHA-256 check still applies. Automatic install is not allowed. |
| Key pinned, `.sig` missing | Refused ("the release is not signed"). |
| Key pinned, `.sig` not 64 bytes in raw, hex or base64 form | Refused ("the signature file is malformed"). |
| Key pinned, signature valid for none of the pinned keys, or `SHA256SUMS.txt` changed | Refused ("the signature is not valid for any trusted key"). |
| Key pinned, valid signature, archive hash differs from its line | Refused (hash mismatch). |
| Key pinned, valid signature, hash matches | Accepted. |

`SHA256SUMS.txt` is always required, signed or not.
