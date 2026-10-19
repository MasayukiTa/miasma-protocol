# Traffic shaping policies

`traffic_shape_policy` selects an optional shaping layer above the transports.
Protocol-required padding is always on, whatever the policy.

| Policy | State in this release | Effect |
|---|---|---|
| `off` (default) | supported | No optional shaping. |
| `fixed_padding` | supported | Same as `off`; first-hop cells are already fixed length. |
| `bucketed` | supported | Same as `off` for onion cells. |
| `cover_basic` | supported | Turns cover traffic on at the configured rate and daily budget. |
| `constant_rate` | not supported | The daemon refuses to start and says so. |
| `adaptive` | not supported | The daemon refuses to start and says so. |

Selecting `adaptive` or `constant_rate` is reported at startup as
`traffic shaping policy '<name>' is not supported in this release`, followed by
the list of supported policies. The daemon does not fall back to another policy.

## What is measured and claimed

The wire-shape tests (`cargo test --package miasma-core --lib cover`) build
first-hop cells with the production code and record what the transport envelope
shows:

- Every first-hop request frame, real or cover, has the same length
  (`FIRST_HOP_FRAME_BYTES`) and the same framing (4-byte length prefix, same
  enum tag). The cover marker is visible only after the cell authenticates.
- Cover cells follow a configured mean rate with bounded uniform jitter
  (`pattern_jitter_pct`). Nothing more is claimed about timing; in particular it
  is not claimed to resemble any other protocol.
- Emission stops at `daily_budget_bytes` per rolling 24 hours, and stopping the
  engine ends its task.

A relay whose peer id is not an Ed25519 id (38 bytes serialized) would produce a
first-hop cell a few bytes longer or shorter than a cover cell. Peers running older
versions pad the outer layer to a smaller size, so their real cells are shorter
than current ones; cover from current versions matches current real cells.

## Why `adaptive` is not supported

An adaptive policy needs a profile that can be measured and reproduced: cell
sizes plus the parameters of a timing distribution, stored in configuration and
compared with a reference population. This release has no such reference, and a
randomized distribution specific to this project would itself be a distinguishing
feature. The policy stays unsupported until a profile can be specified that way.
