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

### Cell length

A first-hop request is built only within fixed bounds: a relay or target peer id
of at most 64 bytes, a return address of at most 256 bytes, a request body of at
most `ONION_MAX_E2E_REQUEST_LEN` (8188 bytes), and for the lower-level
`build` entry point a body of at most `ONION_MAX_BODY_LEN`. Every request inside
the bounds has the same length on the wire, whatever the peer id length (the
padding of the outer layer is adjusted for it), and cover cells have that length
too when the relay peer id is the usual 38-byte Ed25519 id. A request outside the
bounds is refused with an error; it is never sent as a longer cell. Peers running
older versions pad the outer layer to a smaller size, so their real cells are
shorter than current ones; cover from current versions matches current real
cells. Older builds still decode current cells, because the padding is removed
by its length prefix.

### Response timing of cover cells

A relay forwards a real cell to the next hop and answers when that hop answers.
A cover cell has nothing to forward. With cover traffic enabled, the relay keeps
the delays it actually observed between forwarding a cell and receiving the
answer (the last 64, nothing else is stored) and holds each cover
acknowledgement for a delay drawn from that set, at most 5 seconds, with at most
64 acknowledgements held at once. With cover traffic disabled, or before any
forward delay has been observed, a cover cell is acknowledged immediately.

Not claimed:

- The delay is drawn from this relay's own observations, so it follows that
  relay's recent forwarding delays and nothing else.
- The size of the answer to a real cell is not shown to match the 8 KiB random
  acknowledgement of a cover cell.
- Timing seen anywhere other than on the link between the sender and this relay
  is not shaped.
- Relays that run an older version, or that have cover traffic disabled, still
  acknowledge cover cells immediately.

## Why `adaptive` is not supported

An adaptive policy needs a profile that can be measured and reproduced: cell
sizes plus the parameters of a timing distribution, stored in configuration and
compared with a reference population. This release has no such reference, and a
randomized distribution specific to this project would itself be a distinguishing
feature. The policy stays unsupported until a profile can be specified that way.
