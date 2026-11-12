## What

Add the call controller ports layer above the pure call state machine:

- `CallPorts` trait injecting the host clock (`now_ms`) and the contact check (`is_contact_allowed`).
- `CallNotice` mirroring `state::Notice` plus a `SendFailed` variant; fixed-string `Debug`.
- `NoticeQueue`: a bounded queue (capacity 64) that drops the oldest notice when full, raises a `gap` flag, and reports the gap once on `drain`.
- `CallController<P: CallPorts>` holding the ports, a `CallMachine`, the active peer, the notice queue and the incoming-call approval token state (`pending_token` / `next_token`), with `new`, `status`, `take_notices`, `begin_incoming` and `approve`.
- `CallStatus` snapshot where `signalling_connected` is true only in `Connected` (signalling connected, not media flowing).

The approval token is unique and strictly increasing so a stale user interface cannot approve a replacement call. Types holding a call id or peer id do not derive `Debug`; they print a fixed string instead.

## Tests

In-file unit tests with a fake `CallPorts`:

- queue overflow drops the oldest item and sets the gap flag;
- drain reports the gap once;
- tokens are unique and increasing;
- approve accepts only the current token;
- status reports `signalling_connected` only in the `Connected` state.

## Not done

Sending, encoding and message handling are out of scope for this change and are not implemented here.
