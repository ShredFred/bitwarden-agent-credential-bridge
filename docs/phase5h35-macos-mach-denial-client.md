# Phase 5h.35 — production Mach denial client

This phase implements the caller side of the denial-only protocol already
compiled into the native LaunchDaemon helper. It still does not install or start
that helper.

## Process and message binding

Immediately before denial, the launchctl adapter reprints the owned running job,
revalidates retained artifacts, uniquely parses its PID, and passes that PID to
the Mach client. The client resolves `_bwagentbridge` and requires its fixed UID
499, `/var/empty`, and `/usr/bin/false`; the current caller must have a different
EUID.

Before looking up the already activated fixed service, the client records the
PID's public `proc_bsdinfo` start timestamp, EUID, and `proc_pidpath`. Production
requires the exact retained helper path. It then sends one fixed non-complex
request with a cryptographically random 32-byte nonce and a send-once reply
right.

The reply is accepted only when its size, non-complex header, ID, ports, version,
kind, explicit denial value, and nonce are exact. `MACH_RCV_TRAILER_AUDIT` must
name the expected PID and UID and contain a positive pidversion. A second process
snapshot after the reply must preserve the same start timestamp and executable
path. This public-API combination prevents PID reuse during the exchange; this
SDK does not expose another process's pidversion before receipt, so the code does
not pretend it can compare an unavailable value.

Malformed successful receives are destroyed with `mach_msg_destroy`, and all
send/receive operations are bounded to two seconds before port rights are
released.

## Private test

With `BW_MACH_PROBE_TESTING`, the self-test registers a randomized private
bootstrap service, forks a client, and exercises the exact request/reply parser.
It then repeats the exchange with a deliberately wrong expected PID and proves
rejection. The fixed production service name is never queried.

```bash
npm run test:phase5h35
```

Cursor Composer review led to the before/after process snapshot, fixed UID,
fresh denial-time PID read, trailer bounds check, invalid-message destruction,
and stricter reply header validation. No Bitwarden, Keychain, credential,
network, system account, LaunchDaemon, or `/Library` state is accessed or changed.
