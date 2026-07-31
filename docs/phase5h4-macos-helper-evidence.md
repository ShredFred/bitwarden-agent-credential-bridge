# Phase 5h.4: macOS helper peer evidence

This phase adds a pure, offline compiler for facts that a future native macOS
collector would obtain from a local XPC connection and trusted OS APIs. It does
not open a Mach service, inspect a process, invoke the Security framework, or
launch a helper.

## Authorization boundary

The evaluator returns only the five booleans consumed by the Phase 5h.1 helper
protocol:

- `local_transport`
- `identity_verified`
- `different_principal`
- `caller_write_denied`
- `helper_write_allowed`

It accepts an exact, accessor-free, non-proxy schema and snapshots data-property
values before evaluation. Effective UIDs enter only as
lowercase SHA-256 digests and never appear in the result. The collector must
hash the canonical UTF-8 preimage `euid:<decimal>`, where `<decimal>` is the
unsigned base-10 EUID with no leading zeroes (except `0` itself). A different writer is
proved only when both audit-token/effective-UID identities are verified, the
audit-token EUIDs match their independently verified EUIDs, the helper satisfies
its pinned code requirement, and the two effective-UID
digests differ.

## Required native evidence

A future collector must bind a fixed Mach service, obtain the peer audit token
from the accepted XPC connection, and bind peer and helper PID plus pidversion
to prevent PID-reuse substitution. It must independently verify the caller and
helper audit tokens, effective UIDs, and the helper's designated code
requirement.

The write claims require symlink-safe effective-access checks for every target
already bound by the confirmed manifest. Partial checks make both claims false.

## Signals that do not create a principal

App Sandbox, Hardened Runtime, valid signing, different signing requirements,
different audit sessions, and sandbox-denied writes may reduce risk, but they do
not create a separate OS writer. Equal effective-UID digests always produce
`different_principal: false`.

## Still not implemented

There is no native XPC listener or collector, launchd helper, Authorization
Services workflow, inherited launcher handle transfer, permission mutation,
manifest execution outside the disposable test root, or Bitwarden connection.
Those remain behind a later explicit live-test gate.
