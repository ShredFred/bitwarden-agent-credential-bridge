# Phase 5h.18: macOS launchd system-helper boundary plan

This phase adds a pure, value-free plan for a future macOS helper in the launchd
system domain. It closes the architectural gap between the Phase 5h.4 evidence
compiler and any later native XPC work. It performs no launchd, XPC, Security
framework, signing, account, filesystem, Keychain, vault, or network operation.

## Fixed distinct-writer boundary

The plan fixes one system-domain LaunchDaemon label and Mach service, one static
hidden non-login helper account, and a stable effective UID different from the
caller. A LaunchAgent, GUI-domain helper, same-EUID process, App Sandbox,
Hardened Runtime, or a different signing identity alone cannot satisfy the
distinct-principal requirement.

The reviewed helper is bound by exact binary SHA-256, byte length, the SHA-256
of its reviewed designated code requirement, and the exact LaunchDaemon plist
SHA-256. The future installed binary, code requirement, daemon definition, parent chains, loaded daemon
identity, and target access must all be reverified by trusted native collectors.

## XPC caller binding

Phase 5h.4 now requires an explicit proof that the accepted XPC peer audit token
matches the independently verified authorizing caller audit token. Verifying an
arbitrary peer and an unrelated caller can no longer produce transport or
identity success. PID and pidversion bindings remain mandatory for both peer and
helper.

## Production target constraint

The production helper boundary must not write into an ordinary user's home or
the current per-user Application Support layout. The disposable macOS executor
remains useful contract evidence, but it is not the production writer layout.
Future target roots must deny caller ownership, creation, deletion, and write
access while allowing only the fixed helper identity's required writes.

## Deliberately not executable

The plan is in-process branded and cannot be serialized into an authorization
capability. It always reports:

- `mutation_authorized: false`
- `live_test_executed: false`
- `install_gate_eligible: false`

A later phase must add read-only native preflight before any lifecycle or XPC
denial test is considered. Real installation, elevation, account creation,
LaunchDaemon loading, Keychain access, Bitwarden pairing, and credential use
remain outside this phase.

The pure evidence evaluator still consumes trusted booleans. The next read-only
native preflight must be the component that compares the collected designated
code requirement to `binary.designated_requirement_sha256` before it may report
`helper_code_requirement_satisfied: true`; an unbound collector assertion is not
authorization evidence.

```bash
npm run test:phase5h18
```
