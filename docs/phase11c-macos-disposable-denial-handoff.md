# Phase 11c handoff: Mac-host disposable distinct-EUID denial

Phase 11a/11b are pure and runnable on Windows. **Phase 11c requires a Mac host**
with operator approval for a disposable elevated LaunchDaemon denial matrix.

## Preconditions (already on `develop`/`main`)

- Branded Phase 5h.18 boundary + 5h.22 gate + 5h.23 transcript
- Phase 11a install-gate + collector-trust compilers
- Phase 11b layout plan
- Existing provisioner/runner packages through Phase 5h.43

## Required on Mac

1. Operator-approved install of the fixed root-owned lifecycle provisioner.
2. sudo → provisioner → runner → distinct-EUID LaunchDaemon denial → cleanup.
3. Value-free stdout only: fixed step ids/statuses + provenance booleans.
4. Brand the live report in-process (never load forged JSON as a capability).
5. Feed `evaluateMacosLaunchdInstallGate`; expect
   `install_gate_eligible=true` and `authorization_ready=false`.
6. Prove account/plist/binary/label/Mach absence after cleanup.

## Explicitly forbidden

- Personal/company Bitwarden
- Keychain/vault client in the helper
- Claiming `authorization_ready=true` from this disposable matrix alone
- Adopting pre-existing accounts/jobs by fixed name

## Resume point after 11c

Continue with Phase 11d persistent install/uninstall, then macOS 9a–10b analogs
(11e–11l) using the branded install-gate + layout evidence.
