# Phase 12n handoff: Linux-host disposable different-UID denial

Phases 12a–12f are pure and complete on Windows-dev. **Native helper I/O and the
disposable root lifecycle collector require a Linux host** with a real systemd
system instance.

## Preconditions

- Phase 5h.3 peer-evidence evaluator + Phase 5h.17 boundary plan
- Phase 12a–12f pure layout/gate/transcript/trust/install/authorize stack

## Required on Linux

1. Native denial-only AF_UNIX helper scaffold (Type=exec, static UID, initial
   user namespace, always deny, vault/network/manifest absent).
2. Same-UID console denial proving equal host-UID digests fail closed.
3. Operator-approved disposable root collector: create account/units/binary →
   start → different-UID denial → cleanup/absence with retained-handle rules.
4. Value-free stdout only; brand live report in-process.
5. Feed `evaluateLinuxSystemdInstallGate`; expect
   `install_gate_eligible=true` and `authorization_ready=false`.

## Explicitly forbidden

- systemd user manager / OpenRC / ambiguous profiles
- `DynamicUser=` as principal evidence
- Abstract sockets
- Personal/company Bitwarden or vault client in the helper
- Hardcoded `authorization_ready=true`

## Resume after 12n

Persistent install (12o) then Linux 9a–10b analogs (12p–12u).
