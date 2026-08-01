# Phase 5h.24: native macOS launchd denial helper

Phase 5h.24 adds the first production-shaped macOS helper executable. It is
compiled and exercised only in private temporary build roots; it is not installed
or loaded.

## Native service contract

The C executable has exactly two fixed modes:

- With no arguments, it verifies that its effective UID is the fixed hidden
  `_bwagentbridge` account, that the account is non-root, has `/var/empty` as its
  home and an allowed non-login shell, and only then calls `bootstrap_check_in`
  for the fixed production Mach service.
- With the internal `--self-test` argument, it emits one exact compile-time JSON
  record. The runner selects this mode internally; it is not public input to an
  installation API.

Service mode accepts one fixed-size, non-complex request carrying protocol
version, denial-probe kind, and a generated non-secret nonce. It requires a
non-zero nonce, a send-once reply right, plus a kernel
`MACH_RCV_TRAILER_AUDIT` with valid PID and
PID generation. The only reply repeats the protocol/kind/nonce and sets the
fixed denial bit. Receive and send operations have bounded timeouts. Malformed
messages and failed sends destroy received rights and fail closed.

There is no authorization-success message, descriptor passing, anonymous or
ephemeral registration, service lookup, manifest parser/executor, target path,
file writer, Keychain/vault client, network stack, subprocess launch, or
credential surface. Service mode writes neither stdout nor stderr.

## Private deterministic build inspection

`inspectMacosNativeLaunchdHelperScaffold()` accepts no arguments. It:

1. Opens the repo-owned C source read-only with no-follow semantics and reads one
   stable descriptor snapshot.
2. Creates two mode-0700 directories under the canonical macOS temporary root.
3. Publishes identical mode-0400 source snapshots with exclusive no-follow
   creation and fsync.
4. Compiles each snapshot using fixed `/usr/bin/clang` arguments and no external
   package dependency.
5. Requires safe compiler outputs and identical SHA-256 digests on that host and
   toolchain.
6. Parses only the exact non-authorizing self-test record.
7. Runs no-argument mode outside the fixed account/launchd context and requires
   silent fail-closed rejection.
8. Unlinks both binaries and snapshots and removes both private roots exactly.

The reproducibility claim is deliberately same-host only. The build is not
signed, notarized, installed, or treated as the reviewed production artifact.

## Remaining trust boundary

Compiled code is not live lifecycle evidence. The self-test keeps launchd
lifecycle, distinct EUID, code requirement, installation eligibility, collector
trust, live test, and authorization readiness false. A later native
collector/driver must bind the reviewed binary and plist to Phase 5h.22, emit a
Phase 5h.23 transcript, and obtain explicit current operator approval before any
account creation, `/Library` write, bootstrap, Mach production probe, bootout,
or deletion.

```bash
npm run test:phase5h24
```
