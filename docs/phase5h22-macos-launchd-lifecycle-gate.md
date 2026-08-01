# Phase 5h.22: macOS LaunchDaemon lifecycle gate

Phase 5h.22 is a pure, non-executable contract for a future operator-approved,
disposable distinct-EUID denial test. It does not install or run anything.

## Bound scope

The builder accepts only the branded in-process Phase 5h.18 macOS boundary plan
and copies exactly four reviewed values: binary SHA-256, binary byte length,
designated-requirement SHA-256, and plist SHA-256. It accepts no approval or
caller-selected account, path, UID, GUID, label, service, command, audit token,
or native output. Cloned, spread, proxied, accessor-backed, and forged plans are
rejected.

The future lifecycle is restricted to the fixed system-domain launchd helper,
static hidden non-login account, PrivilegedHelperTools binary, LaunchDaemons
plist, production Mach service, and a denial-only probe. Manifest execution,
credentials, Keychain, vault, network, ordinary user homes, KeepAlive, and timers
remain forbidden.

## Ordered lifecycle

Before mutation, a future collector must reverify the plan bindings, absence of
the fixed account/artifacts/job/service, parent-directory policy, and collision-
free run-private account identity material. Each account, descriptor, binary,
plist, bootstrap, and activation mutation is immediately followed by identity,
digest, owner/mode, requirement, launchd, process-EUID, or Mach-service
reverification. The only allowed probe outcome is a value-free distinct-EUID
audit-trailer denial.

Phase 5h.22 records this sequence but does not execute it.

## Ownership and collisions

File mutations and deletion require retained parent and file descriptors.
Account cleanup is allowed only after this run proved create success and the
recorded GeneratedUID and UniqueID still match. Job cleanup is allowed only
after this run proved bootstrap success and the loaded identity still matches
the recorded bootstrap epoch. Those account and job claims are deliberately
soft ownership evidence; macOS does not provide a durable handle equivalent.

A pre-existing object, exclusive-create collision, ambiguous create/bootstrap
outcome, or later identity mismatch is never adopted. Destructive retry by the
fixed name or path is forbidden; the run stops and records manual recovery.

## Always-cleanup contract

After the first run-owned object is created, cleanup must execute in `finally`
and continue after individual failures:

1. Stop and reverify the run-owned helper process.
2. Boot out and reverify the run-owned system job and Mach service.
3. Unlink and reverify the run-owned plist through retained descriptors.
4. Unlink and reverify the run-owned binary through retained descriptors.
5. Delete and reverify the run-owned account only if both recorded IDs match.
6. Prove final absence of account, plist, binary, label, and Mach service.

Incomplete cleanup is a failed run requiring manual recovery, never permission
for a later name-based delete.

## Remaining gate

Every structural result, mutation authorization, collector-trust,
authorization-readiness, live-test, and installation-eligibility flag remains
false. A later phase must first add a strict value-free transcript state machine
and a reviewed native collector. Actual elevation and lifecycle execution still
require separate explicit operator approval naming that exact disposable test.
