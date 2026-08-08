# macOS validation and Windows/Cursor handoff

Validated on 2026-08-01 on macOS (`darwin`, Apple host) with Node.js 24.14.1
and npm 11.11.0. Only generated fake credentials and disposable temporary
workspaces were used.

## Outcome

### Current merge checkpoint (2026-08-01)

Phase 4c now includes a tested fixed-entrypoint runtime supervisor in
`src/onecli-proxy-runtime-supervisor.js`. It launches only the repo-owned
`scripts/run-onecli-proxy.mjs`, inherits no caller environment or arguments,
transfers generated fake token/policy frames over child descriptors 3 and 4,
and holds descriptor 5 as the child-lifetime lease. It accepts exactly one
bounded loopback ready record, probes the listener, invalidates the endpoint on
child exit or output-protocol violation, and escalates a bounded shutdown.

macOS verification at this checkpoint:

- `npm run test:phase4c`: 41/41 passed;
- complete serial repository suite with the dot reporter: exit code 0;
- Cursor Composer 2.5 performed two read-only security reviews; all reported
  High/Medium implementation findings were repaired before merge;
- no sudo, launchd mutation, package installation, OneCLI pairing, Bitwarden
  access, real token, or privileged filesystem write was performed.

The supervisor remains a same-user development boundary, not a production
trust anchor. Repo JavaScript and the Node executable are not yet bound to a
signed reviewed package. Do not connect it to the existing macOS denial-only
lifecycle provisioner; that would incorrectly widen the provisioner's fixed
authority and token-handling surface.

The foreground fake broker demo completes without returning its generated
sentinel. The portable suite now also completes on macOS. Before the fix, five
Phase 5g tests failed because the macOS layout intentionally uses one Application
Support directory as both `config_dir` and `install_root`, while the manifest
contained two exclusive directory-creation actions for that same path.

The manifest builder now:

- emits one exclusive create/rollback pair for the shared macOS directory;
- rejects contradictory observations when the two logical fields describe that
  same physical path differently;
- preserves distinct config/install directory actions on Windows and Linux.

The Windows named-pipe session now performs exact input and request-binding
validation before returning `unsupported_platform`. This keeps its negative
contract tests portable without allowing any Windows process, pipe, or mutation
path to run on macOS.

## Reproduce on macOS

From the repository root:

```bash
node --version
npm test
npm run test:phase5h18
npm run test:phase5h19
npm run test:phase5h20
npm run test:phase5h21
npm run test:phase5h22
npm run test:phase5h23
npm run test:phase5h24
npm run test:phase5h25
npm run start:demo
npm run preflight:bootstrap
npm run preflight:onecli
```

Expected results:

- `npm test` passes, with Windows-only live tests reported as skipped.
- `start:demo` returns status `200` and the constant fake API body only.
- `preflight:bootstrap` may report `missing_or_unreadable` until a separately
  approved per-user installation exists. It is read-only and must fail closed.
- `preflight:onecli` may report `aac` as `missing_or_failed`. Do not install,
  pair, or connect a vault merely to make this readiness check green.

The Phase 5g tests create and remove only marker-authorized descendants of the
canonical macOS temporary directory. They do not write to the real home Library,
read Keychain, access Bitwarden, or use network credentials.

## Continue on Windows with Cursor

### Windows validation checkpoint (2026-08-08)

Validated on Windows 11 (`win32` 10.0.26200) in a non-elevated PowerShell 7.6.3
shell with Node.js v24.13.1, npm 11.8.0, and .NET SDK 8.0.423. Only generated
fake credentials and disposable temporary workspaces were used for the
non-elevated harness suite. A later same-day operator-approved live pass also
exercised disposable elevated service install/deny/cleanup, persistent
install/uninstall, and the pinned disposable DPAPI Bitwarden smoke.

Outcome:

- `npm run test:phase4c`: 41/41 passed after a narrow Windows IPC descriptor
  fix. Node/libuv reports anonymous `stdio: "pipe"` channels with FIFO mode bit
  `0x1000` while `Stats.isFIFO()` remains false; the runtime now accepts that
  exact mode class on `win32` and still rejects files and character devices
  such as `NUL`.
- Windows handoff slices passed: `test:phase5c`, `test:phase5f`,
  `test:phase5h6`, `test:phase5h10`, `test:phase5h15`, `test:phase5h16`.
- Full `npm test`: 361 passed, 35 skipped (macOS/live gates), 0 failed.
- `npm run start:demo`: status `200` with the constant fake API body only.
- `npm run start:operational`: `ok=true`, `harness_ready=true`, all five sample
  smoke aliases true, `authorization_ready=false`.
- Portable source-contract tests tolerate Windows `core.autocrlf` via CRLF
  normalization plus a repository `.gitattributes` LF policy.

Operator-approved live gates (same host, UAC consent):

- `npm run live:windows-service`:
  `live_test_verified=true`, `collector_trust_verified=true`,
  `terminal_code=live_denial_verified_cleaned`,
  `authorization_ready=false`, `install_gate_eligible=false`.
- `npm run live:windows-persistent -- install` then `uninstall`:
  both `ok=true`, `terminal_code=persistent_lifecycle_verified`,
  `authorization_ready=false`; host left without the fixed service after
  uninstall.
- `npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden`:
  `ok=true`, `live_secret_resolved=true`, `broker_smoke_ok=true`,
  `authorization_ready=false`; personal/company/organization vaults remain
  forbidden. DPAPI unlock is not MFA.

1. Pull this branch and verify that the worktree is clean before testing.
2. Use Node.js 20 or newer and run `npm test` in a normal, non-elevated shell.
3. Run the Windows-specific slices explicitly:

   ```powershell
   npm run test:phase5c
   npm run test:phase5f
   npm run test:phase5h6
   npm run test:phase5h10
   npm run test:phase5h15
   npm run test:phase5h16
   ```

   Also run the new end-to-end supervisor slice first:

   ```powershell
   npm run test:phase4c
   ```

   This is the most important Windows continuation gate. Confirm that Node's
   extra child `stdio: "pipe"` descriptors pass the FIFO/socket identity rules,
   that the child reaches its ready record, that closing the lease exits code
   0, and that the reported proxy port is closed afterward. If Windows `fstat`
   classifies anonymous child pipes differently, add a narrowly win32-specific
   descriptor rule backed by a native integration test; do not weaken the
   POSIX FIFO/socket rule or accept regular files/devices.

4. Record the Node, npm, PowerShell, Windows, and .NET versions with the result.
5. Do not install the native service, elevate, pair Bitwarden, pull OneCLI
   images, or use a real secret unless a later phase explicitly authorizes that
   live gate.

Recommended next development order on Windows:

1. ~~Prove `npm run test:phase4c` unchanged in a non-elevated shell and record
   exact OS/Node/npm results in this document.~~ Done on 2026-08-08.
2. ~~Operator-approved elevated disposable service denial, persistent
   install/uninstall cleanup, and disposable DPAPI Bitwarden smoke.~~ Done on
   2026-08-08 (`authorization_ready` remains false).
3. ~~Phase 9a pure production authorization compiler + milestone plan defining
   the exact evidence required before `authorization_ready` may become true.~~
   Done on 2026-08-08.
4. ~~Phase 9b read-only handle-bound identity collector (native 5h.13 + handle
   binary probe).~~ Done on 2026-08-08; complete positive evidence still needs a
   running persistent install from a separate elevated gate
   (`npm run live:windows-handle-bound-identity`).
5. ~~Phase 9c read-only target-ACL AccessCheck matrix on the five persistent
   ProgramData targets.~~ Done on 2026-08-08; complete positive evidence needs
   present root + running LocalService
   (`npm run live:windows-target-acl-matrix`).
6. ~~Phase 9d different-principal persistent pipe session → branded Phase 5h.1
   five-facts.~~ Done on 2026-08-08; complete positive evidence needs running
   LocalService + complete 9c ACL
   (`npm run live:windows-persistent-peer-session`).
7. ~~Phase 9e wire readiness surfaces to the branded Phase 9a report.~~ Done;
   default incomplete evidence stays false; never hardcode true; mutation stays
   on a separate apply gate
   (`docs/phase9e-windows-operational-authorization.md`).
8. ~~Phase 9f package-bind reviewed helper/supervisor digests and expand pure
   Windows CI without live service install.~~ Done
   (`docs/phase9f-windows-helper-package-binding.md`).
9. ~~Phase 10a Day-2 evidence refresh for an already-installed LocalService.~~
   Done (`docs/phase10a-windows-authorization-evidence-refresh.md`;
   `npm run live:windows-authorization-refresh`). Uninstall stays explicit.
10. Keep personal/company Bitwarden pairing forbidden. macOS/Linux distinct-writer
    parity remains a separate milestone; do not claim cross-platform
    `authorization_ready` from Windows-only evidence.
11. Day-2 refresh does not claim same-user memory isolation; agent-readable
    surface non-disclosure remains the exposure-test contract.

Cursor should treat a Windows-only skip on macOS as expected, but any failure in
a pure validator or disposable test as a portability regression. Keep fixes
value-free: errors and evidence must not include paths, SIDs, usernames, raw ACLs,
vault references, command output, or credential material.

## Security boundary retained

This change improves cross-platform correctness; it does not widen authority.
Unsupported platforms and malformed inputs still fail closed. Phase 5h.18 now
defines the fixed system-domain launchd/Mach-service, distinct-EUID, binary, and
designated-code-requirement contract, and Phase 5h.4 explicitly binds the Mach
request audit token to the authorizing caller. Both remain pure and non-executable.

Phase 5h.19 runs that read-only native preflight and returns the canonical
all-false absent snapshot on an uninstalled Mac. It compares any future fixed
helper's binary and designated requirement to the branded plan internally while
returning booleans only and remaining non-authorizing. Phase 5h.20 closes the
static-code path gap by copying the already-open bytes into an exclusive private
temporary measurement object and running Apple verification only against that
byte-identical snapshot. The live macOS test verifies `/bin/ls` through this route
and proves exact cleanup. A fully matching static snapshot may now be reported,
but `authorization_ready` remains structurally false.

Phase 5h.21 now proves a real same-EUID raw-Mach request/reply denial using
kernel audit trailers on both directions. This console test uses only a random
ephemeral bootstrap name; it does not claim the fixed launchd service or reviewed
code requirement and sends no manifest request.

Phase 5h.22 freezes the next lifecycle before any privileged implementation is
allowed. Its in-process branded gate binds all reviewed artifact values and the
exact preflight, exclusive-create, reverify, system-bootstrap, denial, and
always-cleanup sequence. Files use retained-descriptor ownership; account and
launchd cleanup use deliberately softer run-create/bootstrap identity evidence.
Collisions and ambiguous outcomes are never adopted or deleted. The gate accepts
no approval and performs no host mutation or live test.

Phase 5h.23 adds the strict value-free grammar for that future collector. It
derives ownership from the ordered transcript, distinguishes failed mutations
that provably made no change from ambiguous outcomes, forbids destructive
cleanup of ambiguous account/job identities, and requires the aggregate
read-only absence check last. Even a complete synthetic denial transcript is
explicitly untrusted and cannot authorize installation or credential work.

Phase 5h.24 compiles the real denial-only launchd helper entrypoint twice from
the same retained-FD source snapshot. The no-argument path verifies the fixed
hidden non-login account before checking in to the fixed Mach service; it accepts
one exact bounded audit-trailer request and can only send a denial. The live Mac
test runs only the fixed self-test and proves ambient no-argument execution is
silently rejected. It does not install, elevate, touch `/Library`, or contact the
production service.

Phase 5h.25 turns that source into an exact in-memory lifecycle package: two
same-host reproducible Hardened-Runtime ad-hoc signed builds, strict Apple
designated-requirement parsing, FD-content code snapshot verification, and one
fixed linted demand-only plist. The real binary/plist/requirement bindings now
feed branded Phase 5h.18 and 5h.22 objects. All artifacts are removed from disk;
the package is still non-installing and non-authorizing.

There is still no live production Mach service, installed distinct writer, Keychain
integration, production installer, or real Bitwarden/OneCLI credential handoff
on macOS. The next macOS milestone must be an explicitly approved disposable
native LaunchDaemon lifecycle collector/driver that binds the fixed system service, distinct helper EUID,
connected helper audit trailer, loaded launchd identity, and plan-pinned code
requirement. It must still deny and must not execute a manifest or access credentials.

Phase 5h.40 adds the non-live bridge to that future approved run. The reproducible
package now contains both the signed denial runner and a signed fixed launcher;
the launcher embeds the exact helper, plist, helper-requirement, and runner
digests and rehashes the fixed root-owned runner before invoking sudo. A separate
root-side primitive exclusively publishes the runner through a retained parent
descriptor, executes only through its retained `/dev/fd` identity, and performs
identity-bound cleanup. Collision and replacement fixtures are preserved and
reported for manual recovery. See `docs/phase5h40-macos-runner-provisioning.md`.

Windows Cursor should run `npm run test:phase5h40` as a portability slice. The
native macOS fixtures will skip where appropriate, while all source-contract
checks must pass. This phase performed no sudo invocation or `/Library` mutation;
those remain an explicit operator-approved live gate.

Phase 5h.41 removes the persistent-runner assumption. The launcher now accepts
only an absent runner path and a digest-matched fixed root-owned provisioner.
That provisioner embeds the exact package runner, publishes it exclusively,
executes it through a sanitized retained descriptor, bounds and reaps it, and
performs identity-bound cleanup. A foreign/stale runner is an explicit collision,
never a replace/delete opportunity. Approval permits only direct sudo ancestry
or the exact provisioner with sudo as its parent. See
`docs/phase5h41-macos-lifecycle-provision-composition.md` and run
`npm run test:phase5h41` on both platforms.

The one-time provisioner installation remains deliberately outside this slice:
there is no safe cold-start sudo target in a user-writable path under the stated
same-user threat model. Windows Cursor must not reinterpret the packaged
provisioner bytes as installation authorization, and must keep all Windows live
service tests non-elevated/disposable until their separate gate is approved.

Phase 5h.42 adds the non-installing bootstrap artifact for that trust anchor.
`pkgbuild` receives only the exact branded provisioner in a private destination
root. The result is expanded and checked against a pinned PackageInfo,
`pkgutil --payload-files` manifest, root:wheel BOM modes, bounded AppleDouble
metadata, exact extracted tree, and byte-equal executable. It contains no
installer scripts and exposes no lifecycle-package authority. Signature,
notarization, installation, authorization, and live verification remain false.
See `docs/phase5h42-macos-provisioner-bootstrap-package.md` and run
`npm run test:phase5h42`; Windows should skip Apple package execution only.

Phase 5h.43 adds a read-only, fail-closed distribution inspection over those
exact branded PKG bytes. It uses only fixed `pkgutil --check-signature`, binds
the private snapshot before and after the tool, and strictly recognizes the
unsigned or Developer ID Installer certificate-chain grammar. No production
certificate pin is approved yet, and network-backed ticket validation is out
of scope, so signature, notarization, distribution, install, authorization,
and live claims remain false. See
`docs/phase5h43-macos-provisioner-distribution-readiness.md` and run
`npm run test:phase5h43`; Windows must keep this Darwin integration skipped.
