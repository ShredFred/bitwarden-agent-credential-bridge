# macOS validation and Windows/Cursor handoff

Validated on 2026-08-01 on macOS (`darwin`, Apple host) with Node.js 24.14.1
and npm 11.11.0. Only generated fake credentials and disposable temporary
workspaces were used.

## Outcome

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

4. Record the Node, npm, PowerShell, Windows, and .NET versions with the result.
5. Do not install the native service, elevate, pair Bitwarden, pull OneCLI
   images, or use a real secret unless a later phase explicitly authorizes that
   live gate.

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
