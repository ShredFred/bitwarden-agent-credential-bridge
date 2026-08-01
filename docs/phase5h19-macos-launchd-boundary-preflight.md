# Phase 5h.19: macOS launchd boundary read-only preflight

This phase adds the first real macOS host inspection for the fixed Phase 5h.18
system-helper contract. It is read-only and advisory. A matching snapshot never
authorizes installation, launchd activation, Mach requests, manifest execution,
Keychain access, vault access, or credential use.

## Public control plane

`inspectMacosLaunchdBoundary(plan)` accepts only an in-process branded
Phase 5h.18 plan. Clones, spreads, proxies, extended objects, and modified plans
are rejected before the probe process starts. The process boundary receives only:

- reviewed helper binary SHA-256;
- reviewed helper binary byte length;
- reviewed designated-code-requirement SHA-256.
- reviewed exact LaunchDaemon plist SHA-256.

The label, account, plist path, binary path, tool paths, and inspection rules are
fixed inside the repository-owned probe. Callers cannot select a service,
account, command, path, environment, timeout, or output schema.

## Fixed read-only sensors

The probe uses only local read operations:

- `lstat`, required `open(O_NOFOLLOW)`, handle-bound file size/read, and SHA-256;
- `/usr/bin/plutil` for the fixed LaunchDaemon plist;
- `/usr/bin/dscl` for the fixed hidden non-login helper account;
- `/usr/bin/codesign --verify` and `codesign -d -r-` for the fixed helper;
- effective `access(W_OK)` plus ownership/mode, conservative extended-ACL
  rejection, and symlink checks over complete binary and plist chains.

All tools use absolute paths, bounded output, fixed arguments, short timeouts,
and a minimal environment. Raw stdout/stderr, paths, UIDs, account data, plist
content, signing identities, designated-requirement text, and native errors never
leave the child. Tool failures become stable parent-side error codes.

The plist is opened with `O_NOFOLLOW`, hashed from that handle, and passed to
`plutil` through the inherited read-only descriptor. Content and identity checks
therefore describe the same plist generation.

The designated-requirement pin is SHA-256 over the exact UTF-8 stdout bytes of
`/usr/bin/codesign -d -r- -- <fixed-helper>`, requiring exactly one
`designated => ...\n` record. The path-bearing codesign diagnostic channel is
discarded inside the probe. Operators must derive a future reviewed pin with the
same bytes and trailing-newline rule.

The binary remains open while it is hashed, inspected by `codesign`, its complete
path chain is checked, and it is hashed again. Its handle and fixed path must
retain the same device, inode, size, mtime, ctime, and digest across the
inspection. In the original Phase 5h.19 implementation, Apple's lack of a
documented `/dev/fd` code object meant this could establish only the advisory
`designated_requirement_path_snapshot_matches_plan` bit; verified code and the
aggregate snapshot remained false.

Phase 5h.20 changes the shared probe by measuring a byte-identical exclusive
private copy sourced from the already-open descriptor. That later verifier may
set `designated_requirement_verified` and therefore a fully matching static
snapshot. The installed-path diagnostic remains advisory, and neither result can
authorize a request because `authorization_ready` is still forced false.

Phase 5h.20 subsequently supplies a content-bound measurement without pretending
that the installed pathname is descriptor-bound: it copies the already-open
bytes into an exclusive private snapshot and lets Apple validate only that exact
copy. See `docs/phase5h20-macos-code-snapshot-verification.md`.

## Value-free report

The child returns an exact schema containing `schema_version` plus booleans only.
The parent recomputes `snapshot_matches_plan`, rejects impossible partial/absent
claims, rejects any extra or non-boolean field, and requires
`authorization_ready: false`. In Phase 5h.19 the child could only report
`designated_requirement_verified: false`; Phase 5h.20 may set it true through the
separate content-bound private-snapshot verifier.

If the fixed LaunchDaemon plist is absent, the probe exits successfully with the
canonical all-false report and does not call `plutil`, `dscl`, or `codesign`.
That is the expected result before a separately approved installation phase.

Even a fully matching path snapshot is advisory and cannot set Phase 5h.4 live
live Mach evidence. A later handle/audit-token-bound collector must reverify the loaded
helper identity and designated requirement at the request boundary.

## Prohibited operations

The Phase 5h.19 implementation contained no `launchctl`, account creation,
signing, chmod/chown, filesystem write, elevation, Mach connection,
Security-framework mutation, Keychain lookup, Bitwarden/OneCLI access, or network
call. Phase 5h.20 adds only one exclusive temporary measurement-file write and
its mandatory exact cleanup; all other prohibitions remain.

```bash
npm run test:phase5h19
```
