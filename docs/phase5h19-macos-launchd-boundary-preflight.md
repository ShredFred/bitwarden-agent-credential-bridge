# Phase 5h.19: macOS launchd boundary read-only preflight

This phase adds the first real macOS host inspection for the fixed Phase 5h.18
system-helper contract. It is read-only and advisory. A matching snapshot never
authorizes installation, launchd activation, XPC requests, manifest execution,
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
path chain is checked, and it is hashed
again. Its handle and fixed path must retain the same device, inode, size,
mtime, ctime, and digest across the inspection. Because Apple's `codesign` tool
does not accept `/dev/fd` as a code object, this remains a conservative
path-snapshot check against privileged swap-and-restore. The report may set only
`designated_requirement_path_snapshot_matches_plan`; both child and parent force
`designated_requirement_verified: false`. Consequently Phase 5h.19 can never
produce `snapshot_matches_plan: true` or authorize a request. A later native
fd-/Mach-O-bound requirement reader is required for the verified bit.

## Value-free report

The child returns an exact schema containing `schema_version` plus booleans only.
The parent recomputes `snapshot_matches_plan`, rejects impossible partial/absent
claims, rejects any extra or non-boolean field, and requires both
`designated_requirement_verified: false` and `authorization_ready: false`.

If the fixed LaunchDaemon plist is absent, the probe exits successfully with the
canonical all-false report and does not call `plutil`, `dscl`, or `codesign`.
That is the expected result before a separately approved installation phase.

Even a fully matching path snapshot is advisory and cannot set Phase 5h.4 live
XPC evidence. A later handle/audit-token-bound collector must reverify the loaded
helper identity and designated requirement at the request boundary.

## Prohibited operations

This phase contains no `launchctl`, account creation, signing, chmod/chown,
filesystem write, elevation, XPC connection, Security-framework mutation,
Keychain lookup, Bitwarden/OneCLI access, or network call.

```bash
npm run test:phase5h19
```
