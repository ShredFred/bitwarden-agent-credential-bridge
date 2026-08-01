# Phase 5h.26: macOS lifecycle read-only dry run

Phase 5h.26 performs the seven fixed pre-mutation checks from the branded
LaunchDaemon lifecycle gate without accepting input, elevating, or changing
OpenDirectory, `/Library`, or launchd state.

`runMacosLaunchdLifecycleDryRun()` first builds and re-verifies the exact signed
Phase 5h.25 helper/plist package in private temporary roots. It then launches a
fixed child probe with no arguments. The probe returns only an exact bounded
boolean schema; raw account candidates, UUIDs, paths, launchctl output, tool
errors, or package bytes never cross the result boundary.

The read-only checks establish, at one point in time:

1. the reviewed binary, plist, designated requirement, plan, and lifecycle gate
   remain bound by the branded package;
2. the fixed account name is absent and at least one system-UID candidate plus
   a fresh GeneratedUID candidate have no current directory collision;
3. the fixed plist is absent;
4. the fixed helper binary is absent;
5. the fixed system label is unloaded and the fixed Mach registration is not
   present in the system launchd domain snapshot;
6. both fixed parent-directory chains are directories, symlink-free,
   root-owned, not group/world writable, and not writable by the ordinary
   caller; and
7. run-private account identity material is selectable.

Label absence uses the exact bounded `LANG=C` absent response from
`launchctl print system/<fixed-label>`. Mach registration absence uses a
bounded successful `launchctl print system` domain snapshot, which the
`launchctl(1)` contract documents as including Mach bootstrap name
registrations. No Mach lookup API is used because lookup could demand-activate
a registered service. Any command drift, noisy output, truncation, collision,
or incoherent boolean combination fails closed.

This is a point-in-time dry run, not an ownership lease. A future approved
executor must repeat every check immediately before mutation and preserve the
Phase 5h.22 retained-FD/soft-identity rules. Even a complete result is
`dry_run_complete_untrusted`: mutation, collector trust, live-test verification,
authorization readiness, and installation eligibility all remain false.

The directory policy also rejects extended ACLs, even if the current caller's
`access(2)` result happens to be non-writable. Exact `dscl` and launchctl output
requirements intentionally favor a false-negative dry run over interpreting
warnings or platform-format drift as safe absence.

Run:

```bash
npm run test:phase5h26
```

No current operator approval is needed for this read-only phase. Account
creation, writes below `/Library`, launchd bootstrap/bootout, and the production
Mach denial exchange remain later explicitly approved work.
