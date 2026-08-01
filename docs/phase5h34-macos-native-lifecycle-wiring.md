# Phase 5h.34 — native macOS lifecycle wiring

This phase joins the fixed `dscl` and `launchctl` adapters with the composite
account/file/job controller. It closes the gap between path-oriented launchctl
commands and the controller's retained file ownership.

## Retained artifact binding

After the account, helper, and plist have been created and verified, the
controller invokes a mandatory one-shot binder with its run-owned binary and
plist descriptors. Binder failure immediately enters reverse cleanup and no job
bootstrap occurs.

The launchctl adapter's artifact callback verifies both retained descriptors,
device/inode identities, current no-follow directory entries, exact bytes,
ownership, and modes. It runs before bootstrap and activation and during every
loaded-job, process, stop, and bootout identity check. A replacement is foreign:
job mutation stops, retained cleanup refuses the foreign path, and the report
requires manual recovery.

Because launchctl always bootstraps the fixed `/Library/LaunchDaemons` path,
production initialization accepts only retained parents whose `F_GETPATH`
values are exactly `/Library/PrivilegedHelperTools` and
`/Library/LaunchDaemons`. The same parent-path binding is repeated during each
artifact callback. This prevents a verified temp or renamed directory from being
mistaken for the path launchd actually reads.

## Test and lifetime boundary

The private-temp integration test enables `BW_NATIVE_WIRING_TESTING`, which is
the only build that exposes a fixture-path constructor. Normal builds contain
only the exact-system-parent initializer. The test proves:

- production initialization rejects its temporary parent;
- clean fake dscl/launchctl/Mach operation and complete reverse cleanup;
- binder failure performs no job mutation;
- launchctl refuses bootstrap when its artifact probe reports drift;
- denial-time plist replacement blocks subsequent job cleanup and preserves the
  foreign file.

Caller-provided artifact buffers must remain immutable and alive from wiring
initialization until `bw_run_native_lifecycle` returns. The wiring object itself
must not be copied or moved after initialization because its operation contexts
point into that object.

```bash
npm run test:phase5h34
```

There is still no executable privileged runner or approval token in this phase.
All system command and Mach boundaries are fake in mutation tests, and no real
account, daemon, system artifact, credential, Keychain, vault, or network state
is changed.
