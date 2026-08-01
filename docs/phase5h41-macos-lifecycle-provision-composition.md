# Phase 5h.41 — package-bound macOS provision composition

Phase 5h.41 connects the non-root launcher to the retained-FD runner provisioning transaction without requiring a persistent installed runner. It remains a non-live composition: no sudo command was executed, no file under `/Library` was created, and all mutation, live-test, and install-eligibility flags remain false.

## Explicit bootstrap boundary

A cold start cannot safely ask sudo to execute a user-owned temporary binary under the concurrent same-user threat model. Extra file descriptors also do not provide a reliable general transport across sudo on macOS. The composition therefore requires one deliberately installed trust anchor at the fixed root-owned path:

`/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner`

The reproducible package now builds, signs, verifies, and returns this minimal provisioner alongside the launcher and runner. Installing the provisioner is a separate operator-approved bootstrap gate; this phase does not implement or authorize that host mutation.

## Exact execution chain

The launcher requires the ephemeral runner path to be absent. A pre-existing runner of any identity is a collision and fails closed with `runner_collision_detected`; an unreadable/indeterminate runner state sets `runner_state_unknown`; a missing or digest-invalid trust anchor sets `provisioner_unavailable`. None is adopted, replaced, or deleted. When the runner is absent, the launcher verifies the fixed provisioner is root-owned, non-writable by group/other, free of extended ACL entries, stable across path/FD inspection, and byte-equal to the provisioner digest embedded in the launcher. It then invokes only:

`/usr/bin/sudo -k -- <fixed-provisioner> --provision-run-cleanup-approved-denial-lifecycle`

The provisioner requires a non-root real UID, root effective UID, and a stable direct sudo parent. It rechecks that ancestry, opens the canonical `/Library/PrivilegedHelperTools` directory with no-follow semantics, verifies the retained descriptor resolves to that exact path, rejects group/world write bits and every extended ACL entry, validates its compile-time embedded runner digest, and calls the Phase 5h.40 transaction.

The transaction exclusively publishes the exact runner bytes, verifies them through the retained descriptor, forks, sanitizes file descriptors, and executes `/dev/fd/3` in the fixed runner mode. The runner approval boundary accepts only a direct sudo parent or the exact provisioner whose stable parent is sudo. It retains the nonce, PID, real-UID peer, expiry, and helper/plist/requirement digest binding from Phase 5h.37.

The provisioner bounds the nested runner to 120 seconds, kills and reaps its exact child on timeout, and always performs inode-bound runner cleanup afterward. The outer launcher independently bounds and kills the complete sudo process group. The runner is the only process that emits the exact success record; the provisioner exits zero only after runner success and final runner-path absence. Launcher result fields are intentionally named `child_reported_denial` and `child_reported_cleanup`: they describe the exact authenticated child record rather than claiming an independent second lifecycle observation.

## Package and tests

Two complete same-host builds must produce identical runner, provisioner, and launcher bytes and designated requirements. The provisioner Mach-O contains the exact runner bytes and runner digest in named sections. The launcher contains exact helper, plist, helper-requirement, runner, and provisioner digests. The section parser records the first section fields only, preventing later load-command segment metadata from overwriting the section identity.

Run:

```bash
npm run test:phase5h41
```

The slice covers package reproducibility and copies, strict launcher branching, collision behavior, approval receipts, direct-versus-mediated elevation-chain decisions, provisioner ambient/unelevated rejection, retained-FD publication, timeout structure, replacement preservation, and cleanup. Windows runs keep native macOS executions skipped while source-contract checks remain mandatory.

## Remaining gates

This phase does not prove the installed provisioner, sudo prompt, real `/Library` publication, real launchd lifecycle, or aggregate post-run absence. Those require an explicitly approved disposable privileged macOS live test. The current ancestry proof binds stable root-owned paths, PIDs, parent relationships, and process start identity; it does not claim protection against a malicious concurrent root actor, who already controls the bootstrap paths and host. A production distribution also needs a reviewed installer/package and signing/notarization policy for the persistent provisioner trust anchor. Windows-native service lifecycle tests still require a Windows host. The complete real sudo→provisioner→runner chain is intentionally a live-gate test; non-live tests cover its branch, ancestry, approval, fork, retained-FD, output, and cleanup components separately.
