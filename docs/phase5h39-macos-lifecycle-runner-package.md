# Phase 5h.39 — fixed macOS lifecycle runner package

This phase completes the non-live production composition for the privileged macOS denial lifecycle. No system account, file under `/Library`, LaunchDaemon, Mach registration, or sudo invocation was created or executed.

## Fixed runner

The runner accepts exactly `--approved-denial-lifecycle`. It rejects every ambient invocation with no output and rejects execution unless the real UID is non-root and the effective UID is root. Only after those checks does it open the two fixed root-owned parent directories.

Its build-generated header embeds the reviewed helper and plist bytes, their SHA-256 values, and the designated-requirement SHA-256. It creates a new run-private GeneratedUID for the fixed `_bwagentbridge` account, initializes the combined nonactivating launchctl-presence and audit-bound Mach-denial probes, and wires the fixed command runner, dscl adapter, launchctl adapter, retained-FD controller, and stdin approval handshake. Success requires denial plus complete cleanup and emits one fixed value-free record; every failure is silent and nonzero.

## Reproducible package

Package construction accepts no input. It first builds the already branded signed helper/plist lifecycle package and independently repeats the helper FD-content code-snapshot check against its designated-requirement digest. Every required native C/H source is read through `O_NOFOLLOW`, ownership/mode/size checked, held open across the complete read pass, globally rechecked, and copied into two independent private `0700` build roots. This proves stable per-file snapshots, not an atomic repository revision; package metadata states that distinction explicitly. A generated read-only artifact header binds the helper, plist, and requirement bytes plus all three hexadecimal digests.

Both complete runner builds must be byte-identical and have the same designated requirement. The selected runner is ad-hoc signed with hardened runtime, strictly verified, re-measured from a stable descriptor, checked with the existing FD-content code-snapshot verifier, and executed in both harmless rejection modes: ambient invocation and the fixed mode without elevation. Post-link verification requires the final Mach-O to contain the exact helper/plist byte sequences, their ASCII digests, and the requirement digest in binary and ASCII form. Private build roots are removed file-by-file; cleanup failure invalidates the package.

The returned branded package provides independent copies of runner/helper/plist bytes but explicitly keeps mutation authorization, live-test verification, and install eligibility false.

## Remaining gate

The next phase must bind the non-root launcher to this exact branded runner package and implement a narrowly scoped provisioning/cleanup transaction for the root-owned runner path. That provisioning is itself a privileged mutation and will not be executed without explicit operator approval.
