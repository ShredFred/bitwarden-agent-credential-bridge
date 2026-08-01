# Phase 5h.25: signed macOS lifecycle package

Phase 5h.25 replaces placeholder digests with a real locally built helper and
exact LaunchDaemon plist while still performing no system installation.

## Exact artifact build

`buildMacosLaunchdLifecyclePackage()` accepts no arguments. It opens the fixed
repo-owned Phase 5h.24 C source once with no-follow semantics and reads a stable
descriptor snapshot. Two separate mode-0700 directories are created under the
real canonical macOS temporary root. Each receives exclusive, fsynced mode-0400
copies of the same source and plist bytes.

The helper is compiled with fixed `/usr/bin/clang` arguments and linker ad-hoc
signing disabled. `/usr/bin/codesign` then applies an explicit ad-hoc signature,
the fixed helper identifier, no timestamp, and Hardened Runtime. The builder
requires strict signature verification and parses exactly one designated-
requirement record. Standard signed requirements retain their existing grammar;
the only new accepted form is Apple's exact ad-hoc record:

```text
# designated => cdhash H"<40 lowercase hex>"
```

Arbitrary comments, uppercase hashes, shortened hashes, paths, multiple records,
NULs, and extra lines remain invalid. The read helper bytes are independently
verified through the Phase 5h.20 private FD-content snapshot route before their
digest is accepted. Both builds must have byte-identical binaries and identical
requirement records on that host/toolchain.

## Fixed plist

The exact XML plist contains only `Label`, one-element `ProgramArguments`,
`UserName`, and the single `MachServices` entry. It contains no KeepAlive,
RunAtLoad, timer, path/socket trigger, environment, or stdout/stderr path. Both
`plutil -lint` and the pure Phase 5h.19 rules must accept it. The plist is never
written outside the private package build roots.

## Branded package

The real binary SHA-256 and length, designated-requirement SHA-256, and plist
SHA-256 create a branded Phase 5h.18 boundary plan and Phase 5h.22 lifecycle
gate. Binary/plist bytes are kept outside the public frozen object in a WeakMap.
`copyMacosLaunchdLifecyclePackageArtifacts()` accepts only the branded in-process
package and returns fresh copies; clone, spread, and forged lookalikes fail.

Artifact bytes are data, not authority. The package reports only readiness for
explicit lifecycle review. Mutation authorization, collector trust, live-test
verification, authorization readiness, and install eligibility remain false.

## Non-goals

This phase does not use a private signing identity, notarize, persist build
outputs, elevate, create an account, touch `/Library`, invoke launchctl or
OpenDirectory, contact the production Mach service, access Keychain/vault/
network/credentials, install, load, or delete anything outside its exact private
temporary roots. Ad-hoc signing is suitable only for this local reviewed test
artifact and is not distribution trust.

```bash
npm run test:phase5h25
```
