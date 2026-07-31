# Phase 5h.10: native Windows service lifecycle scaffold

This phase introduces the first repo-owned executable that can enter the Windows
Service Control Manager lifecycle. It is intentionally not yet a credential
helper and must not be installed.

## Build boundary

The project targets the locally available .NET 8 Windows runtime and uses no
application `PackageReference` or external service wrapper. Its SDK-driven
single-file build does require the pinned ILLink package. Tests copy the four project files into
separate OS-temporary workspaces and publish framework-dependent, single-file,
`win-x64` release outputs. A local `global.json` pins SDK `8.0.423`; the project
uses runtime baseline `8.0.29` with explicit `LatestPatch` roll-forward; and the required ILLink `8.0.29` package
is copied from the local cache only after its SHA-256 matches the reviewed lock.
Restore uses an explicit source-cleared NuGet config and that one-package local
feed, followed by `publish --no-restore`. Both builds must produce exactly one
executable with the same SHA-256. This establishes reproducibility for the same
source and pinned local toolchain, not universal cross-machine reproducibility.
No `bin`/`obj` output is created in the repository.

The actual loaded .NET 8 servicing patch remains a supply-chain dependency and
must be recorded and approved by a later host preflight and patch policy;
deterministic application bytes do not pin Microsoft runtime files.

## Lifecycle contract

The native entrypoint compiles bindings for the fixed service name through
`StartServiceCtrlDispatcher`, registers stop/shutdown handling, and reports
start-pending, running, stop-pending, and stopped states. Every registration or
status-report failure is retained and produces a non-zero process exit; unknown
controls return `ERROR_CALL_NOT_IMPLEMENTED`, and interrogate acknowledges the
SCM-held last status without mutating pending checkpoint or wait hint.
These successful SCM transitions remain unverified until the gated live service
matrix. A normal console launch
cannot impersonate the SCM and exits silently with a fixed non-zero code.

Exact `--self-test` returns only fixed booleans. It explicitly records that the
SCM lifecycle is not live-verified, the IPC listener and manifest executor are
absent, and the binary is not install-gate eligible, alongside absence of network
and vault surfaces. A whole-source/project audit fails on new pipe, network,
filesystem, registry, process-launch, manifest, or vault surfaces. Any other
argument exits silently non-zero.

Because authenticated IPC and execution are absent, this binary is not eligible
for the service installation gate. Phase 5h.10 compiles and executes only the
console self-test inside disposable roots; it performs no elevation, service or
registry operation, ACL change, normal-root write, secret handling, or vault
connection.
