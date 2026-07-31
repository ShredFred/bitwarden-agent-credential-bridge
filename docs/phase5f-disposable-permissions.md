# Phase 5f: disposable permission hardening

Phase 5f changes permissions only on existing objects inside a currently valid,
marked disposable workspace. Every call re-verifies the workspace and marker,
requires a regular single-link target of the declared type, and rejects paths
outside the root.

POSIX targets are opened with no-follow semantics, identity-checked with `fstat`,
and changed through the verified handle to owner-only modes. The Windows setter independently checks
the canonical root, exact marker nonce/bytes, containment, every path segment,
item type, and reparse attributes before replacing inherited ACLs. It grants
FullControl only to the current user SID, LocalSystem, and Builtin Administrators.
The process is hidden, non-interactive, bounded, silent on success, and maps all
raw failures to stable errors.

Real Windows tests harden a workspace plus child directory/file and use the
separate read-only ACL probe to confirm the resulting policy. This phase still
does not execute a manifest, access Bitwarden, or touch default user roots.

```bash
npm run test:phase5f
```
