# Phase 5b: read-only host preflight

Phase 5b audits an already-derived per-user bootstrap layout without repairing
or creating it. It inspects metadata for the user config, installation root,
and launcher. Only the non-secret launcher may be read, and only when an
expected SHA-256 digest is supplied. User config contents are never opened.

On POSIX, every target must belong to the supplied current UID. The config must
deny all group/other permissions, while the install directory and launcher must
not be group/other writable. Symbolic links are rejected.

On Windows, Node metadata alone is not treated as sufficient. A later host
adapter must return exactly three booleans for each target: reparse-point state,
current-user ownership, and other-user writability. Missing, malformed, or
throwing adapters fail closed. Reports expose only fixed check IDs and reasons,
never command output, account names, SIDs, ACL entries, paths, or exceptions.

This is still not an installer and does not read config values, access
Bitwarden, start a broker, chmod files, change DACLs, or mutate the machine.

```bash
npm run test:phase5b
```
