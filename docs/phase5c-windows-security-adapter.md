# Phase 5c: Windows security adapter

Phase 5c supplies the value-free Windows metadata adapter required by the
read-only host preflight. Node launches the repo-owned PowerShell probe with an
argument array, hidden window, no profile, non-interactive mode, a five-second
default timeout, and a 4096-byte output bound.

The probe reads only item attributes and ACL metadata. It reports exactly three
booleans: whether the target is a reparse point, whether the owner is the current
user SID, and whether an untrusted principal has a write-capable Allow ACE.
LocalSystem and Builtin Administrators are treated as privileged system writers;
the owner must still be the current user. Broad Allow ACEs remain unsafe even if
a Deny ACE could restrict effective access, keeping the preflight conservative.

Non-zero exit, timeout, stderr, malformed JSON, extra fields, or unexpected types
become stable value-free errors. Raw PowerShell output, paths, SIDs, principals,
usernames, and exceptions are never returned by the adapter.

This remains read-only. It does not repair ACLs, create files, install launchers,
read configuration contents, access Bitwarden, or start the broker.

```bash
npm run test:phase5c
```
