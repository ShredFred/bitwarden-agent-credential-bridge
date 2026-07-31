# Phase 5a: portable bootstrap plan

Phase 5a defines the machine/repository boundary before any installer or vault
reader exists. The same model applies to Windows, macOS, and Linux:

- install the bridge once per operating-system user;
- keep tracked repository configuration limited to selected service aliases;
- keep Bitwarden item and field references in a user-local, untracked config;
- let repositories select only aliases already approved by that user.

The pure planner accepts already-supplied objects and synthetic platform inputs.
It reads no files or environment variables and performs no system calls. Its
output contains derived paths, selected aliases, and verification action kinds;
it deliberately omits item IDs and field references.

## Trust boundaries

Project configuration cannot define executables, commands, paths, URLs, HTTP
headers, credential fields, policy files, or vault identifiers. Aliases use a
strict lowercase ASCII grammar and exact schemas reject every extra field.
User-local configuration is authoritative and uses credential-class-specific,
exact schemas. Unsupported platforms and ambiguous configurations fail closed.

The next apply/read phase must add checks that do not belong in a pure planner:
canonical containment, symlink and Windows reparse-point rejection, current-user
ownership, POSIX `0700`/`0600` permissions, Windows DACL validation, atomic
writes, launcher integrity, and value-free errors. Until those gates exist,
Phase 5a does not install anything or read a real local configuration.

Verify this slice with:

```bash
npm run test:phase5a
```
