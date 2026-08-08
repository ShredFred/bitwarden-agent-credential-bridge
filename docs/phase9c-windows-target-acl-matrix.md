# Phase 9c: persistent target-ACL AccessCheck matrix

Phase 9c collects value-free evidence that the five canonical persistent
ProgramData-class helper targets have been AccessChecked for both the
interactive caller and the running LocalService helper token.

## Fixed targets

Under `%ProgramData%\BitwardenAgentCredentialBridge` (never caller-selected):

1. `config` (directory)
2. `config\config.json` (file)
3. `install` (directory)
4. `bin` (directory)
5. `bin\launcher` (file)

These match the Phase 5h.54 / first-install apply layout. Absent targets are
checked against the nearest existing ancestor inside the root for the exact
create right (same rules as Phase 5h.7).

## Completeness rules

`all_targets_checked=true` only when:

- the persistent root exists;
- the fixed SCM service is running;
- the helper process token was opened;
- AccessCheck finished for all five targets for both caller and helper.

Ownership/reparse bits require a trusted owner (SYSTEM / Administrators /
TrustedInstaller / per-service SID), forbid caller ownership, and forbid shared
`LocalService` TokenUser ownership (`S-1-5-19`).

Malformed or incoherent probe JSON is rejected. Path-only advisory preflight is
not used. Public reports always keep `authorization_ready=false`.

## Commands

```bash
npm run test:phase9c
# Optional operator live collection (read-only; no UAC):
npm run live:windows-persistent -- install
# optional: vault-free first-install apply so the five targets exist
npm run live:windows-target-acl-matrix
npm run live:windows-persistent -- uninstall
```

Absent root/service yields `terminal_code=target_acl_matrix_incomplete` with
branded all-false Phase 9a target-ACL evidence.

## Non-claims

- Does not set operational `authorization_ready` by itself (Phase 9e composes)
- Does not run a different-principal authorize session (Phase 9d)
- Does not mutate ACLs, elevate, or access Bitwarden
- Helper remains vault-free
