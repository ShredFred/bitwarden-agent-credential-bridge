# Phase 9b: handle-bound installed-service identity collector

Phase 9b collects value-free evidence that a **running** fixed LocalService
helper is the pipe server and that its installed image matches the reviewed
digest through a **file handle**, not through path-only `Get-FileHash` (Phase
5h.9 advisory preflight).

## Composition

1. **Native Phase 5h.13 verifier** (`--verify-fixed-server-identity`) — connects
   to the fixed local denial pipe, binds the server PID with
   `OpenProcess`, checks LocalService `TokenUser` + enabled service SID, and
   matches the SCM running PID before/after token inspection. Sends no request.
2. **Handle-bound binary/service probe**
   (`scripts/windows-handle-bound-identity-probe.ps1`) — opens the service image
   with `CreateFile` + `FILE_FLAG_OPEN_REPARSE_POINT`, hashes bytes via
   `ReadFile` on that handle, walks ancestors the same way for reparse/owner/
   caller-control checks, and AccessChecks the service-object security
   descriptor. `path_hash_used` is always false.

Node merges both into the exact Phase 9a handle-bound evidence schema and brands
the object for `evaluateWindowsProductionAuthorization`. The public collector
report always keeps `authorization_ready=false` and
`operational_bridge_unwired=true`.

## Commands

```bash
npm run test:phase9b
# Optional operator live collection (read-only; no UAC). Requires a running
# persistent install for a complete result:
npm run live:windows-persistent -- install   # elevated, separate approval
npm run live:windows-handle-bound-identity   # no elevation
npm run live:windows-persistent -- uninstall
```

Absent service/pipe yields an honest incomplete branded evidence object
(`terminal_code=handle_bound_identity_incomplete`). That is success for the
collector contract, not production authorization.

## Non-claims

- Does not set operational `authorization_ready` by itself (Phase 9e composes)
- Does not collect the five-target ACL matrix (see Phase 9c /
  `docs/phase9c-windows-target-acl-matrix.md`)
- Does not run a different-principal authorize/apply session (Phase 9d)
- Does not replace Phase 5h.9; path-based preflight remains advisory only
- Helper stays vault-free; no Bitwarden access
