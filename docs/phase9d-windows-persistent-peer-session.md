# Phase 9d: persistent different-principal peer session

Phase 9d collects value-free Phase 5h.1 peer five-facts from a live session
against the fixed LocalService denial pipe on the persistent boundary.

## Composition

1. **Native service-denial client** — `--self-test-pipe-client service-denial`
   with a fresh non-secret nonce. Requires the exact different-principal denial
   response schema (`authorization_denied=true`).
2. **Phase 5h.13 identity verifier** — `--verify-fixed-server-identity` must
   prove LocalService `TokenUser`, enabled service SID, and SCM PID match.
   Client-only `different_principal` bits are insufficient.
3. **Phase 9c target-ACL evidence** — `caller_write_denied` /
   `helper_write_allowed` become true only when the ACL matrix completed.

## Five-facts mapping

| Fact | True only when |
|---|---|
| `local_transport` | Service-denial client connected with exact schema |
| `identity_verified` | 5h.13 server identity fully verified |
| `different_principal` | Both of the above (LocalService peer, not console same-user) |
| `caller_write_denied` | 9c `all_targets_checked` and caller denied |
| `helper_write_allowed` | 9c `all_targets_checked` and helper allowed |

Absent pipe / console same-user hosts yield incomplete or
`same_principal_rejected` terminal codes and must not invent production peer
facts. Public reports always keep `authorization_ready=false` and
`operational_bridge_unwired=true`. Branded peer evidence is available for
Phase 9e wiring.

## Commands

```bash
npm run test:phase9d
npm run live:windows-persistent -- install    # elevated, separate approval
npm run live:windows-persistent-peer-session  # no UAC; may be ACL-incomplete
npm run live:windows-persistent -- uninstall
```

## Non-claims

- Does not set operational `authorization_ready` by itself (Phase 9e composes)
- Does not execute a vault-backed apply or place secrets on the helper pipe
- Helper remains vault-free; personal/company Bitwarden remain forbidden
- Same-user console denial is not a distinct principal
