# Phase 10b: Windows authorization-ready bootstrap

Phase 10b adds an operator bootstrap that can exit with
`authorization_ready=true` only when branded Phase 9e compose reports that
value from live (or injected) 9b/9c/9d evidence. The boolean is never hardcoded.

## What it does

1. Optionally runs the elevated persistent LocalService install
   (`--i-approve-persistent-install`).
2. Collects handle-bound identity, target-ACL, and peer five-facts.
3. If target-ACL evidence is incomplete and collectors did not fail closed,
   attempts one vault-free LocalService first-install apply
   (`--self-test-pipe-client service-apply`) that creates the five ProgramData
   targets when absent.
4. Re-collects and recomposes. Exit 0 only when `authorization_ready===true`.
5. Optionally wires the operational bridge and/or enters the Phase 10a refresh
   loop; optional `--uninstall-after` cleans the persistent service.

## Commands

```bash
npm run test:phase10b
npm run live:windows-authorization-ready -- --i-approve-persistent-install
npm run live:windows-authorization-ready -- --i-approve-persistent-install --with-operational-bridge
npm run live:windows-authorization-ready -- --uninstall-after
```

## Non-goals

- No personal/company Bitwarden pairing
- No vault client inside LocalService
- No OAuth/MFA/SSH/`env_inject`
- No claim of same-user memory isolation against a malicious agent
- `mutation_authorized` stays false; disposable/dev readiness is separate

## Honest readiness

`authorization_ready=true` means the in-process production authorization
compiler accepted complete branded Windows evidence for the fixed LocalService
helper layout. It does not authorize persistent mutation of arbitrary roots or
production writer isolation beyond what Phase 9 documents.
