# Phase 8: Operational disposable/dev multi-service bridge

Phase 8 adds a foreground operator profile for day-to-day disposable/dev use of
the supported auth contracts. It is **not** company-HQ production authorization.

## Readiness taxonomy

| Flag | Meaning |
|---|---|
| `harness_ready` | Bound fake policies validated; brokers started; smoke passed |
| `disposable_dev_ready` | Separate DPAPI disposable smoke passed (`live:disposable-bitwarden`) |
| `authorization_ready` | From Phase 9e → Phase 9a only; default incomplete evidence stays `false` |

## Commands

```bash
npm run test:phase8
npm run start:operational
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
```

`start:operational` loads `samples/operational/bindings.json`, starts the bound
HTTP and session brokers with fake vault secrets, prints value-free status
JSON, then waits for Ctrl+C. SM-backed start is
`npm run start:operational:sm` (Phase 14). The Bridge-owned browser
(`startBridgeOwnedBrowser`) is a separate Phase 17 runtime, not this auto-login
session broker.

## Binding rules

- Policies must live under `policies/*.json`
- Alias, policy path, and `credential_class` must match atomically
- Rejected classes (`oauth`, MFA/SMS/email, `env_inject`) fail closed.
  SSH/FTP are dedicated session brokers (Phase 16), never `env_inject`.
- DPAPI disposable password is never reused across multiple aliases

## Non-claims

- Not personal/company Bitwarden pairing
- Not PID-file multi-process supervision
- Not LocalService writer production readiness
- Not OAuth/MFA issuance
