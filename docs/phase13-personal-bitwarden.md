# Phase 13: Personal Bitwarden → Agent (helper vault-free)

Operator-approved personal Bitwarden resolve for Windows agents. Secrets unlock
only in the Bridge/broker process under the interactive user. LocalService stays
vault-free. Company and organization vaults remain forbidden until a later
Phase 14 gate.

## What this phase adds

| Piece | Role |
|---|---|
| `src/personal-bitwarden-live-gate.mjs` | Branded scope: personal allowed, company/org forbidden |
| `src/personal-bitwarden-allow-config.mjs` | Machine-local digest allowlist |
| `src/personal-bitwarden-dpapi-collector.mjs` | DPAPI collect + digest match |
| `src/personal-bitwarden-resolver.mjs` | Injected adapter resolve under branded gate |
| `npm run live:personal-bitwarden` | Approval-flag CLI smoke |
| `npm run live:windows-laptop-ready` | Optional Day-2 + personal smoke |

## Operator setup (once per laptop)

1. Print the allowlist JSON for your personal Bitwarden account email:

```powershell
node scripts/print-personal-vault-email-digest.mjs you@example.com
```

2. Write that object to:

`%LOCALAPPDATA%\BitwardenAgentCredentialBridge\personal-vault.allow.json`

Schema example: `samples/personal-vault.allow.example.json` (never commit a
real digest file if it would identify your account in a public fork).

3. Create the DPAPI store once for this Windows user (Purpose must be
`bitwarden-agent-credential-bridge-personal-dpapi-v1`, basename
`bitwarden-agent-personal.credential.xml` under `~\.codex\secrets\`, with
`PersonalVaultAllowed=$true` and `CompanyVaultAllowed=$false`). Old-PC DPAPI
blobs do not migrate.

4. Smoke without printing secrets:

```powershell
npm run live:personal-bitwarden -- --i-approve-personal-bitwarden-agent-resolve
```

## Laptop-ready combo

```powershell
npm run live:windows-laptop-ready -- `
  --i-approve-persistent-install `
  --i-approve-personal-bitwarden-agent-resolve `
  --uninstall-after
```

Day-2 may set `authorization_ready=true` from branded Windows evidence.
Personal unlock never sets `authorization_ready`.

## Hard rules

- Approval flag is CLI-only, never a library capability
- Helper pipe remains vault-free
- Company / org / privateHQ still rejected
- Exposure surfaces must not contain plaintext secrets
- Forged gates and digest mismatches fail closed
