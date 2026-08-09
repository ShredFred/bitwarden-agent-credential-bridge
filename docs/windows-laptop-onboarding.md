# Windows laptop onboarding (operator runbook)

Use this on a **new Windows PC** to bring up the Agent Credential Bridge harness,
the Windows Day-2 authorization path, and (optionally) **personal** Bitwarden
resolve under an explicit approval flag. Company / org / privateHQ vaults remain
forbidden until Phase 14. LocalService stays vault-free.

## What this system does today

| Goal | Status |
|---|---|
| Fake/disposable credential brokers for agents | Ready (`start:operational`) |
| Windows LocalService writer boundary + `authorization_ready` | Ready (Day-2 operator) |
| Disposable Bitwarden smoke (`frederikstadler+bridge@gmail.com` via DPAPI) | Ready (separate live command) |
| Personal Bitwarden → agent (Bridge process only) | Ready behind Phase 13 approval flag |
| Company / org / privateHQ Bitwarden → agent | **Forbidden** (Phase 14 later) |
| Auto-sync HQ accounts into Codex on every PC | **Not built** |
| macOS parity live path | Pure compilers ready; Mac live handoff pending |

## Prerequisites (new laptop)

1. Windows 11, admin rights for UAC service install
2. Git
3. Node.js 24.x (LTS matching the repo)
4. .NET SDK **8.0.423** (pinned helper toolchain)
5. Clone this repo (do **not** push secrets):

```powershell
git clone https://github.com/ShredFred/bitwarden-agent-credential-bridge.git
cd bitwarden-agent-credential-bridge
git checkout main
npm ci
```

## Step A — Harness smoke (no elevation, no Bitwarden)

```powershell
npm run test:ci
npm run start:operational
```

Expect: `harness_ready=true`, `authorization_ready=false` (no persistent helper yet).
Ctrl+C to stop.

## Step B — Windows Day-2 authorization (elevated once)

```powershell
npm run live:windows-day2-operator -- --i-approve-persistent-install --interval-ms=15000
```

Approve UAC. Expect JSON with `authorization_ready=true` and
`terminal_code=production_authorization_ready`. Leave it running for Day-2, or
Ctrl+C to stop the bridge/refresh (service stays installed unless you uninstall).

Uninstall when done testing:

```powershell
npm run live:windows-persistent -- uninstall
```

## Step C — Disposable Bitwarden smoke (optional)

Only the pinned disposable identity is allowed. DPAPI is **per Windows user
profile** — a new laptop does **not** inherit the old PC’s DPAPI blob.

```powershell
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
```

Expect value-free booleans; `authorization_ready` stays false for this smoke.

## Step D — Personal Bitwarden (Phase 13, optional)

Unlock and resolve stay in the **Bridge/broker** process. The LocalService helper
never receives vault secrets.

1. Digest your personal account email (identity, not a password):

```powershell
node scripts/print-personal-vault-email-digest.mjs you@example.com
```

2. Save the JSON to
`%LOCALAPPDATA%\BitwardenAgentCredentialBridge\personal-vault.allow.json`
(see `samples/personal-vault.allow.example.json`).

3. Create the personal DPAPI store once for this Windows user
(`~\.codex\secrets\bitwarden-agent-personal.credential.xml`, Purpose
`bitwarden-agent-credential-bridge-personal-dpapi-v1`,
`PersonalVaultAllowed=$true`, `CompanyVaultAllowed=$false`). Details:
`docs/phase13-personal-bitwarden.md`.

4. Smoke:

```powershell
npm run live:personal-bitwarden -- --i-approve-personal-bitwarden-agent-resolve
```

Expect `live_secret_resolved=true`, `authorization_ready=false`,
`company_vault_forbidden=true`, `helper_vault_free=true`. No password printed.

### Combined laptop-ready entry

```powershell
npm run live:windows-laptop-ready -- `
  --i-approve-persistent-install `
  --i-approve-personal-bitwarden-agent-resolve `
  --uninstall-after
```

Day-2 authorization and personal resolve are separate: vault unlock never
sets `authorization_ready`.

## Before cloning privateHQ / Mivia HQ into Codex

1. `npm run test:ci` green
2. `npm run start:operational` → `harness_ready=true`
3. Day-2 operator → live `authorization_ready=true` once
4. Optional personal Bitwarden smoke (Phase 13) if you need personal items
5. Confirm you are **not** pointing the bridge at a company/org vault

HQ / privateHQ org resolve is still out of band until Phase 14.

## Honest path to your end goal

| Layer | How it works today | Gap |
|---|---|---|
| Bitwarden cloud sync of *your* vault | Bitwarden client on each PC | Outside this bridge |
| Agent-safe personal injection | Phase 13 Bridge resolve + DPAPI | Binding table per alias still operator-driven |
| Distinct writer (`authorization_ready`) | Windows live path ready | Mac/Linux live collectors pending |
| Company / org / privateHQ in agents | Forbidden | Needs Phase 14 gate + review |

**Do not** put a vault client in LocalService. **Do not** treat company/org
stores as Phase 13 personal.

## Next actions (recommended order)

1. On the new Windows laptop: Steps A → B, then D if personal resolve is needed.
2. Keep company/HQ vaults in the normal Bitwarden app until Phase 14.
3. MacBook: follow `docs/phase11c-macos-disposable-denial-handoff.md` after Windows
   laptop validation.

## Commands cheat sheet

```powershell
npm ci
npm run test:ci
npm run start:operational
npm run live:windows-day2-operator -- --i-approve-persistent-install
npm run live:personal-bitwarden -- --i-approve-personal-bitwarden-agent-resolve
npm run live:windows-laptop-ready -- --i-approve-persistent-install --i-approve-personal-bitwarden-agent-resolve
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
npm run live:windows-persistent -- uninstall
```
