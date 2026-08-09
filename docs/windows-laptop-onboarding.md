# Windows laptop onboarding (operator runbook)

Use this on a **new Windows PC** to bring up the Agent Credential Bridge harness
and the Windows Day-2 authorization path. This is **not** personal/company
Bitwarden pairing and **not** a Mivia HQ / privateHQ vault sync into Codex.

## What this system does today

| Goal | Status |
|---|---|
| Fake/disposable credential brokers for agents | Ready (`start:operational`) |
| Windows LocalService writer boundary + `authorization_ready` | Ready (Day-2 operator) |
| Disposable Bitwarden smoke (`frederikstadler+bridge@gmail.com` via DPAPI) | Ready (separate live command) |
| Personal / company / org Bitwarden → agent passwords | **Forbidden** (AGENTS.md) |
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

## Step C — Disposable Bitwarden smoke (optional, not HQ vault)

Only the pinned disposable identity is allowed. DPAPI is **per Windows user
profile** — a new laptop does **not** inherit the old PC’s DPAPI blob. You must
have the fixed store file already present for this user, or recreate it under
the same operator-approved disposable procedure used on the first machine.

```powershell
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
```

Expect value-free booleans; `authorization_ready` stays false for this smoke.
Personal/company vaults are rejected.

## Before cloning privateHQ / Mivia HQ into Codex

Run this checklist on the new laptop **first**:

1. `npm run test:ci` green
2. `npm run start:operational` → `harness_ready=true`
3. Day-2 operator → live `authorization_ready=true` once
4. Optional disposable Bitwarden smoke if that store exists for this Windows user
5. Confirm you are **not** pointing the bridge at a personal/company vault

Only then mirror privateHQ / load Codex. Treat HQ credentials as **out of band**
until a future, separately reviewed live gate exists for org vaults (not in
this repo today).

## Honest path to your end goal

Desired end state: HQ accounts usable from agents on each PC (and later Mac),
synced via Bitwarden.

| Layer | How it works today | Gap |
|---|---|---|
| Bitwarden cloud sync of *your* vault | Bitwarden client on each PC | Outside this bridge |
| Agent-safe injection without printing secrets | Fake + disposable only | Org vault gate missing |
| Distinct writer (`authorization_ready`) | Windows live path ready | Mac/Linux live collectors pending |
| “Install once, passwords just work in Codex” | Not a shipped product yet | Needs explicit org-vault phase + review |

**Do not** put personal/company Bitwarden master passwords into DPAPI for agents
and claim it is this system’s supported path — AGENTS.md forbids it.

## Next actions (recommended order)

1. On the new Windows laptop: Steps A → B (this runbook).
2. Keep personal/HQ vaults in the normal Bitwarden app for humans.
3. Use this bridge for harness / disposable / authorized LocalService demos only.
4. When you want HQ-in-agents: open a dedicated milestone for **operator-approved
   org-scoped vault resolve** (separate from personal vaults), with exposure tests
   and no LocalService vault client — then re-review before privateHQ Codex use.
5. MacBook: follow `docs/phase11c-macos-disposable-denial-handoff.md` after Windows
   laptop validation.

## Commands cheat sheet

```powershell
npm ci
npm run test:ci
npm run start:operational
npm run live:windows-day2-operator -- --i-approve-persistent-install
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
npm run live:windows-persistent -- uninstall
```
