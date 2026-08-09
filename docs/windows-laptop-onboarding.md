# Windows laptop onboarding (operator runbook)

Use this on a **new Windows PC** to bring up the productive **same-user Secrets
Manager** path (MiViA + private-hq) without extra OS accounts and without a
vault client in LocalService. Day-2 LocalService authorization remains an
**optional** harder boundary.

## What this system does today

| Goal | Status |
|---|---|
| Fake/disposable credential brokers for agents | Ready (`start:operational`) |
| **Secrets Manager same-user resolve (MiViA / private-hq)** | Ready (Phase 14, approval flag) |
| Personal Bitwarden PM → agent (Bridge process) | Ready behind Phase 13 flag |
| Windows LocalService writer + `authorization_ready` | Optional Day-2 path |
| Extra interactive OS user accounts | **Not required / not used** |
| Vault client inside LocalService | **Forbidden** |
| Auto-sync every HQ password into Codex after clone | Needs binding table + SM keys |

## Prerequisites (new laptop)

1. Windows 11 (admin only if you later choose Day-2 service install)
2. Git, Node.js matching the repo, `bws` (Bitwarden Secrets Manager CLI) on PATH
3. Clone (do **not** push secrets):

```powershell
git clone https://github.com/ShredFred/bitwarden-agent-credential-bridge.git
cd bitwarden-agent-credential-bridge
git checkout main
npm ci
```

## Default path — same-user SM (no LocalService)

Follow [`docs/phase14-secrets-manager-same-user.md`](phase14-secrets-manager-same-user.md):

1. Create a machine account for this PC; grant **MiViA** and **private-hq**
2. Store the access token in the DPAPI SM store
3. Write `sm-machine.allow.json` with both project UUIDs
4. Align secret keys with `samples/operational/bindings-sm.example.json` (copy/edit under `samples/` if needed)
5. Run:

```powershell
npm run test:ci
npm run live:sm-machine -- --i-approve-secrets-manager-machine-resolve
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Expect: brokers start, smoke OK, **no** tokens/secrets printed,
`authorization_ready=false` unless you separately complete Day-2 evidence.

Repeat the same machine-account + token + allowlist setup on the desktop and
the private Mac (macOS uses the token file path in the Phase 14 doc).

## Optional — harness-only smoke (fake secrets)

```powershell
npm run start:operational
```

## Optional — Day-2 LocalService (`authorization_ready`)

Only if you want the harder writer boundary later:

```powershell
npm run live:windows-day2-operator -- --i-approve-persistent-install --interval-ms=15000
```

This does **not** put SM tokens or secrets into LocalService.

## Optional — personal Password Manager path (Phase 13)

See Phase 13 docs / Step D in older notes. Separate from SM machine tokens.

## Commands cheat sheet

```powershell
npm ci
npm run test:ci
npm run start:operational
npm run live:sm-machine -- --i-approve-secrets-manager-machine-resolve
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
npm run live:personal-bitwarden -- --i-approve-personal-bitwarden-agent-resolve
npm run live:windows-day2-operator -- --i-approve-persistent-install
```
