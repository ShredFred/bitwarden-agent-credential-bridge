# Windows laptop onboarding

**Default:** Windows Setup EXE or guided `setup:sm` → Secrets Manager same-user
(MiViA + private-hq). No extra OS account. LocalService optional.

**Agents / full import flow:**  
[`agent-windows-install.md`](agent-windows-install.md) ·  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md) ·  
[`sm-operational-key-naming.md`](sm-operational-key-naming.md)

## Schnellstart (Nutzer)

1. Codex installieren (extern, falls gewünscht)
2. In Bitwarden SM: Machine Account + Token; Projekte MiViA + private-hq
3. Entweder Release-Setup EXE **oder**:

```powershell
npm ci
npm run setup:sm:wizard
npm run seed:sm -- --i-approve-secrets-manager-machine-write --prune --smoke --i-approve-secrets-manager-machine-resolve
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Self-Host-URLs nur wenn nötig (nicht Default) — siehe Phase-14-Doku / Setup-Wizard.

Keys liegen im passenden SM-Projekt und heißen `{projekt}_{dienst}_{rolle}`
(z.B. `phq_web_user`). Details: Onboarding-/Import-Doku oben.

## Deinstallieren

- Apps & Features (wenn per Installer installiert), oder  
  `npm run uninstall:sm -- --i-approve-sm-machine-uninstall`

## Optional

| Befehl | Zweck |
|---|---|
| `npm run start:operational` | Fake-Harness |
| `npm run live:sm-matrix` | Alle SM-Aliase smoke + Exposure |
| `npm run live:windows-day2-operator -- --i-approve-persistent-install` | LocalService-Grenze |
| `npm run live:sm-write -- …` | Agent-blind SM write |
