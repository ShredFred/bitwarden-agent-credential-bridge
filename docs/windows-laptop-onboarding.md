# Windows laptop onboarding

**Default:** Windows Setup EXE or guided `setup:sm` → Secrets Manager same-user
(MiViA + private-hq). No extra OS account. LocalService optional.

Agents: follow [`agent-windows-install.md`](agent-windows-install.md).

## Schnellstart (Nutzer)

1. Codex installieren (extern, falls gewünscht)
2. In Bitwarden SM: Machine Account + Token; Projekte MiViA + private-hq
3. Entweder Release-Setup EXE **oder**:

```powershell
npm ci
npm run setup:sm -- --i-approve-sm-machine-setup
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Self-Host-URLs nur wenn nötig (nicht Default) — siehe Phase-14-Doku / Setup-Wizard.

## Deinstallieren

- Apps & Features (wenn per Installer installiert), oder  
  `npm run uninstall:sm -- --i-approve-sm-machine-uninstall`

## Optional

| Befehl | Zweck |
|---|---|
| `npm run start:operational` | Fake-Harness |
| `npm run live:windows-day2-operator -- --i-approve-persistent-install` | LocalService-Grenze |
| `npm run live:sm-write -- …` | Agent-blind SM write |
