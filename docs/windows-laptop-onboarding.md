# Windows laptop onboarding

**Default:** same-user Secrets Manager (MiViA + private-hq).  
Kein Extra-Account. LocalService optional/später.

## Schnellstart

```powershell
git clone https://github.com/ShredFred/bitwarden-agent-credential-bridge.git
cd bitwarden-agent-credential-bridge
git checkout main
npm ci

# 1) bws installieren (Bitwarden Secrets Manager CLI) und auf PATH legen
# 2) In Bitwarden SM: Machine Account + Token; Projekte MiViA + private-hq zuweisen

npm run setup:sm -- --i-approve-sm-machine-setup
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Details: [`phase14-secrets-manager-same-user.md`](phase14-secrets-manager-same-user.md)

## Schreiben / Deinstallieren

```powershell
"secret-value" | npm run live:sm-write -- --i-approve-secrets-manager-machine-write --project mivia --key my_key
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

## Optional

| Befehl | Zweck |
|---|---|
| `npm run start:operational` | Fake-Harness ohne Bitwarden |
| `npm run live:windows-day2-operator -- --i-approve-persistent-install` | Härtere LocalService-Grenze |
| `npm run live:personal-bitwarden -- --i-approve-personal-bitwarden-agent-resolve` | Persönlicher PM-Pfad (Phase 13) |
