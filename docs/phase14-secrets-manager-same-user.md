# Phase 14/15: Secrets Manager — einfach

Kein Extra-Windows-User. Kein LocalService nötig. Token einmal einfügen.

**Agenten:** [`agent-windows-install.md`](agent-windows-install.md)  
**Installer:** GitHub Releases → `BitwardenAgentCredentialBridge-Setup-*.exe`

## Was ist `bws`?

Bitwarden Secrets Manager CLI. Bridge nutzt sie im Hintergrund; muss auf PATH
liegen (Installer prüft / weist hin).

## Setup

```powershell
npm run setup:sm -- --i-approve-sm-machine-setup
```

Windows: Kennwort-Fenster → Access Token einfügen.  
Cloud ist Default. Self-Host nur wenn du Custom-URLs setzt (Allowlist /
Wizard).

## Start / Write / Uninstall

```powershell
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
"value" | npm run live:sm-write -- --i-approve-secrets-manager-machine-write --project mivia --key my_key
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Produkt-Deinstall: Windows **Apps & Features**.
