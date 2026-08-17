# Phase 14/15: Secrets Manager — einfach

Kein Extra-Windows-User. Kein LocalService nötig. Token einmal einfügen.

Produktüberblick: [README](../README.md) · [Features](features.md).

**Onboarding + Import (Keys, Naming, Seed):**  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md)  
**Agenten:** [`agent-windows-install.md`](agent-windows-install.md)  
**Installer:** GitHub Releases → `BitwardenAgentCredentialBridge-Setup-*.exe`  
**Key-Namen:** [`sm-operational-key-naming.md`](sm-operational-key-naming.md)

## Was ist `bws`?

Bitwarden Secrets Manager CLI. Bridge nutzt sie im Hintergrund. Windows:
Default-Install unter `LocalAppData\Programs\Bitwarden\bws.exe` — PATH ist
nicht nötig, wenn diese Datei existiert. Fehlt `bws`, ist der Code
`bws_missing` (nicht `authorization_ready`).

## Setup

```powershell
npm run setup:sm:wizard
# oder: npm run setup:sm -- --i-approve-sm-machine-setup
```

Windows: Token-Fenster → Access Token einfügen.  
Cloud ist Default. Self-Host nur wenn du Custom-URLs setzt (Allowlist /
Wizard).

## Import (Repo → MiViA + private-hq)

Bindings: `samples/operational/bindings-sm.json`  
Jeder Eintrag sagt klar: welches SM-Projekt + welche Key-Namen + welche Klasse.

```powershell
npm run seed:sm -- --i-approve-secrets-manager-machine-write --prune --smoke --i-approve-secrets-manager-machine-resolve
```

## Start / Write / Uninstall

```powershell
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
"value" | npm run live:sm-write -- --i-approve-secrets-manager-machine-write --project private-hq --key phq_api_bearer
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Produkt-Deinstall: Windows **Apps & Features**.
