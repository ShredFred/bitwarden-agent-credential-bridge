# Phase 14: Secrets Manager — einfach

Du brauchst **keinen** Extra-Windows-User und **keinen** LocalService.
Ein Machine-Access-Token einmal einfügen reicht.

## Was ist `bws`?

Das Bitwarden-Secrets-Manager-Kommandozeilen-Tool. Die Bridge nutzt es im
Hintergrund. Du musst es nur einmal installieren und auf `PATH` haben.

## Einmal-Setup (geführt)

1. In Bitwarden SM: Machine Account für diesen PC anlegen  
2. Projekte **MiViA** + **private-hq** dem Machine Account geben  
3. Access Token erzeugen und bereithalten  
4. Hier:

```powershell
npm run setup:sm -- --i-approve-sm-machine-setup
```

- Windows öffnet ein **Kennwort-Fenster** → Token als Passwort einfügen  
- MiViA + private-hq sind schon vorausgewählt  
- Token landet nur lokal (DPAPI), nie im Git

## Starten (lesen / Agent ohne Klartext)

```powershell
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

## Schreiben (ohne dass der Agent den Wert sieht)

Wert nur über stdin, Ausgabe nur `ok` / `created|updated`:

```powershell
# Beispiel: Secret anlegen/aktualisieren
"mein-geheimes-passwort" | npm run live:sm-write -- --i-approve-secrets-manager-machine-write --project mivia --key mivia_demo_bearer
```

`--project` darf `mivia`, `private-hq` oder eine UUID sein.

## Deinstallieren (lokal, nahtlos)

```powershell
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Löscht Allowlist + Token-Store auf diesem PC.  
Token in Bitwarden SM zusätzlich **revoke**, wenn der PC keinen Zugriff mehr haben soll.

## Hard rules

- Approval-Flags nur an der CLI  
- Kein `BWS_ACCESS_TOKEN` in Agent-Umgebungen  
- Helper/LocalService bleibt vault-free  
- `authorization_ready` wird durch SM nicht auf true gesetzt  
