# Phase 15: Windows product installer

## Build (maintainer)

1. Install [Inno Setup 6](https://jrsoftware.org/isinfo.php) (`ISCC.exe` on PATH).
2. From repo root on Windows:

```powershell
New-Item -ItemType Directory -Force dist\installer | Out-Null
& "${env:LocalAppData}\Programs\Inno Setup 6\ISCC.exe" installer\windows\bridge-sm.iss
```

Output: `dist/installer/BitwardenAgentCredentialBridge-Setup-0.1.0.exe`

## Release

GitHub Actions workflow `.github/workflows/windows-installer-release.yml` builds
on tag `v*` and uploads the Setup EXE.

## User journey

Product overview: [README](../README.md) · [Features](features.md).

1. Install Node.js 20+ (required; not bundled).
2. Install `bws` (Bitwarden Secrets Manager CLI); PATH optional if it lives at
   `%LOCALAPPDATA%\Programs\Bitwarden\bws.exe`.
3. Run Setup EXE → Start Menu **Setup Bridge** → paste machine token.
4. Cloud default; optional self-host URL in the wizard.
5. **Start Bridge** from Start Menu.
6. Uninstall via Apps & Features (also clears local SM token/allowlist).

## Agent journey

See [`agent-windows-install.md`](agent-windows-install.md).

## macOS

Not in this slice — use from-source `setup:sm` / Phase 14 docs until a pkg handoff.
