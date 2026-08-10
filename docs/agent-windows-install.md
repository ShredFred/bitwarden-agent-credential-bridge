# Agent instructions: install Bridge on Windows

Use this when the user says roughly: **clone this repo and install it** /
**make this PC ready for Bitwarden Secrets Manager agents**.

**Full onboarding + import (keys, naming, seed):**  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md)  
**Key naming:** [`sm-operational-key-naming.md`](sm-operational-key-naming.md)

## Goals

- Same-user Secrets Manager path (MiViA + private-hq by default)
- User ideally only pastes a **machine access token** once
- Repo bindings define which SM project/account each key belongs to
- No LocalService required for productive SM use
- Do **not** put tokens/secrets in chat logs or agent-visible env

## Do not bundle

- Do **not** silently install Codex or Bitwarden Desktop.
- If missing, tell the user to install them separately (or ask before downloading).

## Preferred path: GitHub Release installer

1. Open the latest GitHub Release for this repo.
2. Download `BitwardenAgentCredentialBridge-Setup-*.exe`.
3. Run the Setup EXE (UAC if prompted).
4. From Start Menu run **Bitwarden Agent Bridge Setup** (token window).
5. Cloud is default. Only if the user asks for self-host: enter custom server URLs in the wizard.
6. From a checkout (or installed scripts), seed/import operational keys from the repo bindings, then start the bridge — see [`sm-onboarding-and-import.md`](sm-onboarding-and-import.md).
7. Uninstall later via Windows **Apps & features** (not only terminal).

## From-source path (dev / no Release yet)

```powershell
git clone https://github.com/ShredFred/bitwarden-agent-credential-bridge.git
cd bitwarden-agent-credential-bridge
git checkout main
npm ci
# Ensure Bitwarden Secrets Manager CLI `bws` is on PATH (pin per docs).
npm run setup:sm:wizard
# Import keys named from samples/operational/bindings-sm.json into MiViA + private-hq
npm run seed:sm -- --i-approve-secrets-manager-machine-write --prune --smoke --i-approve-secrets-manager-machine-resolve
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

## Before setup (Bitwarden SM, human once)

1. Create a **machine account** for this PC in Bitwarden Secrets Manager.
2. Grant projects **MiViA** and **private-hq**.
3. Create an access token; user pastes it into the setup window only.

## Uninstall

- **Installed product:** Windows Settings → Apps → Bitwarden Agent Credential Bridge → Uninstall  
  (also clears local token/allowlist best-effort).
- **From-source only:**

```powershell
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Also revoke the machine token in Bitwarden SM if the PC should lose access.

## Hard rules for agents

- Never echo or log the access token or secret values.
- Never set `BWS_ACCESS_TOKEN` in the user/agent environment for general use.
- Never claim `authorization_ready=true` from SM setup alone.
- LocalService Day-2 install is optional and separate.
- Follow [`sm-onboarding-and-import.md`](sm-onboarding-and-import.md) when adding or importing service keys.
