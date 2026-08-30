# Agent instructions: install Bridge on Linux

Use this when the user says roughly: **set up the Bridge on this Linux box** /
**make this machine ready for Bitwarden Secrets Manager agents**.

**Full onboarding + import (keys, naming, seed):**  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md)  
**Key naming:** [`sm-operational-key-naming.md`](sm-operational-key-naming.md)  
**Windows / macOS twins:** [`agent-windows-install.md`](agent-windows-install.md) ·
[`agent-macos-install.md`](agent-macos-install.md)

## Goals

- Same-user Secrets Manager path (MiViA + private-hq by default)
- User pastes a **machine access token** once (owner-only `0600` file under
  `~/.config/BitwardenAgentCredentialBridge/`)
- Repo bindings define which SM project/account each key belongs to
- No systemd helper / extra OS user required for productive SM use
- Do **not** put tokens/secrets in chat logs or agent-visible env

## Do not bundle

- Do **not** silently install Codex, distro packages, or Bitwarden Desktop.
- If `bws` or Node is missing, tell the user to install them separately.
- A `.deb` / `.rpm` / Flatpak installer is a later slice.

## From-source path

```bash
git clone https://github.com/ShredFred/bitwarden-agent-credential-bridge.git
cd bitwarden-agent-credential-bridge
git checkout main
npm ci
# bws: PATH, ~/.local/bin/bws, /usr/local/bin/bws, or /usr/bin/bws
npm run install:user-path
npm run setup:sm:wizard
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Do **not** run `seed:sm --prune` against projects that already hold real
HQ/MiViA secrets from another machine. This Linux host only needs a **new**
machine account with access to those projects.

`setup:sm:wizard` uses zenity/kdialog when a display is present. Headless
hosts can use `npm run setup:sm -- --i-approve-sm-machine-setup` (hidden TTY
prompt). `--self-test` never uses a live token.

## Before setup (Bitwarden SM, human once)

1. Create a **machine account for this Linux host** (not the Windows or Mac
   token).
2. Grant projects **MiViA** and **private-hq**.
3. Create an access token; user pastes it into the setup window or TTY only.

## Uninstall

```bash
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Also revoke the machine token in Bitwarden SM if the host should lose access.

## Hard rules for agents

- Never echo or log the access token or secret values.
- Never set `BWS_ACCESS_TOKEN` in the user/agent environment for general use.
- Never claim `authorization_ready=true` from SM setup alone.
- Missing `bws` is `bws_missing`. `authorization_ready: false` is writer
  evidence and does not mean the SM CLI failed.
- Follow [`sm-onboarding-and-import.md`](sm-onboarding-and-import.md) when
  adding service keys. Use `bw-sm ask` (zenity/kdialog), never chat paste.
- systemd distinct-writer research is optional and not required for SM resolve.

## Browser (agent-blind)

```bash
npm run start:browser:sm -- --i-approve-secrets-manager-machine-resolve --i-approve-bridge-owned-browser --alias phq_web
```

Default is the fast `fetch` driver. See
[`phase17-bridge-owned-browser.md`](phase17-bridge-owned-browser.md).
