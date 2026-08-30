# Linux laptop onboarding

Human quickstart for Linux. Product overview:
[README](../README.md) · [Features](features.md).

**Default:** from-source `setup:sm:wizard` → Secrets Manager same-user
(MiViA + private-hq). Token in an owner-only file under
`~/.config/BitwardenAgentCredentialBridge/`. No extra OS account.
systemd helper optional research.

**Agents / full import flow:**  
[`agent-linux-install.md`](agent-linux-install.md) ·  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md) ·  
[`sm-operational-key-naming.md`](sm-operational-key-naming.md)

## Quick start

1. Node.js 20+ and `bws` (`~/.local/bin/bws`, `/usr/local/bin/bws`, or PATH)
2. In Bitwarden SM: **new** machine account for this host + token; grant
   projects **MiViA** and **private-hq** (same projects as Windows/macOS,
   different machine account). Empty `project list` means the token works but
   the machine has no project access yet.
3. From the repo:

```bash
npm ci
npm run install:user-path
npm run setup:sm:wizard
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Paste the token only into the zenity/kdialog prompt (or the hidden TTY prompt
from `npm run setup:sm -- --i-approve-sm-machine-setup`). Cloud is default.
Do not paste the token into chat.

**Machine ID** is a local label, not the Bitwarden SM secret key. Prefer a
stable hostname, never an ISP DHCP fragment (`*.vodafone`). Rename later with:

```bash
npm run setup:sm:rename-id -- pc-your-label
```

Do **not** run `seed:sm --prune` if those SM projects already hold real keys
from another machine's import.

## Uninstall

```bash
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Also revoke the machine token in Bitwarden SM if this host should lose access.

## Optional

| Command | Purpose |
|---|---|
| `npm run start:operational` | Fake harness |
| `npm run live:sm-matrix` | All SM aliases smoke + exposure |
| `npm run bw-sm -- ask klicktipp --approve` | Agent-blind secret entry |
| `npm run live:sm-write -- …` | Agent-blind SM write |
