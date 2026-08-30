# macOS laptop onboarding

Human quickstart for this Mac. Product overview:
[README](../README.md) · [Features](features.md).

**Default:** from-source `setup:sm:wizard` → Secrets Manager same-user
(MiViA + private-hq). Token in the login Keychain. No extra OS account.
LaunchDaemon optional research.

**Agents / full import flow:**  
[`agent-macos-install.md`](agent-macos-install.md) ·  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md) ·  
[`sm-operational-key-naming.md`](sm-operational-key-naming.md)

## Schnellstart (Nutzer)

1. Node.js 20+ and `bws` (`~/.local/bin/bws`, Homebrew, or Bitwarden SM CLI docs)
2. In Bitwarden SM: **new** machine account for this Mac + token; grant
   projects **MiViA** and **private-hq** (same projects as Windows, different
   machine account). Empty `project list` means the token works but the
   machine has no project access yet.
3. From the repo:

Do **not** run `npm run setup:sm:wizard` from `~`. From the repo, or after
`npm run install:macos-path`, run `setup-sm-wizard` from any directory.

```bash
npm ci
npm run install:macos-path
npm run setup:sm:wizard
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Copy the token, then paste with **Cmd-V** into the password prompt and
click **Save**. Cloud is default. Do not paste the token into chat.

**Machine ID** is a local label (Keychain account), not the Bitwarden SM
secret key. Use the Mac ComputerName, never the DHCP/ISP hostname
(`*.vodafone`). Example for this laptop: `pc-macbookm1-andrada`. If a
wizard already saved an ISP id:

```bash
npm run setup:sm:rename-id -- pc-macbookm1-andrada
```

Do **not** run `seed:sm --prune` if those SM projects already hold real keys
from the Windows import.

## Deinstallieren

```bash
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Also revoke the machine token in Bitwarden SM if this Mac should lose access.

## Optional

| Befehl | Zweck |
|---|---|
| `npm run start:operational` | Fake-Harness |
| `npm run live:sm-matrix` | Alle SM-Aliase smoke + Exposure |
| `npm run bw-sm -- ask klicktipp --approve` | Agent-blind secret entry (native dialog) |
| `npm run live:sm-write -- …` | Agent-blind SM write |
