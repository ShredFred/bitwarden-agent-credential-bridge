# Agent Credential Bridge

**Give an AI agent the *use* of a secret — never the secret itself.**

A fail-closed credential broker for coding agents. The agent asks to call an
allowed API, log into a form, or run a pinned SSH/FTP op. The Bridge injects
the credential at the outbound boundary. Passwords, tokens, cookies, and
session material stay in Bridge memory. If they leak onto an agent-readable
surface, tests fail.

> Experimental software. Not affiliated with, endorsed by, or supported by
> Bitwarden. Not a production password manager, and not a claim that
> same-user process isolation is a production writer boundary.

[Install on Windows](#install-on-windows) ·
[Install on macOS](#install-on-macos) ·
[Install on Linux](#install-on-linux) ·
[What you get](#what-you-get) ·
[For agents](#for-agents) ·
[Honest limits](#honest-limits)

---

## Why this exists

Agents are extraordinary at using tools and terrible at keeping secrets.
Paste an API key into chat once and it lives in logs, transcripts, screenshots,
and the next model's context window.

This project inverts that:

| The agent may | The agent never gets |
| --- | --- |
| Call a policy-pinned HTTP route | The bearer token, API key, or Basic password |
| Pick login fields by **index** | CSS/XPath, cookies, CDP, or the password value |
| Replay an opaque session on allow-listed paths | `Set-Cookie`, storage state, or `eval` |
| Exec a pinned SSH/FTP op on loopback | Process-environment injection (`env_inject`) |

The operator pastes a Bitwarden Secrets Manager **machine token** once, into a
local setup window. After that, agents work. Secrets do not.

## What you get

### Productive same-user path (Windows, macOS, and Linux)

- **Windows:** GitHub Release installer with Start Menu setup, start, and
  Apps & Features uninstall. Token in DPAPI.
- **macOS:** from-source wizard (`npm run setup:sm:wizard`). Token in the
  same-user Keychain. Signed `.pkg` remains a later slice.
- **Linux:** from-source wizard (`npm run setup:sm:wizard`, zenity/kdialog or
  a hidden TTY prompt). Token in an owner-only `0600` file under XDG config.
  Distro packages remain a later slice.
- **Bitwarden Secrets Manager** as the default vault: machine account, project
  allowlist. Cloud by default; optional self-host URLs.
- **No extra OS user** and **no LocalService / LaunchDaemon / systemd helper
  required** for day-to-day SM resolve. Distinct-writer install remains
  optional research.
- Guided import of local DPAPI / `.env` material into SM (Windows; dry-run
  default). macOS and Linux consume the same SM projects after a machine-account
  grant.

### Credential classes that actually run

| Class | What the Bridge does |
| --- | --- |
| HTTP bearer / API-key header / Basic / query | Injects exactly one outbound credential; strips caller forgeries |
| Browser form-login | Logs in from memory; agent sees an opaque session, not the cookie |
| Bridge-owned browser | Agent is the *eyes* (field indices, plus screenshots except during password fill). Bridge is the *hands* for secrets. Optional in-process Playwright adapter (not a package dependency; headless default). Never agent CDP |
| SSH / FTP (loopback) | Dedicated session brokers, allow-listed ops, no `env_inject` |

Unsupported on purpose, and they fail closed: OAuth, interactive MFA, SMS,
email codes, and process-environment injection.

### Security posture you can show a reviewer

- Policies are **allow-lists**, not template languages. Placeholders only —
  never values.
- Every runtime secret is scanned in raw, percent, form, Base64, and Base64url
  forms across responses, logs, and errors.
- One writer at a time. MFA/CAPTCHA terminate with value-free codes, not HTML.
- `authorization_ready` is evidence-driven. Unlocking SM does **not** set it
  true. The helper process stays vault-free.

```mermaid
flowchart LR
  Agent["Calling agent"] -->|"Allowed request only"| Bridge["Bridge / broker"]
  SM["Bitwarden Secrets Manager<br/>or fake vault"] --> Bridge
  Bridge -->|"One policy-pinned injection"| Upstream["API / login / session"]
  Upstream -->|"Sanitized response"| Bridge
  Bridge -->|"No plaintext secret"| Agent
```

## Install on Windows

1. Install [Node.js 20+](https://nodejs.org/) and the
   [Bitwarden Secrets Manager CLI (`bws`)](https://bitwarden.com/help/secrets-manager-cli/).
2. In Bitwarden SM: create a **machine account**, grant your projects, create an
   access token. Do not paste it into chat.
3. Download `BitwardenAgentCredentialBridge-Setup-*.exe` from GitHub Releases
   when a release exists, or clone this repo and run `npm run setup:sm:wizard`.
4. Start Menu → **Bitwarden Agent Bridge Setup** → paste the token locally.
5. Seed bindings, then start:

```powershell
npm run seed:sm -- --i-approve-secrets-manager-machine-write --prune --smoke --i-approve-secrets-manager-machine-resolve
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Human walkthrough: [Windows laptop onboarding](docs/windows-laptop-onboarding.md) ·
[SM onboarding and import](docs/sm-onboarding-and-import.md)

Uninstall via **Apps & Features**, or `npm run uninstall:sm -- --i-approve-sm-machine-uninstall`.

## Install on macOS

1. Install [Node.js 20+](https://nodejs.org/) and the
   [Bitwarden Secrets Manager CLI (`bws`)](https://bitwarden.com/help/secrets-manager-cli/)
   (`~/.local/bin/bws`, `/opt/homebrew/bin/bws`, `/usr/local/bin/bws`, or PATH).
2. In Bitwarden SM: create a **machine account for this Mac**, grant **MiViA**
   and **private-hq**, create an access token. Do not paste it into chat. Do
   not reuse the Windows machine token.
3. From a clone of this repo:

```bash
npm run setup:sm:wizard
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Do **not** run `seed:sm --prune` against projects that already hold real
HQ/MiViA keys. The Windows import already wrote those secrets; this Mac only
needs project access.

Human walkthrough: [macOS laptop onboarding](docs/macos-laptop-onboarding.md) ·
[SM onboarding and import](docs/sm-onboarding-and-import.md)

Uninstall: `npm run uninstall:sm -- --i-approve-sm-machine-uninstall` (clears
allowlist + Keychain item). Revoke the machine token in Bitwarden SM if the
Mac should lose access.

A signed `.pkg` installer is a later slice.

## Install on Linux

1. Install [Node.js 20+](https://nodejs.org/) and the
   [Bitwarden Secrets Manager CLI (`bws`)](https://bitwarden.com/help/secrets-manager-cli/)
   (`~/.local/bin/bws`, `/usr/local/bin/bws`, `/usr/bin/bws`, or PATH).
2. In Bitwarden SM: create a **machine account for this host**, grant **MiViA**
   and **private-hq**, create an access token. Do not paste it into chat. Do
   not reuse the Windows or macOS machine token.
3. From a clone of this repo:

```bash
npm ci
npm run install:user-path
npm run setup:sm:wizard
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Do **not** run `seed:sm --prune` against projects that already hold real
HQ/MiViA keys. This host only needs project access.

Human walkthrough: [Linux laptop onboarding](docs/linux-laptop-onboarding.md) ·
[SM onboarding and import](docs/sm-onboarding-and-import.md)

Uninstall: `npm run uninstall:sm -- --i-approve-sm-machine-uninstall` (clears
allowlist + owner-only token file). Revoke the machine token in Bitwarden SM
if the host should lose access.

A `.deb` / `.rpm` package is a later slice.

## For agents

If you are an AI agent pointed at this repo, start here — not at the research
phase list:

1. [Install on Windows (agent runbook)](docs/agent-windows-install.md),
   [Install on macOS (agent runbook)](docs/agent-macos-install.md), or
   [Install on Linux (agent runbook)](docs/agent-linux-install.md)
2. [SM onboarding and import](docs/sm-onboarding-and-import.md)
3. [Experiment rules](AGENTS.md)
4. [Bridge-owned browser contract](docs/phase17-bridge-owned-browser.md)
   (`npm run start:browser:sm`)

Never echo tokens. Never set `BWS_ACCESS_TOKEN` in the user environment.
Never claim `authorization_ready=true` from SM setup alone. Missing `bws` is
`bws_missing`, not an authorization failure.

## Honest limits

- **Experimental.** Contracts are real; production isolation is not claimed.
- **Not affiliated with Bitwarden.** You bring your own SM machine account.
- **Loopback-first.** Public sites such as `traffic.mivia.ai` need a later
  explicit live gate. Agent Playwright-CLI, Chrome extensions, and agent CDP
  are not the secret path.
- **No cookie export.** If a task needs the cookie, use an HTTP broker or stop.
- **No screenshots during password fill.** `GET /screenshot` is allowed before
  and after login as raw `image/png` (not JSON). `inject_login` and occupied
  password fields return `password_entry_active`. The `fetch` driver cannot
  screenshot.
- **No MFA solving.** Challenge pages fail closed.
- Platform writer isolation (Windows LocalService, macOS LaunchDaemon, Linux
  systemd) is a documented research ladder, not a prerequisite for SM resolve.

Full capability map: [Features](docs/features.md).  
Phase-by-phase research index: [Research status](docs/research-status.md).

## Requirements

- Node.js 20+ (default tests are standard-library only — no npm runtime
  dependencies). Playwright is optional and **not** a package dependency:
  the repo ships a small page adapter, not a browser. Default driver is
  `fetch`. Install Playwright yourself only if you want `--driver playwright`.

```bash
npm test
node src/run-demo.js
```

`run-demo.js` generates a fake sentinel, drives the loopback broker, and exits
non-zero if that sentinel appears on any agent-readable surface.

## Contributing

- **Issues** — reproducible bugs and bounded work.
- **Discussions** — architecture and early ideas.
- **Pull requests** — tested, narrow, with a security-boundary note.
- **Private vulnerability reporting only** for suspected security issues.

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SUPPORT.md](SUPPORT.md), and [Architecture](docs/architecture.md).

## Funding

If this is useful, you can support maintenance on
[Buy Me a Coffee](https://buymeacoffee.com/shredfred).

## License

[Apache-2.0](LICENSE). This aligns with upstream Bitwarden Agent Access / OneCLI
licensing for research references only. This repository does not ship their
source, claim compatibility, or imply endorsement. See
[Licensing](docs/licensing.md).

Publication review: [publication-review.md](docs/publication-review.md).
The [public release checklist](docs/public-release-checklist.md) remains the
gate for later releases.
