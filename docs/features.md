# Features

A human-facing map of what the Bridge can do today, what it refuses, and what
is still research. Agent runbooks live separately:
[agent Windows install](agent-windows-install.md),
[agent macOS install](agent-macos-install.md),
[agent Linux install](agent-linux-install.md), [AGENTS.md](../AGENTS.md).

## Available now

### Operator experience

- Windows Setup EXE from GitHub Releases, Start Menu **Setup** / **Start**,
  Apps & Features uninstall.
- macOS from-source wizard (`npm run setup:sm:wizard`); signed `.pkg` later.
- Linux from-source wizard (`npm run setup:sm:wizard`, zenity/kdialog or TTY);
  distro packages later.
- One local paste of a Bitwarden Secrets Manager machine token (Windows DPAPI,
  macOS Keychain, or Linux owner-only `0600` file). Cloud SM is the default;
  self-host URLs are optional.
- Machine-local project allowlist. Tokens never belong in git, chat, or
  `process.env`.
- Guided local DPAPI / `.env` → SM import (dry-run default; apply behind an
  explicit write flag). Local purge is a later dedicated gate.
- Canonical MiViA + private-hq bindings and key naming, with idempotent seed
  and prune.

### Agent-blind credential use

- **HTTP** — bearer, API-key header, HTTP Basic, API-key query. Exactly one
  outbound injection. Caller forgeries are stripped. Redirects fail closed.
  Response bodies are bounded and scanned.
- **Browser form-login** — dedicated session broker (not the HTTP header
  broker). Opaque session id; allow-listed replay paths; cookies stay in the
  jar.
- **Bridge-owned browser** — the agent snapshots value-free field **indices**
  and calls `inject_login` with an empty body. Optional in-process Playwright
  driver (not a package dependency; headless by default, `--headed` for a
  visible window); page, CDP, and cookies never appear on the session handle.
  Screenshots are allowed except during password fill.
  Operator/SM start: `npm run start:browser:sm`. Re-read operational ports at
  `http://127.0.0.1:18791/services`.
- **SSH / FTP** — loopback session brokers with allow-listed ops. Not OpenSSH
  or wire FTP. Never `env_inject`.

### Proof, not vibes

- Exposure tests fail if a sentinel appears in responses, logs, errors, or the
  worktree — including percent, form, Base64, and Base64url variants.
- Stable, value-free error codes (`playwright_absent`, `mfa_required`,
  `session_material_forbidden`, `bws_missing`, …).
- `authorization_ready` is compiled from branded platform evidence. SM unlock
  alone cannot set it true. The OS helper stays vault-free.

## Refused on purpose

These are product decisions, not missing tickets:

| Refused | Why |
| --- | --- |
| Agent sees the password / cookie / CDP | That is the whole point of the Bridge |
| `env_inject` / general process environment | Secrets in env become logs and child processes |
| OAuth, interactive MFA, SMS, email codes | Need a later explicit live gate and a different broker |
| Free CSS / XPath / `eval` in the browser | Prompt-injection / confused deputy |
| Cookie export / Playwright storage state | Use an HTTP broker or stop |
| Screenshots during password fill | Occupied password inputs and in-flight `inject_login` return `password_entry_active`. Empty login form and post-login pages may be captured as raw `image/png`, never `png_base64` JSON |
| Personal or company Bitwarden PM as the default | SM machine accounts are the productive path; personal PM is a separate flagged slice |
| `authorization_ready=true` from install or unlock | Would launder incomplete evidence |

## Research ladders (not required for SM)

Windows LocalService, macOS LaunchDaemon, and Linux systemd system-instance
work climb toward a **different-principal writer**. They are documented,
tested, and fail-closed. They are optional. Same-user SM resolve does not wait
on them.

See [Research status](research-status.md) for the phase index.

## Platform notes

| Platform | Productive SM | Native installer | Distinct-writer research |
| --- | --- | --- | --- |
| Windows | Yes (DPAPI + `bws`) | Yes (Inno Setup) | LocalService ladder |
| macOS | Yes (Keychain + `bws`, from source) | Not in this slice | LaunchDaemon ladder |
| Linux | Yes (`0600` XDG file + `bws`, from source) | Not in this slice | systemd system-instance ladder |

## Related docs

- [Windows laptop onboarding](windows-laptop-onboarding.md)
- [macOS laptop onboarding](macos-laptop-onboarding.md)
- [Linux laptop onboarding](linux-laptop-onboarding.md)
- [SM onboarding and import](sm-onboarding-and-import.md)
- [Windows installer](phase15-windows-installer.md)
- [Bridge-owned browser](phase17-bridge-owned-browser.md)
- [SSH / FTP session brokers](phase16-ssh-ftp-session-brokers.md)
- [Architecture](architecture.md)
