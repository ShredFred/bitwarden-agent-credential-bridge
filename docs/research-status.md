# Research status

This is the phase index for contributors and reviewers. Operators and agents
should start at the [README](../README.md) and [Features](features.md) instead.

The public project is still a **fail-closed research harness**. Capabilities
below are real contracts with tests; they are not a production isolation claim.
`authorization_ready` stays false unless branded platform evidence is complete.

## How to read this

- **Harness** — fake loopback brokers, policies, exposure tests.
- **Productive SM** — same-user Bitwarden Secrets Manager resolve (no extra OS
  user; helper stays vault-free).
- **Writer ladder** — optional distinct-principal research (Windows / macOS /
  Linux). Not required for SM.

When a phase becomes a stable capability, prefer the responsibility-based doc
in [Architecture](architecture.md) over adding another README section.

## Harness contracts

| Slice | One-line | Doc |
| --- | --- | --- |
| 1 | Fake bearer HTTP broker | README history / `src/broker.js` |
| 2 | Offline OneCLI readiness, no deploy | [phase2](phase2-onecli-readiness.md) |
| 3 | Supply-chain evidence + disposable live-test design | [phase3](phase3-disposable-live-test.md) |
| 4a | HTTP API-key header | [phase4a](phase4a-http-api-key.md) |
| 4b | HTTP Basic | [phase4b](phase4b-http-basic.md) |
| 4c | OneCLI chained proxy (fake gateway) | [phase4c](phase4c-onecli-chained-proxy.md) |
| 6 | Browser form-login session broker | [phase6](phase6-browser-form-login.md) |
| 7 | Query API keys, rejected classes, multi-class matrix | [phase7](phase7-hq-operational-readiness.md) |
| 8 | Operational multi-service bridge | [phase8](phase8-operational-bridge.md) |
| 16 | Loopback SSH/FTP session brokers | [phase16](phase16-ssh-ftp-session-brokers.md) |
| 17 / 17b | Bridge-owned browser + optional Playwright adapter (not vendored; headless default; screenshots forbidden) | [phase17](phase17-bridge-owned-browser.md) |
| 17c | SM start command + `/services` discovery | [phase17](phase17-bridge-owned-browser.md) |

## Secrets Manager and install

| Slice | One-line | Doc |
| --- | --- | --- |
| 13 | Flagged personal Bitwarden PM resolve (Windows) | [phase13](phase13-personal-bitwarden.md) |
| 14 | Same-user SM machine resolve (productive default) | [phase14](phase14-secrets-manager-same-user.md) |
| 15 | Windows product installer | [phase15](phase15-windows-installer.md) |

## Windows writer ladder (optional)

Bootstrap plan through disposable apply, persistent LocalService, and
Day-2 `authorization_ready` compose. Start at
[phase9](phase9-windows-authorization-ready.md) and
[phase10c](phase10c-windows-day2-operator.md).
Native 5h.* docs remain the evidence trail under `docs/phase5h*.md`.

## macOS / Linux writer ladders (optional)

- macOS: [phase11a](phase11a-macos-install-gate.md),
  [phase11b](phase11b-macos-helper-layout.md),
  [handoff](phase11c-macos-disposable-denial-handoff.md)
- Linux: [phase12](phase12-linux-pure-gate-stack.md),
  [handoff](phase12n-linux-disposable-denial-handoff.md)
- Cross-platform compose:
  [cross-platform authorization](cross-platform-production-authorization.md)

## Commands researchers actually run

```bash
npm test
npm run test:phase17
npm run preflight:onecli
npm run preflight:bootstrap
node src/run-demo.js
```

Live / mutating commands stay behind explicit operator approval flags and are
listed in the matching phase doc. A passing unit suite is not permission to
install a service, pair a personal vault, or open a public origin.

## Non-claims that still apply

- Fake sentinels in tests; never real credentials in git or CI.
- No fallback to printing secrets or injecting `process.env`.
- Same-user restrictions are not production writer isolation.
- Path-based preflight is advisory, not authorization.
- Playwright-CLI, Chrome extensions, and agent CDP are not the secret path.
