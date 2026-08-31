# Changelog

All notable changes to this project are documented here. This project follows
Semantic Versioning while it remains on the experimental 0.x line.

## Unreleased

### Changed

- Public README: CareerOps-style hero (logo, experimental release badges,
  Built with, manifesto, FAQ, disclaimer, author, Let's connect), plus
  Agent Access SDK flow diagrams that explain the Bridge injection boundary.
- Public-cutover review: host-specific paths and per-laptop machine ids
  removed from docs; secret scan recorded in
  [publication-review.md](docs/publication-review.md). The Discussions
  **Architecture** category remains an incomplete cutover item until a
  maintainer rename in the GitHub UI.

### Fixed

- Windows CI: Linux/macOS SM path helpers use `path.posix` so simulated
  XDG/`~/.local/bin` locations stay slash-stable, and POSIX `0600` token-file
  tests skip on NTFS (owner-only bits are not preserved there). An injected
  Linux `home` no longer inherits the runner `XDG_CONFIG_HOME`.
- Linux SM token store opens with `O_NOFOLLOW`, requires current-UID ownership
  and owner-only parent/file modes, refuses relative paths and symlink
  parents, and cleans leftover temp files. GUI zenity/kdialog runs with a
  bounded capture, a minimal environment (no `BWS_ACCESS_TOKEN`), and only
  `/usr/bin` binaries that are not group/other-writable.
- macOS SM setup uses StandardAdditions `displayDialog` (Cmd-V works in
  the hidden-answer token prompt) instead of NSAlert accessory fields that
  crashed on Save. Empty `defaultAnswer` is padded to 8192 characters so
  AppleScript does not cap paste at a few glyphs. `--self-test` applies a
  fake token to a temp allowlist and Keychain account `pc-selftest-wizard`,
  then uninstalls. Stuck wizard processes are replaced before a new dialog
  opens. Setup verifies the token with `bws project list` (counts only).
- Laptop-ready CLI reports `approval_flag_required` before
  `unsupported_platform`, so Linux CI matches the operator-flag contract.
  Phase 9e operational-bridge tests pin `platform: 'win32'` when feeding
  Windows synthetic evidence. Live Windows handle-bound and target-ACL
  probes are skipped in GitHub Actions.
- Secrets Manager CLIs resolve `bws` from the default Windows install
  location (`LocalAppData\\Programs\\Bitwarden\\bws.exe`) when it is not on
  PATH, and report `bws_missing` instead of a generic startup failure.
  `authorization_ready: false` remains LocalService writer evidence and is
  not the missing-CLI error code.

### Added

- Linux same-user SM parity with Windows/macOS: owner-only `0600` token file
  under XDG config, allowlist next to it (not `AppData`), `bws` lookup in
  `~/.local/bin` / `/usr/local/bin` / `/usr/bin`, first-run wizard
  (zenity/kdialog or `--self-test`), `bw-sm ask`, PATH wrappers
  (`npm run install:user-path`), and from-source onboarding docs.
  Distro packages remain a later slice. `authorization_ready` stays false.
- macOS same-user SM product parity with Windows: Keychain token store
  (`security -i`, same-user `-A`), AppKit first-run wizard and
  `bw-sm ask` secret-entry dialog, Homebrew/`~/.local/bin` `bws` lookup,
  PATH wrappers (`npm run install:macos-path`), and from-source onboarding
  docs. Signed `.pkg` remains a later slice. `authorization_ready` stays
  false. Wizard `machine_id` prefers ComputerName over ISP DHCP hostnames;
  `npm run setup:sm:rename-id` re-homes an existing Keychain item.
- Bridge-owned Playwright accepts both headless (default) and `--headed`.
  `--headed` with the `fetch` driver is `invalid_request`. Unknown flags
  such as `--devtools` fail closed. Launch pins
  `devtools: false` and lets the Bridge own SIGINT.
  `GET /screenshot` is allowed except during password fill
  (`password_entry_active`); success is raw `image/png` (no `png_base64`
  JSON). `fetch` returns `screenshot_unsupported`.
  Playwright is an optional host install, not a package dependency.
- Phase 17c `npm run start:browser:sm` (dual approval flags, `--alias`) and
  operational `GET /services` discovery on `http://127.0.0.1:18791`.
  Bridge-owned browser CLI binds `http://127.0.0.1:18792`.
- Human-facing product README, [feature map](docs/features.md), and
  [research index](docs/research-status.md). Agent runbooks stay separate.
- Phase 17b in-process Bridge-owned Playwright driver behind the same
  index-only login allow-list (`driver: 'playwright'`). Playwright is not a
  package dependency; stub tests always run. Agent CDP, `playwright-cli`,
  cookie export, and non-loopback hosts remain forbidden.
- Phase 17 Bridge-owned browser for `browser_form_login`: agent selects
  field indices, Bridge injects in-memory secrets, cookies never leave the
  jar (`docs/phase17-bridge-owned-browser.md`). Agent CDP, cookie export, and
  `playwright-cli` remain forbidden; `authorization_ready` stays false.
- Phase 16 fake-loopback SSH/FTP session brokers (policy versions 7/8), private-hq
  multi-class SM matrix coverage, and operator docs
  (`docs/phase16-ssh-ftp-session-brokers.md`). `env_inject` remains rejected;
  `authorization_ready` stays false.
- Agent-blind local DPAPI / `.env` → Secrets Manager import
  (`npm run import:local-to-sm`, default dry-run; apply behind write approval;
  local purge disabled). Manifest covers MiViA CliXml inventory + private-hq
  personal-hq `.dpapi` keys and cleartext `.env` / provider-lab secrets.
  HQ resolve helpers + value-free parity verifier
  (`npm run verify:hq-sm-parity`, `resolve:sm-secret`); purge deferred
  (`docs/sm-local-purge-later.md`).
- Canonical MiViA + private-hq operational SM bindings
  (`samples/operational/bindings-sm.json`) with idempotent seed/prune
  (`npm run seed:sm`) over the DPAPI machine token.
- Operator/agent onboarding + import guide
  (`docs/sm-onboarding-and-import.md`) and service-oriented key naming
  (`docs/sm-operational-key-naming.md`), wired into Windows install/onboarding
  docs.
- Public-facing project documentation, contributor guidance, security policy,
  support routing, issue forms, pull-request template, and CI workflow.
- A documented public/private/local repository boundary and release process.
- Apache-2.0 licensing and the maintainer-controlled Buy Me a Coffee funding
  route.
- Phase 6 disposable browser form-login and Phase 7 HQ auth matrix (including
  query API keys and disposable DPAPI live smoke).
- Phase 8 in-process operational multi-service bridge (`npm run start:operational`)
  with explicit `harness_ready` / `disposable_dev_ready` / `authorization_ready`
  taxonomy.
- Windows operator-approved live evidence recorded in the handoff: elevated
  disposable LocalService denial (`live_test_verified`), persistent
  install/uninstall cleanup, and disposable DPAPI Bitwarden broker smoke.
  `authorization_ready` remains false.
- Phase 9a pure Windows production authorization evidence compiler and milestone
  plan (`docs/phase9-windows-authorization-ready.md`). Synthetic complete
  evidence may exercise `authorization_ready=true` in unit tests only; the
  operational bridge stays unwired and false until live handle-bound collectors
  and an explicit wire-up slice exist.
- Phase 9b read-only handle-bound installed-service identity collector
  (`docs/phase9b-windows-handle-bound-identity.md`): native 5h.13 pipe/SCM/token
  verifier plus handle-open binary digest/ACL probe. Public reports keep
  `authorization_ready=false`; complete positive evidence still requires a
  separately installed running LocalService.
- Phase 9c read-only persistent target-ACL AccessCheck matrix
  (`docs/phase9c-windows-target-acl-matrix.md`) over the five fixed ProgramData
  helper targets. Brands Phase 9a target-ACL evidence; incomplete without a
  present root and running LocalService; `authorization_ready` stays false.
- Phase 9d read-only different-principal persistent pipe session
  (`docs/phase9d-windows-persistent-peer-session.md`) feeding branded Phase 5h.1
  peer five-facts. Console same-user hosts stay non-authorizing;
  collector reports keep `authorization_ready=false`.
- Phase 9e operational wire-up
  (`docs/phase9e-windows-operational-authorization.md`): readiness surfaces copy
  `authorization_ready` only from the branded Phase 9a evaluator. Default
  incomplete evidence stays false; synthetic complete fixtures may exercise
  true in unit tests only.
- Phase 9f package binding
  (`docs/phase9f-windows-helper-package-binding.md`): pins reviewed helper
  source/toolchain/entrypoint digests and the OneCLI proxy supervisor
  entrypoint/imports; publish/collector paths brand fail-closed publish
  bindings. Pure CI expanded without live service install.
- Phase 10a Day-2 authorization evidence refresh
  (`docs/phase10a-windows-authorization-evidence-refresh.md`): foreground loop
  re-collects branded 9b/9c/9d evidence and recomposes Phase 9e readiness for an
  already-installed LocalService; optional operational-bridge restart; uninstall
  stays explicit. Does not claim same-user memory isolation.
- Phase 10b authorization-ready bootstrap
  (`docs/phase10b-windows-authorization-ready-bootstrap.md`): operator path that
  may exit with `authorization_ready=true` only when branded compose reports it
  after optional persistent install and vault-free first-install apply; never
  hardcodes the boolean; personal/company vaults stay forbidden.
- Phase 10c Windows Day-2 operator session
  (`docs/phase10c-windows-day2-operator.md`): unifies bootstrap, operational
  bridge, and evidence refresh with fail-closed drift handling; uninstall stays
  explicit.
- Phase 11a/11b macOS pure install-gate, collector-trust, and helper layout
  (`docs/phase11a-macos-install-gate.md`, `docs/phase11b-macos-helper-layout.md`).
  Live distinct-EUID denial remains a Mac-host handoff
  (`docs/phase11c-macos-disposable-denial-handoff.md`).
- Phase 12a–12f Linux pure gate stack
  (`docs/phase12-linux-pure-gate-stack.md`): layout, lifecycle gate, transcript,
  collector trust, install gate, and authorize envelope. Native/live denial is a
  Linux-host handoff (`docs/phase12n-linux-disposable-denial-handoff.md`).
- Cross-platform production authorization compilers and operational wire-up for
  macOS (11e/11j/11l) and Linux (12p/12t/12u), plus platform dispatch in the
  operational bridge (`docs/cross-platform-production-authorization.md`).
  Synthetic fixtures may exercise `authorization_ready=true` in unit tests;
  live Mac/Linux collectors remain host handoffs.
- Windows laptop operator onboarding runbook
  (`docs/windows-laptop-onboarding.md`) for harness + Day-2 setup, with optional
  Phase 13 personal Bitwarden resolve (company/org still forbidden).
- Phase 13 personal Bitwarden → agent path
  (`docs/phase13-personal-bitwarden.md`): branded live gate, digest allowlist,
  DPAPI collector, resolver, `live:personal-bitwarden`, and
  `live:windows-laptop-ready`. Secrets stay in the Bridge process;
  LocalService remains vault-free; `authorization_ready` is never set by vault
  unlock.
- Phase 14 Secrets Manager same-user productive path
  (`docs/phase14-secrets-manager-same-user.md`): machine-account allowlist,
  local access-token store (Windows DPAPI / macOS token file), pinned `bws`
  adapter, `operational_sm_same_user` bindings, `live:sm-machine`, and
  `start:operational:sm`. Default laptop path needs no extra OS user and no
  LocalService vault client; Day-2 LocalService stays optional.
- Guided SM setup/uninstall and agent-blind write:
  `npm run setup:sm` (credential window for token), `npm run uninstall:sm`,
  and `npm run live:sm-write` (stdin value, value-free result only).
- Phase 15 Windows product installer (Inno Setup): Start Menu Setup/Start,
  Apps & Features uninstall with local SM cleanup, optional self-host
  `server_url` in allowlist, WinForms wizard (`setup:sm:wizard`), agent
  install doc (`docs/agent-windows-install.md`), and tag release workflow
  for `BitwardenAgentCredentialBridge-Setup-*.exe`.

### Fixed

- CI `npm test` glob so Node discovers `test/*.test.js` on Ubuntu and Windows
  runners.
- Windows Phase 4c inherited `stdio: "pipe"` descriptors: accept libuv's FIFO
  mode bit when `Stats.isFIFO()` is false, while still rejecting files and
  devices such as `NUL`.
- Portable macOS source-contract tests under Windows `core.autocrlf` checkouts
  by normalizing CRLF before newline-sensitive ordering checks, plus a
  repository `.gitattributes` LF policy.

## 0.1.0 - Unreleased experimental baseline

### Added

- Fake-only credential-boundary contracts and exposure tests.
- Offline OneCLI and Agent Access readiness and supply-chain evidence.
- Disposable platform-boundary research and value-free helper/service evidence.

### Security

- Real vault access, real credentials, and production deployment remain out of
  scope.
