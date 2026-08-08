# Changelog

All notable changes to this project are documented here. This project follows
Semantic Versioning while it remains on the experimental 0.x line.

## Unreleased

### Added

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
