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

### Fixed

- CI `npm test` glob so Node discovers `test/*.test.js` on Ubuntu and Windows
  runners.

## 0.1.0 - Unreleased experimental baseline

### Added

- Fake-only credential-boundary contracts and exposure tests.
- Offline OneCLI and Agent Access readiness and supply-chain evidence.
- Disposable platform-boundary research and value-free helper/service evidence.

### Security

- Real vault access, real credentials, and production deployment remain out of
  scope.
