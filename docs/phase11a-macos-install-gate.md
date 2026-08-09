# Phase 11a: macOS install-gate + collector trust

Pure compilers over the branded Phase 5h.22 lifecycle gate and Phase 5h.23
transcript schema. Synthetic provenance may satisfy collector-trust schema in
unit tests; `live_test_verified` and `authorization_ready` stay false until a
Mac-host disposable collector (Phase 11c) exists.

## APIs

- `buildMacosLaunchdLifecycleCollectorContract` /
  `evaluateMacosLaunchdLifecycleCollectorTrust`
- `evaluateMacosLaunchdInstallGate` /
  `brandMacosLaunchdLifecycleLiveReportForHarness`

## Non-goals

No sudo, launchd mutation, Mach IPC, Keychain/vault access, or hardcoded
`authorization_ready=true`.
