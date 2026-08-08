# Phase 10a: Windows authorization evidence refresh (Day-2)

Phase 10a adds a foreground Day-2 loop that assumes an already-installed
persistent LocalService helper and periodically re-collects branded Phase 9b /
9c / 9d evidence, then recomposes Phase 9e operational authorization.

It does **not** elevate, install, or uninstall the helper. Uninstall remains an
explicit operator step. It does **not** hardcode `authorization_ready=true`.

## Threat-model honesty

- Agent-facing broker responses/logs must not disclose secrets (existing exposure
  tests). Day-2 refresh does **not** prove memory isolation against a malicious
  process running as the same Windows user as the Node broker.
- Personal/company Bitwarden pairing, OAuth, interactive MFA, SSH, FTP, and
  `env_inject` remain forbidden.
- LocalService stays vault-free.
- `mutation_authorized` stays false.

## Operator sequence

```text
npm run live:windows-persistent -- install          # elevated, once
# vault-free first-install apply when targets are absent (existing helper path)
npm run live:windows-authorization-refresh          # foreground; Ctrl+C to stop
# optional:
npm run live:windows-authorization-refresh -- --with-operational-bridge
npm run live:windows-persistent -- uninstall        # explicit cleanup
```

Optional `--interval-ms=N` (clamped to 15s–3600s; default 60s).

## API

```js
import {
  startWindowsAuthorizationEvidenceRefresh,
  refreshWindowsAuthorizationEvidenceOnce,
  clampAuthorizationRefreshIntervalMs,
} from '../src/windows-authorization-evidence-refresh.mjs';

import { createLiveWindowsAuthorizationEvidenceCollectors } from '../src/windows-authorization-evidence-live-collectors.mjs';
```

- Collectors are injected (live or fake) so unit tests never need a service.
- Each tick emits a value-free snapshot: `refresh_generation`,
  `authorization_ready`, `evidence_complete`, `terminal_code`, vault flags,
  `collector_error`. No wall-clock timestamps, paths, or SIDs.
- Collector failures fail closed to incomplete branded evidence →
  `authorization_ready=false`.

Install-gate + layout foundation for the live collectors is rebuilt in-process
from the published helper digest using a branded disposable-live transcript
replay (the same approach used when a persistent service occupies the host and a
fresh disposable matrix cannot run). Live readiness still depends on complete
9b–9d facts from the running LocalService boundary.

## Tests

```bash
npm run test:phase10a
```

## Non-goals

- Auto-install / auto-elevate / background Windows service for the Node loop
- Leaving the helper installed after CI
- Personal Bitwarden pairing
- OAuth / MFA / SSH / `env_inject`
- Package signing beyond Phase 9f digests
- Claiming agents cannot read secrets under same-user compromise
