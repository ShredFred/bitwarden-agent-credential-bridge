# Phase 9e: Wire operational readiness to Phase 9a

Phase 9e connects the operational bridge readiness surface to a branded Phase
9a production authorization report composed from branded install-gate, persistent
layout, handle-bound identity (9b), target-ACL (9c), and peer five-facts (9d).

## Contract

- `authorization_ready` is copied only from
  `evaluateWindowsProductionAuthorization` (via
  `composeWindowsOperationalAuthorization`). It is never a hardcoded `true`.
- Default / absent host evidence uses incomplete branded fixtures and evaluates
  to `authorization_ready=false` with `operational_bridge_unwired=false`
  (wired path, incomplete evidence).
- Forged or unbranded evidence fails closed.
- Personal/company vaults remain forbidden; helper stays vault-free;
  `mutation_authorized` stays false.

## API

```js
import {
  composeWindowsOperationalAuthorization,
  absentWindowsOperationalAuthorization,
  buildIncompleteOperationalAuthorizationEvidence,
  buildCompleteOperationalAuthorizationEvidenceForHarness,
} from '../src/windows-operational-authorization.mjs';

import { startOperationalBridge } from '../src/operational-bridge.mjs';

// Default: wired incomplete → false on typical same-user hosts
const bridge = await startOperationalBridge({ repoRoot, bindings });

// Optional: pass a complete branded evidence bundle (unit tests / operator compose)
const wired = composeWindowsOperationalAuthorization(evidenceBundle);
```

`startOperationalBridge` exposes:

| Field | Source |
|---|---|
| `authorization_ready` | Wired Phase 9a/9e report only |
| `operational_authorization_wired` | `true` when the 9e path ran |
| `production_authorization_terminal_code` | 9a terminal code |
| vault / helper flags | Copied from the wired report |

## Commands

```bash
npm run test:phase9e
npm run start:operational
```

## Operator sequence for a live-complete matrix (optional)

On a Windows host where you intentionally want to exercise collectors against a
real LocalService boundary (not required for CI; always uninstall afterward):

1. Operator-approved persistent install:
   `npm run live:windows-persistent -- install`
2. Collect branded evidence (no UAC for these read-only probes when the service
   is already running):
   - `npm run live:windows-handle-bound-identity`
   - `npm run live:windows-target-acl-matrix`
   - `npm run live:windows-persistent-peer-session`
3. Compose the five branded objects and pass them as
   `productionAuthorizationEvidence` to `startOperationalBridge` (or call
   `composeWindowsOperationalAuthorization` directly).
4. Uninstall and prove absence:
   `npm run live:windows-persistent -- uninstall`

Typical same-user console hosts without a live-complete persistent boundary
still evaluate to `authorization_ready=false`. Unit tests may exercise `true`
only with synthetic complete branded fixtures
(`buildCompleteOperationalAuthorizationEvidenceForHarness`).

## Non-goals

- Hardcoding `authorization_ready: true`
- Leaving a persistent service installed after smoke
- Personal/company Bitwarden pairing or helper vault clients
- Phase 9f package-binding of reviewed helper digests
  (`docs/phase9f-windows-helper-package-binding.md`)
