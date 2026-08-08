# Phase 9: Windows production `authorization_ready` gate

Phase 8 delivered disposable/dev operational brokers with a structurally false
`authorization_ready`. Live disposable LocalService denial, persistent
install/uninstall, and disposable DPAPI smoke are useful evidence, but they do
**not** authorize production writer isolation.

This milestone defines the fail-closed path to a legitimate
`authorization_ready=true` under the repository threat model, then implements it
in narrow vertical slices. It does **not** flip the operational bridge flag as a
shortcut.

## Threat-model conditions (all required)

`authorization_ready` may become true on Windows only when every class below is
proven by branded, value-free evidence:

1. **Install-gate eligibility** — disposable elevated denial matrix verified with
   complete collector provenance (`install_gate_eligible=true`). Necessary, not
   sufficient.
2. **Persistent ProgramData layout** — trusted roots; ordinary LocalAppData/home
   roots forbidden; shared `LocalService` TokenUser ownership forbidden.
3. **Handle-bound installed-service identity** — live pipe server PID/token bound
   to SCM service identity (`LocalService` TokenUser + enabled service SID),
   binary digest matched through a handle (not path-only advisory preflight),
   service DACL denies caller configuration changes.
4. **Complete target-ACL matrix** — every bound target checked; caller write/
   create/DACL/owner/delete denied; helper/service-SID write allowed; ownership
   trusted and not the interactive caller.
5. **Phase 5h.1 peer five-facts** — local transport, verified identity, different
   principal, caller write denied, helper write allowed.
6. **Helper remains vault-free** — no Bitwarden/DPAPI/network vault client inside
   LocalService; personal/company/organization vault pairing remains forbidden.
7. **Operational wiring** — Phase 9e copies `authorization_ready` only from the
   branded 9a report. Default incomplete evidence stays false; unit tests may
   exercise a synthetic complete report.

Permanent rejects remain: OAuth, interactive MFA, SMS/email, SSH/FTP,
`env_inject`, and personal/company vault pairing.

## Why current live evidence is insufficient

| Evidence | Why it does not set `authorization_ready` |
|---|---|
| `live_test_verified` disposable denial | Proves disposable install/deny/cleanup, then absence; not a persistent handle-bound production matrix |
| `install_gate_eligible` | Eligibility to *consider* a later installer; Phase 5h.46 keeps `authorization_ready=false` |
| Persistent install/uninstall | Lifecycle under ProgramData still lacks handle-bound authorize + complete ACL production evidence |
| DPAPI disposable Bitwarden smoke | Dev secret resolve + broker smoke; same-user process; not writer isolation |
| Path-based Phase 5h.9 preflight | Explicitly advisory; AGENTS.md forces `authorization_ready=false` until handle-bound evidence exists |
| Phase 8 operational bridge | In-process same-user brokers; Phase 9e wires the flag from 9a (default incomplete → false) |

## Slice order

| Slice | Scope | Status |
|---|---|---|
| **9a** | Pure authorization evidence compiler + branded schemas; synthetic true-path unit tests | Done |
| **9b** | Live handle-bound installed-service identity collector (value-free; read-only; persistent running service needed for complete result) | Done — see `docs/phase9b-windows-handle-bound-identity.md` |
| **9c** | Live complete target-ACL AccessCheck matrix for the five persistent targets under service SID ownership | Done — see `docs/phase9c-windows-target-acl-matrix.md` |
| **9d** | Different-principal session on the persistent pipe feeding Phase 5h.1 five-facts; vault-free helper apply still separate | Done — see `docs/phase9d-windows-persistent-peer-session.md` |
| **9e** | Wire operational readiness to the branded 9a report; never hardcode true | Done — see `docs/phase9e-windows-operational-authorization.md` |
| **9f** | Package-bind reviewed helper/supervisor digests; expand CI for pure Windows slices without live service install | **This pass** — see `docs/phase9f-windows-helper-package-binding.md` |

Multi-provider plan review (Antigravity Sonnet 4.6 + Cursor Composer 2.5 via `mco review`) agreed that disposable
`live_test_verified` / `install_gate_eligible` / persistent install / DPAPI smoke are mechanics evidence only.
Cursor additionally emphasized a vault-free persistent helper apply and package-binding before treating the
operational surface as authorized; 9a–9f are complete for the evidence/wiring path, while a real-host
`authorization_ready=true` still requires operator live evidence (not a boolean flip).

macOS/Linux distinct-writer parity remains separate milestones; a Windows-only
`authorization_ready=true` must be platform-scoped in API reports.

## Phase 9a API

```js
import {
  brandWindowsHandleBoundIdentityEvidenceForHarness,
  brandWindowsTargetAclEvidenceForHarness,
  evaluateWindowsProductionAuthorization,
} from '../src/windows-production-authorization.mjs';
```

- Accepts only branded install-gate + persistent layout + handle-bound identity +
  target-ACL evidence, plus exact peer five-facts.
- Rejects path-based preflight (`path_based_preflight_only=true`), forged clones,
  disposable layouts, and extra fields.
- May return `authorization_ready=true` for complete synthetic evidence in tests.
- Always keeps `mutation_authorized=false` and vault forbidden flags true.
  Pure 9a reports keep `operational_bridge_unwired=true`; Phase 9e sets that
  bit false when wiring the operational surface.

```bash
npm run test:phase9a
npm run test:phase9b
npm run test:phase9c
npm run test:phase9d
npm run test:phase9e
npm run test:phase9f
```

## Phase 9b API

```js
import {
  collectWindowsHandleBoundIdentityEvidence,
  mergeWindowsHandleBoundIdentityEvidence,
  brandWindowsHandleBoundIdentityEvidence,
} from '../src/windows-handle-bound-identity.mjs';
```

- Merges native `--verify-fixed-server-identity` facts with the handle-bound
  binary/service probe into branded Phase 9a evidence.
- Public report always has `authorization_ready=false`.
- Operator live: `npm run live:windows-handle-bound-identity` (no UAC; complete
  only when the fixed service is already installed and running).

## Phase 9c API

```js
import {
  collectWindowsTargetAclEvidence,
  brandWindowsTargetAclEvidence,
  mapWindowsTargetAclMatrixProbeToEvidence,
} from '../src/windows-target-acl-matrix.mjs';
```

- AccessChecks the five fixed ProgramData targets for caller + helper tokens.
- Brands Phase 9a target-ACL evidence; public report always
  `authorization_ready=false`.
- Operator live: `npm run live:windows-target-acl-matrix` (no UAC; complete only
  with present root + running LocalService).

## Phase 9d API

```js
import {
  collectWindowsPersistentPeerSession,
  brandWindowsPeerAuthorizationEvidence,
  mapWindowsPersistentPeerSessionToEvidence,
} from '../src/windows-persistent-peer-session.mjs';
```

- Feeds branded Phase 5h.1 five-facts for Phase 9e wiring.
- `different_principal` requires service-denial + 5h.13 LocalService identity.
- Public report always `authorization_ready=false`.
- Operator live: `npm run live:windows-persistent-peer-session`.

## Phase 9e API

See [phase9e-windows-operational-authorization.md](phase9e-windows-operational-authorization.md).

- Composes branded 5h.46 / 5h.47 / 9b / 9c / 9d evidence into a wired 9a report.
- Operational bridge copies `authorization_ready` from that report only.
- Default path is wired-but-incomplete (`false` on typical same-user hosts).
- Synthetic complete fixtures may exercise `true` in unit tests only.

## Phase 9f API

See [phase9f-windows-helper-package-binding.md](phase9f-windows-helper-package-binding.md).

- Pins reviewed helper source/toolchain/entrypoint digests and the OneCLI proxy
  supervisor entrypoint/imports.
- Publish brands a package-bound binary digest for collectors.
- Pure CI only; no live service install required.

## Non-goals for Phase 9

- Hardcoding `authorization_ready: true` on operational surfaces
- Personal/company Bitwarden pairing
- Vault client inside LocalService
- Treating disposable harness green as production isolation
- Claiming protection from a malicious same-user process without the distinct
  writer boundary above
