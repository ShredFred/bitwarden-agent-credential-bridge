# Phase 9f: Package-bind reviewed helper / supervisor digests

Phase 9f pins the reviewed Windows helper source tree, toolchain, SCM/console
entrypoint surface, and the OneCLI proxy supervisor entrypoint/imports. Live
publish and collector paths must match these pins fail-closed.

`authorization_ready` remains evidence-driven via Phase 9e → 9a only. This slice
never invents authorization.

## What is bound

| Binding | Contents |
|---|---|
| Helper source package | Exact LF-normalized SHA-256 + byte length for every file under `native/windows-helper-service/` |
| Package digest | Canonical sorted JSON digest of those file facts |
| Toolchain | SDK `8.0.423`, runtime `8.0.29`, ILLink `8.0.29` + nupkg digest, `win-x64` |
| Entrypoint surface | Fixed argv modes (`--self-test`, `--verify-fixed-server-identity`, …) and self-test JSON keys including `scm_entrypoint_compiled` / `vault_client_absent` |
| Supervisor | `onecli-proxy-runtime-supervisor.js` + `run-onecli-proxy.mjs` + frame module digests and required imports |

Published **binary** digests remain same-host publish outputs (deterministic
build). Collectors bind those digests into boundary plans only after a branded
publish that already verified the source/toolchain package.

## API

```js
import {
  evaluateWindowsHelperPackageBinding,
  verifyWindowsHelperReviewedSources,
  verifyOneCliProxySupervisorPackageBinding,
  requireWindowsHelperPublishBinding,
} from '../src/windows-helper-package-binding.mjs';
import { publishWindowsHelperServiceBinary } from '../src/windows-helper-publish.mjs';
```

- `verifyWindowsHelperReviewedSources()` — read-only source/toolchain/entrypoint check
- `publishWindowsHelperServiceBinary()` — verifies package binding before restore/publish, then brands `{ bytes, sha256, byteLength, package_binding_verified }`
- Collector paths call `requireWindowsHelperPublishBinding` so forged publish clones fail closed

## Commands

```bash
npm run test:phase9f
```

Pure tests do not install or start the LocalService. Expanding CI includes this
file plus other pure Windows Phase 9 / boundary slices that need no live service.

## Updating pins

When reviewed helper sources or the supervisor modules change intentionally:

1. Recompute LF-normalized digests (CRLF normalized to LF).
2. Update `WINDOWS_HELPER_SOURCE_*`, `WINDOWS_HELPER_PACKAGE_DIGEST`, and/or
   `ONECLI_PROXY_SUPERVISOR_BINDING` in
   `src/windows-helper-package-binding.mjs`.
3. Run `npm run test:phase9f`.

## Non-goals

- Changing `authorization_ready` semantics
- Live service install in CI
- Cross-host pinning of the published `.exe` digest (same-host reproducibility remains)
- Personal/company Bitwarden or helper vault clients
