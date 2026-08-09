# Phase 12a–12f: Linux pure gate stack

Pure, non-executable Linux slices runnable on any host (including Windows):

| Slice | Module |
|---|---|
| 12a layout | `src/linux-helper-layout-plan.mjs` |
| 12b lifecycle gate | `src/linux-systemd-lifecycle-gate.mjs` |
| 12c transcript SM | `src/linux-systemd-lifecycle-evidence.mjs` |
| 12d collector trust | `src/linux-systemd-lifecycle-collector-trust.mjs` |
| 12e install gate | `src/linux-systemd-install-gate.mjs` |
| 12f authorize envelope | `src/linux-helper-authorize-envelope.mjs` |

All keep `authorization_ready=false` and `mutation_authorized=false`. Rules from
Phase 5h.17 remain: systemd system instance only, no `DynamicUser=`, filesystem
AF_UNIX only, no abstract sockets, no home/XDG writer roots.

## Tests

`npm run test:phase12`
