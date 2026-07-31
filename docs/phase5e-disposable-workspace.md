# Phase 5e: marked disposable workspace

Phase 5e creates the only root in which the first apply executor may operate.
The root comes from `mkdtemp` beneath the canonical OS temporary directory and
contains an exclusively created marker with a cryptographic nonce. Synthetic
home, LocalAppData, and XDG paths all remain beneath that root.

Before every later disposable operation, verification must re-resolve the temp
root and workspace, reject links/reparse points, enforce strict containment,
require a single-link marker file, and compare its bounded bytes exactly with
the expected canonical marker. Parsing permissive or duplicate-key JSON is not
used as an authorization decision.

The product API deliberately exposes no recursive cleanup. Tests remove only
the exact root they created. This phase does not execute manifests, create a
Bitwarden config, access a vault/network, or touch normal per-user paths.

```bash
npm run test:phase5e
```
