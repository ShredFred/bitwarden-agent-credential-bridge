# Phase 5g: disposable manifest executor

Phase 5g is the first real installer execution, but only inside a valid marked
workspace beneath the OS temporary directory. A synthetic scaffold represents
the host-managed home/LocalAppData/XDG/Application Support parents and is itself
permission-hardened before use.

The executor requires the full manifest confirmation, rebuilds the manifest from
the workspace and supplied launcher bytes, re-observes every target, and rejects
any difference before mutation. It uses exclusive directories/files, synced
same-directory temporary files, and hard-link publication/moves so existing
destinations cannot be overwritten. Every completed step is post-verified.

Only activated rollback actions execute, in strict reverse order. Digests and
state are checked before removal or restoration; unexpected state stops rollback.
Real tests cover first install, no-op reinstall, upgrade with backup commit,
injected first-install failure, and restoration after an interrupted upgrade.

This executor cannot target default user roots and does not access Bitwarden,
network services, real configuration, or credentials.

The permission boundary does not defend against a malicious process running as
the same OS user while execution is in progress. Same-user races remain possible;
a production executor therefore needs a separate OS identity or equivalent
sandbox boundary. That production isolation is not implemented in Phase 5g.

```bash
npm run test:phase5g
```
