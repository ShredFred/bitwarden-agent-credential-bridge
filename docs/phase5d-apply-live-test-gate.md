# Phase 5d gate: apply and disposable live test

Phase 5d may build and verify a pure, deterministic action manifest; it still
performs no host I/O. No apply executor is authorized yet. A later installer may proceed only
after all of the following are implemented and independently reviewed:

1. Generate a complete value-free action manifest before mutation, including
   exact destinations, launcher digest, intended permission policy, and rollback
   operations. Require explicit confirmation tied to that manifest digest.
2. Re-run containment, link/reparse, owner, permission/DACL, and destination
   existence checks immediately before every write. Never overwrite an unknown
   file or follow a replaced parent directory.
3. Write into a newly created same-directory temporary file, set restrictive
   ownership/permissions, verify content integrity, then atomically rename.
4. Record a value-free rollback manifest. On partial failure, restore only files
   created or replaced by the confirmed manifest and verify the final state.
5. First exercise install, upgrade, idempotent reinstall, forced failure, and
   rollback under disposable roots on Windows, macOS, and Linux. The real default
   per-user roots remain out of scope until those tests pass.
6. Use generated fake configuration and credentials only. Do not pair Bitwarden,
   access a personal/company vault, create real Agent Access tokens, or start a
   long-lived broker during installer testing.
7. Before a Bitwarden live test, require a separate approval for a disposable
   account/item, bounded relay/network access, cache/revocation tests, process and
   log non-disclosure checks, cleanup, and a reviewed redacted evidence bundle.

The manifest builder hashes launcher bytes without returning them, derives every
destination internally, binds coherent observed states plus forward/rollback
actions, and requires `APPLY <full 64-character SHA-256>`. Existing user config
is preserved; an absent config receives only the public empty-services skeleton.

Browser automation, website form filling, SSH, databases, RDP, desktop logins,
TLS interception, and environment-variable secret injection remain separate
credential-class projects, not fallbacks of this installer.
