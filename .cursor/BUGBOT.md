# Bugbot review rules — Agent Credential Bridge

This repository is a **sample-only security experiment**. Prefer high-severity, actionable findings. Skip style nits unless they create a security or correctness bug.

## Hard invariants

- Never introduce real credentials, vault exports, cookies, recovery codes, auth tokens, or private service inventories. Tests must use generated fake sentinels only.
- Fail closed: unsupported credential classes, ambiguous platform inputs, malformed peer evidence, and missing authorization facts must deny — never fall back to printing secrets, process-environment injection, or “best effort” allow.
- Runtime secrets must never land in policy files, env vars, logs, responses, errors, transcripts, or agent-readable surfaces. Reports and IPC frames are value-free (fixed codes/booleans/counts only).
- Do not add custom cryptography. Prefer standard-library code and pinned upstream tools.
- Phase scope is strict: do not sneak in Bitwarden pairing, live vault access, network clients beyond the gated local surface, TLS interception, firewall/proxy mutation, or persistent production installs behind an unapproved path.

## Exposure and redaction

- Flag any path where a sentinel/credential, Basic Auth material, derived Base64/percent forms, SIDs, PIDs, paths, ACL/SDDL text, UIDs, audit tokens, exception messages, or raw command output can reach an agent-readable surface.
- Caller-supplied headers that look credential-shaped must be stripped before injection; exactly one policy-pinned outbound credential value is allowed.
- Redirects, oversized bodies, unconfigured query strings, and forbidden header names must fail closed.

## Windows / helper / service boundary

- Distinct-principal evidence requires unequal TokenUser / host-UID / effective-UID digests. Restricted tokens, AppContainer, namespace-local UID 0, App Sandbox, and similar signals are defense-in-depth only — never sufficient alone.
- Pipe/server auth must bind live PID + token (LocalService TokenUser + expected service SID group). A predictable pipe name or first-instance flag is not authentication.
- Targets and security-relevant ancestors must not be caller-owned or shared LocalService-owned in a way that breaks the LocalService service boundary plan.
- Disposable elevated lifecycle tests must refuse pre-existing service/pipe collisions, never reacquire foreign objects by fixed name for cleanup, and keep `mutation_authorized`, `install_gate_eligible`, and `authorization_ready` false unless a later phase explicitly changes that contract.
- Collector trust needs retained-handle elevation facts; UAC consent / admin group / high integrity alone must not establish trust.

## Authorization and gates

- Serialized, cloned, spread, accessor-backed, or forged gate/plan/transcript objects are not capabilities — reject them.
- Positive completion fields on pure evaluators are structural claims only, never live verification, unless the phase explicitly allows `live_test_verified` after trusted collection.
- Public APIs must not accept caller overrides for paths, pipe/service names, commands, credentials, approval values, or Bitwarden references when the phase forbids them.

## Review focus by change type

- **Policy / broker / injection:** wrong header handling, placeholder leakage, fallback injection, incomplete stripping, redirect/query holes.
- **Peer evidence / IPC:** same-principal acceptance, incomplete ACL checks, raw identity leakage, missing local-only / reject-remote requirements.
- **Service / install / collector:** install eligibility flipping true too early, missing absence proofs, destructive cleanup by name, value-bearing stdout/stderr.
- **Tests:** missing exposure assertions, accepting real vault/network side effects, weakening fail-closed cases.

## Comment style

- Cite file and behavior; state the invariant violated and the concrete failure mode.
- Do not request real secrets, vault contents, or production credentials in review comments.
