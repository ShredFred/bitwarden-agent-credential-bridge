# Phase 5h.23: value-free macOS lifecycle transcript

Phase 5h.23 defines the evidence grammar for a future trusted native collector.
It does not collect evidence, elevate, or execute the lifecycle.

`evaluateMacosLaunchdLifecycleTranscript` accepts only the branded in-process
Phase 5h.22 gate and an exact bounded plain-object transcript. Each event has
exactly one fixed step and one fixed status. Preflight must complete before
mutation; any mutation failure must be followed by the complete ordered cleanup;
the final aggregate absence proof is always last.

## Effect grammar

Read-only checks and ordinary operations use `verified` or `failed`. The five
operations whose failure can otherwise hide a partial system mutation—account
create, binary exclusive-create, plist exclusive-create, launchd bootstrap, and
demand activation—use only:

- `verified`: the step's effect and immediate contract are established;
- `failed_no_effect`: the collector established that the attempted operation
  did not create/start/load anything;
- `failed_effect_ambiguous`: the operation failed without proving whether its
  effect happened.

Using a generic failure for those operations is rejected. This prevents an
uncertain OpenDirectory or launchd result from being silently interpreted as
"not owned."

## Derived ownership

The transcript cannot assert ownership directly:

- An account is owned only after this run's create and immediate identity
  re-verification both succeed. A create or identity ambiguity stays ambiguous.
- A binary or plist is owned after verified exclusive creation through its
  retained parent/file descriptors, independently of a later write or digest
  failure.
- A launchd job is owned only after bootstrap and loaded-identity verification
  both succeed. A bootstrap or identity ambiguity stays ambiguous.
- A process requires stop after an activation attempt of an owned job, including
  an effect-ambiguous activation. A proven no-effect activation may be marked
  not started.

Cleanup uses `verified`, `failed`, `skipped_not_owned`, `skipped_not_started`, or
`skipped_ownership_ambiguous`. The latter is mandatory for account/job identity
ambiguity: destructive deletion or bootout is structurally rejected. A final
read-only aggregate absence proof can show that no debris remains, but it never
retroactively authorizes the skipped destructive action.

## Outcomes and trust boundary

The fixed outcomes are `denial_verified`, `preflight_failed`, `mutation_failed`,
and `cleanup_failed`. Cleanup continues after every individual failure. If the
final aggregate absence proof fails, the structural report requires manual
recovery; if it succeeds after an earlier cleanup error, the report preserves
the cleanup failure but does not invent a remaining-debris claim.

The evaluator rejects proxies, accessors, custom prototypes, sparse arrays,
extra fields, reordering, omissions, illegal statuses, ownership-inconsistent
skips, and forged gates. Its return value contains only structural booleans and
a fixed terminal code—never the transcript, paths, account names, UIDs, GUIDs,
audit tokens, commands, native errors, or output.

Structural validity is not provenance. Even a complete synthetic transcript
returns `collector_trust_verified=false`, `live_test_verified=false`,
`authorization_ready=false`, and `install_gate_eligible=false`. A separately
reviewed native collector and explicit operator approval are still required
before any disposable system lifecycle can be considered.
