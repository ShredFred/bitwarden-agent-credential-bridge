# Phase 5h.16: value-free Windows lifecycle transcript

This phase defines the evidence grammar that a future trusted elevated collector
must satisfy. It does not collect evidence or run the service lifecycle.

`evaluateWindowsServiceLifecycleTranscript` accepts only the branded in-process
Phase 5h.15 gate and an exact bounded event list. Each event contains one fixed
step id and one fixed status. Preflight must finish before mutation. A successful
denial transcript must contain every mutation/re-verification step, the exact
denial step, every finally-cleanup step, and the final aggregate proof that the
service, binary, disposable root, and pipe are absent.

For partial failures, the state machine derives run ownership from prior verified
create steps. Root and binary ownership are derived independently from their
separate exclusive handle-acquisition events. Service/root/binary cleanup cannot be labeled `skipped_not_owned`
after this run created the object. A service whose start was never attempted may
use `skipped_not_started` only for its stop action; a failed or ambiguous start
attempt must still run stop. Delete and verification still
run. Cleanup continues after an individual failure and the transcript remains
incomplete when any cleanup or final absence check fails.

Exact plain-object schemas reject proxies, prototypes, accessors, extra properties,
invented steps, event reordering, illegal skips, omitted cleanup, and forged gate
objects. The returned report contains explicitly structural
`*_claim_structurally_complete` booleans and a fixed terminal code,
never events, paths, handles, SIDs, ACLs, native errors, or output.

## Trust boundary

Structural validity is not provenance. Caller-supplied JSON can forge booleans,
so the evaluator never exposes positively named denial or final-absence
verification facts. Even the complete synthetic success path returns
`collector_trust_verified=false`, `live_test_verified=false`, and
`authorization_ready=false`. A later native collector must be independently
authenticated and bind facts to retained handles before a separate adapter may
upgrade those fields. No such adapter exists in this phase.
