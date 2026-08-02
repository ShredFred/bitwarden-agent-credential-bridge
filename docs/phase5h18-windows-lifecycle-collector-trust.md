# Phase 5h.18: Windows elevated-collector provenance trust

This phase adds the missing adapter after Phase 5h.16: a pure evaluator that may
set `collector_trust_verified` only when a branded Phase 5h.15 gate, a
structurally complete Phase 5h.16 transcript, and exact injected collector
provenance all agree. It does not collect evidence, elevate, or mutate the host.

## Contract

`buildWindowsServiceLifecycleCollectorContract` accepts only an in-process
branded lifecycle gate and returns a branded, frozen contract. The contract
lists the required provenance fields, names the defense-in-depth-only signals,
and always reports mutation unauthorized, live test not executed/verified,
install ineligible, and authorization not ready. Cloned, spread, JSON, and
accessor lookalikes are rejected by `isWindowsServiceLifecycleCollectorContract`.

`evaluateWindowsServiceLifecycleCollectorTrust` revalidates the transcript
through Phase 5h.16, then accepts exactly one plain provenance object:

- required: elevated token verification, local-only collection, complete
  retained-handle binding, no path reacquisition, value-free stdout emission,
  absent stderr, gate step-surface match, and cleanup-finally binding;
- defense-in-depth only: UAC consent observed, admin group present, and high
  integrity reported.

UAC consent, Builtin Administrators membership, and high integrity never
establish collector trust when the required retained-handle elevation facts are
incomplete. Proxies, accessors, extra fields, and wrong schema versions fail
closed.

## Trust boundary

Even when required provenance is complete and `collector_trust_verified` becomes
true, the report keeps `live_test_verified=false`, `mutation_authorized=false`,
`install_gate_eligible=false`, and `authorization_ready=false`. Synthetic
provenance can satisfy the schema in unit tests; it is not live elevated
collection. A later operator-approved collector that actually performs the
disposable install/start/deny/stop/delete sequence is required before live
verification can become representable.

This phase performs no PowerShell launch, elevation, SCM/filesystem/registry/ACL
mutation, path emission, network or vault access, manifest execution, or
Bitwarden connection. Approval remains out-of-band and is never accepted as API
input.
