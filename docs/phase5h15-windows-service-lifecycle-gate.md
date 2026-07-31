# Phase 5h.15: disposable Windows service lifecycle gate

This phase freezes the exact scope of the first elevated SCM test without
installing or starting anything. `buildWindowsServiceLifecycleGate` accepts only
the in-process canonical Phase 5h.8 boundary plan and binds its reviewed binary
digest and byte length to one ordered denial-only lifecycle.

Before any mutation, the lifecycle re-verifies the canonical boundary and binary,
proves the fixed service and pipe absent, selects a fresh disposable root, and
proves its root/binary targets absent. It then stages the reviewed helper beneath that disposable
administrator-controlled root, re-verifies the binary and ACLs, creates only the
fixed demand-start LocalService service with its unrestricted service SID, starts
it, verifies the running service and pipe-server identity, performs one
value-free different-principal denial handshake, and then stops/deletes the
service and removes the disposable binary/root. Final evidence must prove that
the service, binary, root, and fixed pipe are absent.

Every transition has a fixed stop condition. Cleanup is a separate `finally`
phase triggered after the first run-owned object is successfully created; it continues through individual
cleanup failures and always ends with the absence check. Any binary drift, pre-existing
service, scope mismatch, service/ACL/identity mismatch, non-denial response, or
incomplete cleanup fails closed. Cleanup must be attempted after any activation,
even when an intermediate verification fails.

Every created service/file/root remains bound to a handle retained by this run.
Each staging, configuration, ACL, and cleanup mutation is followed immediately by native verification
through retained object or parent-directory handles. Cleanup may stop/delete/remove only run-owned
objects whose retained-handle identities still match. If service or root creation
collides after preflight, the run must never reacquire that object by fixed name or
path for destructive cleanup.

## Approval boundary

Approval is deliberately not an input to the API. The returned envelope always
states `mutation_authorized=false`, `live_test_executed=false`, and
`install_gate_eligible=false`. A later executor may exist only after Frederik
explicitly approves this named disposable install/start/remove test and its
elevation scope in the active task. Generic permission to develop the bridge is
not installation approval.

The gate is branded in-process and `isWindowsServiceLifecycleGate` rejects JSON,
structured-clone, spread, accessor, and forged lookalikes. A future executor must
rebuild it from the canonical boundary plan in the same process and combine it
with fresh out-of-band operator approval; serialized gate data is never an
approval or authorization capability.

This phase emits no installer commands, paths, SIDs, ACLs, service output, or
native errors. It performs no elevation, filesystem/registry/SCM mutation,
network or vault access, manifest execution, or Bitwarden connection.
