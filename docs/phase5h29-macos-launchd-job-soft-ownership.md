# Phase 5h.29: native launchd job soft ownership

Phase 5h.29 implements the launchd-job ownership and denial lifecycle state
machine for the future native controller. It uses a fake launchd adapter for
fault injection and performs no actual bootstrap, process activation, Mach IPC,
or bootout.

Preparation requires both the fixed system label and fixed Mach service name to
be absent. The candidate is fixed to the reviewed helper path, hidden account,
matching label/Mach name, binary SHA-256, plist SHA-256, and demand-only policy.

Bootstrap success is provisional. Ownership becomes verified only after an
immediate loaded-job read matches every field and both label and Mach service
probe present. An ambiguous bootstrap or identity mismatch is never adopted and
is not eligible for automated bootout.

Every bootstrap invocation other than a proven no-effect result is recorded as
attempted. If the job never becomes verified, cleanup performs absence-only
label/Mach probes: proven absence clears the attempt, while any presence or
probe uncertainty remains ambiguous and never triggers destructive bootout.

Activation re-verifies the job first. A proven no-effect activation requires no
process stop; every other error or ambiguous activation records that a process
may have started,
so cleanup attempts a job-scoped stop before bootout. Denial is accepted only
after both loaded-job and helper-process identity are freshly verified.

Cleanup freshly verifies the job, attempts process stop after activation,
re-verifies, invokes a conditional full-identity bootout adapter, and proves
both label and Mach service absent. Stop failure does not prevent bootout while
job identity remains intact, but preserves an ambiguous terminal result. A
foreign swap before cleanup or inside the bootout adapter is never removed.

The self-test proves clean denial/cleanup, preexisting collision, post-bootstrap
drift, ambiguous activation cleanup, pre-cleanup foreign replacement,
activation-error cleanup, adapter-local bootout race, and continued cleanup
after stop failure.

```bash
npm run test:phase5h29
```

This is reusable native control logic, not a live launchd test, trusted evidence,
authorization, or installation permission.
