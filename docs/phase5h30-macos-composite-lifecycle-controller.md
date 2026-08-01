# Phase 5h.30: composite native macOS lifecycle controller

Phase 5h.30 composes the retained-FD file, full-tuple account, and full-identity
launchd-job ownership primitives into the future privileged controller's exact
control flow. Its adapters remain fake and its file mutations remain confined
to a private `/tmp` fixture.

Before the first mutation the controller verifies artifact SHA-256 bindings,
both retained parent descriptors, fixed binary/plist absence, account identity
namespace absence, and launchd label/Mach-name absence.

Mutation order is fixed:

1. create and reverify the helper account;
2. exclusively publish and reverify the signed helper bytes;
3. exclusively publish and reverify the plist bytes;
4. bootstrap and reverify the exact launchd job;
5. activate and reverify the helper process; and
6. exercise the denial-only exchange.

The finally path runs after any first mutation, regardless of the failing stage:

1. stop and bootout the run-owned launchd job;
2. unlink the run-owned plist via retained descriptors;
3. unlink the run-owned binary via retained descriptors;
4. delete the full-tuple run-owned account; and
5. aggregate file, account-name/UID/GUID, label, and Mach-name absence.

Every cleanup operation is attempted even when an earlier cleanup step fails.
Any remaining or ambiguous object sets `manual_recovery_required`; a replaced
foreign object is preserved rather than removed.

The cross-layer fixture proves a complete denial lifecycle, collision abort
before mutation, ambiguous account creation with no unsafe delete, ambiguous
create-result debris with mandatory manual recovery, activation with full
cleanup, and plist path replacement that is preserved
while the job, binary, and account still clean up.

```bash
npm run test:phase5h30
```

This phase contains no real OpenDirectory, launchctl, Mach, elevation, approval,
network, Keychain, vault, or credential adapter and performs no system mutation.
