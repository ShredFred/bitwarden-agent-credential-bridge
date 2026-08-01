# Phase 5h.28: native macOS account soft ownership

Phase 5h.28 adds the account-ownership state machine required by the future
single-process LaunchDaemon lifecycle controller. It deliberately does not call
OpenDirectory or `dscl`; those fixed native/tool adapters are a later layer over
this independently fault-tested core.

An account is never owned by short name alone. Before create, the adapter must
prove all three namespaces absent: short name, candidate UniqueID, and fresh
GeneratedUID. The state machine snapshots the complete candidate record:

- fixed hidden short name;
- system-range UniqueID;
- canonical uppercase GeneratedUID;
- `/usr/bin/false` or `/usr/bin/nologin` shell; and
- `/var/empty` home.

Create success is only provisional. The controller immediately re-reads the
record, re-probes all three namespaces as present, and compares every field
before setting `verified`. A create that reports
success but re-reads with any drift is ambiguous and is not eligible for
automatic deletion.

Deletion is allowed only for a previously created and verified record, after a
fresh full-tuple re-read. The delete adapter receives the complete recorded
identity, not merely the short name. After deletion, name, UniqueID, and
GeneratedUID must all be absent before ownership is cleared. Any mismatch or
probe/delete error is ambiguous and preserves the record for manual review.

Ownership storage requires explicit initialization and is one-shot. `prepare`
refuses to overwrite any prepared, created, or ambiguous state. Successful
delete clears preparation plus the identity snapshot, so any later create
requires a fresh three-namespace absence proof.

The fake-directory self-test proves:

- a clean prepare/create/reverify/delete/absence lifecycle;
- a pre-existing collision causes no create or delete;
- post-create identity drift never becomes verified or deleted; and
- pre-delete identity replacement remains present and delete is never called; and
- a final adapter-local delete race is detected and preserves the swapped record.

```bash
npm run test:phase5h28
```

This phase performs no system account mutation, elevation, launchd work,
credential access, or live lifecycle test.
