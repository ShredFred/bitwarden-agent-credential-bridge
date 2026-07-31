# Phase 5h.3: Linux helper peer evidence

Phase 5h.3 compiles trusted Linux collector facts into the five value-free
booleans required by the helper protocol. It performs no I/O.

The future collector must run from a helper in the initial user namespace and
prove AF_UNIX `SO_PEERCRED` plus peer/helper process binding. Caller and helper
UIDs must be translated to the initial user namespace and represented only as
SHA-256 digests of one canonical host-UID encoding. The peercred UID must agree
with the translated caller host UID.

This prevents namespace-root cosplay: a caller can map its host UID to UID 0 in
its own user namespace, but that does not change its host principal. Equal host
UID digests always yield `different_principal: false`, even when no-new-privs,
empty effective capabilities, seccomp, Landlock, or a root UID mapping are active.

Write claims require verified checks for every manifest-bound target from the
helper mount namespace. Skipping that namespace, any target, or the effective
access procedure makes both write claims false.

The evaluator returns no UID digest, PID, uid map, namespace identifier, path,
capability set, filter, ACL, or exception detail. Missing, extra, accessor-backed,
wrongly typed, raw-UID-shaped, and non-AF_UNIX evidence fails with the fixed
`peer_identity_unverified` code.

AF_UNIX I/O, `SO_PEERCRED`/pidfd collection, `/proc` reads, namespaces, mounts,
Landlock/seccomp setup, dedicated UID provisioning, helper launch, handle passing,
real user roots, manifest execution, and Bitwarden access remain live-gated.

```bash
npm run test:phase5h3
```
