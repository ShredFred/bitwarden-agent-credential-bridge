# Phase 5h.8: passwordless Windows service-boundary plan

The intended Windows writer boundary must not introduce another password for an
agent to handle. The future helper is therefore fixed to the built-in
`NT AUTHORITY\LocalService` identity and an unrestricted per-service SID. A
human-approved installer can later grant the service SID narrowly scoped write
access while denying the interactive caller, without placing an account password
in a repository, environment variable, command line, DPAPI blob, or agent reply.

## Pure contract in this phase

`buildWindowsServiceBoundaryPlan` accepts only the platform plus a reviewed
helper binary's lowercase SHA-256 and byte length. It returns an immutable,
non-executable plan with fixed service and pipe identities, demand start, no
required network or vault access, and the complete approval/reverification gate
list. It deliberately returns no installer command or mutable host instruction.

The future service boundary must prove all of the following after installation:

- first-instance named pipe with remote clients rejected;
- connected caller PID and token binding;
- connected server PID/token binding to the `LocalService` TokenUser and the
  expected per-service SID token group, so a same-user pipe squatter cannot
  impersonate the demand-start helper;
- a different live `TokenUser` for the helper;
- caller write denied and service-SID write allowed on every bound target;
- target and relevant ancestor ownership held by Administrator, SYSTEM,
  TrustedInstaller, or exactly the expected per-service SID, never by the shared
  `LocalService` TokenUser or the interactive caller,
  with caller `WRITE_DAC`, `WRITE_OWNER`, `DELETE`, create/data rights, and
  parent `FILE_DELETE_CHILD` all denied by native effective-access checks;
- the installed binary still matches the reviewed digest;
- the binary and every parent are reparse-free and caller-nonwritable;
- the service-object DACL prevents the caller from changing image path, account,
  start configuration, or other security-relevant service settings;
- disposable install, rollback, and cleanup complete without value exposure.

## Why `LocalService`

`LocalService` is passwordless and has deliberately limited local privileges.
Its `TokenUser` identifies the shared built-in account; the separate service SID
must appear as a token group and gives target ACLs a service-specific identity.
The helper must not retrieve Bitwarden secrets
or require outbound network access; it is only the narrow writer/executor behind
the authenticated Bridge protocol.

This phase does not prove that the service exists or that these controls are live.
Service installation, elevation, ACL mutation, start/stop, and cleanup require a
separately approved disposable live gate followed by native read-only evidence.

The ordinary per-user LocalAppData/home layout from the portable bootstrap plan
cannot satisfy this stronger boundary when the interactive caller owns its parent
directories. Production-managed artifacts must move under a trusted-system/admin
root or one owned exactly by the expected per-service SID; the shared
`LocalService` TokenUser is explicitly insufficient. Any user-facing path must be a deliberately designed,
read-only indirection that does not restore delete, ownership, or DACL control.
