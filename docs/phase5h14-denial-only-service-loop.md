# Phase 5h.14 denial-only Windows service loop

This increment connects the fixed native pipe listener to the Windows
`ServiceMain` path without making the helper installable or capable of mutation.

Before the service reports `SERVICE_RUNNING`, it opens its current process token
and requires both fixed facts:

- `TokenUser` is LocalService (`S-1-5-19`).
- `TokenGroups` contains the enabled, non-deny-only SID of
  `BitwardenAgentCredentialBridgeHelper`.

The same identity gate runs before every listener session. The service creates
and verifies the fixed protected first-instance pipe once, keeps that handle for
its whole Running lifetime to prevent a namespace gap, and disconnects/reuses it
between clients. Remote-client rejection remains enabled, and
bounded overlapped I/O. It accepts only a 64-byte lowercase hexadecimal nonce
followed by LF. The reported client PID is pinned with a process handle, verified
live before and after token inspection. The pipe-presented impersonation token
must match that pinned process primary token, and its `TokenUser` must differ from
the service. Regardless of valid input, the only response is a fixed JSON denial
that marks target ACL evidence incomplete and the manifest executor absent.

Malformed frames, same-principal callers, disconnects, missing acknowledgements,
and I/O timeouts close that session and return to the loop. Pipe creation, kernel
DACL verification, or service self-identity failure stops the service fail-closed
with fixed service-specific codes. Stop/shutdown checks occur between bounded I/O
steps, with a five-second SCM wait hint.

## Evidence boundary

The source and published executable are tested through the existing console
denial harness. Static tests verify that the identity gate precedes Running and
that the service loop follows it. No service is installed, started, stopped, or
removed in this phase; therefore both SCM lifecycle and service pipe activation
remain not live-verified. There is still no target ACL collector, manifest
executor, filesystem surface, network stack, vault client, or Bitwarden access.
