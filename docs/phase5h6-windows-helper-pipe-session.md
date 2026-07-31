# Phase 5h.6: Windows native helper pipe session

This phase replaces the synthetic Windows transport and token facts with a real
denial-path session. It still does not install or run a privileged helper.

## Native transport

The parent derives an unguessable short pipe name and handshake nonce internally
from cryptographic randomness and the verified disposable workspace. The
calling Bridge process connects directly and retries only that local pipe. The
repo-owned PowerShell probe uses fixed C# P/Invoke declarations to call `CreateNamedPipe`
with:

- `FILE_FLAG_FIRST_PIPE_INSTANCE`;
- exactly one instance; and
- `PIPE_REJECT_REMOTE_CLIENTS`.

After connection, the probe calls `GetNamedPipeClientProcessId` and
`GetNamedPipeServerProcessId`. It inspects the expected parent, connected client,
and current server process tokens while the client is still connected. The
connected client's `TokenUser` must equal the parent caller's `TokenUser` before
`caller_token_verified` becomes true.

## Value-free evidence

Raw SIDs never leave the probe. It hashes the caller and helper `TokenUser` SID
strings with SHA-256 and emits only the exact Phase 5h.2 fact schema. Raw token
handles, PIDs, pipe handles, names, ACLs, process output, and exception text are
not returned by the public API. Process output is bounded, strict UTF-8, and
exact-schema parsed; stderr, timeout, non-zero exit, and extra output fail closed.

## Expected authorization result

On this workstation the probe and caller have the same `TokenUser`. The live
facts therefore compile to:

- local transport verified;
- identity verified;
- different principal false.

The Phase 5h.1 authorization call must terminate with
`same_principal_rejected`. ACL and effective-write facts remain false because
this phase performs no target access checks. Any other authorization result is
a stable failure, and the manifest executor is never invoked.

## Remaining live gate

A later explicitly approved disposable test must provision or use a real second
principal, establish target ACLs that deny the caller and allow only the helper,
combine the native session with the inherited launcher handle, and clean up the
identity/service. Linux AF_UNIX/SO_PEERCRED and macOS XPC/audit-token collectors
also remain unimplemented.
