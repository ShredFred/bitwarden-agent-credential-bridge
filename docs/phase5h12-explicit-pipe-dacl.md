# Phase 5h.12 explicit native pipe DACL

The console-only denial probe no longer inherits the launching token's default
DACL. Before `CreateNamedPipe`, the native helper builds one fixed protected
security descriptor with exactly three Allow entries:

- LocalSystem: full control;
- the fixed `BitwardenAgentCredentialBridgeHelper` service SID: full control;
- Authenticated Users: file-generic read plus `FILE_WRITE_DATA` and
  `FILE_WRITE_ATTRIBUTES` for the future native local client handshake and
  message-read-mode selection. The mask deliberately excludes
  `FILE_APPEND_DATA`, which aliases `FILE_CREATE_PIPE_INSTANCE` on named pipes.

There is no Everyone, Anonymous, Network, Builtin Administrators, owner-rights,
inherited, Deny, or additional entry. Remote clients remain kernel-rejected by
`PIPE_REJECT_REMOTE_CLIENTS`; the Authenticated Users entry is therefore an
admission rule for local handshakes, not authorization to mutate anything.

The included native self-test client opens the pipe with exactly generic read,
`FILE_WRITE_DATA`, and `FILE_WRITE_ATTRIBUTES`; it never requests generic write or
`FILE_CREATE_PIPE_INSTANCE`. It sends generated non-secret denial frames only,
validates the server response byte-for-byte, and reports explicitly that server
identity is not yet verified. It is not a production Bridge client.

Any authenticated local principal can still connect, consume one bounded session,
or send an invalid frame. Deadlines limit that availability impact but do not
eliminate local denial of service. Before any sensitive request exists, the real
Bridge client must authenticate the connected server PID, `LocalService`
`TokenUser`, and expected service-SID token group; this phase does none of those
and sends non-secret denial frames only.

After pipe creation, the helper queries the kernel object's DACL and fails closed
unless it is protected and its ACE count, order, type, flags, masks, and SIDs
match the compiled contract exactly. The live response exposes booleans only;
it never returns the service SID, descriptor, account, ACL, path, or native error.

This phase still runs only through the console denial mode. `ServiceMain` does
not activate the pipe, no installed service identity has been authenticated,
the manifest executor is absent, and `install_gate_eligible` remains false.
