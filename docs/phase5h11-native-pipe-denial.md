# Phase 5h.11 native pipe denial probe

This phase moves the Windows same-user denial proof into the native helper
executable without activating IPC from the SCM service entrypoint.

The console-only probe creates one fixed message-mode named pipe using
`PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and bounded
overlapped connect/read/write operations. A direct client
must send the exact non-secret lowercase hexadecimal nonce supplied when the
probe starts. The helper obtains the connected client's PID with
`GetNamedPipeClientProcessId`, impersonates that pipe client, opens the resulting
thread token, then safely reverts before returning. It separately opens its own
process token, validates both `TokenUser` SIDs, and compares them with `EqualSid`.

The pipe response contains fixed booleans only. The same-user test must report
`same_token_user=true`, `different_principal=false`, and
`authorization_denied=true`. It never returns the PID, SID, nonce, token, pipe
name, path, or native error. Missing, partial, oversized, or otherwise invalid
framing and identity-probe failures close the session without a response and
exit nonzero. After reading the fixed response, the client sends a fixed
non-secret acknowledgement; that bounded round trip replaces an unbounded pipe
flush. An idle or non-reading client cannot hold the one-shot probe indefinitely.
Pending I/O owns an unmanaged `OVERLAPPED` allocation until completion. If a
timed-out operation cannot itself reach cancellation completion within the fixed
second deadline, the console-only one-shot process exits immediately rather than
releasing live native I/O state or waiting without a bound.

This is not the service transport. `ServiceMain` does not create a pipe and no
service-specific pipe security descriptor exists yet. The console probe inherits
the launching token's ambient default DACL and makes no exclusive caller-admission
claim; every admitted caller still reaches only a deliberately non-authorizing
test path. The binary still
cannot execute manifests, access a vault or network, and remains ineligible for
installation. The next service step requires an explicit pipe DACL and
handle-bound verification of the installed service identity before activation.
