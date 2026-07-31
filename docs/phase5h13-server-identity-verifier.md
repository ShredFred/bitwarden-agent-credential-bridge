# Phase 5h.13 fixed server identity verifier

The native client now has a separate verification-only mode that connects to the
fixed local pipe with the narrow Phase 5h.12 rights but sends no request.

It obtains the pipe server PID from the connected handle, pins that process with
`PROCESS_QUERY_LIMITED_INFORMATION`, and confirms the process handle still maps
to that PID. It queries the fixed SCM service before and after token inspection;
both snapshots must report the same nonzero PID, running state, and Win32
own-process type, and that PID must equal the pipe server PID.
The pinned process handle includes `SYNCHRONIZE`, and a zero-time wait must return
`WAIT_TIMEOUT`; process exit code 259 is deliberately not used as liveness proof.

The pinned process token must have `TokenUser` equal to LocalService. Its bounded
`TokenGroups` buffer must contain the fixed service SID with `SE_GROUP_ENABLED`
and without `SE_GROUP_USE_FOR_DENY_ONLY`. Raw PID, SID, token, account, SCM output,
and native errors never leave the process.

The current console server is intentionally rejected: it proves live pipe PID and
token access, but it is not the installed SCM service, is not LocalService, and
does not carry the service SID. The verifier therefore reports only value-free
false facts, `request_sent=false`, and `authorization_denied=true`.
An unverified identity exits nonzero even after emitting that value-free report;
exit zero is reserved for a fully verified server identity.

This phase does not activate IPC in `ServiceMain`, install or start a service,
elevate, mutate state, execute a manifest, access normal roots, use a network, or
connect to Bitwarden. A positive service identity result is not yet live-tested.
