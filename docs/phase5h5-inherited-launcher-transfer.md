# Phase 5h.5: inherited launcher handle transfer

This phase replaces one previously paper-only boundary with real process I/O.
A short-lived child receives the generated launcher through an inherited
read-only file handle and receives the canonical Phase 5h.1 request separately
through stdin. The child independently parses the request, reads the handle to
EOF, and verifies both the exact length and SHA-256 digest.

## Transfer construction

The parent first verifies the marked disposable workspace. It creates an
exclusive cryptographically random file beneath that root, writes and syncs the
non-secret launcher bytes, opens a separate read-only handle, unlinks the name,
and closes the writer. Only the read handle is placed in the child stdio table.
The launcher path and bytes are absent from argv, environment, request JSON,
stdout, stderr, and the returned result.

The public API deliberately accepts only `workspace`, `requestBytes`, and
`launcherBytes`. Caller-supplied paths, descriptors, commands, executables,
environment, or peer-evidence booleans are schema errors.

## Fail-closed worker contract

The request is capped at 64 KiB and launcher input at 1 MiB. Worker output is a
single exact UTF-8 JSON line of at most 1 KiB. Only the exact verified response
is accepted. Timeout, stderr, a non-zero exit, malformed or extra output, digest
or length mismatch, missing handles, and child-process failures return stable
value-free errors.

## Security claim and remaining gate

This proves actual inherited-handle delivery and independent child hashing. It
does not prove that the child is a different OS principal, that stdin is an
authenticated production IPC transport, or that a same-user attacker cannot
interfere. It never calls the disposable manifest executor.

The next native phases must add platform transports and live identity
collection: Windows named pipes and token inspection, Linux AF_UNIX/SO_PEERCRED,
and macOS Mach-message audit tokens. A successful authorization/apply path still requires
an explicitly approved disposable second-principal live gate.
