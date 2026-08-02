# Phase 5h.53 / 5h.54: retained-handle live collector + LocalService first-install apply

Phase 5h.53 retains an `OpenService` handle through `DeleteService` (via
`OpenSCManagerW`/`IntPtr.Zero` P/Invoke), binds completion nonces, and reports
provenance honestly. `retained_handle_binding_complete` and
`path_reacquisition_absent` are true only when delete used that handle.

Phase 5h.54 compiles a vault-free first-install apply under the helper module
ProgramData-class parent after a different-principal pipe session. The elevated
disposable collector opens a second session through the native narrow-rights
`--self-test-pipe-client service-apply` path (not `NamedPipeClientStream`, which
requests `CREATE_PIPE_INSTANCE`). Five exclusive paths are created when absent.
Directory ACLs grant Modify to the fixed per-service SID only. Helper remains
vault-free; `authorization_ready` stays false.
