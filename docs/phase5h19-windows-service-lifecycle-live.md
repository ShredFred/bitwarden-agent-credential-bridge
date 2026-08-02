# Phase 5h.19: disposable elevated Windows service lifecycle live test

This phase executes the operator-approved disposable LocalService
install/start/deny/stop/delete matrix on Windows. Approval is out-of-band in the
active task and is never an API field.

## Flow

1. Publish the reviewed helper with the pinned toolchain into an OS-temp workspace.
2. Rebuild the branded Phase 5h.8 plan and Phase 5h.15 gate from the published
   digest and byte length.
3. Stage payload bytes and a marker nonce under a fresh temp staging root, then
   best-effort harden the staging ACL. Digest/length/nonce/denial nonce are also
   passed as authoritative collector CLI arguments so staged `params.json`
   TOCTOU cannot silently retarget the reviewed binary binding.
4. Launch the repo-owned elevated collector
   (`scripts/windows-service-lifecycle-live-collector.ps1`), prompting UAC when
   the current process is not already elevated.
5. The collector creates a disposable ProgramData root, writes the binary through
   an exclusive handle, creates the fixed demand-start LocalService service,
   sets unrestricted service SID, locks service/binary ACLs, starts the service,
   verifies server identity, then runs the denial client itself (medium-IL via
   `runas /trustlevel` when available, otherwise a direct different-TokenUser
   client). Forgeable `state.json` handoff is not used. Cleanup re-checks the
   run-owned binary path/digest before `sc delete`, then proves absence.
6. Node parses the value-free result, revalidates the transcript (5h.16) and
   provenance (5h.18), and brands the live report only from the operator-approved
   runner. Structural `evaluateLiveCollectorResult` alone is not an install
   capability. The live collector currently reports honest
   `retained_handle_binding_complete=false` and `path_reacquisition_absent=false`
   because cleanup still uses path/name after handles close; therefore a real
   live run does not claim `collector_trust_verified` until retained-handle
   cleanup exists.

The service loop prefers OpenProcess PID↔token binding for different-principal
denial and falls back to pipe-impersonation TokenUser compare with
`client_pid_bound=false` when LocalService cannot open the interactive caller.

## Non-goals

- No Bitwarden/DPAPI credential access
- No persistent production install authorization from unbranded or forged reports
- Persistent LocalService install is a later phase; this matrix only proves the
  disposable elevated denial path and always cleans up
- No approval token accepted by the API
- No path/SID/ACL/command leakage in the public report
- Same-user concurrent malware during elevation is not a fully closed threat;
  CLI-authoritative digests and branding reduce, but do not eliminate, that class

## Edge cases covered by the collector/orchestrator

- Pre-existing fixed service or pipe fails closed in preflight
- Mid-mutation failures still run finally cleanup for run-owned objects only
- Denial client is collector-owned (no forgeable staging state signal)
- UAC elevation timeout surfaces as `elevation_timeout` without mutating by name
- Service delete requires PathName/digest identity match for run-owned cleanup
- Collector provenance cannot alone authorize persistent install; install-gate
  requires a branded live report
- Result files carry a CLI-bound completion nonce; forged `result.json` without
  that nonce is rejected before branding
- Elevated collector locks staging writes (Authenticated Users read-only) before
  emitting `result.json`

Run with:

```bash
node scripts/run-windows-service-lifecycle-live.mjs
```

UAC consent is required unless the shell is already elevated.
