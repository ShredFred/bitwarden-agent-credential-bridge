# Phase 5h.9: native Windows service-boundary preflight

This phase turns the pure Phase 5h.8 contract into a real, read-only host sensor.
It does not install the helper. On a machine without the fixed service, the
expected result is a valid report with `service_present=false`, every other
readiness fact false, and no host identifier or path returned.

## Bound inputs and output

The Node adapter accepts only the exact object produced by the in-process
canonical service-plan builder. Forged, copied, extended, accessor-backed, or
mutated lookalikes cannot launch the probe. Only the reviewed binary's lowercase
SHA-256 and byte length cross the process boundary. The public result contains
one schema version and twelve booleans. `snapshot_matches_plan` is recomputed
from every evidence fact, while `authorization_ready` must remain false;
contradictory output is rejected. The adapter exposes no runner, executable,
script-path, command, or timeout injection surface.

## Read-only native evidence

For the one fixed service name, the repo-owned PowerShell probe checks:

- service presence, exact Win32 own-process type, built-in `LocalService`
  account, demand start, and
  unrestricted service SID type;
- the SCM security descriptor through fixed-system `sc.exe sdshow`, with native
  `AccessCheck` denial of caller change-config, delete, DACL, and owner rights;
- a single argument-free absolute `.exe` image path;
- exact installed byte length and SHA-256;
- every image/path ancestor is reparse-free and owned only by SYSTEM,
  Administrators, TrustedInstaller, or the expected per-service SID;
- native caller denial for data/create, extended-attribute write, delete/
  delete-child, `WRITE_DAC`, and `WRITE_OWNER` rights throughout that chain.

Raw paths, SIDs, SDDL, registry values, ACLs, hashes, subprocess output, and
exception text never cross the public result boundary. Relative, drive-relative,
UNC/device, unresolved-variable, unquoted, argument-bearing, and non-`.exe`
image paths fail closed. PowerShell receives a minimal environment rather than
inheriting agent/provider variables, and the probe resolves `sc.exe` from the
OS-reported system directory. The initial PowerShell path still bootstraps from
the process `SystemRoot`; an in-process caller can influence that value, so this
is another reason the result remains non-authorizing. The probe is a path-racy advisory snapshot, not an authorization
token; repeating path snapshots does not close TOCTOU. A future positive gate
must use non-following handles, bind file identity/security/hash to those handles,
and test an installed disposable service matrix before authorization can become
representable.

No service, account, registry, file, ACL, process, or vault state is changed.
