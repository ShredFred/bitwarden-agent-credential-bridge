# Phase 5h.26: gated dev Bitwarden resolver

Branded in-process live gate plus injected adapter resolve one item field into
short-lived broker memory. Personal/company vaults are forbidden; helper remains
vault-free; secrets must not be logged. Tests use synthetic adapters; a live
DPAPI adapter may be supplied only under operator-approved host conditions.
The fixed basename `mivia-bitwarden-agent-manager-dev.credential.xml` is read
through `scripts/dev-bitwarden-dpapi-probe.ps1`, which refuses personal/company
vault flags and pins Purpose by SHA-256. The helper remains vault-free; secrets
stay in short-lived broker memory and must never be logged.
