# Phase 5h.50: test-persistent LocalService lifecycle plan

Pure persistent install/uninstall plan that requires an eligible Phase 5h.46
install-gate report and a persistent Phase 5h.47 layout. Value-free operation
reports cover install/preflight/uninstall/prove_absent with collision rejection.
`authorization_ready` remains false; helper stays vault-free.

The elevated collector takes CLI-authoritative digest/length/marker arguments
(params.json must match). Install refuses a pre-existing service or ProgramData
root (`collision_detected`). Uninstall refuses deletion unless the fixed service
PathName and on-disk binary digest match the reviewed binding; foreign occupants
fail closed with `collision_detected` instead of deleting by name alone. The
Node runner returns a value-free `elevation_timeout` / `collector_result_*`
failure when `result.json` never appears.
