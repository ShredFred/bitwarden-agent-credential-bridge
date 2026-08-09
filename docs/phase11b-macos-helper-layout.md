# Phase 11b: macOS helper layout plan

Pure layout contract for disposable and persistent LaunchDaemon helpers under
PrivilegedHelperTools / LaunchDaemons class roots. Forbids Application Support
and home writer roots. Emits no concrete host paths.

## API

`buildMacosHelperLayoutPlan(boundaryPlan, { layout_mode })`

Always reports `mutation_authorized=false`, `install_gate_eligible=false`, and
`authorization_ready=false`.
