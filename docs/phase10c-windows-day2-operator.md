# Phase 10c: Windows Day-2 operator session

Phase 10c unifies Phase 10b bootstrap, the operational bridge, and Phase 10a
evidence refresh into one foreground Day-2 operator session.

## Behavior

1. Optional elevated persistent install (`--i-approve-persistent-install`).
2. Run the Phase 10b bootstrap (collect / optional vault-free apply / compose).
3. Fail closed unless branded compose reports `authorization_ready===true`.
4. Start the operational bridge with that branded evidence bundle.
5. Start the Phase 10a refresh loop; each tick recomposes and replaces the bridge.
6. If a tick drifts to `authorization_ready=false`, emit `authorization_drift`
   and keep the bridge on incomplete evidence — never invent `true`.
7. Ctrl+C stops bridge/refresh only. Uninstall is explicit
   (`--uninstall-after` or `npm run live:windows-persistent -- uninstall`).

## Commands

```bash
npm run test:phase10c
npm run live:windows-day2-operator -- --i-approve-persistent-install --interval-ms=15000
npm run live:windows-day2-operator -- --i-approve-persistent-install --uninstall-after
```

## Non-goals

- No personal/company Bitwarden pairing
- No vault client inside LocalService
- No OAuth/MFA/SSH/`env_inject`
- No same-user memory-isolation claim
- `mutation_authorized` stays false
