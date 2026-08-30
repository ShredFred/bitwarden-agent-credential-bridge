# Later local secret purge (DO NOT RUN YET)

Local DPAPI / `.env` copies may have been imported into Bitwarden Secrets
Manager. **Do not delete** them until consuming apps fully run on SM resolve
and the operator explicitly approves a digest-verified purge gate.

## Policy

- Tracked import manifests list **basenames and key names only**. They must
  never contain secret values.
- Machine-local stores (DPAPI, Keychain, owner-only files, `.env`) stay on
  disk until that later gate.
- Keep the SM machine-token store until a separate uninstall decision.

## Verify before any purge

```powershell
npm run verify:hq-sm-parity -- --i-approve-secrets-manager-machine-resolve --env-root "C:\path\to\your-app"
```

Then prove consuming apps resolve from SM only. Local delete remains disabled
in this slice (`purge_disabled`).
