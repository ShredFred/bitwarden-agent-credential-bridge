# Later local secret purge (DO NOT RUN YET)

Local DPAPI / `.env` copies were imported into Bitwarden Secrets Manager.
**Do not delete** them until HQ repos are fully on SM resolve and the user
explicitly approves a purge gate.

## Candidates (names only)

### MiViA DPAPI (`~\.codex\secrets\`)
- All `mivia-*.credential.xml` inventory files mapped in
  `samples/operational/local-to-sm-import-manifest.json`
- Keep until decided separately: `bitwarden-agent-sm-machine.credential.xml`,
  `mivia-bitwarden-agent-manager-dev.credential.xml`

### private-hq / personal-hq
- `personal-hq-brave-api-key.dpapi`
- `personal-hq-brave-answer-api-key.dpapi`
- `personal-hq-context7-api-key.dpapi`
- Secret vars in `personal-hq/.env` (API keys/tokens/passwords mapped to `phq_*`)
- Secret vars in `personal-hq/active/provider-lab/**/.env.local`

## Keep as config / separate decision
- Non-secret `.env` config (URLs, flags, model names)
- Tax / PII fields in `.env` (not API keys)

## Verify before any purge
```powershell
npm run verify:hq-sm-parity -- --i-approve-secrets-manager-machine-resolve --env-root "F:\Github Repos\personal-hq"
$env:MIVIA_SECRET_SOURCE='sm_only'; # then run MiViA balance probes
$env:PHQ_SECRET_SOURCE='sm_only';   # then run personal-hq context7/brave resolve
```
