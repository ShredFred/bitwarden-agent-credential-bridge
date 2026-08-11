# Secrets Manager onboarding and import

This is the canonical operator/agent guide for making **MiViA** and
**private-hq** usable on a Windows (or macOS) machine without putting tokens or
secret values in chat, logs, or agent `process.env`.

Related:

- Install / token paste: [`agent-windows-install.md`](agent-windows-install.md)
- Laptop quickstart: [`windows-laptop-onboarding.md`](windows-laptop-onboarding.md)
- Key naming rules: [`sm-operational-key-naming.md`](sm-operational-key-naming.md)
- Bindings source of truth: [`samples/operational/bindings-sm.json`](../samples/operational/bindings-sm.json)

## Model (read this once)

```text
Machine account (Freddy Desktop, …)
  └─ access token  →  DPAPI / local secure store (once)
        └─ allowlisted SM projects
              ├─ MiViA
              └─ private-hq
                    └─ secrets named {project}_{service}_{role}
                          └─ repo bindings alias → policy + class + keys
```

1. **Account boundary** = Bitwarden SM **project** (MiViA vs private-hq).  
   Repo field: `sm_project_id`.
2. **Service** = site/system (`web`, `api`, later `github`, …).  
   Repo field: `alias` + key prefix.
3. **Role** = credential shape (`bearer`, `user`/`pass`, …).  
   Repo fields: `sm_secret_key` (+ `sm_secret_key_password` when needed).
4. Secret **values** never live in git — only names and project ids.

## Onboarding checklist

### A. Human once in Bitwarden SM

1. Create a **machine account** for this PC.
2. Assign projects **MiViA** and **private-hq**.
3. Create an **access token** (Zugriffstoken). Do not paste it into chat.

### B. Local bridge setup (DPAPI / secure store)

Preferred: Release Setup EXE → Start Menu **Bitwarden Agent Bridge Setup**.

From source:

```powershell
npm ci
# bws must be on PATH (default install: %LOCALAPPDATA%\Programs\Bitwarden)
npm run setup:sm:wizard
# or: npm run setup:sm -- --i-approve-sm-machine-setup
```

Paste the token only into the setup window. Cloud is default.

### C. Import real local secrets into SM (preferred)

If this PC already has MiViA / personal-hq secrets under `~\.codex\secrets\`
(DPAPI CliXml or `ConvertFrom-SecureString` `.dpapi` files), import them
**agent-blind** into the allowlisted SM projects. Default is dry-run (no SM
write, no local delete):

```powershell
npm run import:local-to-sm
# when dry-run is all green (add --env-root for personal-hq .env paths):
npm run import:local-to-sm -- --apply --i-approve-secrets-manager-machine-write --env-root "F:\Github Repos\personal-hq"
```

Manifest: `samples/operational/local-to-sm-import-manifest.json`  
Local purge stays **disabled** until a later digest-verified gate — old DPAPI
files are kept after a successful apply. See
[`sm-local-purge-later.md`](sm-local-purge-later.md).

Team journey: once SM holds the keys, assign the same machine/project access to
Miriam or Jessica; they run setup once and do **not** need your local DPAPI
files.

### D. Seed operational broker class slots (optional harness)

Bindings in `samples/operational/bindings-sm.json` define broker aliases
(bearer/header/basic/web/ssh/ftp). Seed creates missing class-slot keys with
fake harness values, optionally prunes unknowns, then smokes. Prune **keeps**
keys listed in the local→SM import manifesto so real inventory is not deleted:

```powershell
npm run seed:sm -- --i-approve-secrets-manager-machine-write --prune --smoke --i-approve-secrets-manager-machine-resolve
```

### E. Start the operational bridge

```powershell
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Or re-verify the full matrix:

```powershell
npm run live:sm-matrix -- --i-approve-secrets-manager-machine-resolve
```

## Adding a real website / service

1. Pick the SM project (`mivia` or `phq`).
2. Choose a **service** slug (`github`, `heroku`, `intranet`, …).
3. Create keys in **that** Bitwarden project using the naming formula
   (`docs/sm-operational-key-naming.md`), e.g. `phq_github_api_bearer`.
4. Add a binding row in `samples/operational/bindings-sm.json` (or a private
   overlay file) with matching `alias`, `credential_class`, `policy`, and
   `sm_secret_key` / `sm_secret_key_password`.
5. Put the real value in SM (UI) **or** agent-blind write:

```powershell
# value on stdin only — never echoed
"***" | npm run live:sm-write -- --i-approve-secrets-manager-machine-write --project private-hq --key phq_github_api_bearer
```

Or open the **agent-callable WinForms dialog** (multi-field, value-free result):

```powershell
npm run sm:secret-entry -- --i-approve-secrets-manager-machine-write `
  --form-file samples/operational/sm-secret-entry-klicktipp.json
```

See [`sm-secret-entry-dialog.md`](sm-secret-entry-dialog.md) for the form schema
and `npm run sm:secret-exists` so agents can check presence without reading values.

6. Re-run seed **without** inventing new fake values for that key if you only
   added a binding for an existing SM value — or upsert via write as above.
7. Start `start:operational:sm` and confirm the new alias smokes.

Do **not** store real passwords in the repo. Do **not** put `BWS_ACCESS_TOKEN`
in agent-visible environment variables.

## Import from an existing SM inventory

If secrets already exist in MiViA / private-hq:

1. Rename (or recreate) keys to `{project}_{service}_{role}` when practical.
2. Point bindings at those exact key names.
3. Prefer `npm run import:local-to-sm` when the source is local DPAPI / `.env`.
4. Prefer `--prune` only after bindings **and** the local→SM manifesto are
   complete — prune deletes keys that are in neither list.

## Uninstall / revoke

```powershell
npm run uninstall:sm -- --i-approve-sm-machine-uninstall
```

Also revoke the machine token in Bitwarden SM when the PC should lose access.
Installed product: Windows **Apps & features**.

## Agent hard rules

- Never print tokens, passwords, or secret values.
- Never claim `authorization_ready=true` from SM unlock or seed alone.
- Keep the helper vault-free; resolve only in the Bridge/broker process.
- Use approval flags only on explicit CLI entrypoints — not as library inputs.
