# Operational SM key naming (MiViA + private-hq)

Onboarding and import steps (setup → seed → start):  
[`sm-onboarding-and-import.md`](sm-onboarding-and-import.md).

## Account boundary

- Bitwarden **Secrets Manager project** = account/tenant boundary.
- Repo bindings pin that with `sm_project_id`:
  - MiViA → `e186495e-8667-436f-9f78-b49800eba251`
  - private-hq → `1d9a72dc-75aa-4bf3-a528-b49800ebbf68`
- The machine DPAPI token only unlocks the allowlisted projects. A key for
  MiViA is created **inside** the MiViA project; private-hq likewise.

## Name formula

```text
{project}_{service}_{role}
```

Examples (canonical inventory):

| SM project | Service | Role keys |
|---|---|---|
| `mivia` | `api` | `mivia_api_bearer` |
| `mivia` | `web` | `mivia_web_user` + `mivia_web_pass` |
| `phq` | `ssh` | `phq_ssh_user` + `phq_ssh_pass` |

- **project** prefix matches the SM project (`mivia` / `phq`).
- **service** is the site or system (`api`, `web`, `admin`, later `github`, …).
- **role** is the credential shape (`bearer`, `header`, `query`, `user`/`pass`).

Repo `alias` (what operators start) mirrors that: `phq_web`, `mivia_api`.

## Source of truth

[`samples/operational/bindings-sm.json`](../samples/operational/bindings-sm.json)
lists every alias → project → key(s). Seed/prune from that file:

```bash
npm run seed:sm -- --i-approve-secrets-manager-machine-write --prune --smoke --i-approve-secrets-manager-machine-resolve
```

Extend with more service names when you attach real sites (`phq_github_…`);
keep the project prefix and put the secret in the matching SM project.
Never put secret values in the repo — only key names and project ids.
