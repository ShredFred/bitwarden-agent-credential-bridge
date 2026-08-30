# Agent-callable SM secret entry + presence checks

Agents must **never** ask the user to paste passwords into chat.

## How agents know which account it is

Three layers, none of which need the secret value:

1. **SM key name** — `{project}_{service}_{role}` is already the account binding  
   (`mivia_klicktipp_user`, `mivia_close_api_key`). Prefer reading `written` /
   `matching_keys` / `field_meta[].sm_key`.
2. **Public fields** — usernames, display labels, “which key is this?” nicknames
   come back in `public_values` (`secret: false`, usually `kind: text`).
3. **Form labels** — `field_meta[].label` tells the human/agent what was asked.

Secret fields (`kind: password` / `secret: true`) are written to SM but **never**
returned. `agent_secret_visible` stays `false`.

## Fast CLI (`bw-sm`) — preferred

```bash
npm run bw-sm -- presets
npm run bw-sm -- exists mivia prefix:mivia_klicktipp_ --approve
npm run bw-sm -- ask klicktipp --approve
npm run bw-sm -- ask-pair --project mivia --service something --approve
```

Example success (username public, password hidden):

```json
{
  "ok": true,
  "project": "mivia",
  "written": ["mivia_klicktipp_user", "mivia_klicktipp_pass"],
  "public_values": { "mivia_klicktipp_user": "api-subuser" },
  "secret_keys": ["mivia_klicktipp_pass"],
  "field_meta": [
    { "sm_key": "mivia_klicktipp_user", "label": "Benutzername", "secret": false, "kind": "text" },
    { "sm_key": "mivia_klicktipp_pass", "label": "Passwort", "secret": true, "kind": "password" }
  ],
  "agent_secret_visible": false
}
```

For an API key with a human label, the agent form should be:

```json
"fields": [
  { "sm_key": "mivia_acme_label", "label": "Bezeichnung", "kind": "text", "secret": false },
  { "sm_key": "mivia_acme_api_key", "label": "API Key", "kind": "password", "secret": true }
]
```

## Agent playbook (KlickTipp)

```powershell
npm run bw-sm -- exists mivia prefix:mivia_klicktipp_ --approve
npm run bw-sm -- ask klicktipp --approve
npm run bw-sm -- exists mivia prefix:mivia_klicktipp_ --approve
```

## Limitations

- Native dialog: Windows WinForms or macOS NSAlert (this slice).
- Max 8 fields; public values capped at 256 chars.
- Personal/company password vault remains out of scope.
