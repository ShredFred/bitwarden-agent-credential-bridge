# Phase 17: Bridge-owned browser (agent-blind login)

Phase 17 adds a Bridge-owned browser session for `browser_form_login` when
the agent must see a UI but must not hold cookies or type passwords.

The agent is the eyes. The Bridge is the hands for secrets.

## What works today

- Loopback fake login site (same Phase 6 fixture)
- Agent `GET /snapshot` returns value-free field **indices** (username /
  password / submit). No HTML, CSRF values, cookies, or passwords.
- Agent `POST /select_targets` picks among those indices only. Extra fields
  such as `selector` / CSS / XPath fail closed (`extra_field_forbidden`).
- Agent `POST /inject_login` sends **no** credential. The Bridge re-checks
  origin, password `type`, and same-origin form action, then fills from
  in-memory secrets.
- After `logged_in=true`, the agent may `POST /goto` only on
  `allowed_paths`.
- `cookie_list`, `eval`, `cdp`, `fill`, `state_save`, and related ops return
  `session_material_forbidden` or `command_forbidden`.
- Exposure tests scan username, password, hidden-field values, and issued
  session cookies on every agent-readable surface.
- One Bridge-owned browser at a time. MFA/CAPTCHA fail closed.

## Contract

- Same policy version 5 `browser_form_login` as Phase 6. This is a different
  runtime (`startBridgeOwnedBrowser`), not `startBroker` and not the fetch
  session broker's auto-login.
- Candidate generation is required on select. Stale generations fail closed.
- Cookies stay in the adapter jar. They never appear in JSON, logs, or the
  session handle.
- `authorization_ready` stays false. Same-user memory isolation is not claimed.
- Playwright / Chrome extensions / agent CDP are **not** wired. A later slice
  may add a Bridge-owned Playwright driver behind the same command allow-list.
  Raw `playwright-cli` remains forbidden for secrets.

## Commands

```bash
npm run test:phase17
```

## Agent HTTP surface

```http
GET  /status
GET  /snapshot
POST /select_targets   {"generation":1,"username_index":0,"password_index":1,"submit_index":2}
POST /inject_login     {}
POST /goto             {"path":"/home"}
```

If the task needs cookies, storage state, or CDP, this surface will not grow
those ops. Use the HTTP credential brokers (or stop) instead.

## Non-claims / not ready

- Not a general password manager for arbitrary public websites
- Not `traffic.mivia.ai` or other non-loopback hosts (needs a later live gate)
- Not Playwright-CLI, Claude Chrome extension, or agent-owned CDP
- Not cookie export, `state-save`, or MFA/CAPTCHA solving
- `authorization_ready` remains false
