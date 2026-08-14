# Phase 17: Bridge-owned browser (agent-blind login)

Phase 17 adds a Bridge-owned browser session for `browser_form_login` when
the agent must see a UI but must not hold cookies or type passwords.

The agent is the eyes. The Bridge is the hands for secrets.

## Status

The HTTP contract is implemented and tested. **There is not yet an operator
CLI that starts it against Secrets Manager.** `npm run start:operational:sm`
still uses the Phase 6 auto-login session broker for `browser_form_login`.
A consuming agent (Claude) asked for `npm run start:browser:sm` as the next
slice — see Phase 17c in `AGENTS.md`.

Until then, the surface below is what tests drive, and what a later start
command will print as a JSON handle.

## What works in-process

- Loopback fake login site (same Phase 6 fixture)
- `GET /contract` — allowed/forbidden ops, allow-listed paths, error codes
- `GET /snapshot` — value-free field **indices** (username / password /
  submit). No HTML, CSRF values, cookies, or passwords
- `POST /select_targets` — indices only. Extra fields such as `selector` /
  CSS / XPath fail closed (`extra_field_forbidden`)
- `POST /inject_login` — empty body, or `{ "generation": <n> }` to pin the
  snapshot. No credential in the command. The Bridge re-checks origin,
  password `type`, and same-origin form action, then fills from memory
- After `logged_in=true`, `POST /goto` only on `allowed_paths`
- `cookie_list`, `eval`, `cdp`, `fill`, `state_save`, `playwright_cli`, and
  related ops return `session_material_forbidden` or `command_forbidden`
- Exposure tests scan username, password, hidden-field values, and issued
  session cookies on every agent-readable surface
- One Bridge-owned browser at a time. MFA/CAPTCHA fail closed

## Drivers

`startBridgeOwnedBrowser` accepts `driver: 'fetch'` (default) or
`driver: 'playwright'`.

- **fetch** — stdlib HTTP + private cookie jar. Always available. Default
  `npm test` path.
- **playwright** (Phase 17b) — in-process Playwright owned by the Bridge.
  Same HTTP allow-list. The `page` / `context` objects never leave the adapter.
  Playwright is **not** a package dependency; tests inject a stub or skip when
  `import('playwright')` fails. Missing install → `playwright_absent`. Launch
  failure → `playwright_launch_failed`.

Raw `playwright-cli`, Chrome extensions, and agent CDP remain forbidden. If a
task needs cookies or storage state, use the HTTP credential brokers instead
of asking this surface to grow export ops.

## Contract

- Same policy version 5 `browser_form_login` as Phase 6. This is a different
  runtime (`startBridgeOwnedBrowser`), not `startBroker` and not the fetch
  session broker's auto-login.
- Candidate generation is required on select. Stale generations fail closed.
- Cookies stay in the adapter jar. They never appear in JSON, logs, or the
  session handle.
- `authorization_ready` stays false. Same-user memory isolation is not claimed.

## Commands

```bash
npm run test:phase17
```

## Agent HTTP surface

Discover the session, then the four-call login (replace `$BASE` with the
session URL from the future start command or from a test handle):

```http
GET  /contract
GET  /snapshot
POST /select_targets   {"generation":1,"username_index":0,"password_index":1,"submit_index":2}
POST /inject_login     {"generation":1}
POST /goto             {"path":"/home"}
```

```bash
curl -s "$BASE/contract"
curl -s "$BASE/snapshot"
curl -s -H "content-type: application/json" -d '{"generation":1,"username_index":0,"password_index":1,"submit_index":2}' "$BASE/select_targets"
curl -s -H "content-type: application/json" -d '{"generation":1}' "$BASE/inject_login"
```

Pinning `generation` on `inject_login` is the safe call. An empty `{}` body
is also accepted.

If the task needs cookies, storage state, or CDP, this surface will not grow
those ops. Use the HTTP credential brokers (or stop) instead.

## Non-claims / not ready

- Not a Secrets Manager start command yet (Phase 17c)
- Not a general password manager for arbitrary public websites
- Not `traffic.mivia.ai` or other non-loopback hosts (needs a later live gate)
- Not Playwright-CLI, Claude Chrome extension, or agent-owned CDP
- Not cookie export, `state-save`, or MFA/CAPTCHA solving
- `authorization_ready` remains false
