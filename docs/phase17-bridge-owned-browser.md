# Phase 17: Bridge-owned browser (agent-blind login)

Phase 17 adds a Bridge-owned browser session for `browser_form_login` when
the agent must see a UI but must not hold cookies or type passwords.

The agent is the eyes. The Bridge is the hands for secrets.

## Status

`npm run start:browser:sm` starts one Secrets Manager `browser_form_login`
alias as a Bridge-owned browser. The agent is the eyes; the Bridge injects
secrets. Loopback fake login site only.

`npm run start:operational:sm` still auto-logs-in `browser_form_login` via the
Phase 6 session broker. Re-read ports at `http://127.0.0.1:18791/services`.

The owned-browser CLI binds `http://127.0.0.1:18792` so `/contract` stays
findable after a lost stdout line.

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
- `GET /screenshot` — Playwright raw `image/png` except during password fill
  (`password_entry_active`). Errors stay JSON. `fetch` returns
  `screenshot_unsupported`
- `cookie_list`, `eval`, `cdp`, `fill`, `state_save`, `playwright_cli`, and
  related ops return `session_material_forbidden` or `command_forbidden`
- Exposure tests scan username, password, hidden-field values, and issued
  session cookies on every agent-readable surface
- One Bridge-owned browser at a time. MFA/CAPTCHA fail closed

## Drivers

`startBridgeOwnedBrowser` accepts `driver: 'fetch'` (default) or
`driver: 'playwright'`.

- **fetch** — stdlib HTTP + private cookie jar. Always available. Fastest.
  No window. `GET /screenshot` → `screenshot_unsupported`.
- **playwright** (Phase 17b / 17d) — in-process Playwright owned by the Bridge.
  Same HTTP allow-list. **Headless is the default** and can render pages
  without a window; `--headed` opens a window for a human watching.
  `GET /screenshot` is allowed on an empty login form and after login.
  Success is raw `image/png` with value-free `x-bridge-logged-in` /
  `x-bridge-path` headers — never `png_base64` in JSON.
  It is forbidden while `inject_login` fills the password and while any
  password input is non-empty (`password_entry_active`). Ops are serialized
  so a screenshot cannot interleave with fill. Playwright is **not** a
  package dependency and is **not** vendored: the repo ships a small page
  adapter (allow-list + fill/submit), not Chromium.
  Tests inject a stub or skip when `import('playwright')` fails. Missing
  install → `playwright_absent`. Launch failure → `playwright_launch_failed`.

To try the Playwright driver locally without adding it to this repo:

```bash
npm install --no-save playwright
npx playwright install chromium
```

Then start with `--driver playwright` (headless) or `--driver playwright --headed`.

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
npm run start:browser:sm -- --i-approve-secrets-manager-machine-resolve --i-approve-bridge-owned-browser --alias phq_web
```

Optional `--driver playwright` (not a package dependency; fails `playwright_absent`
when Playwright is not installed). Playwright is **headless by default**;
`--headed` opens a window (Playwright only; invalid with `fetch`).
Unknown flags such as `--devtools` are `invalid_request`.
`GET /screenshot` (HTTP, Playwright) is allowed except during password fill;
the body is `image/png`, not JSON.

## Agent HTTP surface

The start command prints one JSON handle with `baseUrl` and `contract_url`.
The CLI also binds **http://127.0.0.1:18792**. Operational SM brokers are
listed at **http://127.0.0.1:18791/services**.

Discover the session, then the four-call login (replace `$BASE` with the
session URL from the start command or from a test handle):

```http
GET  /contract
GET  /snapshot
GET  /screenshot
POST /select_targets   {"generation":1,"username_index":0,"password_index":1,"submit_index":2}
POST /inject_login     {"generation":1}
GET  /screenshot
POST /goto             {"path":"/home"}
GET  /screenshot
```

```bash
curl -s http://127.0.0.1:18792/contract
curl -s http://127.0.0.1:18792/snapshot
curl -s -H "content-type: application/json" -d '{"generation":1,"username_index":0,"password_index":1,"submit_index":2}' http://127.0.0.1:18792/select_targets
curl -s -H "content-type: application/json" -d '{"generation":1}' http://127.0.0.1:18792/inject_login
```

Pinning `generation` on `inject_login` is the safe call. An empty `{}` body
is also accepted.

If the task needs cookies, storage state, or CDP, this surface will not grow
those ops. Use the HTTP credential brokers (or stop) instead.

## Non-claims / not ready

- Not a general password manager for arbitrary public websites
- Not `traffic.mivia.ai` or other non-loopback hosts (needs a later live gate)
- Not Playwright-CLI, Claude Chrome extension, or agent-owned CDP
- Not cookie export, `state-save`, MFA/CAPTCHA solving, or screenshots during
  password fill
- `authorization_ready` remains false
