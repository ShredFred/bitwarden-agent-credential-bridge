# Phase 6: Disposable/Dev browser form-login readiness

Phase 6 adds policy version 5 `browser_form_login` for disposable/dev secrets
only. The HTTP `startBroker` path rejects this class (`wrong_broker`).

## What works today

- Loopback fake website login (form + CSRF hidden field + session cookie)
- Dedicated session broker (stdlib `fetch` + in-memory cookie jar; no Playwright)
- Opaque `{ logged_in, origin_bound, session_id }` plus allow-listed replay only
- Exposure tests that scan username, password, and issued session cookie values
- MFA / CAPTCHA / bad login / concurrent writer / idle TTL / cross-origin redirect
  fail closed with value-free codes
- Fake-vault + gated dev-resolver shapes for `{username,password}`
- HTTPS hostname pin gate (`pin-https`) without executing third-party login

## Contract

- Exact `{{username}}` / `{{password}}` placeholders
- Exact username/password field names and exact hidden-field name allow-list
- Session cookies join the sensitive-variant set; `Set-Cookie` is never returned
- One session writer at a time; jar cleared on `close`
- Default `npm test` includes Phase 6 tests (no extra CI job required)

## Commands

```bash
npm run test:phase6
npm run live:browser-form-login
npm run live:browser-form-login -- pin-https login.example.test
```

## Non-claims / not ready

- Not a general password manager for personal/company Bitwarden
- Not automatic login to arbitrary public websites (no disposable third-party
  live login executor yet beyond origin pinning)
- Not Playwright/browser DOM automation by default
- Not FTP/SSH/RDP/cookie export to the agent
- `authorization_ready` remains false; same-user process isolation is not claimed
