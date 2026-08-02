# Phase 6: Disposable/Dev browser form-login readiness

Phase 6 adds policy version 5 `browser_form_login` for disposable/dev secrets
only. The HTTP `startBroker` path rejects this class (`wrong_broker`).

## Contract

- Exact `{{username}}` / `{{password}}` placeholders
- Exact username/password field names and exact hidden-field name allow-list
- Loopback fake login site (`src/fake-login-site.mjs`)
- Stdlib fetch + in-memory cookie jar session broker (`src/browser-session-broker.mjs`)
- Opaque session id; agent may only hit policy `allowed_paths` via the replay bind
- Session cookies join the sensitive-variant set; `Set-Cookie` is never returned to the agent
- MFA / CAPTCHA / login failure → fixed value-free codes
- One session writer at a time; jar cleared on `close`
- Non-loopback HTTPS origins require `buildBrowserFormLoginLiveGate` (pin only by default)

## Commands

```bash
npm run test:phase6
npm run live:browser-form-login
npm run live:browser-form-login -- pin-https login.example.test
```

## Non-claims

Not personal/company Bitwarden. Not Playwright-by-default. Not FTP/SSH.
`authorization_ready` remains false. Same-user process isolation is not claimed.
