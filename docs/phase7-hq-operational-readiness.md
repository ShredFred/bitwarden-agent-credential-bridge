# Phase 7: HQ operational readiness (disposable/dev)

Phase 7 hardens the auth **types** used by typical HQ HTTP tooling without
connecting personal or company Bitwarden vaults.

## Derived auth matrix

| Class | Version | Status |
|---|---|---|
| `http_bearer` | 1 | Supported (fake/loopback) |
| `http_api_key_header` | 2 | Supported (fake/loopback) |
| `http_basic` | 3 | Supported (fake/loopback) |
| `onecli_proxy` | 4 | Supported (fake gateway path) |
| `browser_form_login` | 5 | Supported (fake + optional public demo) |
| `http_api_key_query` | 6 | Supported (fake/loopback; residual URL-log risk upstream) |
| `oauth` / interactive MFA / SMS / email | — | Permanently rejected |
| SSH / FTP / `env_inject` | — | Permanently rejected |

**DPAPI** protects a Windows development credential-at-rest store. It is **not**
MFA, OAuth, SMS, or email second-factor support (`dpapi_is_not_mfa=true`).

## Query API-key contract

Agent requests must not contain `?` or `#`. The broker builds:

`upstream + path + '?' + URLSearchParams(query_name=credential)`

and verifies exact origin, pathname, single parameter, and value before fetch.
Logs expose only the path (never the assembled query URL).

## Disposable Bitwarden live scope (1B)

Pinned disposable account identity (not a secret):
`frederikstadler+bridge@gmail.com` — compared by SHA-256 digest against the
DPAPI username; password stays in short-lived broker memory only.

```bash
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
```

Success reports value-free booleans plus `account_email_digest` only. Failure
modes include `approval_flag_required`, `dpapi_probe_failed`, and
`account_mismatch`. Mock/unit evidence never sets `authorization_ready=true`.

## Commands

```bash
npm run test:phase7
npm run live:disposable-bitwarden -- --i-approve-disposable-dev-bitwarden
```

## Non-claims

- Not production authorization (`authorization_ready=false`)
- Not personal/company/Mivia HQ vault pairing
- Not OAuth issuance/refresh or interactive MFA
- Query credentials may appear in upstream access logs (residual risk)
