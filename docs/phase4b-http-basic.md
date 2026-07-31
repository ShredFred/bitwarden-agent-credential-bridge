# Phase 4b: fake HTTP Basic contract

Phase 4b extends the local contract harness with one version-3 `http_basic`
policy. It proves only that a bounded foreground broker can inject a fake
username/password bundle into one allow-listed loopback HTTP request without
returning that bundle on the tested caller-visible surfaces.

## Contract

- The policy schema is exact and requires `username_value: "{{username}}"`
  and `password_value: "{{password}}"`. Literal values, mixed templates,
  cross-version fields, and extra fields fail closed.
- Runtime material is an in-memory object with exactly the data properties
  `username` and `password`; accessors, missing fields, and extra fields fail.
- Both fields must be printable ASCII. Username length is 8..256 and password
  length is 8..1024. A username cannot contain `:`; a password can.
- The broker strips caller authentication, cookie, forwarding, framing, and
  connection-nominated headers, then adds exactly one standard padded,
  unwrapped `Authorization: Basic <base64(username:password)>` value.
- Only the configured method and path are accepted. Query or fragment-like
  targets and redirects fail closed. Request and response bodies are bounded
  to 1 MiB.

## Non-disclosure checks

Before forwarding an upstream response, the broker scans its complete body and
header names and values. The sensitive set includes username, password,
`username:password`, the raw Basic payload, the full authorization value, and
their raw, upper/lower percent-encoded, Base64, and Base64url forms. The same
set redacts structured logs and errors. A match produces only a generic error.

These tests reduce accidental disclosure risk; they do not prove that a secret
cannot be observed by the broker process, its administrator, a debugger, or a
compromised operating system. The broker necessarily holds the credentials in
memory while constructing the upstream request.

## Boundaries

This phase is dependency-free, loopback-only, foreground-only, and fake-only.
It does not access Bitwarden, pair Agent Access, read a real vault, persist
credentials, modify environment variables, install certificates, intercept
TLS, automate browsers or websites, or establish production isolation.

Run the focused verification with:

```bash
npm run test:phase4b
```
