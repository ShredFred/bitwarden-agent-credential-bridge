# Agent Credential Bridge Experiment

Sample-only security experiment. Phase 1 tests a **credential-bridge contract**.
Phase 2 adds an offline, non-mutating OneCLI readiness audit. Phase 3 adds
offline supply-chain evidence and a not-run disposable live-test design. None
of these phases tests Bitwarden product security or OneCLI production security.

## What Phase 1 covers

| Piece | Role |
| --- | --- |
| Fake HTTP API | Local loopback server that accepts one runtime-generated bearer sentinel and returns a constant JSON body |
| Sample policy | Declarative allow-list with bind URL, upstream URL, method, path, and `authorization: "{{credential}}"` |
| Policy validation | Rejects non-loopback URLs, literal credentials, unsupported placeholders, and unsupported credential classes (fail closed) |
| Foreground HTTP broker | Binds to loopback (ephemeral port allowed), strips caller `Authorization`, injects the sentinel only on the outbound request, returns a sanitized response |
| Tests | Functional coverage plus exposure checks (broker logs, stdout/stderr, worktree file scan) that fail if the runtime sentinel appears on agent-readable surfaces |

## What Phase 1 does **not** cover

Bitwarden pairing, OneCLI deployment, TLS interception, certificate installation, firewall mutation, background services, browser login, MFA, SSH, databases, RDP, or desktop credential handling.

Do not connect this harness to a personal or company Bitwarden vault.

## What Phase 2 covers

- An upstream lock for OneCLI release `1.45.0`, its reviewed source commit, and
  the crates.io `ap-client` `0.9.0` dependency actually linked by OneCLI.
- Pure proposed-configuration validators for audited local binds, pinned images,
  deployment values, relay transport, the source-fixed cache TTL, and runtime
  separation.
- An injected-runner preflight that checks platform, Docker CLI, Compose,
  `aac`, and the audited local ports (dashboard `10254`, gateway `10255`,
  Postgres `5432`) using read-only commands.
- A placeholder-only, deliberately non-deployable sample configuration.
- Readiness limits and threat boundaries in
  [`docs/phase2-onecli-readiness.md`](docs/phase2-onecli-readiness.md).

Phase 2 does not start or stop Docker, pull images, access a network or relay,
pair a vault, read environment values, create tokens, or read/write real
secrets. Those operations require a separate live-test gate.

For the pinned baseline, the audited Bitwarden provider hard-codes
`credentialCacheTtlSeconds` to `60`; this is source behavior, not a Compose
setting.

## What Phase 3 covers

- An offline evidence lock for the supplied OneCLI and Postgres OCI index and
  Linux platform-manifest digests.
- An explicit distinction between OneCLI's linked crates.io `ap-client`
  `0.9.0`, candidate AAC `0.11.0`, and the later Agent Access workspace
  `0.12.0` source-audit reference.
- Pure validators for canonical SHA-256 values, three-part versions, exact
  platform-manifest selection, and the candidate's required `unverified`
  compatibility status.
- A deliberately non-deployable Compose example: digest placeholders only,
  internal-only Postgres, no host-published dashboard, and a loopback-only
  gateway.
- A gated disposable live-test runbook covering artifact checks, isolation,
  non-disclosure, denial tests, cache/revocation behavior, cleanup, and
  redacted evidence.

Phase 3 artifacts have not been deployed or paired. Candidate AAC `0.11.0`
compatibility with OneCLI `1.45.0` remains **unverified** until the separately
approved disposable test passes and its evidence is reviewed. See
[`docs/phase3-disposable-live-test.md`](docs/phase3-disposable-live-test.md).

## Requirements

- Node.js 20+ (ESM, standard library only — no npm dependencies)

## Quick start

```bash
npm test
npm run test:phase3
node src/run-demo.js
```

`run-demo.js` generates a cryptographically random fake sentinel, starts the fake API and foreground broker, calls through the broker bind URL, and prints only caller-visible status/body. It exits non-zero if the sentinel leaks into those surfaces or broker logs.

To perform only the optional local Phase 2 readiness inspection:

```bash
npm run preflight:onecli
```

The preflight prints JSON and exits non-zero when a prerequisite is missing, a
required port is occupied, or a probe cannot establish readiness. It does not
print command output or environment values. A pass is not permission to deploy
or pair OneCLI.

## Contract under test

1. The **caller** (stand-in for an agent) never receives the plaintext sentinel in the HTTP response body, sanitized headers, broker logs, stdout/stderr, `process.env`, or tracked worktree files.
2. The **broker** listens on the policy bind URL, accepts only the allow-listed method/path, strips caller `Authorization`, and injects `Authorization: Bearer <runtime-sentinel>` only on the outbound upstream request.
3. Policy `authorization` must be exactly `{{credential}}`. Literal credential values and any other placeholder are rejected.
4. **Bind** and **upstream** must be `http` loopback only (`127.0.0.1` or `localhost`) with an explicit port (`0` allowed for ephemeral bind).
5. **Unsupported credential classes** fail closed at validation and again at broker start. There is no fallback to printing secrets or injecting them into the general process environment.

## Runtime sentinel

No bearer token is hard-coded in tracked source. Each demo/test process calls `generateFakeSentinel()` (cryptographically random) and passes that value explicitly into the fake API and broker. Appearance of that runtime value on agent-readable surfaces is a hard test failure.

## Sample policy shape

```json
{
  "version": 1,
  "service": "fake-sample-api",
  "credential_class": "http_bearer",
  "bind": "http://127.0.0.1:0",
  "upstream": "http://127.0.0.1:0",
  "method": "GET",
  "path": "/v1/resource",
  "authorization": "{{credential}}"
}
```

Demo/tests rewrite `upstream` to the fake API’s concrete loopback origin after it binds.

## Layout

```
policies/sample-fake-service.json   declarative sample policy
upstream/onecli.lock.json            corrected Phase 2 upstream revisions
upstream/supply-chain.lock.json      Phase 3 offline digest/revision evidence
samples/onecli/secure-local.example.json
                                      rejected deployment placeholders
deploy/compose.disposable.example.yaml
                                      non-deployable bounded template
src/constants.js                    constant API body + sentinel generator
src/policy.js                       load + validate (loopback + placeholder rules)
src/fake-api.js                     local fake HTTP API
src/broker.js                       foreground loopback HTTP broker
src/run-fake-api.js                 foreground API process
src/run-demo.js                     end-to-end foreground demo
src/onecli-audit.mjs                pure proposed-config validators
src/supply-chain-audit.mjs          pure Phase 3 evidence validators
scripts/preflight-onecli.mjs        read-only, value-free readiness report
docs/phase2-onecli-readiness.md     evidence, platform path, threat boundaries
docs/phase3-disposable-live-test.md approval-gated, not-run live-test plan
test/*.test.js                      functional + exposure tests
AGENTS.md                           experiment rules for agents
```

## Limitations

- Single credential class (`http_bearer`) and a single sample service.
- Sample policy uses port `0` for bind/upstream placeholders; runtime code supplies the concrete upstream origin after the fake API listens.
- No TLS, no persistence, no multi-writer coordination beyond “one writer at a time” for this repo.
- Not a substitute for vault, OS keychain, or production broker hardening.
- Phase 2 validates a proposal and local prerequisites only. It does not verify
  remote tags, images, relay reachability, Docker permissions, or runtime
  isolation.
- Phase 3 records supplied evidence but performs no network verification,
  download, install, image pull, deployment, pairing, or live compatibility
  test.

## Publication

Do not create a remote or push this repository until a separate secret scan and publication review pass succeeds.
