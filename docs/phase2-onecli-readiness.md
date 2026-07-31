# Phase 2: OneCLI readiness and threat boundaries

Phase 2 is an offline, non-mutating readiness review. It does not deploy OneCLI,
prove OneCLI or Bitwarden production security, or authorize a live pairing.

## Upstream evidence lock

`upstream/onecli.lock.json` records the reviewed baseline:

- repository: `https://github.com/onecli/onecli.git`
- release: `1.45.0`
- OneCLI commit: `84ccaf74ce6350f8925675457b48272c29f32c1a`
- audited Bitwarden Agent Access commit:
  `9cd303f65dc501c19d1d513fb4cf88fe5f44936a`
- audited OneCLI Docker Compose default ports: dashboard `10254`, gateway
  `10255`, and Postgres `5432`
- audited Bitwarden provider credential cache TTL: `60` seconds

The lock is evidence metadata, not an installer and not a trust-on-first-use
mechanism. This harness never clones the repository, resolves tags, downloads
images, or checks a remote. A later publication or live-test review must
independently verify that the release, commit, source tree, image, and Agent
Access revision correspond before using them.

The cache TTL is hard-coded source behavior in the audited Bitwarden provider;
it is not a Docker Compose setting and cannot be configured by this baseline.

## Offline configuration review

`src/onecli-audit.mjs` contains pure validators for a proposed version 1
configuration. A valid proposal requires:

- dashboard, gateway, and Postgres binds on `127.0.0.1`, `::1`, or `localhost`,
  using the audited Docker Compose defaults `10254`, `10255`, and `5432`,
  respectively;
- explicitly tagged or SHA-256-digest-pinned OneCLI and Postgres images, never
  an omitted or `latest` tag;
- explicit, non-default, non-placeholder Postgres credentials;
- a non-placeholder encryption key;
- an `https` or `wss` Bitwarden relay URL with no embedded user information;
- the hard-coded Bitwarden provider credential-cache TTL of exactly 60 seconds;
- explicit acknowledgement that the future runtime must be separated from the
  agent process.

`samples/onecli/secure-local.example.json` is deliberately non-deployable.
Every deployment-specific image, credential, key, and relay host is a
placeholder, and validation rejects those placeholders. Phase 2 must not
replace them with real values or store a completed configuration.

`auditOneCliConfig()` returns only issue codes, field names, and fixed messages.
It never returns rejected values. `validateOneCliConfig()` returns a normalized
copy on success, so callers must not log or serialize that successful object
when it contains deployment values.

## Read-only preflight

Run `npm run preflight:onecli` only when local host inspection is wanted. The
script:

1. recognizes Windows, macOS, or Linux;
2. runs only `docker --version`, `docker compose version`, and `aac --version`;
3. checks whether local ports 10254, 10255, and 5432 are already listening; and
4. prints a value-free JSON readiness report.

It does not run Docker containers, contact the Docker daemon for workload
state, pull images, open a socket, connect to a port, call a relay, inspect
environment values, or print command output. Missing commands, occupied ports,
timeouts, and probe failures become structured `ready: false` checks rather
than stack traces.

Platform-specific port inspection is:

| Platform | Read-only local probe | Prerequisite |
| --- | --- | --- |
| Windows | `Get-NetTCPConnection` through Windows PowerShell | Windows PowerShell |
| macOS | `lsof` for each exact TCP port | system `lsof` |
| Linux | `ss` filtered to each exact TCP port | `iproute2`/`ss` |

A passing report means only that these local prerequisites were observable at
that moment. It does not verify container images, daemon permissions, relay
reachability, certificates, pairing, or credentials.

The current Windows preflight is intentionally blocked (`ready: false`) while
`aac` is absent. Missing `aac` produces a structured `missing_or_failed` check;
there is no fallback executable, shell evaluation, or live pairing attempt.

## Threat and trust boundaries

| Boundary | Risk or limitation | Required later control |
| --- | --- | --- |
| Same user | Any process running as the OneCLI OS user may be able to reach its loopback listeners, files, IPC, or process handles. Loopback is not an authentication boundary. | Use a dedicated least-privilege runtime identity and restrict local access with OS controls. |
| Docker control | Docker daemon or Docker Desktop control commonly grants host-equivalent power. A Docker controller can inspect or replace containers, mounts, networks, and runtime inputs. | Keep agents outside the Docker-control group/socket and narrowly administer the runtime. |
| Dashboard | A loopback dashboard can still be reached by same-user processes and browser-origin attacks. Binding locally does not establish authorization. | Require upstream-supported authentication, session protection, and explicit exposure review; never publish the port by default. |
| Gateway | The gateway is a credential-use boundary. A broad route or bind could turn it into a general-purpose proxy. | Bind only to loopback, allow-list destinations and operations, and fail closed. |
| Postgres | Database control may expose configuration, cached material, logs, or metadata. Default credentials and externally reachable binds are unsafe. | Use unique generated credentials, loopback/private networking, minimal grants, and reviewed storage. |
| Credential cache | TTL limits duration, not access. Encryption does not protect data from a process that has both ciphertext and the active key. | Minimize TTL, define deletion behavior, isolate keys, and test crash/restart residue. |
| Relay | Relay traffic crosses the local trust boundary. HTTPS/WSS validates transport shape but not endpoint ownership or egress policy. | Verify the exact Bitwarden endpoint, certificate behavior, DNS/proxy path, and upstream protocol at the live-test gate. |
| Logs and diagnostics | Tool, container, dashboard, or exception output may disclose tokens, headers, configuration, paths, or service metadata. | Use field allow-lists, redact before persistence, disable debug output, and test every log sink. |
| Egress | A compromised runtime could send credentials or metadata to destinations other than the approved relay or target service. | Apply destination-level egress allow-lists outside the agent-controlled boundary and test deny behavior. |

The acknowledgement field is documentary only. It cannot create process,
identity, container, or host isolation.

## Gates carried into the disposable live-test phase

An adversarial review using Antigravity (`gemini-3.1-pro-high`) identified the
following claims that Phase 2 deliberately does not prove. A later live-test
plan must turn each one into an observable pass/fail check:

1. inspect the rendered Compose configuration and running Docker port mappings;
   reject unqualified or `0.0.0.0` publishing even when the proposal says
   loopback;
2. prove the gateway runs under a dedicated restricted runtime identity and
   that the agent identity cannot control the Docker daemon/Desktop API,
   container, volumes, database, process handles, or gateway administration;
3. verify the pinned image digest against the reviewed source/release before
   pulling or starting anything;
4. verify cache purge behavior on disconnect, revocation, gateway restart, and
   abnormal termination instead of relying only on the source-fixed 60-second
   expiry; and
5. test destination egress denial, redirect handling, response/log redaction,
   dashboard authentication, and certificate trust with disposable credentials.

Docker CLI availability is not evidence for any of these controls. On Windows,
membership in the same interactive Docker Desktop control context is itself a
failed separation gate.

## Explicit no-live-pairing gate

Stop after static validation and preflight. Phase 2 does **not** permit:

- starting or stopping Docker, building or pulling images, or creating
  containers, volumes, or networks;
- pairing a Bitwarden vault, calling the Bitwarden relay, creating an agent
  token, or reading/writing any real secret;
- installing certificates, changing firewall/proxy settings, or enabling a
  background service; or
- testing with a personal or company vault.

Those actions require a separately approved live-test plan with disposable
accounts, generated test-only values, verified upstream artifacts, explicit
egress controls, cleanup steps, and a publication/secret-scan review.
