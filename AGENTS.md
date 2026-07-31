# Agent Credential Bridge Experiment Rules

This repository is a sample-only security experiment.

- Never use, request, read, copy, log, or store real credentials, vault exports, cookies, recovery codes, authentication tokens, or private service inventories.
- Use generated fake values only. Tests must fail if a fake sentinel secret appears on an agent-readable surface.
- Do not connect to a personal or company Bitwarden vault in Phase 1.
- Do not add custom cryptography. Prefer standard-library code and pinned upstream tools.
- Unsupported credential classes must fail closed. Never fall back to printing or general process-environment injection.
- Keep the first slice dependency-free where practical and cross-platform across Windows, macOS, and Linux.
- One writer at a time. Preserve unrelated changes and keep diffs narrow.
- Run tests before claiming completion. Report limitations explicitly.
- Do not create a remote or push this repository until a separate secret scan and publication review pass succeeds.

## Phase 1 scope

Implement only:

- a local fake HTTP API that accepts one bearer-token sentinel and returns a constant response;
- a declarative sample policy for the fake service;
- policy validation;
- a foreground-only fake broker that applies the policy and injects the sentinel at the outbound boundary;
- functional and exposure tests proving the caller receives no plaintext secret;
- documentation explaining that this harness tests the contract, not Bitwarden or OneCLI production security.

Do not implement Bitwarden pairing, OneCLI deployment, TLS interception, certificate installation, firewall mutation, background services, browser login, MFA, SSH, databases, RDP, or desktop credential handling in this slice.

## Phase 2 scope

Phase 2 may add only a non-mutating OneCLI/Bitwarden readiness layer:

- pin and document audited upstream commits/releases;
- inspect local Docker/Compose, ports, platform, and `aac` availability;
- validate a proposed deployment configuration without starting containers;
- model the same-user, Docker-control, dashboard, relay, cache, log, and egress boundaries;
- use generated fake values in tests and redact command output.

Phase 2 must not start/stop Docker, pull images, pair a vault, call the Bitwarden
relay, create real agent tokens, install certificates, modify firewall/proxy
settings, or read/write a real secret. Those require a later explicit live-test gate.

## Phase 3 scope

Phase 3 may add offline supply-chain evidence, pure verifiers, non-deployable
Compose templates, and a disposable live-test runbook. It must distinguish the
Agent Access crate actually linked by OneCLI from newer `aac` releases and source
audit references. Postgres and the administrative dashboard must be internal-only
in the strong-boundary design; only the scoped gateway may be exposed to an agent.

Phase 3 still must not download/install `aac`, pull or start images, generate or
persist deployment secrets, pair any vault, or change host networking. The live
runbook must use a disposable Bitwarden account/item and require explicit approval.

## Phase 4a scope

Phase 4a remains fake-only and may add one narrowly tagged version-2 credential
contract for a policy-pinned HTTP API-key header. Runtime fake values stay explicit
function inputs and must never be written into a policy, environment variable, file,
log, response, or error surface. Version 1 bearer policies remain compatible.

The version-2 policy must describe exactly one `http_api_key_header` injection with
an exact `{{credential}}` placeholder and a canonical lowercase ASCII header name.
Reject forbidden protocol, hop-by-hop, cookie, authorization, framing, and content
headers. Strip the pinned header and every credential/protocol header supplied by
the caller before injecting exactly one outbound value.

Phase 4a must also reject unconfigured query strings and bound upstream response
bodies before buffering them. Keep redirects fail-closed and test split response
chunks, duplicate/case-varied caller headers, forbidden header names, oversized
responses, and all agent-readable surfaces. Do not add Basic Auth, query, cookie,
form, browser, process-env, SSH, database, or arbitrary-template injection yet.

## Phase 4b scope

Phase 4b may add one fake-only version-3 `http_basic` policy and an explicit
in-memory `{ username, password }` runtime bundle. Policy files contain only exact
`{{username}}` and `{{password}}` placeholders, never values. Preserve valid
version-1 bearer and version-2 API-key behavior.

For this slice, accept bounded printable ASCII runtime fields only; reject control
characters, empty values, and `:` in the username. Inject exactly one outbound
`Authorization: Basic <base64(username:password)>` value after stripping every
caller credential/protocol header. Treat username, password, their joined form,
the complete Basic value, and their deterministic percent/Base64/Base64url forms
as sensitive for response blocking and recursive log/error redaction. Tests must
cover username byte alignment, duplicate Authorization inputs, derived echoes,
invalid bundles, v1/v2 regressions, and every existing exposure surface.

Phase 4b remains loopback, foreground, dependency-free, and fake-only. It must not
add live Bitwarden/OneCLI access, Unicode Basic interoperability, browser or form
login, cookies, query credentials, process environment, SSH, databases, or desktop
credential handling.

## Phase 5a scope

Phase 5a may add only a pure, offline bootstrap planner for Windows, macOS, and
Linux. It must separate one per-user machine installation from tracked,
secret-free per-repository service selections. Project configuration may select
strict ASCII service aliases only; it must not choose commands, executable paths,
URLs, headers, policies, vault identifiers, or credential fields.

User-local configuration may map pre-approved aliases to structurally validated
Bitwarden item and field references, but the planner output must never include
those references. Local configuration is authoritative: a repository can select
only aliases already enabled by the user. Schemas are exact and unsupported
platforms, fields, credential classes, and ambiguous runtime inputs fail closed.

This slice must remain a pure function over supplied objects and synthetic
platform inputs. It must not read files or environment variables, inspect file
permissions, resolve links, access a vault or network, install launchers, create
directories, or mutate machine/repository state. Those operations require a
later explicit apply gate with symlink/reparse-point and ownership/DACL checks.

## Phase 5b scope

Phase 5b may add a read-only host preflight over already-derived paths. It may
inspect file metadata and hash the non-secret launcher, but must not read the
user config contents. POSIX readiness requires current-UID ownership and rejects
group/other-writable installation artifacts plus any group/other access to the
config file. Windows readiness requires an injected, value-free security adapter
that confirms no reparse point, current-user ownership, and no other-user write;
absence or malformed output from that adapter fails closed.

Reports contain fixed check ids/status/reasons only: never raw OS command output,
ACL principals, SIDs, usernames, config values, vault references, or exception
messages. Phase 5b remains non-mutating and must not create, repair, chmod, install,
pair, authenticate, access Bitwarden, or start the broker.

## Phase 5c scope

Phase 5c may implement the Windows security adapter required by Phase 5b using a
repo-owned PowerShell probe launched with argument-array semantics. The probe may
read item attributes and ACL metadata only. It must require current-user ownership,
reject reparse points, and conservatively mark any write-capable Allow ACE unsafe
unless its SID is the current user, LocalSystem, or Builtin Administrators. Broad
Allows remain unsafe even when a Deny might reduce their effective rights.

The Node adapter must use a hidden, non-interactive, no-profile process with a
short timeout and small output bound. It accepts exactly one JSON object with
three booleans and rejects stderr, extra output/fields, non-zero exit, timeout,
or malformed data with stable value-free errors. It must never return raw command
output, paths, principals, SIDs, usernames, or exception messages.

## Phase 5d scope

Phase 5d may implement only a pure, non-mutating apply/rollback manifest builder.
It derives destinations internally, accepts launcher bytes only to hash them, and
returns no content or vault references. Exact observed states must distinguish
absent paths from previously verified secure/managed paths and reject incoherent
parent/child states. Unknown existing files are never representable as writable.

The manifest must bind exact forward and reverse actions, prior/post digests,
permission policy, exclusive backup absence, and strict reverse rollback order.
Canonical sorted-key UTF-8 JSON is hashed without self-referential digest fields;
confirmation requires the complete SHA-256 digest. This phase must not create,
move, replace, chmod, delete, inspect, or read any host path and must not implement
the apply executor itself.

## Phase 5e scope

Phase 5e may create and verify a disposable workspace only beneath the canonical
OS temporary directory. The workspace root must come from `mkdtemp`, be a real
directory rather than a link/reparse point, and contain a newly exclusive marker
with a cryptographic nonce. Marker verification is byte-exact and bounded; roots,
markers, and synthetic home/config/data paths must remain strict descendants of
the canonical temp root.

The workspace API must not expose recursive cleanup, accept default user roots,
create Bitwarden configuration, access a vault/network, or execute an apply
manifest. Tests may remove only the exact root they created after verification.

## Phase 5f scope

Phase 5f may restrict permissions only for existing paths inside a currently
valid disposable workspace. POSIX uses owner-only modes. Windows uses a
repo-owned PowerShell setter with argument-array invocation; the script must
independently verify the canonical root, exact marker bytes/nonce, containment,
item type, and every existing path segment before replacing inheritance with
FullControl for only current user, LocalSystem, and Builtin Administrators.

The setter must be silent on success and expose stable value-free failures only.
It must not accept paths outside the marked root, create/delete/move files,
operate on normal user roots, access Bitwarden, or execute manifests.

## Phase 5g scope

Phase 5g may execute confirmed manifests only inside a valid, permission-hardened
disposable workspace. A test scaffold may create only the synthetic OS base
directories that stand in for an existing home/LocalAppData/XDG/Application
Support root. Manifest paths and launcher digest must be rebuilt from the
workspace and match exactly before execution.

Every action re-verifies workspace authorization, target containment, observed
state, link/reparse/hardlink rules, digest, and permissions. File publication and
moves use same-filesystem exclusive hard links; writes use same-directory temp
files with sync before publication. Failures run only activated rollback actions
in strict reverse order with digest/state checks. The executor must support
first install, idempotent reinstall, upgrade, injected failure, and rollback in
the disposable root only; it must never accept normal user roots or access a vault.
This phase does not claim protection from a malicious concurrent process running
as the same OS user. A production executor requires a separate identity or
equivalent sandbox boundary.

## Phase 5h.1 scope

Phase 5h.1 may define only the pure, offline wire contract for a future
short-lived helper with a distinct writer identity. Requests must be canonical
UTF-8 JSON bounded to 64 KiB and bind one disposable workspace root/marker nonce,
one already-confirmed complete manifest, and the digest/length of launcher bytes
delivered later through an inherited read-only handle. Requests must contain no
secret values, vault references, arbitrary commands, executable paths, network
addresses, or caller-selected mutation paths beyond the already-bound manifest.

Authorization must fail closed unless an injected platform adapter proves a
local transport, verified identity, a principal different from the caller, caller
write denial, and helper write permission. Responses expose fixed codes and
counts only. This phase must not launch a helper, open IPC, pass handles, create
users/tokens/sandboxes, install services, mutate permissions, execute manifests,
access real user roots, or connect to Bitwarden. Those require later OS-specific
phases and an explicit live gate.

## Phase 5h.2 scope

Phase 5h.2 may add only a pure Windows peer-evidence evaluator over trusted,
injected Win32 probe facts. It must require a local named pipe with remote clients
rejected, verified client/server process binding, verified caller/helper tokens,
different `TokenUser` SID digests, complete ACL checks over every bound target,
no caller effective write access, and required helper write access. Returned data
contains only the five cross-platform authorization booleans.

Restricted tokens, lowered integrity, capability SIDs, and AppContainer state do
not establish a different principal when `TokenUser` remains equal. Evidence is
exact-schema, boolean-exact, digest-only, accessor-free, and fail-closed; raw SIDs,
PIDs, paths, ACLs, token details, and exception text must never be returned.
This phase still must not inspect live tokens/ACLs, open a pipe, launch a helper,
create an account/service/AppContainer, pass handles, mutate permissions, execute
a manifest, access real user roots, or connect to Bitwarden.

## Phase 5h.3 scope

Phase 5h.3 may add only a pure Linux peer-evidence evaluator over trusted,
injected collector facts. It must require AF_UNIX peer credentials with verified
peer/helper process binding, caller/helper UIDs translated to the initial user
namespace, the helper itself in the initial user namespace, peercred agreement
with the translated caller host UID, unequal host-UID digests, and complete
effective-access checks in the helper mount namespace over every bound target.

Namespace-local UID 0, UID maps, no-new-privs, empty capabilities, seccomp, and
Landlock are defense-in-depth signals only. They must never establish a distinct
principal when host-UID digests are equal. Returned evidence contains only the
five shared booleans; raw UIDs, PIDs, uid maps, namespace identifiers, paths,
capabilities, filters, ACLs, and errors must not escape. This phase performs no
socket or `/proc` I/O, namespace creation, helper launch, mount, permission
mutation, manifest execution, real-root access, or Bitwarden connection.
