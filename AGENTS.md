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

## Phase 5h.4 scope

Phase 5h.4 may add only a pure macOS peer-evidence evaluator over trusted,
injected Mach-message and audit-token collector facts. It must require a bound
launchd Mach service, verified request/reply peers and caller/helper process
generations, verified audit tokens and effective UIDs, an exact match between
the accepted request-sender audit token and the independently verified
authorizing caller audit token, a
pinned helper code requirement, unequal
effective-UID digests, and complete symlink-safe effective-access checks over
every bound target.

App Sandbox, Hardened Runtime, code signatures, differing code requirements,
audit sessions, and sandbox write restrictions are defense-in-depth signals
only. They must never establish a distinct principal when effective-UID
digests are equal. Returned evidence contains only the five shared booleans;
raw UIDs, audit tokens, PIDs, pidversions, code identities, paths, entitlements,
ACLs, and errors must not escape. This phase performs no Mach or Security
framework I/O, helper launch, authorization-service changes, permission
mutation, manifest execution, real-root access, or Bitwarden connection.

## Phase 5h.5 scope

Phase 5h.5 may exercise the first real helper-process boundary only for launcher
delivery. It creates an exclusive random temporary file inside an already
verified disposable workspace, writes generated non-secret launcher bytes,
opens a separate read-only handle, unlinks the path, and passes only that handle
to a short-lived child. The canonical Phase 5h.1 request travels separately
over stdin. The child must independently parse the request, read the bounded
inherited handle to EOF, and match both launcher length and SHA-256.

The live API accepts no caller-selected path, file descriptor, peer evidence,
command, executable, or environment. Child output is exact, bounded, and
value-free; stderr, timeout, excess output, non-zero exit, malformed UTF-8, and
any mismatch fail closed. This phase does not prove a different principal or
local authenticated IPC, inspect tokens/UIDs/audit tokens, execute a manifest,
touch normal user roots, access Bitwarden, or claim protection from a malicious
same-user process. Named-pipe/Mach-message/AF_UNIX identity collection and any successful
authorization remain later live-gated work.

## Phase 5h.6 scope

Phase 5h.6 may exercise a real Windows named-pipe and process-token boundary
inside a verified disposable workspace. A repo-owned PowerShell probe may use
fixed P/Invoke declarations to create exactly one first-instance byte pipe with
`PIPE_REJECT_REMOTE_CLIENTS`, bind the actual pipe client/server PIDs, inspect
the caller, client, and helper process tokens, and emit only lowercase SHA-256
digests of `TokenUser` SIDs plus exact booleans. The calling Bridge process
connects directly and completes a nonce handshake derived from the marked
workspace.

The live session API accepts no pipe name, PID, executable, command,
environment, SID, token, ACL, or peer evidence. It must prove the pipe client
token matches the caller token and then feed the existing Phase 5h.2 evaluator
and Phase 5h.1 authorization contract. On the current same-user host the only
valid terminal result is `same_principal_rejected`. ACL/write evidence remains
false, no manifest executor is called, and success under a distinct principal
is not representable in this phase. It must not create accounts/services,
change ACLs, access normal user roots or Bitwarden, or claim that the separate
writer boundary is complete.

## Phase 5h.7 scope

Phase 5h.7 may extend the Phase 5h.6 denial session only for a first-install
manifest whose five canonical target paths are absent. The caller sends the
canonical bounded helper request over the already PID/token-bound named pipe.
Launcher bytes must travel separately through an anonymous, unlinked read-only
handle inherited as the probe's stdin. The probe independently parses the
request, binds workspace root/nonce and first-install observed state, reads the
launcher handle to EOF with a 1 MiB cap, and verifies exact length and SHA-256.

The probe may use `DuplicateToken` plus Win32 `AccessCheck` against the caller
and helper tokens for all five bound target paths. Existing ancestors must stay
inside the disposable root and contain no reparse point; absent targets are
checked against the nearest existing ancestor for the exact first missing file
or directory creation right. `all_targets_checked` is true only after all five
checks complete. On this same-user host the honest result is caller write not
denied, helper write allowed, and authorization still terminates earlier at
`same_principal_rejected`.

This phase accepts no caller-selected handle, path, pipe, PID, command,
executable, environment, or evidence. It does not support upgrade/backup
manifests, execute any manifest action, create a second principal, change target
ACLs, access normal user roots or Bitwarden, or claim production readiness.

## Phase 5h.8 scope

Phase 5h.8 may define only a pure, non-executable Windows service-boundary plan.
The fixed future helper identity is the built-in `LocalService` account with an
unrestricted service SID, demand start, no password, no required network access,
and no vault access. The plan binds a reviewed helper binary by lowercase SHA-256
and byte length and requires local-only first-instance pipe, PID/token, target
ACL, disposable apply/rollback, and cleanup gates.

The Bridge client must authenticate the connected pipe server PID and token as
both `LocalService` TokenUser and the expected per-service SID token group; a
predictable pipe name plus first-instance flag is not server authentication.
The installed binary/parent chain must be reparse-free and caller-nonwritable,
and the service-object DACL must deny caller configuration changes.
Targets and every security-relevant ancestor must be owned by a trusted
Administrator/SYSTEM/TrustedInstaller identity or exactly the expected
per-service SID, never by the caller or shared `LocalService` TokenUser. Native
checks must deny caller data/create, `WRITE_DAC`,
`WRITE_OWNER`, `DELETE`, and parent `FILE_DELETE_CHILD` rights. Ordinary
caller-owned LocalAppData/home roots cannot establish this boundary.

The API accepts no account, service name, pipe name, path, command, password,
credential, ACL, or approval evidence from the caller. It performs no I/O and
must not emit installer commands. It does not install/start a service, elevate,
change ACLs, create an account, inspect the host, execute a manifest, or access
Bitwarden. Every mutable operation remains behind an explicit operator-approved
live gate and must be reverified from native evidence afterward.

## Phase 5h.9 scope

Phase 5h.9 may perform a bounded, read-only Windows preflight for the single
fixed Phase 5h.8 service. It accepts only a plan object created by the in-process
canonical builder, passes only the reviewed binary SHA-256 and byte length to a
repo-owned PowerShell probe, and returns an exact value-free boolean schema.

The probe may read the fixed service registry configuration, fixed SCM security
descriptor, installed image metadata/content for hashing, and image ancestor
security descriptors. It must verify exact Win32 own-process type, `LocalService`, demand start, unrestricted
service SID type, caller denial of service change/delete/DACL/owner rights,
binary digest/length, reparse-free trusted ownership, and caller denial of file,
create, delete, DACL, and ownership rights. A missing service is a successful
read-only probe with every readiness boolean false. The phase must not return
paths, SIDs, SDDL, ACEs, account names, hashes, process output, or exception text.
The public API uses fixed system PowerShell and the fixed repo script; it accepts
no runner, executable, script path, command, or timeout override. Because the
collector is path-based, even a fully matching snapshot must keep
`authorization_ready=false`; it is advisory evidence only until a handle-bound
installed-service matrix exists.
The child receives a fixed minimal environment and resolves `sc.exe` through the
OS system-directory API. A mutable in-process `SystemRoot` still selects the
initial PowerShell binary, so no Phase 5h.9 result may be authorization evidence.
It does not start/install/delete a service, mutate registry/SCM/files/ACLs,
execute the helper, access a vault, or authorize a live apply.

## Phase 5h.10 scope

Phase 5h.10 may add an application-dependency-free .NET 8 Windows own-process service
lifecycle scaffold using direct SCM P/Invoke. It may be copied and published
only inside disposable temporary workspaces, producing one same-source,
same-pinned-toolchain reproducible framework-dependent single-file `win-x64`
executable. SDK `8.0.423`, .NET 8 runtime baseline `8.0.29` with explicit
`LatestPatch` roll-forward, and the locally cached
ILLink package digest are pinned; restore uses an explicit source-cleared config
plus a one-package digest-verified local feed. The only console mode is
exact `--self-test`, with fixed value-free booleans; unknown arguments and
non-SCM no-argument launches exit silently non-zero.

The scaffold may register stop/shutdown controls and report SCM lifecycle state.
It must contain no IPC listener, manifest executor, vault client, network stack,
process launcher, secret input, config reader, or filesystem mutation. Its
self-test must explicitly report `ipc_listener_absent=true`,
`manifest_executor_absent=true`, `scm_lifecycle_live_verified=false`, and
`install_gate_eligible=false`. Therefore it is not installable under the live
gate and must never be treated as a functional helper. This phase performs no
service install/start, elevation, ACL/registry mutation, real-root access, or
Bitwarden access.

## Phase 5h.11 scope

Phase 5h.11 may add one console-only denial probe to the native Windows helper
executable. It uses one fixed local named-pipe name with
`PIPE_REJECT_REMOTE_CLIENTS` and `FILE_FLAG_FIRST_PIPE_INSTANCE`, accepts only a
canonical 64-character lowercase hexadecimal non-secret nonce, and obtains the
connected client's live PID and `TokenUser` through Win32 APIs. It compares that
token to the helper's live `TokenUser` internally and returns only fixed boolean
facts. No PID, SID, token, path, nonce, OS error, or provider text may be emitted.
Connect, read, and write must use bounded overlapped operations. The console pipe
inherits the ambient default DACL and must not claim an exclusive admission
boundary.

The only successful Phase 5h.11 result on the current console host is explicit
same-principal denial. The SCM service entrypoint must not activate the pipe, and
the executable still has no service-specific pipe DACL, manifest executor,
network stack, vault client, or install eligibility. This phase does not install
or start a service, elevate, mutate ACLs/registry/files, access normal user roots,
execute a manifest, or connect to Bitwarden.

## Phase 5h.12 scope

Phase 5h.12 may replace the console denial pipe's ambient default DACL with one
fixed protected DACL compiled into the native helper. The DACL contains exactly
three Allow ACEs: LocalSystem and the fixed service-specific SID receive full
control; Authenticated Users receive file-generic read plus `FILE_WRITE_DATA`
and `FILE_WRITE_ATTRIBUTES` only, so a future native local Bridge client can set
message read mode and complete the handshake without receiving
`FILE_CREATE_PIPE_INSTANCE`. It must contain no Everyone, Anonymous,
Network, Builtin Administrators, owner-rights, inherited, Deny, or extra ACE.

The helper must query the created kernel pipe object and verify the protected
DACL, exact ACE count/order/types/flags, masks, and SIDs before accepting a
client. It returns fixed booleans only and preserves every Phase 5h.11 timeout,
framing, token, and same-principal denial property. ServiceMain still must not
activate the listener in this phase, and install eligibility remains false.
No service install/start, elevation, filesystem/registry/ACL mutation, manifest
execution, normal-root access, network access, or Bitwarden access is permitted.

## Phase 5h.13 scope

Phase 5h.13 may add a native, value-free pre-request verifier for the single fixed
Windows service. It opens only the fixed pipe with the Phase 5h.12 narrow client
rights, obtains the live pipe server PID, pins that process with a handle, and
requires the fixed SCM service to be running as an own-process service with the
same stable PID before and after token inspection. The process `TokenUser` must
equal LocalService and its `TokenGroups` must contain the enabled, non-deny-only
fixed service SID.

Reports contain exact booleans only and must always expose
`request_sent=false` and `authorization_denied=true` in this phase. The current
uninstalled console server must prove PID/token binding but fail SCM, LocalService,
service-SID, and aggregate identity verification. No nonce, request, manifest,
launcher, credential, SID, PID, account, service output, or native error may be
sent or returned. ServiceMain IPC, installation, elevation, mutation, manifest
execution, network, and Bitwarden access remain absent; install eligibility stays
false.

## Phase 5h.14 scope

Phase 5h.14 may compile the fixed denial-only pipe listener into `ServiceMain`.
Before reporting `SERVICE_RUNNING`, and again before each listener instance, the
service must prove that its current process token has LocalService as `TokenUser`
and the enabled, non-deny-only fixed service SID group. Failure reports a fixed
service-specific stop code without exposing native errors.

The loop remains bounded and stop-aware, holds one verified first-instance pipe
handle for the full Running lifetime, uses the fixed protected Phase 5h.12 DACL,
accepts only a canonical lowercase hexadecimal non-secret nonce frame, pins the
reported live client process, requires its primary token to have a different
`TokenUser`, and returns only a
fixed value-free denial frame. It must always report incomplete target-ACL
evidence, an absent manifest executor, and denied authorization. Malformed,
same-principal, stalled, or unread clients must never authorize or crash the
service loop.

This phase compiles the service path but does not live-install or start it. It
must continue to report `scm_lifecycle_live_verified=false`,
`service_pipe_activation_live_verified=false`, and
`install_gate_eligible=false`. No elevation, service/registry/ACL mutation,
manifest execution, filesystem access, network access, vault access, or
Bitwarden connection is permitted. A positive SCM lifecycle test requires a
later explicit operator-approved disposable install/start/remove gate.

## Phase 5h.15 scope

Phase 5h.15 may add only a pure, non-executable approval envelope for the first
disposable elevated Windows service lifecycle test. It accepts only the canonical
in-process Phase 5h.8 boundary plan and binds its reviewed binary digest and byte
length to a fixed ordered stage, install, configure, start, identity-check,
denial-handshake, stop, delete, remove, and absence-verification sequence.

Before mutation the plan must prove the fixed service/pipe absent and select and
verify a fresh absent disposable root/binary target. The scope remains the fixed demand-start LocalService service, unrestricted fixed
service SID, disposable administrator-controlled root, and denial-only pipe.
Every mutation requires immediate native re-verification; cleanup is a separate
finally path after the first run-owned object is created, continues after individual cleanup
failures, and ends with absence proof. Any drift, unexpected
pre-existing service, ACL/configuration/identity mismatch, non-denial response,
or incomplete cleanup stops the test. Cleanup must be attempted after any
activation and final evidence must prove service, binary, root, and pipe absent.
Every service/file/root mutation and destructive cleanup must use retained handles
for objects created by this run, with immediate native re-verification after each
mutation. A create collision must never cause reacquisition or deletion by the
fixed name/path of an object owned by another process.
Root creation and exclusive binary creation must be separate ownership-emitting
steps; binary write occurs only through its retained handle. A partial staging
failure must preserve exact per-object ownership for cleanup.

Approval is not representable as API input. The plan must always report
`mutation_authorized=false`, `live_test_executed=false`, and
`install_gate_eligible=false`. This phase must not emit commands, paths, SIDs,
ACLs, or raw output and must not elevate, install/start/stop/delete a service,
mutate files/registry/ACLs, execute a manifest, access a network/vault, or connect
to Bitwarden. Execution requires a later explicit operator approval naming this
disposable install/start/remove test and elevation scope.
Serialized, cloned, spread, accessor-backed, or forged gate objects are not
security capabilities and must be rejected; a future executor must rebuild the
branded gate in-process from the canonical boundary plan plus fresh out-of-band
operator approval.

## Phase 5h.16 scope

Phase 5h.16 may add only a pure value-free transcript state machine for facts
eventually produced by a trusted elevated lifecycle collector. It accepts only a
branded in-process Phase 5h.15 gate and an exact bounded sequence of fixed step
ids plus `verified`, `failed`, `skipped_not_owned`, or `skipped_not_started`
statuses. Preflight, mutation, denial, cleanup, and final absence evidence must
occur in the canonical order; reordering, omission, extra fields/events, illegal
skips, proxies, accessor values, and false success claims fail closed.

Cleanup skip semantics must match run ownership derived from earlier verified
create steps. A created service/root/binary cannot later be marked not owned, and
an attempted start (including a failed/ambiguous call) cannot skip stop. Final
aggregate absence must be structurally present.
Mutation failures may be structurally complete only after the full finally cleanup
sequence. Cleanup failures remain incomplete.

The evaluator validates transcript structure only. Positive completion fields
must be explicitly named as structural claims, never live verification. It must always expose
`collector_trust_verified=false`, `live_test_verified=false`, and
`authorization_ready=false`; no caller-supplied transcript may become live proof,
approval, or authorization. This phase performs no collection, command execution,
elevation, SCM/filesystem/registry/ACL mutation, manifest execution, network/vault
access, or Bitwarden connection.

## Phase 5h.17 scope

Phase 5h.17 may add only a pure Linux boundary plan for the system instance of
systemd. It must fail closed for systemd user managers, other init systems,
non-Linux platforms, and ambiguous runtime profiles. The future helper identity
is a fixed static, passwordless, non-login system user; `DynamicUser=` must not be
treated as stable ownership or distinct-principal evidence.

The plan must bind a reviewed binary digest/length, fixed service and socket unit
names, root-owned caller-nonwritable unit/binary objects and their complete
parent/mount chains, retained-descriptor identity at use, post-`daemon-reload`
loaded fragment/drop-in verification, and a root-owned filesystem
AF_UNIX endpoint with caller connect-only access, kernel peer/process binding,
initial-user-namespace identity, complete target access checks, and explicit
system-service sandbox requirements. No-network must require later-verifiable
enforcement through a private network namespace, exact AF_UNIX-only address
families, `IPAddressDeny=any`, and fail-closed runtime verification. It must accept no command, path, UID, unit
content, account override, approval value, or credential reference.

The plan is non-executable and must always report mutation unauthorized, live
test not executed, and install gate ineligible. No host inspection, account/unit
creation, elevation, file/ACL mutation, socket I/O, helper launch, manifest
execution, network/vault access, or Bitwarden connection is permitted. Those
require later Linux-specific preflight, lifecycle, trusted-collector, and explicit
operator-approval phases.

## Phase 5h.18 scope

Phase 5h.18 may add only a pure macOS boundary plan for the launchd system
domain and tighten the existing pure macOS evidence contract. It fixes one
LaunchDaemon label, Mach service, and static hidden passwordless non-login helper
account with a stable effective UID distinct from the caller. LaunchAgents,
GUI-domain services, same-EUID helpers, App Sandbox, Hardened Runtime, signing
identity differences, and audit-session differences must not establish a
distinct writer.

The plan must bind the reviewed binary digest/length and the digest of one
reviewed designated code requirement. Future trusted collectors must reverify
the installed binary, code requirement, daemon definition, loaded identity,
complete parent chains, Mach request/reply peer/helper PID and pidversion, and
symlink-safe effective access over every manifest target. The accepted request-
sender audit token
must match the independently verified authorizing caller audit token; unrelated
peer and caller facts must fail both transport and identity closed. Ordinary
user-home targets are forbidden for the production writer boundary.

The plan is value-free, non-executable, and in-process branded. It must always
report mutation unauthorized, live test not executed, and install gate
ineligible. No host inspection, signing, launchd/Mach/Security-framework I/O,
account or daemon creation, elevation, filesystem/ACL mutation, Keychain/vault
access, network access, Bitwarden pairing, or credential use is permitted.

## Phase 5h.19 scope

Phase 5h.19 may add only a read-only macOS host preflight for the fixed branded
Phase 5h.18 launchd system-helper plan. The public API accepts no caller-selected
path, label, account, command, tool, environment, timeout, or collector facts.
Only the plan-bound binary digest/length, designated-code-requirement digest,
and exact LaunchDaemon plist digest
may cross into a repo-owned probe whose service label, Mach service, static
account, LaunchDaemon plist, helper binary, and absolute tool paths are fixed.

The probe may use local `lstat`, `open(O_NOFOLLOW)`, file hashing, `plutil`,
`dscl`, and `codesign --verify`/`codesign -d -r-` against those fixed artifacts.
It must bound time/output, use a minimal environment, open the plist and binary
with required `O_NOFOLLOW`, bind plist parsing to the inherited read-only handle,
reject extended ACLs conservatively, verify complete plist and binary chains
without following symlinks, compare the exact designated-
requirement stdout bytes to the pinned digest internally, and suppress all raw
paths, UIDs, account/plist/signing data, tool output, and native errors.

Reports contain an exact boolean-only schema. The parent recomputes aggregate
state, rejects impossible partial claims, and always requires
`authorization_ready=false`. Because path-based `codesign` cannot bind its
measurement to the already-open binary descriptor, this phase may report a
separate path-snapshot match. The original Phase 5h.19 implementation must force
`designated_requirement_verified=false` and therefore
`snapshot_matches_plan=false`; Phase 5h.20 may lift those static bits only through
its content-bound private-snapshot verifier. An absent fixed plist returns the canonical all-
false report without running other tools. Individual matching evidence remains
advisory and must not become Phase 5h.4 live Mach authorization evidence.

No launchd/account/signing mutation, installation, elevation, chmod/chown,
filesystem write, Mach/Security-framework operation, Keychain/vault access,
network access, Bitwarden pairing, OneCLI deployment, manifest execution, or
credential use is permitted.

## Phase 5h.20 scope

Phase 5h.20 may lift only the Phase 5h.19 designated-requirement verification
bit by measuring an exclusive byte-identical private snapshot copied from the
already-open `O_NOFOLLOW` helper descriptor. The snapshot must live directly
beneath the canonical OS temporary directory in a fresh `mkdtemp` root owned by
the current EUID with mode `0700`; its one fixed-name file must be created with
`O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, written completely, synced, and
verified byte-for-byte before Apple `codesign` inspects only that snapshot path.

The verifier must require Apple strict signature validation, the exact pinned
designated-requirement stdout digest, stable snapshot handle/path identity and
content across inspection, and stable original installed handle identity/content
after inspection. Exact snapshot unlink and directory removal are mandatory on
both success and failure; cleanup failure fails the probe. No caller-selected
path, temp base, filename, command, tool, environment, or output may enter this
operation. `/dev/fd`, `F_GETPATH`, path-only installed-binary checks, and direct
requirements-blob parsing must not establish verification.

The report remains boolean-only. The parent may accept
`designated_requirement_verified=true` and a recomputed matching snapshot, but
must still require `authorization_ready=false`. This preflight remains advisory:
it does not prove the loaded launchd job, live helper process, distinct EUID, Mach
peer audit token/PID generation, or target access. The only new write authority
is the fixed private temporary snapshot and its exact cleanup. No write under
`/Library` or user home, launchd/account mutation, elevation, Mach operation,
Keychain/vault access, network access, Bitwarden pairing, OneCLI deployment,
manifest execution, credential use, or authorization is permitted.

## Phase 5h.21 scope

Phase 5h.21 may add only a console denial harness for the public raw Mach
request/reply transport that a future launchd `MachServices` helper will use.
The native probe must use fixed-size non-complex messages, fixed message IDs,
one generated non-secret nonce, send-once reply rights, bounded send/receive
timeouts, and `MACH_RCV_TRAILER_AUDIT` on both request and reply. Audit tokens,
not message-body identity claims, must bind PID, pidversion, EUID, and the exact
spawned caller/expected helper process generations.

The console rendezvous may use only a fresh random ephemeral bootstrap name and
must never register, check in, or look up the fixed production Mach service.
It must report `mach_service_bound=false`,
`launchd_system_service_verified=false`,
`helper_code_requirement_satisfied=false`, `manifest_request_sent=false`,
`authorization_denied=true`, and `install_gate_eligible=false`. Equal EUIDs are
the expected denial result and must be recomputed from canonical `euid:<decimal>`
SHA-256 digests by the parent. Raw audit tokens, port names, bootstrap names,
PIDs, pidversions, UIDs, native errors, and tool output must never escape.

The Node runner may compile only the fixed repo-owned C source with fixed
absolute tooling into a fresh private canonical-temp directory, execute it with
no arguments and a minimal environment, bound output/time, and require exact
cleanup. It accepts no caller input. Public SDK APIs only are permitted;
`NSXPCConnection.auditToken`, private libxpc audit-token getters, `task_for_pid`,
and PID-only identity claims are forbidden. This phase must not install or load
a LaunchDaemon, create an account, elevate, use the production service name,
verify the production code requirement, pass a launcher/manifest, mutate target
permissions, execute a manifest, access Keychain/vault/network/Bitwarden, use a
real credential, or become authorization evidence.

## Phase 5h.22 scope

Phase 5h.22 may add only a pure, branded, non-executable lifecycle gate for a
future explicitly approved macOS distinct-EUID LaunchDaemon denial test. It
accepts only the in-process branded Phase 5h.18 boundary plan and binds the
reviewed binary SHA-256 and length, designated-requirement SHA-256, and plist
SHA-256. It accepts no approval, commands, paths, account names, UIDs, GUIDs,
audit tokens, native output, or other host-selected values.

The gate must freeze the exact preflight, exclusive create/reverify, system
bootstrap, demand-activation, denial, and always-cleanup order. File ownership
must remain bound to retained parent/file descriptors. Account ownership is
only soft evidence from this run's successful create plus its recorded
GeneratedUID/UniqueID, and launchd ownership is only soft evidence from this
run's successful bootstrap plus the reverified loaded identity and bootstrap
epoch. Pre-existing objects, collisions, uncertain outcomes, or identity drift
must never be adopted or removed.

Cleanup must proceed process stop, bootout, plist unlink, binary unlink,
account deletion, then final absence verification, continuing after individual
failures while preserving manual-recovery evidence. This phase performs no
host inspection, elevation, account/file/job mutation, Mach I/O, Keychain/vault
access, credential operation, or live test, and must keep every authorization
and installation eligibility claim false.

## Phase 5h.23 scope

Phase 5h.23 may add only a pure value-free transcript state machine over the
branded in-process Phase 5h.22 gate. The input is limited to an exact bounded
plain-object transcript containing a fixed terminal outcome and ordered events
with only fixed step/status strings. It must reject proxies, accessors, custom
prototypes, holes, extras, invented or reordered steps, forged gates, and any
status that is invalid for its step.

State-changing account, file-create, bootstrap, and demand-activation steps
must distinguish a verified effect, a proven no-effect failure, and an
effect-ambiguous failure. The evaluator must derive account, binary, plist,
launchd-job, and process ownership from prior events rather than accept caller-
asserted ownership. Account and job identity-verification failure is ambiguous,
not owned. Retained-descriptor file creation success remains run-owned. An
ambiguous account or job must use `skipped_ownership_ambiguous`, never a
destructive cleanup status; a final read-only aggregate absence proof may resolve
the debris question without retroactively authorizing destruction.

Every mutation failure must carry the full ordered cleanup transcript, cleanup
must continue after individual failure, and the final aggregate absence event
must be last. Returned facts are structural claims only and must never include
events, values, paths, account/UID/GUID/audit-token data, commands, errors, or
native output. Collector trust, live verification, authorization readiness, and
installation eligibility remain false. This phase performs no collection,
elevation, launchd/OpenDirectory/file/Mach mutation, credential access, or live
test.

A `dry_run_complete` terminal outcome is permitted only for an exact complete
pre-mutation prefix with no mutation or cleanup events. It is structural and
untrusted, and must keep every live, mutation, authorization, and installation
claim false. A future read-only collector must fail closed rather than infer
that the fixed Mach service is unbound from label absence alone.

## Phase 5h.24 scope

Phase 5h.24 may add a native macOS denial-only helper scaffold with exactly two
fixed modes. Its no-argument service mode must first verify that its effective
UID belongs to the fixed hidden non-login helper account, then check in only to
the fixed production launchd Mach service. It may receive one exact bounded,
non-complex nonce probe with a kernel audit trailer and send only one send-once
denial reply. It must never authorize, execute a manifest, access credentials,
Keychain, vault, network or filesystem targets, launch a process, register or
look up another service, accept caller-selected service/account/protocol values,
or emit service-mode output.

The fixed internal self-test may report compile-time booleans only. The Node
runner accepts no input, reads the repo-owned C source through one retained
no-follow descriptor, creates two exclusive read-only source snapshots in
separate private canonical-temp roots, builds both with fixed Apple tooling and
flags, requires same-host digest equality, runs the fixed self-test, proves the
no-argument binary is silently rejected outside the fixed account/launchd
context, and performs exact cleanup. It must not install, sign, elevate, create
an account, write under `/Library`, invoke launchctl/OpenDirectory, access the
production Mach service, or leave build artifacts.

Same-host reproducibility and a compiled check-in path are not live launchd,
distinct-EUID, loaded-code, collector-trust, authorization, or installation
evidence. Every such flag remains false. The first real lifecycle still requires
a separately reviewed collector and explicit current operator approval naming
the exact disposable system test.

## Phase 5h.25 scope

Phase 5h.25 may build only an in-memory, branded, non-installing lifecycle
package from the fixed Phase 5h.24 source and exact fixed LaunchDaemon plist. It
accepts no caller input. The builder must read one stable no-follow source
snapshot, publish identical exclusive read-only source/plist snapshots into two
private canonical-temp roots, compile with fixed Apple tooling, explicitly
ad-hoc sign with the fixed identifier and Hardened Runtime, verify the signature,
parse only the exact standard or Apple ad-hoc designated-requirement record,
reverify the read binary bytes through the Phase 5h.20 FD-content snapshot path,
require same-host byte/requirement reproducibility, validate the plist with
`plutil` plus the pure fixed rules, run only the fixed self-test and ambient
service rejection, then perform exact cleanup.

The resulting real binary SHA-256/length, designated-requirement SHA-256, and
plist SHA-256 must feed a branded Phase 5h.18 plan and Phase 5h.22 gate. Artifact
bytes remain in a private WeakMap and may be retrieved only as fresh copies from
the branded package; bytes are data and never approval or mutation authority.
Clones, spreads, and forged packages must be rejected.

This phase must not elevate, create/delete an account, write under `/Library`,
invoke launchctl/OpenDirectory, contact the production Mach service, install or
load a daemon, sign with a private identity, access credentials/Keychain/vault/
network, or persist build/package bytes. Ad-hoc signing is only a local reviewed-
artifact mechanism, not distribution trust. Mutation, collector trust, live
verification, authorization, and installation eligibility remain false.

## Phase 5h.26 scope

Phase 5h.26 may add only a no-input, ordinary-user, read-only lifecycle dry-run
collector. It must first build and reverify the branded Phase 5h.25 package,
then evaluate all seven Phase 5h.22 pre-mutation checks through fixed bounded
argument-array tooling. The child schema contains booleans only and must never
emit selected UIDs/GeneratedUIDs, paths, labels, account names, commands, native
errors, tool output, or package bytes.

Label absence must use the fixed system-domain service target. Mach-service
absence must use a bounded non-activating system-domain snapshot; a label miss
alone is insufficient, and Mach lookup APIs that can demand-activate a service
are forbidden. Directory chains must be symlink-free, root-owned, not group or
world writable, and caller-nonwritable. Every collision, output drift, timeout,
truncation, incoherent result, or unsupported platform fails closed.

The probe may use only read-only OpenDirectory searches, lstat/access checks,
and launchctl print. It must not elevate, create/delete accounts, write under
`/Library`, bootstrap/bootout/kickstart, perform Mach IPC, access credentials,
Keychain, vault, network, or return approval. Completion is point-in-time,
structural, and untrusted; all mutation, live, authorization, collector-trust,
and install flags remain false. A future executor must repeat the checks just
before mutation and still requires explicit current operator approval.

## Phase 5h.27 scope

Phase 5h.27 may add only the native retained-FD file ownership primitive needed
by the later single-process lifecycle controller. Publication must use a caller-
retained directory descriptor plus `openat` with exclusive create and no-follow;
all write, owner, mode, content, and identity verification must use retained
descriptors. Cleanup may use `unlinkat` only after the retained descriptor,
current no-follow directory entry, and recorded device/inode still match.

A collision is a proven no-effect result. Any post-create failure or identity
drift is ambiguous. A replaced entry is foreign and must be preserved, never
adopted or deleted. The self-test may mutate only its own private canonical-temp
fixture and must prove collision preservation, normal cleanup, replacement
refusal, foreign-file preservation, and exact fixture cleanup.

This component must contain no system paths, account or launchd operations,
elevation, network, credential, Keychain/vault, manifest execution, approval,
or install surface. It is reusable implementation work, not live evidence.

## Phase 5h.28 scope

Phase 5h.28 may add only the native account soft-ownership state machine and a
fake directory adapter. Preparation must prove the candidate short name,
UniqueID, and GeneratedUID absent and snapshot the exact full record. Create
success remains provisional until immediate re-read verifies name, UniqueID,
GeneratedUID, non-login shell, and `/var/empty` home.

The ownership object must require explicit initialization. Preparation must
refuse to overwrite prepared, created, or ambiguous state; create must re-probe
all three namespaces after the full-record read; and successful delete must
clear preparation so any later create requires a fresh absence proof.

Deletion is eligible only for this run's created and fully verified identity,
after a fresh full-tuple re-read. The deletion adapter must receive the complete
identity rather than a bare name. Any collision, probe error, create ambiguity,
or identity drift must prevent deletion. Successful deletion must be followed
by absence checks for all three namespaces.

Tests must cover clean lifecycle, preexisting collision, post-create drift, and
pre-delete identity replacement with proof that delete was never invoked for a
foreign identity. This phase must not invoke OpenDirectory/dscl, mutate a real
account, elevate, touch launchd or system paths, or access credentials.

## Phase 5h.29 scope

Phase 5h.29 may add only the native launchd-job soft-ownership state machine and
a fake adapter. Preparation requires the fixed label and Mach name absent and
snapshots the exact program, account, Mach service, binary/plist bindings, and
demand-only policy. Bootstrap success is provisional until immediate loaded-job
read plus label/Mach presence re-verification matches the full snapshot.

Activation and denial must freshly reverify job identity. An ambiguous
activation records that a process may exist and therefore requires stop cleanup.
Denial requires separately verified process identity. Cleanup must freshly
verify the job, attempt job-scoped stop after any activation attempt, reverify
again, perform full-identity conditional bootout, and prove label plus Mach name
absent. Stop failure must not prevent bootout while identity remains intact.

Bootstrap ambiguity, identity drift, pre-cleanup swap, or adapter-local bootout
race must never authorize destructive action against a foreign job. Tests must
cover each case plus clean denial/cleanup and continued cleanup after stop
failure. This phase performs no real launchctl, Mach, process, account, file, or
system mutation and grants no approval.

Every bootstrap or activation result other than proven no-effect must be tracked
as attempted. An unverified bootstrap may perform absence-only cleanup proof but
must never bootout; presence remains ambiguous. Any non-no-effect activation
must require stop cleanup. Failed fresh identity verification must invalidate
the corresponding verified state rather than leave stale ownership flags true.

## Phase 5h.30 scope

Phase 5h.30 may compose the Phase 5h.27–29 primitives into one native controller
using fake account and launchd adapters plus private-temp retained file parents.
All absence and artifact-binding checks must finish before the first mutation.
Mutation order is account, binary, plist, job bootstrap, activation, denial.

After any first mutation, finally cleanup must always proceed job stop/bootout,
plist unlink, binary unlink, account delete, then aggregate absence, continuing
after every individual cleanup failure. Each primitive's ownership rules remain
authoritative; the controller must never reacquire or delete a foreign object.
Any unresolved or ambiguous object requires manual recovery.

Tests must cross layer boundaries: clean denial/cleanup, collision abort before
mutation, ambiguous account create, ambiguous activation cleanup, and file path
replacement during the job/denial phase with foreign preservation plus cleanup
of remaining run-owned objects. This phase contains no real OpenDirectory,
launchctl, Mach, elevation, approval, network, or credential adapter.

## Phase 5h.31 scope

Phase 5h.31 may add only a native fixed-command subprocess runner for later
OpenDirectory and launchctl adapters. It must execute an absolute, root-owned,
non-group/world-writable regular executable directly with `posix_spawn`, never
through a shell or PATH lookup. The argument vector, timeout, environment, and
output bound must be explicit and bounded; stdin is `/dev/null`; unrelated file
descriptors are closed; timeout, I/O error, and output overflow kill and reap the
child before returning.

The runner reports nonzero exits rather than treating them as transport errors.
Its self-test may invoke only harmless macOS system tools (`true`, `false`,
`printf`, `sleep`, and `yes`) and must prove capture, nonzero status, timeout,
output-flood termination, and relative-path rejection. This phase must not invoke
dscl or launchctl, elevate, create/delete accounts, write system paths, perform
Mach IPC, access credentials, or grant installation approval.

## Phase 5h.32 scope

Phase 5h.32 may add the fixed native `dscl` directory adapter over the Phase
5h.31 runner. It accepts only `_bwagentbridge`, a system-range UniqueID, the
canonical generated UUID, `/usr/bin/false`, and `/var/empty`. Searches, reads,
property creation, and deletion use fixed argument arrays and bounded, silent,
strictly parsed output. Every partial create or uncertain mutation is ambiguous,
never no-effect.

Deletion must re-read and compare the complete live identity immediately before
the fixed-path delete. A mismatch or unreadable record is ambiguous and must not
invoke delete. The outer account ownership state machine still performs its own
fresh verification and post-delete three-namespace absence proof. Tests use an
in-process fake command runner only; they must not invoke real dscl, create an
account, elevate, touch system paths, access credentials, or grant approval.

## Phase 5h.33 scope

Phase 5h.33 may add the fixed native launchctl job adapter over the Phase 5h.31
runner. Commands are limited to the exact system-domain helper target and fixed
plist: print, bootstrap, kickstart, SIGTERM kill, and bootout. Successful
mutations require exit zero and completely silent output; every other outcome
is ambiguous unless a future macOS-version-pinned rule proves no effect.

Loaded-job parsing must require exactly one canonical header, program, and user
line. Running-process evidence additionally requires exactly one running-state
line and one bounded PID line. Duplicate or conflicting keys fail closed. Every
loaded-job read and pre-stop/pre-bootout check must also pass an injected
artifact/policy verifier bound to the expected binary/plist digests. Mach-name
presence and denial evidence remain separate mandatory injected probes; the
adapter must not infer them from weak launchctl text.

Tests use only fake command and probe callbacks and must prove the full owned-job
lifecycle plus malformed identity rejection. A real read-only print of an
unrelated Apple job may validate output grammar, but this phase must not load,
start, signal, or remove the bridge job; perform Mach IPC; elevate; access
credentials; or grant live approval.

## Phase 5h.34 scope

Phase 5h.34 may wire the fixed dscl and launchctl adapters into the composite
controller and bind the controller's run-owned binary/plist retained descriptors
to every launchd identity check. Both files must publish and verify before a
one-shot binder succeeds; bootstrap must not run after binder failure. Bootstrap,
activation, loaded-job reads, stop, and bootout must each reverify the retained
file identities, bytes, ownership, modes, and expected job tuple as applicable.

Production initialization must prove the retained parent descriptors resolve
exactly to `/Library/PrivilegedHelperTools` and `/Library/LaunchDaemons`, and
repeat that proof during artifact checks so launchctl's fixed plist path cannot
diverge from the verified file. Temporary-path end-to-end tests may use only the
compile-time `BW_NATIVE_WIRING_TESTING` constructor, which must not exist in a
normal build. Artifact byte buffers must remain immutable for the complete run.

Tests must prove a clean fake-system lifecycle, binder-failure cleanup with no
job mutation, production rejection of temp parents, pre-bootstrap artifact-drift
blocking, and foreign plist preservation after denial-time replacement. This
phase exposes no executable CLI or approval bypass and performs no real dscl,
launchctl mutation, system write, Mach IPC, elevation, or credential access.

## Phase 5h.35 scope

Phase 5h.35 may add the production client side of the fixed Mach denial protocol
and propagate the freshly parsed launchctl helper PID into that probe. The
launchctl adapter must refresh the running PID inside denial, not trust an older
cached value. The client may look up the fixed Mach service only after owned-job
activation and process verification, so the lookup is not an absence probe and
cannot unexpectedly activate during preflight.

The reply must be a bounded non-complex fixed-size message with the exact ID,
version, kind, denial value, ports, and random nonce. Its kernel audit trailer
must match the immediately refreshed helper PID, fixed UID 499, and carry a
positive PID generation. Public `proc_pidinfo`/`proc_pidpath` snapshots before
and after the exchange must retain the same PID, EUID, start timestamp, and exact
fixed helper path, preventing PID reuse or executable replacement across the
exchange. Invalid received messages must be destroyed before rights are released.

Private-bootstrap tests may expose an alternate service name only under
`BW_MACH_PROBE_TESTING`; they must prove a valid exchange and behavioral rejection
of a wrong expected PID. Production code must require the initialized probe
context, fixed service/identity, distinct current/helper EUIDs, and the exact
account record. This phase still performs no production service lookup, account
or launchd mutation, system write, elevation, credential, Keychain, vault, or
network access.

## Phase 5h.36 scope

Phase 5h.36 may add the production non-activating Mach-name presence callback.
It must execute only fixed `/bin/launchctl print system` with the hardened
absolute-executable, fixed-environment, closed-FD, process-group, timeout, and
kill/reap rules. It must stream and validate at most 8 MiB rather than buffer an
unbounded domain snapshot; any stderr, invalid byte, long line, truncation,
nonzero exit, timeout, or missing final newline is a probe error.

Presence requires the exact trimmed launchctl endpoint-entry line
`"de.frederikstadler.bitwarden-agent-credential-bridge.helper" = {`. Bare name
occurrences in paths, labels, prefixes, or suffixes must not match. The collector
must not call bootstrap lookup/check-in because those APIs can activate a
demand-only service. A fixed probe bundle may combine this callback with the
Phase 5h.35 denial callback for native lifecycle wiring.

Tests may parse synthetic snapshots and perform the real read-only system-domain
print, whose expected current result is fixed-name absence. They must not invoke
bootstrap, kickstart, kill, bootout, Mach lookup, account or system mutation,
elevation, credentials, Keychain, vault, or network access.

## Phase 5h.44 scope

Phase 5h.44 may add only a pure Windows elevated-collector provenance evaluator
over trusted, injected collector facts. It accepts a branded in-process Phase
5h.15 gate, a transcript revalidated by Phase 5h.16, and an exact boolean
provenance object. It may set `collector_trust_verified` only when the transcript
is structurally complete and every required provenance boolean is true:
elevated-token verification, local-only collection, retained-handle binding,
absent path reacquisition, value-free emission, absent stderr, gate step-surface
match, and cleanup-finally binding.

UAC consent, admin-group membership, and high-integrity reports are
defense-in-depth signals only. They must never establish collector trust when
required retained-handle elevation facts are incomplete. Exact plain-object
schemas reject proxies, accessors, extra fields, and wrong versions. The report
must always keep `live_test_verified=false`, `mutation_authorized=false`,
`install_gate_eligible=false`, and `authorization_ready=false`. Synthetic
provenance may satisfy the schema in tests but is not live collection.

This phase performs no collection, PowerShell launch, elevation, SCM/filesystem/
registry/ACL mutation, path or SID emission, manifest execution, network/vault
access, or Bitwarden connection. Approval remains out-of-band and must never be
accepted as API input. A later explicit operator-approved elevated disposable
install/start/remove collector is required before live verification.

## Phase 5h.45 scope

Phase 5h.45 may implement and run the operator-approved disposable elevated
Windows service lifecycle collector on an explicitly approved host. It may publish
the reviewed helper into an OS-temporary build workspace, stage payload bytes under
a marked temp staging root, elevate a repo-owned PowerShell collector, create a
fresh disposable root under ProgramData, install the fixed demand-start
LocalService service with unrestricted service SID, start it, verify
LocalService/server identity, exercise the different-principal denial pipe using
the native service-denial client, then stop/delete/remove and prove absence.

The public Node API accepts no approval value, path override, service name,
pipe name, command, credential, or Bitwarden reference. It rebuilds the branded
Phase 5h.8/5h.15 objects in-process from the published digest/length. Collector
stdout/result JSON remains value-free: fixed step ids/statuses plus exact
provenance booleans only. `live_test_verified` may become true only after a
structurally complete denial transcript, required provenance, and successful
cleanup/absence proof. `mutation_authorized`, `install_gate_eligible`, and
`authorization_ready` remain false; this disposable matrix does not authorize a
persistent production install.

The collector must refuse to run without elevation, refuse pre-existing service
or pipe collisions, and never reacquire colliding objects by fixed name for
destructive cleanup. The different-principal denial client runs from the
non-elevated Bridge process; LocalService binds the caller through named-pipe
impersonation rather than `OpenProcess` on the interactive client. It must not
access Bitwarden, read DPAPI vault credentials, open a network client beyond
local SCM/pipe, or execute a manifest.

## Phase 5h.46 scope

Phase 5h.46 may add only a pure Windows install-gate evidence compiler. It
accepts a branded Phase 5h.15 lifecycle gate, an exact Phase 5h.45 live report
object, and an optional Phase 5h.9 advisory preflight snapshot. It may set
`install_gate_eligible=true` only when disposable live denial was verified,
collector trust was complete, the gate binary binding is present, and any
supplied post-cleanup preflight shows the fixed service absent without claiming
authorization. It must keep `authorization_ready=false`,
`mutation_authorized=false`, `persistent_mutator_absent=true`, and
`vault_access_forbidden=true`. Forged gates, authorizing preflight claims, and
extra fields fail closed. This phase performs no elevation, SCM mutation,
persistent install, manifest execution, network/vault access, or Bitwarden
connection.

## Phase 5h.47 scope

Phase 5h.47 may add only a pure Windows helper layout contract for service-SID
trusted roots. It must distinguish disposable and persistent layouts, bind the
fixed service identity from the Phase 5h.8 boundary plan, forbid ordinary
user-profile roots (LocalAppData/home), require ProgramData-class trusted roots
owned by trusted administrators/SYSTEM/service SID, and never emit concrete host
paths, SIDs as caller-chosen inputs, commands, or vault references. The plan is
non-executable and must report mutation unauthorized until a later apply slice.
No host I/O, elevation, install, or Bitwarden access is permitted.

## Phase 5h.53 scope

Phase 5h.53 may harden the disposable elevated live collector to retain an
`OpenService` handle through `DeleteService`, track stderr emptiness, bind
completion nonces, and report honest provenance. It may set
`retained_handle_binding_complete` and `path_reacquisition_absent` only when the
service object was deleted via that retained handle. Binary image handles must
still close before SCM start so the loader can map the executable.

## Phase 5h.54 scope

Phase 5h.54 may compile a vault-free LocalService first-install apply under the
helper module's ProgramData-class parent root after a different-principal pipe
session. It creates exactly five exclusive absent targets (config dir/file,
install dir, bin dir, launcher file) from launcher bytes delivered on the pipe
after the denial handshake. Self-test may report `manifest_executor_absent=false`.
No Bitwarden/vault client, network stack, or persistent apply is permitted. The
helper must never accept caller-chosen filesystem roots beyond digest-bound
authorize metadata already validated by schema.

## Phase 5h.48 scope

Phase 5h.48 may add a bounded LocalService authorize-request schema and a
native stdin self-test that validates the schema shape while always denying
mutation. It may compile `service_authorize_schema_compiled=true` into the helper
self-test. Target ACL evidence remains incomplete, and the manifest executor,
vault client, and network stack remain absent. No persistent install, apply
execution, or Bitwarden access is permitted.

## Phase 5h.49 scope

Phase 5h.49 may add a pure/Node disposable apply authorization envelope for
LocalService-targeted ProgramData disposable roots and a test harness that
simulates helper-side apply under disposable workspace semantics without placing
vault secrets on the helper pipe. Live elevated apply under the installed
service remains optional behind existing operator approval; mutation must use
retained-handle rules and cleanup. Helper stays vault-free.

## Phase 5h.50 scope

Phase 5h.50 may add a pure persistent install/uninstall plan and value-free
lifecycle report schema for test-persistent LocalService installs under the
5h.21 layout, plus an elevated collector entrypoint that can install or remove
the fixed service under ProgramData with absence proof on uninstall. Collision
and reacquisition fail closed. Vault access remains forbidden in the helper.

## Phase 5h.51 scope

Phase 5h.51 may add a fake vault resolver that maps bootstrap service aliases to
in-memory fake secrets and feeds `startBroker` without network or DPAPI. Secrets
must never appear in policies, logs, helper pipes, or exposure surfaces.

## Phase 5h.52 scope

Phase 5h.52 may add a gated dev-Bitwarden resolver that reads only the
operator-approved DPAPI-backed development credential store, resolves one
configured item field into short-lived broker memory, and extends exposure tests.
It must refuse personal/company vaults, never log secrets, and keep the helper
vault-free. The fixed store basename is opened through a repo-owned PowerShell
probe that pins Purpose by SHA-256 and emits only the password on stdout for an
in-process adapter; forged gates and wrong ACL/account flags fail closed.

## Phase 6 scope

Phase 6 supersedes the Phase 1 / 4a / 4b exclusions of browser and form login for
this milestone only. It may add disposable/dev-only `browser_form_login` (policy
version 5) with exact `{{username}}` / `{{password}}` placeholders, exact field
names, an exact hidden-field name allow-list (no wildcards / auto-scrape-all),
loopback fake login sites, and a dedicated session broker that never routes
through `startBroker` HTTP header injection.

The session broker uses stdlib `fetch` plus an in-memory cookie jar (Playwright
remains opt-in and out of default `npm test`). Secrets and issued session cookies
are confined to broker memory, added to the sensitive-variant set, and must never
appear on agent-readable surfaces. Opaque session ids are random in-process
handles; the agent may only call policy-pinned replay paths on the same origin.
Redirects inside the login child path are same-origin with a hard hop cap; the
agent-facing HTTP path keeps redirects fail-closed. MFA, CAPTCHA, and login
failure terminate with fixed value-free codes and must never return HTML, titles,
screenshots, or DOM. One session writer at a time; destroy jar/profile on stop.

Non-loopback HTTPS login origins require a branded operator live gate. A single
operator-approved disposable public demo (`the-internet.herokuapp.com`) may
execute live login behind an explicit approval flag and hostname pin; personal
and company Bitwarden pairing, FTP/SSH/RDP, interactive MFA/SMS/email, vault
clients inside LocalService, and `authorization_ready=true` remain forbidden.
Version 1–4 policies stay compatible.

## Phase 7 scope

Phase 7 may add HQ operational readiness for disposable/dev secrets only:

- policy version 6 `http_api_key_query` with exact `query_name` matching
  `^[a-z][a-z0-9_-]{0,63}$` and exact `{{credential}}` `query_value`;
- agent-facing requests remain query/fragment-free; the broker appends exactly
  one outbound query parameter via `URLSearchParams` and verifies origin,
  pathname, parameter count, and parameter name before fetch;
- never log or return the outbound query URL; expand sensitive-variant scanning
  for raw, percent, form-urlencoded (`+`), `name=value` pairs, Base64, and
  Base64url forms; scan redirect `Location` headers before fail-closed denial;
- printable-ASCII runtime sentinels only (8–4096 bytes) for query class;
- permanently reject named classes `oauth`, `mfa_interactive`, `sms`, `email`,
  and `env_inject` with stable codes at policy/resolver/broker boundaries
  (unknown classes stay default-denied; Phase 16 adds dedicated `ssh`/`ftp`
  session brokers — still never via `env_inject`); DPAPI unlock is not MFA;
- one concurrent multi-class loopback matrix across bearer, API-key header,
  Basic, API-key query, and browser form-login with unique secrets and
  cross-contamination checks;
- branded disposable/dev Bitwarden live scope (choice 1B) constructed only by
  an operator-approved CLI flag; library APIs never accept the flag as a
  capability; evidence is boolean-only; `authorization_ready` stays false;
  personal/company/organization vaults remain forbidden.
- On Windows, the fixed DPAPI store may unlock the pinned disposable account
  identity `frederikstadler+bridge@gmail.com` (digest-compared, never logged)
  for broker smoke tests only; DPAPI unlock is not MFA.

Phase 7 must not pair personal or company Bitwarden, implement OAuth/MFA/SMS
flows, inject process environment secrets, follow redirects with query tokens,
or claim production writer isolation.

## Phase 8 scope

Phase 8 may add an in-process operational disposable/dev multi-service bridge:

- a tracked secret-free binding table mapping aliases to repo-relative policy
  paths and exact credential classes;
- foreground start of fake-vault-backed HTTP and browser brokers for the bound
  aliases with atomic alias/policy/class matching before resolve/start;
- transactional reverse-order cleanup on startup failure and on SIGINT/SIGTERM;
- readiness taxonomy with `harness_ready`, optional `disposable_dev_ready`, and
  `authorization_ready` (Phase 9e wires the latter from branded Phase 9a; Phase 8
  alone must not invent true);
- no PID-file stop, no lease-based remote kill, no company/personal vault pairing,
  and no reuse of the disposable DPAPI account password across multiple aliases.

Phase 8 must not claim production writer isolation or elevate install eligibility.
Hardcoded `authorization_ready=true` remains forbidden; Phase 9e may copy the
flag from a complete branded Phase 9a report only.

## Phase 9 scope

Phase 9 defines the fail-closed Windows path to a legitimate
`authorization_ready=true` under the repository threat model. Disposable live
denial, `install_gate_eligible`, persistent install/uninstall, DPAPI smoke, and
path-based preflight remain individually insufficient.

### Phase 9a

Phase 9a may add only a pure Windows production authorization evidence compiler:

- accept branded Phase 5h.46 install-gate eligibility, a branded persistent
  ProgramData layout plan, branded handle-bound installed-service identity
  facts, branded complete target-ACL matrix facts, and exact Phase 5h.1 peer
  five-facts;
- set `authorization_ready=true` only when every class is complete and
  `path_based_preflight_only` is false;
- keep `mutation_authorized=false`, helper vault-free, and personal/company
  vault forbidden;
- reject forged clones, disposable layouts, advisory path-only pretenses, and
  extra fields;
- keep pure 9a reports marked `operational_bridge_unwired=true` (Phase 9e wires
  the operational surface separately).

Phase 9a performs no host I/O, elevation, SCM/pipe mutation, manifest execution,
or Bitwarden access. Synthetic harness branding may exercise the true path in
unit tests only. The operational bridge consumes 9a reports only through Phase
9e.

### Phase 9b

Phase 9b may add a read-only Windows handle-bound installed-service identity
collector:

- compose the native Phase 5h.13 pipe/SCM/token verifier with a handle-open
  binary digest and service-object ACL probe (`CreateFile` +
  `FILE_FLAG_OPEN_REPARSE_POINT` + `ReadFile` hashing; never path `Get-FileHash`);
- brand the merged exact Phase 9a handle-bound evidence schema;
- keep `path_based_preflight_only=false` and public collector
  `authorization_ready=false`;
- accept a branded Phase 5h.8 boundary plan only; emit value-free reports.

Phase 9b must not elevate, install/start/stop a service, execute a manifest,
access Bitwarden, or treat Phase 5h.9 path preflight as sufficient. A complete
positive result requires an already running persistent LocalService install from
a separate operator-approved gate. Operational `authorization_ready` is decided
only by Phase 9e over branded 9a composition.

### Phase 9c

Phase 9c may add a read-only AccessCheck matrix over the five fixed persistent
ProgramData-class targets (config dir/file, install root, bin dir, launcher):

- require a branded persistent Phase 5h.47 layout plan;
- bind caller and running LocalService helper tokens; finish all five checks
  before `all_targets_checked=true`;
- brand the exact Phase 9a target-ACL evidence schema;
- keep public collector `authorization_ready=false`;
- emit value-free reports only (no paths, SIDs, usernames, or raw ACL text).

Phase 9c must not elevate, mutate ACLs, install/start/stop a service, execute a
manifest, or access Bitwarden. Incomplete host state (absent root or non-running
service) must fail closed as an incomplete branded matrix. Operational
`authorization_ready` is decided only by Phase 9e.

### Phase 9d

Phase 9d may add a read-only different-principal persistent pipe session that
feeds branded Phase 5h.1 peer five-facts:

- compose native `service-denial` pipe client, Phase 5h.13 server identity
  verification, and Phase 9c target-ACL evidence;
- set `different_principal=true` only when the denial peer is proven LocalService
  with enabled service SID (never from console same-user denial alone);
- brand peer five-facts for Phase 9e wiring; keep public collector
  `authorization_ready=false`;
- emit value-free reports only.

Phase 9d must not elevate, install/start/stop a service, execute a vault-backed
apply, or access Bitwarden. Absent pipe or same-principal hosts must fail closed
as incomplete / `same_principal_rejected`. Operational `authorization_ready` is
decided only by Phase 9e.

### Phase 9e

Phase 9e may wire operational readiness surfaces to a branded Phase 9a report
composed from branded Phase 5h.46 install-gate, Phase 5h.47 persistent layout,
Phase 9b handle-bound, Phase 9c target-ACL, and Phase 9d peer evidence:

- copy `authorization_ready` only from `evaluateWindowsProductionAuthorization`
  output — never hardcode `true`;
- default/absent evidence uses incomplete branded fixtures and remains false on
  typical same-user hosts;
- fail closed on forged/unbranded evidence;
- keep personal/company vaults forbidden and the helper vault-free;
- set `operational_bridge_unwired=false` on the wired report while still
  evaluating false until every production evidence class is complete.

Phase 9e must not invent live host completeness, leave a persistent service
installed, pair personal/company Bitwarden, or claim macOS/Linux authorization
from Windows-only evidence. Synthetic complete fixtures may exercise
`authorization_ready=true` in unit tests only.

### Phase 9f

Phase 9f may package-bind reviewed helper and supervisor digests used by
collectors and expand CI for pure Windows slices without live service install:

- pin LF-normalized digests/lengths for the exact
  `native/windows-helper-service/` tree, the canonical package digest, and the
  fixed SDK/runtime/ILLink toolchain;
- bind the helper SCM/console entrypoint argv surface and self-test keys;
- pin the OneCLI proxy supervisor module, frame helper, and
  `run-onecli-proxy.mjs` entrypoint digests plus required imports;
- require publish/collector paths to verify those pins and brand publish
  bindings fail-closed; forged publish clones are rejected;
- keep `authorization_ready` evidence-driven via Phase 9e/9a only;
- do not weaken same-host publish/self-test reproducibility.

Phase 9f must not install/start a service in CI, hardcode
`authorization_ready=true`, pair personal/company Bitwarden, or place a vault
client in LocalService.

Phase 9 must not pair personal/company Bitwarden, place a vault client in
LocalService, implement OAuth/MFA/SMS/SSH/FTP/`env_inject`, or claim macOS/Linux
authorization from Windows-only evidence.

## Phase 10a scope

Phase 10a may add a foreground Windows Day-2 authorization evidence refresh:

- assume an already-installed persistent LocalService helper;
- periodically re-collect branded Phase 9b/9c/9d evidence via injected or live
  collectors and recompose Phase 9e readiness;
- emit value-free snapshots (`refresh_generation`, booleans, terminal codes);
- fail closed to `authorization_ready=false` on collector errors;
- optionally restart the operational bridge with the latest branded evidence
  bundle;
- keep uninstall explicit and operator-gated;
- keep `mutation_authorized=false`, helper vault-free, and personal/company
  vaults forbidden.

Phase 10a must not auto-elevate, auto-install, implement OAuth/MFA/SSH/
`env_inject`, pair personal/company Bitwarden, claim same-user memory isolation,
or leave a persistent service installed after CI.

## Phase 10b scope

Phase 10b may add an operator bootstrap that exits with
`authorization_ready=true` only when branded Phase 9e compose reports that value
from live or injected collectors:

- optional elevated persistent LocalService install behind an explicit approval
  flag (not a library capability);
- one vault-free first-install apply when target-ACL evidence is incomplete;
- re-collect and recompose; never hardcode `authorization_ready=true`;
- optional operational-bridge wire-up and Phase 10a refresh keep-alive;
- optional uninstall-after cleanup;
- keep `mutation_authorized=false`, helper vault-free, and personal/company
  vaults forbidden.

Phase 10b must not pair personal/company Bitwarden, implement OAuth/MFA/SSH/
`env_inject`, place a vault client in LocalService, claim same-user memory
isolation, or treat a forged JSON report as authorization evidence.

## Phase 10c scope

Phase 10c may add a foreground Windows Day-2 operator session that unifies
Phase 10b bootstrap, operational-bridge wire-up, and Phase 10a evidence refresh:

- fail closed unless branded compose reports `authorization_ready=true`;
- replace the operational bridge on each refresh tick from latest branded evidence;
- emit value-free `authorization_drift` when readiness becomes false and never
  invent `authorization_ready=true`;
- leave the persistent LocalService installed by default; uninstall remains an
  explicit operator flag or separate command;
- keep `mutation_authorized=false`, helper vault-free, and personal/company
  vaults forbidden.

Phase 10c must not auto-elevate without an explicit approval flag, pair
personal/company Bitwarden, implement OAuth/MFA/SSH/`env_inject`, claim
same-user memory isolation, or treat a forged JSON report as authorization
evidence.

## Phase 11 scope (macOS authorization ladder)

Phase 11 climbs the macOS path toward platform-scoped `authorization_ready`
without reusing Windows `5h.44–54` numbers. It builds on Phase 5h.18–5h.43.

### Phase 11a

Phase 11a may add only pure macOS collector-trust and install-gate compilers
over branded Phase 5h.22 gates, Phase 5h.23 transcripts, and an exact live-report
schema. Synthetic provenance may satisfy the trust schema in tests;
`live_test_verified` and `authorization_ready` stay false. No sudo, launchd,
Mach, Keychain, or vault I/O is permitted.

### Phase 11b

Phase 11b may add only a pure macOS helper layout plan for disposable and
persistent LaunchDaemon artifacts under PrivilegedHelperTools / LaunchDaemons
class roots. Application Support and home writer roots are forbidden. The plan
emits no concrete paths and keeps mutation unauthorized.

### Phase 11c+

Later Phase 11 slices require a macOS host for live disposable distinct-EUID
denial and persistent collectors
(`docs/phase11c-macos-disposable-denial-handoff.md`). Pure Phase 11e/11j/11l
production authorization, operational wire-up, and injected bootstrap compilers
may run on any host; synthetic fixtures may exercise `authorization_ready=true`
in unit tests only.

## Phase 12 scope (Linux authorization ladder)

Phase 12 climbs the Linux systemd system-instance path toward platform-scoped
`authorization_ready`, building on Phase 5h.3 and 5h.17.

### Phase 12a–12f

These slices may add only pure layout, lifecycle gate, transcript state machine,
collector-trust, install-gate, and vault-free authorize-envelope compilers.
`DynamicUser=`, systemd user managers, abstract sockets, and home/XDG writer
roots remain forbidden. Every report keeps `authorization_ready=false` and
`mutation_authorized=false`. No host I/O, account/unit mutation, or Bitwarden
access is permitted.

### Phase 12g+

Native helper scaffolds and disposable root lifecycle collectors require a Linux
host with a real systemd system instance; see
`docs/phase12n-linux-disposable-denial-handoff.md`. Pure Phase 12p/12t/12u
production authorization, operational wire-up, and injected bootstrap compilers
may run on any host; synthetic fixtures may exercise `authorization_ready=true`
in unit tests only. Platform reports must never copy Windows readiness onto
Linux.

## Phase 13 scope

Phase 13 may add an operator-approved **personal** Bitwarden resolve path for
Windows agents without placing a vault client in LocalService:

- allow branded personal-vault resolve only behind the CLI flag
  `--i-approve-personal-bitwarden-agent-resolve` (never a library capability);
- pin the account identity as a SHA-256 digest from a machine-local,
  schema-fixed allowlist config (not a free runtime email string);
- keep `company_vault_forbidden=true` and `organization_vault_forbidden=true`;
- keep `helper_vault_free=true` — secrets unlock and resolve only in the
  Bridge/broker process under the interactive Windows user; never on the
  helper pipe;
- never log or return secrets; exposure tests must fail if a sentinel appears
  on an agent-readable surface;
- keep `authorization_ready` evidence-driven (Windows 9e/10c) and never set it
  true from vault unlock alone;
- provide optional laptop-ready operator entry that separates Day-2
  authorization from personal resolve.

Phase 13 must not pair company/organization/privateHQ vaults, place a vault
client in LocalService, implement OAuth/MFA/SMS/SSH/`env_inject`, hardcode
`authorization_ready=true`, or treat a forged JSON report as authorization
evidence. Org/privateHQ Secrets Manager resolve is Phase 14.

## Phase 14 scope

Phase 14 may add an operator-approved Bitwarden **Secrets Manager**
machine-account resolve path as the productive same-user default:

- allow branded SM resolve only behind the CLI flag
  `--i-approve-secrets-manager-machine-resolve` (never a library capability);
- pin allowed project UUIDs in a machine-local schema-fixed allowlist
  (not free runtime org strings);
- store the machine access token only in a local secure store (Windows DPAPI
  or macOS owner-only file / Keychain path); never commit tokens; never place
  `BWS_ACCESS_TOKEN` on an agent-readable process environment;
- resolve secret values into short-lived Bridge/broker memory via a pinned
  upstream `bws` CLI or an injected test adapter; never log or return secrets;
- keep `helper_vault_free=true` — no vault client and no secrets on the
  LocalService helper pipe;
- keep `authorization_ready` evidence-driven (Windows 9e/10c or platform
  analogs) and never set it true from SM unlock alone;
- treat LocalService distinct-writer install as optional research, not required
  for productive same-user SM resolve;
- expose an `operational_sm_same_user` binding profile mapping aliases to
  project id + secret key without embedding secret values.

Phase 14 must not create extra interactive OS user accounts, place a vault
client in LocalService, implement OAuth/MFA/SMS/SSH/`env_inject`, hardcode
`authorization_ready=true`, or treat a forged JSON report as authorization
evidence.

Phase 14 may also add guided local machine setup/uninstall and agent-blind
SM write (create/update) behind separate CLI flags
`--i-approve-sm-machine-setup`, `--i-approve-sm-machine-uninstall`, and
`--i-approve-secrets-manager-machine-write`. Write APIs must never return
secret values to agent-readable surfaces; setup may accept a token only
through a local secure prompt/store path.

## Phase 15 scope

Phase 15 may add a Windows **product installer** for the same-user Secrets
Manager path:

- ship an Inno Setup installer from GitHub Releases with Start Menu entries
  and an Apps & Features uninstaller;
- first-run guided setup may collect the machine access token via a local
  secure prompt and write the machine allowlist (default MiViA + private-hq);
- Bitwarden SM **cloud is the default**; optional self-hosted `server_url`
  and/or `api_url` + `identity_url` may be stored in the local allowlist and
  passed only to short-lived `bws` child processes — never as agent
  `process.env`;
- do **not** bundle Codex or the Bitwarden desktop app; agent/user docs may
  instruct installing those separately on request;
- uninstall must remove installed app files and best-effort clear local SM
  token/allowlist state;
- keep `helper_vault_free=true`, no LocalService vault client, and never set
  `authorization_ready=true` from installer or SM unlock;
- provide [`docs/agent-windows-install.md`](docs/agent-windows-install.md) so
  agents pointed at this repo can run a guided install without requiring the
  user to be a terminal expert.

Phase 15 must not create macOS installers in this slice, auto-create Bitwarden
machine accounts, place secrets on agent-readable surfaces, or treat the
installer as LocalService authorization evidence.

## Phase 16 scope

Phase 16 may add fake-loopback **SSH** and **FTP** session brokers (policy
versions 7 and 8) for disposable/dev Secrets Manager secrets only:

- move `ssh` and `ftp` from the permanent reject list into supported classes
  with dedicated session brokers (never `startBroker` HTTP header injection,
  never `env_inject` / process-environment secrets);
- exact `{{username}}` / `{{password}}` placeholders only; credentials stay in
  broker memory after SM/DPAPI resolve;
- loopback-only fake SSH/FTP protocol servers; agent surfaces expose opaque
  session ids plus allow-listed ops (`exec` with exact command allow-list;
  FTP `list`/`retr` on exact virtual paths);
- one session writer at a time; destroy session state on close; bound I/O;
  recursive sensitive-variant redaction on logs/errors/responses;
- wire SM operational bindings and private-hq matrix coverage for bearer,
  API-key header/query, Basic, browser form-login, SSH, and FTP;
- keep `oauth`, `mfa_interactive`, `sms`, `email`, and `env_inject` rejected;
- keep `authorization_ready=false`, helper vault-free, and no personal/company
  vault pairing.

Phase 16 must not open non-loopback SSH/FTP without a later explicit live gate,
implement OpenSSH/FTP wire compatibility, place credentials in agent env, or
treat session success as production writer isolation.
