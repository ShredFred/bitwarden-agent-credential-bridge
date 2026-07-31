# Phase 3 disposable live-test runbook

Status: **NOT RUN; compatibility UNVERIFIED**.

This is a future, operator-executed runbook. It does not authorize work by
itself, and no step in it has been performed by this repository change. Its
reader is the engineer conducting a separately approved disposable test. The
goal is to produce pass/fail evidence without retaining credentials or implying
that candidate AAC compatibility has already been established.

## 1. Explicit approval gate

Before any network access, download, image pull, container start, account
creation, or pairing:

- [ ] Obtain explicit approval naming the operator, disposable host, time
  window, allowed Bitwarden endpoints, fake target endpoint, and cleanup owner.
- [ ] Confirm the test uses no personal or company Bitwarden account, vault,
  item, credential, token, service inventory, or recovery material.
- [ ] Approve the exact OneCLI image repository corresponding to version
  `1.45.0`; the repository name is intentionally absent from the offline lock.
- [ ] Approve destination-level egress controls and a capture location that
  stores only redacted evidence.
- [ ] Assign a separate OS/runtime identity to OneCLI and a distinct,
  least-privilege agent identity.
- [ ] Confirm the agent identity has no Docker control: no daemon socket,
  Docker group, Docker Desktop control context/API, container control, volume
  access, database access, gateway administration, or runtime process access.

Any unmet entry condition is a stop condition. Do not improvise around it.

## 2. Locked evidence to verify offline

Use the supply-chain lock as the expected-value list, not as an installer.
Re-establish provenance under the approved process before execution.

### OneCLI and its linked Agent Access crate

- OneCLI version: `1.45.0`
- tag commit: `84ccaf74ce6350f8925675457b48272c29f32c1a`
- OCI index:
  `sha256:d0177458b1f9ecece4abbe9abb6c5f925475357c1734f50a675d83a2ef9c8687`
- Linux amd64 manifest:
  `sha256:5b9367221f7b9acb741cadd67b0ce0384bc344994effb9e04ce339f8930cdc8a`
- Linux arm64 manifest:
  `sha256:cb55d9e7b71c655134d4a1fe03a6152ad0e2c44518bcf4f68418c9e6bb98f9df`
- actually linked crate: crates.io `ap-client` `0.9.0`
- crate checksum:
  `7c7dfbe9db85d3e17e654afa4117ae76c5ec16750cee817a80432b2e93f724a2`
- matching Agent Access v0.9.0 source tag commit:
  `fc858195ccabd88737a0255a0fda60a7a02c2286`

The later commit `9cd303f65dc501c19d1d513fb4cf88fe5f44936a`
belongs to workspace `0.12.0`. It is a source-audit reference and is **not**
the dependency linked by OneCLI 1.45.0.

### Postgres image

- tag context: `18-alpine`
- OCI index:
  `sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`
- Linux amd64 manifest:
  `sha256:b6a16ed0eb96e2c362811f7eeb951eac8b459e7b40be4149ea5444aa7c65569b`
- Linux arm64 manifest:
  `sha256:122c9942437efcbbb8d595fc578dee7d26ee1543c2a8634d183adfa4a1e55b4d`

### Candidate AAC

Candidate AAC `0.11.0` is separate from the crate linked into OneCLI:

- tag commit: `3b000d15af71be5ddcf8893b099f3a66d386be9d`
- Windows zip SHA-256:
  `bc72b7e3e04d0cb53d4b1117326045383974f5092588a9bff6e2484029be040c`
- compatibility status: **unverified**

After approval and download through the reviewed channel, calculate the
candidate AAC checksum locally. On Windows, use `Get-FileHash -Algorithm
SHA256 <candidate-zip>`; compare the normalized hexadecimal result exactly to
the value above before extracting or executing it. A mismatch means stop and
clean up the untrusted file.

## 3. Prepare disposable identities and data

- [ ] Create a disposable Bitwarden account dedicated to this test.
- [ ] Create exactly one disposable item containing a generated fake value
  unique to the test. Do not reuse any real username, endpoint, or secret.
- [ ] Record only a random evidence ID and the fake value's one-way test
  fingerprint. Do not record the plaintext fake value in evidence.
- [ ] Create the separate OS/runtime identity and agent identity approved in
  section 1.
- [ ] From the agent identity, prove Docker control is denied. Record only
  pass/fail and the attempted control surface; redact command output.
- [ ] Prove the agent cannot read runtime configuration, process state,
  container files, volumes, Postgres, or administrative endpoints.

Failure to establish identity separation blocks all pairing and startup.

## 4. Materialize and inspect the Compose proposal

The tracked Compose file is deliberately non-deployable. Copy it into the
approved disposable workspace. Replace its image, command, and configuration
placeholders only after checking the OneCLI interface at the locked source
revision. Generate unique Postgres values and an encryption key outside this
repository; never persist them in source control, shell history, evidence, or
agent-readable files.

Before starting anything:

- [ ] Select the manifest matching the runtime platform: only `linux/amd64` or
  `linux/arm64` is locked.
- [ ] Pin each image as `<approved-repository>@sha256:<platform-manifest>`.
  Do not use a mutable tag or only the multi-platform index for execution.
- [ ] Render the Compose model with the approved environment using `docker
  compose config`; store only a redacted copy.
- [ ] Inspect the rendered Compose ports. Postgres must have no host
  publication, dashboard target `10254` must not be published, and gateway
  target `10255` must be the only publication, exactly as
  `127.0.0.1:10255:10255/tcp`.
- [ ] Confirm Postgres attaches only to an `internal: true` network.
- [ ] Confirm no default credential, implicit environment value, host Docker
  socket, host path, or persistent database volume is present.
- [ ] Verify each resolved local image digest against the selected locked
  image digest before container start. Record repository, platform, expected
  digest, observed digest, and pass/fail; do not record environment values.

An image digest, platform, or rendered-port mismatch means stop and clean up.

## 5. Pair and start only inside the approved window

Follow the reviewed upstream pairing procedure for the exact candidate AAC
artifact; do not invent flags from this runbook.

1. Start the repository's local fake target API under a test-only identity. It
   must accept only a runtime-generated fake bearer sentinel and return its
   constant non-secret body.
2. Apply the external egress allow-list before OneCLI starts. Permit only the
   approved Bitwarden relay path and fake target path needed by the test.
3. Start Postgres and OneCLI under the separate runtime identity.
4. Pair candidate AAC only to the disposable Bitwarden account and disposable
   item.
5. Configure exactly one allow-listed gateway operation to the fake target API.
6. Re-check actual running port mappings and runtime image digests; compare
   them with the rendered Compose evidence.

Never pair a personal or company vault. Never broaden the target route to make
a failing test pass.

## 6. Required pass/fail tests

Use a fresh generated fake value for the run. Each check records only status,
timestamp, evidence ID, and redacted observations.

### Allowed call and non-disclosure

- [ ] The agent can call the single approved fake target API operation through
  the loopback gateway.
- [ ] The target observes the expected injected fake value.
- [ ] The agent receives only the constant non-secret response.
- [ ] Non-disclosure holds across response body/headers, stdout, stderr,
  process environment, command errors, browser surfaces, dashboard surfaces,
  Compose output, container output, Docker events, Postgres, and host logs.

### Boundary denial

- [ ] A different method, path, destination, port, and credential class each
  fail closed.
- [ ] Dashboard denial is proven from the agent identity: loopback port `10254`
  is not listening for the agent, and no alternate published mapping exists.
- [ ] Docker, container, volume, database, process, configuration, and gateway
  administration remain denied to the agent.
- [ ] Egress denial is proven against a controlled unapproved destination.
  The denied destination must receive neither a request nor credential data.
- [ ] A controlled redirect from the approved fake target to an unapproved
  destination is rejected without forwarding the authorization value.

### Logs, cache, restart, and revocation

- [ ] Search every approved log and diagnostic sink for the exact generated
  fake value and credential-shaped headers. Any match fails the test.
- [ ] Disconnect AAC and prove cache purge rather than waiting only for expiry.
- [ ] Reconnect with a fresh fake value, restart the gateway, and prove the old
  value cannot be used or recovered.
- [ ] Revoke access to the disposable item/account and prove subsequent calls
  fail closed and cached access is purged.
- [ ] Repeat purge checks after normal shutdown and an approved simulated
  abnormal termination.

Any disclosure, unexpected access, stale-value reuse, or ambiguous result
means stop and clean up. It does not establish compatibility.

## 7. Cleanup

Perform cleanup even after an early failure:

- [ ] Stop and remove disposable containers, networks, tmpfs state, and any
  test-only volumes created by the approved materialized configuration.
- [ ] Delete extracted candidate AAC files and downloaded archives according
  to the approved disposal process.
- [ ] Revoke pairing and delete the disposable item and disposable Bitwarden
  account.
- [ ] Remove generated environment files, keys, fake values, certificates (if
  separately approved), captures, and temporary configuration.
- [ ] Verify no test port, process, container, network, cache, log copy, or
  credential remains.
- [ ] Run the separate secret scan and publication review before retaining any
  redacted report.

## 8. Evidence checklist

Retain only redacted, non-secret evidence:

- [ ] approval record and test window
- [ ] operator, runtime identity, and agent identity IDs
- [ ] Docker-control denial result
- [ ] source/tag/checksum verification results
- [ ] candidate AAC checksum result
- [ ] selected platform and image digest comparisons
- [ ] redacted rendered Compose port/network inspection
- [ ] pairing status with opaque disposable evidence ID
- [ ] fake target allowed-call and non-disclosure results
- [ ] dashboard denial, egress denial, and redirect results
- [ ] log search, cache purge, restart, revocation, and termination results
- [ ] cleanup verification and disposable account deletion
- [ ] final compatibility status

Compatibility may move away from **unverified** only after every mandatory
check passes, cleanup is confirmed, and an authorized reviewer approves the
evidence. This offline repository does not make that transition.
