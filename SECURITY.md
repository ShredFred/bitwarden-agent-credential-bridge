# Security policy

## Scope

Agent Credential Bridge is experimental software. Automated tests and CI use
generated fake values only. An operator may unlock a local Bitwarden Secrets
Manager machine token behind an explicit approval flag; those secrets still
must never appear in git, issues, pull requests, discussions, tests, logs, or
agent-readable surfaces.

Do not treat this project as a production password manager or as authorization
evidence. A potential vulnerability can still affect the project's safety
claims, so please report it privately.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

https://github.com/ShredFred/bitwarden-agent-credential-bridge/security/advisories/new

Do not create a public issue, pull request, or discussion for a suspected
vulnerability. Do not include a real credential, token, vault reference, account
identifier, private endpoint, or raw host output in any report.

Do not disclose exploit details publicly.

## What to include

- A concise description of the affected contract or boundary.
- Reproduction steps using fake data only.
- Expected and observed behavior.
- The affected version or commit.
- Potential impact and any safe mitigation you identified.

## What to expect

The maintainer will acknowledge a valid report, assess reproducibility and
scope, coordinate a fix privately where possible, and publish a sanitized
advisory after users have a reasonable opportunity to update. Response timing
depends on maintainer availability; no SLA is promised for this experimental
project.

## Supported versions

Only the latest published experimental release receives security triage. Older
pre-release versions may be closed with upgrade guidance.
