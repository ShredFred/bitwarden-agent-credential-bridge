# Architecture and repository boundaries

## Purpose

This document gives contributors a stable mental model for the project. It is
not a deployment guide and it does not authorize a live credential experiment.

**Two audiences, two doors:**

- Humans installing and running the Bridge start at the
  [README](../README.md) and [Features](features.md).
- Coding agents start at [agent-windows-install.md](agent-windows-install.md)
  and [AGENTS.md](../AGENTS.md).

This architecture note is for people changing the code. After reading it, a
contributor should be able to decide whether a proposed change belongs in the
public research harness, in private planning, or outside the project entirely.

## Boundary model

The project explores a narrow credential-use contract:

1. A caller asks for an allowed request without providing a credential.
2. A broker validates an exact policy and removes caller-supplied
   credential/protocol headers.
3. The broker injects one runtime-only fake value at the configured outbound
   boundary.
4. The upstream response is bounded and screened before a sanitized result is
   returned to the caller.
5. Tests fail if a generated fake value or its deterministic representations
   reach an agent-readable surface.

The caller, broker, policy, and upstream service are separate roles. A policy is
an allow-list, not a template language. Runtime fake values are inputs, not
configuration.

## Layers of the public project

| Layer | Responsibility | Must not contain |
| --- | --- | --- |
| Contracts | Exact input schemas, policy validation, stable failure behavior | Real values, broad template substitution, implicit defaults |
| Harness | Fake loopback service, broker, demo, and exposure checks | Live vaults, real accounts, production endpoints |
| Platform research | Pure plans, evidence evaluators, and disposable-boundary experiments | Authorization claims beyond available evidence |
| Native scaffolds | Narrow OS-specific proof code that is independently testable | General command execution, network access, credential access |
| Evidence | Pinned public upstream metadata and reproducible offline checks | Private inventories, logs, user names, tokens, or service identifiers |
| Documentation | Scope, threat boundaries, release process, and contributor guidance | Unreviewed security claims or private operational detail |

## Public, private, and local separation

The safest long-term organization is three distinct places with different
permissions and audiences.

This does **not** mean creating three repositories today. Start with the current
repository as the only development repository. It stays private until the public
release checklist passes, then the same repository becomes public. Do not copy,
fork, or split the source history merely to change visibility.

| Place | What belongs there | What never belongs there |
| --- | --- | --- |
| Public source repository | Reviewable code, fake fixtures, synthetic tests, documentation, public upstream references, and release notes | Credentials, vault exports, local configuration, customer/work data, raw security reports |
| Private planning space | Sanitized roadmap notes, maintainer decisions, risk register, release drafts, and non-sensitive operational checklists | A backup for secrets, real vault identifiers, raw host output, personal service inventories |
| Per-user local configuration | Only a future explicitly approved machine-local configuration, owned by that user and excluded from Git | Any material intended for review, sharing, CI, or source control |

The private planning space is not a secret store. If a future local configuration
contains a reference that could help locate a secret, do not commit it even to a
private repository.

## Practical setup

Use this sequence:

1. **Now:** keep the current repository private and continue all source, test,
   documentation, and release-preparation work here. There is no second
   repository and no local credential configuration to create.
2. **At public release:** run the publication review, make this same repository
   public, then immediately enable GitHub private vulnerability reporting and
   verify the reporting button. The public repository remains the canonical
   source for issues, pull requests, discussions, and releases.
3. **Only if needed later:** create one separate private planning repository for
   sanitized maintainer material that must not be public, such as roadmap drafts,
   non-sensitive decision records, and release planning. Do not mirror source
   code or use it to bypass public review.
4. **Only after a later explicit live gate:** create the per-user local
   configuration defined by the runtime. It is a normal ignored local directory,
   not a Git repository, not a cloud-synced folder, and never a backup of a
   vault. It must not exist until the corresponding implementation and approval
   gate actually exist.

The existing ignored local broker area is reserved for that fourth step. It is
not a place to put a real value now.

## Repository evolution

Keep the public codebase organized by responsibility, not by a growing list of
phases. Existing phase documents are valuable historical evidence, but new work
should keep these surfaces recognizable:

- Core policy and wire contracts.
- Fake broker and fake upstream harness.
- Platform-specific boundary adapters and native code.
- Test fixtures plus behavior and exposure tests.
- Public policies, supply-chain evidence, and non-deployable examples.
- Human-facing documentation and GitHub community files.

When an experimental phase becomes a stable capability, give it a
responsibility-based home, public API contract, tests, and a migration note.
Avoid moving files solely for cosmetic consistency; preserve auditability and
use small, reviewable refactors.

## Design invariants

Every public change should preserve these invariants:

- Real credentials are never requested, read, logged, stored, or used in tests.
- Unsupported credential classes and ambiguous inputs fail closed.
- A caller cannot choose arbitrary headers, targets, commands, paths, identity
  evidence, or mutation scope.
- A synthetic pass cannot become a claim of live authorization or production
  safety.
- Platform-specific evidence is value-free and exposes only the minimum facts
  required by the contract.
- Mutation is separate from planning, inspection, verification, and approval.
- A future production boundary needs a genuinely different writer identity or
  equivalent isolation; same-user restrictions alone are not sufficient.

## Decision rule for new work

Open a discussion first when a proposal changes a threat boundary, supported
credential class, policy language, compatibility promise, or user-visible
security claim. Open an issue when the desired behavior is already agreed and
can be tested. Use a pull request only when an issue or discussion provides a
clear scope and acceptance criteria.
