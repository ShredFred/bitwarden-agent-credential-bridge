# Development and releases

## Goal

This project should be easy to understand, hard to misuse, and calm to maintain.
The public GitHub repository is the source of truth for reviewable code and
decisions. Private planning is separate, sanitized, and never a place for
credentials.

Humans installing the Bridge: [README](../README.md) and [Features](features.md).
Agents: [agent-windows-install.md](agent-windows-install.md).
This document is the maintainer workflow.

## The everyday workflow

1. Start with a discussion if the idea changes a security boundary, scope, or
   public contract. Use an issue for an already agreed, bounded task.
2. Create a short-lived branch for the issue. Do not work directly on main.
3. Make the smallest change that proves the behavior. Add or adjust tests at the
   same time.
4. Open a pull request early, as a draft if the design is still being tested.
5. Review the exact threat-boundary impact, test results, documentation, and
   release-note need before merging.
6. Merge only after required checks pass and every unresolved conversation is
   addressed.

Even as a solo maintainer, using your own pull requests is worthwhile: it
creates a review record, makes CI visible, and gives you a pause before changing
a security-sensitive boundary.

## What belongs where on GitHub

| Tool | Use it for | Do not use it for |
| --- | --- | --- |
| Issues | Reproducible bugs, scoped features, testable chores | Vulnerabilities, secrets, open-ended design debates |
| Pull requests | Code and docs ready for review | Raw research notes or an unscoped idea |
| Discussions | Architecture proposals, Q&A, roadmap feedback, and early experiments | Sensitive reports or decisions that need a testable implementation |
| Private vulnerability reporting | Potential security vulnerabilities | General support or feature requests |
| Releases | Reviewed versions, release notes, upgrade notes, and integrity artifacts | A substitute for a branch or pull-request review |

Turn on GitHub Discussions when the repository becomes public. Begin with
categories for Announcements, Ideas, Q&A, and Architecture. Convert an agreed
discussion into an issue so implementation work has a bounded record.

## Labels to create

Start small and apply one label from each relevant group:

| Group | Initial labels |
| --- | --- |
| Type | `bug`, `feature`, `documentation`, `question`, `maintenance` |
| Security | `security-boundary`, `needs-threat-model`, `safe-to-discuss-publicly` |
| State | `needs-triage`, `needs-design`, `ready-for-pr`, `blocked` |
| Contribution | `good first issue`, `help wanted` |
| Scope | `contracts`, `harness`, `platform`, `native`, `release` |

Only mark something `good first issue` after its acceptance criteria are clear
and it cannot accidentally expand a security boundary.

## Branch and merge policy

Before public visibility, protect main with a GitHub ruleset or branch-protection
rule:

- Require a pull request before merge.
- Require the CI test check to pass.
- Require resolved conversations.
- Block force pushes and branch deletion.
- Require linear history if you prefer a clean release history.
- Do not allow an administrator bypass for changes that affect policies,
  platform boundaries, native helpers, or security documentation.

For a solo project, one approving review cannot be independent. Treat your own
review as a structured pause and obtain an external review for changes that add
a credential class, change a security invariant, add a privileged platform
operation, or change the public threat model.

## Versioning policy

Use Semantic Versioning with an intentionally conservative `0.x` line.

| Change | Version action |
| --- | --- |
| Documentation, CI, test-only correction, or compatible bug fix | Patch release, for example `0.1.1` |
| New experimental contract, supported policy shape, or incompatible `0.x` behavior | Minor release, for example `0.2.0` |
| Stable, independently reviewed public product contract | First `1.0.0` release only after an explicit maintainer decision |

Do not publish a version merely because a large amount of code was written. A
release needs a tested commit, a changelog entry, known limitations, and a clear
statement of whether it is experimental.

## Release process

1. Freeze the intended scope and link every included pull request or issue.
2. Run the full test suite on supported platforms and record only value-free
   results.
3. Perform the separate secret scan and publication review described in the
   public release checklist.
4. Update the version, changelog, README status, compatibility notes, and
   supported-version table.
5. Create an annotated tag and GitHub release from the reviewed commit.
6. Attach checksums or provenance only after they are reproducibly generated and
   independently reviewed.
7. Announce the release in GitHub Discussions and watch issues/security reports.

The first public repository release should be clearly marked **experimental**.
Do not call it production-ready, security-certified, or Bitwarden-compatible
unless independently verified evidence supports that exact claim.

## Public and private operating model

- The public repository hosts code, public decisions, synthetic tests, and
  release artifacts.
- A private planning space holds only sanitized maintainership notes and draft
  decisions.
- Machine-local configuration is outside Git and must not be copied into either
  space.
- CI receives no credentials. It must run the fake harness with generated values
  only.
- Any sensitive report starts with private vulnerability reporting, not an issue,
  pull request, or discussion.

## Minimum GitHub configuration before launch

Enable CI, protected main, private vulnerability reporting, secret scanning
alerts, push protection, Dependabot alerts/updates when dependencies are added,
and Discussions. Configure notifications for security alerts. Use the public
release checklist as the authoritative pre-launch sequence.
