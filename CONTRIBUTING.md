# Contributing to Agent Credential Bridge

Thank you for considering a contribution. This is a security research harness,
so clarity and restraint matter more than feature count.

## Before you start

- Read the README, architecture document, security policy, and code of conduct.
- Never include a real credential, vault export, token, cookie, recovery code,
  private service inventory, or raw machine output in a commit, issue, pull
  request, discussion, test, or log.
- Use generated fake values only. If a contribution needs a real vault or live
  service to demonstrate value, it is outside the current public scope.
- Do not open a public issue for a potential vulnerability. Use private
  vulnerability reporting as described in SECURITY.md.

## Choose the right place

- Use a **Discussion** for a security-boundary proposal, a new credential class,
  a public API change, or an early research idea.
- Use an **Issue** for a reproducible bug or a change with agreed acceptance
  criteria.
- Open a **Pull Request** only when the work is scoped, tested, and ready for
  review. Draft pull requests are welcome for early implementation feedback.

## Pull request expectations

Each pull request should:

1. Explain the problem and link its issue or discussion.
2. Keep the change narrow and avoid unrelated formatting or refactors.
3. Preserve the fake-only, fail-closed, value-free invariants.
4. Add or update behavior and exposure tests.
5. Run the full test suite locally and state the result without pasting sensitive
   output.
6. Update documentation, compatibility notes, and release notes where relevant.

Changes to a credential contract, policy language, platform identity boundary,
native helper, or public security claim need explicit threat-model discussion and
maintainer approval before merge.

## Development principles

- Prefer standard-library code and pinned, auditable tools.
- Reject unsupported input; never silently broaden access or fall back to general
  process-environment injection.
- Keep real host mutation behind a separately approved, disposable, verifiable
  gate.
- Treat logs, errors, response bodies, response headers, files, and tool output
  as exposure surfaces.
- Write tests that prove both the intended outcome and the absence of sensitive
  data on agent-readable surfaces.

## Review and merge

All changes go through a pull request. Maintainers may ask for a smaller scope,
additional tests, or a public design discussion before review. Passing CI is a
minimum requirement, not a substitute for a security review.

By submitting a contribution, you agree that it may be distributed under the
Apache-2.0 repository license.
