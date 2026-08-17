# GitHub launch settings

Use this page when the public release checklist is otherwise complete. These are
copy-ready repository settings, not commands to run before approval.

## Repository description

> Agents can use Bitwarden Secrets Manager without seeing the secrets. Fail-closed brokers, Windows installer, experimental research harness. Not affiliated with Bitwarden.

This description sells the operator-visible product without claiming
production writer isolation, Bitwarden endorsement, or `authorization_ready`.

## Suggested topics

Add only topics that are true today:

- `security-research`
- `ai-agents`
- `credential-security`
- `secret-management`
- `nodejs`
- `security-testing`
- `fail-closed`
- `developer-tools`
- `windows`

Do not add `onecli`, `production-ready`, `password-manager`, or `mcp` merely
for discoverability. Do not add `bitwarden` as a topic: the project integrates
with Secrets Manager that *you* bring, and is not an official Bitwarden
product.

## About panel

| Setting | Launch value |
| --- | --- |
| Website | Leave blank until there is a maintained public documentation or project site. |
| Releases | Enabled. The first release remains explicitly experimental. |
| Packages | Disabled unless an audited distribution plan exists. |
| Wiki | Disabled initially. Keep canonical documentation reviewable in the repository. |
| Discussions | Enabled with Announcements, Ideas, Q&A, and Architecture categories. |
| Sponsorships | Enabled with the maintainer-controlled Buy Me a Coffee account already declared in the funding file. |

Keep the package manifest private until there is a separate npm publication plan.
Making a GitHub repository public does not require publishing a package.

## Security and automation

- Enable private vulnerability reporting and subscribe maintainers to security
  alerts.
- Enable secret scanning alerts and push protection where available.
- Enable dependency alerts and automated updates when a dependency is added.
- Require the CI workflow before merge and give it read-only default
  permissions.
- Do not add repository secrets to CI for the fake-only test suite.

## Initial community setup

1. Create the label set in the development-and-releases guide.
2. Post one pinned Discussion: welcome, scope, security-reporting route, and
   where to ask questions.
3. Post one pinned Discussion: public roadmap and how an idea becomes an issue.
4. Confirm every contact link and funding link as the maintainer before enabling
   them.
