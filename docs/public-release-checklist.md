# Public release checklist

## Purpose

This checklist is the gate for changing repository visibility or publishing a
release. It is deliberately stricter than "the tests are green." Do not make
the repository public until every required item has an accountable answer.

## Repository content

- [ ] The working tree is clean and every intended change has a reviewed pull
      request or documented maintainer decision.
- [ ] The full test suite passes with generated fake values only.
- [ ] A separate secret scan covers current files, Git history, generated
      artifacts, documentation, issue/PR templates, and release attachments.
- [ ] A human publication review confirms that no vault references, private
      service inventories, customer/work data, raw host output, personal paths,
      account information, or live credentials are present.
- [ ] The README accurately says the project is experimental and names its
      non-goals.
- [ ] Every public upstream statement is checked against its linked primary
      source and uses correct project and trademark language.

## Legal and ownership

- [ ] The code owner confirms the copyright holder and the repository license.
- [ ] The selected license text is added at the repository root.
- [ ] Upstream attributions and notices are reviewed. If third-party source is
      copied or distributed, retain every license and notice required by that
      source.
- [ ] The project does not use an upstream name, logo, or mark in a way that
      implies endorsement, partnership, or certification.

## GitHub community health

- [ ] A README, contribution guide, code of conduct, security policy, support
      route, issue forms, and pull-request template are present and accurate.
- [ ] Immediately after public visibility is enabled, private vulnerability
      reporting is enabled, the report button is verified, and maintainers
      subscribe to security-alert notifications. GitHub does not allow this
      feature to be enabled while the repository is private.
- [ ] GitHub Discussions is enabled with Announcements, Ideas, Q&A, and
      Architecture categories.
- [ ] The initial label set is created and contributors know which surface to
      use for issues, pull requests, discussions, and security reports.
- [ ] The Buy Me a Coffee funding account declared in the funding file is still
      maintainer-controlled and its destination page has been verified.

## Repository protections

- [ ] Main is protected by a ruleset or branch-protection rule.
- [ ] Pull requests, CI, and resolved conversations are required before merge.
- [ ] Force pushes and branch deletion are blocked.
- [ ] Secret scanning alerts and push protection are enabled where available.
- [ ] Dependency alerts and automated updates are enabled when dependencies are
      introduced.
- [ ] CI has read-only default permissions and no credential secrets.

## First public release

- [ ] The version, changelog, release notes, support window, and limitations
      are consistent.
- [ ] The release is labelled experimental unless an independently reviewed
      threat model and live verification prove a narrower production claim.
- [ ] Maintainers have tested clone, test, and demo instructions from a clean
      machine or disposable environment.
- [ ] The release commit and tag are verified before publishing.
- [ ] The release announcement directs questions to Discussions and security
      findings to private vulnerability reporting.

## Funding setup

GitHub can show a Sponsor button when a maintainer-controlled funding file is
present on the default branch. It supports GitHub Sponsors, Buy Me a Coffee,
Patreon, and other platforms. Start with one option only:

- Choose **Buy Me a Coffee** for a simple, low-commitment tip jar.
- Choose **GitHub Sponsors** if you want the funding relationship to stay inside
  the open-source workflow.
- Choose **Patreon** only if you will provide recurring public updates or other
  ongoing supporter benefits.

The funding file declares the verified Buy Me a Coffee account. Do not add a
second funding platform unless it gives contributors a distinct, maintained
option.
