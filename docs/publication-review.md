# Publication review (2026-08-31)

Accountable answers for
[public-release-checklist.md](public-release-checklist.md). This is a
maintainer review, not a claim that production isolation is proven.

## Repository content

| Item | Result |
| --- | --- |
| Working tree / reviewed PR | Landed on `develop`, merged to `main` via PR before visibility change |
| Fake-only tests | `npm run test:ci` on this cutover |
| Secret scan | Current tree + git pickaxe: no PEM private keys, no `ghp_` / `github_pat_`, no `AKIA`, no `BWS_ACCESS_TOKEN=` assignments, no live SM token shape (`0.<uuid>.<payload>`). Fake sentinels (`0.fake-…`) only. |
| Human publication review | Host-specific paths removed from docs (`F:\Github Repos\…`, per-laptop machine ids). Reverse-DNS helper labels (`de.frederikstadler.…`) and sample SM **project UUIDs** remain: they are identifiers, not credentials, and do not unlock a vault. The operational import manifest lists **basenames/key names only**. |
| README non-goals | Experimental; not affiliated with Bitwarden; not a production password manager |
| Trademark language | README and licensing docs deny endorsement |

**Accepted residual identifiers (not secrets):**

- Maintainer reverse-DNS in the macOS helper research ladder
- Sample Bitwarden SM project UUIDs in `samples/operational/` and defaults (allowlist identifiers)
- Pinned disposable Bitwarden account digest comparison in Phase 7/13 tests (email is a fixture, never logged)
- Buy Me a Coffee handle `shredfred`

Git history is not rewritten. Scan found no live credential values. Do not treat identifier presence as token presence.

## Legal

- License: Apache-2.0 at repository root
- No upstream Bitwarden source is shipped; research references only
- Product name does not claim Bitwarden endorsement

## Community health (cutover sequence)

1. Merge this review to `main`
2. Set repository visibility to **public**
3. Enable Discussions (Announcements, Ideas, Q&A, Architecture)
4. Enable private vulnerability reporting and verify the Security Advisories button
5. Enable secret scanning + push protection
6. Protect `main` (PR required, CI required, no force-push)

GitHub branch rulesets are unavailable on a free-plan **private** repo; they
are applied immediately after the visibility change.

## Cutover status (2026-08-31)

Completed after `main` received the review commit:

- Repository visibility: **public**
- Discussions: enabled (default categories include Announcements, Ideas, Q&A)
- Private vulnerability reporting: **enabled**
- Secret scanning + push protection: **enabled**
- `main` branch protection: PRs, required CI (`Test on ubuntu-latest`,
  `Test on windows-latest`), conversation resolution, no force-push, no
  branch deletion
- Extra labels: `security`, `research`, `windows`, `macos`, `linux`

Rename the default Discussions category **Show and tell** to **Architecture**
in the GitHub UI if you want that name exactly. GraphQL category mutations
are not available on this token.
