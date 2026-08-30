# Licensing and upstream use

## Recommendation

Agent Credential Bridge uses the Apache License, Version 2.0 (Apache-2.0) for
the repository's own code.

This is an engineering recommendation, not legal advice.

## Why Apache-2.0 fits

- OneCLI publishes its source under Apache-2.0.
- Bitwarden Agent Access publishes its source under Apache-2.0.
- Apache-2.0 is permissive, allows commercial and non-commercial reuse, and
  includes an express patent license plus a patent-retaliation clause.
- It sets clear contribution and notice expectations without making this
  repository a copyleft project.

This repository currently records public upstream metadata and uses no direct
runtime package dependency on OneCLI or Bitwarden Agent Access. Referencing or
interoperating with an Apache-2.0 project does not by itself force this project
to use the same license. Apache-2.0 is still the cleanest choice here because it
aligns with those upstreams and reduces future license friction if a small,
properly attributed derivative component is ever needed.

## Obligations to keep in mind

If the project copies, modifies, or distributes Apache-2.0 source or files in
the future, it must retain applicable copyright, patent, trademark, and
attribution notices, include the Apache-2.0 license text, mark modified files,
and carry any applicable NOTICE-file attribution. Review the exact upstream
license and NOTICE files at that time.

Do not copy product logos or use Bitwarden, OneCLI, or other upstream names in a
way that suggests sponsorship, certification, partnership, or endorsement.
Factual compatibility and research references should be precise and attributed.
Public naming rules: [Trademark](trademark.md).

## Release decision

Before public visibility, the maintainer must make and record these decisions:

1. The legal copyright holder and ownership record for the repository.
2. Whether a NOTICE file is required by any copied or distributed upstream work.
3. The support statement and the exact limits of any compatibility claim.

Do not publish without a license. Without one, others generally do not have
clear permission to use, modify, or distribute the project.
