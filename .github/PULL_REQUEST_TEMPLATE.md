## Summary

<!-- What changes, and why? Link the issue or discussion. -->

Closes #

## Security boundary review

- [ ] This change uses generated fake values only.
- [ ] This change does not add a real vault, credential, token, private service, or raw host output.
- [ ] Unsupported or ambiguous inputs still fail closed.
- [ ] I considered caller-visible responses, logs, errors, headers, files, and environment as exposure surfaces.
- [ ] I updated the threat-boundary documentation if the public contract changed.

## Verification

- [ ] I added or updated tests for the intended behavior.
- [ ] I added or updated exposure tests where appropriate.
- [ ] npm test passes locally.
- [ ] Documentation and changelog entries are accurate.

## Reviewer notes

<!-- Call out contract changes, limitations, migration needs, or questions. -->
