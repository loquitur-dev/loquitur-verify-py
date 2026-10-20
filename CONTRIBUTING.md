# Contributing to loquitur-verify-py

**Role:** Standalone verifier package  
**Status:** preview contributor guide of a package for offline bundle verification.

## Contribution discipline

Contributions should be small, reviewable, and limited to this repository's owned surface. Do not
use this repository to introduce runtime behavior another repository owns, private evidence
material, unrelated package code, or undocumented public claims.

A good contribution states:

1. what repository-owned surface changes;
2. whether any public claim changes;
3. what public/private boundary risk was considered;
4. what checks were run;
5. what remains unverified.

## Boundary rules

Do not add:

- private evidence bundles;
- real issuer material, or third-party material other than test data whose license permits
  redistribution and which NOTICE credits (as it credits the Wycheproof vectors);
- credentials, tokens, headers, cookies, API keys, or private URLs;
- unsupported production-readiness, compliance, audit, legal-truth, chain-finality, or
  valuation-correctness claims;
- code, routes or runtime internals that another repository owns.

## Local checks and maintainer documentation

The maintainer documentation is under [`docs/maintainers/`](docs/maintainers/):

- [`testing.md`](docs/maintainers/testing.md): how to run the full suite, the coverage gate and
  the wheel gate, with the sibling repositories the cross-repository tests read;
- [`build-checks.md`](docs/maintainers/build-checks.md): the checks that build the
  release artifacts and check what was built;
- [`releasing.md`](docs/maintainers/releasing.md): the tag rules, the release workflow and how a
  release is checked;
- [`TEST_OWNERSHIP.md`](docs/maintainers/TEST_OWNERSHIP.md) and
  [`DOCS_OWNERSHIP.md`](docs/maintainers/DOCS_OWNERSHIP.md): what this repository's tests and
  documents own;
- [`REPOSITORY_LAYOUT.md`](docs/maintainers/REPOSITORY_LAYOUT.md): the layout of this repository
  and of the sibling checkouts;
- [`public-private-boundary.md`](docs/maintainers/public-private-boundary.md): what this package
  must not be described as proving.

## Contributions during the preview

External contributions start with an issue. A pull request is welcome under the Developer
Certificate of Origin when it is tied to an issue the maintainer has accepted. A normative
change to the protocol goes through the LCP change-proposal register of `loquitur-protocol`,
`docs/change-proposals.md`.

## Developer Certificate of Origin

Contributions are made under the Developer Certificate of Origin 1.1
(https://developercertificate.org/). Every commit, the maintainer's own included, carries a
sign-off line whose name and address match the commit's author, and CI checks every commit of
a push or pull request for it. `git commit -s` adds the line:

```
Signed-off-by: Your Name <your.email@example.com>
```

The sign-off certifies that the contributor wrote the change or otherwise has the right to
submit it under the licenses of this repository. There is no separate contributor agreement.

## License

This repository is licensed under either of the Apache License, Version 2.0
([`LICENSE-APACHE`](LICENSE-APACHE)) or the MIT License ([`LICENSE-MIT`](LICENSE-MIT)), at your
option. The third-party Wycheproof test-vector file under `tests/vectors/` keeps its own license,
the Apache License, Version 2.0 only, as `NOTICE` states.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this repository, as defined in the Apache License, Version 2.0, is dual licensed as above, without
any additional terms or conditions. Every contribution carries the sign-off described in
[Developer Certificate of Origin](#developer-certificate-of-origin).
