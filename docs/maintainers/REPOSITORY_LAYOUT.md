# Repository layout

`loquitur-verify-py` is the standalone offline verifier package repository. It is not a server
implementation, not a registry service, not a valuation engine, not a compliance or KYC tool, and
not a document repository.

```text
loquitur-verify-py/
├─ .github/workflows/           # ci.yml: the checks of every push and pull request;
│                               # release.yml: the release build from a version tag
├─ .github/dependabot.yml       # weekly updates of the actions the workflows use
├─ src/loquitur/verify/        # verifier package source
├─ tests/                       # verifier contract/fixture tests
├─ tools/                       # wheel gate, public-boundary and verdict-path isolation checks,
│                               # conformance adapter, schema-contract generator, quickstart signer,
│                               # golden narrative builder
├─ docs/outcome-categories.md   # the report members that belong to this verifier
├─ docs/maintainers/            # maintainer documentation: testing, build checks,
│                               # releasing, ownership and layout
├─ pyproject.toml  MANIFEST.in  # the build; what the source distribution ships
├─ .gitignore  .gitattributes   # ignored files; byte-exact line endings for the files the protocol hashes
├─ README.md  CHANGELOG.md  SECURITY.md  CONTRIBUTING.md
├─ GOVERNANCE.md  CODE_OF_CONDUCT.md  LICENSE-APACHE  LICENSE-MIT  NOTICE
└─ CONFORMANCE_CONSUMER.json  RELEASE_SET_POINTER.json
```

Expected sibling workspace for local development:

```text
LoquiturWorkspace/
├─ loquitur-protocol/
├─ loquitur-schemas/
├─ loquitur-verify-py/
└─ loquitur-verify-ts/
```

The siblings are optional. `loquitur-verify` installs and runs every check with `rfc8785` and
`cryptography` as its dependencies; `loquitur-schemas` is needed for the `narrative` extra and for
the differential tests, `loquitur-protocol` for the tests that read its specification and
conformance material, and `loquitur-verify-ts` for the cross-language locks. A missing sibling makes
its tests skip rather than fail.

Install order:

```bash
python -m pip install -e ../loquitur-schemas
python -m pip install -e ".[dev]"
```

The verifier consumes `loquitur-schemas>=0.1.0,<0.2.0` for the `narrative` extra and for
development.
