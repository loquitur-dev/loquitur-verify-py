# Testing

Run these checks from the `loquitur-verify-py` repository root. The full suite, with the narrative
tests that read the reason-code catalog, needs the sibling `loquitur-schemas` package installed
first:

```bash
python -m pip install -e ../loquitur-schemas
python -m pip install -e ".[dev]"
python -m pytest -q
loquitur-verify --help
loquitur-verify --version
```

Without `loquitur-schemas`, the base verifier still installs and runs with
`python -m pip install -e ".[dev]"`; the narrative tests skip.

The suite also reads two sibling checkouts when they sit beside this one: `loquitur-protocol`,
whose specification documents and conformance material the cross-repository tests compare this
verifier with, and `loquitur-verify-ts`, for the cross-language locks. Without them those tests
skip, and each skip names the missing checkout. With `LOQUITUR_REQUIRE_SIBLINGS=1` in the
environment, a missing sibling fails the run instead. [`REPOSITORY_LAYOUT.md`](REPOSITORY_LAYOUT.md)
shows the sibling layout.

## The README's commands

`tests/test_readme_quickstart.py` reads every `loquitur-verify` command out of the README, runs
it, and compares its result with the `Expected result` block that follows it; it also runs the
Python API example and compares what it prints with the line the README states after it. A README
that drifts from the verifier fails the suite. The same module holds the include markers the
documentation site reads: each region opens one blank line under its `## ` heading and ends before
the next one, its id is a name every package README shares or its heading's anchor, the ids are a
fixed set, and a region holds no link to an anchor of the README itself, since the site page that
includes the region does not carry that anchor.

The authorization runs read `tests/fixtures/authorization_quickstart_trust_registry.json` and
`tests/fixtures/authorization_quickstart_trust_root.json`. `tools/sign_quickstart_trust_fixtures.py`
writes both, with a new trust root each time it runs; run it again when
`authorization_valid_trust_registry.json` changes.

## Coverage and the installed wheel

```bash
python -m coverage run -m pytest -q
python -m coverage report --fail-under=85
python tools/local_wheel_gate.py
```

The wheel gate builds a temporary `loquitur_verify-*.whl`, installs it into a temporary virtual
environment, and runs the installed `loquitur-verify` console script over the golden fixtures: the
integrity check on `tests/fixtures/valid_bundle.zip`, then the link check and the authorization
check on `tests/fixtures/link_valid_bundle.zip` with a registry entry and a trust registry from the
same folder. The authorization run must exit `2`, `OFFLINE_REVIEW`, because no trust root is pinned.
It does not write to `dist/` unless an explicit `--dist-dir` is
provided. In an offline environment where `rfc8785` is already available from the system site
packages, run it as:

```bash
python tools/local_wheel_gate.py --system-site-packages --no-deps
```

The checks that build and check the release artifacts are in
[`build-checks.md`](build-checks.md).

The repository must remain runnable as a standalone repository. Any dependency on a sibling
repository must be explicit in the command or the documentation, never implicit through a path
outside this repository. [`TEST_OWNERSHIP.md`](TEST_OWNERSHIP.md) states what this repository's
tests own.
