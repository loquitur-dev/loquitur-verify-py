# Release build checks

These checks build the package from this source tree and check what was built. Run them from the
`loquitur-verify-py` repository root, in a clean virtual environment:

```bash
python -m pip install -e ../loquitur-schemas
python -m pip install -e ".[dev]"
python -m pytest -q
python -m coverage run -m pytest -q
python -m coverage report --fail-under=85
python tools/local_wheel_gate.py --check-reproducible
rm -rf build dist src/*.egg-info
SOURCE_DATE_EPOCH=1700000000 PYTHONHASHSEED=0 python -m build
python tools/local_wheel_gate.py
python tools/local_wheel_gate.py --check-dist dist
```

The build backend is pinned to one setuptools version in `pyproject.toml`, so every build
runs the same backend, and `wheel` is not a build requirement: setuptools builds wheels itself.
`--check-reproducible` builds the wheel twice with `SOURCE_DATE_EPOCH` fixed to
`REPRODUCIBLE_EPOCH` in `tools/local_wheel_gate.py` (1700000000) and requires the two to be
byte-identical; it prints `wheel_reproducible_ok sha256=...`. That proves the wheel can be
rebuilt to the same bytes. It proves nothing about a wheel built another way, which is why
the build line above fixes the same two variables: `python -m build` without them stamps the
current time into every archive entry and yields a different digest on every run. The digest
of `dist/loquitur_verify-0.1.0-py3-none-any.whl` built by the line above equals the one
`--check-reproducible` printed; built without the two variables, it differs.

The sdist is not covered: two builds with both variables set do not give the same `.tar.gz`
digest, so no reproducibility claim is made for it; the `--check-dist` step still compares its
contents with `src/` and runs its tests.

`tools/local_wheel_gate.py` builds the wheel, installs it into a temporary environment, and runs
smoke checks of the installed command line for the `structure` and `integrity` checks, the `link`
check of a registry entry supplied locally, and the `authorization` check of the entry's signature
and of the issuer key's authorization. It does not verify trust-registry root authenticity, registry
inclusion, checkpoint consistency, chain anchors or their finality, legal identity, compliance
correctness, or valuation correctness.

`twine check` is the last of these checks, and it is not enough on its own: it renders the long
description and nothing else. It passes a wheel built from stale bytes, and it passes a
wheel carrying a module that exists only in an uncleaned `build/lib`. The `--check-dist`
step above is what compares the artifacts to `src/` and refuses a `dist/` holding anything
else.

```bash
python -m pip install twine
python -m twine check dist/*
```

`twine` belongs to no extra of this package, which is why the commands above install it. If
`rfc8785`, `build` or `twine` cannot be installed in the environment, the clean-environment
check has not run: record the missing dependency rather than introducing a permissive verifier
fallback or a broad skip.

The coverage report and `twine check` run only when these commands are run by hand: no workflow
runs either of them. The CI workflow runs the suite, the wheel gate and the `--check-dist` step,
and the release workflow runs `--check-reproducible` and `--check-dist` on the files it attests.

How a version tag is built, summed and attested by `.github/workflows/release.yml`, and how
the result is checked, is in [`releasing.md`](releasing.md).

The structure, integrity, link and authorization checks remain local and read only the material
supplied. Passing these checks does not prove trust-registry root authenticity, registry inclusion,
checkpoint consistency or anchor finality, and it does not imply production readiness, registry
finality verification, legal truth, valuation correctness, regulatory compliance, external audit
status, or oracle behavior.
