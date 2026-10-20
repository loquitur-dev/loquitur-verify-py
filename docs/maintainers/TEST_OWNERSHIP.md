# Test ownership

This repository owns tests for its own published surface only. It must not rely on the layout
of any other repository for test ownership.

## What this repository owns

- offline verification tests;
- link verification tests;
- receipt and bundle verification tests that verifier semantics own;
- CLI tests;
- package build and wheel-gate tests;
- release workflow tests.

## What this repository does not own

- schema package internals;
- tests of any surface another repository owns.

## Local check commands

```bash
python -m pip install -e ../loquitur-schemas
python -m pip install -e ".[dev]"
python -m pytest -q
python -m build
```

## Dependencies on other repositories

Sibling repositories may be installed or referenced for integration checks, but this repository
remains the owner of only the surfaces listed above. Test migrations from another repository
must preserve public/private boundary discipline and must not introduce production, audit,
SOC 2, legal truth, valuation correctness, compliance, chain finality, or oracle claims.
