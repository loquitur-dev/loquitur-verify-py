# Documentation ownership

This repository owns documentation for the standalone `loquitur-verify` package.

It may document:

- offline verifier installation and CLI usage;
- local verification modes supported by this package;
- verifier input/output behavior;
- verifier package tests and release checks;
- what local verification does and does not establish.

It must not document the runtime of another repository, third-party material, or the implementation
history of any repository. The one exception is the provenance of third-party test data the package
ships, which NOTICE and `tests/vectors/README.md` record.

Runnable checks are documented in [`testing.md`](testing.md) and
[`build-checks.md`](build-checks.md); the release workflow and how a release is checked,
in [`releasing.md`](releasing.md).
