# Changelog

All notable changes to `loquitur-verify` are documented in this file.
The format follows Keep a Changelog conventions; the project targets
semantic versioning once the public API stabilizes.

## [0.1.0] - 2026-10-20

First release of `loquitur-verify`, the offline verifier for Loquitur evidence bundles, as a
preview.

### Added
- Offline verification of a bundle given as a directory or a ZIP archive, the `structure` and
  `integrity` checks: archive safety, bundle root discovery, the closed contracts of the
  manifest, P1 and envelope, their self-describing `sha256:` digests under the RFC 8785
  canonical JSON profile, and the local links between them. Input is read as I-JSON.
- The `link` check with `--registry-entry`, and the `authorization` check with
  `--trust-registry`: the issuer's key, judged at the operator's `--evaluation-time`, and the
  entry's signature; `--trust-root` authenticates the trust registry against a root key
  supplied out of band. Without an evaluation time, authorization is not established.
- One public key under two labels is an ambiguous key: authorization stops with
  `TRUST_REGISTRY_AMBIGUOUS_KEY` when the trust entry found shares its secp256k1 point with
  another trust entry of the registry, and root authentication with `AMBIGUOUS_ROOT_KEY` when
  the matched root shares its point with another pinned root, in any SEC1 encoding and
  whatever the statuses, issuers and key types.
- Version gates on every versioned object, with the outcome `UNSUPPORTED_VERSION`.
- Signing Envelope v2 verification, with a closed allowlist of signature algorithm and key
  type pairs chosen by the verifier.
- The report of loquitur-protocol `docs/specification/report-contract.md`, as JSON or as
  readable text, with the checks requested and established, the review reasons and one exit
  code per outcome; `--accept-review` exits 0 for an `OFFLINE_REVIEW` run whose every review
  reason it names, and leaves the report unchanged.
- Opt-in verdict narrative for technical, compliance and executive readers
  (`--narrative`), with the `narrative` extra.
- `verify_path` in `loquitur.verify.runner`, the call the command line makes, for use as a
  library.
