# Security policy

**Repository:** `loquitur-verify-py`  
**Role:** Standalone verifier package  
**Status:** preview security policy of a package for offline bundle verification.

No independent cryptographic review of this protocol or its reference verifiers has been done yet.

## Scope

This repository holds the Python verifier: the package `loquitur.verify` under `src/`, its
command line `loquitur-verify`, the build of its wheel and source distribution, and its test
fixtures. Report security issues that affect that surface, including:

- a verdict, status or exit code the specification does not give for the input, and any case
  where a report claims a guarantee the code does not deliver;
- input a bundle, a registry entry, a trust registry or a trust-root document can carry that
  crashes the verifier, hangs it or makes it read outside the bundle;
- private evidence or bundle material disclosure risks;
- unsafe handling of credentials, tokens, headers, cookies, API keys, or private URLs;
- public/private boundary leakage;
- package supply-chain or build/release risks;
- documentation wording that could cause unsafe integration or unsupported trust assumptions.

## Out of scope for this repository

This repository does not by itself prove legal ownership, valuation correctness, regulatory
compliance, chain finality, registry operation, or external audit status.

The capabilities a report lists in `outcome.not_implemented_capabilities` are absent by design:
stating that one of them is absent is a correct reading of the documentation, not a finding.
Trust-registry root-signature verification is implemented and in scope.

Issues that belong to another Loquitur repository are reported against that repository: a defect
of the specification or of the conformance corpus against `loquitur-protocol`, of a schema against
`loquitur-schemas`, of the TypeScript verifier against `loquitur-verify-ts`. When an issue affects
this verifier and another repository, report it here and say so; the maintainer coordinates the
fixes.

## Do not disclose sensitive material

Do not include real issuer evidence, private bundles, private keys, credentials, tokens, personal
data, or confidential third-party artifacts in public issues, pull requests, discussions, or
unencrypted reports.

## Reporting channel

**Use GitHub's private vulnerability reporting on this repository**: open the *Security*
tab and choose *Report a vulnerability*. The report is visible only to the maintainer, it
carries no address that can be scraped or spoofed, and it produces an advisory record with
a fixed identifier both sides can cite later. It is the primary channel and needs nothing
set up on your side.

If private reporting is unavailable to you, write to **security@loquitur.dev**. Keep the
details of the vulnerability out of the first message if you prefer: the maintainer replies
and agrees a private channel for them. Do not describe a vulnerability in a public issue.

## What to expect

- Acknowledgement within 5 working days.
- An assessment, including whether the maintainer considers it in scope, within 10
  working days.
- Coordinated disclosure: the maintainer agrees a publication date with you first, and
  credits you unless you ask not to be credited.
- The maintainer aims to publish a fix and an advisory within 90 days of the day the report is
  received, and may agree a different date with you.

## Advisories and identifiers

A confirmed vulnerability is published as a GitHub security advisory of this repository, which
carries a `GHSA-` identifier. When it affects a released version, the maintainer requests a CVE
identifier for it through GitHub. The advisory names the affected versions and the version or
commit that fixes it, and the fix is listed in `CHANGELOG.md` under `Security`.

## Checking a release

Releases are built by `.github/workflows/release.yml`, which attaches `SHA256SUMS` and a
CycloneDX SBOM to the release files and records a GitHub artifact attestation for each of them;
[`docs/maintainers/releasing.md`](docs/maintainers/releasing.md) says how to check them.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | on the default branch only |

This is a pre-1.0 preview with no security-supported release line. Fixes land on the
default branch; there are no backports, because there is no earlier release line to
backport to.
