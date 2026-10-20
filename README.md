# loquitur-verify-py

Package status: **0.1.0 preview**.

`loquitur-verify` checks a Loquitur evidence bundle on your own machine, with no network access and
no Loquitur service. It tells you whether the bundle is internally consistent: its files match
its manifest and its digests agree. That alone does not show that nothing changed after issuance,
because whoever alters a bundle can recompute every digest in it. Given the public registry entry
as well, it tells you whether that entry refers to this bundle; given a trust registry too, whether
the entry was signed by an issuer key the trust registry authorizes, which is what ties the bundle
to a signed public commitment from an authorized key. A run that reaches the evidence ends in `PASS`, `REVIEW` or `FAIL`; a run that does not,
because of a fault of the verifier, an unsupported version or a host failure, reports no verdict
and exits 3, 4 or 5. Either way the report is one a program can read. It does
not judge whether a valuation is right, who the issuer is in the real world, or whether any public
registry holds the entry.

## Status

<!-- lq-include: status -->
- **Preview (Alpha).** The command line, the report and the Python API can change in any 0.x
  release.
- **Not yet published to a package index.** The verifier installs from a checkout of the
  `loquitur-verify-py` repository.
- **No independent cryptographic review of this protocol or its reference verifiers has been done
  yet.**
- What it leaves out is listed under
  [What it does not verify](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/README.md#what-it-does-not-verify);
  what the protocol release does not claim is section 12 of
  [`introduction.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/introduction.md).
<!-- lq-include-end: status -->

## Start here

- **You rely on a verdict, or review the risk of relying on one.** Read
  [What it verifies](#what-it-verifies), [What it does not verify](#what-it-does-not-verify) and
  the [Trust model](#trust-model). The protocol's
  [`threat-model.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/threat-model.md)
  states what a verdict asserts (section 2) and what an operator must do that the tool cannot
  (section 10).
- **You integrate the verifier.** [Install it](#installation), run the
  [quickstart](#5-minute-quickstart-from-source), then read
  the [CLI contract](#cli-contract) and the [Python API](#python-api).
- **You review its security.** Read
  [`SECURITY.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/SECURITY.md),
  the threat model,
  [`cryptographic-capabilities.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/cryptographic-capabilities.md),
  [Signature verification](#signature-verification) and [Conformance](#conformance).

## Installation

<!-- lq-include: installation -->
You need Python 3.11 or newer and a checkout of the `loquitur-verify-py` repository. From the
directory that contains the checkout:

```bash
python -m pip install ./loquitur-verify-py
cd loquitur-verify-py
loquitur-verify --version
```

That installs the verifier and its two dependencies, `rfc8785` and `cryptography`. Network access
is needed only to download them when they are not already cached.

The optional `narrative` extra, which adds `--narrative`, needs `loquitur-schemas`
(`>=0.1.0,<0.2.0`): install it the same way from its own checkout, before `loquitur-verify`.
<!-- lq-include-end: installation -->

## 5-minute quickstart from source

<!-- lq-include: quickstart -->
With the verifier installed, run these commands from the root of the `loquitur-verify-py`
checkout. They verify the golden fixtures under `tests/fixtures/`.

Verify the valid golden fixture:

```bash
loquitur-verify tests/fixtures/valid_bundle.zip --json
```

Expected result:

```text
status: OFFLINE_OK
verdict: PASS
exit code: 0
```

Verify a tampered manifest fixture:

```bash
loquitur-verify tests/fixtures/tampered_manifest_bundle.zip --json
```

Expected result:

```text
status: OFFLINE_FAIL
verdict: FAIL
exit code: 1
```

Verify a tampered canonical input fixture:

```bash
loquitur-verify tests/fixtures/tampered_canonical_input_bundle.zip --json
```

Expected result:

```text
status: OFFLINE_FAIL
verdict: FAIL
exit code: 1
```

Verify a bundle missing canonical input:

```bash
loquitur-verify tests/fixtures/missing_canonical_input_bundle.zip --json
```

Expected result:

```text
status: OFFLINE_REVIEW
verdict: REVIEW
exit code: 2
```

For a local workflow that accepts a named review reason, `--accept-review` lists the reasons to
accept; the report is unchanged:

```bash
loquitur-verify tests/fixtures/missing_canonical_input_bundle.zip --json --accept-review canonical_input_not_provided
```

Expected result:

```text
status: OFFLINE_REVIEW
verdict: REVIEW
exit code: 0
```

Only the process exit changes: the report still says `OFFLINE_REVIEW`, and its `exit_code` member
stays `2`
([`report-contract.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/report-contract.md)
section 4).

Each `Expected result` block lists `status`, `verdict` and the process exit code, then members of
the JSON report named by their path in it.
<!-- lq-include-end: quickstart -->

## Windows quickstart

<!-- lq-include: windows-quickstart -->
In PowerShell, from the directory that contains the checkout:

```powershell
python -m pip install .\loquitur-verify-py
cd loquitur-verify-py
loquitur-verify tests\fixtures\valid_bundle.zip --pretty
```

Expected abbreviated result:

```text
Loquitur offline verification: OFFLINE_OK / PASS
registry: REGISTRY_ENTRY_NOT_PROVIDED (signature_supported=False)
```

The other `loquitur-verify` commands of the quickstart and of the link and authorization checks
are written for a POSIX shell. They run unchanged in PowerShell, except that the authorization
commands continue lines with `\`: in PowerShell, end those lines with a backtick instead, or
write the command on one line.
<!-- lq-include-end: windows-quickstart -->

## What it verifies

<!-- lq-include: what-it-verifies -->
Every run makes the `structure` and `integrity` checks of
[`verification-checks.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/verification-checks.md);
the files you supply add the `link` and `authorization` checks.

- **Archive intake:** ZIP safety, path traversal included, and bundle root discovery
  ([`bundle-objects.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/bundle-objects.md)
  section 5).
- **The bundle's objects:** the closed contracts of `manifest.json`, `p1.json` and
  `envelope_env1.json`, the digest of every declared member, and the links between them
  (`bundle-objects.md` sections 1 to 4), with digests computed under the canonical JSON profile of
  [`canonicalization-and-hashing.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/canonicalization-and-hashing.md).
- **The verification receipt:** `verification_receipt.json`, whenever it is present, against its
  closed contract.
- **The `link` check**, with `--registry-entry`: the supplied registry entry against the receipt
  and the bundle
  ([`registry-link.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/registry-link.md),
  [`registry-entry.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/registry-entry.md)).
- **The `authorization` check**, with `--trust-registry` as well: the issuer key's authorization
  in the supplied trust registry at your evaluation time, then the entry's signature over the
  signing envelope
  ([`trust-registry-authorization.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/trust-registry-authorization.md),
  [`signing-envelope-v2.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/signing-envelope-v2.md)).
- **Trust-root authentication**, with `--trust-root`: the trust registry's signature against the
  root you pin
  ([`trust-root.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/trust-root.md)).
- **Registered vocabularies:** asset types, workflows and anchoring methods against the
  vocabularies the verifier holds
  ([`verification-vocabularies.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/verification-vocabularies.md)
  section 8).
- **The report:** status, verdict, exit code and reason surface as
  [`report-contract.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/report-contract.md)
  defines them, as JSON or as readable text.
<!-- lq-include-end: what-it-verifies -->

## What it does not verify

<!-- lq-include: does-not-verify -->
> Loquitur governs the evidence behind a valuation; it does not compute valuations.

The verifier does **not** verify:

- trust registry membership outside the supplied local trust registry;
- issuer signatures without a supplied local `registry_entry` and `trust_registry`;
- issuer authorization without a supplied local `registry_entry` and `trust_registry`;
- trust-registry root authenticity without a root you supply: root-signature verification is
  implemented, `PINNED_TRUST_ROOTS` ships empty and empty means refuse, so a trust registry is
  authenticated only against a trust-root document passed with `--trust-root`;
- registry inclusion or checkpoint proofs (the `transparency` check is reserved in
  `verification-checks.md`);
- chain anchors or their finality (the `anchoring` check is reserved; see
  [`anchor-commitment.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/anchor-commitment.md));
- revocation or supersession beyond the fields of the supplied trust registry;
- anything online: it queries no registry and no service;
- valuation correctness;
- KYC, AML or compliance status;
- whether evidence is economically sufficient for an investment decision.

Each report lists, in `outcome.not_implemented_capabilities`, the capabilities its run did not
have; `threat-model.md` section 9 names the risk each one leaves with the relying party.
<!-- lq-include-end: does-not-verify -->

## Link check

<!-- lq-include: link-check -->
The `link` check runs only when you supply a registry entry:

```bash
loquitur-verify tests/fixtures/link_valid_bundle.zip --registry-entry tests/fixtures/link_valid_registry_entry.json --json
```

Expected result:

```text
status: OFFLINE_OK
verdict: PASS
exit code: 0
outcome.reason: local_integrity_and_registry_link_checks_passed
```

The check holds the supplied entry and the bundle's receipt to their closed contracts, then
compares them with each other and with the bundle, value for value. The entry's own committed
`verdict` caps the result: only a `PASS` entry can reach `OFFLINE_OK`. A passing `link` check
means only that the supplied entry is consistent with the supplied bundle, not who signed the
entry or that any registry holds it.
[`registry-link.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/registry-link.md)
specifies every comparison. Without `--registry-entry`, the report's `registry_link` is `null`.
<!-- lq-include-end: link-check -->

## Authorization check

<!-- lq-include: authorization-check -->
The `authorization` check runs only when you supply a registry entry and a trust registry. Three
runs over the same fixtures show the three outcomes it can reach. Run them from the repository
root.

Without a trust root, a run that passes every other authorization condition still reviews:
nothing authenticates the trust registry itself.

```bash
loquitur-verify tests/fixtures/link_valid_bundle.zip \
  --registry-entry tests/fixtures/authorization_valid_registry_entry.json \
  --trust-registry tests/fixtures/authorization_quickstart_trust_registry.json \
  --evaluation-time 2026-05-20T00:00:00Z \
  --json
```

Expected result:

```text
status: OFFLINE_REVIEW
verdict: REVIEW
exit code: 2
outcome.reason: trust_registry_root_not_pinned
trust_registry.authorization_status: AUTHORIZED_ACTIVE_KEY
trust_registry.signature_status: VALID_SIGNATURE
trust_registry.trust_registry_root_signature_status: NO_PINNED_TRUST_ROOT
```

With `--trust-root`, the trust registry is authenticated against the root that the trust-root
document names, and the run passes:

```bash
loquitur-verify tests/fixtures/link_valid_bundle.zip \
  --registry-entry tests/fixtures/authorization_valid_registry_entry.json \
  --trust-registry tests/fixtures/authorization_quickstart_trust_registry.json \
  --trust-root tests/fixtures/authorization_quickstart_trust_root.json \
  --evaluation-time 2026-05-20T00:00:00Z \
  --json
```

Expected result:

```text
status: OFFLINE_OK
verdict: PASS
exit code: 0
outcome.reason: local_integrity_registry_link_and_trust_checks_passed
trust_registry.trust_registry_root_signature_status: ROOT_SIGNATURE_VALID
```

The evaluation time is yours, never one of the issuer's dates; without `--evaluation-time`,
authorization is not established. One second after the trust registry expires, the run reviews
rather than fails, because no time attested to the signature exists in this version, and root
authentication is not reached:

```bash
loquitur-verify tests/fixtures/link_valid_bundle.zip \
  --registry-entry tests/fixtures/authorization_valid_registry_entry.json \
  --trust-registry tests/fixtures/authorization_quickstart_trust_registry.json \
  --trust-root tests/fixtures/authorization_quickstart_trust_root.json \
  --evaluation-time 2026-05-29T12:00:01Z \
  --json
```

Expected result:

```text
status: OFFLINE_REVIEW
verdict: REVIEW
exit code: 2
outcome.reason: trust_registry_not_current
trust_registry.authorization_status: TRUST_REGISTRY_EXPIRED
trust_registry.trust_registry_root_signature_status: ROOT_SIGNATURE_NOT_EVALUATED
```

The trust root of these runs was generated in memory, used once to sign
`authorization_quickstart_trust_registry.json` and discarded; nothing can sign with it again.
**That root has no authority over anything:** it exists to show what `--trust-root` does. A real
deployment pins a root it obtained out of band, from a party it trusts
([`trust-root.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/trust-root.md)
section 7).

The check first establishes that the supplied trust registry authorizes the entry's issuer key at
your evaluation time, and only then verifies the entry's signature with that key. The conditions,
their order and the status each one reports are specified in
[`trust-registry-authorization.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/trust-registry-authorization.md).
`--trust-registry` requires `--registry-entry`; without `--trust-registry`, the report's
`trust_registry` is `null`.

A key is judged as a key and not by its label. The check stops with `TRUST_REGISTRY_AMBIGUOUS_KEY`
when more than one trust entry of the issuer carries the entry's `issuer_key_id`, and when the trust
entry found shares its secp256k1 point with another trust entry of the registry, whatever their
statuses, issuers and key types and in either SEC1 spelling, compressed or uncompressed. The same
`issuer_key_id` under another `issuer_id` with a key of its own is not a duplicate.
<!-- lq-include-end: authorization-check -->

## Trust model

<!-- lq-include: trust-model -->
`loquitur-verify` is an offline verifier. It shows that a disclosed bundle is internally
consistent, that a supplied registry entry agrees with it, and that a supplied trust registry
authorizes the key that signed the entry. It does not show who governs the root a trust registry
is authenticated against, that the entry was committed to any registry, that a chain anchor is
final, or that the valuation is correct.

What an `OFFLINE_OK` run asserts depends on the files you supplied:

- the bundle alone: the local integrity checks passed;
- with `--registry-entry`: the `link` check passed too, the entry conforms to its contract, and
  the entry's own committed `verdict` is `PASS`;
- with `--trust-registry` too: the `authorization` check passed at your `--evaluation-time`, and
  `--trust-root` pinned a root against which the trust registry verifies.

Without `--trust-root` no root is pinned, and the trust registry's own authenticity is never
established. Root-signature verification reports in `trust_registry_root_signature_status` and
in the boolean `trust_registry_root_signature_verified`; with no root pinned it reports
`NO_PINNED_TRUST_ROOT`, the boolean stays `false`, and the run returns `OFFLINE_REVIEW` rather
than `OFFLINE_OK`. That is deliberate: a trust registry nobody vouches for is one an issuer can
mint alongside the entry it authorizes. `OFFLINE_REVIEW` means the run could not establish
everything requested, and `review_reasons` says why. `OFFLINE_FAIL` means a check failed or the
input was refused, so refused evidence never exits `0`.

Revocation is of a key, not of the label it is listed under, so a key is compared as a point of
secp256k1 and never as a string. A revoked key listed again under an active `issuer_key_id`, under
another issuer, in another SEC1 spelling or under another key type would otherwise authorize, and
the authorization check stops with `TRUST_REGISTRY_AMBIGUOUS_KEY`
([`trust-registry-authorization.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/trust-registry-authorization.md)
section 6, row 6). Root authentication applies the same rule to the pinned roots: it stops with
`AMBIGUOUS_ROOT_KEY` when more than one pinned root has the key id, or when the matched root shares
its point with another pinned root
([`trust-root.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/trust-root.md)
section 5, row 7). A value that encodes no point shares none.

The verdict path contains no AI: no machine-learning model or other learned component takes part in
any outcome (enforced by an allow-list of imports, `tools/check_verdict_path_isolation.py`).
<!-- lq-include-end: trust-model -->

## CLI contract

<!-- lq-include: cli-contract -->
```text
loquitur-verify <bundle-dir-or-zip> --json
loquitur-verify <bundle-dir-or-zip> --pretty
loquitur-verify <bundle-dir-or-zip> --json --accept-review <review-reason>[,<review-reason>...]
loquitur-verify <bundle-dir-or-zip> --registry-entry <registry-entry.json> --json
loquitur-verify <bundle-dir-or-zip> --registry-entry <registry-entry.json> --trust-registry <trust-registry.json> --evaluation-time <YYYY-MM-DDTHH:MM:SSZ> --json
loquitur-verify <bundle-dir-or-zip> --registry-entry <registry-entry.json> --trust-registry <trust-registry.json> --trust-root <trust-root.json> --evaluation-time <YYYY-MM-DDTHH:MM:SSZ> --json
loquitur-verify <bundle-dir-or-zip> --asset-type-vocabulary <asset_type.json> --workflow-vocabulary <workflow.json> --anchoring-method-vocabulary <anchoring_method.json> --json
```

The grammar is section 4.1 of
[`report-contract.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/report-contract.md);
`--json`, `--pretty` and `--narrative` choose the output. The report goes to stdout, also when
verification fails; usage errors go to stderr. No online registry is called.

Exit codes, as `report-contract.md` section 4 defines them:

- `0`: `OFFLINE_OK` / `PASS`;
- `1`: `OFFLINE_FAIL` / `FAIL`;
- `2`: `OFFLINE_REVIEW` / `REVIEW`, unless `--accept-review` accepts every review reason of the
  run;
- `3`: `INTERNAL_ERROR`, a fault of the verifier;
- `4`: `UNSUPPORTED_VERSION`, an object of a version this verifier does not support;
- `5`: `HOST_FAILURE`, the host failed an operation on your input; it says nothing about the
  evidence;
- `64`: usage error, with no report.

A run that exits `3`, `4` or `5` reports its `status` and a `null` `verdict`: it reached no
verdict about the evidence.

The verifier holds the protocol's registered vocabularies built in. The three vocabulary options
supply a later version of one, for that kind only. A value the vocabulary held does not register
makes the run `OFFLINE_REVIEW` with the review reason `vocabulary_value_unknown`; a vocabulary
document that is malformed, or registers another kind than its option names, is a usage error. The
report's `vocabularies` member records the version, digest and source of each document held.
<!-- lq-include-end: cli-contract -->

### The report

The members a conformance comparison reads, and their values, are defined in `report-contract.md`
sections 2, 3 and 5; every other member is informative. The informative members that belong to
this verifier, `outcome.category`, `outcome.not_implemented_capabilities` and the messages that
name refused content, are listed in
[`docs/outcome-categories.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/docs/outcome-categories.md).
Refused content is always `OFFLINE_FAIL` / exit `1`, never exit `3`.

## Python API

<!-- lq-include: python-api -->
The command line is a thin layer over one call, `verify_path`, which returns the report that
`--json` writes. From the repository root:

```python
from loquitur.verify import exit_code_for_status, read_trust_root_document, verify_path

report = verify_path("tests/fixtures/valid_bundle.zip")
print(report.status, report.verdict, exit_code_for_status(report.status))

report = verify_path(
    "tests/fixtures/link_valid_bundle.zip",
    registry_entry_path="tests/fixtures/authorization_valid_registry_entry.json",
    trust_registry_path="tests/fixtures/authorization_quickstart_trust_registry.json",
    trust_roots=read_trust_root_document("tests/fixtures/authorization_quickstart_trust_root.json"),
    evaluation_time="2026-05-20T00:00:00Z",
)
payload = report.to_dict()  # the JSON report, as a dict
print(payload["status"], payload["outcome"]["reason"])
```

It prints `OFFLINE_OK PASS 0`, then `OFFLINE_OK local_integrity_registry_link_and_trust_checks_passed`.

`verify_path` takes the bundle path and, as keywords, `registry_entry_path`, `trust_registry_path`,
`trust_roots`, `evaluation_time`, your evaluation time as a string of the form
`YYYY-MM-DDTHH:MM:SSZ`, and `vocabularies`, a mapping of a kind (`asset_type`, `workflow` or
`anchoring_method`) to the path of a vocabulary document you supply or to a `HeldVocabulary`; a
document that is refused raises `VocabularyError` before anything is read. Evidence that fails verification is a report, never an exception. A
malformed `trust_roots` or `evaluation_time` raises `TrustRootError` or `EvaluationTimeError`
before anything is read, where the command line exits `64`. A host that reads the trust-root
document itself and fails to read it passes `DOCUMENT_READ_FAILED` of `loquitur.verify` as
`trust_roots`: the report is `HOST_FAILURE` with the error `trust_root_read_failed`, as the
command line reports a `--trust-root` file it fails to read. Every exception the package raises on
purpose is also a `LoquiturVerifyError` (`from loquitur.verify import LoquiturVerifyError`), beside
the built-in base it has always had (`ValueError`, `OSError` or `Exception`): one `except` clause
catches the verifier's own errors, and code that catches the built-in base is unaffected. The
package ships type information (`py.typed`).
<!-- lq-include-end: python-api -->

The entry points above import from `loquitur.verify`: `verify_path`, `OfflineVerificationReport`
(what it returns), `exit_code_for_status`, `read_trust_root_document`, `TrustRootError`,
`EvaluationTimeError`, `DOCUMENT_READ_FAILED` and `LoquiturVerifyError`, which are the names of
`loquitur.verify.__all__` with `verify_registry_link`, `verify_registry_entry_trust` and the
narrative renderer; `tools/public_api_parity.json` pairs each with its counterpart in
`loquitur-verify-ts`. Importing the package
loads none of them until it is used, and loads neither the narrative renderer nor
`loquitur-schemas`. The command line is also `python -m loquitur.verify`.

Of the rest of the package, the modules `runner`, `trust_root`, `trust_registry`, `registry_link`
and `narrative` are stable provisional API: their public names are kept through the 0.x releases
unless a release says otherwise. Everything else is internal and may change before 1.0, whatever
its name.

## Reading a bundle

A directory argument must itself be the bundle root, the directory holding `manifest.json`. A ZIP
archive may hold the bundle at its top level or in one folder; a file of the archive outside that
folder is reported in `input.container_extra_files` and makes the run `OFFLINE_REVIEW`, as an
undeclared member inside the bundle does. The rules are `bundle-objects.md` sections 1 and 5.

This verifier is the project's only implementation of archive intake, so no second implementation
is compared with it: its ZIP reader is checked against the `archive_intake_*` runs of the
conformance corpus and against this repository's own suite.

Reading a directory bundle has limits an operator should know:

- Containment is checked on every path component immediately before each read, and links are
  refused, but a directory that another process changes during verification can still change
  between the check and the read. Verify bundles from a location no other process writes to.
- A hard link cannot be told from a regular file, and is verified as one.
- Every reparse point is refused, cloud-sync placeholders and deduplicated files included. Do not
  verify bundles from a synchronized folder.
- Alternate data streams are not bundle members, and are neither listed nor verified.
- Member names resolve exactly as the directory lists them: a manifest declaring `P1.JSON` does
  not name `p1.json`, whatever the host filesystem would open.

## Signature verification

The `authorization` check verifies secp256k1 ECDSA signatures with pyca/`cryptography`
(`ec.SECP256K1`), handing it the 32-byte SHA-256 of the signing message as prehashed, so SHA-256
is applied exactly once. The protocol is stricter than the library, so its rules are checked
before the library is called: the signature is 128 lowercase hex characters, `r` and `s` are in
`[1, n-1]` and `s` is at most `n/2` (the library accepts a high `s`), and the public key is an
uncompressed SEC1 point with both coordinates below `p` and on the curve. The package only
verifies: it handles no key material for signing. Its verdicts are compared with the Wycheproof
secp256k1 vectors and with cross vectors checked against `@noble/curves`
(`tests/test_secp256k1_cross_vectors.py`). Registry-entry signatures are verified over the
domain-separated signing envelope v2; a signature object without `payload_id` and
`payload_version` breaks the entry's contract, and a later payload identifier is an unsupported
version
([`signing-envelope-v2.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/signing-envelope-v2.md)).

## Conformance

This verifier is measured against the protocol's conformance corpus
`loquitur-conformance-bdbadee7f6144d08`, which
[`CONFORMANCE_CONSUMER.json`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/CONFORMANCE_CONSUMER.json)
pins by digest and which this repository reads and never changes. The corpus and its expected
outcomes belong to `loquitur-protocol`
([`conformance-testing.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/conformance-testing.md)).
The golden fixtures under `tests/fixtures/` are tests of this implementation, and
[`tests/fixtures/README.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/tests/fixtures/README.md)
lists each one with its expected result. Passing the corpus is the maintainer's own testing, carried out with
the help of AI tools, which is internal verification and not an audit.

## Compatibility

- **Python:** 3.11 or newer (`requires-python = ">=3.11"`). Continuous integration runs the suite
  on Linux with Python 3.11 to 3.14.
- **Platforms:** the verifier is pure Python. Continuous integration runs its suite on Linux; the
  suite also passes on Windows locally. macOS is not tested.
- **Dependencies:** `rfc8785` and `cryptography`; the `narrative` extra adds
  `loquitur-schemas>=0.1.0,<0.2.0`.
- **Protocol:** release 0.1 of the Loquitur protocol, as pinned by the conformance corpus above.

## Links

- Specification: [`loquitur-protocol`](https://github.com/loquitur-dev/loquitur-protocol), table
  of contents in
  [`docs/README.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/README.md)
- Security policy:
  [`SECURITY.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/SECURITY.md)
- Contributing, with the maintainer documentation:
  [`CONTRIBUTING.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/CONTRIBUTING.md)
- Changes:
  [`CHANGELOG.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/CHANGELOG.md)
- License: MIT OR Apache-2.0, as [License](#license) states

## License

Licensed under either of

- the Apache License, Version 2.0,
  [`LICENSE-APACHE`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/LICENSE-APACHE),
  or
- the MIT License,
  [`LICENSE-MIT`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/LICENSE-MIT),

at your option. The license covers the code, the JSON documents, the test fixtures, the tools and
the tests. The Wycheproof test-vector file under `tests/vectors/` is third-party material under
the Apache License, Version 2.0 only, as
[`NOTICE`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/NOTICE) states.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this repository, as defined in the Apache License, Version 2.0, is dual licensed as above, without
any additional terms or conditions, and carries the Developer Certificate of Origin sign-off that
[`CONTRIBUTING.md`](https://github.com/loquitur-dev/loquitur-verify-py/blob/main/CONTRIBUTING.md)
describes.
