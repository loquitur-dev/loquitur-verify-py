# Outcome categories and refusal messages

The members a conformance comparison reads, and their values, are defined in sections 2, 3 and 5 of
[`report-contract.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/report-contract.md):
`status`, `verdict`, `exit_code`, `outcome.reason`, the codes of `errors`, `checks_requested`,
`checks_established`, `review_reasons`, `evaluation_time` and, when the trust registry was
evaluated, its three statuses. Every other member is informative. This page lists the informative
members that belong to `loquitur-verify`; another verifier of the protocol may report them
differently.

## `outcome.category`

`outcome.category` sorts a run for automation:

- `success_local_integrity_only`, `success_registry_link_verified` and
  `success_trust_registry_verified`: an `OFFLINE_OK` run, by the last check it established;
- `warning_or_review_state`: an `OFFLINE_REVIEW` run;
- `proof_integrity_failure`: a manifest, P1 or envelope integrity or link check failed;
- `issuer_authorization_failure`: the bundle is intact and the `authorization` check failed;
- `registry_verdict_not_pass`: the bundle is intact and the supplied entry commits
  `verdict: "FAIL"`;
- `trust_root_authentication_failure`: a root was pinned and the trust registry did not verify
  against it, so nothing is asserted about the issuer;
- `archive_safety_failure`: a ZIP archive or bundle directory failed the intake safety rules;
- `malformed_input_failure`: a required bundle member, or a file you supplied, is missing,
  unreadable, or outside its closed contract;
- `unsupported_input_failure`: the input, or the combination of inputs, is not supported;
- `unsupported_version`, `host_failure` and `internal_error`: the runs of exit `4`, `5` and `3`.

A category of a run that did not establish `authorization` implies nothing about the issuer, the
trust registry, registry inclusion, anchors, valuation or compliance.

## `outcome.not_implemented_capabilities`

The list is computed per run: `trust_registry_root_signature_verification` is left out exactly when
a pinned root verified the trust registry in that run. Section 9 of
[`threat-model.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/threat-model.md)
names the risk each capability leaves with the relying party.

## Messages that name refused content

Refused content is always `OFFLINE_FAIL` / exit `1`, never exit `3`. The `message` of an `errors[]`
entry, and the `notes`, name what was refused:

- `manifest_canonicalize_failed:<class>` and `envelope_canonicalize_failed:<class>`: the manifest
  or the envelope could not be canonicalized;
- `unsafe_bundle_member:link:<name>`, one note per link: a directory bundle holds a symbolic link,
  a junction or another reparse point;
- `bundle_member_name_invalid`: an entry of the bundle directory has a name outside the portable
  member-name rule of `bundle-objects.md` section 2, or two names of one directory conflict under
  ASCII case folding;
- `member_too_large`: a declared member is larger than 20 MiB, in a directory as in a ZIP archive;
- `verification_receipt_contract_violation:<path>:<keyword>`, at most eight notes: a present
  receipt breaks its closed contract;
- `json_nesting_too_deep:<member>`, `non_finite_json_number:overflow:<member>`,
  `json_integer_outside_safe_range:<member>`, `json_lone_surrogate:<member>`,
  `json_noncharacter:<member>` and `json_excess_precision:<member>`: a document broke the strict
  load rules of `canonicalization-and-hashing.md`.

A directory of the bundle that the host fails to list is not refused content. Its error,
`bundle_inventory_failed`, is a host failure: when it is the run's only error and no failure
condition holds, the run is `HOST_FAILURE` / exit `5`, which says nothing about the evidence. A
layer that fails on its own still makes the run `OFFLINE_FAIL` / exit `1`.
