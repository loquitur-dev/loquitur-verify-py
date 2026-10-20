"""The link check against a registry entry supplied locally, for loquitur-verify.

This module compares, deterministically and locally, the private bundle material the holder
discloses with a supplied public ``registry_entry`` JSON file. It does not verify issuer
signatures, trust registries, registry inclusion or checkpoint proofs, anchors, timestamps,
finality, revocation or online registry state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import CanonicalizationError, JsonLoadError, canonical_json_sha256, loads_json_bytes
from .contract_validation import contract_errors
from .errors import LoquiturVerifyError
from .host_path import host_path
from .manifest import (
    ManifestVerificationResult,
    is_blank,
    is_prefixed_sha256,
    labelled,
    usable_bundle_id,
)
from .members import (
    MemberTooLargeError,
    member_is_file,
    path_names_regular_file,
    read_file_bytes,
    read_member_bytes,
)
from .verdict_grounds import registry_entry_grounds_errors

STATUS_OFFLINE_OK = "OFFLINE_OK"
STATUS_OFFLINE_REVIEW = "OFFLINE_REVIEW"
STATUS_OFFLINE_FAIL = "OFFLINE_FAIL"
VERDICT_PASS = "PASS"
VERDICT_REVIEW = "REVIEW"
VERDICT_FAIL = "FAIL"

_SHA256_PREFIX = "sha256:"
_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)(?:-[A-Za-z0-9_.-]+)?$"
)


class RegistryLinkVerificationError(LoquiturVerifyError):
    """Base class for expected registry-link verification failures.

    ``read_error`` carries the host failure to read a document the link reads that was
    observed BEFORE the refusal this exception names. Both conditions hold, and
    report-contract.md section 5.3 asks for both codes; an exception that carried its own
    refusal alone would make the caller drop the other.
    """

    read_error: OSError | None = None


class RegistryEntryMissingError(RegistryLinkVerificationError):
    """Raised when the supplied registry-entry path does not exist."""


class RegistryEntryTypeError(RegistryLinkVerificationError):
    """Raised when registry_entry JSON is not an object."""


class VerificationReceiptMissingError(RegistryLinkVerificationError):
    """Raised when verification_receipt.json is absent from the bundle."""


class VerificationReceiptTypeError(RegistryLinkVerificationError):
    """Raised when verification_receipt.json is not an object."""


@dataclass(frozen=True)
class RegistryLinkFieldCheck:
    name: str
    expected: Any
    actual: Any
    ok: bool | None
    note: str | None = None


@dataclass(frozen=True)
class RegistryLinkVerificationResult:
    registry_entry: dict[str, Any] | None
    registry_entry_path: str | None
    verification_receipt: dict[str, Any] | None
    verification_receipt_path_name: str | None
    receipt_sha256_actual: str | None
    checks: tuple[RegistryLinkFieldCheck, ...]
    notes: tuple[str, ...] = ()
    # Why a supplied entry, or a present receipt, could not be read as an object at all.
    entry_error: str | None = None
    receipt_error: str | None = None
    # The host failure to read one of the two documents the link reads: the caller reports
    # registry_link_read_failed and the link reaches no conclusion. Not a finding about the
    # document, which is why it is not one of the two errors above. The exception travels,
    # not its text: the caller decides what of it a report may carry.
    read_error: OSError | None = None
    # The bundle carries no verification_receipt.json: nothing to link. Not an error: the link is
    # not established, which is the review reason verification_receipt_not_provided
    # (registry-link.md section 5).
    receipt_missing: bool = False

    @property
    def entry_present(self) -> bool:
        return self.registry_entry is not None

    @property
    def receipt_present(self) -> bool:
        return self.verification_receipt is not None

    @property
    def link_holds(self) -> bool:
        """Whether the link holds: both documents are present, no check failed and every hard
        check passed.

        Not the verdict. A check that is not hard and could not be compared leaves the link
        holding while ``status`` is OFFLINE_REVIEW and ``verdict`` REVIEW; those two are the
        outcome. The result has no ``ok``, which a host reading it alone would take for the
        verdict.
        """
        return (
            self.entry_present
            and self.receipt_present
            and all(check.ok is not False for check in self.checks)
            and not any(check.ok is None for check in self.checks if check.name in _HARD_CHECK_NAMES)
        )

    @property
    def status(self) -> str:
        if not self.entry_present or not self.receipt_present:
            return STATUS_OFFLINE_FAIL
        for check in self.checks:
            if check.name in _HARD_CHECK_NAMES and check.ok is not True:
                return STATUS_OFFLINE_FAIL
        if any(check.ok is False for check in self.checks):
            return STATUS_OFFLINE_FAIL
        if any(check.ok is None for check in self.checks):
            return STATUS_OFFLINE_REVIEW
        return STATUS_OFFLINE_OK

    @property
    def verdict(self) -> str:
        if self.status == STATUS_OFFLINE_OK:
            return VERDICT_PASS
        if self.status == STATUS_OFFLINE_REVIEW:
            return VERDICT_REVIEW
        return VERDICT_FAIL


_HARD_CHECK_NAMES = frozenset(
    {
        "manifest_hash",
        "receipt_manifest_sha256",
        "receipt_hash",
        "policy_id",
        "policy_version",
        "reason_code_catalog_version",
        "reason_codes",
        "asset_type",
        "registry_entry_contract",
        "verification_receipt_contract",
        "receipt_bundle_id",
        "receipt_p1_sha256",
    }
)

# The closed vocabulary, and nothing else: no synonym such as `passed`, `ok` or `success`
# maps to PASS.
#
# loquitur-protocol/docs/specification/verification-vocabularies.md §3 forbids a status
# outside the four, and forbids coercing an unrecognized value to PASS, WARN, REVIEW or FAIL:
# an unrecognized status is a rejection, not a downgrade. loquitur-schemas closes the same set in
# STATUS_TO_REGISTRY_VERDICT with no aliases, and its README states the MUST while naming
# this function in the next sentence as the thing that bridges the two.
#
# A receipt carrying `status: "ok"`, a value the specification says to reject, would
# otherwise produce verdict PASS and exit 0 against an otherwise valid bundle. Accepting
# a synonym on a verdict surface is a fail-open, and a lenient reader of someone else's
# field name is not worth one.
_STATUS_TO_VERDICT = {
    "pass": "PASS",
    "warning": "WARN",
    "review": "REVIEW",
    "fail": "FAIL",
}


def _read_json_file(path: Path) -> Any:
    """The strict JSON of a host document. A host failure to read it is the host's (OSError),
    not a link failure: report-contract.md section 5.3 reports it as registry_link_read_failed,
    not as registry_link_verification_failed."""
    return loads_json_bytes(read_file_bytes(path), name=path.name)


# Every comparison below takes the two values exactly as written: no whitespace is
# stripped from identifiers or reason codes, no digest is lower-cased and no policy
# version is read out of a string, so " loquitur.policy.property.demo" does not match the
# entry's policy_id, nor [" INTEGRITY_OK "] its reason codes. A value of the wrong type is
# None, and a hard check against None fails.


def _exact_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _prefixed_sha256(value: Any) -> str | None:
    """A self-describing digest exactly as written, or None (canonicalization-and-hashing.md section 2)."""
    return value if is_prefixed_sha256(value) else None


def _normalize_reason_codes(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    # Order is not protocol-significant for the link check's membership comparison. MULTIPLICITY is, so
    # duplicates are kept: an entry carrying ["INTEGRITY_OK", "INTEGRITY_OK"], a
    # `uniqueItems` violation the schema rejects, does not compare equal to a clean
    # receipt. The sorted tuples compare element by element, so ["A,B"] or a NUL-joined
    # code never equals ["A", "B"], and nothing is stripped.
    return tuple(sorted(value))


# The receipt's policy_version is at most 2^53 - 1, sixteen decimal digits. A MAJOR with more
# digits equals no receipt integer, and is never converted: int() of unbounded text is refused by
# the interpreter above 4300 digits, which would make a run exit 3 over content.
_RECEIPT_INTEGER_DIGITS = 16


def _entry_policy_major(value: Any) -> int | str | None:
    """MAJOR of the entry's semver policy_version (registry-entry.md §6), as written.

    MAJOR is compared as decimal text (registry-link.md section 4): the grammar admits no
    leading zero, so two spellings of one number never differ. A MAJOR of at most sixteen digits
    is returned as its integer, which compares with the receipt's integer exactly as its decimal
    text would; a longer one is returned as the text itself, which equals no integer.
    """
    if not isinstance(value, str):
        return None
    match = _SEMVER_RE.fullmatch(value)
    if not match:
        return None
    major = match.group("major")
    return int(major) if len(major) <= _RECEIPT_INTEGER_DIGITS else major


def _receipt_policy_version(value: Any) -> int | None:
    """The receipt's integer policy_version under the canonical numeric model, never a string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _map_receipt_status_to_verdict(value: Any) -> str | None:
    """Map a receipt status to a registry verdict, or None if it is not one of the four.

    No ``.strip().lower()``: the status field is a closed lowercase enum in the schema, so
    anything that is not already an exact member, ``"  SUCCESS  "`` included, is not that
    member, and the honest answer is None.
    """

    if not isinstance(value, str):
        return None
    return _STATUS_TO_VERDICT.get(value)


def read_registry_entry(path: str | Path) -> dict[str, Any]:
    # Read as it is written, in the file namespace on Windows, as the input is (host_path). The
    # string is inspected, not a Path: pathlib gives a device path such as \\.\nul a separator
    # after it, which names another thing. A regular file's path survives the Path unchanged.
    host = host_path(path)
    registry_path = Path(host)
    # A host that fails to inspect the path raises its OSError: the entry is unread
    # (registry_link_read_failed), not a path naming no regular file.
    if not path_names_regular_file(host):
        raise RegistryEntryMissingError("registry_entry_not_found")
    try:
        entry = _read_json_file(registry_path)
    except JsonLoadError as exc:
        raise RegistryLinkVerificationError(str(exc)) from exc
    if not isinstance(entry, dict):
        raise RegistryEntryTypeError("registry_entry_invalid_type")
    return entry


def read_verification_receipt(bundle_root: Path) -> tuple[dict[str, Any], str]:
    if not member_is_file(bundle_root, "verification_receipt.json"):
        raise VerificationReceiptMissingError("verification_receipt_missing")
    receipt = _read_receipt(bundle_root)
    if not isinstance(receipt, dict):
        raise VerificationReceiptTypeError("verification_receipt_invalid_type")
    return receipt, "verification_receipt.json"


def _read_receipt(bundle_root: Path) -> Any:
    """The receipt's strict JSON. Over the per-member bound is the receipt's contract failing;
    any other OSError is the host failing to read a document the link reads, which propagates
    and is reported as registry_link_read_failed whichever checks are requested (report-contract.md
    section 5.3), not as a contract violation."""
    try:
        data = read_member_bytes(bundle_root, "verification_receipt.json")
    except MemberTooLargeError as exc:
        raise RegistryLinkVerificationError(str(exc)) from exc
    try:
        return loads_json_bytes(data, name="verification_receipt.json")
    except JsonLoadError as exc:
        raise RegistryLinkVerificationError(str(exc)) from exc


def verification_receipt_contract_violations(bundle_root: Path) -> list[str] | None:
    """Every way a present verification_receipt.json breaks its closed contract.

    None when the receipt is absent; an empty list when it conforms. A receipt that cannot
    be read or parsed, or is not a JSON object, is a violation as well, named by why.

    The receipt is validated against the generated contract of
    verification_receipt.schema.json whenever it is present, whichever checks are requested, not
    only compared field by field by the link check: a receipt with an unknown member, a string
    policy_version or no object_type does not verify, whatever the run requests.
    """
    if not member_is_file(bundle_root, "verification_receipt.json"):
        return None
    try:
        receipt = _read_receipt(bundle_root)
    except RegistryLinkVerificationError as exc:
        return [f"verification_receipt:{exc}"]
    return contract_errors("verification_receipt", receipt) + free_string_errors(
        receipt, "verification_receipt", VERIFICATION_RECEIPT_FREE_STRINGS
    )


# The free strings of the two documents (bundle-objects.md, "Free strings"; registry-link.md
# section 2): the members their schemas type as strings and hold to no pattern, enumeration or
# constant. A nested member is named by its path; it is read only when the object carrying it is
# present. Every other string member of either document is held by the schema to a form that no
# string of the whitespace set W matches.
VERIFICATION_RECEIPT_FREE_STRINGS = (
    "bundle_id",
    "policy_id",
    "verification_mode",
    "asset_id",
    "network",
    "anchor_provider",
    "anchor_type",
)
REGISTRY_ENTRY_FREE_STRINGS = (
    "issuer_key_id",
    "policy_id",
    "signature.key_id",
    "anchor.anchor_reference",
    "anchor.system",
)
# A second name for the same table, read by callers under that name.
REGISTRY_ENTRY_NAMED_STRINGS = REGISTRY_ENTRY_FREE_STRINGS


def free_string_errors(document: Any, name: str, members: tuple[str, ...]) -> list[str]:
    """Every free string of ``document`` that is a string made only of the whitespace set W.

    The schema's minLength 1 lets ``" "`` through, and such a value names nothing. The empty
    string has no code point outside W either, and is reported here too: four receipt members
    carry no minLength, and an empty one would otherwise pass. A value of another type, or a null where the
    schema admits one, is the schema's finding and is not reported here; a member whose
    carrying object is absent is not read. Nothing is trimmed.
    """
    if not isinstance(document, dict):
        return []
    errors: list[str] = []
    for member in members:
        node: Any = document
        for part in member.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, str) and is_blank(node):
            errors.append(f"{name}.{member}:blank")
    return errors


def registry_entry_identifier_errors(entry: Any) -> list[str]:
    """The registry entry's free strings made only of W (registry-link.md section 2), in every check."""
    return free_string_errors(entry, "registry_entry", REGISTRY_ENTRY_FREE_STRINGS)


def registry_entry_contract_violations(entry: Any) -> list[str]:
    """Every way a registry entry breaks its contract: its schema, its instants, its identifiers, its grounds.

    Empty when the entry satisfies the contract (registry-link.md section 2). The link reads it
    as a hard check, the authorization check reads the same function, and the report reads it before the
    entry's committed verdict: an entry that breaks its contract commits nothing.
    """
    return (
        contract_errors("registry_entry", entry)
        + registry_entry_identifier_errors(entry)
        + registry_entry_grounds_errors(entry)
    )


def _field_check_failed(name: str, reason: str) -> RegistryLinkFieldCheck:
    return RegistryLinkFieldCheck(name=name, expected=[], actual=[reason], ok=False)


def _field_check(name: str, expected: Any, actual: Any, *, note: str | None = None) -> RegistryLinkFieldCheck:
    ok: bool | None
    if expected is None or actual is None:
        ok = None
    else:
        ok = expected == actual
    return RegistryLinkFieldCheck(name=name, expected=expected, actual=actual, ok=ok, note=note)


def verify_registry_link(
    bundle_root: Path,
    *,
    registry_entry_path: str | Path,
    manifest_result: ManifestVerificationResult | None,
    p1_sha256_verified: str | None = None,
) -> RegistryLinkVerificationResult:
    """Verify the supplied public registry entry against local bundle material.

    The check is deterministic and local. It does not query any backend or
    registry service and it does not verify issuer signatures, trust registry
    membership, registry inclusion or checkpoint proofs, anchors, finality or
    revocation.

    ``p1_sha256_verified`` is the digest of a P1 that verified, or None; a receipt that
    names a p1_sha256 is held to it.

    Raises only when there is nothing to link: the entry file does not exist, or the
    bundle has no verification_receipt.json. A registry entry or a receipt that is present
    and cannot be read, is not a JSON object or breaks its contract is a failed link, and
    the result says so: the link does not hold.

    A host failure to read either document is recorded in ``read_error`` and never raised:
    the caller reports it once as registry_link_read_failed, and every condition of
    report-contract.md section 5.3 that does not depend on the document the host refused is
    still judged here, so a supplied entry that is not a registry entry at all, or one
    committing FAIL, is reported when the host refused the receipt. A refusal this function
    raises carries the read error with it.
    """

    entry_error: str | None = None
    receipt_error: str | None = None
    read_error: OSError | None = None
    try:
        entry: dict[str, Any] | None = read_registry_entry(registry_entry_path)
    except RegistryEntryMissingError:
        raise
    except RegistryLinkVerificationError as exc:
        # JSON null, an array, invalid JSON: a supplied document that is not a registry
        # entry. A failed link, not a raise: registry_link null would say "not evaluated"
        # for a document the caller supplied and the run refused.
        entry, entry_error = None, str(exc)
    except OSError as exc:
        entry, read_error = None, exc
    try:
        receipt: dict[str, Any] | None
        receipt, receipt_name = read_verification_receipt(bundle_root)
    except VerificationReceiptMissingError:
        # The bundle carries no receipt: nothing to link, and no error; the caller reports the
        # review reason. What was found reading the entry still holds and travels along.
        return RegistryLinkVerificationResult(
            registry_entry=entry,
            registry_entry_path=str(registry_entry_path),
            verification_receipt=None,
            verification_receipt_path_name=None,
            receipt_sha256_actual=None,
            checks=(_field_check_failed("registry_entry_contract", entry_error),) if entry_error is not None else (),
            notes=("verification_receipt_not_provided",),
            entry_error=entry_error,
            read_error=read_error,
            receipt_missing=True,
        )
    except RegistryLinkVerificationError as exc:
        receipt, receipt_name, receipt_error = None, "verification_receipt.json", str(exc)
    except OSError as exc:
        receipt, receipt_name = None, "verification_receipt.json"
        read_error = read_error or exc

    if entry is None or receipt is None:
        failed = []
        if entry_error is not None:
            failed.append(_field_check_failed("registry_entry_contract", entry_error))
        if receipt_error is not None:
            failed.append(_field_check_failed("verification_receipt_contract", receipt_error))
        return RegistryLinkVerificationResult(
            registry_entry=entry,
            registry_entry_path=str(registry_entry_path),
            verification_receipt=receipt,
            verification_receipt_path_name=receipt_name,
            receipt_sha256_actual=None,
            checks=tuple(failed),
            notes=("registry_link_signature_trust_inclusion_anchor_not_verified",),
            entry_error=entry_error,
            receipt_error=receipt_error,
            read_error=read_error,
        )

    try:
        receipt_sha = canonical_json_sha256(receipt)
    except CanonicalizationError as exc:
        # Not reachable from a document read under input strictness, whose rules make every document
        # canonicalizable (report-contract.md section 5.3); kept as a defense in depth.
        raise RegistryLinkVerificationError(f"verification_receipt_canonicalize_failed:{type(exc).__name__}") from exc

    notes: list[str] = []
    checks: list[RegistryLinkFieldCheck] = []

    # The public registry entry is validated against the generated contract HERE, on the
    # link path, as on the authorization path (trust_registry._registry_entry_shape_errors):
    # `read_registry_entry` checks only that the bytes parse into a dict, and an entry
    # violating registry_entry.schema.json (`object_type: "not_a_registry_entry"`, an
    # unbounded extra field against `additionalProperties: false`, a missing
    # `subject_ref_hash`) must not be reported as REGISTRY_ENTRY_LINK_VERIFIED. The link check
    # is the one the README puts in front of every reader, and a report that establishes
    # structure and link asserts the schema conformance the structure check is defined as.
    # It has to be computed before it can be asserted.
    #
    # The contract includes the entry's grounds: its verdict must be the verdict its reason
    # codes derive (verdict_grounds.py, VG-1 to VG-4), so an entry with verdict PASS citing a
    # fail-severity code does not link.
    checks.append(
        _field_check(
            "registry_entry_contract",
            [],
            registry_entry_contract_violations(entry),
            note="registry_entry_validated_against_generated_schema_contract",
        )
    )
    # The receipt the entry is compared against gets the same treatment, for the same reason,
    # and over the same predicate as the receipt's error row: its schema, its instants and its
    # free strings (registry-link.md section 7). A receipt refused for a free string made only
    # of W does not hold the link, so the trust registry is not evaluated beside it.
    checks.append(
        _field_check(
            "verification_receipt_contract",
            [],
            contract_errors("verification_receipt", receipt)
            + free_string_errors(receipt, "verification_receipt", VERIFICATION_RECEIPT_FREE_STRINGS),
            note="verification_receipt_validated_against_generated_schema_contract",
        )
    )

    # Every digest is compared as the whole self-describing string, label included, with the
    # label and the recomputed digest (canonicalization-and-hashing.md section 2): nothing is
    # stripped, and a bare or upper-case value never equals.
    registry_manifest_hash = _prefixed_sha256(entry.get("manifest_hash"))
    receipt_manifest_hash = _prefixed_sha256(receipt.get("manifest_sha256"))
    manifest_actual = labelled(manifest_result.manifest_sha256_actual) if manifest_result is not None else None
    checks.append(_field_check("manifest_hash", registry_manifest_hash, manifest_actual))
    checks.append(_field_check("receipt_manifest_sha256", receipt_manifest_hash, manifest_actual))

    registry_receipt_hash = _prefixed_sha256(entry.get("receipt_hash"))
    checks.append(_field_check("receipt_hash", registry_receipt_hash, labelled(receipt_sha)))

    # The receipt names a bundle and, optionally, a P1 digest. Both are tied to the bundle in
    # hand, or an authorized issuer could sign a receipt about a different bundle, or a P1
    # this bundle does not carry, and collect a PASS. Both are hard checks: the bundle_id
    # exactly equal to the manifest's (false when the manifest's is not a usable string), and
    # a non-null p1_sha256 equal to the verified P1 digest (false when P1 did not verify).
    manifest_bundle_id = usable_bundle_id(manifest_result.manifest) if manifest_result is not None else None
    receipt_bundle_id = receipt.get("bundle_id")
    checks.append(
        RegistryLinkFieldCheck(
            name="receipt_bundle_id",
            expected=manifest_bundle_id,
            actual=receipt_bundle_id,
            ok=manifest_bundle_id is not None and receipt_bundle_id == manifest_bundle_id,
        )
    )
    receipt_p1_sha256 = receipt.get("p1_sha256")
    p1_sha256_verified = labelled(p1_sha256_verified)
    checks.append(
        RegistryLinkFieldCheck(
            name="receipt_p1_sha256",
            expected=p1_sha256_verified,
            actual=receipt_p1_sha256,
            ok=receipt_p1_sha256 is None
            or (p1_sha256_verified is not None and receipt_p1_sha256 == p1_sha256_verified),
            note="not_asserted_by_receipt" if receipt_p1_sha256 is None else None,
        )
    )

    checks.append(_field_check("policy_id", _exact_str(entry.get("policy_id")), _exact_str(receipt.get("policy_id"))))

    registry_policy_version = _entry_policy_major(entry.get("policy_version"))
    receipt_policy_version = _receipt_policy_version(receipt.get("policy_version"))
    checks.append(
        _field_check(
            "policy_version",
            registry_policy_version,
            receipt_policy_version,
            note="semver_major_compared_to_receipt_integer",
        )
    )

    checks.append(
        _field_check(
            "reason_code_catalog_version",
            _exact_str(entry.get("reason_code_catalog_version")),
            _exact_str(receipt.get("reason_code_vocabulary_version")),
        )
    )
    checks.append(
        _field_check(
            "reason_codes",
            _normalize_reason_codes(entry.get("reason_codes")),
            _normalize_reason_codes(receipt.get("reason_codes")),
        )
    )
    checks.append(
        _field_check("asset_type", _exact_str(entry.get("asset_type")), _exact_str(receipt.get("asset_type")))
    )

    mapped_receipt_verdict = _map_receipt_status_to_verdict(receipt.get("status"))
    registry_verdict = _exact_str(entry.get("verdict"))
    checks.append(
        _field_check(
            "status_verdict",
            registry_verdict,
            mapped_receipt_verdict,
            note="receipt_status_mapped_to_registry_verdict_when_recognized",
        )
    )
    # `status_verdict` asks whether the two documents AGREE; it is satisfied by a receipt
    # and an entry that agree perfectly on FAIL. This check surfaces what they agree ABOUT,
    # so a reader scanning the checks list sees the committed verdict without decoding the
    # outcome block. It carries no ok of its own on purpose: a FAIL the two documents agree
    # on is an intact link, and letting this decide the link's status would report a
    # correctly linked bundle as a broken one. Whether the committed verdict is acceptable
    # is decided by the run, where it becomes registry_entry_verdict_fail or
    # registry_entry_verdict_requires_review.
    checks.append(
        RegistryLinkFieldCheck(
            name="registry_entry_verdict",
            expected=None,
            actual=registry_verdict,
            ok=registry_verdict is not None,
            note="committed_verdict_enforced_by_the_run_not_by_the_link_check",
        )
    )
    if mapped_receipt_verdict is None:
        notes.append("receipt_status_not_mapped_to_registry_verdict")

    if _exact_str(entry.get("receipt_id")):
        notes.append("registry_receipt_id_metadata_not_matched_by_receipt_schema")
    notes.append("registry_link_signature_trust_inclusion_anchor_not_verified")

    return RegistryLinkVerificationResult(
        registry_entry=entry,
        registry_entry_path=str(registry_entry_path),
        verification_receipt=receipt,
        verification_receipt_path_name=receipt_name,
        receipt_sha256_actual=receipt_sha,
        checks=tuple(checks),
        notes=tuple(dict.fromkeys(notes)),
    )
