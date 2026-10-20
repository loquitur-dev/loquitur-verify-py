"""End-to-end offline verification orchestration for the public CLI.

The runner wires together the extracted archive, manifest, P1 and envelope
cores, and orchestrates issuer-signature verification and trust-registry
validation when the caller supplies the material for them. The report shape it
defines carries those results: ``registry_signature``, ``trust_registry`` and
the root-signature fields among them.

It does not implement chain-anchor validation or online registry queries, and it
never fetches anything: every input arrives as a local path.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ._version import __version__
from .archive import (
    ArchiveLoadError,
    ArchiveReadError,
    ArchiveSafetyLimitError,
    BundleRootError,
    InvalidZipError,
    UnsafeZipMemberError,
    extracted_zip,
    find_bundle_root,
    is_zip_archive,
)
from .envelope import (
    EnvelopeVerificationError,
    EnvelopeVerificationResult,
    envelope_member_present,
    envelope_path,
    envelope_shape_errors_for,
    judged_envelope_sha256,
    read_envelope,
    verify_envelope,
)
from .evaluation_time import operator_evaluation_time
from .host_path import host_path
from .manifest import (
    MANIFEST_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION_GRAMMAR,
    STATUS_OFFLINE_FAIL,
    STATUS_OFFLINE_OK,
    STATUS_OFFLINE_REVIEW,
    ManifestVerificationError,
    ManifestVerificationResult,
    is_reserved_member,
    manifest_canonical_sha256,
    read_manifest,
    read_stored_manifest_sha256,
    verify_manifest,
)
from .members import (
    DIRECTORY,
    REGULAR_FILE,
    BundleInventory,
    BundleInventoryError,
    BundleMemberNameError,
    MemberTooLargeError,
    bundle_inventory,
    inspect_path,
    member_is_file,
    open_for_reading,
    read_member_bytes,
)
from .p1 import (
    P1VerificationError,
    P1VerificationResult,
    canonical_p1_bytes,
    read_canonical_input,
    read_p1,
    verified_p1_sha256,
    verify_p1,
)
from .registry_link import (
    RegistryEntryMissingError,
    RegistryLinkVerificationError,
    RegistryLinkVerificationResult,
    read_registry_entry,
    read_verification_receipt,
    registry_entry_contract_violations,
    verification_receipt_contract_violations,
    verify_registry_link,
)
from .trust_registry import (
    ROOT_NOT_EVALUATED_NOTE,
    ROOT_WINDOW_STATUSES,
    TrustRegistryVerificationError,
    TrustRegistryVerificationResult,
    read_trust_registry,
    verify_registry_entry_trust,
)
from .trust_root import (
    DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
    DOCUMENT_READ_FAILED,
    PINNED_TRUST_ROOTS,
    STATUS_NOT_EVALUATED,
    TrustRootDocumentUnreadableError,
    TrustRootKey,
    parse_trust_roots,
    trust_root_document_unsupported_version,
    validate_trust_roots,
)
from .vocabulary import KINDS as VOCABULARY_KINDS
from .vocabulary import UNKNOWN as VOCABULARY_UNKNOWN
from .vocabulary import HeldVocabulary, embedded_vocabulary, resolve_vocabularies, value_status

# The outcome table of report-contract.md section 3.1: three evidence outcomes (STATUS_OFFLINE_OK,
# STATUS_OFFLINE_REVIEW and STATUS_OFFLINE_FAIL, defined once in manifest.py), and three that are
# not about the evidence and carry no verdict.
STATUS_INTERNAL_ERROR = "INTERNAL_ERROR"
STATUS_UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
STATUS_HOST_FAILURE = "HOST_FAILURE"
VERDICT_PASS = "PASS"
VERDICT_REVIEW = "REVIEW"
VERDICT_FAIL = "FAIL"

EXIT_OFFLINE_OK = 0
EXIT_OFFLINE_FAIL = 1
EXIT_OFFLINE_REVIEW = 2
EXIT_INTERNAL_ERROR = 3
EXIT_UNSUPPORTED_VERSION = 4
EXIT_HOST_FAILURE = 5
EXIT_USAGE_ERROR = 64

# The checks of verification-checks.md, in their dependency order. transparency and anchoring are
# reserved: never requested, never reported.
CHECK_NAMES: tuple[str, ...] = ("structure", "integrity", "link", "authorization")

# The closed review-reason vocabulary of report-contract.md section 3.3, in its order.
REVIEW_REASONS: tuple[str, ...] = (
    "registry_entry_verdict_requires_review",
    "verification_receipt_not_provided",
    "evaluation_time_not_provided",
    "trust_registry_not_current",
    "issuer_key_outside_validity_window",
    "trust_root_outside_validity_window",
    "trust_registry_root_not_pinned",
    "bundle_reserved_member",
    "container_extra_files",
    "bundle_extra_files",
    "canonical_input_not_provided",
    "envelope_not_provided",
    "offline_review_required",
    "vocabulary_value_unknown",
)
# The review reasons that withhold the integrity check (report-contract.md section 3.2): the rows
# from bundle_reserved_member to offline_review_required. vocabulary_value_unknown is after them
# and withholds no check.
_INTEGRITY_REVIEW_REASONS = frozenset(
    REVIEW_REASONS[REVIEW_REASONS.index("bundle_reserved_member") : REVIEW_REASONS.index("offline_review_required") + 1]
)

OUTCOME_SUCCESS_LOCAL_INTEGRITY_ONLY = "success_local_integrity_only"
OUTCOME_SUCCESS_REGISTRY_LINK_VERIFIED = "success_registry_link_verified"
OUTCOME_SUCCESS_TRUST_REGISTRY_VERIFIED = "success_trust_registry_verified"
OUTCOME_PROOF_INTEGRITY_FAILURE = "proof_integrity_failure"
# An intact bundle whose issuer is not authorized is not a proof-integrity
# failure: reporting it as one would tell the reader the evidence is damaged when it
# is not. This is a machine-readable report field a consumer can branch on, so the
# distinction is carried in the wire contract and not only in the prose.
OUTCOME_ISSUER_AUTHORIZATION_FAILURE = "issuer_authorization_failure"
# The trust registry's own root could not be authenticated against a pinned root. This is
# deliberately not an issuer-authorization failure: when the registry is not authentic,
# nothing has been established about the issuer, and saying otherwise would be a claim of
# the verifier's own.
OUTCOME_TRUST_ROOT_AUTHENTICATION_FAILURE = "trust_root_authentication_failure"
# An intact bundle whose registry entry commits a verdict other than PASS. The evidence is
# consistent; the registry says it was examined and rejected. Reporting that as an
# integrity failure would blame the bundle for what the issuer published about it.
OUTCOME_REGISTRY_VERDICT_NOT_PASS = "registry_verdict_not_pass"
OUTCOME_ARCHIVE_SAFETY_FAILURE = "archive_safety_failure"
OUTCOME_MALFORMED_INPUT_FAILURE = "malformed_input_failure"
OUTCOME_UNSUPPORTED_INPUT_FAILURE = "unsupported_input_failure"
OUTCOME_INTERNAL_ERROR = "internal_error"
OUTCOME_WARNING_OR_REVIEW_STATE = "warning_or_review_state"
OUTCOME_HOST_FAILURE = "host_failure"
OUTCOME_UNSUPPORTED_VERSION = "unsupported_version"

NOT_IMPLEMENTED_CAPABILITIES: tuple[str, ...] = (
    "trust_registry_root_signature_verification",
    "registry_inclusion_or_finality_verification",
    "anchor_timestamp_or_chain_finality_verification",
    "revocation_or_supersession_verification",
    "valuation_correctness_verification",
    "kyc_aml_or_compliance_verification",
)


_EXIT_FOR_STATUS = {
    STATUS_OFFLINE_OK: EXIT_OFFLINE_OK,
    STATUS_OFFLINE_FAIL: EXIT_OFFLINE_FAIL,
    STATUS_OFFLINE_REVIEW: EXIT_OFFLINE_REVIEW,
    STATUS_INTERNAL_ERROR: EXIT_INTERNAL_ERROR,
    STATUS_UNSUPPORTED_VERSION: EXIT_UNSUPPORTED_VERSION,
    STATUS_HOST_FAILURE: EXIT_HOST_FAILURE,
}


def exit_code_for_status(status: str) -> int:
    return _EXIT_FOR_STATUS.get(status, EXIT_INTERNAL_ERROR)


@dataclass(frozen=True)
class OfflineVerificationReport:
    status: str
    # None for a status that is not an evidence outcome (report-contract.md section 3.1).
    verdict: str | None
    input_path: str
    input_type: str | None
    bundle_root_name: str | None
    manifest: ManifestVerificationResult | None = None
    p1: P1VerificationResult | None = None
    envelope: EnvelopeVerificationResult | None = None
    registry_link: RegistryLinkVerificationResult | None = None
    trust_registry: TrustRegistryVerificationResult | None = None
    notes: tuple[str, ...] = ()
    errors: tuple[dict[str, str], ...] = ()
    # Whether canonical_input.json was present in the bundle, observed while
    # the bundle root was still live. P1 verification aborts on a shape error before it
    # reaches this file, and a zip's extracted root is gone by reporting time, so the
    # observation cannot be recovered later: it has to be taken here or not at all.
    canonical_input_observed: bool | None = None
    # Whether the envelope member envelope_env1.json existed, observed the
    # same way and for the same reason: when envelope verification raises there is no
    # result object to carry the fact.
    envelope_observed: bool | None = None
    # Files of a ZIP container outside the bundle root that was selected in it, as sorted
    # POSIX names relative to the container.
    container_extra_files: tuple[str, ...] = ()
    # Whether the caller supplied a registry entry, which asks for the link check whatever became of it.
    registry_entry_supplied: bool = False
    # Whether the caller supplied a trust registry, and whether the input was refused as a whole
    # (report-contract.md section 5.3, input_not_found to filesystem_error), so that no layer
    # was evaluated.
    trust_registry_supplied: bool = False
    input_refused: bool = False
    # report-contract.md sections 3.2 and 3.3: the checks requested and established, the
    # informative checks evaluated, the review reasons that hold and the operator's evaluation time.
    checks_requested: tuple[str, ...] = ("structure", "integrity")
    checks_established: tuple[str, ...] = ()
    checks_evaluated: tuple[str, ...] = ()
    review_reasons: tuple[str, ...] = ()
    evaluation_time: str | None = None
    # The per-check results of a run a version gate stopped: nothing was evaluated.
    version_gated: bool = False
    # The registered vocabulary document held for each kind (verification-vocabularies.md section 8),
    # recorded in the informative member `vocabularies`. Empty means the embedded ones.
    vocabularies: tuple[HeldVocabulary, ...] = ()

    @property
    def exit_code(self) -> int:
        return exit_code_for_status(self.status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "loquitur-verify",
            "tool_version": __version__,
            "status": self.status,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "outcome": _outcome_dict(self),
            "checks_requested": list(self.checks_requested),
            "checks_established": list(self.checks_established),
            "checks_evaluated": list(self.checks_evaluated),
            "review_reasons": list(self.review_reasons),
            "evaluation_time": self.evaluation_time,
            "input": {
                "path": self.input_path,
                "type": self.input_type,
                "bundle_root_name": self.bundle_root_name,
                "container_extra_files": list(self.container_extra_files),
            },
            "checks": (
                _version_gated_checks()
                if self.version_gated
                else _refused_input_checks(self.registry_entry_supplied, self.trust_registry_supplied)
                if self.input_refused
                else _checks_dict(
                    self.manifest,
                    self.p1,
                    self.envelope,
                    self.registry_link,
                    self.trust_registry,
                    self.canonical_input_observed,
                    self.envelope_observed,
                )
            ),
            "manifest": _manifest_dict(self.manifest),
            "p1": _p1_dict(self.p1),
            "envelope": _envelope_dict(self.envelope),
            "registry": _registry_dict(
                self.envelope, self.registry_link, self.trust_registry, self.registry_entry_supplied
            ),
            "registry_link": _registry_link_dict(self.registry_link),
            "trust_registry": _trust_registry_dict(self.trust_registry),
            "notes": list(self.notes),
            "errors": list(self.errors),
            "vocabularies": _vocabularies_dict(self.vocabularies),
        }


def _vocabularies_dict(held: tuple[HeldVocabulary, ...]) -> dict[str, dict[str, str]]:
    """The informative member `vocabularies`: per kind, the version, digest and source held."""
    by_kind = {vocabulary.kind: vocabulary for vocabulary in held}
    return {kind: (by_kind.get(kind) or embedded_vocabulary(kind)).to_dict() for kind in VOCABULARY_KINDS}


def _outcome_dict(report: OfflineVerificationReport) -> dict[str, Any]:
    return {
        "category": _outcome_category(report),
        "reason": _primary_reason(report),
        "not_implemented_capabilities": _not_implemented_capabilities(report),
    }


def _not_implemented_capabilities(report: OfflineVerificationReport) -> list[str]:
    """The capabilities this run did not exercise, computed per run.

    trust_registry_root_signature_verification is omitted exactly when a pinned root
    verified the trust registry's signature in this run, so the list never contradicts
    trust_registry_root_signature_verified: true in the same report. Every other
    capability is always listed.
    """
    root_verified = report.trust_registry is not None and report.trust_registry.root_signature_verified is True
    return [
        capability
        for capability in NOT_IMPLEMENTED_CAPABILITIES
        if not (root_verified and capability == "trust_registry_root_signature_verification")
    ]


def _primary_reason(report: OfflineVerificationReport) -> str:
    if report.errors:
        first = report.errors[0]
        code = first.get("code")
        if code:
            return code
    if report.status == STATUS_OFFLINE_OK:
        if report.trust_registry is not None and report.trust_registry.trust_registry_verified:
            return "local_integrity_registry_link_and_trust_checks_passed"
        if report.registry_link is not None and report.registry_link.link_holds:
            return "local_integrity_and_registry_link_checks_passed"
        return "local_integrity_checks_passed"
    # Rule 5: the trust registry stopped at a row whose effect is a failure; rule 6: a link that
    # was evaluated and does not hold.
    if report.trust_registry is not None and report.trust_registry.failed:
        return "trust_registry_verification_failed"
    if report.registry_link is not None and not report.registry_link.link_holds:
        return "registry_link_verification_failed"
    if report.status == STATUS_OFFLINE_REVIEW:
        # Rule 7: the first entry of review_reasons.
        return report.review_reasons[0] if report.review_reasons else "offline_review_required"
    # report-contract.md section 5.2, rules 14 to 16: each names a layer that FAILED. A layer that is
    # only in review (P1 with the canonical input absent, an absent envelope) did not fail the run,
    # and naming it would blame the wrong layer: P1 in review beside a failed envelope is not
    # p1_integrity_failed.
    if report.manifest is not None and not report.manifest.ok:
        return "manifest_integrity_failed"
    if report.p1 is not None and report.p1.status == STATUS_OFFLINE_FAIL:
        return "p1_integrity_failed"
    if report.envelope is not None and report.envelope.status == STATUS_OFFLINE_FAIL:
        return "envelope_integrity_or_link_failed"
    return "offline_verification_failed"


def _outcome_category(report: OfflineVerificationReport) -> str:
    if report.errors:
        return _category_for_error_code(report.errors[0].get("code", ""))
    if report.status == STATUS_OFFLINE_OK:
        if report.trust_registry is not None and report.trust_registry.trust_registry_verified:
            return OUTCOME_SUCCESS_TRUST_REGISTRY_VERIFIED
        if report.registry_link is not None and report.registry_link.link_holds:
            return OUTCOME_SUCCESS_REGISTRY_LINK_VERIFIED
        return OUTCOME_SUCCESS_LOCAL_INTEGRITY_ONLY
    if report.status == STATUS_OFFLINE_REVIEW:
        return OUTCOME_WARNING_OR_REVIEW_STATE
    if report.status == STATUS_HOST_FAILURE:
        return OUTCOME_HOST_FAILURE
    if report.status == STATUS_OFFLINE_FAIL:
        # The integrity layers are checked first: if any of them failed, the bundle
        # really is inconsistent and that is the honest headline. Only when they all
        # hold is the failure attributable to the issuer's authority.
        if _integrity_layers_hold(report) and report.trust_registry is not None:
            return OUTCOME_ISSUER_AUTHORIZATION_FAILURE
        return OUTCOME_PROOF_INTEGRITY_FAILURE
    return OUTCOME_INTERNAL_ERROR


def _integrity_layers_hold(report: OfflineVerificationReport) -> bool:
    """True when manifest, P1 and envelope all verified.

    Deliberately conservative: an absent result counts as not holding, so a bundle whose
    integrity could not be established is never described as an authorization failure.
    """
    manifest, p1, envelope = report.manifest, report.p1, report.envelope
    if manifest is None or not manifest.ok:
        return False
    if p1 is None or p1.p1_sha256_ok is not True or p1.input_hash_ok is not True:
        return False
    if envelope is None or envelope.envelope_sha256_ok is False or envelope.links_ok is False:
        return False
    return True


# outcome.category of the first error (informative). A link inside a directory bundle is the
# same refusal as a symlink member of a ZIP.
_ARCHIVE_SAFETY_CODES: frozenset[str] = frozenset(
    {"archive_unsafe_member", "archive_safety_limit", "unsafe_bundle_member"}
)
# Content the caller supplied that breaks its contract, or a layer refused for it.
_MALFORMED_INPUT_CODES: frozenset[str] = frozenset(
    {
        "invalid_zip",
        "manifest_verification_failed",
        "p1_verification_failed",
        "envelope_verification_failed",
        "registry_link_verification_failed",
        "trust_registry_verification_failed",
        "verification_receipt_contract_violation",
        "bundle_member_name_invalid",
        "envelope_incomplete",
        "registry_entry_contract_violation",
        "trust_registry_requires_valid_registry_entry",
    }
)
# An input that is not a bundle, or an invocation that lacks the input a check needs.
_UNSUPPORTED_INPUT_CODES: frozenset[str] = frozenset(
    {"bundle_root_invalid", "unsupported_input", "trust_registry_requires_registry_entry"}
)


def _category_for_error_code(code: str) -> str:
    """The outcome category of an error code; every host code first (report-contract.md section 3.1).

    A trust root that did not authenticate the registry and a committed verdict of FAIL are
    categories of their own: neither is an integrity failure, and a byte-perfect bundle must not
    be reported as one. A code no category names is an integrity failure.
    """
    if code in HOST_ERROR_CODES:
        return OUTCOME_HOST_FAILURE
    if code == "unsupported_version":
        return OUTCOME_UNSUPPORTED_VERSION
    if code in _ARCHIVE_SAFETY_CODES:
        return OUTCOME_ARCHIVE_SAFETY_FAILURE
    if code in _MALFORMED_INPUT_CODES:
        return OUTCOME_MALFORMED_INPUT_FAILURE
    if code == "trust_registry_root_not_authenticated":
        return OUTCOME_TRUST_ROOT_AUTHENTICATION_FAILURE
    if code == "registry_entry_verdict_fail":
        return OUTCOME_REGISTRY_VERDICT_NOT_PASS
    if code in _UNSUPPORTED_INPUT_CODES:
        return OUTCOME_UNSUPPORTED_INPUT_FAILURE
    if code == "internal_error":
        return OUTCOME_INTERNAL_ERROR
    return OUTCOME_PROOF_INTEGRITY_FAILURE


_REGISTRY_ENTRY_CONTRACT_VIOLATIONS_REPORTED = 8


def _check_committed_registry_verdict(
    entry: dict[str, Any],
    notes: list[str],
    errors: list[dict[str, str]],
    unresolved: list[str],
) -> None:
    """Let the verdict the issuer published decide the verdict this tool reports.

    The link check asks whether the entry and the receipt AGREE, and they can agree
    perfectly on FAIL. An entry committing ``verdict: "FAIL"`` is a public statement that
    this evidence was examined and rejected, so it must not produce OFFLINE_OK / PASS /
    exit 0: a CI gate keyed on the exit code, which is the use the README recommends,
    would admit rejected evidence.
    """
    verdict = entry.get("verdict")
    if verdict == "PASS":
        return
    if verdict == "FAIL":
        notes.append("registry_entry_verdict_fail")
        errors.append(_error("registry_entry_verdict_fail"))
        return
    # WARN and REVIEW are the registry saying "not settled". So is a verdict outside the
    # four-value enum: an unrecognized verdict is a rejection, not a downgrade.
    notes.append("registry_entry_verdict_requires_review")
    unresolved.append("registry_entry_verdict_requires_review")


def _verdict_for_status(status: str) -> str | None:
    if status == STATUS_OFFLINE_OK:
        return VERDICT_PASS
    if status == STATUS_OFFLINE_REVIEW:
        return VERDICT_REVIEW
    if status == STATUS_OFFLINE_FAIL:
        return VERDICT_FAIL
    # No verdict on the evidence was computed (report-contract.md section 3.1).
    return None


def _safe_error_message(exc: BaseException) -> str | None:
    """Return a stable user-facing error reason without stack traces or host paths."""

    message = str(exc).strip()
    if not message:
        return None
    if isinstance(exc, ArchiveLoadError):
        return message
    if isinstance(
        exc, (ManifestVerificationError, P1VerificationError, EnvelopeVerificationError, RegistryLinkVerificationError)
    ):
        return message
    return None


# The error rows of report-contract.md section 5.3, in the order of its table. A run appends
# the error of each row whose condition holds, IN THE ORDER OF THE TABLE, and no code appears
# twice. That is a property of the report, not of the order in which this module happens to
# reach each condition: outcome.reason is the first code (section 5.2, rule 1), so a code
# emitted out of table order would name the wrong one. The list is projected onto the report
# once, at the end, and tests/test_spec_report_contract.py holds it to the table cell for cell.
ERROR_CODES: tuple[str, ...] = (
    "input_not_found",
    "invalid_zip",
    "archive_unsafe_member",
    "archive_safety_limit",
    "bundle_root_invalid",
    "archive_load_failed",
    "unsupported_input",
    "filesystem_error",
    "bundle_inventory_failed",
    "bundle_member_name_invalid",
    "unsafe_bundle_member",
    "manifest_verification_failed",
    "manifest_read_failed",
    "p1_verification_failed",
    "p1_read_failed",
    "envelope_verification_failed",
    "envelope_incomplete",
    "envelope_read_failed",
    "verification_receipt_contract_violation",
    "registry_link_verification_failed",
    "registry_entry_contract_violation",
    "registry_entry_verdict_fail",
    "registry_link_read_failed",
    "trust_registry_requires_registry_entry",
    "trust_registry_requires_valid_registry_entry",
    "trust_registry_read_failed",
    "trust_root_read_failed",
    "trust_registry_root_not_authenticated",
    "unsupported_version",
    "internal_error",
)

# The codes of report-contract.md section 5.3 whose class is host: the host failed an operation on
# the operator's path or on the verifier's working space, or found nothing at the path. Every
# other code but the two non-evidence ones is content.
HOST_ERROR_CODES: frozenset[str] = frozenset(
    {
        "input_not_found",
        "archive_load_failed",
        "filesystem_error",
        "bundle_inventory_failed",
        "manifest_read_failed",
        "p1_read_failed",
        "envelope_read_failed",
        "registry_link_read_failed",
        "trust_registry_read_failed",
        "trust_root_read_failed",
    }
)
NON_EVIDENCE_ERROR_CODES: frozenset[str] = frozenset({"unsupported_version", "internal_error"})

# Errors whose holding means the structure check is not established (report-contract.md section
# 3.2: the rows bundle_inventory_failed to verification_receipt_contract_violation).
_STRUCTURE_ERRORS: frozenset[str] = frozenset(
    ERROR_CODES[
        ERROR_CODES.index("bundle_inventory_failed") : ERROR_CODES.index("verification_receipt_contract_violation") + 1
    ]
)


def _in_table_order(errors: Sequence[dict[str, str]]) -> tuple[dict[str, str], ...]:
    """The errors as the table lists them: in its order, and no code twice.

    A code the table does not carry would be a vocabulary defect, which the specification
    suite fails on; it keeps its place at the end here rather than making a run raise.
    """

    order = {code: index for index, code in enumerate(ERROR_CODES)}
    first: dict[str, dict[str, str]] = {}
    for error in errors:
        first.setdefault(error.get("code", ""), error)
    return tuple(sorted(first.values(), key=lambda error: order.get(error.get("code", ""), len(order))))


def _error(code: str, exc: BaseException | None = None) -> dict[str, str]:
    out = {"code": code}
    if exc is not None:
        out["type"] = type(exc).__name__
        message = _safe_error_message(exc)
        if message:
            out["message"] = message
    return out


def _archive_error_code(exc: ArchiveLoadError) -> str:
    if isinstance(exc, ArchiveReadError):
        # The host failed to read the input itself; nothing about its bytes was established.
        return "filesystem_error"
    if isinstance(exc, UnsafeZipMemberError):
        return "archive_unsafe_member"
    if isinstance(exc, ArchiveSafetyLimitError):
        return "archive_safety_limit"
    if isinstance(exc, InvalidZipError):
        return "invalid_zip"
    if isinstance(exc, BundleRootError):
        return "bundle_root_invalid"
    return "archive_load_failed"


def internal_error_report(path: str | Path, exc: BaseException) -> OfflineVerificationReport:
    """Build a controlled CLI report for unexpected verifier exceptions.

    This is a CLI automation-safety boundary. It prevents raw stack traces from
    becoming normal user-facing output while preserving a non-zero internal-error
    exit code. It does not convert internal errors into proof-integrity failures
    and it does not imply issuer, trust-registry, registry-finality or anchor
    verification.
    """

    return OfflineVerificationReport(
        status=STATUS_INTERNAL_ERROR,
        verdict=None,
        input_path=str(path),
        input_type=None,
        bundle_root_name=None,
        notes=("internal_error",),
        errors=(_error("internal_error", exc),),
    )


def checks_requested_for(entry_supplied: bool, trust_supplied: bool) -> tuple[str, ...]:
    """report-contract.md section 3.2: what the caller supplied requests, and no option changes it."""
    requested = ["structure", "integrity"]
    if entry_supplied:
        requested.append("link")
    if trust_supplied:
        requested.append("authorization")
    return tuple(requested)


def unsupported_version_report(
    path: str | Path,
    object_name: str,
    version: str,
    *,
    input_type: str | None = None,
    registry_entry_supplied: bool = False,
    trust_registry_supplied: bool = False,
    evaluation_time: str | None = None,
) -> OfflineVerificationReport:
    """The report of a run a version gate stopped (report-contract.md section 5.5).

    The single error unsupported_version names the object and the identifier as read; nothing
    else is evaluated, and no acceptance option changes exit 4.
    """
    return OfflineVerificationReport(
        status=STATUS_UNSUPPORTED_VERSION,
        verdict=None,
        input_path=str(path),
        input_type=input_type,
        bundle_root_name=None,
        notes=(f"unsupported_version:{object_name}",),
        errors=(
            {
                "code": "unsupported_version",
                "object": object_name,
                "version": version,
                "message": f"{object_name} carries the unsupported version {version}",
            },
        ),
        registry_entry_supplied=registry_entry_supplied,
        trust_registry_supplied=trust_registry_supplied,
        checks_requested=checks_requested_for(registry_entry_supplied, trust_registry_supplied),
        evaluation_time=evaluation_time,
        version_gated=True,
    )


def _document_path_names_nothing(path: str | Path | None) -> bool:
    """True when ``path`` is supplied and nothing is found there (report-contract.md section 5.3).

    The path is read as it is written (host_path). A host failure to inspect it is not nothing
    found: it is reported by the check that reads the document, as its read failure.
    """
    if path is None:
        return False
    try:
        return inspect_path(host_path(path)) is None
    except OSError:
        return False


def _refused_input_report(
    input_path: Path,
    input_type: str | None,
    error: dict[str, str],
    *,
    entry_supplied: bool,
    trust_supplied: bool,
    evaluation_time: str | None,
    notes: tuple[str, ...] = (),
) -> OfflineVerificationReport:
    """A run whose input was refused as a whole (report-contract.md section 5.3): the one error.

    A host-class row is HOST_FAILURE, a content-class row OFFLINE_FAIL (section 3.1, rule 3).
    """
    host = error.get("code") in HOST_ERROR_CODES
    status = STATUS_HOST_FAILURE if host else STATUS_OFFLINE_FAIL
    return OfflineVerificationReport(
        status=status,
        verdict=_verdict_for_status(status),
        input_path=str(input_path),
        input_type=input_type,
        bundle_root_name=None,
        notes=notes,
        errors=(error,),
        registry_entry_supplied=entry_supplied,
        trust_registry_supplied=trust_supplied,
        input_refused=True,
        checks_requested=checks_requested_for(entry_supplied, trust_supplied),
        checks_evaluated=() if host else ("structure",),
        evaluation_time=evaluation_time,
    )


def verify_path(
    path: str | Path,
    *,
    registry_entry_path: str | Path | None = None,
    trust_registry_path: str | Path | None = None,
    evaluation_time: str | None = None,
    trust_roots: Sequence[TrustRootKey] | Any = PINNED_TRUST_ROOTS,
    vocabularies: Mapping[str, str | os.PathLike[str] | HeldVocabulary] | None = None,
) -> OfflineVerificationReport:
    """Verify a bundle directory or ZIP archive and return a stable report.

    ``vocabularies`` maps a kind of registered vocabulary (``asset_type``, ``workflow``,
    ``anchoring_method``) to the path of a vocabulary document the operator supplies, or to a
    ``HeldVocabulary``; every other kind is judged against the version built into this package
    (verification-vocabularies.md section 8). A supplied document is read and checked before any
    evidence: one that is refused raises ``VocabularyError`` and no report is returned.

    ``evaluation_time`` is the operator's evaluation time (trust-registry-authorization.md §2),
    a calendar instant of the form ``YYYY-MM-DDTHH:MM:SSZ``; any other value raises
    ``EvaluationTimeError`` before any evidence is read. Issuer dates are never read as a time:
    without it, authorization is not established (review reason evaluation_time_not_provided).

    ``trust_roots`` are the roots, as ``TrustRootKey`` values or as a trust-root document (a
    mapping, trust-root.md §3). They are validated as a whole before anything is read: one
    malformed root raises ``TrustRootError`` and no report is returned, as the command line exits
    64 for the document. A document of a well-formed version this verifier does not support is
    not malformed: the report is UNSUPPORTED_VERSION, exit 4 (report-contract.md §5.5).

    A host that reads the trust-root document itself passes, in its place,
    ``DOCUMENT_PATH_NAMES_NO_REGULAR_FILE`` when the path names no regular file, which raises
    ``TrustRootDocumentUnreadableError`` as a malformed document does, or ``DOCUMENT_READ_FAILED``
    when it failed to read the regular file: the run then reports the host failure
    trust_root_read_failed and does not evaluate root authentication (report-contract.md §4 and
    §5.3, trust-root.md §3).
    """

    if evaluation_time is not None:
        evaluation_time = operator_evaluation_time(evaluation_time)
    held = resolve_vocabularies(vocabularies)
    report = _verify_path(
        path,
        registry_entry_path=registry_entry_path,
        trust_registry_path=trust_registry_path,
        evaluation_time=evaluation_time,
        trust_roots=trust_roots,
        held=held,
    )
    return replace(report, vocabularies=tuple(held[kind] for kind in VOCABULARY_KINDS))


def _verify_path(
    path: str | Path,
    *,
    registry_entry_path: str | Path | None,
    trust_registry_path: str | Path | None,
    evaluation_time: str | None,
    trust_roots: Sequence[TrustRootKey] | Any,
    held: Mapping[str, HeldVocabulary],
) -> OfflineVerificationReport:
    entry_supplied = registry_entry_path is not None
    trust_supplied = trust_registry_path is not None
    if trust_roots is DOCUMENT_PATH_NAMES_NO_REGULAR_FILE:
        raise TrustRootDocumentUnreadableError("the trust-root document's path names no regular file")
    roots_read_failed = trust_roots is DOCUMENT_READ_FAILED
    if roots_read_failed:
        trust_roots = ()
    if isinstance(trust_roots, Mapping):
        unsupported = trust_root_document_unsupported_version(trust_roots)
        if unsupported is not None:
            # Gate 1 runs at invocation, before any evidence.
            return unsupported_version_report(
                path,
                "trust_root_document",
                unsupported,
                registry_entry_supplied=entry_supplied,
                trust_registry_supplied=trust_supplied,
                evaluation_time=evaluation_time,
            )
        trust_roots = parse_trust_roots(trust_roots)
    trust_roots = validate_trust_roots(trust_roots)
    input_path = Path(path)
    input_type: str | None = None
    notes: list[str] = []
    errors: list[dict[str, str]] = []

    # The input is read as it is written (host_path): on Windows in the file namespace, so no
    # name loses a trailing dot or space, NUL in a directory is an entry of that name and not the
    # null device, and an input longer than MAX_PATH is found (report-contract.md section 5.3).
    # The report still names the path as it was given.
    #
    # The input is inspected once, links followed. Nothing found there is input_not_found, and
    # any other failure of the host is filesystem_error, a refusal of the input itself
    # (report-contract.md section 5.3). Path.exists() is not used: which host failures it reads
    # as a missing input depends on the Python version.
    # Taken from ``path`` itself: Path("") is Path("."), so a Path would verify the empty path,
    # which names nothing, as the working directory. The string is inspected, not a Path: pathlib
    # gives a device path such as \\.\C: a separator after it, which names the drive's root
    # directory instead of the volume. A directory's or a regular file's path survives the Path.
    host_text = host_path(path)
    host_input = Path(host_text)
    input_kind: str | None
    refused: dict[str, Any] = {
        "entry_supplied": entry_supplied,
        "trust_supplied": trust_supplied,
        "evaluation_time": evaluation_time,
    }
    # Nothing found at the path of a supplied registry entry or trust registry refuses the run as
    # a whole, as nothing found at the input does: input_not_found is the first row of the
    # whole-input refusals (report-contract.md section 5.3), so it is reported before whatever
    # else the input would have given. Something found that is not a regular file, and a host
    # failure to inspect the path, are left to the check that reads the document.
    if any(_document_path_names_nothing(document) for document in (registry_entry_path, trust_registry_path)):
        return _refused_input_report(input_path, None, _error("input_not_found"), notes=("input_not_found",), **refused)
    try:
        input_kind = inspect_path(host_text)
    except OSError as exc:
        return _refused_input_report(input_path, None, _error("filesystem_error", exc), **refused)
    if input_kind is None:
        return _refused_input_report(input_path, None, _error("input_not_found"), notes=("input_not_found",), **refused)

    try:
        if input_kind == DIRECTORY:
            input_type = "directory"
            # The directory given is the bundle root, or it is not a bundle (bundle-objects.md
            # section 1). A parent directory holding one bundle folder is not searched:
            # whatever else the parent held would be neither verified nor reported, and a
            # wrapper with an uncommitted file beside the bundle would verify OFFLINE_OK.
            # The marker is matched exactly.
            if "manifest.json" not in os.listdir(host_input):
                raise BundleRootError("bundle_root_marker_missing")
            bundle_root = host_input
            return _verify_bundle_root(
                input_path,
                input_type,
                bundle_root,
                registry_entry_path=registry_entry_path,
                trust_registry_path=trust_registry_path,
                evaluation_time=evaluation_time,
                trust_roots=trust_roots,
                roots_read_failed=roots_read_failed,
                bundle_root_name=bundle_root.name,
                held=held,
            )
        if input_kind == REGULAR_FILE:
            input_type = "zip"
            # A host that fails to read the archive refuses the input itself: the OSError is
            # filesystem_error below. zipfile.is_zipfile is not used: it answers False for a read
            # that failed, which would report an archive the host held locked as invalid_zip, a
            # finding about bytes nobody read.
            _read_through(host_input)
            # is_zip_archive is metadata-only and avoids extracting non-ZIP inputs.
            if not is_zip_archive(host_input):
                return _refused_input_report(
                    input_path, input_type, _error("invalid_zip"), notes=("invalid_zip",), **refused
                )
            with extracted_zip(host_input) as extracted:
                bundle_root = find_bundle_root(extracted)
                # A ZIP may hold the bundle in one top-level folder, and the archive is the
                # delivered evidence: a file beside that folder is part of the delivery and
                # no part of the bundle, so it is reported.
                container_extra: tuple[str, ...] = ()
                if bundle_root != extracted:
                    prefix = bundle_root.relative_to(extracted).as_posix() + "/"
                    listing = bundle_inventory(extracted)
                    container_extra = tuple(
                        name for name in (*listing.files, *listing.links) if not name.startswith(prefix)
                    )
                return _verify_bundle_root(
                    input_path,
                    input_type,
                    bundle_root,
                    registry_entry_path=registry_entry_path,
                    trust_registry_path=trust_registry_path,
                    evaluation_time=evaluation_time,
                    trust_roots=trust_roots,
                    roots_read_failed=roots_read_failed,
                    container_extra_files=tuple(sorted(container_extra)),
                    # The archive's top level has no name: the extraction directory's is a
                    # random host temporary name, and two runs over one archive would differ.
                    bundle_root_name=None if bundle_root == extracted else bundle_root.name,
                    held=held,
                )
        # Something is there and it is neither a directory nor a regular file: a FIFO, a
        # socket, or on Windows a device name such as `nul`. The error is appended here: a
        # report with OFFLINE_FAIL and no error would make _outcome_category report
        # proof_integrity_failure for a bundle that was never opened.
        notes.append("unsupported_input")
        errors.append(_error("unsupported_input"))
    except ArchiveLoadError as exc:
        errors.append(_error(_archive_error_code(exc), exc))
    except OSError as exc:
        errors.append(_error("filesystem_error", exc))

    return _refused_input_report(input_path, input_type, _in_table_order(errors)[0], notes=tuple(notes), **refused)


def _read_through(path: Path) -> None:
    """Read every byte of ``path``, keeping none, so a host that fails to read it raises here."""
    with open_for_reading(path) as handle:
        while handle.read(_READ_THROUGH_CHUNK):
            pass


_READ_THROUGH_CHUNK = 1024 * 1024


def _observed(observe: Callable[[], bool]) -> bool:
    """An informative observation that a member is present: False when the host fails to make it.

    A presence flag records what the verifier saw (bundle-objects.md section 6): a member the
    host lets it find is present even when the host then fails to read it, and a member the host
    does not let it inspect was not seen. The failure itself is reported by the layer that reads
    the member, as that layer's ``*_read_failed`` error, and is not allowed to escape from here,
    where verify_path would take it for a refusal of the input itself.
    """
    try:
        return observe()
    except OSError:
        return False


# The members a layer reads whatever else refuses it (bundle-objects.md section 6). The manifest
# layer also reads every member manifest.files declares once it accepts the manifest, and
# verify_manifest reads those itself: a manifest it refuses declares nothing it reads. The
# envelope layer reads envelope_env1.json and its sidecar only: envelope.json is an ordinary
# member name (bundle-objects.md section 4), never read as an envelope.
_MANIFEST_MEMBERS = ("manifest.json", "manifest.sha256")
_P1_MEMBERS = ("p1.json", "p1.sha256", "canonical_input.json")
_ENVELOPE_MEMBERS = ("envelope_env1.json", "envelope.sha256")


def _host_read_failure(bundle_root: Path, names: Sequence[str]) -> OSError | None:
    """The host's failure to read one of the members ``names`` the verifier finds, or None.

    Each layer reads the members it finds whatever else refuses it, and a host failure on one
    is the layer's ``*_read_failed`` row, judged on its own: a layer refused for what one member
    holds still reports the host failing to read another (report-contract.md section 5.3). A
    member over the per-member bound is judged by its size and not read, as the layers judge it.
    """
    for name in names:
        try:
            if member_is_file(bundle_root, name):
                read_member_bytes(bundle_root, name)
        except MemberTooLargeError:
            continue
        except OSError as exc:
            return exc
    return None


def _envelope_read_failure(bundle_root: Path) -> OSError | None:
    """The host's failure to read the envelope or its sidecar, whichever of them is present."""
    return _host_read_failure(bundle_root, _ENVELOPE_MEMBERS)


def _manifest_refusal(bundle_root: Path) -> ManifestVerificationError | None:
    """manifest_verification_failed, judged over the manifest members the host did read.

    Used when the host failed to read a member the manifest layer reads. The row is judged on
    its own (report-contract.md section 5.3): a manifest that is not strict JSON is refused
    whether or not the host could read its sidecar, and a sidecar that is not a regular member
    whether or not it could read the manifest. The rules are the manifest layer's own (its
    readers and manifest_canonical_sha256), applied to the members the host did read.
    """
    manifest: dict[str, Any] | None = None
    try:
        manifest = read_manifest(bundle_root)
    except ManifestVerificationError as exc:
        return exc
    except OSError:
        pass
    try:
        read_stored_manifest_sha256(bundle_root)
    except ManifestVerificationError as exc:
        return exc
    except OSError:
        pass
    if manifest is not None:
        try:
            manifest_canonical_sha256(manifest)
        except ManifestVerificationError as exc:
            return exc
    return None


def _p1_refusal(bundle_root: Path) -> P1VerificationError | None:
    """p1_verification_failed, judged over the P1 members the host did read.

    Used when the host failed to read a member the P1 layer reads: a P1 that breaks its contract
    is refused whether or not the host could read the canonical input, and a canonical input
    that is not a strict JSON object whether or not it could read P1.
    """
    try:
        canonical_p1_bytes(read_p1(bundle_root))
    except P1VerificationError as exc:
        return exc
    except OSError:
        pass
    try:
        read_canonical_input(bundle_root)
    except P1VerificationError as exc:
        return exc
    except OSError:
        pass
    return None


def _envelope_refusal(bundle_root: Path) -> EnvelopeVerificationError | None:
    """envelope_verification_failed, judged over the envelope members the host did read.

    Used when the host failed to read a member the envelope layer reads: a bundle carrying both
    envelope names is refused whatever the host read, and an envelope beside its sidecar that is
    not a strict JSON object, or satisfies its contract and cannot be canonicalized, is refused
    whether or not the host could read the sidecar. The rules are the envelope layer's own (its
    readers and judged_envelope_sha256), applied to the members the host did read.
    """
    try:
        envelope_path(bundle_root)
        present = envelope_member_present(bundle_root)
        sidecar = member_is_file(bundle_root, "envelope.sha256")
    except EnvelopeVerificationError as exc:
        return exc
    except OSError:
        return None
    if not (present and sidecar):
        return None
    try:
        envelope, _name = read_envelope(bundle_root)
    except EnvelopeVerificationError as exc:
        return exc
    except OSError:
        return None
    try:
        judged_envelope_sha256(envelope, shape_ok=not envelope_shape_errors_for(envelope))
    except EnvelopeVerificationError as exc:
        return exc
    return None


@dataclass(frozen=True)
class _StageRows:
    """The errors and the notes one stage adds to the run, each in the order the stage adds them."""

    errors: tuple[dict[str, str], ...] = ()
    notes: tuple[str, ...] = ()


def _inventory_stage(bundle_root: Path) -> tuple[BundleInventory | BundleInventoryError, _StageRows]:
    """The bundle's enumeration, or why it failed, and the rows it adds.

    The whole bundle is enumerated, without following anything, before any member is read. A
    symbolic link, a junction or any other reparse point anywhere in a directory bundle fails the
    run, as a symlink member of a ZIP does: a link lets a name inside the bundle stand for bytes
    outside it, or for another member, and a read follows it.
    """
    try:
        inventory = bundle_inventory(bundle_root)
    except BundleMemberNameError as exc:
        # A listed name that is not a portable member name, or two that conflict: content.
        return exc, _StageRows(errors=(_error("bundle_member_name_invalid", exc),))
    except BundleInventoryError as exc:
        # Not manifest_read_failed: a loop or a dangling junction is not a failure to read a
        # byte-perfect manifest.
        return exc, _StageRows(errors=(_error("bundle_inventory_failed", exc),))
    if not inventory.links:
        return inventory, _StageRows()
    return inventory, _StageRows(
        errors=(_error("unsafe_bundle_member"),),
        notes=tuple(f"unsafe_bundle_member:link:{name}" for name in inventory.links),
    )


def _manifest_stage(
    bundle_root: Path, inventory: BundleInventory | BundleInventoryError
) -> tuple[ManifestVerificationResult | None, _StageRows]:
    """The manifest layer's result, or None when it is refused or unread, and the rows it adds.

    The layer reads the run's enumeration, a failed one included, and never walks the bundle again.

    The read row and the verification row are each judged on their own (report-contract.md
    section 5.3): a refusal still reports the host failing to read another manifest member, and a
    host failure still reports a refusal of what the host did read.
    """
    try:
        if isinstance(inventory, BundleInventoryError):
            manifest_result = verify_manifest(bundle_root, inventory_error=str(inventory))
        else:
            manifest_result = verify_manifest(bundle_root, inventory=inventory)
    except ManifestVerificationError as exc:
        errors = [_error("manifest_verification_failed", exc)]
        manifest_read_error = _host_read_failure(bundle_root, _MANIFEST_MEMBERS)
        if manifest_read_error is not None:
            errors.append(_error("manifest_read_failed", manifest_read_error))
        return None, _StageRows(errors=tuple(errors))
    except OSError as exc:
        errors = [_error("manifest_read_failed", exc)]
        manifest_refusal = _manifest_refusal(bundle_root)
        if manifest_refusal is not None:
            errors.append(_error("manifest_verification_failed", manifest_refusal))
        return None, _StageRows(errors=tuple(errors))
    if not manifest_result.ok:
        return manifest_result, _StageRows(notes=("manifest_integrity_failed",))
    if manifest_result.extra_files:
        # The manifest is the inventory the receipt commits to. A member outside it is
        # reported, or a bundle could carry arbitrary extra content and still report PASS
        # with every check true. The names are in manifest.extra_files.
        return manifest_result, _StageRows(notes=("bundle_extra_files",))
    return manifest_result, _StageRows()


def _p1_stage(bundle_root: Path) -> tuple[P1VerificationResult | None, _StageRows]:
    """The P1 layer's result, or None when it is refused or unread, and the rows it adds.

    The read row and the verification row are each judged on their own, as for the manifest.
    """
    try:
        p1_result = verify_p1(bundle_root)
    except P1VerificationError as exc:
        errors = [_error("p1_verification_failed", exc)]
        p1_read_error = _host_read_failure(bundle_root, _P1_MEMBERS)
        if p1_read_error is not None:
            errors.append(_error("p1_read_failed", p1_read_error))
        return None, _StageRows(errors=tuple(errors))
    except OSError as exc:
        errors = [_error("p1_read_failed", exc)]
        p1_refusal = _p1_refusal(bundle_root)
        if p1_refusal is not None:
            errors.append(_error("p1_verification_failed", p1_refusal))
        return None, _StageRows(errors=tuple(errors))
    return p1_result, _StageRows(notes=tuple(p1_result.notes))


def _envelope_stage(
    bundle_root: Path,
    *,
    manifest_result: ManifestVerificationResult | None,
    p1_result: P1VerificationResult | None,
    p1_digest_verified: str | None,
    entry_supplied: bool,
) -> tuple[EnvelopeVerificationResult | None, _StageRows]:
    """The envelope layer's result, or None when it is refused or unread, and the rows it adds.

    The read row and the verification row are each judged on their own, as for the manifest. The
    envelope layer reads the envelope and its sidecar whenever either is present (bundle-objects.md
    section 6), also when it lacks the other and verifies neither. Exactly one of the two
    (bundle-objects.md section 4) is envelope_incomplete, judged on its own after the layer's rows.
    """
    envelope_result: EnvelopeVerificationResult | None = None
    errors: list[dict[str, str]] = []
    notes: tuple[str, ...] = ()
    try:
        envelope_result = verify_envelope(
            bundle_root,
            manifest_result=manifest_result,
            p1_result=p1_result,
            p1_sha256_verified=p1_digest_verified if p1_result is None else None,
        )
        envelope_read_error = _envelope_read_failure(bundle_root)
        if envelope_read_error is not None:
            envelope_result = None
            raise envelope_read_error
        notes = envelope_result.notes
        if entry_supplied:
            notes = tuple(note for note in notes if note != "registry_entry_not_provided")
    except EnvelopeVerificationError as exc:
        errors.append(_error("envelope_verification_failed", exc))
        envelope_read_error = _envelope_read_failure(bundle_root)
        if envelope_read_error is not None:
            errors.append(_error("envelope_read_failed", envelope_read_error))
    except OSError as exc:
        errors.append(_error("envelope_read_failed", exc))
        envelope_refusal = _envelope_refusal(bundle_root)
        if envelope_refusal is not None:
            errors.append(_error("envelope_verification_failed", envelope_refusal))
    if _observed(lambda: member_is_file(bundle_root, "envelope_env1.json")) != _observed(
        lambda: member_is_file(bundle_root, "envelope.sha256")
    ):
        errors.append(_error("envelope_incomplete"))
    return envelope_result, _StageRows(errors=tuple(errors), notes=notes)


@dataclass(frozen=True)
class _LinkStage:
    """What the link stage found, and the rows and review conditions it adds."""

    result: RegistryLinkVerificationResult | None = None
    receipt_missing: bool = False
    entry_missing: bool = False
    receipt_uncanonicalisable: bool = False
    unresolved: tuple[str, ...] = ()
    rows: _StageRows = _StageRows()
    # The entry when the run judged its contract (both the entry and the receipt are objects,
    # report-contract.md section 5.3) and it holds: the one whose registered values are judged.
    judged_entry: dict[str, Any] | None = None


def _receipt_stage(bundle_root: Path) -> tuple[list[str] | None, bool, _StageRows]:
    """The receipt's contract violations (None when it was not read), whether the host failed to read it, and the rows.

    The receipt is a document the link reads, and a host failure to read it is
    registry_link_read_failed whichever checks are requested (report-contract.md section 5.3),
    not a contract violation: nothing about the document was established. A present receipt
    that breaks its closed contract is refused whichever checks are requested, not only when a
    registry entry is supplied: it is a document in the bundle, refused whether or not anything
    goes on to compare it.
    """
    try:
        receipt_violations = verification_receipt_contract_violations(bundle_root)
    except OSError as exc:
        return None, True, _StageRows(errors=(_error("registry_link_read_failed", exc),))
    if not receipt_violations:
        return receipt_violations, False, _StageRows()
    return (
        receipt_violations,
        False,
        _StageRows(
            errors=(_error("verification_receipt_contract_violation"),),
            notes=tuple(
                f"verification_receipt_contract_violation:{violation}"
                for violation in receipt_violations[:_REGISTRY_ENTRY_CONTRACT_VIOLATIONS_REPORTED]
            ),
        ),
    )


def _link_stage(
    bundle_root: Path,
    *,
    registry_entry_path: str | Path,
    manifest_result: ManifestVerificationResult | None,
    p1_digest_verified: str | None,
    receipt_violations: list[str] | None,
    receipt_read_failed: bool,
) -> _LinkStage:
    """The registry link of a run given a registry entry (registry-link.md), and the rows it adds."""
    # A host failure to read one of the two documents the link reads leaves the link with
    # no conclusion (the report's registry_link stays null, bundle-objects.md section 6 and
    # registry-link.md section 5), but it refuses nothing by itself. Every other condition of
    # report-contract.md section 5.3 is judged on the inputs it names, so an entry that
    # is not a registry entry at all, and an entry committing FAIL, are still reported.
    link_read_error: OSError | None = None
    registry_link_result: RegistryLinkVerificationResult | None = None
    judged_entry: dict[str, Any] | None = None
    receipt_missing = False
    entry_missing = False
    receipt_uncanonicalisable = False
    errors: list[dict[str, str]] = []
    notes: list[str] = []
    unresolved: list[str] = []
    try:
        link_result = verify_registry_link(
            bundle_root,
            registry_entry_path=registry_entry_path,
            manifest_result=manifest_result,
            p1_sha256_verified=p1_digest_verified,
        )
        link_read_error = link_result.read_error
        receipt_missing = link_result.receipt_missing
        if link_read_error is None and not receipt_missing:
            registry_link_result = link_result
        notes.extend(link_result.notes)
        if not link_result.link_holds and link_result.entry_error is not None:
            # A supplied entry that is not a registry entry at all: invalid JSON, JSON
            # null, an array. The link is false, and this is why.
            errors.append(
                {
                    "code": "registry_link_verification_failed",
                    "type": "RegistryLinkVerificationError",
                    "message": link_result.entry_error,
                }
            )
        elif not link_result.link_holds:
            # Name the reason, not just the layer. `registry_link.py` runs the
            # registry entry through `contract_errors` as a hard check, so when that
            # is the check that failed the honest error is a malformed input, not a
            # generic link failure, and `_outcome_category` maps the two differently:
            # one is `malformed_input_failure`, the other falls through to
            # `proof_integrity_failure`, which would blame a byte-perfect bundle for a
            # defect in the document handed alongside it.
            violations = next(
                (
                    check.actual
                    for check in link_result.checks
                    if check.name == "registry_entry_contract" and check.ok is not True
                ),
                None,
            )
            if violations is None and (receipt_violations or link_read_error is not None):
                # The receipt failed the link (its contract, or a host that refused to
                # read it), and that error is already reported. The link itself refuses
                # nothing here, so it says nothing.
                pass
            elif violations is not None and not receipt_missing:
                errors.append(_error("registry_entry_contract_violation"))
                # Name the violated keywords, not just the fact that something was
                # violated. `registry_entry_contract_violation` alone tells a reader that
                # the document they handed over is not a registry entry without telling
                # them which field to look at; the cap keeps a wholly unrelated JSON
                # document from burying every other note under its own field list.
                for violation in list(violations)[:_REGISTRY_ENTRY_CONTRACT_VIOLATIONS_REPORTED]:
                    notes.append(f"registry_entry_contract_violation:{violation}")
            elif not receipt_missing:
                notes.append("registry_link_verification_failed")
        # Only an entry that satisfies its contract commits a verdict, so the committed verdict
        # is read only from an entry that parsed and validated (registry-link.md section 6).
        # An entry refused for its contract reports neither registry_entry_verdict_fail nor a
        # review over a verdict it has not validly committed.
        if link_result.registry_entry is not None and not registry_entry_contract_violations(
            link_result.registry_entry
        ):
            _check_committed_registry_verdict(link_result.registry_entry, notes, errors, unresolved)
            if link_result.verification_receipt is not None:
                judged_entry = link_result.registry_entry
    except RegistryLinkVerificationError as exc:
        errors.append(_error("registry_link_verification_failed", exc))
        if isinstance(exc, RegistryEntryMissingError):
            entry_missing = True
        elif "canonicalize" in str(exc):
            receipt_uncanonicalisable = True
        # A read that failed before the refusal: both conditions hold (section 5.3).
        link_read_error = exc.read_error
    except OSError as exc:
        # A host failure the link makes that is not one of the two documents it reads.
        link_read_error = exc
    if link_read_error is not None and not receipt_read_failed:
        # A receipt the host could not read was reported by the receipt stage; a code is emitted once.
        errors.append(_error("registry_link_read_failed", link_read_error))
    return _LinkStage(
        result=registry_link_result,
        receipt_missing=receipt_missing,
        entry_missing=entry_missing,
        receipt_uncanonicalisable=receipt_uncanonicalisable,
        unresolved=tuple(unresolved),
        rows=_StageRows(errors=tuple(errors), notes=tuple(notes)),
        judged_entry=judged_entry,
    )


def _unknown_values(
    bundle_root: Path,
    receipt_violations: list[str] | None,
    judged_entry: dict[str, Any] | None,
    held: Mapping[str, HeldVocabulary],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The governed members whose value the held vocabulary does not register, and the notes.

    verification-vocabularies.md section 7: a receipt that satisfies its contract is judged at
    `asset_type`, and an entry whose contract the run judged and that holds it at `asset_type` and
    `workflow`; each unknown value is the review reason vocabulary_value_unknown. An unknown
    `anchor.method` is noted and decides nothing: the anchor is outside the signature.
    """
    members: list[str] = []
    notes: list[str] = []
    if receipt_violations == []:
        try:
            receipt, _name = read_verification_receipt(bundle_root)
        except (RegistryLinkVerificationError, OSError):
            receipt = None
        if receipt is not None and value_status(receipt.get("asset_type"), held["asset_type"]) == VOCABULARY_UNKNOWN:
            members.append("verification_receipt.asset_type")
    if judged_entry is not None:
        for member, kind in (("asset_type", "asset_type"), ("workflow", "workflow")):
            if value_status(judged_entry.get(member), held[kind]) == VOCABULARY_UNKNOWN:
                members.append(f"registry_entry.{member}")
        anchor = judged_entry.get("anchor")
        method = anchor.get("method") if isinstance(anchor, dict) else None
        if method is not None and value_status(method, held["anchoring_method"]) == VOCABULARY_UNKNOWN:
            notes.append("vocabulary_value_unknown:registry_entry.anchor.method")
    notes.extend(f"vocabulary_value_unknown:{member}" for member in members)
    return tuple(members), tuple(notes)


@dataclass(frozen=True)
class _TrustStage:
    """What the trust stage found, and the rows it adds.

    ``unsupported_version`` is the trust registry's version when version gate 8 fired: the run
    stops there and reports that gate alone.
    """

    result: TrustRegistryVerificationResult | None = None
    root_failed: bool = False
    root_window: bool = False
    unsupported_version: str | None = None
    rows: _StageRows = _StageRows()


def _trust_stage(
    trust_registry_path: str | Path,
    *,
    registry_entry_supplied: bool,
    registry_link_result: RegistryLinkVerificationResult | None,
    entry_missing: bool,
    receipt_uncanonicalisable: bool,
    trust_roots: Sequence[TrustRootKey],
    roots_read_failed: bool,
    roots_supplied: bool,
    evaluation_time: str | None,
) -> _TrustStage:
    """The authorization of a run given a trust registry (trust-registry-authorization.md), and the rows it adds."""
    errors: list[dict[str, str]] = []
    notes: list[str] = []
    if not registry_entry_supplied:
        return _TrustStage(rows=_StageRows(errors=(_error("trust_registry_requires_registry_entry"),)))
    if roots_read_failed:
        # report-contract.md section 5.3: a trust-root document the host failed to read is
        # a host failure, judged on its own; root authentication is not evaluated
        # (trust-root.md section 3), and nothing about the roots is reported as a finding.
        errors.append(_error("trust_root_read_failed"))
    trust_registry_result: TrustRegistryVerificationResult | None = None
    root_failed = False
    root_window = False
    if (
        registry_link_result is not None
        and registry_link_result.registry_entry is not None
        and registry_link_result.link_holds
    ):
        # Gate 8: the trust registry's version, read when it is read (the link holds).
        trust_gate = _trust_registry_gate(trust_registry_path)
        if trust_gate is not None:
            return _TrustStage(unsupported_version=trust_gate)
        try:
            trust_registry_result = verify_registry_entry_trust(
                registry_link_result.registry_entry,
                trust_registry_path=trust_registry_path,
                trust_roots=trust_roots,
                evaluation_time=evaluation_time,
            )
        except OSError as exc:
            # The host failed to read the trust registry: it is not evaluated, the
            # report's trust_registry stays null, and the run is HOST_FAILURE unless
            # something else fails (report-contract.md section 5.3,
            # trust_registry_read_failed). It is never INVALID_TRUST_REGISTRY, a finding
            # about bytes nobody read.
            errors.append(_error("trust_registry_read_failed", exc))
        if trust_registry_result is not None and roots_read_failed and trust_registry_result.authorization_holds:
            # Root authentication was not evaluated: the roots were never read.
            trust_registry_result = replace(
                trust_registry_result,
                root_signature_verified=False,
                root_signature_status=STATUS_NOT_EVALUATED,
                root_key_id=None,
                notes=tuple(
                    ROOT_NOT_EVALUATED_NOTE if note.startswith("trust_registry_root_signature_not_verified:") else note
                    for note in trust_registry_result.notes
                ),
            )
        if trust_registry_result is not None:
            notes.extend(trust_registry_result.notes)
            root_status = trust_registry_result.root_signature_status
            if trust_registry_result.failed:
                notes.append("trust_registry_verification_failed")
            elif trust_registry_result.authorization_holds and roots_read_failed:
                # Neither a failure nor a review: the host failure decides the run.
                pass
            elif trust_registry_result.authorization_holds and roots_supplied:
                # Root authentication (trust-root.md sections 5 and 6): a window outside
                # the evaluation time is REVIEW; any other status but ROOT_SIGNATURE_VALID
                # fails the run. This is the case a rogue issuer exploits: create a
                # registry, create an entry, collect a PASS; a caller who pins a root gets
                # a verdict that reflects it.
                # The failure is read off the result's verdict, the one its trust_registry section
                # restates, and the window off the statuses that verdict reviews, so the headline
                # and the result never part.
                if root_status in ROOT_WINDOW_STATUSES:
                    root_window = True
                elif trust_registry_result.root_failed:
                    root_failed = True
                    notes.append("trust_registry_root_signature_required_but_not_verified")
                    errors.append(_error("trust_registry_root_not_authenticated"))
            elif trust_registry_result.authorization_holds:
                # No root supplied: who vouches for the registry cannot be established.
                # Refusing is not accusing: REVIEW, trust_registry_root_not_pinned.
                notes.append("trust_registry_root_not_pinned")
    elif registry_link_result is not None and not registry_link_result.link_holds:
        notes.append("trust_registry_skipped_registry_link_failed")
    elif entry_missing or receipt_uncanonicalisable:
        # report-contract.md section 5.3: only these two conditions; a host failure to read
        # a document the link reads is registry_link_read_failed alone, and a bundle with no
        # receipt is a review reason.
        errors.append(_error("trust_registry_requires_valid_registry_entry"))
    return _TrustStage(
        result=trust_registry_result,
        root_failed=root_failed,
        root_window=root_window,
        rows=_StageRows(errors=tuple(errors), notes=tuple(notes)),
    )


def _verify_bundle_root(
    input_path: Path,
    input_type: str,
    bundle_root: Path,
    *,
    registry_entry_path: str | Path | None,
    trust_registry_path: str | Path | None,
    evaluation_time: str | None,
    trust_roots: Sequence[TrustRootKey],
    roots_read_failed: bool = False,
    container_extra_files: tuple[str, ...] = (),
    bundle_root_name: str | None = None,
    held: Mapping[str, HeldVocabulary],
) -> OfflineVerificationReport:
    entry_supplied = registry_entry_path is not None
    trust_supplied = trust_registry_path is not None
    # Version gates 2 to 7 (document-contracts.md, "Version gate"), read after input strictness
    # and before any contract, in the order of the table; the first that fires stops the run.
    gate = _bundle_gate(bundle_root, registry_entry_path)
    if gate is not None:
        return unsupported_version_report(
            input_path,
            gate[0],
            gate[1],
            input_type=input_type,
            registry_entry_supplied=entry_supplied,
            trust_registry_supplied=trust_supplied,
            evaluation_time=evaluation_time,
        )
    # Taken here, while the root is live. For a zip input the extracted root
    # is removed before the report is serialized, and P1 verification can abort before
    # ever reaching this file, so the observation is unrecoverable afterwards.
    canonical_input_observed = _observed(lambda: member_is_file(bundle_root, "canonical_input.json"))
    envelope_observed = _observed(lambda: envelope_member_present(bundle_root))
    errors: list[dict[str, str]] = []
    notes: list[str] = []

    inventory, rows = _inventory_stage(bundle_root)
    errors.extend(rows.errors)
    notes.extend(rows.notes)
    manifest_result, rows = _manifest_stage(bundle_root, inventory)
    errors.extend(rows.errors)
    notes.extend(rows.notes)
    p1_result, rows = _p1_stage(bundle_root)
    errors.extend(rows.errors)
    notes.extend(rows.notes)

    # The digest of a P1 that verified (contract, size, sidecar), or None. When full P1
    # verification raised, it is recomputed from p1.json alone, so a canonical input that
    # could not be read does not also unmake the P1 the envelope and the receipt name.
    if p1_result is not None:
        p1_digest_verified = p1_result.p1_sha256_actual if p1_result.p1_sha256_ok else None
    else:
        p1_digest_verified = verified_p1_sha256(bundle_root)

    envelope_result, rows = _envelope_stage(
        bundle_root,
        manifest_result=manifest_result,
        p1_result=p1_result,
        p1_digest_verified=p1_digest_verified,
        entry_supplied=registry_entry_path is not None,
    )
    errors.extend(rows.errors)
    notes.extend(rows.notes)

    receipt_violations, receipt_read_failed, rows = _receipt_stage(bundle_root)
    errors.extend(rows.errors)
    notes.extend(rows.notes)

    unresolved: list[str] = []
    if container_extra_files:
        # Not FAIL: whether material delivered beside the bundle matters cannot be decided
        # by hashing, exactly as for an undeclared member inside it. Not PASS either.
        notes.append("container_extra_files")
        unresolved.append("container_extra_files")

    link = (
        _link_stage(
            bundle_root,
            registry_entry_path=registry_entry_path,
            manifest_result=manifest_result,
            p1_digest_verified=p1_digest_verified,
            receipt_violations=receipt_violations,
            receipt_read_failed=receipt_read_failed,
        )
        if registry_entry_path is not None
        else _LinkStage()
    )
    errors.extend(link.rows.errors)
    notes.extend(link.rows.notes)
    unresolved.extend(link.unresolved)
    registry_link_result = link.result
    receipt_missing = link.receipt_missing
    entry_missing = link.entry_missing
    receipt_uncanonicalisable = link.receipt_uncanonicalisable

    # Roots the host failed to read were supplied: no root is "not pinned", and none authenticates.
    roots_supplied = bool(trust_roots) or roots_read_failed
    trust = (
        _trust_stage(
            trust_registry_path,
            registry_entry_supplied=registry_entry_path is not None,
            registry_link_result=registry_link_result,
            entry_missing=entry_missing,
            receipt_uncanonicalisable=receipt_uncanonicalisable,
            trust_roots=trust_roots,
            roots_read_failed=roots_read_failed,
            roots_supplied=roots_supplied,
            evaluation_time=evaluation_time,
        )
        if trust_registry_path is not None
        else _TrustStage()
    )
    if trust.unsupported_version is not None:
        return unsupported_version_report(
            input_path,
            "trust_registry",
            trust.unsupported_version,
            input_type=input_type,
            registry_entry_supplied=entry_supplied,
            trust_registry_supplied=trust_supplied,
            evaluation_time=evaluation_time,
        )
    errors.extend(trust.rows.errors)
    notes.extend(trust.rows.notes)

    reserved_found = isinstance(inventory, BundleInventory) and any(
        is_reserved_member(name) for name in inventory.files
    )
    if reserved_found:
        notes.append("bundle_reserved_member")
    vocabulary_unknown, vocabulary_notes = _unknown_values(bundle_root, receipt_violations, link.judged_entry, held)
    notes.extend(vocabulary_notes)
    return _bundle_report(
        _RunFacts(
            input_path=input_path,
            input_type=input_type,
            bundle_root_name=bundle_root_name,
            entry_supplied=entry_supplied,
            trust_supplied=trust_supplied,
            evaluation_time=evaluation_time,
            container_extra_files=container_extra_files,
            canonical_input_observed=canonical_input_observed,
            envelope_observed=envelope_observed,
            manifest=manifest_result,
            p1=p1_result,
            envelope=envelope_result,
            receipt_read_failed=receipt_read_failed,
            receipt_missing=receipt_missing,
            registry_link=registry_link_result,
            unresolved=tuple(unresolved),
            trust_registry=trust.result,
            root_failed=trust.root_failed,
            root_window=trust.root_window,
            roots_supplied=roots_supplied,
            reserved_found=reserved_found,
            vocabulary_unknown=vocabulary_unknown,
            errors=tuple(errors),
            notes=tuple(notes),
        )
    )


@dataclass(frozen=True)
class _RunFacts:
    """What the stages of a bundle run found. The decision and the report read these alone.

    ``errors`` and ``notes`` are in the order the stages added them: the decision puts the errors
    in table order (report-contract.md section 5.3), and the report keeps the first of each note.
    """

    input_path: Path
    input_type: str
    bundle_root_name: str | None
    entry_supplied: bool
    trust_supplied: bool
    evaluation_time: str | None
    container_extra_files: tuple[str, ...]
    canonical_input_observed: bool
    envelope_observed: bool
    manifest: ManifestVerificationResult | None
    p1: P1VerificationResult | None
    envelope: EnvelopeVerificationResult | None
    receipt_read_failed: bool
    receipt_missing: bool
    registry_link: RegistryLinkVerificationResult | None
    unresolved: tuple[str, ...]
    trust_registry: TrustRegistryVerificationResult | None
    root_failed: bool
    root_window: bool
    roots_supplied: bool
    reserved_found: bool
    vocabulary_unknown: tuple[str, ...]
    errors: tuple[dict[str, str], ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class _Decision:
    """The outcome of a bundle run, concluded from its facts.

    ``review_reasons`` are the reasons the report names: those that hold when the status is
    OFFLINE_REVIEW, and none otherwise.
    """

    status: str
    errors: tuple[dict[str, str], ...]
    review_reasons: tuple[str, ...]
    checks_requested: tuple[str, ...]
    checks_established: tuple[str, ...]
    checks_evaluated: tuple[str, ...]


def _decide(facts: _RunFacts) -> _Decision:
    """The status, review reasons and checks of a bundle run (report-contract.md sections 3 and 5)."""
    manifest_result = facts.manifest
    p1_result = facts.p1
    envelope_result = facts.envelope
    registry_link_result = facts.registry_link
    tr = facts.trust_registry
    ordered = _in_table_order(facts.errors)
    codes = [error.get("code", "") for error in ordered]
    content_error = any(code not in HOST_ERROR_CODES for code in codes)
    host_error = any(code in HOST_ERROR_CODES for code in codes)
    manifest_unread_by_host = manifest_result is None and "manifest_verification_failed" not in codes
    p1_unread_by_host = p1_result is None and "p1_verification_failed" not in codes
    manifest_failed = manifest_result is not None and not manifest_result.ok
    p1_failed = p1_result is not None and p1_result.status == STATUS_OFFLINE_FAIL
    envelope_failed = (
        envelope_result is not None
        and envelope_result.status == STATUS_OFFLINE_FAIL
        and not (manifest_unread_by_host or p1_unread_by_host)
    )
    link_failed = registry_link_result is not None and not registry_link_result.link_holds
    committed_fail = "registry_entry_verdict_fail" in codes
    trust_failed = tr is not None and tr.failed
    failure = (
        content_error
        or manifest_failed
        or p1_failed
        or envelope_failed
        or link_failed
        or committed_fail
        or trust_failed
    )

    holding: dict[str, bool] = {
        "registry_entry_verdict_requires_review": "registry_entry_verdict_requires_review" in facts.unresolved,
        "verification_receipt_not_provided": facts.entry_supplied and facts.receipt_missing,
        "evaluation_time_not_provided": tr is not None
        and facts.evaluation_time is None
        and not trust_failed
        and not facts.root_failed,
        "trust_registry_not_current": tr is not None and tr.review_reason == "trust_registry_not_current",
        "issuer_key_outside_validity_window": tr is not None
        and tr.review_reason == "issuer_key_outside_validity_window",
        "trust_root_outside_validity_window": facts.root_window,
        "trust_registry_root_not_pinned": tr is not None and tr.authorization_holds and not facts.roots_supplied,
        "bundle_reserved_member": facts.reserved_found,
        "container_extra_files": bool(facts.container_extra_files),
        "bundle_extra_files": manifest_result is not None and manifest_result.ok and bool(manifest_result.extra_files),
        "canonical_input_not_provided": p1_result is not None and p1_result.status == STATUS_OFFLINE_REVIEW,
        "envelope_not_provided": envelope_result is not None
        and not envelope_result.envelope_present
        and not envelope_result.envelope_sha256_present,
        "offline_review_required": False,
        "vocabulary_value_unknown": bool(facts.vocabulary_unknown),
    }
    reasons = [name for name in REVIEW_REASONS if holding[name]]

    if failure:
        status = STATUS_OFFLINE_FAIL
    elif host_error:
        status = STATUS_HOST_FAILURE
    elif reasons:
        status = STATUS_OFFLINE_REVIEW
    else:
        status = STATUS_OFFLINE_OK
    evidence = status != STATUS_HOST_FAILURE

    # report-contract.md section 3.2: each check established only when every check before it is.
    requested = checks_requested_for(facts.entry_supplied, facts.trust_supplied)
    checks = _checks_dict(
        manifest_result,
        p1_result,
        envelope_result,
        registry_link_result,
        tr,
        facts.canonical_input_observed,
        facts.envelope_observed,
    )
    envelope_shape_ok = envelope_result is not None and (
        envelope_result.envelope is None or not envelope_shape_errors_for(envelope_result.envelope)
    )
    structure_ok = (
        not any(code in _STRUCTURE_ERRORS for code in codes)
        and not facts.receipt_read_failed
        and manifest_result is not None
        and manifest_result.shape_ok
        and p1_result is not None
        and envelope_shape_ok
    )
    integrity_ok = (
        structure_ok
        and all(
            checks[name] is True
            for name in (
                "manifest_sha256",
                "manifest_files",
                "p1_sha256",
                "p1_input_hash",
                "envelope_sha256",
                "envelope_links",
            )
        )
        and not any(name in _INTEGRITY_REVIEW_REASONS for name in reasons)
    )
    link_ok = integrity_ok and registry_link_result is not None and registry_link_result.link_holds
    # Established exactly when the trust registry's verdict is PASS: authorization holds, a root
    # authenticated the registry and the operator gave an evaluation time.
    authorization_ok = link_ok and tr is not None and tr.trust_registry_verified
    holds = {"structure": structure_ok, "integrity": integrity_ok, "link": link_ok, "authorization": authorization_ok}
    established: list[str] = []
    if evidence:
        for name in requested:
            if not holds[name]:
                break
            established.append(name)
    evaluated = (
        tuple(
            name
            for name in requested
            if name in ("structure", "integrity")
            or (name == "link" and registry_link_result is not None)
            or (name == "authorization" and tr is not None)
        )
        if evidence
        else ()
    )
    return _Decision(
        status=status,
        errors=ordered,
        review_reasons=tuple(reasons) if status == STATUS_OFFLINE_REVIEW else (),
        checks_requested=requested,
        checks_established=tuple(established),
        checks_evaluated=evaluated,
    )


def _bundle_report(facts: _RunFacts) -> OfflineVerificationReport:
    """The report of a bundle run, built from its facts and the decision over them alone."""
    decision = _decide(facts)
    return OfflineVerificationReport(
        status=decision.status,
        verdict=_verdict_for_status(decision.status),
        input_path=str(facts.input_path),
        input_type=facts.input_type,
        bundle_root_name=facts.bundle_root_name,
        manifest=facts.manifest,
        p1=facts.p1,
        envelope=facts.envelope,
        registry_link=facts.registry_link,
        trust_registry=facts.trust_registry,
        notes=tuple(dict.fromkeys(facts.notes)),
        errors=decision.errors,
        canonical_input_observed=facts.canonical_input_observed,
        envelope_observed=facts.envelope_observed,
        container_extra_files=facts.container_extra_files,
        registry_entry_supplied=facts.entry_supplied,
        trust_registry_supplied=facts.trust_supplied,
        checks_requested=decision.checks_requested,
        checks_established=decision.checks_established,
        checks_evaluated=decision.checks_evaluated,
        review_reasons=decision.review_reasons,
        evaluation_time=facts.evaluation_time,
    )


# ---------------------------------------------------------------------------------------------
# Version gates (document-contracts.md, "Version gate"): read after input strictness and before
# the contract. A well-formed identifier other than the supported one fires the gate; anything
# else does not, and the object's contract judges it.

_VERSION_GRAMMAR_RE = re.compile(r"v[1-9][0-9]{0,8}")
_VOCABULARY_GRAMMAR_RE = re.compile(r"loquitur\.reason_codes\.v[1-9][0-9]{0,8}")
_PAYLOAD_ID_GRAMMAR_RE = re.compile(r"registry_entry_signing_payload_v[1-9][0-9]{0,8}")
SUPPORTED_VOCABULARY = "loquitur.reason_codes.v1"


def _gate_of(value: Any, grammar: re.Pattern[str], supported: str) -> str | None:
    if isinstance(value, str) and grammar.fullmatch(value) and value != supported:
        return value
    return None


def _quietly(read: Callable[[], Any]) -> Any:
    """A document as loaded, or None when it cannot be read: a gate reads only what was read.

    A refusal of the document, or a host failure to read it, is left to the layer that reads it
    next, which reports it. A RecursionError is a fault of the verifier, not of the document, and
    propagates as everywhere else (report-contract.md section 4).
    """
    try:
        return read()
    except _DOCUMENT_READ_REFUSALS:
        return None


# What a document read raises for a document it refuses or a host that fails to read it: host
# failures are OSError, strictness refusals ValueError, and each layer's own refusal its error.
_DOCUMENT_READ_REFUSALS = (
    OSError,
    ValueError,
    ManifestVerificationError,
    RegistryLinkVerificationError,
    TrustRegistryVerificationError,
)


def _bundle_gate(bundle_root: Path, registry_entry_path: str | Path | None) -> tuple[str, str] | None:
    """Gates 2 to 7: the manifest, the receipt and its vocabulary, the entry, its vocabulary and
    its signing payload. The receipt is gated in every run; the entry only when supplied."""
    manifest = _quietly(lambda: read_manifest(bundle_root))
    if isinstance(manifest, dict):
        version = _gate_of(manifest.get("schema_version"), MANIFEST_SCHEMA_VERSION_GRAMMAR, MANIFEST_SCHEMA_VERSION)
        if version is not None:
            return "manifest", version
    receipt = _quietly(lambda: read_verification_receipt(bundle_root)[0])
    if isinstance(receipt, dict) and receipt.get("object_type") == "verification_receipt":
        version = _gate_of(receipt.get("schema_version"), _VERSION_GRAMMAR_RE, "v2")
        if version is not None:
            return "verification_receipt", version
        version = _gate_of(receipt.get("reason_code_vocabulary_version"), _VOCABULARY_GRAMMAR_RE, SUPPORTED_VOCABULARY)
        if version is not None:
            return "reason_code_vocabulary", version
    if registry_entry_path is None:
        return None
    entry = _quietly(lambda: read_registry_entry(registry_entry_path))
    if not isinstance(entry, dict) or entry.get("object_type") != "registry_entry":
        return None
    version = _gate_of(entry.get("schema_version"), _VERSION_GRAMMAR_RE, "v1")
    if version is not None:
        return "registry_entry", version
    version = _gate_of(entry.get("reason_code_catalog_version"), _VOCABULARY_GRAMMAR_RE, SUPPORTED_VOCABULARY)
    if version is not None:
        return "reason_code_vocabulary", version
    signature = entry.get("signature")
    if not isinstance(signature, dict):
        return None
    payload_id = signature.get("payload_id")
    payload_version = signature.get("payload_version")
    # The canonical numeric model: 2.0 is the integer 2.
    if isinstance(payload_version, float) and payload_version.is_integer():
        payload_version = int(payload_version)
    if not isinstance(payload_id, str) or not _PAYLOAD_ID_GRAMMAR_RE.fullmatch(payload_id):
        return None
    if isinstance(payload_version, bool) or not isinstance(payload_version, int):
        return None
    if not 1 <= payload_version <= 999_999_999:
        return None
    if payload_id == "registry_entry_signing_payload_v2" and payload_version == 2:
        return None
    return "signing_payload", f"{payload_id}/{payload_version}"


def _trust_registry_gate(trust_registry_path: str | Path) -> str | None:
    """Gate 8: the trust registry, read when the link holds."""
    registry = _quietly(lambda: read_trust_registry(trust_registry_path))
    if not isinstance(registry, dict) or registry.get("object_type") != "trust_registry":
        return None
    return _gate_of(registry.get("schema_version"), _VERSION_GRAMMAR_RE, "v1")


def _version_gated_checks() -> dict[str, Any]:
    """The per-check results of a run a version gate stopped: nothing was evaluated."""
    return {
        "manifest_sha256": None,
        "manifest_files": None,
        "p1_sha256": None,
        "canonical_input_present": None,
        "p1_input_hash": None,
        "envelope_present": None,
        "envelope_sha256": None,
        "envelope_links": None,
        "registry_signature": "UNSUPPORTED",
        "registry_link": None,
        "trust_registry": None,
    }


def _registry_signature_check(
    envelope: EnvelopeVerificationResult | None,
    trust_registry: TrustRegistryVerificationResult | None,
) -> str | None:
    """Registry-entry issuer signature status reported to consumers.

    Runs without the authorization check never evaluate the issuer signature, so the check
    stays UNSUPPORTED. When a trust registry is supplied the signature *is*
    verified, and the report must carry that real outcome: reporting
    UNSUPPORTED there contradicts ``checks.trust_registry``.
    """
    if envelope is None:
        return None
    return _evaluated_signature_status(trust_registry)


def _evaluated_signature_status(trust_registry: TrustRegistryVerificationResult | None) -> str:
    """The issuer signature status the trust-registry step evaluated, or UNSUPPORTED when it evaluated none."""
    if trust_registry is None or trust_registry.signature_status is None:
        return "UNSUPPORTED"
    return trust_registry.signature_status


def _refused_input_checks(registry_entry_supplied: bool, trust_registry_supplied: bool) -> dict[str, Any]:
    """The checks block of a run whose input was refused as a whole (bundle-objects.md section 6).

    No layer ran, and each was refused with the input. Each bundle check reports false, the two
    presence flags report that nothing was found, registry_signature is UNSUPPORTED because no
    signature was evaluated, registry_link is false when a registry entry was supplied, and
    trust_registry is false when a registry entry and a trust registry were supplied; each of the
    two is null otherwise.
    """
    return {
        "manifest_sha256": False,
        "manifest_files": False,
        "p1_sha256": False,
        "canonical_input_present": False,
        "p1_input_hash": False,
        "envelope_present": False,
        "envelope_sha256": False,
        "envelope_links": False,
        "registry_signature": "UNSUPPORTED",
        "registry_link": False if registry_entry_supplied else None,
        "trust_registry": False if registry_entry_supplied and trust_registry_supplied else None,
    }


def _checks_dict(
    manifest: ManifestVerificationResult | None,
    p1: P1VerificationResult | None,
    envelope: EnvelopeVerificationResult | None,
    registry_link: RegistryLinkVerificationResult | None,
    trust_registry: TrustRegistryVerificationResult | None,
    canonical_input_observed: bool | None = None,
    envelope_observed: bool | None = None,
) -> dict[str, Any]:
    """Assemble the checks block.

    Seven entries are either a verified conclusion or an unevaluated null. The
    other five, the ones whose result object may be absent entirely, fall back
    to ``False`` rather than ``None``, so for those a reader cannot distinguish
    "checked, and it failed" from "never evaluated". That is a real limitation of
    this block, not a guess about the evidence: nothing here infers a conclusion it
    did not compute. See the note below for why presence is observed rather than
    inferred.
    """
    if envelope is None and envelope_observed is not None:
        # The envelope layer ran and was refused: its verification raised, for an envelope
        # that is unreadable, not an object, not canonicalizable or beside a second envelope
        # name, or for a member the host failed to read or to inspect. The checks of a refused
        # layer are false (bundle-objects.md §6), never null: null would tell a reader the
        # digest and the links had no input, for a bundle the run refused over that layer.
        # Presence is a fact, so the flag is what the verifier saw: true for an envelope found
        # and not read, false when the host did not let it see one.
        # The issuer signature is the registry entry's, evaluated by the trust-registry step
        # whatever the envelope holds, so its status is reported here as everywhere else:
        # report-contract.md section 6 keeps UNSUPPORTED for a run that evaluated no signature.
        envelope_checks = {
            "envelope_present": envelope_observed,
            "envelope_sha256": False,
            "envelope_links": False,
            "registry_signature": _evaluated_signature_status(trust_registry),
        }
    else:
        envelope_checks = {
            "envelope_present": envelope.envelope_present if envelope is not None else False,
            "envelope_sha256": envelope.envelope_sha256_ok if envelope is not None else None,
            "envelope_links": envelope.links_ok if envelope is not None else None,
            "registry_signature": _registry_signature_check(envelope, trust_registry),
        }
    return {
        "manifest_sha256": manifest.manifest_sha256_ok if manifest is not None else False,
        "manifest_files": manifest.files_established if manifest is not None else False,
        "p1_sha256": p1.p1_sha256_ok if p1 is not None else False,
        # This is an observation about the bundle, not a conclusion about P1.
        # When P1 verification aborts on a shape error it never reaches the file, and
        # reporting False then would conflate "absent" with "not evaluated", a factual
        # claim the verifier has not checked.
        "canonical_input_present": (p1.canonical_input_present if p1 is not None else canonical_input_observed),
        "p1_input_hash": p1.input_hash_ok if p1 is not None else False,
        **envelope_checks,
        "registry_link": registry_link.link_holds if registry_link is not None else None,
        "trust_registry": trust_registry.authorization_holds if trust_registry is not None else None,
    }


_BARE_SHA256 = re.compile(r"[0-9a-f]{64}")


def _restated_digest(value: str | None) -> str | None:
    """A digest the report restates, in the self-describing form ``sha256:<hex>``.

    report-contract.md section 6: every digest the report restates is written as
    canonicalization-and-hashing.md section 2 writes it. A sidecar compares 64 bare hex
    characters; the report names the algorithm. A value that is not a digest (a malformed
    sidecar, or None) is restated as it was read.
    """
    if isinstance(value, str) and _BARE_SHA256.fullmatch(value):
        return f"sha256:{value}"
    return value


def _manifest_dict(result: ManifestVerificationResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result.ok,
        "manifest_sha256_expected": _restated_digest(result.manifest_sha256_expected),
        "manifest_sha256_actual": _restated_digest(result.manifest_sha256_actual),
        "manifest_sha256_ok": result.manifest_sha256_ok,
        "files_ok": result.files_ok,
        "shape_errors": list(result.shape_errors),
        "extra_files": list(result.extra_files),
        "file_checks": [
            {
                "name": check.name,
                "expected_sha256": check.expected_sha256,
                "actual_sha256": check.actual_sha256,
                "ok": check.ok,
                "error": check.error,
            }
            for check in result.file_checks
        ],
    }


def _p1_dict(result: P1VerificationResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result.ok,
        "status": result.status,
        "verdict": result.verdict,
        "p1_sha256_expected": _restated_digest(result.p1_sha256_expected),
        "p1_sha256_actual": _restated_digest(result.p1_sha256_actual),
        "p1_sha256_ok": result.p1_sha256_ok,
        "p1_size_bytes": result.p1_size_bytes,
        "canonical_input_present": result.canonical_input_present,
        "input_hash_expected": result.input_hash_expected,
        "input_hash_actual": result.input_hash_actual,
        "input_hash_ok": result.input_hash_ok,
        "input_keys": list(result.input_keys) if result.input_keys is not None else None,
        "notes": list(result.notes),
    }


def _envelope_dict(result: EnvelopeVerificationResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "ok": result.ok,
        "status": result.status,
        "verdict": result.verdict,
        "envelope_path_name": result.envelope_path_name,
        "envelope_sha256_expected": _restated_digest(result.envelope_sha256_expected),
        "envelope_sha256_actual": _restated_digest(result.envelope_sha256_actual),
        "envelope_sha256_ok": result.envelope_sha256_ok,
        "envelope_present": result.envelope_present,
        "envelope_sha256_present": result.envelope_sha256_present,
        "envelope_files_complete": result.envelope_files_complete,
        "bundle_id_expected": result.bundle_id_expected,
        "bundle_id_actual": result.bundle_id_actual,
        "bundle_id_ok": result.bundle_id_ok,
        "manifest_link_ok": result.manifest_link_ok,
        "p1_link_ok": result.p1_link_ok,
        "links_ok": result.links_ok,
        "notes": list(result.notes),
    }


def _registry_dict(
    result: EnvelopeVerificationResult | None,
    registry_link: RegistryLinkVerificationResult | None,
    trust_registry: TrustRegistryVerificationResult | None,
    registry_entry_supplied: bool = False,
) -> dict[str, Any]:
    # Whether an entry is present is the operator's fact, as checks_requested reads it: an
    # entry the run never compared (no receipt beside it, a version gate, a host failure)
    # was still supplied, and the block must not report it as not provided.
    if trust_registry is not None:
        # Read off the trust registry's verdict, the one the report's trust_registry section
        # restates, so the two never disagree. "TRUST_REGISTRY_VERIFIED" for a registry whose own
        # root was never authenticated, or for an authorization not established, is the sentence
        # a counterparty quotes back, and it would claim more than the tool has checked: it is
        # said for a PASS alone. A FAIL, a failed authorization row or a root that was evaluated
        # and failed (an altered registry, an unknown or revoked root key, trust-root.md section
        # 6), is a failed trust registry. A REVIEW says which question is open: no root
        # authenticated the registry, or authorization was not established (no evaluation time,
        # or a window that does not hold it).
        if trust_registry.verdict == VERDICT_PASS:
            registry_status = "TRUST_REGISTRY_VERIFIED"
        elif trust_registry.verdict == VERDICT_FAIL:
            registry_status = "TRUST_REGISTRY_FAILED"
        elif trust_registry.authorization_holds and not trust_registry.root_signature_verified:
            registry_status = "TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED"
        else:
            registry_status = "TRUST_REGISTRY_AUTHORIZATION_NOT_ESTABLISHED"
        return {
            "entry_present": registry_link.entry_present if registry_link is not None else registry_entry_supplied,
            "status": registry_status,
            "signature_supported": True,
            "link_verification_supported": registry_link is not None,
            "trust_registry_supported": True,
        }
    if registry_link is not None:
        return {
            "entry_present": registry_link.entry_present,
            "status": "REGISTRY_ENTRY_LINK_VERIFIED" if registry_link.link_holds else "REGISTRY_ENTRY_LINK_FAILED",
            "signature_supported": False,
            "link_verification_supported": True,
            "trust_registry_supported": False,
        }
    if registry_entry_supplied:
        # An entry was supplied and the link was not compared: the run stopped before it (a
        # refused input, or a refused layer the link reads). The `registry` member is one of the
        # informative members report-contract.md section 2 allows and section 7 names; the
        # normative answer is in status, errors and checks_established.
        return {
            "entry_present": True,
            "status": "REGISTRY_ENTRY_LINK_NOT_EVALUATED",
            "signature_supported": False,
            "link_verification_supported": True,
            "trust_registry_supported": False,
        }
    return {
        "entry_present": False,
        "status": "REGISTRY_ENTRY_NOT_PROVIDED",
        "signature_supported": False,
        "link_verification_supported": False,
        "trust_registry_supported": False,
    }


def _registry_link_dict(result: RegistryLinkVerificationResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "status": result.status,
        # `verdict` is the outcome of the LINK check, whether entry and receipt agree,
        # and it reuses the exact word the registry entry uses for its own published
        # verdict, with a different meaning. `registry_entry_verdict` carries what the
        # issuer committed, verbatim, so a reader can never mistake one for the other.
        "verdict": result.verdict,
        "registry_entry_verdict": (result.registry_entry.get("verdict") if result.registry_entry is not None else None),
        # Informative, and kept under its name: whether the link holds, never the verdict, which
        # is the member above.
        "ok": result.link_holds,
        "registry_entry_path": result.registry_entry_path,
        "verification_receipt_path_name": result.verification_receipt_path_name,
        "receipt_sha256_actual": _restated_digest(result.receipt_sha256_actual),
        # This section restates the link check alone (report-contract.md section 2): the link
        # compares the entry with the receipt and verifies no signature, trust registry or log
        # inclusion, so these are false on every run. They do not contradict an established
        # authorization check, which the trust_registry section reports.
        "signature_verified": False,
        "trust_registry_verified": False,
        "registry_inclusion_verified": False,
        "anchor_finality_verified": False,
        "checks": [
            {
                "name": check.name,
                "expected": check.expected,
                "actual": check.actual,
                "ok": check.ok,
                "note": check.note,
            }
            for check in result.checks
        ],
        "notes": list(result.notes),
    }


def _trust_registry_dict(result: TrustRegistryVerificationResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "status": result.offline_status,
        "verdict": result.verdict,
        # No `ok`: a member of that name beside the verdict would say authorization alone
        # (trust-registry-authorization.md section 9) and read as the outcome. Whether
        # authorization held is checks.trust_registry and authorization_status.
        "trust_registry_path": result.trust_registry_path,
        "trust_registry_id": result.trust_registry_id,
        "evaluation_time": result.evaluation_time,
        "issuer_id": result.issuer_id,
        "issuer_key_id": result.issuer_key_id,
        "trust_entry_status": result.trust_entry_status,
        "signature_verified": result.signature_valid,
        "trust_registry_verified": result.trust_registry_verified,
        # Not a literal False. A literal cannot distinguish "not checked" from
        # "checked, and nothing is pinned", and a counterparty reading the report needs
        # that difference: the first is a gap in the tool, the second is a gap in the
        # deployment. The status field carries which one it is.
        "trust_registry_root_signature_verified": result.root_signature_verified,
        "trust_registry_root_signature_status": result.root_signature_status,
        "trust_registry_root_key_id": result.root_key_id,
        "registry_inclusion_verified": False,
        "anchor_finality_verified": False,
        "authorization_status": result.authorization_status,
        "signature_status": result.signature_status,
        "signing_payload_hash": result.signing_payload_hash,
        "signing_payload_id": result.signing_payload_id,
        "signing_payload_version": result.signing_payload_version,
        "error": result.error,
        "checks": [
            {
                "name": check.name,
                "expected": check.expected,
                "actual": check.actual,
                "ok": check.ok,
                "note": check.note,
            }
            for check in result.checks
        ],
        "notes": list(result.notes),
    }
