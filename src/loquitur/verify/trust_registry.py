"""The authorization check against a trust registry supplied locally, for loquitur-verify.

This module verifies a supplied public ``registry_entry`` against a supplied
local ``trust_registry`` object. It checks the registry-entry issuer signature,
the authorization of the issuer and its key, the key status, the scope and the validity
window, using only the local material the caller supplies.

It also authenticates the trust registry itself against the roots passed in
``trust_roots``, reporting the outcome as ``root_signature_verified``,
``root_signature_status`` and ``root_key_id``. The default root set is empty, so
without a root supplied out of band the outcome is ``NO_PINNED_TRUST_ROOT``: a
computed answer, not a claim of authenticity. A caller who pins a root, or passes
one with ``--trust-root``, gets a real verification.

It does not perform online registry lookups, verify registry inclusion or checkpoint
proofs, verify anchors or finality, use a KMS, an HSM, TUF or a time-stamp authority, or
assert the real-world or legal identity of an issuer beyond the supplied trust material.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import CanonicalizationError, JsonLoadError, loads_json_bytes
from .contract_validation import contract_errors
from .cryptographic_capabilities import (
    CRYPTOGRAPHIC_CAPABILITY_PROFILE,
    SUPPORTED_SIGNATURE_PAIRS,
    signature_pair_supported,
)
from .errors import LoquiturVerifyError
from .evaluation_time import operator_evaluation_time, parse_calendar_instant
from .host_path import host_path
from .manifest import STATUS_OFFLINE_FAIL, STATUS_OFFLINE_OK, STATUS_OFFLINE_REVIEW, is_blank
from .members import path_names_regular_file, read_file_bytes
from .registry_link import registry_entry_contract_violations
from .secp256k1 import (
    SIGNATURE_HEX_RE,
    PublicKeyError,
    parse_uncompressed_public_key,
    shares_point,
    verify_digest,
)
from .signing_envelope import (
    SIGNING_PAYLOAD_ID,
    SIGNING_PAYLOAD_VERSION,
    signing_message_bytes,
    signing_message_hash,
)
from .trust_root import (
    PINNED_TRUST_ROOTS,
    STATUS_NO_PINNED_ROOT,
    STATUS_NOT_EVALUATED,
    STATUS_ROOT_EXPIRED,
    STATUS_ROOT_NOT_YET_VALID,
    STATUS_VALID,
    TrustRootKey,
    validate_trust_roots,
    verify_trust_registry_root_signature,
)

VERDICT_PASS = "PASS"
VERDICT_REVIEW = "REVIEW"
VERDICT_FAIL = "FAIL"

AUTH_STATUS_VALID = "AUTHORIZED_ACTIVE_KEY"
AUTH_STATUS_ISSUER_NOT_FOUND = "ISSUER_NOT_FOUND"
AUTH_STATUS_KEY_NOT_FOUND = "ISSUER_KEY_NOT_FOUND"
AUTH_STATUS_SUSPENDED = "ISSUER_KEY_SUSPENDED"
AUTH_STATUS_REVOKED = "ISSUER_KEY_REVOKED"
AUTH_STATUS_NOT_YET_EFFECTIVE = "ISSUER_KEY_NOT_YET_EFFECTIVE"
AUTH_STATUS_EXPIRED = "ISSUER_KEY_EXPIRED"
AUTH_STATUS_SCOPE_MISMATCH = "ISSUER_KEY_SCOPE_MISMATCH"
# Row 6 of trust-registry-authorization.md section 6: more than one trust entry of the issuer with
# the entry's issuer_key_id, or a trust entry whose secp256k1 point another trust entry of the
# registry carries too (any issuer, status, key type or SEC1 spelling). Either would make the
# verdict depend on which label is read, or on array order, and revocation is of the key.
AUTH_STATUS_AMBIGUOUS_KEY = "TRUST_REGISTRY_AMBIGUOUS_KEY"
AUTH_STATUS_TRUST_REGISTRY_NOT_YET_EFFECTIVE = "TRUST_REGISTRY_NOT_YET_EFFECTIVE"
AUTH_STATUS_TRUST_REGISTRY_EXPIRED = "TRUST_REGISTRY_EXPIRED"
AUTH_STATUS_INVALID_REGISTRY_ENTRY = "INVALID_REGISTRY_ENTRY"
AUTH_STATUS_INVALID_TRUST_REGISTRY = "INVALID_TRUST_REGISTRY"

SIG_STATUS_VALID = "VALID_SIGNATURE"
# The registry-entry signature step follows the trust-root model (trust-root.md sections 3
# and 5): MALFORMED_SIGNATURE is a matter of form (no signature object, or a value that is not
# 128 lowercase hex characters), and everything that is well formed and does not verify,
# including a public key off the curve and r or s out of range, is SIGNATURE_INVALID.
SIG_STATUS_MALFORMED = "MALFORMED_SIGNATURE"
SIG_STATUS_UNSUPPORTED = "UNSUPPORTED_SIGNATURE_ALGORITHM"
SIG_STATUS_KEY_MISMATCH = "SIGNATURE_KEY_MISMATCH"
SIG_STATUS_INVALID = "SIGNATURE_INVALID"
SIG_STATUS_UNSUPPORTED_PAYLOAD = "UNSUPPORTED_SIGNING_PAYLOAD"


# The rows whose effect is REVIEW (trust-registry-authorization.md section 6, rows 9 to 12): a
# window that does not hold the operator's evaluation time. No time attested to the signature exists
# in this version, so such a window leaves authorization not established; it is not a failure.
WINDOW_REVIEW_REASONS = {
    AUTH_STATUS_TRUST_REGISTRY_NOT_YET_EFFECTIVE: "trust_registry_not_current",
    AUTH_STATUS_TRUST_REGISTRY_EXPIRED: "trust_registry_not_current",
    AUTH_STATUS_NOT_YET_EFFECTIVE: "issuer_key_outside_validity_window",
    AUTH_STATUS_EXPIRED: "issuer_key_outside_validity_window",
}

# The root statuses whose effect, after an authorization that holds, is REVIEW and not FAIL
# (trust-root.md sections 5 and 6): no root pinned, root authentication not evaluated, and a root
# window that does not hold the evaluation time (rows 9 and 10). Every other status but
# ROOT_SIGNATURE_VALID is a failure, a status this version does not know included. The window
# statuses are their own set: a run reports them as trust_root_outside_validity_window.
ROOT_WINDOW_STATUSES = frozenset({STATUS_ROOT_NOT_YET_VALID, STATUS_ROOT_EXPIRED})
ROOT_REVIEW_STATUSES = frozenset({STATUS_NO_PINNED_ROOT, STATUS_NOT_EVALUATED}) | ROOT_WINDOW_STATUSES

# Root authentication was not reached: the entry or the trust registry stopped the run first.
ROOT_NOT_EVALUATED_NOTE = f"trust_registry_root_signature_not_verified:{STATUS_NOT_EVALUATED.lower()}"


class TrustRegistryVerificationError(LoquiturVerifyError):
    """Base class for expected trust-registry verification failures."""


class TrustRegistryMissingError(TrustRegistryVerificationError):
    """Raised when the supplied trust-registry path does not exist."""


class TrustRegistryTypeError(TrustRegistryVerificationError):
    """Raised when trust_registry JSON is not an object."""


@dataclass(frozen=True)
class TrustRegistryFieldCheck:
    name: str
    expected: Any
    actual: Any
    ok: bool
    note: str | None = None


@dataclass(frozen=True)
class TrustRegistryVerificationResult:
    trust_registry: dict[str, Any] | None
    trust_registry_path: str | None
    evaluation_time: str | None
    checks: tuple[TrustRegistryFieldCheck, ...]
    issuer_id: str | None = None
    issuer_key_id: str | None = None
    trust_registry_id: str | None = None
    trust_entry_status: str | None = None
    signing_payload_hash: str | None = None
    signing_payload_id: str | None = None
    signing_payload_version: int | None = None
    signature_status: str | None = None
    authorization_status: str | None = None
    root_signature_verified: bool = False
    root_signature_status: str | None = None
    root_key_id: str | None = None
    error: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def authorization_holds(self) -> bool:
        """Authorization holds (trust-registry-authorization.md section 9) against the trust registry as supplied.

        AUTHORIZED_ACTIVE_KEY and VALID_SIGNATURE, and nothing more: it says nothing about who
        vouches for the trust registry, and it is never a PASS on its own. ``verdict``,
        ``offline_status`` and ``trust_registry_verified`` fold in root authentication and the
        evaluation time. The result has no ``ok``: a member of that name read alone would say
        True for an altered, unknown-root or revoked-root registry.
        """
        return (
            self.trust_registry is not None
            and self.authorization_status == AUTH_STATUS_VALID
            and self.signature_status == SIG_STATUS_VALID
        )

    @property
    def root_failed(self) -> bool:
        """The verdict is FAIL after an authorization that holds: the root failed (trust-root.md section 5)."""
        return self.authorization_holds and self.verdict == VERDICT_FAIL

    @property
    def review_reason(self) -> str | None:
        """The review reason of a window row the evaluation stopped at (rows 9 to 12), else None."""
        if self.signature_status is not None:
            return None
        return WINDOW_REVIEW_REASONS.get(self.authorization_status or "")

    @property
    def failed(self) -> bool:
        """The evaluation stopped at an authorization row whose effect is a failure (section 9).

        The verdict is FAIL before authorization held; a root failure is ``root_failed``.
        """
        return not self.authorization_holds and self.verdict == VERDICT_FAIL

    @property
    def offline_status(self) -> str:
        """The status that goes with ``verdict``: OFFLINE_OK, OFFLINE_REVIEW or OFFLINE_FAIL."""
        return {
            VERDICT_PASS: STATUS_OFFLINE_OK,
            VERDICT_REVIEW: STATUS_OFFLINE_REVIEW,
        }.get(self.verdict, STATUS_OFFLINE_FAIL)

    @property
    def verdict(self) -> str:
        """The verdict of this evaluation, root authentication and the evaluation time included.

        PASS only when authorization holds, a pinned root authenticated the trust registry
        (ROOT_SIGNATURE_VALID) and an evaluation time was given (trust-root.md sections 2 and 6,
        trust-registry-authorization.md section 2). An authorization row whose effect is a
        failure, or a root row whose effect is a failure, is FAIL. Anything else is REVIEW: a
        window that does not hold the evaluation time, no pinned root, a root whose window does
        not hold the evaluation time, root authentication not evaluated, or no evaluation time.

        The one place the verdict is decided: ``failed``, ``root_failed``, ``offline_status`` and
        ``trust_registry_verified`` read it, and so does a bundle run's headline (runner.py), so
        the result and the report never part.
        """
        if not self.authorization_holds:
            return VERDICT_REVIEW if self.review_reason is not None else VERDICT_FAIL
        if self.root_signature_status == STATUS_VALID:
            return VERDICT_PASS if self.evaluation_time is not None else VERDICT_REVIEW
        return VERDICT_REVIEW if self.root_signature_status in ROOT_REVIEW_STATUSES else VERDICT_FAIL

    @property
    def signature_valid(self) -> bool:
        return self.signature_status == SIG_STATUS_VALID

    @property
    def trust_registry_verified(self) -> bool:
        """True only for a PASS: authorization holds against a root-authenticated trust registry."""
        return self.verdict == VERDICT_PASS


def _read_json_file(path: Path) -> Any:
    """The strict JSON of the trust registry. A host failure to read it is the host's (OSError),
    not a finding about the registry: report-contract.md section 5.3 reports it as
    trust_registry_read_failed, and the registry is not evaluated."""
    return loads_json_bytes(read_file_bytes(path), name=path.name)


def read_trust_registry(path: str | Path) -> dict[str, Any]:
    # Read as it is written, in the file namespace on Windows, as the input is (host_path). The
    # string is inspected, not a Path: pathlib gives a device path such as \\.\nul a separator
    # after it, which names another thing. A regular file's path survives the Path unchanged.
    host = host_path(path)
    trust_path = Path(host)
    # A host that fails to inspect the path, or to read the file, raises its OSError: the
    # registry is unread (trust_registry_read_failed), not missing and not malformed.
    regular = path_names_regular_file(host)
    if not regular:
        raise TrustRegistryMissingError("trust_registry_not_found")
    try:
        trust_registry = _read_json_file(trust_path)
    except JsonLoadError as exc:
        raise TrustRegistryVerificationError(str(exc)) from exc
    if not isinstance(trust_registry, dict):
        raise TrustRegistryTypeError("trust_registry_invalid_type")
    return trust_registry


def _check(name: str, expected: Any, actual: Any, ok: bool, note: str | None = None) -> TrustRegistryFieldCheck:
    return TrustRegistryFieldCheck(name=name, expected=expected, actual=actual, ok=ok, note=note)


def _parse_instant(value: Any, *, field_name: str) -> datetime:
    # Exactly the form the schemas give an instant, so that a date-only or offset form never
    # reaches a parser that would read it in the host's local time.
    instant = parse_calendar_instant(value)
    if instant is None:
        raise TrustRegistryVerificationError(f"{field_name}_invalid_instant")
    return instant


def _trust_registry_shape_errors(trust_registry: dict[str, Any]) -> list[str]:
    """Every way a trust registry breaks its contract (trust-registry-authorization.md section 3).

    The generated contract (its schema, with every instant a calendar instant), then what the
    schema cannot express: free strings made only of W, and fields that contradict each other.
    The contract holds every required member, its type, its pattern and the closed member set,
    so nothing here restates it. The trust registry is the authority every later row inherits
    from: one that breaks its contract stops the evaluation at row 3.
    """
    errors: list[str] = list(contract_errors("trust_registry", trust_registry))
    errors.extend(_trust_registry_free_string_errors(trust_registry))
    errors.extend(_trust_registry_coherence_errors(trust_registry))
    return errors


# The trust registry's free strings (trust-registry-authorization.md section 3): the schema holds
# each by minLength alone, and a value made only of the whitespace set W names nothing. Every
# entry counts, not only the one the registry entry names. `signature.signature` is not among
# them: trust-root.md holds it to its compact form when a root authenticates the registry.
TRUST_ENTRY_FREE_STRINGS = ("issuer_display_name", "issuer_key_id", "notes", "revocation_reason")


def _trust_registry_free_string_errors(trust_registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    signature = trust_registry.get("signature")
    if isinstance(signature, dict) and isinstance(signature.get("key_id"), str) and is_blank(signature["key_id"]):
        errors.append("trust_registry.signature.key_id:blank")
    entries = trust_registry.get("entries")
    for index, item in enumerate(entries if isinstance(entries, list) else ()):
        if not isinstance(item, dict):
            continue
        for member in TRUST_ENTRY_FREE_STRINGS:
            value = item.get(member)
            if isinstance(value, str) and is_blank(value):
                errors.append(f"trust_registry.entries[{index}].{member}:blank")
    return errors


def _instant_or_none(value: Any) -> datetime | None:
    try:
        return _parse_instant(value, field_name="instant")
    except TrustRegistryVerificationError:
        return None


def _later(first: Any, second: Any) -> bool:
    """True when both are protocol instants and ``first`` is strictly later than ``second``."""
    a, b = _instant_or_none(first), _instant_or_none(second)
    return a is not None and b is not None and a > b


def _trust_registry_coherence_errors(trust_registry: dict[str, Any]) -> list[str]:
    """Contradictions between a trust registry's fields, each a malformed trust registry.

    Key status does not decide alone; the fields beside it are read: an entry marked
    ``active`` with a past ``revoked_at``, a ``revoked`` entry with no ``revoked_at``, a
    ``suspended`` entry carrying a revocation, and a window ending before it begins are each
    contradictory. Contradictory trust material is refused, not read one way or the other
    (trust-registry-authorization.md section 3).
    Every entry counts, not only the one a registry entry names: the document is malformed.

    A registry issued before it takes effect is an advance issue and stays valid; equal
    bounds are not inverted; a coherent revoked entry is revoked whatever the evaluation
    instant (the status decides).
    """
    errors: list[str] = []
    if _later(trust_registry.get("effective_at"), trust_registry.get("expires_at")):
        errors.append("trust_registry:effective_at_after_expires_at")
    if _later(trust_registry.get("issued_at"), trust_registry.get("expires_at")):
        errors.append("trust_registry:issued_at_after_expires_at")
    entries = trust_registry.get("entries")
    for index, item in enumerate(entries if isinstance(entries, list) else ()):
        if not isinstance(item, dict):
            continue
        where = f"trust_registry.entries[{index}]"
        status = item.get("status")
        carries_revocation = item.get("revoked_at") is not None or item.get("revocation_reason") is not None
        if status == "active" and carries_revocation:
            errors.append(f"{where}:active_key_carries_revocation")
        if status == "suspended" and carries_revocation:
            # A suspension is reversible and a revocation is not: the entry says both of one key.
            errors.append(f"{where}:suspended_key_carries_revocation")
        if status == "revoked" and item.get("revoked_at") is None:
            errors.append(f"{where}:revoked_key_without_revoked_at")
        if _later(item.get("effective_from"), item.get("expires_at")):
            errors.append(f"{where}:effective_from_after_expires_at")
    return errors


def _registry_entry_shape_errors(entry: Any) -> list[str]:
    """Every way a registry entry breaks its contract: row 2 of trust-registry-authorization.md §6.

    One contract for the entry in every check (registry-link.md section 2), the one the link
    reads: its generated schema, closed by ``additionalProperties: false``, with every instant a
    calendar instant, its named strings not empty under W, and its grounds. An entry the link
    accepts is not refused here, and nothing here restates the schema.

    No signature check: the schema allows ``signature: null`` and an absent signature, so such an
    entry satisfies its contract, and the missing signature is the signature step's first finding
    (MALFORMED_SIGNATURE, trust-registry-authorization.md section 6, row 14).
    """
    return registry_entry_contract_violations(entry)


def _payload_version(value: Any) -> int | None:
    """``payload_version`` under the canonical numeric model (2.0 is the integer 2), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


@dataclass(frozen=True)
class _SignatureOutcome:
    """What the signature step (rows 14 to 20) found: its status, and what it read of the payload."""

    status: str
    error: str | None = None
    payload_hash: str | None = None
    payload_id: str | None = None
    payload_version: int | None = None


def _verify_signature(
    entry: dict[str, Any],
    public_key_hex: str,
    *,
    expected_key_id: str,
    key_type: Any,
) -> _SignatureOutcome:
    """The registry-entry signature step, rows 14 to 20 of trust-registry-authorization.md §6.

    14. no signature object: MALFORMED_SIGNATURE;
    15. a payload other than registry_entry_signing_payload_v2 version 2:
        UNSUPPORTED_SIGNING_PAYLOAD (this version defines no earlier payload);
    16. the pair of the signature's algorithm and the trust entry's key type outside the
        verifier's allowlist: UNSUPPORTED_SIGNATURE_ALGORITHM, decided by the verifier and
        never by the input;
    17. the form of the value, exactly 128 lowercase hex characters: MALFORMED_SIGNATURE;
    18, 19. the key ids, the signature's key_id and then the entry's issuer_key_id, each equal
        to the authorized key id as written: SIGNATURE_KEY_MISMATCH;
    20. verification, SIGNATURE_INVALID for anything well formed that does not verify: a
        public key that is not of the form of its key type, a payload that cannot be
        canonicalized, r or s out of range, a high s, a wrong signature.
    """
    signature_obj = entry.get("signature")
    if not isinstance(signature_obj, dict):
        return _SignatureOutcome(SIG_STATUS_MALFORMED, "registry entry has no signature object")
    algorithm = signature_obj.get("algorithm")
    # The key ids as written, whatever they hold (rows 18 and 19): nothing is trimmed, and a value
    # made only of the whitespace set W is compared as written, so three identical W-only ids match
    # and an id with a trailing space does not match one without it (canonicalization-and-hashing.md
    # section 7).
    signature_key_id = signature_obj.get("key_id")
    signature_hex = signature_obj.get("signature")
    issuer_key_id = entry.get("issuer_key_id")
    raw_payload_id = signature_obj.get("payload_id")
    payload_id = raw_payload_id if isinstance(raw_payload_id, str) else None
    payload_version = _payload_version(signature_obj.get("payload_version"))

    def refused(status: str, error: str, payload_hash: str | None = None) -> _SignatureOutcome:
        return _SignatureOutcome(status, error, payload_hash, payload_id, payload_version)

    if payload_id != SIGNING_PAYLOAD_ID or payload_version != SIGNING_PAYLOAD_VERSION:
        return refused(
            SIG_STATUS_UNSUPPORTED_PAYLOAD,
            f"unsupported signing payload: {raw_payload_id!r} version {signature_obj.get('payload_version')!r}",
        )
    if not signature_pair_supported(algorithm, key_type):
        return refused(
            SIG_STATUS_UNSUPPORTED,
            f"unsupported pair of signature algorithm {algorithm!r} and key type {key_type!r} "
            f"for {CRYPTOGRAPHIC_CAPABILITY_PROFILE}",
        )
    if not isinstance(signature_hex, str) or not SIGNATURE_HEX_RE.fullmatch(signature_hex):
        return refused(SIG_STATUS_MALFORMED, "signature value must be 128 lowercase hex characters")
    if signature_key_id != expected_key_id:
        return refused(SIG_STATUS_KEY_MISMATCH, "signature key_id does not match authorized trust-registry key")
    if issuer_key_id != expected_key_id:
        return refused(
            SIG_STATUS_KEY_MISMATCH, "registry_entry issuer_key_id does not match authorized trust-registry key"
        )
    try:
        parse_uncompressed_public_key(public_key_hex)
    except PublicKeyError as exc:
        return refused(SIG_STATUS_INVALID, str(exc))
    try:
        payload = signing_message_bytes(entry)
        payload_hash = signing_message_hash(entry)
    except CanonicalizationError as exc:
        # Not reachable from a document read under input strictness, whose rules make every document
        # canonicalizable (report-contract.md section 5.3); kept as a defense in depth.
        return refused(
            SIG_STATUS_INVALID, f"registry_entry_signing_payload_canonicalization_failed:{type(exc).__name__}"
        )
    valid = verify_digest(hashlib.sha256(payload).digest(), signature_hex, public_key_hex)
    if not valid:
        return refused(SIG_STATUS_INVALID, f"signature does not verify for {payload_id}", payload_hash)
    return _SignatureOutcome(SIG_STATUS_VALID, None, payload_hash, payload_id, payload_version)


@dataclass(frozen=True)
class _TrustContext:
    """The two documents of one evaluation, both satisfying their contracts, and what it recorded.

    ``checks`` and ``notes`` grow as the rows are evaluated, in row order; every result of the
    evaluation is built from them.
    """

    entry: dict[str, Any]
    trust_registry: dict[str, Any]
    trust_registry_path: str
    evaluation_time: str | None
    checks: list[TrustRegistryFieldCheck]
    notes: list[str]


def _failure(
    context: _TrustContext,
    *,
    authorization_status: str,
    error: str,
    trust_entry_status: str | None = None,
    signature: _SignatureOutcome | None = None,
) -> TrustRegistryVerificationResult:
    """The result of an evaluation that stopped at a row after the two contracts (rows 4 to 20)."""
    return TrustRegistryVerificationResult(
        trust_registry=context.trust_registry,
        trust_registry_path=context.trust_registry_path,
        trust_registry_id=context.trust_registry["trust_registry_id"],
        evaluation_time=context.evaluation_time,
        checks=tuple(context.checks),
        issuer_id=context.entry["issuer_id"],
        issuer_key_id=context.entry["issuer_key_id"],
        trust_entry_status=trust_entry_status,
        signing_payload_hash=signature.payload_hash if signature is not None else None,
        signing_payload_id=signature.payload_id if signature is not None else None,
        signing_payload_version=signature.payload_version if signature is not None else None,
        signature_status=signature.status if signature is not None else None,
        authorization_status=authorization_status,
        error=error,
        # The entry failed before root authentication was reached, so the honest report is
        # "not evaluated", distinct from "evaluated, nothing pinned".
        root_signature_status=STATUS_NOT_EVALUATED,
        notes=tuple(dict.fromkeys(context.notes + [ROOT_NOT_EVALUATED_NOTE])),
    )


def _contract_rows(
    entry: Any, trust_registry: dict[str, Any], trust_registry_path: str
) -> TrustRegistryVerificationResult | None:
    """Rows 2 and 3: the registry entry, then the trust registry, against its contract; None when both hold."""
    entry_errors = _registry_entry_shape_errors(entry)
    if entry_errors:
        return TrustRegistryVerificationResult(
            trust_registry=trust_registry,
            trust_registry_path=trust_registry_path,
            evaluation_time=None,
            checks=(_check("registry_entry_shape", [], entry_errors, False),),
            authorization_status=AUTH_STATUS_INVALID_REGISTRY_ENTRY,
            error="registry_entry breaks its contract: " + ",".join(entry_errors),
            # Root authentication was not reached on this path either: NOT_EVALUATED, as every later
            # refusal reports it, not a null root status.
            root_signature_status=STATUS_NOT_EVALUATED,
            notes=(ROOT_NOT_EVALUATED_NOTE,),
        )
    trust_errors = _trust_registry_shape_errors(trust_registry)
    if trust_errors:
        return TrustRegistryVerificationResult(
            trust_registry=trust_registry,
            trust_registry_path=trust_registry_path,
            evaluation_time=None,
            checks=(_check("trust_registry_shape", [], trust_errors, False),),
            issuer_id=entry["issuer_id"],
            issuer_key_id=entry["issuer_key_id"],
            authorization_status=AUTH_STATUS_INVALID_TRUST_REGISTRY,
            error="trust_registry breaks its contract: " + ",".join(trust_errors),
            root_signature_status=STATUS_NOT_EVALUATED,
            notes=(ROOT_NOT_EVALUATED_NOTE,),
        )
    return None


def _key_rows(context: _TrustContext) -> TrustRegistryVerificationResult | dict[str, Any]:
    """Rows 4 to 8: the issuer, its key, the key's uniqueness and its status; the trust entry when they hold."""
    entry, checks = context.entry, context.checks
    # From here both documents satisfy their contracts, so every member the rows read is
    # present and of its type: they are read directly.
    issuer_id: str = entry["issuer_id"]
    issuer_key_id: str = entry["issuer_key_id"]
    issuer_entries = [item for item in context.trust_registry["entries"] if item["issuer_id"] == issuer_id]
    checks.append(
        _check(
            "issuer_id_authorized",
            issuer_id,
            [item.get("issuer_id") for item in issuer_entries],
            bool(issuer_entries),
        )
    )
    if not issuer_entries:
        return _failure(
            context,
            authorization_status=AUTH_STATUS_ISSUER_NOT_FOUND,
            error=f"issuer_id {issuer_id!r} is not present in trust_registry",
        )

    matching = [item for item in issuer_entries if item.get("issuer_key_id") == issuer_key_id]
    checks.append(
        _check(
            "issuer_key_id_authorized",
            issuer_key_id,
            [item.get("issuer_key_id") for item in matching],
            bool(matching),
        )
    )
    if not matching:
        return _failure(
            context,
            authorization_status=AUTH_STATUS_KEY_NOT_FOUND,
            error=f"issuer_key_id {issuer_key_id!r} is not present for issuer {issuer_id!r}",
        )

    # Revocation must not be defeatable by list ordering. Taking matching[0] would
    # make the verdict depend on ARRAY ORDER: a registry with the same issuer_id +
    # issuer_key_id twice, one `revoked` and one `active`, would authorize a REVOKED
    # key whenever the active duplicate came first. Revocation is the primary control
    # after a key compromise. A duplicated pair is a malformed registry with no
    # well-defined authority for that key: fail closed rather than guess.
    checks.append(_check("issuer_key_unique", 1, len(matching), len(matching) == 1))
    if len(matching) > 1:
        return _failure(
            context,
            authorization_status=AUTH_STATUS_AMBIGUOUS_KEY,
            error=(
                f"trust_registry contains {len(matching)} entries for issuer {issuer_id!r} "
                f"key {issuer_key_id!r}; the authority for this key is ambiguous"
            ),
        )

    trust_entry: dict[str, Any] = matching[0]
    # Row 6 also: the trust entry's point under another trust entry of the registry, of any
    # issuer, status or key type, in any SEC1 spelling. Revocation is of the key, not of its
    # label, so a revoked point listed again under another issuer_key_id must not authorize.
    sharing = _shares_point_with_other_entry(trust_entry, context.trust_registry["entries"])
    checks.append(_check("issuer_key_point_unique", 0, int(sharing), not sharing))
    if sharing:
        return _failure(
            context,
            authorization_status=AUTH_STATUS_AMBIGUOUS_KEY,
            error=(
                f"trust_registry lists the point of issuer {issuer_id!r} key {issuer_key_id!r} "
                "under another trust entry; the authority for this key is ambiguous"
            ),
        )

    status: str = trust_entry["status"]
    checks.append(_check("issuer_key_status", "active", status, status == "active"))
    # Revocation before suspension. Both are terminal, but revocation is the
    # response to a suspected compromise and suspension is a reversible hold, so when
    # a registry carries both the reader must be told the more serious one.
    if status == "revoked":
        return _failure(
            context,
            authorization_status=AUTH_STATUS_REVOKED,
            error="issuer key is revoked",
            trust_entry_status=status,
        )
    if status == "suspended":
        return _failure(
            context,
            authorization_status=AUTH_STATUS_SUSPENDED,
            error="issuer key is suspended",
            trust_entry_status=status,
        )
    return trust_entry


def _shares_point_with_other_entry(trust_entry: dict[str, Any], entries: Sequence[Any]) -> bool:
    """True when another trust entry of the registry carries the secp256k1 point of ``trust_entry``."""
    return shares_point(
        (other.get("public_key_hex") for other in entries if other is not trust_entry and isinstance(other, dict)),
        trust_entry.get("public_key_hex"),
    )


def _window_rows(
    context: _TrustContext, trust_entry: dict[str, Any], reference_time: datetime
) -> TrustRegistryVerificationResult | None:
    """Rows 9 to 12: the registry's window, then the key's, at the operator's evaluation time; None when both hold.

    Both windows include their bounds. A window that does not hold the time is a review row.
    """
    checks, evaluation_time = context.checks, context.evaluation_time
    trust_registry = context.trust_registry
    trust_effective = _parse_instant(trust_registry.get("effective_at"), field_name="trust_registry.effective_at")
    trust_expires = _parse_instant(trust_registry.get("expires_at"), field_name="trust_registry.expires_at")
    checks.append(
        _check("trust_registry_effective", "<= evaluation_time", evaluation_time, reference_time >= trust_effective)
    )
    checks.append(
        _check("trust_registry_expires", ">= evaluation_time", evaluation_time, reference_time <= trust_expires)
    )
    window: tuple[str, str] | None = None
    if reference_time < trust_effective:
        window = (
            AUTH_STATUS_TRUST_REGISTRY_NOT_YET_EFFECTIVE,
            "trust registry is not yet effective at evaluation time",
        )
    elif reference_time > trust_expires:
        window = (AUTH_STATUS_TRUST_REGISTRY_EXPIRED, "trust registry is expired at evaluation time")
    if window is None:
        effective_from = _parse_instant(trust_entry.get("effective_from"), field_name="trust_entry.effective_from")
        expires_at = _parse_instant(trust_entry.get("expires_at"), field_name="trust_entry.expires_at")
        checks.append(
            _check("issuer_key_effective", "<= evaluation_time", evaluation_time, reference_time >= effective_from)
        )
        checks.append(_check("issuer_key_expires", ">= evaluation_time", evaluation_time, reference_time <= expires_at))
        if reference_time < effective_from:
            window = (AUTH_STATUS_NOT_YET_EFFECTIVE, "issuer key is not yet effective at evaluation time")
        elif reference_time > expires_at:
            window = (AUTH_STATUS_EXPIRED, "issuer key is expired at evaluation time")
    if window is None:
        return None
    return _failure(context, authorization_status=window[0], error=window[1], trust_entry_status=trust_entry["status"])


def _scope_row(context: _TrustContext, trust_entry: dict[str, Any]) -> TrustRegistryVerificationResult | None:
    """Row 13: the entry's asset type and workflow among the key's, by exact equality; None when both are."""
    allowed_asset_types: list[str] = trust_entry["allowed_asset_types"]
    allowed_workflows: list[str] = trust_entry["allowed_workflows"]
    asset_type: str = context.entry["asset_type"]
    workflow: str = context.entry["workflow"]
    asset_allowed = asset_type in allowed_asset_types
    workflow_allowed = workflow in allowed_workflows
    context.checks.append(_check("asset_type_allowed", asset_type, allowed_asset_types, asset_allowed))
    context.checks.append(_check("workflow_allowed", workflow, allowed_workflows, workflow_allowed))
    if asset_allowed and workflow_allowed:
        return None
    return _failure(
        context,
        authorization_status=AUTH_STATUS_SCOPE_MISMATCH,
        error="issuer key is not authorized for registry_entry asset_type/workflow scope",
        trust_entry_status=trust_entry["status"],
    )


def _signature_rows(context: _TrustContext, trust_entry: dict[str, Any]) -> _SignatureOutcome:
    """Rows 14 to 20 against the key the trust entry authorizes, recorded as checks."""
    key_type = trust_entry.get("key_type")
    context.checks.append(
        _check(
            "issuer_key_type_supported",
            [list(pair) for pair in SUPPORTED_SIGNATURE_PAIRS],
            key_type,
            any(key_type == pair[1] for pair in SUPPORTED_SIGNATURE_PAIRS),
            note=CRYPTOGRAPHIC_CAPABILITY_PROFILE,
        )
    )
    signature = _verify_signature(
        context.entry,
        trust_entry["public_key_hex"],
        expected_key_id=context.entry["issuer_key_id"],
        key_type=key_type,
    )
    context.checks.append(
        _check(
            "registry_entry_signature",
            SIG_STATUS_VALID,
            signature.status,
            signature.status == SIG_STATUS_VALID,
            note=signature.payload_id,
        )
    )
    return signature


def verify_registry_entry_trust(
    entry: dict[str, Any],
    *,
    trust_registry_path: str | Path,
    trust_roots: Sequence[TrustRootKey] = PINNED_TRUST_ROOTS,
    evaluation_time: str | None = None,
) -> TrustRegistryVerificationResult:
    """Verify a registry entry against a supplied local trust registry.

    Deterministic local authorization check: the registry-entry issuer signature, the
    authorization of the issuer and its key, the scope and the validity windows, from local
    material only. It does not
    verify registry inclusion, anchors or finality.

    ``trust_roots`` authenticates the trust registry itself. Default empty means refuse:
    the result reports ``NO_PINNED_TRUST_ROOT`` rather than claiming a registry is
    authentic when nothing establishes that it is.

    ``evaluation_time`` is the operator's evaluation time (trust-registry-authorization.md §2), a
    calendar instant of the form ``YYYY-MM-DDTHH:MM:SSZ``, or None. The issuer's own dates are
    never read as a time. Without it, rows 9 to 12 of section 6 and rows 9 and 10 of trust-root.md
    section 5 are skipped: a revoked key still fails, and an evaluation that holds leaves
    authorization not established, which the caller reports as evaluation_time_not_provided.

    ``trust_roots`` are validated as a whole first (trust-root.md §3): one malformed root raises
    ``TrustRootError`` before the trust registry is read; an evaluation time that is not a
    calendar instant raises ``EvaluationTimeError``. A host that fails to inspect or read the
    trust registry raises its ``OSError``: nothing about the registry was read, so no status is
    reported for it (report-contract.md section 5.3, trust_registry_read_failed).

    The rows are evaluated in the order of section 6 and the evaluation stops at the first that
    holds: the two contracts, the key (rows 4 to 8), the windows (9 to 12), the scope (13) and
    the signature (14 to 20); the root is authenticated only after all of them hold.
    """

    trust_roots = validate_trust_roots(trust_roots)
    if evaluation_time is not None:
        evaluation_time = operator_evaluation_time(evaluation_time)
    path = str(trust_registry_path)
    try:
        trust_registry = read_trust_registry(trust_registry_path)
        # Row 2 judges any value: one that is not an object breaks the entry's contract
        # (INVALID_REGISTRY_ENTRY), and says nothing about the trust registry, which row 1 read.
        refused = _contract_rows(entry, trust_registry, path)
        if refused is not None:
            return refused

        # The operator's evaluation time, or None: the rows that read it are skipped without one,
        # and no issuer date stands in for it (trust-registry-authorization.md section 2).
        reference_time = (
            _parse_instant(evaluation_time, field_name="evaluation_time") if evaluation_time is not None else None
        )
        context = _TrustContext(entry, trust_registry, path, evaluation_time, checks=[], notes=[])
        trust_entry = _key_rows(context)
        if isinstance(trust_entry, TrustRegistryVerificationResult):
            return trust_entry
        # Key status came first: a revoked key behind a stale registry copy is reported as revoked.
        if reference_time is not None:
            refused = _window_rows(context, trust_entry, reference_time)
            if refused is not None:
                return refused
        refused = _scope_row(context, trust_entry)
        if refused is not None:
            return refused
        status: str = trust_entry["status"]
        signature = _signature_rows(context, trust_entry)
        if signature.status != SIG_STATUS_VALID:
            return _failure(
                context,
                authorization_status=AUTH_STATUS_VALID,
                error=signature.error or "registry_entry signature failed",
                trust_entry_status=status,
                signature=signature,
            )

        # Root authentication is COMPUTED rather than asserted, so the report tells "not
        # checked" from "checked, and nothing is pinned". With no root pinned the outcome
        # is not-verified, with a status saying why, and a caller who pins a root gets a real
        # answer.
        notes = context.notes
        root_result = verify_trust_registry_root_signature(
            trust_registry, evaluated_at=evaluation_time, roots=trust_roots
        )
        if root_result.ok:
            notes.append("trust_registry_root_signature_verified")
        else:
            notes.append(f"trust_registry_root_signature_not_verified:{root_result.status.lower()}")
        notes.extend(
            [
                "registry_inclusion_anchor_finality_not_verified",
                "issuer_real_world_identity_not_verified_beyond_supplied_trust_registry",
            ]
        )
        return TrustRegistryVerificationResult(
            trust_registry=trust_registry,
            trust_registry_path=path,
            trust_registry_id=trust_registry["trust_registry_id"],
            evaluation_time=evaluation_time,
            checks=tuple(context.checks),
            issuer_id=entry["issuer_id"],
            issuer_key_id=entry["issuer_key_id"],
            trust_entry_status=status,
            signing_payload_hash=signature.payload_hash,
            signing_payload_id=signature.payload_id,
            signing_payload_version=signature.payload_version,
            signature_status=signature.status,
            authorization_status=AUTH_STATUS_VALID,
            root_signature_verified=root_result.ok,
            root_signature_status=root_result.status,
            root_key_id=root_result.root_key_id,
            notes=tuple(dict.fromkeys(notes)),
        )
    except TrustRegistryVerificationError as exc:
        return TrustRegistryVerificationResult(
            trust_registry=None,
            trust_registry_path=path,
            evaluation_time=None,
            checks=(),
            authorization_status=AUTH_STATUS_INVALID_TRUST_REGISTRY,
            error=str(exc),
            root_signature_status=STATUS_NOT_EVALUATED,
            notes=(ROOT_NOT_EVALUATED_NOTE,),
        )
    except CanonicalizationError as exc:
        # Not reachable from a document read under input strictness, whose rules make every document
        # canonicalizable (report-contract.md section 5.3); kept as a defense in depth.
        return TrustRegistryVerificationResult(
            trust_registry=None,
            trust_registry_path=path,
            evaluation_time=None,
            checks=(),
            authorization_status=AUTH_STATUS_INVALID_TRUST_REGISTRY,
            error=f"trust_registry_canonicalization_failed:{type(exc).__name__}",
            root_signature_status=STATUS_NOT_EVALUATED,
            notes=(ROOT_NOT_EVALUATED_NOTE,),
        )
