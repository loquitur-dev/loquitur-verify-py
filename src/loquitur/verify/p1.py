"""P1 and canonical-input verification for the public offline verifier.

This module stops at P1 and the canonical input:
- load p1.json and p1.sha256;
- canonicalize p1 with the RFC 8785 (JCS) profile the rest of the verifier uses;
- verify p1.sha256;
- load canonical_input.json when present;
- rebuild p1.ih from canonical_input.json and p1.ik;
- return OFFLINE_REVIEW, not OK, when canonical_input.json is missing.

It does not verify envelopes, registry entries, issuer signatures, anchors, or trust
registry state.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import (
    CanonicalizationError,
    JsonLoadError,
    canonical_json_bytes,
    canonical_json_sha256,
    loads_json_bytes,
    sha256_hex,
)
from .errors import LoquiturVerifyError
from .manifest import (
    SHA256_LABEL,
    STATUS_OFFLINE_FAIL,
    STATUS_OFFLINE_OK,
    STATUS_OFFLINE_REVIEW,
    is_bare_sha256,
    is_blank,
    is_prefixed_sha256,
)
from .members import MemberTooLargeError, member_is_file, read_member_bytes

DEFAULT_P1_MAX_BYTES = 1024


class P1VerificationError(LoquiturVerifyError):
    """Base class for expected P1 verification failures."""


class P1MissingError(P1VerificationError):
    """Raised when p1.json is missing."""


class P1TypeError(P1VerificationError):
    """Raised when p1.json or canonical_input.json has the wrong JSON type."""


class P1CanonicalizationError(P1VerificationError):
    """Raised when p1 cannot be canonicalized as a P1 object."""


@dataclass(frozen=True)
class P1VerificationResult:
    p1: dict[str, Any]
    canonical_input: dict[str, Any] | None
    p1_sha256_expected: str | None
    p1_sha256_actual: str
    p1_sha256_ok: bool
    p1_size_bytes: int
    canonical_input_present: bool
    input_hash_expected: str | None
    input_hash_actual: str | None
    input_hash_ok: bool | None
    input_keys: tuple[str, ...] | None
    notes: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if self.p1_sha256_ok is False or self.input_hash_ok is False:
            return STATUS_OFFLINE_FAIL
        if self.input_hash_ok is not True:
            return STATUS_OFFLINE_REVIEW
        return STATUS_OFFLINE_OK

    @property
    def verdict(self) -> str:
        if self.status == STATUS_OFFLINE_OK:
            return "PASS"
        if self.status == STATUS_OFFLINE_REVIEW:
            return "REVIEW"
        return "FAIL"

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OFFLINE_OK


def read_p1(bundle_root: Path) -> dict[str, Any]:
    if not member_is_file(bundle_root, "p1.json"):
        raise P1MissingError("p1_missing")
    try:
        p1 = loads_json_bytes(read_member_bytes(bundle_root, "p1.json"), name="p1.json")
    except (JsonLoadError, MemberTooLargeError) as exc:
        raise P1VerificationError(str(exc)) from exc
    if not isinstance(p1, dict):
        raise P1TypeError("p1_invalid_type")
    return p1


def read_canonical_input(bundle_root: Path) -> dict[str, Any] | None:
    if not member_is_file(bundle_root, "canonical_input.json"):
        return None
    try:
        canonical_input = loads_json_bytes(
            read_member_bytes(bundle_root, "canonical_input.json"), name="canonical_input.json"
        )
    except (JsonLoadError, MemberTooLargeError) as exc:
        raise P1VerificationError(str(exc)) from exc
    if not isinstance(canonical_input, dict):
        raise P1TypeError("canonical_input_invalid_type")
    return canonical_input


def read_stored_p1_sha256(bundle_root: Path) -> str | None:
    if not member_is_file(bundle_root, "p1.sha256"):
        return None
    try:
        raw = read_member_bytes(bundle_root, "p1.sha256").decode("utf-8")
    except (UnicodeDecodeError, MemberTooLargeError):
        # Untrusted input: an undecodable sidecar is a mismatch, not a crash.
        return None
    # Exactly as stored, or nothing: the sidecar is the 64 lowercase hexadecimal characters
    # of the digest and no other byte, not even a newline. Nothing is stripped or lower-cased,
    # so neither "<digest>\n" nor an uppercase digest matches.
    return raw if is_bare_sha256(raw) else None


# The closed contract, not only the marker s=="p1": the version is checked and no extra
# field is accepted. A P1 lacking `v` and carrying a smuggled field is self-consistent
# (every digest matches, because the digest is computed over whatever P1 contains), and
# digest self-consistency is not protocol conformance: "these bytes hash to these
# hashes" is not "this is a valid P1".
P1_ALLOWED_FIELDS = frozenset({"s", "v", "ih", "ik"})
P1_SUPPORTED_VERSIONS = frozenset({1})


def protocol_integer(value: Any) -> int | None:
    """Return `value` as an integer under the protocol's canonical numeric model.

    JSON `1.0` decodes to a Python float and to a JavaScript Number, and
    RFC 8785 serializes both as `1`, so under the canonical form the protocol commits
    to, `1.0` and `1` are the same value, and every digest over them is identical, so both
    spellings are accepted identically (bundle-objects.md section 3, "`v` under the canonical
    numeric model"). Deferring to JCS is what makes them agree.

    A bool is not an integer here: `True` is `1` in Python but `true` in JSON.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def p1_shape_errors(p1: Any) -> list[str]:
    """Closed-contract validation of a P1 projection. Empty list == conformant."""
    errors: list[str] = []
    if not isinstance(p1, dict):
        return ["p1_not_an_object"]
    if p1.get("s") != "p1":
        errors.append("p1_invalid_marker")
    version = p1.get("v")
    normalized_version = protocol_integer(version)
    if version is None:
        errors.append("p1_missing_version")
    elif normalized_version is None or normalized_version not in P1_SUPPORTED_VERSIONS:
        errors.append(f"p1_unsupported_version:{version!r}")
    # An explicitly empty input-key projection has two incompatible readings: `[]` as
    # "no projection given", hashing the whole canonical input, or as a projection over
    # no keys, hashing `{}`. The two expected `ih` values are mutually exclusive. It is
    # refused rather than assigned a meaning, because a projection over no keys commits
    # to nothing about the input it claims to cover.
    if "ik" in p1:
        keys = p1["ik"]
        if isinstance(keys, list) and not keys:
            errors.append("p1_empty_input_key_projection")
        elif not (isinstance(keys, list) and all(isinstance(key, str) for key in keys)):
            # A present ik that is not a list of strings, null included, is a rejection
            # (bundle-objects.md §3), not replaced by the whole canonical input: the ih would
            # then commit to keys the producer never declared.
            errors.append("p1_input_key_projection_not_a_string_list")
        elif len(set(keys)) != len(keys):
            # ["a", "a"] projects one member under a declaration that names two; the
            # projection is ambiguous about what it covers, so it is refused rather than
            # collapsed.
            errors.append("p1_input_key_projection_duplicate")
        elif any(is_blank(key) for key in keys):
            # The keys are the projection's free strings (bundle-objects.md section 3): a key
            # made only of the whitespace set W names no member of the canonical input.
            errors.append("p1_input_key_projection_empty_key")
    # ih is part of the contract, not only of the input-hash check: sha256: and exactly 64
    # lowercase hex characters (bundle-objects.md §3). An uppercase, bare, padded or absent ih
    # refuses the P1 itself, so p1_sha256 is false (bundle-objects.md section 6, a refused layer);
    # envelope_links is false beside it, an informative result (report-contract.md section 2).
    if not is_prefixed_sha256(p1.get("ih")):
        errors.append("p1_ih_missing_or_invalid")
    for unexpected in sorted(set(p1) - P1_ALLOWED_FIELDS):
        errors.append(f"p1_unexpected_field:{unexpected}")
    return errors


def canonical_p1_bytes(p1: dict[str, Any], *, max_bytes: int = DEFAULT_P1_MAX_BYTES) -> bytes:
    shape_errors = p1_shape_errors(p1)
    if shape_errors:
        raise P1CanonicalizationError(";".join(shape_errors))
    try:
        data = canonical_json_bytes(p1)
    except CanonicalizationError as exc:
        # Not reachable from a document read under input strictness, whose rules make every document
        # canonicalizable (report-contract.md section 5.3); kept as a defense in depth.
        raise P1CanonicalizationError(f"p1_canonicalize_failed:{type(exc).__name__}") from exc
    if len(data) > int(max_bytes):
        raise P1CanonicalizationError("p1_too_large")
    return data


def canonical_p1_sha256(p1: dict[str, Any], *, max_bytes: int = DEFAULT_P1_MAX_BYTES) -> tuple[str, int]:
    data = canonical_p1_bytes(p1, max_bytes=max_bytes)
    return sha256_hex(data), len(data)


def input_keys_from_p1(p1: dict[str, Any], canonical_input: dict[str, Any]) -> tuple[str, ...] | None:
    """The projection ik declares; the whole canonical input only when ik is absent.

    p1_shape_errors has already refused a present ik that is not a non-empty list of
    distinct strings, so the whole-input fallback is reached by absence alone.
    """
    if "ik" in p1:
        return tuple(p1["ik"])
    return tuple(canonical_input.keys()) if canonical_input else None


def verified_p1_sha256(bundle_root: Path, *, max_p1_bytes: int = DEFAULT_P1_MAX_BYTES) -> str | None:
    """The canonical P1 digest when p1.json satisfies its contract and matches p1.sha256.

    None when P1 is absent, unreadable, malformed, too large or unequal to its sidecar. It
    does not touch canonical_input.json, so an envelope's P1 link can be decided when full
    P1 verification stopped on the canonical input.
    """
    try:
        digest, _size = canonical_p1_sha256(read_p1(bundle_root), max_bytes=max_p1_bytes)
        stored = read_stored_p1_sha256(bundle_root)
    except (P1VerificationError, OSError):
        return None
    return digest if stored == digest else None


def canonical_input_hash(canonical_input: dict[str, Any], keys: Iterable[str] | None) -> str:
    if keys:
        payload = {key: canonical_input.get(key, None) for key in keys}
    else:
        payload = dict(canonical_input)
    return canonical_json_sha256(payload)


def verify_p1(bundle_root: Path, *, max_p1_bytes: int = DEFAULT_P1_MAX_BYTES) -> P1VerificationResult:
    notes: list[str] = []
    p1 = read_p1(bundle_root)
    p1_sha_actual, p1_size = canonical_p1_sha256(p1, max_bytes=max_p1_bytes)
    p1_sha_expected = read_stored_p1_sha256(bundle_root)
    p1_sha_ok = bool(p1_sha_expected and p1_sha_expected == p1_sha_actual)
    if p1_sha_expected is None:
        notes.append("p1_sha256_missing_or_invalid")
    elif not p1_sha_ok:
        notes.append("p1_sha_mismatch")

    canonical_input = read_canonical_input(bundle_root)
    canonical_input_present = canonical_input is not None
    # canonical_p1_sha256 has already refused a P1 whose ih is not exactly 64 lowercase hex
    # characters (p1_shape_errors); the test stays so that the input hash never compares
    # against anything else.
    input_hash_expected = p1.get("ih") if is_prefixed_sha256(p1.get("ih")) else None
    input_hash_actual: str | None = None
    input_hash_ok: bool | None = None
    input_keys: tuple[str, ...] | None = None

    if canonical_input is None:
        notes.append("canonical_input_not_provided")
    else:
        input_keys = input_keys_from_p1(p1, canonical_input)
        try:
            input_hash_actual = SHA256_LABEL + canonical_input_hash(canonical_input, input_keys)
        except CanonicalizationError as exc:
            # Not reachable from a document read under input strictness, whose rules make every document
            # canonicalizable (report-contract.md section 5.3); kept as a defense in depth.
            notes.append(f"input_hash_rebuild_failed:{type(exc).__name__}")
            input_hash_ok = False
        else:
            input_hash_ok = bool(input_hash_expected and input_hash_actual == input_hash_expected)
            if input_hash_expected is None:
                notes.append("p1_ih_missing_or_invalid")
            elif not input_hash_ok:
                notes.append("input_hash_mismatch")

    return P1VerificationResult(
        p1=p1,
        canonical_input=canonical_input,
        p1_sha256_expected=p1_sha_expected,
        p1_sha256_actual=p1_sha_actual,
        p1_sha256_ok=p1_sha_ok,
        p1_size_bytes=p1_size,
        canonical_input_present=canonical_input_present,
        input_hash_expected=input_hash_expected,
        input_hash_actual=input_hash_actual,
        input_hash_ok=input_hash_ok,
        input_keys=input_keys,
        notes=tuple(notes),
    )
