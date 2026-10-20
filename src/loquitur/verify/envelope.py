"""Verification of the env1 envelope for the offline verifier.

This module stops at the envelope digest and its local links:
- load envelope_env1.json, the one envelope name;
- recompute the envelope's canonical digest and compare it with envelope.sha256;
- verify the envelope's link to the manifest when manifest information is supplied or present;
- verify the envelope's link to P1 when P1 information is supplied or present;
- classify registry-entry and signature verification as unsupported here.

It does not verify issuer signatures, public registry entries, trust registries,
chain anchors, revocation, or online registry state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .canonical import CanonicalizationError, JsonLoadError, canonical_json_sha256, loads_json_bytes
from .errors import LoquiturVerifyError
from .manifest import (
    STATUS_OFFLINE_FAIL,
    STATUS_OFFLINE_OK,
    STATUS_OFFLINE_REVIEW,
    ManifestVerificationResult,
    is_bare_sha256,
    is_blank,
    is_prefixed_sha256,
    labelled,
    usable_bundle_id,
)
from .members import MemberTooLargeError, member_is_file, read_member_bytes
from .p1 import P1VerificationResult, protocol_integer
from .registry_link import registry_entry_contract_violations

REGISTRY_ENTRY_NOT_PROVIDED = "REGISTRY_ENTRY_NOT_PROVIDED"


class EnvelopeVerificationError(LoquiturVerifyError):
    """Base class for expected envelope verification failures."""


class EnvelopeTypeError(EnvelopeVerificationError):
    """Raised when an envelope JSON document is not an object."""


@dataclass(frozen=True)
class EnvelopeVerificationResult:
    envelope: dict[str, Any] | None
    envelope_path_name: str | None
    envelope_sha256_expected: str | None
    envelope_sha256_actual: str | None
    envelope_sha256_ok: bool | None
    envelope_present: bool
    envelope_sha256_present: bool
    envelope_files_complete: bool
    bundle_id_expected: str | None
    bundle_id_actual: str | None
    bundle_id_ok: bool | None
    manifest_sha256_expected: str | None
    manifest_sha256_actual: str | None
    manifest_link_ok: bool | None
    p1_sha256_expected: str | None
    p1_sha256_actual: str | None
    p1_link_ok: bool | None
    registry_entry_present: bool
    registry_status: str
    registry_signature_supported: bool
    notes: tuple[str, ...] = ()

    @property
    def links_ok(self) -> bool | None:
        link_values = [self.bundle_id_ok, self.manifest_link_ok, self.p1_link_ok]
        checked = [value for value in link_values if value is not None]
        if not checked:
            return None
        return all(checked)

    @property
    def status(self) -> str:
        hard_values = [self.envelope_sha256_ok, self.bundle_id_ok, self.manifest_link_ok, self.p1_link_ok]
        if self.envelope_files_complete is False or any(value is False for value in hard_values):
            return STATUS_OFFLINE_FAIL
        if self.envelope_present is False or self.envelope_sha256_ok is not True:
            return STATUS_OFFLINE_REVIEW
        # Absence of links is not "no link failed". An envelope whose entire purpose is to
        # bind bundle_id/manifest/p1 attests nothing if it binds none of them: that is not a
        # pass, it is unverifiable.
        #
        # Nor is one link enough: a bundle_id comparison, a plain copyable string, holding
        # while both DIGEST links were skipped would bind nothing cryptographically. Each link
        # must have been evaluated and held; a link that could not be evaluated leaves the
        # envelope unverifiable, which is REVIEW, not OK.
        if any(value is not True for value in (self.bundle_id_ok, self.manifest_link_ok, self.p1_link_ok)):
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


def envelope_path(bundle_root: Path) -> Path | None:
    """The envelope member, selected by existence, never by whether it parses.

    envelope_env1.json is the only envelope name (bundle-objects.md section 4): this version
    defines no earlier one, and envelope.json is an ordinary member name like any other.
    """
    if member_is_file(bundle_root, "envelope_env1.json"):
        return bundle_root / "envelope_env1.json"
    return None


def envelope_member_present(bundle_root: Path) -> bool:
    """Whether an envelope member exists, as a fact about the bundle (bundle-objects.md §6).

    Presence is observed, not concluded: an envelope that exists and cannot be read is
    present, and the report says envelope_present true for it.
    """
    return member_is_file(bundle_root, "envelope_env1.json")


def read_envelope(bundle_root: Path) -> tuple[dict[str, Any], str]:
    path = envelope_path(bundle_root)
    if path is None:
        raise FileNotFoundError("envelope_missing")
    try:
        envelope = loads_json_bytes(read_member_bytes(bundle_root, path.name), name=path.name)
    except (JsonLoadError, MemberTooLargeError) as exc:
        raise EnvelopeVerificationError(str(exc)) from exc
    if not isinstance(envelope, dict):
        raise EnvelopeTypeError("envelope_invalid_type")
    return envelope, path.name


def read_stored_envelope_sha256(bundle_root: Path) -> str | None:
    if not member_is_file(bundle_root, "envelope.sha256"):
        return None
    try:
        raw = read_member_bytes(bundle_root, "envelope.sha256").decode("utf-8")
    except (UnicodeDecodeError, MemberTooLargeError):
        # Untrusted input: an undecodable sidecar is a mismatch, not a crash.
        return None
    # Exactly as stored or nothing: an uppercase or newline-terminated sidecar is not folded
    # into the digest it resembles, and does not match.
    return raw if is_bare_sha256(raw) else None


def canonical_envelope_sha256(envelope: dict[str, Any]) -> str:
    return canonical_json_sha256(envelope)


def judged_envelope_sha256(envelope: dict[str, Any], *, shape_ok: bool) -> str | None:
    """The envelope's canonical digest, judged as the envelope layer judges it beside its sidecar.

    An envelope that satisfies its contract and cannot be canonicalized is refused
    (envelope_verification_failed). One that breaks its contract is not refused for it: its layer
    fails, and it has no digest to compare (None). The one canonicalization rule of the envelope
    layer: the layer and the row judged over the envelope members the host did read when it failed
    to read another both apply it. Not reachable from a document read under input strictness, whose
    rules make every document canonicalizable (report-contract.md section 5.3); kept as a defense
    in depth, so that such an envelope never escapes verify_path as a verifier fault.
    """
    try:
        return canonical_envelope_sha256(envelope)
    except CanonicalizationError as exc:
        if not shape_ok:
            return None
        raise EnvelopeVerificationError(f"envelope_canonicalize_failed:{type(exc).__name__}") from exc


def _manifest_identity(manifest_result: ManifestVerificationResult | None) -> tuple[str | None, str | None]:
    """The bundle_id and digest a link may be checked against, from a verified manifest only.

    Verified means parsed, conformant to its closed contract, and equal to its sidecar. A
    link to anything less is not a link to the manifest: manifest.json and manifest.sha256
    are not read afresh when verification failed, so an envelope naming a refused manifest
    never reports its link as holding. Declared files are not part of this: a tampered
    member fails the file check, not the envelope's commitment to the manifest.
    """
    if manifest_result is None or not manifest_result.shape_ok or not manifest_result.manifest_sha256_ok:
        return None, None
    manifest = manifest_result.manifest
    manifest_sha = manifest_result.manifest_sha256_actual

    # Never derive the expected bundle_id from the filesystem. For a ZIP input
    # bundle_root.name is the archive's own top-level entry prefix, a name the
    # counterparty writes, so such a fallback would compare an attacker-supplied envelope
    # field against an attacker-supplied path and report the result as a verified link.
    # If the manifest does not name the bundle, nothing here does.
    #
    # Taken as written: a string that is not blank, never str() of another type and never
    # trimmed, so 7 does not equal "7", true does not equal "True", and " id " does not
    # equal "id".
    return usable_bundle_id(manifest), manifest_sha


def _p1_sha(p1_result: P1VerificationResult | None, p1_sha256_verified: str | None) -> str | None:
    """The P1 digest a link may be checked against, from a verified P1 only.

    From the result when there is one and its sidecar matched; otherwise only what the
    caller verified itself and passes explicitly. There is no fallback to p1.sha256: a
    sidecar next to a P1 that failed its contract, or no P1 at all, is not a digest the
    bundle verifiably commits to, and linking against it would report envelope_links true
    over a refused P1.
    """
    if p1_result is not None:
        return p1_result.p1_sha256_actual if p1_result.p1_sha256_ok else None
    return p1_sha256_verified


# The env1 envelope is a closed contract. Anything outside this set, or a
# version this verifier does not implement, means the envelope cannot be interpreted, and an
# envelope that cannot be interpreted must not contribute a PASS.
#
# The set comes from the contract (bundle-objects.md section 4), not from a sample: the
# bundle fixtures carry only the six core fields, but the envelope also legitimately
# carries anchor/provenance metadata (ts, network, p1_txid, uri) and subject identifiers
# (asset_id, asset_type, receipt_id).
ENVELOPE_ALLOWED_FIELDS = frozenset(
    {
        # core envelope identity + links
        "s",
        "v",
        "bundle_id",
        "bundle_manifest_sha256",
        "p1_sha256",
        "registry_entry",
        # anchor / provenance metadata
        "ts",
        "network",
        "p1_txid",
        "uri",
        # subject identifiers
        "asset_id",
        "asset_type",
        "receipt_id",
    }
)
ENVELOPE_SUPPORTED_VERSIONS = frozenset({1})
# The optional members carry declared types (bundle-objects.md §4). No check reads them, and
# that is why: a member the contract leaves untyped is the same silence as a member it does not
# name, and two verifiers reading `ts: {}` differently disagree about the same bytes.
ENVELOPE_STRING_OR_NULL_FIELDS = ("network", "p1_txid", "uri", "asset_id", "asset_type", "receipt_id")
# `ts` is a time in whole seconds, under the same canonical numeric model as `v`: 1 and 1.0 are
# one value under RFC 8785, so a verifier that refused the float form would refuse a bundle
# whose every digest matches.
ENVELOPE_INTEGER_OR_NULL_FIELDS = ("ts",)
# The three links are what an envelope IS. An envelope omitting bundle_manifest_sha256
# and p1_sha256 binds no digest at all, and that silence is not "no link failed".
# Declaring them required makes an unbound envelope a shape failure rather than a clean
# bill of health.
ENVELOPE_REQUIRED_FIELDS = ("bundle_id", "bundle_manifest_sha256", "p1_sha256")


def envelope_shape_errors_for(envelope: Any) -> list[str]:
    """Closed-contract validation of an env1 envelope. Empty list == conformant."""
    errors: list[str] = []
    if not isinstance(envelope, dict):
        return ["envelope_not_an_object"]
    if envelope.get("s") != "env1":
        errors.append("envelope_invalid_marker")
    version = envelope.get("v")
    # Same canonical numeric model as the P1 version field: JCS serializes
    # 1.0 and 1 identically, so the two forms must be accepted identically.
    normalized_version = protocol_integer(version)
    if version is None:
        errors.append("envelope_missing_version")
    elif normalized_version is None or normalized_version not in ENVELOPE_SUPPORTED_VERSIONS:
        errors.append(f"envelope_unsupported_version:{version!r}")
    for field in ENVELOPE_REQUIRED_FIELDS:
        if envelope.get(field) is None:
            errors.append(f"envelope_missing_field:{field}")
    for field in ENVELOPE_STRING_OR_NULL_FIELDS:
        value = envelope.get(field)
        if value is not None and not isinstance(value, str):
            errors.append(f"envelope_invalid_field_type:{field}")
        elif isinstance(value, str) and is_blank(value):
            # The envelope's free strings (bundle-objects.md section 4): a string made only of
            # the whitespace set W is a rejection in the same way as a value of another type.
            errors.append(f"envelope_empty_field:{field}")
    for field in ENVELOPE_INTEGER_OR_NULL_FIELDS:
        value = envelope.get(field)
        if value is not None and protocol_integer(value) is None:
            errors.append(f"envelope_invalid_field_type:{field}")
    registry_entry = envelope.get("registry_entry")
    if registry_entry is not None:
        # A registry entry carried inside the envelope is a registry entry: one contract for one
        # concept (registry-link.md §2). Nothing here compares it with anything; it is validated
        # because the envelope declares it to be one.
        if not isinstance(registry_entry, dict) or registry_entry_contract_violations(registry_entry):
            errors.append("envelope_invalid_registry_entry")
    for unexpected in sorted(set(envelope) - ENVELOPE_ALLOWED_FIELDS):
        errors.append(f"envelope_unexpected_field:{unexpected}")
    return errors


# What a run reports for the envelope layer when nothing of it was evaluated. Every result below
# is this template with what differs: the envelope layer never reads a registry entry, so the
# three registry fields are the same on every path.
_NOTHING_EVALUATED = EnvelopeVerificationResult(
    envelope=None,
    envelope_path_name=None,
    envelope_sha256_expected=None,
    envelope_sha256_actual=None,
    envelope_sha256_ok=None,
    envelope_present=False,
    envelope_sha256_present=False,
    envelope_files_complete=True,
    bundle_id_expected=None,
    bundle_id_actual=None,
    bundle_id_ok=None,
    manifest_sha256_expected=None,
    manifest_sha256_actual=None,
    manifest_link_ok=None,
    p1_sha256_expected=None,
    p1_sha256_actual=None,
    p1_link_ok=None,
    registry_entry_present=False,
    registry_status=REGISTRY_ENTRY_NOT_PROVIDED,
    registry_signature_supported=False,
)


def _link(raw: Any, actual: str | None, expected: str | None, name: str, notes: list[str]) -> bool | None:
    """One envelope link: whether it holds, or None when the envelope makes no such claim.

    ``raw`` is the member as written and ``actual`` the same value when it is well formed, else
    None; ``expected`` is what the verified manifest or P1 gives, or None when nothing verified.
    A present claim that is malformed fails (``envelope_<name>_malformed``): it is not a link that
    was never made. A well-formed claim with nothing verified to hold it against fails too
    (``envelope_<name>_unverifiable``), so an unreadable manifest or P1 cannot leave
    envelope_links true behind it. Otherwise the two are compared exactly, as whole strings
    (``envelope_<name>_mismatch`` when they differ).
    """
    if actual is not None and expected is not None:
        if actual == expected:
            return True
        notes.append(f"envelope_{name}_mismatch")
        return False
    if actual is None and raw is not None:
        notes.append(f"envelope_{name}_malformed")
        return False
    if actual is not None:
        notes.append(f"envelope_{name}_unverifiable")
        return False
    return None


def verify_envelope(
    bundle_root: Path,
    *,
    manifest_result: ManifestVerificationResult | None = None,
    p1_result: P1VerificationResult | None = None,
    p1_sha256_verified: str | None = None,
) -> EnvelopeVerificationResult:
    """Verify the envelope and its three links.

    ``p1_sha256_verified`` is consulted only when ``p1_result`` is None: the digest of a P1
    that the caller verified (contract, size, sidecar) although its full verification could
    not complete, for instance because canonical_input.json was unreadable. None means no
    verified P1, and the P1 link fails.

    The envelope layer never reads a registry entry: its result always reports none, and
    the report's registry block is built from the run's own facts (whether the operator
    supplied an entry, the registry link, the trust registry).
    """
    notes: list[str] = []
    env_path = envelope_path(bundle_root)

    envelope_present = env_path is not None
    envelope_sha_present = member_is_file(bundle_root, "envelope.sha256")
    registry_note = REGISTRY_ENTRY_NOT_PROVIDED.lower()

    if not envelope_present and not envelope_sha_present:
        notes.append("envelope_not_provided")
        notes.append(registry_note)
        return replace(_NOTHING_EVALUATED, notes=tuple(notes))

    if not envelope_present or not envelope_sha_present:
        notes.append("envelope_files_incomplete")
        notes.append(registry_note)
        return replace(
            _NOTHING_EVALUATED,
            envelope_path_name=env_path.name if env_path is not None else None,
            envelope_sha256_expected=read_stored_envelope_sha256(bundle_root) if envelope_sha_present else None,
            envelope_sha256_ok=False,
            envelope_present=envelope_present,
            envelope_sha256_present=envelope_sha_present,
            envelope_files_complete=False,
            notes=tuple(notes),
        )

    envelope, path_name = read_envelope(bundle_root)

    # The closed contract, schema/version marker included: an envelope declaring
    # {"s":"env1","v":999,"unexpected":...} with no links at all is not a conformant env1,
    # and a bundle whose envelope is not a conformant env1 must not be reported as verified.
    envelope_shape_errors = envelope_shape_errors_for(envelope)
    if envelope_shape_errors:
        notes.extend(envelope_shape_errors)
        # Report the digest comparison rather than stamping it False along with everything
        # else: envelope_sha256_expected and _actual equal beside envelope_sha256_ok: false
        # would tell a third-party reader the digest did not match while showing that it did.
        # The two situations are not the same: a malformed envelope that still matches its
        # stored digest was authored wrong, one that does not was altered after the fact. The
        # refusal does not depend on this field (envelope_files_complete=False below already
        # forces OFFLINE_FAIL, as do the three link checks), so the honest value costs nothing.
        stored_envelope_sha256 = read_stored_envelope_sha256(bundle_root)
        # Refused already by its shape: an envelope that also cannot be canonicalized has no
        # digest to report, and that is a failed comparison, not a crash.
        actual_envelope_sha256 = judged_envelope_sha256(envelope, shape_ok=False)
        return replace(
            _NOTHING_EVALUATED,
            envelope=envelope,
            envelope_path_name=path_name,
            envelope_sha256_expected=stored_envelope_sha256,
            envelope_sha256_actual=actual_envelope_sha256,
            # The sidecar is present on this path (an absent one returned above), so the
            # comparison was made: a sidecar that is not a bare digest (uppercase, prefixed,
            # newline-terminated or undecodable) reads back as None and does not hold.
            envelope_sha256_ok=(
                stored_envelope_sha256 is not None
                and actual_envelope_sha256 is not None
                and stored_envelope_sha256 == actual_envelope_sha256
            ),
            envelope_present=True,
            envelope_sha256_present=True,
            envelope_files_complete=False,
            bundle_id_ok=False,
            manifest_link_ok=False,
            p1_link_ok=False,
            notes=tuple(notes),
        )

    expected_env_sha = read_stored_envelope_sha256(bundle_root)
    actual_env_sha = judged_envelope_sha256(envelope, shape_ok=True)
    env_sha_ok = bool(expected_env_sha and expected_env_sha == actual_env_sha)
    if not env_sha_ok:
        notes.append("envelope_sha_mismatch")

    bundle_id_expected, manifest_sha_expected = _manifest_identity(manifest_result)
    p1_sha_expected = _p1_sha(p1_result, p1_sha256_verified)

    # Each link is read exactly as written. A bundle_id that is not a string, and a digest
    # that is not `sha256:` and 64 lowercase hexadecimal characters, is a malformed link and
    # fails; nothing is coerced, trimmed or case-folded into a value that happens to match. A
    # bundle_id is compared by exact code units: "" and "   " are not read as absent, and " id "
    # is not trimmed into "id"; 7 is not str()-ed into a match for a manifest naming "7".
    raw_bundle_id = envelope.get("bundle_id")
    bundle_id_actual = raw_bundle_id if isinstance(raw_bundle_id, str) else None
    raw_manifest_link = envelope.get("bundle_manifest_sha256")
    manifest_sha_actual = raw_manifest_link if is_prefixed_sha256(raw_manifest_link) else None
    raw_p1_link = envelope.get("p1_sha256")
    p1_sha_actual = raw_p1_link if is_prefixed_sha256(raw_p1_link) else None
    # The links are self-describing digests (canonicalization-and-hashing.md section 2), compared
    # as whole strings with the label and the recomputed digest.
    manifest_sha_expected = labelled(manifest_sha_expected)
    p1_sha_expected = labelled(p1_sha_expected)

    bundle_id_ok = _link(raw_bundle_id, bundle_id_actual, bundle_id_expected, "bundle_id", notes)
    manifest_link_ok = _link(raw_manifest_link, manifest_sha_actual, manifest_sha_expected, "manifest_link", notes)
    p1_link_ok = _link(raw_p1_link, p1_sha_actual, p1_sha_expected, "p1_link", notes)

    notes.append(registry_note)
    return replace(
        _NOTHING_EVALUATED,
        envelope=envelope,
        envelope_path_name=path_name,
        envelope_sha256_expected=expected_env_sha,
        envelope_sha256_actual=actual_env_sha,
        envelope_sha256_ok=env_sha_ok,
        envelope_present=True,
        envelope_sha256_present=True,
        envelope_files_complete=True,
        bundle_id_expected=bundle_id_expected,
        bundle_id_actual=bundle_id_actual,
        bundle_id_ok=bundle_id_ok,
        manifest_sha256_expected=manifest_sha_expected,
        manifest_sha256_actual=manifest_sha_actual,
        manifest_link_ok=manifest_link_ok,
        p1_sha256_expected=p1_sha_expected,
        p1_sha256_actual=p1_sha_actual,
        p1_link_ok=p1_link_ok,
        notes=tuple(notes),
    )
