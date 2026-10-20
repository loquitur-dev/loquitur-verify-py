"""Manifest and declared-file hash verification for Loquitur bundles.

This module stops at the manifest:
- load manifest.json;
- recompute the manifest's canonical digest and compare it with manifest.sha256;
- verify the digests of the files manifest.files declares.

It does not verify P1, canonical_input, envelope, registry entries, or issuer
signatures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import CanonicalizationError, JsonLoadError, canonical_json_sha256, loads_json_bytes, sha256_hex
from .errors import LoquiturVerifyError
from .members import (
    BundleInventory,
    BundleInventoryError,
    MemberTooLargeError,
    UnsafeBundleMemberError,
    bundle_inventory,
    conflicting_names,
    fold_member_name,
    member_is_file,
    member_name_problem,
    read_member_bytes,
)

STATUS_OFFLINE_OK = "OFFLINE_OK"
STATUS_OFFLINE_REVIEW = "OFFLINE_REVIEW"
STATUS_OFFLINE_FAIL = "OFFLINE_FAIL"


class ManifestVerificationError(LoquiturVerifyError):
    """Base class for expected manifest verification failures."""


class ManifestMissingError(ManifestVerificationError):
    """Raised when manifest.json is missing."""


class ManifestShaMissingError(ManifestVerificationError):
    """Raised when manifest.sha256 is missing."""


class ManifestTypeError(ManifestVerificationError):
    """Raised when manifest.json is not a JSON object."""


class UnsafeManifestPathError(ManifestVerificationError):
    """Raised when a manifest-declared path escapes the bundle root."""


@dataclass(frozen=True)
class ManifestFileCheck:
    name: str
    # None when the declared digest is not a string: the declaration names the member, and
    # its check fails without the member being read.
    expected_sha256: str | None
    actual_sha256: str | None
    ok: bool
    error: str | None = None


@dataclass(frozen=True)
class ManifestVerificationResult:
    manifest: dict[str, Any]
    manifest_sha256_expected: str | None
    manifest_sha256_actual: str
    manifest_sha256_ok: bool
    file_checks: tuple[ManifestFileCheck, ...]
    shape_errors: tuple[str, ...] = ()
    extra_files: tuple[str, ...] = ()
    # Links found anywhere in the bundle, by their own names, and why the bundle could not
    # be enumerated, if it could not. A link fails the file check: a bundle whose members
    # cannot all be established as regular files inside it has not had its files checked.
    # An enumeration that fails is the host's failure, bundle_inventory_failed, not the
    # manifest's (bundle-objects.md section 1: "An inventory that fails takes the place of a
    # link, and of nothing else"): it leaves the file check unestablished (files_established)
    # without failing the layer, and the host error decides the run (report-contract.md
    # section 3.1).
    unsafe_links: tuple[str, ...] = ()
    inventory_error: str | None = None

    @property
    def files_ok(self) -> bool:
        return bool(self.file_checks) and all(check.ok for check in self.file_checks) and not self.unsafe_links

    @property
    def files_established(self) -> bool:
        """The report's manifest_files check: the file check holds over an enumerated bundle."""
        return self.files_ok and self.inventory_error is None

    @property
    def shape_ok(self) -> bool:
        return not self.shape_errors

    @property
    def ok(self) -> bool:
        # The shape is checked, not only the DIGEST: the digest is computed over whatever
        # the manifest happens to contain, so a manifest missing bundle_id/schema_version,
        # or carrying unexpected fields, is trivially self-consistent. Digest
        # self-consistency is not protocol conformance.
        return self.manifest_sha256_ok and self.files_ok and self.shape_ok

    @property
    def status(self) -> str:
        """OK, REVIEW or FAIL for the manifest layer.

        Undeclared members are deliberately REVIEW and not FAIL. The manifest is the
        inventory the receipt commits to, so a member outside it is outside the
        commitment, but whether it is material cannot be decided by hashing, and
        calling an intact bundle broken would be as wrong as calling it verified.
        """
        if not self.ok:
            return STATUS_OFFLINE_FAIL
        if self.extra_files:
            return STATUS_OFFLINE_REVIEW
        return STATUS_OFFLINE_OK


_BARE_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def is_bare_sha256(value: Any) -> bool:
    """True for exactly 64 lowercase hexadecimal characters and nothing else.

    Every bundle surface spells a digest this way (bundle-objects.md §2, "not a value to be
    normalized"). Nothing is trimmed or case-folded before the test: an uppercase or padded
    digest is a malformed claim, not a spelling of a well-formed one.
    """
    return isinstance(value, str) and _BARE_SHA256_RE.fullmatch(value) is not None


# Every digest inside a JSON document is self-describing (canonicalization-and-hashing.md section
# 2): the algorithm label, a colon and 64 lowercase hexadecimal characters. The label is a closed
# set for this object version, sha256 only. Sidecar files stay bare hex.
SHA256_LABEL = "sha256:"
_PREFIXED_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")


def is_prefixed_sha256(value: Any) -> bool:
    """True for exactly ``sha256:`` and 64 lowercase hexadecimal characters, nothing trimmed."""
    return isinstance(value, str) and _PREFIXED_SHA256_RE.fullmatch(value) is not None


def labelled(hex_digest: str | None) -> str | None:
    """A bare digest written in the self-describing form, or None."""
    return None if hex_digest is None else SHA256_LABEL + hex_digest


# The whitespace set W of bundle-objects.md, which decides whether a string is empty. Python's
# str.strip() and ECMAScript's String.prototype.trim() remove different characters, so a
# bundle_id of U+001F or U+0085 would be empty to one implementation and not to the other,
# and one of U+FEFF the other way round. W is the union of the two, the stricter reading, spelled
# out so that neither language's builtin decides it. It is used only to decide emptiness,
# never to normalize a compared value.
WHITESPACE_W = frozenset(
    chr(code_point)
    for code_point in (
        *range(0x09, 0x0E),
        *range(0x1C, 0x21),
        0x85,
        0xA0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
        0xFEFF,
    )
)


def is_blank(value: str) -> bool:
    """True when ``value`` has no code point outside the whitespace set W."""
    return all(ch in WHITESPACE_W for ch in value)


def usable_bundle_id(manifest: Any) -> str | None:
    """The manifest's bundle_id when it is a string that is not blank, else None."""
    if not isinstance(manifest, dict):
        return None
    bundle_id = manifest.get("bundle_id")
    if isinstance(bundle_id, str) and not is_blank(bundle_id):
        return bundle_id
    return None


def read_manifest(bundle_root: Path) -> dict[str, Any]:
    if not member_is_file(bundle_root, "manifest.json"):
        raise ManifestMissingError("manifest_missing")
    try:
        manifest = loads_json_bytes(read_member_bytes(bundle_root, "manifest.json"), name="manifest.json")
    except (JsonLoadError, MemberTooLargeError) as exc:
        raise ManifestVerificationError(str(exc)) from exc
    if not isinstance(manifest, dict):
        raise ManifestTypeError("manifest_invalid_type")
    return manifest


def read_stored_manifest_sha256(bundle_root: Path) -> str | None:
    """The sidecar's content, None when it is present and is not text of at most 20 MiB.

    An absent sidecar raises: there is nothing to verify the manifest against. A present one
    that is not UTF-8, or exceeds the member bound, is a sidecar that is not the digest, the
    same failed comparison as a sidecar of 65 characters, and the manifest it names is still
    loaded, as the p1.sha256 and envelope.sha256 sidecars are: a sidecar that does not match fails
    the manifest layer and does not refuse it (bundle-objects.md section 6). Refusing the
    manifest outright would leave the registry link no manifest digest to compare.
    """
    if not member_is_file(bundle_root, "manifest.sha256"):
        raise ManifestShaMissingError("manifest_sha256_missing")
    try:
        raw = read_member_bytes(bundle_root, "manifest.sha256").decode("utf-8")
    except (UnicodeDecodeError, MemberTooLargeError):
        # Untrusted input: never an unhandled decode error out of the verifier.
        return None
    # Returned exactly as stored. The sidecar holds the 64 lowercase hexadecimal characters
    # of the digest and no other byte, not even a newline (bundle-objects.md §1), so a
    # sidecar that differs from the recomputed digest in case, padding or a trailing newline
    # is a mismatch: it is not stripped or lower-cased first.
    return raw


def manifest_files_map(manifest: object) -> dict[str, object]:
    """Return manifest-declared file hashes as declared: names -> digests, both raw.

    Nothing is normalized. A digest the contract rejects (uppercase, bare or padded) is
    stored as written, so its file check compares unequal and the report shows what the
    manifest actually said; manifest_shape_errors names it as well. A digest that is not a
    string is kept too: its name is declared, so the member is not an undeclared file, and
    its file check fails. A declaration a parser cannot read is never skipped
    (bundle-objects.md section 2).

    Only the object form {"files": {"p1.json": "..."}} declares files. The legacy list
    form {"files": [{"name": ..., "sha256": ...}]} is not a manifest
    (manifest_files_not_an_object) and declares nothing: its entries are not hashed, so
    manifest_files is false, as for a files map with no member (bundle-objects.md section 2): a
    manifest that declares nothing commits to nothing.
    """

    if not isinstance(manifest, dict):
        return {}

    files_obj = manifest.get("files")
    out: dict[str, object] = {}

    if isinstance(files_obj, dict):
        for name, digest in files_obj.items():
            if isinstance(name, str):
                out[name] = digest
        return out

    return out


SELF_REFERENTIAL_MEMBERS = frozenset({"manifest.json", "manifest.sha256"})


def _self_referential(declared_name: str) -> bool:
    """True when a declared name is manifest.json or manifest.sha256, in any ASCII letter case.

    The key is compared as written, with A to Z read as a to z and nothing else changed
    (``members.fold_member_name``): ASCII letter case is the only folding of member names
    (bundle-objects.md section 2). It is not Unicode lower-casing: "MANIFEST.JSON" spelled with
    U+0130 for its first "I" is not a self-declaration. Nor is the key trimmed, backslash-folded or stripped of a
    leading "./": " manifest.json" (a real member with a leading space), "./manifest.json" and
    "sub\\manifest.json" are not self-declarations (bundle-objects.md section 2). A name that is not
    exactly one of the two keys is an ordinary declaration, and the portable member-name rule
    decides it.
    """
    if not isinstance(declared_name, str):
        return False
    return fold_member_name(declared_name) in SELF_REFERENTIAL_MEMBERS


def _normalize_manifest_path(relative_name: str) -> str:
    """Return a declared member name unchanged when it is a portable member name.

    The name is refused (UnsafeManifestPathError) unless it is a portable member name
    (bundle-objects.md section 2, ``members.member_name_problem``): "/"-separated segments of the
    POSIX portable filename characters, none "." or "..", ending with "." or beginning with "-",
    none a Windows reserved device name, and at most 255 bytes.

    Nothing is rewritten: no normpath, no backslash folding. "./p1.json", "sub\\p1.json" and
    "p1.json." each name p1.json on some host; "p1.json:hidden" names an NTFS alternate data
    stream no inventory lists, bytes nothing else could see. A name that means one file on
    one host and another elsewhere is not a portable member name.
    """
    if not isinstance(relative_name, str) or not relative_name:
        raise UnsafeManifestPathError("unsafe_manifest_path:empty")
    if member_name_problem(relative_name) is not None:
        raise UnsafeManifestPathError(f"unsafe_manifest_path:{relative_name!r}")
    return relative_name


def safe_manifest_child(bundle_root: Path, relative_name: str) -> tuple[str, Path]:
    """A public helper for callers; verification itself reads through members.py."""
    normalized = _normalize_manifest_path(relative_name)
    root = bundle_root.resolve()
    target = (bundle_root / normalized).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise UnsafeManifestPathError(f"unsafe_manifest_path:{relative_name}") from exc
    return normalized, target


def verify_manifest_files(bundle_root: Path, manifest: dict[str, Any]) -> tuple[ManifestFileCheck, ...]:
    file_map = manifest_files_map(manifest)
    # A self-referential declaration is a shape error (manifest_shape_errors), so the
    # manifest fails; it is still not hashed here, because manifest.json changes when its
    # own files list is written and no digest could ever match it.
    #
    # The two keys are matched in any letter case and otherwise exactly (bundle-objects.md
    # section 2); "./manifest.json" is not one of them and is not a portable member name.
    for declared in [name for name in file_map if _self_referential(name)]:
        file_map.pop(declared, None)
    # Two keys that conflict (bundle-objects.md section 2), such as "a.json" and "A.JSON", name one
    # file on a host that ignores letter case: each fails, and neither is read.
    conflicts = conflicting_names([name for name in file_map if member_name_problem(name) is None])

    checks: list[ManifestFileCheck] = []
    for name, declared_digest in sorted(file_map.items()):
        expected = declared_digest if isinstance(declared_digest, str) else None

        def failed(error: str, name: str = name, expected: str | None = expected) -> ManifestFileCheck:
            return ManifestFileCheck(name=name, expected_sha256=expected, actual_sha256=None, ok=False, error=error)

        # A digest that is not a string declares no digest to compare: the check fails and the
        # member is not read (manifest_shape_errors names the declaration as well).
        if expected is None:
            checks.append(failed("invalid_file_digest"))
            continue
        try:
            _normalize_manifest_path(name)
        except UnsafeManifestPathError:
            checks.append(failed("unsafe_manifest_path"))
            continue
        if name in conflicts:
            checks.append(failed("member_name_conflict"))
            continue
        # Resolved against the directory listing, exactly, never through a link, and read
        # within the per-member bound. A name the listing does not contain code unit for
        # code unit is missing, however the host would have matched it.
        try:
            data = read_member_bytes(bundle_root, name)
        except UnsafeBundleMemberError:
            checks.append(failed("unsafe_bundle_member"))
            continue
        except MemberTooLargeError:
            checks.append(failed("member_too_large"))
            continue
        except FileNotFoundError:
            checks.append(failed("file_missing"))
            continue
        # Compared as the whole string, label included (canonicalization-and-hashing.md section 2):
        # a bare or upper-case declaration never equals the recomputed digest.
        actual = SHA256_LABEL + sha256_hex(data)
        checks.append(
            ManifestFileCheck(
                name=name,
                expected_sha256=expected,
                actual_sha256=actual,
                ok=actual == expected,
                error=None if actual == expected else "sha256_mismatch",
            )
        )
    return tuple(checks)


# manifest.json and manifest.sha256 cannot appear in their own map, and the
# envelope and the receipt are verified by their own layers rather than by
# manifest.files. Everything else in the bundle must be declared.
BUNDLE_STRUCTURAL_MEMBERS = frozenset(
    {
        "manifest.json",
        "manifest.sha256",
        "envelope_env1.json",
        "envelope.sha256",
        "verification_receipt.json",
    }
)


def undeclared_bundle_files(
    bundle_root: Path, manifest: dict[str, Any], *, inventory: BundleInventory | None = None
) -> tuple[str, ...]:
    """Bundle members that manifest.files does not declare.

    verify_manifest_files walks the DECLARATION and hashes what it names, so without
    this enumeration a file added to a registry-anchored bundle (every other member
    byte-identical, so every recorded digest still matches) would never be looked at.
    This is what reaches the three extra-file reason codes the protocol defines.

    Names are compared exactly, and the inventory never follows a link (members.py).
    Raises BundleInventoryError when the bundle cannot be enumerated.
    """

    declared = set(manifest_files_map(manifest))
    listed = inventory if inventory is not None else bundle_inventory(bundle_root)
    return tuple(
        name
        for name in listed.files
        if name not in declared and name not in BUNDLE_STRUCTURAL_MEMBERS and not is_reserved_member(name)
    )


def is_reserved_member(name: str) -> bool:
    """A member at a name a loquitur.bundle.v1 bundle reserves (bundle-objects.md section 1).

    Every member under ``attestations/``, ``document_index.json`` and ``claims_openings.json``
    is not evidence this version defines: the review reason bundle_reserved_member, declared or
    not, and never bundle_extra_files. A declared one is still hashed by the file check.
    """
    return name.startswith("attestations/") or name in RESERVED_MEMBER_NAMES


RESERVED_MEMBER_NAMES = frozenset({"document_index.json", "claims_openings.json"})

# The manifest's version identifier (document-contracts.md, "Version gate", gate 2): the one value
# this verifier supports, and the grammar of a well-formed identifier of any version.
MANIFEST_SCHEMA_VERSION = "loquitur.bundle.v1"
MANIFEST_SCHEMA_VERSION_GRAMMAR = re.compile(r"loquitur\.bundle\.v[1-9][0-9]{0,8}")
_NONCE_RE = re.compile(r"[0-9a-f]{64}")

MANIFEST_ALLOWED_FIELDS = frozenset({"bundle_id", "files", "nonce", "schema_version"})
MANIFEST_REQUIRED_FIELDS = ("bundle_id", "files", "nonce", "schema_version")


def manifest_shape_errors(manifest: Any) -> list[str]:
    """Closed-contract validation of a bundle manifest. Empty list == conformant."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest_not_an_object"]
    for field in MANIFEST_REQUIRED_FIELDS:
        if manifest.get(field) is None:
            errors.append(f"manifest_missing_field:{field}")
    # bundle-objects.md types both identity members as strings: a number, a boolean, an
    # array or an object is refused, so no coercion can make bundle_id 7 match an envelope
    # carrying "7".
    for field in ("bundle_id", "schema_version"):
        if manifest.get(field) is not None and not isinstance(manifest.get(field), str):
            errors.append(f"manifest_invalid_field_type:{field}")
    # An empty bundle_id passes the `is None` test above. A manifest that does not name
    # its bundle is not conformant. Empty means made only of the whitespace set W, not
    # whatever str.strip() removes.
    if isinstance(manifest.get("bundle_id"), str) and is_blank(manifest["bundle_id"]):
        errors.append("manifest_empty_field:bundle_id")
    # schema_version is the constant of this bundle version (bundle-objects.md section 2); a
    # well-formed other version fired the version gate before this contract was read.
    if isinstance(manifest.get("schema_version"), str) and manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
        errors.append("manifest_invalid_schema_version")
    # The hiding nonce (bundle-objects.md section 2): exactly 64 lowercase hexadecimal characters.
    # Its form only is checked; that it is fresh and random is the producer's obligation.
    if "nonce" in manifest and manifest.get("nonce") is not None:
        nonce = manifest["nonce"]
        if not (isinstance(nonce, str) and _NONCE_RE.fullmatch(nonce)):
            errors.append("manifest_invalid_nonce")
    files_obj = manifest.get("files")
    if "files" in manifest and not isinstance(files_obj, dict):
        errors.append("manifest_files_not_an_object")
    elif isinstance(files_obj, dict):
        # A declaration the parser cannot read is not dropped: dropping it would let one
        # readable entry launder any number of unchecked ones while the file check passed.
        # An unreadable declaration is a malformed manifest, not an absent file. Readable
        # means sha256: and exactly 64 lowercase hex characters: an uppercase, bare or padded
        # digest is not folded into a valid one.
        for name, digest in sorted(files_obj.items()):
            if _self_referential(name):
                # bundle-objects.md §2: these keys MUST NOT appear. Dropping them silently would
                # keep a member the closed contract does not name.
                errors.append(f"manifest_self_referential_member:{name}")
            if not is_prefixed_sha256(digest):
                errors.append(f"manifest_invalid_file_digest:{name}")
    for unexpected in sorted(set(manifest) - MANIFEST_ALLOWED_FIELDS):
        errors.append(f"manifest_unexpected_field:{unexpected}")
    return errors


def manifest_canonical_sha256(manifest: dict[str, Any]) -> str:
    """The manifest's canonical digest; manifest_verification_failed when it cannot be canonicalized.

    The one canonicalization rule of the manifest layer: the layer and the row judged over the
    manifest members the host did read when it failed to read another both apply it. Not reachable
    from a document read under input strictness, whose rules make every document canonicalizable
    (report-contract.md section 5.3); kept as a defense in depth. A manifest that cannot be
    canonicalized is refused content, not a verifier fault: it must not escape verify_path and make
    the CLI report INTERNAL_ERROR, exit 3.
    """
    try:
        return canonical_json_sha256(manifest)
    except CanonicalizationError as exc:
        raise ManifestVerificationError(f"manifest_canonicalize_failed:{type(exc).__name__}") from exc


def verify_manifest(
    bundle_root: Path, *, inventory: BundleInventory | None = None, inventory_error: str | None = None
) -> ManifestVerificationResult:
    """Verify manifest.json, its sidecar, its declared files and the bundle's completeness.

    ``inventory`` is the enumeration the caller already made, and ``inventory_error`` why the
    caller's enumeration failed; with neither, it is made here. A failed enumeration is not made
    again: a second walk could answer otherwise than the one the caller reports. An enumeration
    that fails does not stop the manifest's own checks: the digest of a byte-perfect manifest
    still verifies, and the reason is kept in ``inventory_error``. It leaves the file check
    unestablished and fails nothing: the failure is the host's.
    """
    manifest = read_manifest(bundle_root)
    expected_manifest_sha = read_stored_manifest_sha256(bundle_root)
    actual_manifest_sha = manifest_canonical_sha256(manifest)
    file_checks = verify_manifest_files(bundle_root, manifest)
    if inventory is None and inventory_error is None:
        try:
            inventory = bundle_inventory(bundle_root)
        except BundleInventoryError as exc:
            inventory_error = str(exc)
    return ManifestVerificationResult(
        manifest=manifest,
        manifest_sha256_expected=expected_manifest_sha,
        manifest_sha256_actual=actual_manifest_sha,
        manifest_sha256_ok=actual_manifest_sha == expected_manifest_sha,
        file_checks=file_checks,
        shape_errors=tuple(manifest_shape_errors(manifest)),
        extra_files=undeclared_bundle_files(bundle_root, manifest, inventory=inventory) if inventory else (),
        unsafe_links=inventory.links if inventory else (),
        inventory_error=inventory_error,
    )
