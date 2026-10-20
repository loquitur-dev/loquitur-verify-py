"""Trust-registry root authentication, mirrored for the standalone verifier.

The authorization check reads an issuer's signature **against** a trust registry; this module establishes
whether the trust registry itself is authentic. Without it the chain would terminate in
"trust the file you were handed", and for a cross-listing or federation question that gap
*is* the question.

:data:`PINNED_TRUST_ROOTS` is empty, so unless the caller supplies a root every registry
fails root verification. That is deliberate. A mechanism that passed when nothing was
pinned would convert a truthful "not verified" into a false "verified", which is worse
than the gap it papers over. :data:`STATUS_NO_PINNED_ROOT` says so explicitly, and a
caller who pins a root gets a real verification.

**Why this is a mirror rather than an import.** ``loquitur-verify`` is deliberately
standalone: it imports nothing from ``loquitur-schemas`` at runtime, so a counterparty can
verify evidence without installing the issuer's stack. The cost of that property is that
shared logic exists twice, and drift between the copies would be a consensus split. The
domain prefix, the status vocabulary and the payload shape here are asserted equal to the
schemas package by ``tests/test_cross_repo_contract_drift.py``.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import CanonicalizationError, canonical_json_bytes, loads_json_bytes
from .cryptographic_capabilities import signature_algorithm_supported, signature_pair_supported
from .errors import LoquiturVerifyError
from .evaluation_time import parse_calendar_instant
from .host_path import host_path
from .manifest import is_blank
from .members import path_names_regular_file, read_file_bytes
from .secp256k1 import SIGNATURE_HEX_RE, shares_point, verify_digest

# Imported rather than restated: this package already declares the algorithm once, and a
# second literal would be a copy to keep in step for no benefit. The schemas mirror sources
# it the same way, from its own signing_envelope.
from .signing_envelope import SIGNATURE_ALGORITHM

TRUST_ROOT_DOMAIN = "org.loquitur.protocol.trust-registry-root-signature"
TRUST_ROOT_ENVELOPE_SCHEMA = "loquitur.trust_registry_root_signing_envelope.v1"
TRUST_REGISTRY_PAYLOAD_SCHEMA = "loquitur.trust_registry.v1"
TRUST_ROOT_SIGNING_DOMAIN_PREFIX = b"LOQUITUR\x00TRUST_REGISTRY\x00ROOT_SIGNATURE\x00V1\x00"

# The signature cannot cover itself.
TRUST_REGISTRY_SIGNING_EXCLUDED_FIELDS = frozenset({"signature"})

STATUS_VALID = "ROOT_SIGNATURE_VALID"
STATUS_NO_PINNED_ROOT = "NO_PINNED_TRUST_ROOT"
# Reported when the entry failed earlier and root authentication was never reached. This is
# not the same fact as NO_PINNED_TRUST_ROOT, and collapsing the two would put in the status
# vocabulary exactly the ambiguity this module exists to remove.
STATUS_NOT_EVALUATED = "ROOT_SIGNATURE_NOT_EVALUATED"
STATUS_UNKNOWN_ROOT_KEY = "UNKNOWN_ROOT_KEY"
# Row 7 of trust-root.md section 5: two pinned roots sharing a key_id, or the matched root's
# secp256k1 point carried by another pinned root (any key type or SEC1 spelling). The key is
# manifestly KNOWN (it matched twice, or its point did), and reporting that as UNKNOWN_ROOT_KEY
# would leave the truth surviving only in free-text `detail`, which is exactly the collapse the
# comment above refuses. The ambiguity rule one level down does not collapse it either: its
# own status (TRUST_REGISTRY_AMBIGUOUS_KEY) has its own required action in the catalog.
# Mirroring that rule means mirroring its vocabulary.
STATUS_AMBIGUOUS_ROOT_KEY = "AMBIGUOUS_ROOT_KEY"
STATUS_ROOT_NOT_YET_VALID = "ROOT_KEY_NOT_YET_VALID"
STATUS_ROOT_EXPIRED = "ROOT_KEY_EXPIRED"
STATUS_ROOT_REVOKED = "ROOT_KEY_REVOKED"
STATUS_UNSUPPORTED_ALGORITHM = "UNSUPPORTED_SIGNATURE_ALGORITHM"
STATUS_MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
STATUS_SIGNATURE_INVALID = "ROOT_SIGNATURE_INVALID"
STATUS_MALFORMED_TRUST_REGISTRY = "MALFORMED_TRUST_REGISTRY"

# trust-root.md section 3: public_key_hex is lowercase hexadecimal of 1 to 512 bytes, and for the
# key type secp256k1 the uncompressed SEC1 point.
_ROOT_PUBLIC_KEY_RE = re.compile(r"\A(?:[0-9a-f]{2}){1,512}\Z")
_PUBLIC_KEY_RE = re.compile(r"\A04[0-9a-f]{128}\Z")
_KEY_TYPE_RE = re.compile(r"\A[a-z0-9][a-z0-9_]{0,63}\Z")

# The top level of a trust-root document (trust-root.md §3): exactly these three members.
TRUST_ROOT_DOCUMENT_MEMBERS = ("object_type", "schema_version", "roots")
TRUST_ROOT_DOCUMENT_TYPE = "trust_root_document"
TRUST_ROOT_DOCUMENT_VERSION = "v1"
_VERSION_GRAMMAR_RE = re.compile(r"\Av[1-9][0-9]{0,8}\Z")
_ROOT_MEMBERS = frozenset({"key_id", "key_type", "public_key_hex", "not_before", "not_after", "status"})
_ROOT_REQUIRED = frozenset({"key_id", "key_type", "public_key_hex", "not_before", "not_after"})


class TrustRootError(ValueError, LoquiturVerifyError):
    """The trust-root material itself is malformed."""


@dataclass(frozen=True)
class TrustRootKey:
    """A pinned root key, valid only inside its declared window."""

    key_id: str
    public_key_hex: str
    not_before: str
    not_after: str
    status: str = "active"
    # The key type identifier (trust-root.md section 3), required and given by keyword: the
    # document names it for every root, and a library caller does too, so no type is assumed
    # for a root that does not state one. The verifier's allowlist decides at root
    # authentication (section 5, row 11) whether the pair with the signature's algorithm is
    # supported.
    key_type: str = dataclass_field(kw_only=True)

    def assert_valid(self) -> None:
        # Not empty in the sense of bundle-objects.md: a code point outside the whitespace set W.
        # Not str.strip(), which lets a key_id of U+FEFF alone through.
        if not isinstance(self.key_id, str) or is_blank(self.key_id):
            raise TrustRootError("trust root key_id is required")
        if not isinstance(self.key_type, str) or not _KEY_TYPE_RE.fullmatch(self.key_type):
            raise TrustRootError(f"trust root {self.key_id!r}: key_type is not a key type identifier")
        # Not lower-cased first: an uppercase key is not the lowercase hex the contract
        # names, and folding it would make two spellings of one root both acceptable.
        if not isinstance(self.public_key_hex, str) or not _ROOT_PUBLIC_KEY_RE.fullmatch(self.public_key_hex):
            raise TrustRootError(
                f"trust root {self.key_id!r}: public key is not lowercase hexadecimal of 1 to 512 bytes"
            )
        if self.key_type == "secp256k1" and not _PUBLIC_KEY_RE.fullmatch(self.public_key_hex):
            raise TrustRootError(f"trust root {self.key_id!r}: public key must be uncompressed SEC1 hex")
        for field in ("not_before", "not_after"):
            # A calendar instant, not only its shape: February 30 or second 60 is this document's own
            # error, not a bare ValueError from strptime below.
            if not _is_utc_instant(getattr(self, field)):
                raise TrustRootError(f"trust root {self.key_id!r}: {field} must be a UTC instant")
        if _parse_instant(self.not_after) <= _parse_instant(self.not_before):
            raise TrustRootError(f"trust root {self.key_id!r}: validity window is empty or inverted")
        if not isinstance(self.status, str) or self.status not in {"active", "revoked"}:
            raise TrustRootError(f"trust root {self.key_id!r}: unsupported status {self.status!r}")


# Empty, and empty means refuse. A root reaches the check only from the caller (--trust-root,
# or trust_roots on verify_path), obtained out of band from a party the caller trusts.
PINNED_TRUST_ROOTS: tuple[TrustRootKey, ...] = ()


class _UnreadDocument:
    """What a host passes as ``trust_roots`` when it found no trust-root document to hand over."""

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name


# report-contract.md section 4, "A library interface that takes documents": verify_path takes trust
# roots as values, so a host that reads the trust-root document says what it found when it found
# no document. The first is refused as a malformed document is (exit 64 on a command line); the
# second is the host failure trust_root_read_failed (section 5.3), and root authentication is not
# evaluated (trust-root.md section 3).
DOCUMENT_PATH_NAMES_NO_REGULAR_FILE = _UnreadDocument("DOCUMENT_PATH_NAMES_NO_REGULAR_FILE")
DOCUMENT_READ_FAILED = _UnreadDocument("DOCUMENT_READ_FAILED")


@dataclass(frozen=True)
class TrustRootVerification:
    """Outcome of checking a trust registry against the pinned roots."""

    ok: bool
    status: str
    root_key_id: str | None = None
    evaluated_at: str | None = None
    detail: str | None = None


def _parse_instant(value: str) -> datetime:
    """An instant already known to be one (_is_utc_instant); ValueError otherwise."""
    instant = parse_calendar_instant(value)
    if instant is None:
        raise ValueError(f"not a calendar instant: {value!r}")
    return instant


def _is_utc_instant(value: Any) -> bool:
    """``YYYY-MM-DDTHH:MM:SSZ`` naming a real instant (no February 30, no second 60)."""
    return parse_calendar_instant(value) is not None


def trust_registry_signing_bytes(trust_registry: Mapping[str, Any]) -> bytes:
    """Exact bytes a root signs: domain prefix || JCS(closed envelope)."""
    payload = {
        key: value for key, value in dict(trust_registry).items() if key not in TRUST_REGISTRY_SIGNING_EXCLUDED_FIELDS
    }
    envelope = {
        "domain": TRUST_ROOT_DOMAIN,
        "envelope_schema": TRUST_ROOT_ENVELOPE_SCHEMA,
        "envelope_version": 1,
        "payload": payload,
        "payload_schema": TRUST_REGISTRY_PAYLOAD_SCHEMA,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }
    return TRUST_ROOT_SIGNING_DOMAIN_PREFIX + canonical_json_bytes(envelope)


def parse_trust_roots(payload: Any) -> tuple[TrustRootKey, ...]:
    """Build pinned roots from an out-of-band document, refusing anything malformed.

    Roots are supplied separately from the trust registry they authenticate. Reading them
    from the same file would be circular, which is the whole gap this module closes.

    The whole document is validated here, every element whatever its key_id (trust-root.md
    §3), so a malformed root is refused when the document is read and never reaches a row of
    §5. The document is an object, so a bare array is refused, and a member of another type is
    not converted with str(), so a key_id of 9 does not match "9".

    The top level is closed too: exactly ``object_type`` (``trust_root_document``),
    ``schema_version`` (``v1``) and ``roots``. A document carrying any other member,
    ``trust_roots`` included, is refused, so no array is left unread and
    unvalidated whatever it holds. A document of a well-formed later version is not malformed:
    the caller asks :func:`trust_root_document_unsupported_version` first.
    """
    if not isinstance(payload, Mapping):
        raise TrustRootError("trust-root document must be a JSON object")
    unexpected = set(payload) - set(TRUST_ROOT_DOCUMENT_MEMBERS)
    if unexpected:
        raise TrustRootError(f"unexpected trust-root document member(s): {sorted(unexpected)}")
    missing_members = [name for name in TRUST_ROOT_DOCUMENT_MEMBERS if name not in payload]
    if missing_members:
        raise TrustRootError(f"trust-root document has no {missing_members[0]!r}")
    if payload["object_type"] != TRUST_ROOT_DOCUMENT_TYPE:
        raise TrustRootError(f"trust-root document object_type is not {TRUST_ROOT_DOCUMENT_TYPE!r}")
    if payload["schema_version"] != TRUST_ROOT_DOCUMENT_VERSION:
        raise TrustRootError(f"trust-root document schema_version is not {TRUST_ROOT_DOCUMENT_VERSION!r}")
    elements = payload["roots"]
    if not isinstance(elements, list) or not elements:
        raise TrustRootError("trust-root document must carry a non-empty 'roots' array")
    roots: list[TrustRootKey] = []
    for item in elements:
        if not isinstance(item, Mapping):
            raise TrustRootError("each trust root must be an object")
        unknown = set(item) - _ROOT_MEMBERS
        if unknown:
            # A closed shape: an unexpected field could carry an assumption the verifier
            # silently ignores, which is how a permissive parser becomes a trust hole.
            raise TrustRootError(f"unexpected trust-root field(s): {sorted(unknown)}")
        missing = _ROOT_REQUIRED - set(item)
        if missing:
            raise TrustRootError(f"missing trust-root field(s): {sorted(missing)}")
        roots.append(
            TrustRootKey(
                key_id=item["key_id"],
                public_key_hex=item["public_key_hex"],
                not_before=item["not_before"],
                not_after=item["not_after"],
                status=item.get("status", "active"),
                key_type=item["key_type"],
            )
        )
    return validate_trust_roots(roots)


def trust_root_document_unsupported_version(payload: Any) -> str | None:
    """The version of a trust-root document whose version gate fires, else None.

    document-contracts.md, "Version gate", gate 1: an object whose ``object_type`` is
    ``trust_root_document`` and whose ``schema_version`` is a well-formed identifier other than
    ``v1`` fires it. Anything else does not, and is judged by trust-root.md section 3.
    """
    if not isinstance(payload, Mapping) or payload.get("object_type") != TRUST_ROOT_DOCUMENT_TYPE:
        return None
    version = payload.get("schema_version")
    if not isinstance(version, str) or not _VERSION_GRAMMAR_RE.fullmatch(version):
        return None
    return None if version == TRUST_ROOT_DOCUMENT_VERSION else version


class TrustRootDocumentUnsupportedVersion(ValueError, LoquiturVerifyError):
    """A trust-root document of a well-formed version this verifier does not support (gate 1)."""

    def __init__(self, version: str) -> None:
        super().__init__(f"trust-root document of the unsupported version {version!r}")
        self.version = version


class TrustRootDocumentUnreadableError(ValueError, LoquiturVerifyError):
    """The trust-root document's path names no regular file: nothing is found there, or what is
    found is a directory, a device, a pipe or anything else that is not a regular file."""


def read_trust_root_document(path: str | os.PathLike[str]) -> tuple[TrustRootKey, ...]:
    """The roots of the trust-root document at ``path``, read as a document supplied by path.

    report-contract.md section 4: a trust-root path that names no regular file raises
    TrustRootDocumentUnreadableError and a document that breaks trust-root.md section 3
    TrustRootError, both ValueError, which a command line refuses with exit 64. A regular file the
    host fails to inspect or read raises the host's OSError: that is not a refusal but the host
    failure trust_root_read_failed (section 5.3), which the caller reports by passing
    DOCUMENT_READ_FAILED as the trust roots. The path is read as it is written (host_path), as the
    input and the other two documents are.

    The command line and the conformance adapter ask what the path names before reading it, as
    for the other two documents: a device or a named pipe is no regular file (report-contract.md
    section 5.3), and read, a path naming the console input device would wait for a keyboard that
    never types, and a POSIX FIFO or /dev/stdin would be read as a document.
    """
    host = host_path(path)
    document = Path(host)  # used only once the string names a regular file, whose path it keeps
    if not path_names_regular_file(host):
        raise TrustRootDocumentUnreadableError(f"{os.fspath(path)!r} names no regular file")
    payload = loads_json_bytes(read_file_bytes(document), name="trust_root")
    unsupported = trust_root_document_unsupported_version(payload)
    if unsupported is not None:
        raise TrustRootDocumentUnsupportedVersion(unsupported)
    return parse_trust_roots(payload)


def validate_trust_roots(roots: Sequence[TrustRootKey]) -> tuple[TrustRootKey, ...]:
    """Every root checked against trust-root.md §3, before any row of §5 is evaluated.

    A set with one malformed root is refused as a whole, whichever root it is: the statuses
    of §5 are facts about a trust registry measured against a well-formed set of roots, so a
    malformed root the trust registry does not name is refused as well.
    """
    for root in roots:
        if not isinstance(root, TrustRootKey):
            raise TrustRootError("each trust root must be a TrustRootKey")
        root.assert_valid()
    return tuple(roots)


def verify_trust_registry_root_signature(
    trust_registry: Mapping[str, Any],
    *,
    evaluated_at: str | None,
    roots: Sequence[TrustRootKey] = PINNED_TRUST_ROOTS,
) -> TrustRootVerification:
    """Verify a trust registry against the pinned trust roots, in the order of trust-root.md §5.

    ``evaluated_at`` is the operator's evaluation time (trust-registry-authorization.md §2),
    never the system clock and never an issuer's date. ``None`` means none was supplied: rows 9
    and 10, which read it, are then skipped.
    """
    if evaluated_at is not None and not _is_utc_instant(evaluated_at):
        raise TrustRootError("evaluated_at must be a UTC instant")
    roots = validate_trust_roots(roots)

    if not roots:
        return TrustRootVerification(
            ok=False,
            status=STATUS_NO_PINNED_ROOT,
            evaluated_at=evaluated_at,
            detail=(
                "no trust root is pinned, so trust-registry authenticity cannot be "
                "established; this refuses rather than reporting an unverified registry "
                "as verified"
            ),
        )

    if not isinstance(trust_registry, Mapping):
        return TrustRootVerification(ok=False, status=STATUS_MALFORMED_TRUST_REGISTRY, evaluated_at=evaluated_at)

    signature_obj = trust_registry.get("signature")
    if not isinstance(signature_obj, Mapping):
        return TrustRootVerification(
            ok=False,
            status=STATUS_MALFORMED_SIGNATURE,
            evaluated_at=evaluated_at,
            detail="trust registry carries no signature object",
        )

    # Row 4: the algorithm, from the verifier's own allowlist, never from the input.
    if not signature_algorithm_supported(signature_obj.get("algorithm")):
        return TrustRootVerification(
            ok=False,
            status=STATUS_UNSUPPORTED_ALGORITHM,
            evaluated_at=evaluated_at,
            detail=f"unsupported signature algorithm {signature_obj.get('algorithm')!r}",
        )

    key_id = signature_obj.get("key_id")
    signature_hex = signature_obj.get("signature")
    # trust-root.md §4.2: "r || s as exactly 128 lowercase hex characters". Row 5 of the
    # evaluation order tests the form, not only the length: 128 'z' must not go on to the key
    # lookup, and an uppercase or space-padded spelling of a valid signature, which int(x, 16)
    # reads as the same integers, must not verify. The pattern is secp256k1.SIGNATURE_HEX_RE.
    if not isinstance(signature_hex, str) or not SIGNATURE_HEX_RE.fullmatch(signature_hex):
        return TrustRootVerification(
            ok=False,
            status=STATUS_MALFORMED_SIGNATURE,
            evaluated_at=evaluated_at,
            root_key_id=str(key_id or "") or None,
            detail="root signature must be compact 64-byte r||s hex",
        )

    matching = [root for root in roots if root.key_id == key_id]
    if not matching:
        return TrustRootVerification(
            ok=False,
            status=STATUS_UNKNOWN_ROOT_KEY,
            evaluated_at=evaluated_at,
            root_key_id=str(key_id or "") or None,
            detail="signing key is not a pinned trust root",
        )
    if len(matching) > 1:
        # Two pinned roots sharing a key_id have no well-defined authority. Refuse rather
        # than pick one, mirroring the duplicate-issuer rule one level down.
        return TrustRootVerification(
            ok=False,
            status=STATUS_AMBIGUOUS_ROOT_KEY,
            evaluated_at=evaluated_at,
            root_key_id=str(key_id),
            detail="duplicate pinned trust roots share this key_id",
        )

    root = matching[0]
    # Row 7 also: the matched root's point under another pinned root, in any SEC1 spelling and
    # whatever the key types. signature.key_id is outside the signed bytes (section 4), so a
    # registry signed under a revoked root, relabeled with an active key_id that carries the
    # same point, would otherwise authenticate.
    if shares_point((other.public_key_hex for other in roots if other is not root), root.public_key_hex):
        return TrustRootVerification(
            ok=False,
            status=STATUS_AMBIGUOUS_ROOT_KEY,
            evaluated_at=evaluated_at,
            root_key_id=str(key_id),
            detail="another pinned trust root carries this root's public key point",
        )

    # Revocation first, then the window. A root revoked inside a lapsed window must be
    # reported as revoked: the remedies differ, and losing a revocation signal to a
    # date arithmetic detail is the failure this ordering exists to prevent.
    if root.status == "revoked":
        return TrustRootVerification(
            ok=False, status=STATUS_ROOT_REVOKED, evaluated_at=evaluated_at, root_key_id=root.key_id
        )

    # Rows 9 and 10: the window, bounds included, at the evaluation time; skipped without one.
    if evaluated_at is not None:
        now = _parse_instant(evaluated_at)
        if now < _parse_instant(root.not_before):
            return TrustRootVerification(
                ok=False, status=STATUS_ROOT_NOT_YET_VALID, evaluated_at=evaluated_at, root_key_id=root.key_id
            )
        if now > _parse_instant(root.not_after):
            return TrustRootVerification(
                ok=False, status=STATUS_ROOT_EXPIRED, evaluated_at=evaluated_at, root_key_id=root.key_id
            )

    # Row 11: the pair of the signature's algorithm and the matched root's key type.
    if not signature_pair_supported(signature_obj.get("algorithm"), root.key_type):
        return TrustRootVerification(
            ok=False,
            status=STATUS_UNSUPPORTED_ALGORITHM,
            evaluated_at=evaluated_at,
            root_key_id=root.key_id,
            detail=f"unsupported pair of algorithm and key type {root.key_type!r}",
        )

    try:
        message = trust_registry_signing_bytes(trust_registry)
    except CanonicalizationError:
        # A registry that cannot be canonicalized cannot be the one the root signed. Strict JSON
        # intake refuses such a value before a document reaches this point; a library caller
        # handing a mapping directly gets the failed signature, not an escaped exception.
        return TrustRootVerification(
            ok=False, status=STATUS_SIGNATURE_INVALID, evaluated_at=evaluated_at, root_key_id=root.key_id
        )
    digest = hashlib.sha256(message).digest()
    if not verify_digest(digest, signature_hex, root.public_key_hex):
        return TrustRootVerification(
            ok=False, status=STATUS_SIGNATURE_INVALID, evaluated_at=evaluated_at, root_key_id=root.key_id
        )

    return TrustRootVerification(ok=True, status=STATUS_VALID, evaluated_at=evaluated_at, root_key_id=root.key_id)
