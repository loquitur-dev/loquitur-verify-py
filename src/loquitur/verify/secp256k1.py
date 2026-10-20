"""The secp256k1 ECDSA primitive both signature checks of loquitur-verify read.

The registry-entry signature step (trust-registry-authorization.md section 6, row 20) and the
trust registry's root signature (trust-root.md section 5) verify through ``verify_digest``; the
key-point rule of both (trust-registry-authorization.md section 6, row 6, and trust-root.md
section 5, row 7) reads ``secp256k1_point``. It imports nothing of this package but the base class of
its errors, so neither caller imports the other to reach it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from .errors import LoquiturVerifyError

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

PUBLIC_KEY_HEX_RE = re.compile(r"\A04[0-9a-f]{128}\Z")
SIGNATURE_HEX_RE = re.compile(r"\A[0-9a-f]{128}\Z")
# Lowercase only, as loquitur-verify-ts gates its decoder: the contracts that admit a key to the
# rows (the trust registry's schema, trust-root.md section 3) refuse uppercase before this, so an
# uppercase value encodes no point here and the two verifiers agree even on a value no row reads.
_SEC1_POINT_HEX_RE = re.compile(r"\A(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})\Z")


class PublicKeyError(ValueError, LoquiturVerifyError):
    """A public key that is not an uncompressed SEC1 point of secp256k1."""


def parse_uncompressed_public_key(public_key_hex: str) -> tuple[int, int]:
    """The coordinates of an uncompressed SEC1 secp256k1 key, or ``PublicKeyError``.

    The form is checked first, ``04`` and 128 lowercase hex characters, because int(x, 16) reads
    surrounding whitespace, underscores, a 0x prefix and either case as the same integer. Each
    coordinate is below p, as the SEC1 conversion of an octet string to a field element requires,
    so that x + p written in 32 bytes, which names the same point modulo p, is refused
    (canonicalization-and-hashing.md section 4); and the point is on the curve.
    """
    if not isinstance(public_key_hex, str) or not PUBLIC_KEY_HEX_RE.fullmatch(public_key_hex):
        raise PublicKeyError("public key must be uncompressed SEC1 hex")
    point = secp256k1_point(public_key_hex)
    if point is None:
        raise PublicKeyError(
            "public key is not on secp256k1: a coordinate must be below the field prime and the point on the curve"
        )
    return point


def secp256k1_point(public_key_hex: object) -> tuple[int, int] | None:
    """The secp256k1 point ``public_key_hex`` encodes in a SEC1 form, or None when it encodes none.

    Two trust entries, or two pinned roots, that name one key in different spellings are one key
    (trust-registry-authorization.md section 6, row 6; trust-root.md section 5, row 7), whatever
    their key types, so keys are compared as points and never as strings. A point is encoded
    compressed, ``02`` or ``03`` and the 32-byte x, or uncompressed, ``04``, x and y; each
    coordinate is below p and the point is on the curve. The hybrid forms ``06`` and ``07``, the
    point at infinity, every other length and an uppercase spelling encode no point here, and a
    key that encodes none shares its point with no other.
    """
    if not isinstance(public_key_hex, str) or not _SEC1_POINT_HEX_RE.fullmatch(public_key_hex):
        return None
    prefix = public_key_hex[:2]
    x = int(public_key_hex[2:66], 16)
    if x >= SECP256K1_P:
        return None
    right = (x * x * x + 7) % SECP256K1_P
    if prefix == "04":
        y = int(public_key_hex[66:], 16)
        if y >= SECP256K1_P or (y * y - right) % SECP256K1_P != 0:
            return None
        return x, y
    # p is 3 modulo 4, so a square root of a square c is c^((p+1)/4); a non-square has none, and x
    # is then the abscissa of no point. The prefix carries the parity of y.
    y = pow(right, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if y * y % SECP256K1_P != right:
        return None
    if y % 2 != int(prefix[1]) % 2:
        y = SECP256K1_P - y
    return x, y


def shares_point(public_key_hexes: Iterable[object], found: object) -> bool:
    """True when any of ``public_key_hexes`` is a spelling of the point ``found`` encodes.

    ``found`` is the key of the trust entry or the pinned root a row has settled on, and
    ``public_key_hexes`` the keys of the others (trust-registry-authorization.md section 6, row 6;
    trust-root.md section 5, row 7). A value that encodes no point shares none, and so does a
    ``found`` that encodes none. Only ``found`` is decoded: its point has exactly two lowercase
    spellings that ``secp256k1_point`` accepts, the compressed one (the parity of y in the prefix)
    and the uncompressed one, and a value of the others is the same point when it is equal to one
    of them. So the scan is a string comparison per key and stops at the first match, and the
    answer is that of comparing ``secp256k1_point`` of every key with the point of ``found``.
    """
    point = secp256k1_point(found)
    if point is None:
        return False
    x, y = f"{point[0]:064x}", f"{point[1]:064x}"
    compressed = ("03" if point[1] % 2 else "02") + x
    uncompressed = "04" + x + y
    return any(other == compressed or other == uncompressed for other in public_key_hexes)


def verify_digest(digest: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """True when ``signature_hex`` is a valid low-S signature of ``digest`` by ``public_key_hex``.

    ``digest`` is the 32-byte ECDSA hash value e, SHA-256 of the signing message, applied once
    (canonicalization-and-hashing.md section 4): it is handed to the library as prehashed and
    never hashed again. The protocol's strictness is checked here, before the library is called,
    because a library verifier admits what the protocol refuses (OpenSSL accepts a high S):
    the signature is 128 lowercase hex characters, r and s are in [1, n-1] and s is at most n/2;
    the key is an uncompressed SEC1 point with both coordinates below p and on the curve. The
    curve arithmetic is pyca/cryptography's.
    """
    if not isinstance(digest, bytes) or len(digest) != 32:
        return False
    if not isinstance(signature_hex, str) or not SIGNATURE_HEX_RE.fullmatch(signature_hex):
        return False
    try:
        x, y = parse_uncompressed_public_key(public_key_hex)
    except PublicKeyError:
        return False
    r = int(signature_hex[:64], 16)
    s = int(signature_hex[64:], 16)
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False
    if s > SECP256K1_N // 2:
        return False
    try:
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1()).public_key()
    except ValueError:
        return False
    try:
        public_key.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return False
    return True
