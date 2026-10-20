"""One secp256k1 point under two labels is an ambiguous key, whatever the labels say.

Revocation is of a key, not of its label. A trust registry that lists one public key under two
``issuer_key_id`` values, or under two issuers, and a trust-root document that lists one public
key under two ``key_id`` values, give that key two authorities: the revoked label and the active
one. Row 6 of trust-registry-authorization.md section 6 stops such a registry with
``TRUST_REGISTRY_AMBIGUOUS_KEY``, and row 7 of trust-root.md section 5 stops such a root set with
``AMBIGUOUS_ROOT_KEY``. Keys are compared as points, in any SEC1 spelling and whatever their key
types; a value that encodes no point shares none.

The keys here are generated in memory for the run and never written or printed.
"""

from __future__ import annotations

import copy
import random
from typing import Any

import pytest
from authorization_kit import IssuerKey, authorization_material, run_authorization

from loquitur.verify import trust_registry
from loquitur.verify.secp256k1 import SECP256K1_P, secp256k1_point, shares_point
from loquitur.verify.trust_root import (
    STATUS_AMBIGUOUS_ROOT_KEY,
    STATUS_ROOT_REVOKED,
    STATUS_VALID,
    TrustRootKey,
    trust_registry_signing_bytes,
    verify_trust_registry_root_signature,
)

cryptography = pytest.importorskip("cryptography", reason="signing the fixtures needs cryptography")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils  # noqa: E402

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
EVALUATED_AT = "2026-05-10T00:00:00Z"


def _hex32(value: int) -> str:
    return format(value, "064x")


def uncompressed(x: int, y: int) -> str:
    return "04" + _hex32(x) + _hex32(y)


def compressed(x: int, y: int) -> str:
    return ("03" if y % 2 else "02") + _hex32(x)


def spellings_of(public_key_hex: str) -> tuple[str, str]:
    """The compressed spelling of an uncompressed key, and its hybrid spelling (06 or 07)."""
    x, y = int(public_key_hex[2:66], 16), int(public_key_hex[66:], 16)
    return compressed(x, y), ("07" if y % 2 else "06") + public_key_hex[2:]


# ---- the point a public key encodes -------------------------------------------------------------


def test_the_generator_in_each_sec1_spelling_is_one_point() -> None:
    assert secp256k1_point(uncompressed(GX, GY)) == (GX, GY)
    assert secp256k1_point(compressed(GX, GY)) == (GX, GY)
    # The other parity names the negated point, not the generator.
    other = ("02" if GY % 2 else "03") + _hex32(GX)
    assert secp256k1_point(other) == (GX, SECP256K1_P - GY)


def test_an_uppercase_spelling_encodes_no_point() -> None:
    # Lowercase only, as loquitur-verify-ts gates its decoder. The contracts that admit a key to
    # the rows (the trust registry's schema, trust-root.md section 3) refuse uppercase before this
    # is reached, so the two verifiers agree on a value no row reads as well.
    assert secp256k1_point(uncompressed(GX, GY).upper()) is None
    assert secp256k1_point(compressed(GX, GY).upper()) is None
    assert secp256k1_point(uncompressed(GX, GY)[:40] + uncompressed(GX, GY)[40:].upper()) is None


def _x_with_no_point() -> int:
    x = 1
    while pow((x**3 + 7) % SECP256K1_P, (SECP256K1_P - 1) // 2, SECP256K1_P) == 1:
        x += 1
    return x


@pytest.mark.parametrize(
    "public_key_hex",
    [
        pytest.param("04" + _hex32(SECP256K1_P) + _hex32(GY), id="uncompressed-x-is-p"),
        pytest.param("04" + _hex32(GX) + _hex32(SECP256K1_P), id="uncompressed-y-is-p"),
        pytest.param("02" + _hex32(SECP256K1_P), id="compressed-x-is-p"),
        pytest.param("03" + _hex32(SECP256K1_P + 1), id="compressed-x-above-p"),
        pytest.param(uncompressed(GX, GY + 1), id="off-the-curve"),
        pytest.param("02" + _hex32(_x_with_no_point()), id="x-of-no-point"),
        pytest.param("06" + _hex32(GX) + _hex32(GY), id="hybrid-06"),
        pytest.param("07" + _hex32(GX) + _hex32(GY), id="hybrid-07"),
        pytest.param("00", id="infinity"),
        pytest.param("04", id="prefix-only"),
        pytest.param(compressed(GX, GY)[:-2], id="compressed-short"),
        pytest.param(uncompressed(GX, GY) + "00", id="uncompressed-long"),
        pytest.param("05" + _hex32(GX), id="unknown-prefix"),
        pytest.param(" " + uncompressed(GX, GY), id="leading-space"),
        pytest.param(uncompressed(GX, GY) + "\n", id="trailing-newline"),
        pytest.param("0x" + compressed(GX, GY), id="0x-prefix"),
        pytest.param("", id="empty"),
        pytest.param(None, id="null"),
        pytest.param(int(uncompressed(GX, GY), 16), id="number"),
    ],
)
def test_a_value_that_encodes_no_point_has_none(public_key_hex: Any) -> None:
    assert secp256k1_point(public_key_hex) is None


# ---- shares_point against the comparison it replaces ---------------------------------------------


def _reference_shares_point(items: list[Any], found: Any) -> bool:
    """The rule as first written: decode every key and compare the points."""
    point = secp256k1_point(found)
    if point is None:
        return False
    return any(secp256k1_point(other) == point for other in items)


def _spellings(rng: random.Random, x: int, y: int) -> list[Any]:
    """Every way a test draws a value for the point (x, y): right, wrong, and no spelling at all."""
    xh, yh = _hex32(x), _hex32(y)
    parity, wrong = ("03", "02") if y % 2 else ("02", "03")
    return [
        parity + xh,
        wrong + xh,
        "04" + xh + yh,
        "04" + xh + _hex32((y + 1) % SECP256K1_P),
        "04" + xh + _hex32(SECP256K1_P - y),
        "04" + xh + _hex32(y + SECP256K1_P) if y + SECP256K1_P < 2**256 else "04" + xh + yh.upper(),
        (parity + xh).upper(),
        ("04" + xh + yh).upper(),
        "06" + xh + yh,
        "07" + xh + yh,
        parity + _hex32(x + SECP256K1_P) if x + SECP256K1_P < 2**256 else "02" + _hex32(SECP256K1_P),
        " " + parity + xh,
        parity + xh + "\n",
        parity + xh[:-2],
        "04" + xh + yh + "00",
        rng.choice([None, 7, 1.5, True, [], {}, b"02" + xh.encode(), ""]),
    ]


def _draw(rng: random.Random, points: list[tuple[int, int]]) -> Any:
    """A spelling of one of the points, a valid one (the first three) half of the time."""
    spellings = _spellings(rng, *rng.choice(points))
    return rng.choice(spellings[:3] if rng.random() < 0.5 else spellings)


def test_shares_point_agrees_with_decoding_every_key() -> None:
    rng = random.Random(0x5EC1)
    points: list[tuple[int, int]] = []
    while len(points) < 3:
        x = rng.randrange(1, 2**64) if len(points) % 2 else rng.randrange(1, SECP256K1_P)
        decoded = secp256k1_point("02" + _hex32(x))
        if decoded is not None:
            points.append(decoded)
    shared = 0
    for _ in range(4000):
        pool = [_draw(rng, points) for _ in range(rng.randrange(0, 6))]
        found = _draw(rng, points)
        expected = _reference_shares_point(pool, found)
        assert shares_point(iter(pool), found) is expected, (pool, found)
        # The registry helper skips the entry itself and anything that is not an object.
        entries: list[Any] = [{"public_key_hex": value} for value in pool] + [None, 3, "04", ["02"]]
        entry = {"public_key_hex": found}
        entries.insert(rng.randrange(len(entries) + 1), entry)
        assert trust_registry._shares_point_with_other_entry(entry, entries) is expected
        shared += expected
    # Neither all nor none of the draws share a point, so both answers were compared.
    assert 300 < shared < 3700, shared


def test_a_value_that_is_not_a_key_string_is_skipped_by_the_scan() -> None:
    found = compressed(GX, GY)
    assert shares_point([None, 5, b"", [], {"public_key_hex": found}], found) is False
    assert shares_point(iter([None, uncompressed(GX, GY)]), found) is True
    assert shares_point([], found) is False
    assert shares_point([found], "04ab") is False
    assert shares_point([found], None) is False


def test_the_scan_stops_at_the_first_match() -> None:
    consumed: list[int] = []

    def keys():
        for index in range(1000):
            consumed.append(index)
            yield uncompressed(GX, GY) if index == 3 else "ab"

    assert shares_point(keys(), compressed(GX, GY)) is True
    assert consumed == [0, 1, 2, 3]


# ---- trust registry, row 6 -----------------------------------------------------------------------

AMBIGUOUS = ("OFFLINE_FAIL", 1, "TRUST_REGISTRY_AMBIGUOUS_KEY")
AUTHORIZED = ("OFFLINE_REVIEW", 2, "AUTHORIZED_ACTIVE_KEY")


def _second_entry(registry: dict[str, Any], **changes: Any) -> None:
    other = copy.deepcopy(registry["entries"][0])
    other.update(changes)
    registry["entries"].append(other)


def _authorize(tmp_path, key: IssuerKey, trust) -> tuple[str, int, str | None]:
    entry, registry = authorization_material(key, trust=trust)
    report = run_authorization(tmp_path, entry, registry)
    return report["status"], report["exit_code"], report["trust_registry"]["authorization_status"]


REVOKED = {"status": "revoked", "revoked_at": "2026-05-01T00:00:00Z", "revocation_reason": "key_compromise"}


@pytest.mark.parametrize(
    ("case", "second", "expected"),
    [
        # The control: another trust entry with its own key.
        (
            "distinct-key",
            lambda key: {"issuer_key_id": "demo-key-9", "public_key_hex": IssuerKey().public_key_hex},
            AUTHORIZED,
        ),
        # The same issuer_key_id under another issuer_id is not a label duplicate, and a key of its
        # own is not a shared point.
        (
            "same-key-id-other-issuer-own-key",
            lambda key: {"issuer_id": "issuer_other_demo", "public_key_hex": IssuerKey().public_key_hex},
            AUTHORIZED,
        ),
        # Two ids, one key, the other revoked: the revoked point must not authorize under the active label.
        ("two-ids-one-key-other-revoked", lambda key: {"issuer_key_id": "demo-key-9", **REVOKED}, AMBIGUOUS),
        ("two-ids-one-key-both-active", lambda key: {"issuer_key_id": "demo-key-9"}, AMBIGUOUS),
        # One point in another spelling is one key.
        (
            "compressed-and-uncompressed",
            lambda key: {"issuer_key_id": "demo-key-9", "public_key_hex": spellings_of(key.public_key_hex)[0]},
            AMBIGUOUS,
        ),
        # Another issuer, the same issuer_key_id: not a label duplicate, but one point.
        ("two-issuers-one-key", lambda key: {"issuer_id": "issuer_other_demo"}, AMBIGUOUS),
        (
            "two-issuers-one-key-other-id",
            lambda key: {"issuer_id": "issuer_other_demo", "issuer_key_id": "k"},
            AMBIGUOUS,
        ),
        # Whatever the key type, a valid secp256k1 encoding has a point (trust-registry-authorization.md
        # section 5, key_type).
        ("other-key-type", lambda key: {"issuer_key_id": "demo-key-9", "key_type": "ed25519"}, AMBIGUOUS),
        (
            "other-key-type-suspended",
            lambda key: {"issuer_key_id": "demo-key-9", "key_type": "x", "status": "suspended"},
            AMBIGUOUS,
        ),
        # The hybrid spelling encodes no point here, so it shares none.
        (
            "hybrid-spelling-shares-none",
            lambda key: {"issuer_key_id": "demo-key-9", "public_key_hex": spellings_of(key.public_key_hex)[1]},
            AUTHORIZED,
        ),
        ("no-point-shares-none", lambda key: {"issuer_key_id": "demo-key-9", "public_key_hex": "04ab"}, AUTHORIZED),
    ],
)
def test_row_6_stops_a_point_shared_with_another_trust_entry(tmp_path, case: str, second, expected) -> None:
    key = IssuerKey()
    assert _authorize(tmp_path, key, lambda registry: _second_entry(registry, **second(key))) == expected, case


def test_two_other_entries_sharing_a_point_leave_an_entry_that_names_neither_authorized(tmp_path) -> None:
    other = IssuerKey().public_key_hex

    def trust(registry: dict[str, Any]) -> None:
        _second_entry(registry, issuer_key_id="demo-key-8", public_key_hex=other)
        _second_entry(registry, issuer_key_id="demo-key-9", public_key_hex=spellings_of(other)[0], **REVOKED)
        _second_entry(registry, issuer_id="issuer_other_demo", issuer_key_id="demo-key-9", public_key_hex=other)

    assert _authorize(tmp_path, IssuerKey(), trust) == AUTHORIZED


@pytest.mark.parametrize("revoked_first", [True, False])
def test_the_shared_point_stops_whichever_entry_comes_first(tmp_path, revoked_first: bool) -> None:
    def trust(registry: dict[str, Any]) -> None:
        _second_entry(registry, issuer_key_id="demo-key-9", **REVOKED)
        if revoked_first:
            registry["entries"].reverse()

    assert _authorize(tmp_path, IssuerKey(), trust) == AMBIGUOUS


def test_the_point_is_judged_after_the_label_and_before_the_status(tmp_path) -> None:
    # Row 6 between rows 5 and 7: the matched entry is revoked and shares its point with an
    # active one, so the run reports the ambiguity, not the revocation of one label.
    def trust(registry: dict[str, Any]) -> None:
        registry["entries"][0].update(REVOKED)
        _second_entry(registry, issuer_key_id="demo-key-9", status="active", revoked_at=None, revocation_reason=None)

    assert _authorize(tmp_path, IssuerKey(), trust) == AMBIGUOUS


def test_an_uppercase_key_is_refused_by_the_contract_before_row_6(tmp_path) -> None:
    key = IssuerKey()
    status, exit_code, authorization = _authorize(
        tmp_path,
        key,
        lambda registry: _second_entry(registry, issuer_key_id="demo-key-9", public_key_hex=key.public_key_hex.upper()),
    )
    assert (status, exit_code, authorization) == ("OFFLINE_FAIL", 1, "INVALID_TRUST_REGISTRY")


# ---- trust roots, row 7 --------------------------------------------------------------------------


class _RootKey:
    """An ephemeral root key. The private half never leaves this object."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256K1())
        numbers = self._key.public_key().public_numbers()
        self.public_key_hex = uncompressed(numbers.x, numbers.y)

    def sign(self, registry: dict[str, Any], key_id: str) -> dict[str, Any]:
        registry.pop("signature", None)
        der = self._key.sign(trust_registry_signing_bytes(registry), ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        s = min(s, SECP256K1_N - s)
        registry["signature"] = {
            "algorithm": "secp256k1_ecdsa_sha256",
            "key_id": key_id,
            "signature": _hex32(r) + _hex32(s),
        }
        return registry


def _root(key_id: str, public_key_hex: str, **changes: Any) -> TrustRootKey:
    fields = {
        "key_id": key_id,
        "key_type": "secp256k1",
        "public_key_hex": public_key_hex,
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": "2030-01-01T00:00:00Z",
        "status": "active",
    }
    fields.update(changes)
    return TrustRootKey(**fields)


@pytest.fixture(scope="module")
def signed() -> tuple[_RootKey, dict[str, Any]]:
    _, registry = authorization_material(IssuerKey())
    key = _RootKey()
    return key, key.sign(registry, "root-1")


@pytest.mark.parametrize(
    ("case", "other", "expected"),
    [
        ("distinct-key", lambda key: _root("root-9", _RootKey().public_key_hex), STATUS_VALID),
        # Another root with a key of its own that is revoked says nothing of the matched root: only
        # the matched root's status is read.
        (
            "other-own-key-revoked",
            lambda key: _root("root-9", _RootKey().public_key_hex, status="revoked"),
            STATUS_VALID,
        ),
        # trust-root.md section 3, `other-revoked`: root-9 carries N's key and is revoked.
        ("other-revoked", lambda key: _root("root-9", key.public_key_hex, status="revoked"), STATUS_AMBIGUOUS_ROOT_KEY),
        ("other-active", lambda key: _root("root-9", key.public_key_hex), STATUS_AMBIGUOUS_ROOT_KEY),
        # A root of another key type may carry any lowercase hex, so a compressed spelling reaches
        # the rows; it names N's point (trust-root.md section 5, row 7).
        (
            "other-key-type-compressed",
            lambda key: _root("root-9", spellings_of(key.public_key_hex)[0], key_type="ed25519"),
            STATUS_AMBIGUOUS_ROOT_KEY,
        ),
        (
            "other-key-type-hybrid",
            lambda key: _root("root-9", spellings_of(key.public_key_hex)[1], key_type="ed25519"),
            STATUS_VALID,
        ),
        ("other-key-type-no-point", lambda key: _root("root-9", "04ab", key_type="ed25519"), STATUS_VALID),
    ],
)
def test_row_7_stops_a_root_that_shares_its_point(signed, case: str, other, expected: str) -> None:
    key, registry = signed
    roots = (_root("root-1", key.public_key_hex), other(key))
    for ordered in (roots, roots[::-1]):
        result = verify_trust_registry_root_signature(registry, evaluated_at=EVALUATED_AT, roots=ordered)
        assert result.status == expected, (case, [root.key_id for root in ordered])
        assert result.ok is (expected == STATUS_VALID)


def test_row_7_comes_before_the_revocation_of_the_matched_root(signed) -> None:
    key, registry = signed
    roots = (_root("root-1", key.public_key_hex, status="revoked"), _root("root-9", key.public_key_hex))
    assert verify_trust_registry_root_signature(registry, evaluated_at=EVALUATED_AT, roots=roots).status == (
        STATUS_AMBIGUOUS_ROOT_KEY
    )
    # Without the second root, the same matched root is reported revoked.
    alone = verify_trust_registry_root_signature(registry, evaluated_at=EVALUATED_AT, roots=roots[:1])
    assert alone.status == STATUS_ROOT_REVOKED
