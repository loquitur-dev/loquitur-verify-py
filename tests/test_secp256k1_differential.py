"""Randomised differential: the verifier's secp256k1 check vs the schemas package's.

``secp256k1.verify_digest`` hands the curve arithmetic to pyca/cryptography
and checks the protocol's strictness (form, ranges, low S, coordinates below p, on-curve
key) before the library call. The strictness is this package's own code, so it is compared
with an independent implementation rather than assumed.

Two complementary layers sit beside it:
  * ``test_wycheproof_secp256k1`` locks the primitive against the Wycheproof
    known-answer corpus (adversarial edge cases, integrity-pinned);
  * ``test_cross_repo_canonical_equivalence`` proves one signed entry round-trips.

This module adds the layer neither provides: a *randomised differential* over many
independently generated keys and messages, asserting that this package's verifier
and the schemas package's reference reach the **same** accept/reject decision on every
input: valid signatures, tampered digests, tampered signatures, high-S malleated
forms, wrong keys, and structured garbage.

Both implementations enforce the same stricter-than-ECDSA low-S contract, so exact
agreement is the expected invariant; any divergence is a finding.

Determinism: the corpus is seeded, so a failure is always reproducible. Scale with
LOQUITUR_DIFFERENTIAL_ITERATIONS for a longer pre-release run.
"""

from __future__ import annotations

import hashlib
import os
import random

import pytest
from authorization_kit import public_key_hex_for_scalar, sign_digest_with_scalar
from siblings import import_sibling

from loquitur.verify.secp256k1 import (
    SECP256K1_N,
    SECP256K1_P,
    PublicKeyError,
    parse_uncompressed_public_key,
)
from loquitur.verify.secp256k1 import (
    verify_digest as verify_pure,
)

registry_signing = import_sibling(
    "loquitur.schemas.registry_signing",
    "differential requires loquitur-schemas (cryptography-backed reference)",
)

verify_reference = registry_signing._secp256k1_verify_digest


# The signatures under test are made here, with keys drawn from the seeded generator: the
# schemas package builds signing messages and does not sign.
def sign_reference(digest: bytes, private_hex: str) -> tuple[int, int]:
    return sign_digest_with_scalar(digest, int(private_hex, 16))


def public_key_from_private(private_hex: str) -> str:
    return public_key_hex_for_scalar(int(private_hex, 16))


SEED = 20260722
ITERATIONS = int(os.environ.get("LOQUITUR_DIFFERENTIAL_ITERATIONS", "48"))


def _compact(r: int, s: int) -> str:
    return f"{r:064x}{s:064x}"


def _flip_bit(data: bytes, rng: random.Random) -> bytes:
    index = rng.randrange(len(data))
    return data[:index] + bytes([data[index] ^ (1 << rng.randrange(8))]) + data[index + 1 :]


def _flip_hex_nibble(value: str, rng: random.Random) -> str:
    index = rng.randrange(len(value))
    replacement = rng.choice([c for c in "0123456789abcdef" if c != value[index].lower()])
    return value[:index] + replacement + value[index + 1 :]


def _keypair(rng: random.Random) -> tuple[str, str]:
    private_int = rng.randrange(1, SECP256K1_N)
    private_hex = f"{private_int:064x}"
    return private_hex, public_key_from_private(private_hex)


def _assert_agree(digest: bytes, sig_hex: str, public_key_hex: str, label: str) -> bool:
    """Both implementations must reach the same verdict. Returns that verdict."""
    pure = verify_pure(digest, sig_hex, public_key_hex)
    reference = verify_reference(digest, sig_hex, public_key_hex)
    assert pure == reference, (
        f"DIFFERENTIAL DIVERGENCE [{label}]: pure-python={pure} reference={reference}\n"
        f"  digest={digest.hex()}\n  sig={sig_hex}\n  pubkey={public_key_hex}"
    )
    return pure


def test_valid_signatures_are_accepted_by_both_implementations() -> None:
    rng = random.Random(SEED)
    for i in range(ITERATIONS):
        private_hex, public_hex = _keypair(rng)
        digest = hashlib.sha256(f"loquitur-differential-{i}".encode()).digest()
        r, s = sign_reference(digest, private_hex)
        assert _assert_agree(digest, _compact(r, s), public_hex, f"valid#{i}") is True


def test_tampered_digest_is_rejected_by_both_implementations() -> None:
    rng = random.Random(SEED + 1)
    for i in range(ITERATIONS):
        private_hex, public_hex = _keypair(rng)
        digest = hashlib.sha256(f"loquitur-tamper-digest-{i}".encode()).digest()
        r, s = sign_reference(digest, private_hex)
        assert _assert_agree(_flip_bit(digest, rng), _compact(r, s), public_hex, f"digest#{i}") is False


def test_tampered_signature_is_rejected_by_both_implementations() -> None:
    rng = random.Random(SEED + 2)
    for i in range(ITERATIONS):
        private_hex, public_hex = _keypair(rng)
        digest = hashlib.sha256(f"loquitur-tamper-sig-{i}".encode()).digest()
        r, s = sign_reference(digest, private_hex)
        assert _assert_agree(digest, _flip_hex_nibble(_compact(r, s), rng), public_hex, f"sig#{i}") is False


def test_high_s_malleated_signature_is_rejected_by_both_implementations() -> None:
    """The malleable twin (r, n-s) is mathematically valid ECDSA and MUST be refused."""
    rng = random.Random(SEED + 3)
    for i in range(ITERATIONS):
        private_hex, public_hex = _keypair(rng)
        digest = hashlib.sha256(f"loquitur-high-s-{i}".encode()).digest()
        r, s = sign_reference(digest, private_hex)
        assert 0 < s <= SECP256K1_N // 2, "reference signer must emit low-S"
        assert _assert_agree(digest, _compact(r, SECP256K1_N - s), public_hex, f"high-s#{i}") is False


def test_signature_does_not_verify_under_a_different_key() -> None:
    rng = random.Random(SEED + 4)
    for i in range(ITERATIONS):
        private_hex, _ = _keypair(rng)
        _, other_public_hex = _keypair(rng)
        digest = hashlib.sha256(f"loquitur-wrong-key-{i}".encode()).digest()
        r, s = sign_reference(digest, private_hex)
        assert _assert_agree(digest, _compact(r, s), other_public_hex, f"wrongkey#{i}") is False


@pytest.mark.parametrize(
    "label,make",
    [
        ("r_zero", lambda r, s: _compact(0, s)),
        ("s_zero", lambda r, s: _compact(r, 0)),
        ("r_equals_n", lambda r, s: _compact(SECP256K1_N, s)),
        ("s_equals_n", lambda r, s: _compact(r, SECP256K1_N)),
        ("r_above_n", lambda r, s: _compact(SECP256K1_N + 1, s)),
        ("both_zero", lambda r, s: _compact(0, 0)),
    ],
)
def test_out_of_range_scalars_are_rejected_by_both_implementations(label, make) -> None:
    rng = random.Random(SEED + 5)
    private_hex, public_hex = _keypair(rng)
    digest = hashlib.sha256(b"loquitur-scalar-range").digest()
    r, s = sign_reference(digest, private_hex)
    assert _assert_agree(digest, make(r, s), public_hex, label) is False


def test_structurally_invalid_inputs_agree_and_never_accept() -> None:
    rng = random.Random(SEED + 6)
    _, public_hex = _keypair(rng)
    digest = hashlib.sha256(b"loquitur-garbage").digest()
    malformed = [
        ("empty", ""),
        ("short", "00" * 63),
        ("long", "00" * 65),
        ("odd_length", "0" * 127),
        ("non_hex", "z" * 128),
        ("all_zero", "00" * 64),
        ("all_ff", "ff" * 64),
    ]
    for label, sig_hex in malformed:
        assert _assert_agree(digest, sig_hex, public_hex, f"malformed:{label}") is False
    for i in range(ITERATIONS):
        random_sig = "".join(rng.choice("0123456789abcdef") for _ in range(128))
        assert _assert_agree(digest, random_sig, public_hex, f"random#{i}") is False


def test_public_key_off_curve_is_rejected_by_both_implementations() -> None:
    """A point not satisfying y^2 = x^3 + 7 must never authorize a signature."""
    rng = random.Random(SEED + 7)
    private_hex, _ = _keypair(rng)
    digest = hashlib.sha256(b"loquitur-off-curve").digest()
    r, s = sign_reference(digest, private_hex)
    for i in range(8):
        x = rng.randrange(1, SECP256K1_P)
        y = rng.randrange(1, SECP256K1_P)
        if (y * y - (x * x * x + 7)) % SECP256K1_P == 0:  # pragma: no cover - astronomically unlikely
            continue
        off_curve = f"04{x:064x}{y:064x}"
        assert _assert_agree(digest, _compact(r, s), off_curve, f"off-curve#{i}") is False


def test_off_curve_public_keys_are_refused_at_parse_time() -> None:
    """Invalid-curve guard, asserted directly.

    End-to-end verification is NOT sufficient evidence here: removing the on-curve
    check still yields REJECT for most inputs, because the forged point simply fails
    the final r comparison. That makes the differential blind to a missing guard.
    This test pins the guard itself, so deleting it fails loudly.
    """
    x, y = 0x11 * (16**62), 0x22 * (16**62)
    assert (y * y - (x * x * x + 7)) % SECP256K1_P != 0, "fixture must be off-curve"
    with pytest.raises(PublicKeyError, match="not on secp256k1"):
        parse_uncompressed_public_key(f"04{x:064x}{y:064x}")

    rng = random.Random(SEED + 8)
    for _ in range(16):
        x = rng.randrange(1, SECP256K1_P)
        y = rng.randrange(1, SECP256K1_P)
        if (y * y - (x * x * x + 7)) % SECP256K1_P == 0:  # pragma: no cover
            continue
        with pytest.raises(PublicKeyError):
            parse_uncompressed_public_key(f"04{x:064x}{y:064x}")


def test_on_curve_public_keys_are_accepted_at_parse_time() -> None:
    """Counterpart to the guard test: real keys must still parse."""
    rng = random.Random(SEED + 9)
    for _ in range(8):
        _, public_hex = _keypair(rng)
        x, y = parse_uncompressed_public_key(public_hex)
        assert (y * y - (x * x * x + 7)) % SECP256K1_P == 0
