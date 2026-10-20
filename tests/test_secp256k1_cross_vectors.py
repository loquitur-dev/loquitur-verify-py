"""secp256k1 cross vectors: this verifier and @noble/curves give the same verdict on each case.

The file holds public material only: a digest (the ECDSA hash value e), a compact signature and
an uncompressed public key per case, with the verdict both implementations give. The verdicts
were produced by @noble/curves (verify with lowS, the digest as the prehashed message) and are
fixed here; this test holds the Python verifier to them. The cases are the ones a library
verifier and the protocol disagree on, or that an implementation of the curve arithmetic can get
wrong:

- a high S, which OpenSSL accepts and the protocol refuses;
- r or s of 0, n, or above n;
- a public key off the curve;
- a public key whose x or whose y is written as itself plus p (it still fits in 32 bytes for a
  small coordinate). The signature in those cases is valid for the canonical encoding of the
  same point, which is a case of its own and is accepted: only the encoding differs;
- the digest hashed a second time, which the protocol never does;
- forms the protocol refuses before any arithmetic: a compressed key, uppercase hex.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from loquitur.verify.secp256k1 import verify_digest

_VECTORS_PATH = Path(__file__).parent / "vectors" / "secp256k1_cross_vectors.json"
_VECTORS_SHA256 = "65e97c765c8afe5c99d52339ba4c1ad0fcf5c8b7fdafd4f049631b95bbec68ac"
_CASES = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))["cases"]


def test_the_vector_file_is_the_one_checked_against_noble() -> None:
    assert hashlib.sha256(_VECTORS_PATH.read_bytes()).hexdigest() == _VECTORS_SHA256
    names = {case["name"] for case in _CASES}
    for required in ("high_s", "x_not_below_p", "y_not_below_p", "off_curve_key", "double_hashed_digest"):
        assert required in names
    assert any(case["accept"] for case in _CASES) and any(not case["accept"] for case in _CASES)


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_the_verdict_is_the_one_noble_gives(case: dict) -> None:
    digest = bytes.fromhex(case["digest"])
    assert verify_digest(digest, case["signature"], case["public_key"]) is case["accept"]
