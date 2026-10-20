"""A trust registry that cannot be canonicalized fails its root signature (trust-root.md section 5).

The bytes a root signs are the JCS form of the registry. A mapping holding a value JCS refuses (a
float NaN, a lone surrogate) has no such form, so it cannot be the registry the root signed: the
signature step reports ROOT_SIGNATURE_INVALID, as the TypeScript verifier does, instead of letting
the canonicalization error escape to the caller. The verifier's own document intake refuses such
values first; this is the library entry point a caller can hand a mapping to directly.
"""

from __future__ import annotations

import pytest

from loquitur.verify.trust_root import STATUS_SIGNATURE_INVALID, TrustRootKey, verify_trust_registry_root_signature

cryptography = pytest.importorskip("cryptography", reason="the test root key is generated with cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


def _root() -> TrustRootKey:
    # Generated per run; only the public point is kept.
    public = ec.generate_private_key(ec.SECP256K1()).public_key()
    point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    return TrustRootKey(
        key_id="root-1",
        key_type="secp256k1",
        public_key_hex=point,
        not_before="2026-04-01T00:00:00Z",
        not_after="2026-07-01T00:00:00Z",
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "\ud800"], ids=["nan", "infinity", "lone-surrogate"])
def test_a_registry_that_cannot_be_canonicalised_has_an_invalid_root_signature(value: object) -> None:
    registry = {
        "object_type": "trust_registry",
        "entries": [{"note": value}],
        "signature": {"algorithm": "secp256k1_ecdsa_sha256", "key_id": "root-1", "signature": "1" * 128},
    }
    root = _root()
    result = verify_trust_registry_root_signature(registry, evaluated_at="2026-05-01T12:00:00Z", roots=(root,))
    assert result.ok is False
    assert result.status == STATUS_SIGNATURE_INVALID
    assert result.root_key_id == "root-1"
