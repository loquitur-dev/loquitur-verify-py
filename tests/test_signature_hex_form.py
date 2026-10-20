"""Signatures and public keys are lowercase hexadecimal, checked before they are parsed.

trust-root.md §4.2 and canonicalization-and-hashing.md specify "r || s as exactly 128
lowercase hex characters" and public keys as ^04[0-9a-f]{128}$. A length check followed by
int(x, 16) does not hold that form, because int() reads surrounding whitespace, underscores, a
0x prefix and either case as the same integer:
  * the trust-root check (row 5 of the normative evaluation order) would pass 128 'z' on to
    the key lookup and come back UNKNOWN_ROOT_KEY or ROOT_SIGNATURE_INVALID instead of
    MALFORMED_SIGNATURE, and an uppercase or space-padded spelling of a valid root signature
    would come back ROOT_SIGNATURE_VALID;
  * a pinned root's public key lower-cased before its pattern is tested would pass it.
The pattern runs first, on the value as written. Keys are generated in this process and
never written.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr
from pathlib import Path

import pytest
from bundle_builder import FIXTURES, Bundle

from loquitur.verify import cli
from loquitur.verify.secp256k1 import verify_digest
from loquitur.verify.trust_root import (
    TrustRootError,
    TrustRootKey,
    parse_trust_roots,
    trust_registry_signing_bytes,
    verify_trust_registry_root_signature,
)

cryptography = pytest.importorskip("cryptography", reason="signing needs cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils  # noqa: E402

_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
EVALUATED_AT = "2026-09-16T00:00:00Z"


def _public(key) -> str:
    return (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    )


def _signature(key, message: bytes) -> str:
    """A low-s signature whose r and s both start with the digit 0, so padding keeps the value."""
    while True:
        r, s = asym_utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        text = (r.to_bytes(32, "big") + min(s, _ORDER - s).to_bytes(32, "big")).hex()
        if text[0] == "0" and text[64] == "0":
            return text


@pytest.fixture(scope="module")
def signed() -> dict:
    root = ec.generate_private_key(ec.SECP256K1())
    registry = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    registry.pop("signature", None)
    return {"key": root, "registry": registry, "signature": _signature(root, trust_registry_signing_bytes(registry))}


def _roots(signed: dict, key_id: str = "r1", public_key_hex: str | None = None) -> tuple[TrustRootKey, ...]:
    return parse_trust_roots(
        {
            "object_type": "trust_root_document",
            "schema_version": "v1",
            "roots": [
                {
                    "key_id": key_id,
                    "key_type": "secp256k1",
                    "public_key_hex": public_key_hex or _public(signed["key"]),
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z",
                }
            ],
        }
    )


def _status(signed: dict, signature: object, roots: tuple[TrustRootKey, ...]) -> str:
    document = dict(signed["registry"])
    document["signature"] = {"algorithm": "secp256k1_ecdsa_sha256", "key_id": "r1", "signature": signature}
    return verify_trust_registry_root_signature(document, evaluated_at=EVALUATED_AT, roots=roots).status


_MALFORMED = {
    "z128": lambda s: "z" * 128,
    "uppercase": str.upper,
    "space-padded": lambda s: " " + s[1:64] + " " + s[65:],
    "0x-prefixed": lambda s: "0x" + s[2:64] + "0x" + s[66:],
    "underscores": lambda s: "_" + s[1:64] + "_" + s[65:],
    "length-127": lambda s: s[:127],
    "length-129": lambda s: s + "0",
    "not-a-string": lambda s: int(s, 16),
}


def test_a_malformed_root_signature_is_malformed_before_the_key_lookup(signed: dict) -> None:
    # Row 5 precedes row 6: with the signing key not pinned, the answer is still the form. The
    # length and type rows, which a length test refuses too, run with the rows it misses.
    got = {
        label: (
            _status(signed, spell(signed["signature"]), _roots(signed)),
            _status(signed, spell(signed["signature"]), _roots(signed, key_id="other")),
        )
        for label, spell in _MALFORMED.items()
    }
    got["valid-lowercase"] = _status(signed, signed["signature"], _roots(signed))
    assert got == {
        **dict.fromkeys(_MALFORMED, ("MALFORMED_SIGNATURE", "MALFORMED_SIGNATURE")),
        "valid-lowercase": "ROOT_SIGNATURE_VALID",
    }


def test_an_uppercase_root_public_key_is_refused(signed: dict) -> None:
    upper = "04" + _public(signed["key"])[2:].upper()
    with pytest.raises(TrustRootError):
        _roots(signed, public_key_hex=upper)
    with pytest.raises(TrustRootError):
        TrustRootKey(
            key_id="r1",
            key_type="secp256k1",
            public_key_hex=upper,
            not_before="2020-01-01T00:00:00Z",
            not_after="2030-01-01T00:00:00Z",
        ).assert_valid()


def test_the_cli_refuses_a_trust_root_file_with_an_uppercase_key(signed: dict, tmp_path: Path) -> None:
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    entry = bundle.link_entry(tmp_path / "entry.json")
    roots_path = tmp_path / "roots.json"
    roots_path.write_text(
        json.dumps(
            {
                "object_type": "trust_root_document",
                "schema_version": "v1",
                "roots": [
                    {
                        "key_id": "r1",
                        "key_type": "secp256k1",
                        "public_key_hex": "04" + _public(signed["key"])[2:].upper(),
                        "not_before": "2020-01-01T00:00:00Z",
                        "not_after": "2030-01-01T00:00:00Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    trust = FIXTURES / "authorization_valid_trust_registry.json"
    argv = [str(root), "--json", "--registry-entry", str(entry), "--trust-registry", str(trust)]
    with redirect_stderr(io.StringIO()):
        assert cli.main([*argv, "--trust-root", str(roots_path)]) == 64


@pytest.mark.parametrize("label", ["uppercase", "space-padded", "0x-prefixed", "underscores"])
def test_the_ecdsa_helper_refuses_a_signature_int_would_have_read(signed: dict, label: str) -> None:
    import hashlib

    digest = hashlib.sha256(trust_registry_signing_bytes(signed["registry"])).digest()
    public = _public(signed["key"])
    assert verify_digest(digest, signed["signature"], public) is True
    assert verify_digest(digest, _MALFORMED[label](signed["signature"]), public) is False
    assert verify_digest(digest, signed["signature"], "04" + public[2:].upper()) is False
