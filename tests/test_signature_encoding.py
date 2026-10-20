"""A registry-entry signature is `r || s`, and nothing else that happens to be 64 bytes.

canonicalization-and-hashing.md §4 defines one encoding: `r || s` as 128 lowercase hex
characters. A DER encoding whose two integers are 29 bytes each is also 64 bytes, so it
passes every length and alphabet check, and @noble/curves, given bytes and no format, reads
DER first, so a verifier that hands it the bytes alone accepts it. Both verifiers read the two
halves as r and s, which is what the specification says, and fail the entry; the matching lock
is in loquitur-verify-ts/test/cross-language-conformance.test.ts, with the same values.

The values are not a lucky signature. For the fixture entry's signing digest z and a small
r whose x lies on the curve, the key Q = (s*R - z*G) / r makes (r, s) verify, so the DER
bytes below are a valid signature by Q, which the premise test shows by verifying the
same (r, s) written as `r || s`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from loquitur.verify.runner import EXIT_OFFLINE_FAIL, verify_path
from loquitur.verify.secp256k1 import verify_digest
from loquitur.verify.signing_envelope import signing_message_bytes

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE_DIR = FIXTURES / "link_valid_bundle"

DER_SIGNATURE_HEX = (
    "303e021d2e43787471f7543fc08bfd2a4545665ce1c05e3c1dd7d93ed524873173"
    "021d11443e1eba922cb77d8bc4f41992fe8292fd635ad05366b69e6de7dc78"
)
SAME_SIGNATURE_AS_R_S_HEX = (
    "0000002e43787471f7543fc08bfd2a4545665ce1c05e3c1dd7d93ed524873173"
    "00000011443e1eba922cb77d8bc4f41992fe8292fd635ad05366b69e6de7dc78"
)
# Solved over the fixture entry; loquitur-verify-ts holds the same key.
DER_SOLVED_PUBLIC_KEY_HEX = (
    "04a7f98e2d747f760bef34adf11e1a92335dd2ff5a1c33d0aa0c0eb5706f16029b"
    "63216d761bcd05ccfaa4ba01bcee0fc7ca9a74dd5d6bb4ff817687e81099ba3a"
)


def _documents(signature_hex: str) -> tuple[dict, dict]:
    entry = json.loads((FIXTURES / "authorization_valid_registry_entry.json").read_text(encoding="utf-8"))
    trust = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    entry["signature"]["signature"] = signature_hex
    trust["entries"][0]["public_key_hex"] = DER_SOLVED_PUBLIC_KEY_HEX
    return entry, trust


def _verify(tmp_path: Path, signature_hex: str) -> dict:
    entry, trust = _documents(signature_hex)
    entry_path = tmp_path / "entry.json"
    trust_path = tmp_path / "trust.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    return verify_path(
        BUNDLE_DIR,
        registry_entry_path=entry_path,
        trust_registry_path=trust_path,
        evaluation_time="2026-05-10T00:00:00Z",
    ).to_dict()


def test_the_der_bytes_encode_a_valid_signature_by_the_solved_key() -> None:
    """The premise. Without it, the rejection below could be about anything."""

    der = bytes.fromhex(DER_SIGNATURE_HEX)
    assert len(der) == 64 and der[:4] == bytes([0x30, 0x3E, 0x02, 0x1D]) and der[33:35] == bytes([0x02, 0x1D])
    r, s = der[4:33], der[35:]
    assert SAME_SIGNATURE_AS_R_S_HEX == (r.rjust(32, b"\0") + s.rjust(32, b"\0")).hex()

    entry, _ = _documents(DER_SIGNATURE_HEX)
    digest = hashlib.sha256(signing_message_bytes(entry)).digest()
    assert verify_digest(digest, SAME_SIGNATURE_AS_R_S_HEX, DER_SOLVED_PUBLIC_KEY_HEX) is True
    assert verify_digest(digest, DER_SIGNATURE_HEX, DER_SOLVED_PUBLIC_KEY_HEX) is False


def test_the_same_signature_as_r_s_authorises(tmp_path: Path) -> None:
    payload = _verify(tmp_path, SAME_SIGNATURE_AS_R_S_HEX)
    assert payload["checks"]["registry_signature"] == "VALID_SIGNATURE"
    assert payload["checks"]["trust_registry"] is True


def test_a_64_byte_der_signature_fails_the_entry(tmp_path: Path) -> None:
    payload = _verify(tmp_path, DER_SIGNATURE_HEX)
    assert (payload["status"], payload["verdict"], payload["exit_code"]) == ("OFFLINE_FAIL", "FAIL", EXIT_OFFLINE_FAIL)
    assert payload["checks"]["registry_signature"] == "SIGNATURE_INVALID"
    assert payload["checks"]["trust_registry"] is False
    assert payload["trust_registry"]["signature_status"] == "SIGNATURE_INVALID"
