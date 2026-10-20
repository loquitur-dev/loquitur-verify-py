"""One signed registry entry has one H, with no anchor and under an anchor of each method.

anchor-commitment.md section 1 binds whatever the anchoring method, and the anchor is outside the
signing payload (signing-envelope-v2.md section 1). The corpus vector vectors/anchor-methods.json
carries one signed entry with `anchor` null and with an anchor of each registered method; this
checks, with this verifier's own signing message and secp256k1 code, that every case has the
declared digest and that its one signature verifies. The module skips, saying why, when
LOQUITUR_CORPUS_ROOTS names no corpus root or the root carries no such vector.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from loquitur.verify.secp256k1 import verify_digest
from loquitur.verify.signing_envelope import signing_message_bytes

ROOTS_ENV = "LOQUITUR_CORPUS_ROOTS"
VECTOR = "vectors/anchor-methods.json"


def _roots() -> list[Path]:
    value = os.environ.get(ROOTS_ENV, "").strip()
    return [Path(part) for part in value.split(os.pathsep) if part.strip()]


@pytest.mark.skipif(not _roots(), reason=f"{ROOTS_ENV} names no corpus root")
@pytest.mark.parametrize("root", _roots(), ids=lambda root: root.name or str(root))
def test_every_anchor_method_keeps_the_signing_message_and_the_signature(root: Path) -> None:
    path = root / VECTOR
    if not path.is_file():
        pytest.skip(f"{root} carries no {VECTOR}")
    vector = json.loads(path.read_text(encoding="utf-8"))
    methods = set()
    signatures = set()
    for case in vector["cases"]:
        entry = case["entry"]
        anchor = entry.get("anchor")
        methods.add(None if anchor is None else anchor["method"])
        message = signing_message_bytes(entry)
        assert "sha256:" + hashlib.sha256(message).hexdigest() == vector["signing_payload_sha256"], case["id"]
        signature = entry["signature"]["signature"]
        signatures.add(signature)
        assert verify_digest(hashlib.sha256(message).digest(), signature, vector["public_key_hex"]), case["id"]
    assert methods == {None, "blockchain_transaction", "rfc3161_timestamp", "transparency_log_checkpoint"}
    assert len(signatures) == 1
