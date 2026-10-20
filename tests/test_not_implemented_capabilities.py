"""outcome.not_implemented_capabilities says what this run did not do.

The list depends on the run. A run in which a pinned root verified the trust registry's
signature reports trust_registry_root_signature_verified: true, and a constant list would put
trust_registry_root_signature_verification among the capabilities not implemented in the same
report, so the entry is omitted exactly for such a run. Keys are generated in-process for each test;
only public keys and signed documents are written.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from bundle_builder import FIXTURES, Bundle, jcs, sha

from loquitur.verify import cli
from loquitur.verify.runner import verify_path

ROOT_CAPABILITY = "trust_registry_root_signature_verification"

cryptography = pytest.importorskip("cryptography", reason="signing the authorization material needs cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils  # noqa: E402

_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _sign(key, message: bytes) -> str:
    r, s = asym_utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, "big") + min(s, _ORDER - s).to_bytes(32, "big")).hex()


def _public(key) -> str:
    return (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    )


@pytest.fixture
def authorization_files(tmp_path: Path) -> dict[str, Path]:
    from loquitur.verify.signing_envelope import signing_message_bytes
    from loquitur.verify.trust_root import trust_registry_signing_bytes

    issuer, root_key = ec.generate_private_key(ec.SECP256K1()), ec.generate_private_key(ec.SECP256K1())
    bundle = Bundle().seal()
    entry = json.loads((FIXTURES / "authorization_valid_registry_entry.json").read_text(encoding="utf-8"))
    entry["manifest_hash"] = "sha256:" + bundle.manifest_digest()
    entry["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))
    entry["signature"]["signature"] = _sign(issuer, signing_message_bytes(entry))
    trust = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    trust["entries"][0]["public_key_hex"] = _public(issuer)
    trust.pop("signature", None)
    trust["signature"] = {
        "algorithm": "secp256k1_ecdsa_sha256",
        "key_id": "root-1",
        "signature": _sign(root_key, trust_registry_signing_bytes(trust)),
    }
    roots = {
        "object_type": "trust_root_document",
        "schema_version": "v1",
        "roots": [
            {
                "key_id": "root-1",
                "key_type": "secp256k1",
                "public_key_hex": _public(root_key),
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
            }
        ],
    }
    paths = {
        "bundle": bundle.write(tmp_path / "bundle"),
        "entry": tmp_path / "entry.json",
        "trust": tmp_path / "trust.json",
        "roots": tmp_path / "roots.json",
    }
    paths["entry"].write_text(json.dumps(entry), encoding="utf-8")
    paths["trust"].write_text(json.dumps(trust), encoding="utf-8")
    paths["roots"].write_text(json.dumps(roots), encoding="utf-8")
    return paths


def _cli_report(argv: list[str]) -> dict:
    out = io.StringIO()
    with redirect_stdout(out):
        cli.main(argv)
    return json.loads(out.getvalue())


def test_a_run_whose_pinned_root_verified_the_registry_omits_the_capability(
    authorization_files: dict[str, Path],
) -> None:
    from loquitur.verify.trust_root import parse_trust_roots

    roots = parse_trust_roots(json.loads(authorization_files["roots"].read_text(encoding="utf-8")))
    report = verify_path(
        authorization_files["bundle"],
        registry_entry_path=authorization_files["entry"],
        trust_registry_path=authorization_files["trust"],
        trust_roots=roots,
        evaluation_time="2026-05-10T00:00:00Z",
    ).to_dict()
    assert report["status"] == "OFFLINE_OK"
    assert report["trust_registry"]["trust_registry_root_signature_verified"] is True
    assert ROOT_CAPABILITY not in report["outcome"]["not_implemented_capabilities"]
    assert len(report["outcome"]["not_implemented_capabilities"]) == 5

    argv = [str(authorization_files["bundle"]), "--json", "--registry-entry", str(authorization_files["entry"])]
    argv += ["--trust-registry", str(authorization_files["trust"]), "--trust-root", str(authorization_files["roots"])]
    argv += ["--evaluation-time", "2026-05-10T00:00:00Z"]
    assert _cli_report(argv)["outcome"] == report["outcome"]

    # Every other run lists it: authorization with no pinned root, and structure and link.
    unpinned = verify_path(
        authorization_files["bundle"],
        registry_entry_path=authorization_files["entry"],
        trust_registry_path=authorization_files["trust"],
    ).to_dict()
    assert unpinned["status"] == "OFFLINE_REVIEW"
    assert ROOT_CAPABILITY in unpinned["outcome"]["not_implemented_capabilities"]
    for kwargs in ({}, {"registry_entry_path": authorization_files["entry"]}):
        below = verify_path(authorization_files["bundle"], **kwargs).to_dict()
        assert ROOT_CAPABILITY in below["outcome"]["not_implemented_capabilities"]
        assert len(below["outcome"]["not_implemented_capabilities"]) == 6
