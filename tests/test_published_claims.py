"""What this package's published files say about trust roots, held to a run.

A sentence about what the package does, corrected by hand and held by nothing, drifts from
what the package does. This module compares published sentences with a run. It verifies one
authorization bundle three times (with the root that signed the trust registry, with a
stranger's root under the same key id, and with no root at all) and requires the published
sentences to carry the outcomes those runs report. The wording
stays each file's own; the values are the run's, so a change of behavior fails here until
the sentences follow it.

Keys are generated in-process for each run; only public keys and signed documents are written.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_builder import FIXTURES, Bundle, jcs, sha
from repository import flat

from loquitur.verify.runner import verify_path

ROOT = Path(__file__).resolve().parents[1]

# Each row is a published file and the sentence in which it states an outcome of a run. The
# outcome itself is filled in from the run, never written here.
NO_ROOT_SENTENCES = [
    (
        "README.md",
        "with no root pinned it reports `{status}`, the boolean stays `{verified}`, and the run returns `{report}` rather than `{held}`",
    ),
    ("src/loquitur/verify/__init__.py", "with no root supplied the reported outcome is ``{status}``"),
]

# What those files say the package does, held only because a run of it does exactly that.
AFFIRMATIONS = [
    ("README.md", "root-signature verification is implemented"),
    (
        "src/loquitur/verify/__init__.py",
        "trust-registry root-signature verification against roots supplied by the caller",
    ),
]

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


def _document(key) -> dict:
    return {
        "object_type": "trust_root_document",
        "schema_version": "v1",
        "roots": [
            {
                "key_id": "root-1",
                "key_type": "secp256k1",
                "public_key_hex": _public(key),
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
            }
        ],
    }


@pytest.fixture
def authorization_files(tmp_path: Path) -> dict[str, Path]:
    """A sealed bundle, its entry signed by an issuer key, and a trust registry signed by a root."""
    from loquitur.verify.signing_envelope import signing_message_bytes
    from loquitur.verify.trust_root import trust_registry_signing_bytes

    issuer, root_key, stranger_key = (ec.generate_private_key(ec.SECP256K1()) for _ in range(3))
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
    paths = {
        "bundle": bundle.write(tmp_path / "bundle"),
        "entry": tmp_path / "entry.json",
        "trust": tmp_path / "trust.json",
        "roots": tmp_path / "roots.json",
        "stranger": tmp_path / "stranger.json",
    }
    paths["entry"].write_text(json.dumps(entry), encoding="utf-8")
    paths["trust"].write_text(json.dumps(trust), encoding="utf-8")
    paths["roots"].write_text(json.dumps(_document(root_key)), encoding="utf-8")
    paths["stranger"].write_text(json.dumps(_document(stranger_key)), encoding="utf-8")
    return paths


def test_the_published_files_state_the_root_outcomes_a_run_reports(authorization_files: dict[str, Path]) -> None:
    from loquitur.verify.trust_root import parse_trust_roots

    def run(roots_at: Path | None) -> dict:
        # No root at all is the argument left out, which is what a host that pins none does.
        roots = (
            {}
            if roots_at is None
            else {"trust_roots": parse_trust_roots(json.loads(roots_at.read_text(encoding="utf-8")))}
        )
        return verify_path(
            authorization_files["bundle"],
            registry_entry_path=authorization_files["entry"],
            trust_registry_path=authorization_files["trust"],
            evaluation_time="2026-05-10T00:00:00Z",
            **roots,
        ).to_dict()

    held, stranger, none = run(authorization_files["roots"]), run(authorization_files["stranger"]), run(None)
    statuses = [report["trust_registry"]["trust_registry_root_signature_status"] for report in (held, stranger, none)]
    assert len(set(statuses)) == 3, f"the three runs do not part, so the sentences below hold over anything: {statuses}"
    assert len({report["status"] for report in (held, stranger, none)}) == 3

    verified = held["trust_registry"]["trust_registry_root_signature_verified"]
    assert verified is True, "this run authenticates the trust registry against the root it was given"
    for relative, phrase in AFFIRMATIONS:
        assert phrase in flat(relative), f"{relative} does not say the package does what a run of it does: {phrase!r}"

    for relative, sentence in NO_ROOT_SENTENCES:
        written = sentence.format(
            status=statuses[2],
            verified=str(none["trust_registry"]["trust_registry_root_signature_verified"]).lower(),
            report=none["status"],
            held=held["status"],
        )
        assert written in flat(relative), (
            f"{relative} does not state what a run without a pinned root reports: {written}"
        )
