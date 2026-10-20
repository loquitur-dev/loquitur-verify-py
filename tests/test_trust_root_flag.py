"""``--trust-root`` anchors authorization in roots the operator pins.

Without a pinned root, a party that creates its own trust registry, writes an entry for an
issuer it invented, and signs both satisfies every authorization check: the authorization check proves that *some* key
signed the entry and that the registry *you were handed* vouches for it, which whoever
handed you both can satisfy trivially.

``trust_root.py`` verifies a registry against pinned roots, and ``PINNED_TRUST_ROOTS`` is
empty by design: a root is obtained out of band, from a party the operator trusts.
``--trust-root`` on the command line and ``trust_roots`` on ``verify_path`` are how roots
get in from outside.

Two properties are asserted here, and the second is the one that closes the hole:

1. Roots supplied out of band reach the check, and a registry signed by an unpinned key is
   detected.
2. When roots are supplied and the registry fails to authenticate, the VERDICT changes:
   not merely a note: the exit code and the headline are the two channels an integrator
   consumes. A caller who passes no roots gets REVIEW rather than an accusation, as
   test_omitting_roots_reviews_rather_than_passing below asserts.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from loquitur.verify.cli import main
from loquitur.verify.trust_root import trust_registry_signing_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
BUNDLE = FIXTURES / "link_valid_bundle"
ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
REGISTRY = FIXTURES / "authorization_valid_trust_registry.json"

_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

cryptography = pytest.importorskip("cryptography", reason="signing the fixtures needs cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils  # noqa: E402


def _sign_registry(key, key_id: str) -> dict:
    """Sign the fixture registry with ``key``, replacing whatever signature it carried."""
    payload = json.loads(REGISTRY.read_text(encoding="utf-8"))
    payload.pop("signature", None)
    r, s = asym_utils.decode_dss_signature(key.sign(trust_registry_signing_bytes(payload), ec.ECDSA(hashes.SHA256())))
    if s > _SECP256K1_ORDER // 2:  # low-S, as the protocol requires
        s = _SECP256K1_ORDER - s
    payload["signature"] = {
        "algorithm": "secp256k1_ecdsa_sha256",
        "key_id": key_id,
        "signature": (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex(),
    }
    return payload


def _roots_document(key, key_id: str) -> dict:
    public = (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    )
    return {
        "object_type": "trust_root_document",
        "schema_version": "v1",
        "roots": [
            {
                "key_id": key_id,
                "key_type": "secp256k1",
                "public_key_hex": public,
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
                "status": "active",
            }
        ],
    }


def _invoke(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI in-process, as the rest of this suite does."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _run(registry: Path, trust_root: Path | None = None) -> tuple[int, dict]:
    # Judged at the operator's evaluation time, inside the fixture registry's window: without one,
    # authorization is never established (evaluation_time_not_provided).
    argv = [str(BUNDLE), "--registry-entry", str(ENTRY), "--trust-registry", str(registry), "--json"]
    argv += ["--evaluation-time", "2026-05-10T00:00:00Z"]
    if trust_root is not None:
        argv += ["--trust-root", str(trust_root)]
    code, stdout, stderr = _invoke(argv)
    if code == 64:  # usage error: nothing on stdout
        return code, {"stderr": stderr}
    return code, json.loads(stdout)


@pytest.fixture(scope="module")
def material(tmp_path_factory) -> dict[str, Path]:
    directory = tmp_path_factory.mktemp("trust-root")
    pinned = ec.generate_private_key(ec.SECP256K1())
    rogue = ec.generate_private_key(ec.SECP256K1())
    paths = {
        "authentic": directory / "authentic.json",
        "rogue": directory / "rogue.json",
        "roots": directory / "roots.json",
    }
    paths["authentic"].write_text(json.dumps(_sign_registry(pinned, "root-1")), encoding="utf-8")
    paths["rogue"].write_text(json.dumps(_sign_registry(rogue, "root-1")), encoding="utf-8")
    paths["roots"].write_text(json.dumps(_roots_document(pinned, "root-1")), encoding="utf-8")
    return paths


def test_authentic_registry_passes_and_records_the_root(material) -> None:
    code, report = _run(material["authentic"], material["roots"])
    assert code == 0
    assert report["status"] == "OFFLINE_OK"
    assert "trust_registry_root_signature_verified" in report["notes"]


def test_a_registry_the_pinned_root_did_not_sign_fails_the_verdict(material) -> None:
    """The forgery a self-created registry makes. This is the whole point of the flag."""
    code, report = _run(material["rogue"], material["roots"])
    assert code == 1, "a registry signed by an unpinned key must not exit 0"
    assert report["status"] == "OFFLINE_FAIL"
    assert any(n.startswith("trust_registry_root_signature_not_verified") for n in report["notes"])
    assert "trust_registry_root_signature_required_but_not_verified" in report["notes"]


def test_omitting_roots_reviews_rather_than_passing(material) -> None:
    """A caller who pins nothing gets "could not establish", not "verified".

    With nothing pinned, an authentic registry and one the caller created themselves are
    indistinguishable, so neither may return the tool's highest verdict. The specification
    says a verifier with no pinned root refuses rather than assumes.

    Refusing is not accusing. The registry here IS authentic; what is missing is any way
    for this process to know that. So the answer is REVIEW and exit 2. Exit 1 stays
    reserved for the test above, where a root was pinned and the registry failed against
    it: the only case where the tool has grounds to say no.
    """
    code, report = _run(material["authentic"])
    assert code == 2, "an unpinned root must not exit 0, and must not be accused either"
    assert report["status"] == "OFFLINE_REVIEW"
    assert report["verdict"] == "REVIEW"
    assert report["outcome"]["reason"] == "trust_registry_root_not_pinned"
    assert report["registry"]["status"] == "TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED"
    assert "trust_registry_root_signature_not_verified:no_pinned_trust_root" in report["notes"]


def test_roots_without_a_registry_are_refused(material) -> None:
    code, _, stderr = _invoke([str(BUNDLE), "--registry-entry", str(ENTRY), "--trust-root", str(material["roots"])])
    assert code == 64
    assert "--trust-root requires --trust-registry" in stderr


def test_a_malformed_roots_document_refuses_rather_than_falling_back(material, tmp_path) -> None:
    """Falling back to the empty module default would be the worst outcome available.

    An operator who supplied roots and silently got none would believe a check ran that
    did not, which is the precise failure mode this flag exists to remove.
    """
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps({"roots": [{"key_id": "x", "public_key_hex": "nothex"}]}), encoding="utf-8")
    code, report = _run(material["authentic"], broken)
    assert code == 64
    assert "--trust-root could not be read" in report["stderr"]
