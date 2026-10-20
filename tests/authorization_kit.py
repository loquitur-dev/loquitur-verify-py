"""Authorization material for a test: a registry entry signed with an issuer key made for this run.

The key is generated in memory when a test asks for it and never written or printed: only
its public half reaches the trust registry. The entry and the trust registry start from the
authorization fixtures, bound to ``tests/fixtures/link_valid_bundle``, so a test changes exactly the
fields it is about and re-signs the entry after the change. Signing uses ``cryptography``
and the protocol's signing-message bytes; low S is enforced, as the protocol requires.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from loquitur.verify.runner import verify_path
from loquitur.verify.signing_envelope import signing_message_bytes

cryptography = pytest.importorskip("cryptography", reason="signing authorization material needs cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE = FIXTURES / "link_valid_bundle"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

CHECKS = ("registry_link", "trust_registry", "registry_signature")


class IssuerKey:
    """An ephemeral secp256k1 issuer key. The private half never leaves this object."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256K1())
        self.public_key_hex = (
            self._key.public_key()
            .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            .hex()
        )

    def sign_digest(self, digest: bytes) -> str:
        der = self._key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        r, s = asym_utils.decode_dss_signature(der)
        s = min(s, SECP256K1_ORDER - s)
        return format(r, "064x") + format(s, "064x")

    def sign_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Sign ``entry`` in place over the v2 signing message and return it."""
        entry["signature"]["signature"] = self.sign_digest(hashlib.sha256(signing_message_bytes(entry)).digest())
        return entry


def public_key_hex_for_scalar(scalar: int) -> str:
    """The uncompressed SEC1 public key of a private scalar a test made for the run."""
    return (
        ec.derive_private_key(scalar, ec.SECP256K1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        .hex()
    )


def sign_digest_with_scalar(digest: bytes, scalar: int) -> tuple[int, int]:
    """Sign a 32-byte digest with a private scalar a test made for the run: RFC 6979, low S.

    Deterministic, so a test that draws its scalars from a seeded generator reproduces its
    signatures on every run.
    """
    key = ec.derive_private_key(scalar, ec.SECP256K1())
    der = key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    r, s = asym_utils.decode_dss_signature(der)
    return r, min(s, SECP256K1_ORDER - s)


# An instant inside every window of the fixture trust registry (2026-04-29T12:00:00Z to
# 2026-05-29T12:00:00Z): the time an operator of these tests judges authorization at.
EVALUATION_TIME = "2026-05-10T00:00:00Z"


def fixture_entry() -> dict[str, Any]:
    return json.loads((FIXTURES / "authorization_valid_registry_entry.json").read_text(encoding="utf-8"))


def fixture_trust_registry() -> dict[str, Any]:
    return json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))


def authorization_material(
    key: IssuerKey,
    *,
    entry: Callable[[dict[str, Any]], Any] | None = None,
    trust: Callable[[dict[str, Any]], Any] | None = None,
    resign: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The fixture entry and trust registry for ``key``, each changed by its callable.

    ``entry`` runs before signing, so the signature covers the change; pass ``resign=False``
    to keep the signature of the unchanged entry. ``trust`` runs after the key's public half
    is installed in the first trust-registry entry.
    """
    document = fixture_entry()
    if entry is not None:
        entry(document)
    if resign and isinstance(document.get("signature"), dict):
        key.sign_entry(document)
    registry = fixture_trust_registry()
    registry["entries"][0]["public_key_hex"] = key.public_key_hex
    if trust is not None:
        trust(registry)
    return document, registry


def write_json(path: Path, value: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def run_authorization(tmp_path: Path, entry: dict[str, Any], registry: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """verify_path over the link fixture bundle with ``entry`` and ``registry`` written to disk.

    The operator's evaluation time is EVALUATION_TIME unless the caller passes ``evaluation_time``
    (``None`` for a run without one, whose authorization is never established).
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    kwargs.setdefault("evaluation_time", EVALUATION_TIME)
    report = verify_path(
        BUNDLE,
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
        trust_registry_path=write_json(tmp_path / "trust_registry.json", registry),
        **kwargs,
    ).to_dict()
    return report


def outcome(report: dict[str, Any]) -> dict[str, Any]:
    """Status, verdict, exit code, the three registry checks and the authorization statuses of a report."""
    trust = report.get("trust_registry") or {}
    return {
        "status": report["status"],
        "verdict": report["verdict"],
        "exit_code": report["exit_code"],
        **{name: report["checks"][name] for name in CHECKS},
        "authorization_status": trust.get("authorization_status"),
        "signature_status": trust.get("signature_status"),
    }


def deep(value: Any) -> Any:
    return copy.deepcopy(value)
