"""Every verdict-like member of the trust-registry result is the verdict the full run reports.

The cryptographic review found ``verify_registry_entry_trust`` saying PASS and the report's
``trust_registry`` object saying verified for a trust registry no pinned root authenticated, while
the headline was right: the result derived its verdict from authorization alone, the headline from
authorization and the root. Now ``TrustRegistryVerificationResult.verdict`` is the one place the
verdict is decided; ``failed``, ``root_failed``, ``offline_status`` and ``trust_registry_verified``
read it, and so does the run's headline (runner.py).

These tests hold that on behaviour, over the trust-registry cases of the reviews: for the same
entry, trust registry, roots and evaluation time beside an intact bundle, the library's verdict is
the run's verdict, and every member that restates it (trust_registry.status, .verdict,
.trust_registry_verified, registry.status, the authorization check) says the same. Keys are made for
the run and never written or printed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE, EVALUATION_TIME, IssuerKey, authorization_material, write_json

from loquitur.verify import verify_registry_entry_trust
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import TrustRootKey, trust_registry_signing_bytes

OFFLINE_STATUS = {"PASS": "OFFLINE_OK", "REVIEW": "OFFLINE_REVIEW", "FAIL": "OFFLINE_FAIL"}
REGISTRY_STATUS = {
    "PASS": {"TRUST_REGISTRY_VERIFIED"},
    "FAIL": {"TRUST_REGISTRY_FAILED"},
    "REVIEW": {"TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED", "TRUST_REGISTRY_AUTHORIZATION_NOT_ESTABLISHED"},
}


def _root_signed(registry: dict[str, Any], root: IssuerKey, key_id: str = "root-a") -> dict[str, Any]:
    unsigned = {k: v for k, v in registry.items() if k != "signature"}
    signature = root.sign_digest(hashlib.sha256(trust_registry_signing_bytes(unsigned)).digest())
    return {**unsigned, "signature": {"algorithm": "secp256k1_ecdsa_sha256", "key_id": key_id, "signature": signature}}


def _root(public_key_hex: str, key_id: str = "root-a", status: str = "active") -> TrustRootKey:
    return TrustRootKey(
        key_id, public_key_hex, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", status=status, key_type="secp256k1"
    )


def _wide(registry: dict[str, Any]) -> dict[str, Any]:
    """The registry and its key valid from 2025 to 2028, so a root window outside the time is reached."""
    widened = json.loads(json.dumps(registry))
    widened.update(
        issued_at="2025-01-01T00:00:00Z", effective_at="2025-01-01T00:00:00Z", expires_at="2028-01-01T00:00:00Z"
    )
    widened["entries"][0].update(effective_from="2025-01-01T00:00:00Z", expires_at="2028-01-01T00:00:00Z")
    return widened


@pytest.fixture(scope="module")
def cases() -> dict[str, tuple[dict[str, Any], dict[str, Any], tuple[TrustRootKey, ...], str | None]]:
    issuer, root, stranger = IssuerKey(), IssuerKey(), IssuerKey()
    entry, registry = authorization_material(issuer)
    signed = _root_signed(registry, root)
    altered = json.loads(json.dumps(signed))
    altered["entries"][0]["allowed_asset_types"].append("equity")
    wide = _root_signed(_wide(registry), root)
    pinned = (_root(root.public_key_hex),)
    revoked_issuer_entry, revoked_issuer_registry = authorization_material(
        issuer,
        trust=lambda r: r["entries"][0].update(
            status="revoked", revoked_at="2026-05-01T00:00:00Z", revocation_reason="key compromised"
        ),
    )
    tampered = dict(entry, policy_version="1.0.1")
    return {
        "root-authenticated": (entry, signed, pinned, EVALUATION_TIME),
        "root-authenticated-no-evaluation-time": (entry, signed, pinned, None),
        "no-root": (entry, signed, (), EVALUATION_TIME),
        "no-root-no-evaluation-time": (entry, signed, (), None),
        "no-root-altered": (entry, altered, (), EVALUATION_TIME),
        "unknown-root-key-id": (entry, _root_signed(registry, root, "root-b"), pinned, EVALUATION_TIME),
        "signed-by-a-key-not-pinned": (entry, _root_signed(registry, stranger), pinned, EVALUATION_TIME),
        "pinned-root-revoked": (entry, signed, (_root(root.public_key_hex, status="revoked"),), EVALUATION_TIME),
        "pinned-root-revoked-no-evaluation-time": (
            entry,
            signed,
            (_root(root.public_key_hex, status="revoked"),),
            None,
        ),
        "altered-after-root-signed": (entry, altered, pinned, EVALUATION_TIME),
        "altered-after-root-signed-no-evaluation-time": (entry, altered, pinned, None),
        "root-window-not-yet-valid": (entry, wide, pinned, "2025-12-31T23:59:59Z"),
        "root-window-expired": (entry, wide, pinned, "2027-01-01T00:00:01Z"),
        "registry-window-expired": (entry, signed, pinned, "2026-06-01T00:00:00Z"),
        "root-key-under-two-labels-revoked-label": (
            entry,
            _root_signed(registry, root, "root-2025"),
            (_root(root.public_key_hex, "root-2025", "revoked"), _root(root.public_key_hex, "root-2026")),
            EVALUATION_TIME,
        ),
        "issuer-key-revoked": (
            revoked_issuer_entry,
            _root_signed(revoked_issuer_registry, root),
            pinned,
            EVALUATION_TIME,
        ),
        "entry-altered-after-signing": (tampered, signed, pinned, EVALUATION_TIME),
    }


CASE_NAMES = [
    "root-authenticated",
    "root-authenticated-no-evaluation-time",
    "no-root",
    "no-root-no-evaluation-time",
    "no-root-altered",
    "unknown-root-key-id",
    "signed-by-a-key-not-pinned",
    "pinned-root-revoked",
    "pinned-root-revoked-no-evaluation-time",
    "altered-after-root-signed",
    "altered-after-root-signed-no-evaluation-time",
    "root-window-not-yet-valid",
    "root-window-expired",
    "registry-window-expired",
    "root-key-under-two-labels-revoked-label",
    "issuer-key-revoked",
    "entry-altered-after-signing",
]


def test_the_case_list_names_every_case(cases: dict[str, Any]) -> None:
    assert sorted(cases) == sorted(CASE_NAMES)


@pytest.mark.parametrize("name", CASE_NAMES)
def test_the_library_verdict_is_the_run_verdict(tmp_path: Path, cases: dict[str, Any], name: str) -> None:
    entry, registry, roots, evaluation_time = cases[name]
    registry_path = write_json(tmp_path / "trust_registry.json", registry)
    result = verify_registry_entry_trust(
        entry, trust_registry_path=registry_path, trust_roots=roots, evaluation_time=evaluation_time
    )
    report = verify_path(
        BUNDLE,
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
        trust_registry_path=registry_path,
        trust_roots=roots,
        evaluation_time=evaluation_time,
    ).to_dict()
    verdict = result.verdict
    trust = report["trust_registry"]

    # The bundle and the link hold in every case, so the trust registry alone decides the run.
    assert report["checks"]["registry_link"] is True
    assert (report["verdict"], report["status"]) == (verdict, OFFLINE_STATUS[verdict])
    # Every member of the result that restates the verdict.
    assert result.offline_status == OFFLINE_STATUS[verdict]
    assert result.trust_registry_verified is (verdict == "PASS")
    assert result.failed is (verdict == "FAIL" and not result.authorization_holds)
    assert result.root_failed is (verdict == "FAIL" and result.authorization_holds)
    # Every member of the report that restates it.
    assert (trust["verdict"], trust["status"], trust["trust_registry_verified"]) == (
        verdict,
        OFFLINE_STATUS[verdict],
        verdict == "PASS",
    )
    assert report["registry"]["status"] in REGISTRY_STATUS[verdict]
    assert ("authorization" in report["checks_established"]) is (verdict == "PASS")
    # The statuses the verdict is read from are the run's.
    assert (
        trust["authorization_status"],
        trust["signature_status"],
        trust["trust_registry_root_signature_status"],
    ) == (
        result.authorization_status,
        result.signature_status,
        result.root_signature_status,
    )


def test_the_cases_reach_every_verdict(tmp_path: Path, cases: dict[str, Any]) -> None:
    verdicts = set()
    for name, (entry, registry, roots, evaluation_time) in cases.items():
        verdicts.add(
            verify_registry_entry_trust(
                entry,
                trust_registry_path=write_json(tmp_path / name / "trust_registry.json", registry),
                trust_roots=roots,
                evaluation_time=evaluation_time,
            ).verdict
        )
    assert verdicts == {"PASS", "REVIEW", "FAIL"}
