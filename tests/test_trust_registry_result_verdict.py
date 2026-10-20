"""The trust-registry result's headline folds in root authentication and the evaluation time.

trust-root.md section 2: a verifier with no pinned trust root MUST NOT return PASS for a registry
entry verified against a trust registry; section 6: a root that fails to authenticate the registry
changes the verdict, not merely a note. trust-registry-authorization.md section 2: without an
evaluation time authorization is not established. The exported result of
``verify_registry_entry_trust`` and the report's ``trust_registry`` object once derived
``verdict``, ``offline_status`` and ``trust_registry_verified`` from authorization alone, so a
registry altered after the root signed it, signed by an unknown or revoked root, or authenticated
by no root at all read PASS, OFFLINE_OK and verified. ``authorization_holds`` says that authorization
held, and nothing more; the result has no ``ok``, which a host reading it alone would take for the
verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE, EVALUATION_TIME, IssuerKey, authorization_material, write_json

from loquitur.verify import verify_registry_entry_trust
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import TrustRootKey, trust_registry_signing_bytes

ROOT_ID = "root-a"


def _root_signed(registry: dict[str, Any], root: IssuerKey, key_id: str = ROOT_ID) -> dict[str, Any]:
    unsigned = {k: v for k, v in registry.items() if k != "signature"}
    signature = root.sign_digest(hashlib.sha256(trust_registry_signing_bytes(unsigned)).digest())
    return {**unsigned, "signature": {"algorithm": "secp256k1_ecdsa_sha256", "key_id": key_id, "signature": signature}}


def _pin(root: IssuerKey, status: str = "active") -> tuple[TrustRootKey, ...]:
    return (
        TrustRootKey(
            ROOT_ID,
            root.public_key_hex,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
            status=status,
            key_type="secp256k1",
        ),
    )


@pytest.fixture(scope="module")
def chain() -> dict[str, Any]:
    issuer, root, stranger = IssuerKey(), IssuerKey(), IssuerKey()
    entry, registry = authorization_material(issuer)
    signed = _root_signed(registry, root)
    altered = json.loads(json.dumps(signed))
    altered["entries"][0]["allowed_asset_types"].append("equity")
    return {
        "entry": entry,
        "signed": signed,
        "altered": altered,
        "by_stranger": _root_signed(registry, stranger),
        "root": root,
    }


def _headline(result: Any) -> tuple:
    return (
        result.authorization_holds,
        result.verdict,
        result.offline_status,
        result.trust_registry_verified,
        result.root_signature_status,
    )


CASES = {
    # case: (registry, root status or None for no roots, evaluation time given) -> headline
    "root-authenticated": (
        ("signed", "active", True),
        (True, "PASS", "OFFLINE_OK", True, "ROOT_SIGNATURE_VALID"),
    ),
    "root-authenticated-without-evaluation-time": (
        ("signed", "active", False),
        (True, "REVIEW", "OFFLINE_REVIEW", False, "ROOT_SIGNATURE_VALID"),
    ),
    "pinned-root-revoked": (
        ("signed", "revoked", True),
        (True, "FAIL", "OFFLINE_FAIL", False, "ROOT_KEY_REVOKED"),
    ),
    "altered-after-root-signed": (
        ("altered", "active", True),
        (True, "FAIL", "OFFLINE_FAIL", False, "ROOT_SIGNATURE_INVALID"),
    ),
    "signed-by-a-key-not-pinned": (
        ("by_stranger", "active", True),
        (True, "FAIL", "OFFLINE_FAIL", False, "ROOT_SIGNATURE_INVALID"),
    ),
    "no-roots": (
        ("signed", None, True),
        (True, "REVIEW", "OFFLINE_REVIEW", False, "NO_PINNED_TRUST_ROOT"),
    ),
    "no-roots-no-evaluation-time-altered": (
        ("altered", None, False),
        (True, "REVIEW", "OFFLINE_REVIEW", False, "NO_PINNED_TRUST_ROOT"),
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_the_library_result(tmp_path: Path, chain: dict[str, Any], case: str) -> None:
    (which, root_status, timed), expected = CASES[case]
    result = verify_registry_entry_trust(
        chain["entry"],
        trust_registry_path=write_json(tmp_path / "trust_registry.json", chain[which]),
        trust_roots=() if root_status is None else _pin(chain["root"], root_status),
        evaluation_time=EVALUATION_TIME if timed else None,
    )
    assert _headline(result) == expected
    # No member a host could read alone as "verified" while the verdict says otherwise.
    assert not hasattr(result, "ok")


def test_the_result_type_has_no_ok_member() -> None:
    """``ok`` once aliased authorization alone and read True for a registry no root authenticated."""
    from loquitur.verify.trust_registry import TrustRegistryVerificationResult

    assert not hasattr(TrustRegistryVerificationResult, "ok")
    result = TrustRegistryVerificationResult(
        trust_registry=None, trust_registry_path=None, evaluation_time=None, checks=()
    )
    with pytest.raises(AttributeError):
        result.ok  # noqa: B018


def test_an_unknown_root_key_fails(tmp_path: Path, chain: dict[str, Any]) -> None:
    relabeled = _root_signed(
        {k: v for k, v in chain["signed"].items() if k != "signature"}, chain["root"], key_id="root-b"
    )
    result = verify_registry_entry_trust(
        chain["entry"],
        trust_registry_path=write_json(tmp_path / "trust_registry.json", relabeled),
        trust_roots=_pin(chain["root"]),
        evaluation_time=EVALUATION_TIME,
    )
    assert _headline(result) == (True, "FAIL", "OFFLINE_FAIL", False, "UNKNOWN_ROOT_KEY")


def test_the_report_object_and_the_registry_block(tmp_path: Path, chain: dict[str, Any]) -> None:
    def report(which: str) -> dict[str, Any]:
        return verify_path(
            BUNDLE,
            registry_entry_path=write_json(tmp_path / which / "entry.json", chain["entry"]),
            trust_registry_path=write_json(tmp_path / which / "trust_registry.json", chain[which]),
            trust_roots=_pin(chain["root"]),
            evaluation_time=EVALUATION_TIME,
        ).to_dict()

    def block(payload: dict[str, Any]) -> tuple:
        trust = payload["trust_registry"]
        return (
            payload["status"],
            payload["verdict"],
            payload["exit_code"],
            payload["registry"]["status"],
            trust["status"],
            trust["verdict"],
            payload["checks"]["trust_registry"],
            trust["trust_registry_verified"],
            trust["trust_registry_root_signature_status"],
        )

    assert block(report("signed")) == (
        "OFFLINE_OK",
        "PASS",
        0,
        "TRUST_REGISTRY_VERIFIED",
        "OFFLINE_OK",
        "PASS",
        True,
        True,
        "ROOT_SIGNATURE_VALID",
    )
    # The headline was already FAIL; the restating block and the registry status now agree with it.
    assert block(report("altered")) == (
        "OFFLINE_FAIL",
        "FAIL",
        1,
        "TRUST_REGISTRY_FAILED",
        "OFFLINE_FAIL",
        "FAIL",
        True,
        False,
        "ROOT_SIGNATURE_INVALID",
    )


# registry.status, an informative member, says what the trust_registry verdict says: VERIFIED
# only for a PASS, FAILED only for a FAIL, and for a REVIEW either that no root authenticated the
# registry or that authorization was not established (no evaluation time, or a window that does
# not hold it).
REGISTRY_STATUS_FOR_VERDICT = {
    "PASS": {"TRUST_REGISTRY_VERIFIED"},
    "FAIL": {"TRUST_REGISTRY_FAILED"},
    "REVIEW": {"TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED", "TRUST_REGISTRY_AUTHORIZATION_NOT_ESTABLISHED"},
}

REGISTRY_BLOCK_CASES = {
    # case: (registry, root status or None for no roots, evaluation time) -> registry.status
    "root-authenticated": (("signed", "active", EVALUATION_TIME), "TRUST_REGISTRY_VERIFIED"),
    "root-authenticated-without-evaluation-time": (
        ("signed", "active", None),
        "TRUST_REGISTRY_AUTHORIZATION_NOT_ESTABLISHED",
    ),
    "registry-expired-at-the-evaluation-time": (
        ("signed", "active", "2030-01-01T00:00:00Z"),
        "TRUST_REGISTRY_AUTHORIZATION_NOT_ESTABLISHED",
    ),
    "pinned-root-revoked": (("signed", "revoked", EVALUATION_TIME), "TRUST_REGISTRY_FAILED"),
    "altered-after-root-signed": (("altered", "active", EVALUATION_TIME), "TRUST_REGISTRY_FAILED"),
    "no-roots": (("signed", None, EVALUATION_TIME), "TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED"),
    "no-roots-no-evaluation-time": (("signed", None, None), "TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED"),
}


@pytest.mark.parametrize("case", REGISTRY_BLOCK_CASES)
def test_the_registry_status_follows_the_trust_registry_verdict(
    tmp_path: Path, chain: dict[str, Any], case: str
) -> None:
    (which, root_status, evaluation_time), expected = REGISTRY_BLOCK_CASES[case]
    payload = verify_path(
        BUNDLE,
        registry_entry_path=write_json(tmp_path / "entry.json", chain["entry"]),
        trust_registry_path=write_json(tmp_path / "trust_registry.json", chain[which]),
        trust_roots=() if root_status is None else _pin(chain["root"], root_status),
        evaluation_time=evaluation_time,
    ).to_dict()
    assert payload["registry"]["status"] == expected
    assert expected in REGISTRY_STATUS_FOR_VERDICT[payload["trust_registry"]["verdict"]]


def test_the_threat_model_names_every_registry_status_the_trust_registry_verdict_gives() -> None:
    """threat-model.md section 4 lists the registry.status values a trust-registry run reports.

    It once named three, and this verifier also reports TRUST_REGISTRY_AUTHORIZATION_NOT_ESTABLISHED
    (no evaluation time, or a window that does not hold it). The list is the set the cases above
    observe, no more and no fewer.
    """
    from spec_tables import document, sections

    adversaries = next(body for title, body in sections(document("threat-model.md")).items() if title.startswith("4. "))
    bullet = next(item for item in re.split(r"\n(?=- )", adversaries) if item.startswith("- `registry.status`"))
    named = set(re.findall(r"`(TRUST_REGISTRY_[A-Z_]+)`", bullet))
    observed = {expected for _, expected in REGISTRY_BLOCK_CASES.values()}
    assert observed == set().union(*REGISTRY_STATUS_FOR_VERDICT.values())
    assert named == observed, f"threat-model.md section 4 names {sorted(named)}, the runs give {sorted(observed)}"
