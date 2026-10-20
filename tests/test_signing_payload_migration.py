"""The signing payload: one version defined, every other answered by the version gate.

This version of the protocol defines one signing payload, `registry_entry_signing_payload_v2`
with `payload_version` 2, and no earlier one (signing-envelope-v2.md). A signature object of
another well-formed payload pair fires the version gate of its object, `signing_payload`, and
the run is UNSUPPORTED_VERSION, exit 4 (document-contracts.md section 1a, gate 7). A signature
object without the two payload members is not a payload of any version: it breaks the entry's
contract. No caller can ask for an earlier payload to be read.
"""

from __future__ import annotations

import copy
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from bundle_builder import Bundle, jcs, sha

from loquitur.verify.runner import verify_path
from loquitur.verify.trust_registry import _verify_signature, verify_registry_entry_trust

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VECTORS = Path(__file__).resolve().parent / "vectors"
MIGRATION = json.loads((VECTORS / "signature_payload_version.json").read_text(encoding="utf-8"))
SIGNATURE_V2 = json.loads((VECTORS / "signature_v2.json").read_text(encoding="utf-8"))


def _migration_trust_registry(tmp_path: Path) -> Path:
    trust = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    trust["effective_at"] = "2026-04-28T00:00:00Z"
    trust["issued_at"] = "2026-04-28T00:00:00Z"
    trust["entries"][0]["effective_from"] = "2026-04-28T00:00:00Z"
    # The vectors are signed by the key they publish, not by the local fixtures' key.
    trust["entries"][0]["public_key_hex"] = SIGNATURE_V2["public_key_hex"]
    path = tmp_path / "migration-trust-registry.json"
    path.write_text(json.dumps(trust), encoding="utf-8")
    return path


def _bundle_run(tmp_path: Path, signature: dict) -> dict:
    """A link run over a sealed bundle whose entry carries ``signature``."""
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    entry = json.loads((FIXTURES / "link_valid_registry_entry.json").read_text(encoding="utf-8"))
    entry["manifest_hash"] = "sha256:" + bundle.manifest_digest()
    entry["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))
    entry["signature"] = signature
    path = tmp_path / "entry.json"
    path.write_text(json.dumps(entry), encoding="utf-8")
    return verify_path(root, registry_entry_path=path).to_dict()


def test_the_vector_has_the_shape_of_this_version() -> None:
    assert MIGRATION["automatic_fallback"] is False
    assert not [name for name in MIGRATION if name.startswith("legacy") or name.endswith("_explicit_status")]
    signature = MIGRATION["unknown_payload_entry"]["signature"]
    assert MIGRATION["unknown_payload_expected_error"] == {
        "code": "unsupported_version",
        "object": "signing_payload",
        "version": f"{signature['payload_id']}/{signature['payload_version']}",
    }
    assert "payload_id" not in MIGRATION["v2_metadata_stripped_entry"]["signature"]


def test_v2_is_accepted(tmp_path: Path) -> None:
    entry = SIGNATURE_V2["signed_entry"]
    result = verify_registry_entry_trust(
        entry, trust_registry_path=_migration_trust_registry(tmp_path), evaluation_time="2026-05-10T00:00:00Z"
    )
    assert result.authorization_holds is True
    assert result.signature_status == SIGNATURE_V2["expected"]["valid_status"]
    assert result.authorization_status == "AUTHORIZED_ACTIVE_KEY"
    assert (result.signing_payload_id, result.signing_payload_version) == ("registry_entry_signing_payload_v2", 2)


@pytest.mark.parametrize(
    ("payload_id", "payload_version"),
    [
        ("registry_entry_signing_payload_v999", 999),
        ("registry_entry_signing_payload_v3", 3),
        ("registry_entry_signing_payload_v2", 3),
        ("registry_entry_signing_payload_v1", 1),
    ],
    ids=["vector", "v3-3", "v2-3", "v1-1"],
)
def test_another_well_formed_payload_is_an_unsupported_version(
    tmp_path: Path, payload_id: str, payload_version: int
) -> None:
    signature = dict(
        MIGRATION["unknown_payload_entry"]["signature"], payload_id=payload_id, payload_version=payload_version
    )
    report = _bundle_run(tmp_path, signature)
    assert (report["status"], report["verdict"], report["exit_code"]) == ("UNSUPPORTED_VERSION", None, 4)
    assert [{k: e[k] for k in ("code", "object", "version")} for e in report["errors"]] == [
        {"code": "unsupported_version", "object": "signing_payload", "version": f"{payload_id}/{payload_version}"}
    ]
    assert (report["checks_established"], report["review_reasons"]) == ([], [])


def test_the_vector_payload_is_the_declared_error(tmp_path: Path) -> None:
    report = _bundle_run(tmp_path, copy.deepcopy(MIGRATION["unknown_payload_entry"]["signature"]))
    error = report["errors"][0]
    assert {k: error[k] for k in ("code", "object", "version")} == MIGRATION["unknown_payload_expected_error"]


def test_payload_version_2_0_is_the_supported_integer(tmp_path: Path) -> None:
    # The canonical numeric model reads 2.0 as the integer 2: the pair is the supported one,
    # and the run reaches the entry's contract and link rather than the gate.
    signature = dict(SIGNATURE_V2["signed_entry"]["signature"], payload_version=2.0)
    report = _bundle_run(tmp_path, signature)
    assert report["status"] != "UNSUPPORTED_VERSION"
    assert "unsupported_version" not in [error["code"] for error in report["errors"]]


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.update(payload_id="registry-entry-signing-payload-v3"),
        lambda s: s.update(payload_version="3"),
        lambda s: s.update(payload_version=0),
        lambda s: s.update(payload_version=1_000_000_000),
    ],
    ids=["id-not-well-formed", "version-a-string", "version-0", "version-too-long"],
)
def test_a_malformed_payload_pair_is_a_contract_violation_not_a_version(tmp_path: Path, change) -> None:
    signature = dict(SIGNATURE_V2["signed_entry"]["signature"])
    change(signature)
    report = _bundle_run(tmp_path, signature)
    assert (report["status"], [error["code"] for error in report["errors"]]) == (
        "OFFLINE_FAIL",
        ["registry_entry_contract_violation"],
    )


def test_v2_metadata_stripped_is_the_declared_contract_violation(tmp_path: Path) -> None:
    report = _bundle_run(tmp_path, copy.deepcopy(MIGRATION["v2_metadata_stripped_entry"]["signature"]))
    assert [error["code"] for error in report["errors"]] == [MIGRATION["v2_metadata_stripped_expected_error"]]
    standalone = verify_registry_entry_trust(
        MIGRATION["v2_metadata_stripped_entry"], trust_registry_path=_migration_trust_registry(tmp_path)
    )
    assert (standalone.authorization_holds, standalone.authorization_status) == (False, "INVALID_REGISTRY_ENTRY")


def test_the_signature_step_alone_answers_an_unknown_payload_unsupported(tmp_path: Path) -> None:
    # trust-registry-authorization.md section 6 row 15: the standalone signature step, which no
    # version gate precedes, answers UNSUPPORTED_SIGNING_PAYLOAD.
    result = verify_registry_entry_trust(
        MIGRATION["unknown_payload_entry"],
        trust_registry_path=_migration_trust_registry(tmp_path),
        evaluation_time="2026-05-10T00:00:00Z",
    )
    assert result.authorization_holds is False
    assert result.signature_status != "VALID_SIGNATURE"
    assert (result.authorization_status, result.signature_status) in {
        ("AUTHORIZED_ACTIVE_KEY", "UNSUPPORTED_SIGNING_PAYLOAD"),
        ("INVALID_REGISTRY_ENTRY", None),
    }


def test_no_caller_can_ask_for_an_earlier_payload() -> None:
    """No parameter of the library and no flag of the command line names an earlier payload."""
    for func in (verify_registry_entry_trust, verify_path, _verify_signature):
        names = {name.lower() for name in inspect.signature(func).parameters}
        assert not [name for name in names if "legacy" in name or "v1" in name], (func.__name__, sorted(names))
    help_text = subprocess.run(
        [sys.executable, "-m", "loquitur.verify.cli", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=True,
    ).stdout
    assert "legacy" not in help_text.lower(), "the command line offers a legacy option"


def test_the_tampered_v2_entry_matches_its_declared_status(tmp_path: Path) -> None:
    """The vector's tampered entry reaches the signature step and is refused there."""
    result = verify_registry_entry_trust(
        SIGNATURE_V2["tampered_entry"],
        trust_registry_path=_migration_trust_registry(tmp_path),
        evaluation_time="2026-05-10T00:00:00Z",
    )
    assert (result.authorization_status, result.signature_status) == (
        "AUTHORIZED_ACTIVE_KEY",
        SIGNATURE_V2["expected"]["tampered_status"],
    )
