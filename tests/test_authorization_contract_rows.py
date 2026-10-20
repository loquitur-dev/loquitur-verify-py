"""Rows 2 and 3 of the authorization order hold each document to its generated contract alone.

trust-registry-authorization.md section 6: a registry entry that breaks its contract stops the
evaluation at row 2 (INVALID_REGISTRY_ENTRY), a trust registry that breaks its contract at row 3
(INVALID_TRUST_REGISTRY). The contract is generated from the schema and holds the closed member
set, the types, the patterns and the enumerations, so the refusal lists each finding once, in the
contract's words, and says that the document breaks its contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from authorization_kit import EVALUATION_TIME, fixture_entry, fixture_trust_registry, write_json

from loquitur.verify.trust_registry import verify_registry_entry_trust


def _evaluate(tmp_path: Path, entry: dict, registry: dict):
    path = write_json(tmp_path / "trust_registry.json", registry)
    return verify_registry_entry_trust(entry, trust_registry_path=path, evaluation_time=EVALUATION_TIME)


def test_an_entry_with_a_member_outside_its_contract_stops_at_row_2(tmp_path: Path) -> None:
    entry = fixture_entry()
    entry["side_channel"] = "x"
    result = _evaluate(tmp_path, entry, fixture_trust_registry())
    assert result.authorization_status == "INVALID_REGISTRY_ENTRY"
    assert result.error is not None and result.error.startswith("registry_entry breaks its contract: ")
    (check,) = result.checks
    assert check.name == "registry_entry_shape" and check.ok is False
    named = [finding for finding in check.actual if "side_channel" in finding]
    assert len(named) == 1 and named[0].endswith(":additionalProperties"), check.actual


def test_a_trust_registry_of_another_object_type_stops_at_row_3(tmp_path: Path) -> None:
    registry = fixture_trust_registry()
    registry["object_type"] = "registry_entry"
    result = _evaluate(tmp_path, fixture_entry(), registry)
    assert result.authorization_status == "INVALID_TRUST_REGISTRY"
    assert result.error is not None and result.error.startswith("trust_registry breaks its contract: ")
    (check,) = result.checks
    assert check.name == "trust_registry_shape" and check.ok is False
    named = [finding for finding in check.actual if "object_type" in finding]
    assert len(named) == 1 and named[0].endswith(":const"), check.actual


def test_a_key_status_outside_the_enumeration_stops_at_row_3(tmp_path: Path) -> None:
    """No later row judges a key status the contract refuses: the evaluation never reaches the key."""
    registry = fixture_trust_registry()
    registry["entries"][0]["status"] = "retired"
    result = _evaluate(tmp_path, fixture_entry(), registry)
    assert result.authorization_status == "INVALID_TRUST_REGISTRY"
    assert [check.name for check in result.checks] == ["trust_registry_shape"]
    assert result.trust_entry_status is None


@pytest.mark.parametrize("entry", [None, [], ["registry_entry"], "registry_entry", 7, True])
def test_an_entry_that_is_not_an_object_stops_at_row_2(tmp_path: Path, entry: object) -> None:
    """A value that is not an object breaks the entry's contract: row 2, not the trust registry's row 1 or 3.

    The trust registry is read and is an object (row 1 holds), so the first row that holds is the
    entry's contract, INVALID_REGISTRY_ENTRY, as loquitur-verify-ts evaluateTrustRegistry reports
    it. It was reported as INVALID_TRUST_REGISTRY, a finding about the document that was fine.
    """
    result = _evaluate(tmp_path, entry, fixture_trust_registry())  # type: ignore[arg-type]
    assert result.authorization_status == "INVALID_REGISTRY_ENTRY"
    assert result.signature_status is None
    assert result.root_signature_status == "ROOT_SIGNATURE_NOT_EVALUATED"
    assert result.verdict == "FAIL"
    assert [check.name for check in result.checks] == ["registry_entry_shape"]


def test_an_unreadable_trust_registry_is_row_1_whatever_the_entry(tmp_path: Path) -> None:
    """Row 1 comes before row 2: a trust registry that is not an object is refused first."""
    path = write_json(tmp_path / "trust_registry.json", [fixture_trust_registry()])
    result = verify_registry_entry_trust(None, trust_registry_path=path, evaluation_time=EVALUATION_TIME)  # type: ignore[arg-type]
    assert result.authorization_status == "INVALID_TRUST_REGISTRY"
