"""Every free string of every document is not empty under the whitespace set W, by name.

bundle-objects.md defines a free string beside W: a member a document's contract types as a
string and holds to no pattern, enumeration, constant, digest or signature form. Each contract
names its own, and the appendix suite (tests/test_spec_document_contracts.py) runs the rule row
by row on the report's normative surface. This module runs it one level down, on the finding
each contract reports, so that the member a check refuses is the member the contract names:
a check that refused the right document for the wrong member would pass the appendix and fail
here. Three forms of W and the one code point the table places outside it, per member.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from loquitur.verify.envelope import envelope_shape_errors_for
from loquitur.verify.manifest import manifest_shape_errors
from loquitur.verify.p1 import p1_shape_errors
from loquitur.verify.registry_link import (
    REGISTRY_ENTRY_FREE_STRINGS,
    VERIFICATION_RECEIPT_FREE_STRINGS,
    free_string_errors,
    registry_entry_contract_violations,
)
from loquitur.verify.trust_registry import TRUST_ENTRY_FREE_STRINGS, _trust_registry_shape_errors

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BLANK = {"space": " ", "space-tab": " \t", "ideographic-space": "\u3000", "no-break-space": "\u00a0", "bom": "\ufeff"}
NOT_BLANK = "\u200b"  # U+200B is not in W


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _set(document: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    node = document
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value
    return document


def test_the_manifest_names_its_one_free_string() -> None:
    """bundle_id is the manifest's free string; schema_version is the constant loquitur.bundle.v1.

    A blank schema_version is not a free string left empty but a value other than the constant, and
    U+200B, which is not in W, is no more the constant than a blank is.
    """
    manifest = _fixture("link_valid_bundle/manifest.json")
    for label, blank in BLANK.items():
        assert "manifest_empty_field:bundle_id" in manifest_shape_errors(dict(manifest, bundle_id=blank)), label
        assert manifest_shape_errors(dict(manifest, schema_version=blank)) == ["manifest_invalid_schema_version"], label
    assert not manifest_shape_errors(dict(manifest, bundle_id=NOT_BLANK))
    assert manifest_shape_errors(dict(manifest, schema_version=NOT_BLANK)) == ["manifest_invalid_schema_version"]


def test_a_projection_key_is_a_free_string() -> None:
    p1 = _fixture("link_valid_bundle/p1.json")
    for label, blank in BLANK.items():
        assert "p1_input_key_projection_empty_key" in p1_shape_errors(dict(p1, ik=["asset_type", blank])), label
    assert "p1_input_key_projection_empty_key" not in p1_shape_errors(dict(p1, ik=["asset_type", NOT_BLANK]))
    # A duplicate is judged before emptiness, and an element of another type before both.
    assert "p1_input_key_projection_empty_key" not in p1_shape_errors(dict(p1, ik=[" ", " "]))
    assert "p1_input_key_projection_empty_key" not in p1_shape_errors(dict(p1, ik=[" ", 1]))


@pytest.mark.parametrize("member", ["network", "p1_txid", "uri", "asset_id", "asset_type", "receipt_id"])
def test_the_envelopes_six_optional_strings_are_free_strings(member: str) -> None:
    envelope = _fixture("link_valid_bundle/envelope_env1.json")
    for label, blank in BLANK.items():
        assert f"envelope_empty_field:{member}" in envelope_shape_errors_for(dict(envelope, **{member: blank})), label
    assert not envelope_shape_errors_for(dict(envelope, **{member: NOT_BLANK}))
    assert not envelope_shape_errors_for(dict(envelope, **{member: None}))


@pytest.mark.parametrize("member", VERIFICATION_RECEIPT_FREE_STRINGS)
def test_the_receipts_free_strings(member: str) -> None:
    receipt = _fixture("link_valid_bundle/verification_receipt.json")
    for label, blank in BLANK.items():
        assert free_string_errors(
            dict(receipt, **{member: blank}), "verification_receipt", VERIFICATION_RECEIPT_FREE_STRINGS
        ) == [f"verification_receipt.{member}:blank"], label
    assert not free_string_errors(
        dict(receipt, **{member: NOT_BLANK}), "verification_receipt", VERIFICATION_RECEIPT_FREE_STRINGS
    )


@pytest.mark.parametrize("member", REGISTRY_ENTRY_FREE_STRINGS)
def test_the_entrys_free_strings_at_the_top_level_and_nested(member: str) -> None:
    entry = _fixture("authorization_valid_registry_entry.json")
    entry["anchor"] = {"method": "blockchain_transaction", "system": "testnet", "anchor_reference": "tx-1"}
    for label, blank in BLANK.items():
        violations = registry_entry_contract_violations(_set(json.loads(json.dumps(entry)), member, blank))
        assert f"registry_entry.{member}:blank" in violations, (label, violations)
    assert f"registry_entry.{member}:blank" not in registry_entry_contract_violations(
        _set(json.loads(json.dumps(entry)), member, NOT_BLANK)
    )


def test_a_nested_free_string_is_read_only_when_its_object_is_present() -> None:
    entry = _fixture("link_valid_registry_entry.json")
    assert entry.get("signature") is None and entry.get("anchor") is None
    assert free_string_errors(entry, "registry_entry", REGISTRY_ENTRY_FREE_STRINGS) == []
    assert free_string_errors({"signature": " ", "anchor": 7}, "registry_entry", REGISTRY_ENTRY_FREE_STRINGS) == []


@pytest.mark.parametrize("member", ["signature.key_id", *(f"entries.0.{name}" for name in TRUST_ENTRY_FREE_STRINGS)])
def test_the_trust_registrys_free_strings(member: str) -> None:
    registry = _fixture("authorization_valid_trust_registry.json")
    if member.endswith("revocation_reason"):
        registry["entries"][0].update(status="revoked", revoked_at="2026-05-01T00:00:00Z")
    reported = member.replace("entries.0.", "entries[0].")
    for label, blank in BLANK.items():
        document = json.loads(json.dumps(registry))
        node = document
        for part in member.split(".")[:-1]:
            node = node[int(part)] if part.isdigit() else node[part]
        node[member.split(".")[-1]] = blank
        assert f"trust_registry.{reported}:blank" in _trust_registry_shape_errors(document), (label, member)
    document = json.loads(json.dumps(registry))
    node = document
    for part in member.split(".")[:-1]:
        node = node[int(part)] if part.isdigit() else node[part]
    node[member.split(".")[-1]] = NOT_BLANK
    assert not [error for error in _trust_registry_shape_errors(document) if error.endswith(":blank")]


def test_the_trust_registrys_signature_value_is_not_a_free_string() -> None:
    """trust-root.md holds signature.signature to its form when a root authenticates the registry."""
    registry = _fixture("authorization_valid_trust_registry.json")
    registry["signature"]["signature"] = " "
    assert not [error for error in _trust_registry_shape_errors(registry) if error.endswith(":blank")]
