"""The generated value contract must never drift from the normative schemas.

A hand-written mirror of the closed field set with a comment saying it "MUST be kept in
step with registry_entry.schema.json" drifts with nothing to notice: a mirror carrying the
field names and omitting `required`, `enum` and `pattern` would let this verifier authorize
documents the public contract rejects. An instruction in a comment is not a mechanism.

These tests are the mechanism. They regenerate the contract from the schemas and
compare byte for byte, so the checked-in tables cannot fall behind a schema change.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from loquitur.verify.contract_validation import contract_errors
from loquitur.verify.schema_contract import SCHEMA_CONTRACTS

REPO = Path(__file__).resolve().parents[1]
GENERATOR = REPO / "tools/generate_schema_contract.py"
SCHEMAS_REPO = REPO.parent / "loquitur-schemas"
REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"


def _load_generator():
    import os

    if not SCHEMAS_REPO.is_dir():
        if os.environ.get(REQUIRE_SIBLINGS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            pytest.fail(
                f"{REQUIRE_SIBLINGS_ENV}=1 but {SCHEMAS_REPO} is absent, so contract drift "
                "cannot be checked. A skip here is how a mirror drifts unnoticed."
            )
        pytest.skip(f"loquitur-schemas not checked out at {SCHEMAS_REPO}")
    spec = importlib.util.spec_from_file_location("_generate_schema_contract", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generated_contract_matches_the_normative_schemas() -> None:
    generator = _load_generator()
    expected = generator.render(generator.build())
    actual = generator.TARGET.read_text(encoding="utf-8")
    assert actual == expected, (
        "schema_contract.py is stale. Run: python tools/generate_schema_contract.py\n"
        "A stale contract means this verifier is enforcing a different contract than "
        "the one published to integrators."
    )


def test_generation_refuses_a_keyword_it_cannot_enforce() -> None:
    """Fail-closed generation, verified rather than assumed.

    If an unrecognized keyword were skipped instead of raising, a future schema
    tightening would be silently dropped from the mirror: exactly the failure this
    whole mechanism exists to prevent.
    """
    generator = _load_generator()
    with pytest.raises(generator.UnsupportedSchemaKeyword):
        generator.extract({"type": "string", "notAKeywordWeSupport": 1}, path="probe")


# --- the contract is actually enforced, not merely present -----------------------


def test_contract_tables_carry_value_constraints_not_only_field_names() -> None:
    entry = SCHEMA_CONTRACTS["registry_entry"]["properties"]
    assert "enum" in entry["verdict"], "verdict enum missing: the contract does not constrain the verdict"
    assert "pattern" in entry["issuer_id"]
    assert "required" in SCHEMA_CONTRACTS["registry_entry"]


@pytest.mark.parametrize(
    "field,value,keyword",
    [
        ("verdict", "BANANA", "enum"),
        ("privacy_classification", "SECRET", "enum"),
        ("policy_version", "not-a-semver", "pattern"),
        ("issuer_id", "x", "pattern"),
        ("manifest_hash", "sha256:ZZZZ", "pattern"),
        ("object_type", "not_a_registry_entry", "const"),
    ],
)
def test_out_of_contract_values_are_reported(field: str, value: str, keyword: str) -> None:
    """Each of these, on a signed entry, would be AUTHORIZED without the value contract."""
    errors = contract_errors("registry_entry", {"object_type": "registry_entry", field: value})
    assert any(error == f"registry_entry.{field}:{keyword}" for error in errors), (
        f"expected registry_entry.{field}:{keyword} in {errors}"
    )


def test_missing_required_fields_are_reported() -> None:
    errors = contract_errors("registry_entry", {"object_type": "registry_entry"})
    required = {e for e in errors if e.endswith(":required")}
    assert len(required) >= 8, f"expected the required set to be enforced, got {sorted(required)}"


def test_a_conformant_entry_produces_no_errors(tmp_path: Path) -> None:
    """Guards against the opposite failure: a contract so strict it rejects valid input."""
    import json

    entry = json.loads((REPO / "tests/fixtures/authorization_valid_registry_entry.json").read_text())
    assert contract_errors("registry_entry", entry) == []

    trust = json.loads((REPO / "tests/fixtures/authorization_valid_trust_registry.json").read_text())
    assert contract_errors("trust_registry", trust) == []


def test_unknown_contract_name_raises_rather_than_passing() -> None:
    with pytest.raises(KeyError):
        contract_errors("no_such_contract", {})
