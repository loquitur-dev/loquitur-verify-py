"""The embedded registered vocabularies are the protocol's, and their contract table is enforced.

`registered_vocabularies.py` embeds loquitur-protocol's `vocabularies/<kind>.json` byte for byte with
their SHA-256 (verification-vocabularies.md section 8). This regenerates the module from a sibling
protocol checkout and compares, as test_schema_contract_is_current.py does for the schema tables,
and holds the generated table of the vocabulary schema to the keywords it uses.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

from loquitur.verify.contract_validation import contract_errors
from loquitur.verify.registered_vocabularies import REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256

REPO = Path(__file__).resolve().parents[1]
GENERATOR = REPO / "tools/generate_registered_vocabularies.py"
PROTOCOL = REPO.parent / "loquitur-protocol"
REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"


def _load_generator():
    if not (PROTOCOL / "vocabularies").is_dir():
        if os.environ.get(REQUIRE_SIBLINGS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            pytest.fail(
                f"{REQUIRE_SIBLINGS_ENV}=1 but {PROTOCOL} is absent, so the embedded vocabularies were not compared"
            )
        pytest.skip(f"loquitur-protocol not checked out at {PROTOCOL}")
    spec = importlib.util.spec_from_file_location("_generate_registered_vocabularies", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_embedded_vocabularies_are_the_protocol_files() -> None:
    generator = _load_generator()
    assert generator.TARGET.read_text(encoding="utf-8") == generator.render(), (
        "registered_vocabularies.py is stale. Run: python tools/generate_registered_vocabularies.py"
    )
    for kind, data in REGISTERED_VOCABULARIES.items():
        assert data == (PROTOCOL / "vocabularies" / f"{kind}.json").read_bytes(), kind


def test_each_recorded_digest_is_the_digest_of_the_embedded_bytes() -> None:
    assert (
        sorted(REGISTERED_VOCABULARIES)
        == sorted(REGISTERED_VOCABULARY_SHA256)
        == sorted(["anchoring_method", "asset_type", "workflow"])
    )
    for kind, data in REGISTERED_VOCABULARIES.items():
        assert hashlib.sha256(data).hexdigest() == REGISTERED_VOCABULARY_SHA256[kind], kind


@pytest.mark.parametrize(
    "change,expected",
    [
        (lambda d: d.update(values={}), "registered_vocabulary.values:minProperties"),
        (
            lambda d: d["values"].update({"Fund-NAV": d["values"]["fund_nav"]}),
            "registered_vocabulary.values.Fund-NAV:propertyNames",
        ),
        (
            lambda d: d["values"]["fund_nav"].update(status="retired"),
            "registered_vocabulary.values.fund_nav.status:enum",
        ),
        (
            lambda d: d["values"]["fund_nav"].update(note="x"),
            "registered_vocabulary.values.fund_nav.note:additionalProperties",
        ),
        (lambda d: d.update(version="1.0"), "registered_vocabulary.version:pattern"),
    ],
)
def test_the_vocabulary_table_enforces_each_keyword(change, expected: str) -> None:
    import json

    document = json.loads(REGISTERED_VOCABULARIES["asset_type"])
    assert contract_errors("registered_vocabulary", document) == []
    change(document)
    assert expected in contract_errors("registered_vocabulary", document)
