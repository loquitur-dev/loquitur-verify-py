"""A value registered after this verifier was built is a review, until the operator supplies it.

verification-vocabularies.md §8 and §9: the verifier holds one vocabulary per kind, its own unless
the operator supplies one, and a well-formed value it does not hold at a receipt's asset_type, or
an entry's asset_type or workflow, is the review reason vocabulary_value_unknown
(report-contract.md §3.3, row 14). A copy of the embedded asset_type vocabulary gains a value in a
temporary directory; a bundle whose receipt carries it is OFFLINE_REVIEW with the embedded
vocabulary and OFFLINE_OK with the extended one, every check established in both, and nothing the
verifier ships is written.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from bundle_builder import Bundle

from loquitur.verify import registered_vocabularies
from loquitur.verify.runner import verify_path
from loquitur.verify.vocabulary import VocabularyError, embedded_vocabulary, read_vocabulary, value_status

EMBEDDED = {
    kind: hashlib.sha256(data).hexdigest() for kind, data in registered_vocabularies.REGISTERED_VOCABULARIES.items()
}


def _extended(tmp_path: Path) -> Path:
    document = json.loads(registered_vocabularies.REGISTERED_VOCABULARIES["asset_type"])
    document["version"] = "1.1.0"
    document["values"]["example_asset"] = {
        "since": "1.1.0",
        "status": "active",
        "title": "Example asset",
        "profile": None,
    }
    path = tmp_path / "asset_type.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def _bundle(tmp_path: Path, asset_type: str) -> Path:
    bundle = Bundle().edit("verification_receipt.json", lambda receipt: receipt.update(asset_type=asset_type))
    return bundle.seal().write(tmp_path / "bundle")


def test_a_registered_value_is_a_review_until_the_operator_supplies_its_vocabulary(tmp_path: Path) -> None:
    extended = _extended(tmp_path)
    bundle = _bundle(tmp_path, "example_asset")
    embedded = verify_path(bundle).to_dict()
    assert (embedded["status"], embedded["review_reasons"]) == ("OFFLINE_REVIEW", ["vocabulary_value_unknown"])
    assert embedded["checks_established"] == ["structure", "integrity"]
    assert embedded["vocabularies"]["asset_type"]["source"] == "embedded"
    supplied = verify_path(bundle, vocabularies={"asset_type": extended}).to_dict()
    assert (supplied["status"], supplied["review_reasons"]) == ("OFFLINE_OK", [])
    assert supplied["vocabularies"]["asset_type"] == {
        "source": "operator",
        "sha256": "sha256:" + hashlib.sha256(extended.read_bytes()).hexdigest(),
        "version": "1.1.0",
    }
    assert {kind: registered_vocabularies.REGISTERED_VOCABULARY_SHA256[kind] for kind in EMBEDDED} == EMBEDDED


def test_a_known_value_and_a_malformed_one(tmp_path: Path) -> None:
    held = embedded_vocabulary("asset_type")
    assert value_status("property", held) == "known"
    assert value_status("vessel", held) == "unknown"
    for value in ("Vessel", "vessel-class", " ", "", 7, None, "a" * 65):
        assert value_status(value, held) == "invalid", value


def test_a_supplied_document_of_another_kind_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "workflow.json"
    path.write_bytes(registered_vocabularies.REGISTERED_VOCABULARIES["workflow"])
    with pytest.raises(VocabularyError):
        read_vocabulary("asset_type", path)
    with pytest.raises(VocabularyError):
        verify_path(_bundle(tmp_path, "property"), vocabularies={"asset_type": path})


@pytest.mark.parametrize("kind", sorted(registered_vocabularies.REGISTERED_VOCABULARIES))
def test_each_embedded_vocabulary_satisfies_its_contract(kind: str) -> None:
    held = embedded_vocabulary(kind)
    assert held.kind == kind and held.source == "embedded" and held.values
