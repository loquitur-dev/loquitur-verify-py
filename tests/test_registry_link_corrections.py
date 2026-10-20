"""Registry-link corrections: the receipt's whole contract, empty free strings, MAJOR as text.

Each test states the rule it holds. Every bundle is built from the link fixture and
sealed, so a run differs from the passing one only by the member under test.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from authorization_kit import IssuerKey, authorization_material, write_json
from bundle_builder import Bundle, jcs, sha

from loquitur.verify.evaluation_time import operator_evaluation_time
from loquitur.verify.registry_link import (
    RegistryLinkFieldCheck,
    RegistryLinkVerificationResult,
    _entry_policy_major,
)
from loquitur.verify.runner import verify_path

RECEIPT_OPTIONAL_FREE_STRINGS = ("asset_id", "network", "anchor_provider", "anchor_type")


def _bundle_with_receipt(tmp_path: Path, **members: object) -> tuple[Bundle, Path]:
    bundle = Bundle()
    bundle.edit("verification_receipt.json", lambda receipt: receipt.update(members))
    bundle.seal()
    return bundle, bundle.write(tmp_path / "bundle")


# registry-link.md section 2 holds each of the four
# optional receipt free strings, when it is a string, to a code point outside W. "" has none.
@pytest.mark.parametrize("member", RECEIPT_OPTIONAL_FREE_STRINGS)
def test_an_empty_optional_receipt_free_string_breaks_the_receipt_contract(tmp_path: Path, member: str) -> None:
    bundle, root = _bundle_with_receipt(tmp_path, **{member: ""})
    report = verify_path(root).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert [error["code"] for error in report["errors"]] == ["verification_receipt_contract_violation"]
    assert f"verification_receipt_contract_violation:verification_receipt.{member}:blank" in report["notes"]

    linked = verify_path(root, registry_entry_path=bundle.link_entry(tmp_path / "entry.json")).to_dict()
    assert linked["status"] == "OFFLINE_FAIL"
    assert linked["checks"]["registry_link"] is False
    assert "verification_receipt_contract_violation" in [error["code"] for error in linked["errors"]]


@pytest.mark.parametrize("member", RECEIPT_OPTIONAL_FREE_STRINGS)
def test_a_non_empty_optional_receipt_free_string_still_passes(tmp_path: Path, member: str) -> None:
    _bundle, root = _bundle_with_receipt(tmp_path, **{member: "x"})
    report = verify_path(root).to_dict()
    assert report["errors"] == []


# The link holds only over the receipt's full contract (registry-link.md section 7),
# so a receipt free string made only of W leaves the link not holding and trust_registry null.
def test_a_receipt_free_string_made_only_of_w_does_not_hold_the_link(tmp_path: Path) -> None:
    bundle, root = _bundle_with_receipt(tmp_path, anchor_type="\u00a0")
    key = IssuerKey()

    def bind(entry: dict) -> None:
        entry["manifest_hash"] = "sha256:" + bundle.manifest_digest()
        entry["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))

    entry, registry = authorization_material(key, entry=bind)
    report = verify_path(
        root,
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
        trust_registry_path=write_json(tmp_path / "trust_registry.json", registry),
        evaluation_time=operator_evaluation_time("2026-05-10T00:00:00Z"),
    ).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["registry_link"] is False
    assert report["trust_registry"] is None
    assert report["checks"]["trust_registry"] is None
    assert "verification_receipt_contract_violation" in [error["code"] for error in report["errors"]]


# MAJOR is compared as decimal text and never converted, so a MAJOR
# longer than the interpreter's integer-string limit is a link that does not hold, not exit 3.
def test_a_policy_major_over_the_integer_string_limit_is_a_link_that_does_not_hold(tmp_path: Path) -> None:
    bundle = Bundle()
    entry_path = bundle.link_entry(tmp_path / "entry.json", policy_version="1" + "0" * 4400 + ".0.0")
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root, registry_entry_path=entry_path).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert report["exit_code"] == 1
    assert report["checks"]["registry_link"] is False
    assert "internal_error" not in [error["code"] for error in report["errors"]]


@pytest.mark.parametrize(
    ("policy_version", "major"),
    [
        ("1.0.0", 1),
        ("9007199254740991.0.0", 9007199254740991),
        ("10000000000000000.0.0", 10000000000000000),  # 17 digits: text, equal to no receipt integer
        ("1" + "0" * 4400 + ".0.0", "1" + "0" * 4400),
        ("01.0.0", None),
    ],
    ids=["one", "safe_maximum", "seventeen_digits", "4401_digits", "leading_zero"],
)
def test_the_policy_major_is_read_as_written(policy_version: str, major: object) -> None:
    got = _entry_policy_major(policy_version)
    if isinstance(major, int) and len(str(major)) > 16:
        assert got == str(major)
    else:
        assert got == major


# A hard link check that could not be evaluated fails the link like
# one that did not hold (registry-link.md section 3), so the link is FAIL, never REVIEW.
@pytest.mark.parametrize("hard", ["manifest_hash", "receipt_hash", "policy_version", "reason_codes"])
def test_an_unevaluated_hard_check_fails_the_link(hard: str) -> None:
    result = RegistryLinkVerificationResult(
        registry_entry={"object_type": "registry_entry"},
        registry_entry_path="entry.json",
        verification_receipt={"object_type": "verification_receipt"},
        verification_receipt_path_name="verification_receipt.json",
        receipt_sha256_actual="0" * 64,
        checks=(RegistryLinkFieldCheck(name=hard, expected="x", actual=None, ok=None),),
    )
    assert result.status == "OFFLINE_FAIL"
    assert result.verdict == "FAIL"
    assert result.link_holds is False


def test_an_unevaluated_soft_check_leaves_the_link_in_review() -> None:
    result = RegistryLinkVerificationResult(
        registry_entry={"object_type": "registry_entry"},
        registry_entry_path="entry.json",
        verification_receipt={"object_type": "verification_receipt"},
        verification_receipt_path_name="verification_receipt.json",
        receipt_sha256_actual="0" * 64,
        checks=(RegistryLinkFieldCheck(name="status_verdict", expected="PASS", actual=None, ok=None),),
    )
    assert result.status == "OFFLINE_REVIEW"


def test_the_link_result_has_no_ok_and_a_link_in_review_still_holds() -> None:
    """``ok`` read True for a link in REVIEW: a host reading it alone took it for the verdict.

    The result names what that member meant, ``link_holds``; status and verdict are the outcome.
    """
    assert not hasattr(RegistryLinkVerificationResult, "ok")
    result = RegistryLinkVerificationResult(
        registry_entry={"object_type": "registry_entry"},
        registry_entry_path="entry.json",
        verification_receipt={"object_type": "verification_receipt"},
        verification_receipt_path_name="verification_receipt.json",
        receipt_sha256_actual="0" * 64,
        checks=(RegistryLinkFieldCheck(name="status_verdict", expected="PASS", actual=None, ok=None),),
    )
    assert (result.link_holds, result.status, result.verdict) == (True, "OFFLINE_REVIEW", "REVIEW")
    with pytest.raises(AttributeError):
        result.ok  # noqa: B018
