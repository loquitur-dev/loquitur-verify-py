"""A registry entry's verdict equals the verdict its reason codes derive (VG-1 to VG-4).

The entry commits to a verdict and cites the reason codes it rests on, and the two are held
together on the verification path: an entry with verdict PASS citing
AUTHORIZATION_ISSUER_KEY_REVOKED (severity fail) must not link at the link check and verify OFFLINE_OK,
exit 0, and an entry with verdict FAIL citing only INTEGRITY_OK must not be reported as a
failed run for a reason its own grounds deny. The narrative renderer applies the same rule.

The rules verdict-grounds.md states for a summary apply to the entry, as one rule wherever
an entry is read:

- VG-1: ``reason_codes`` is non-empty and cites no code twice;
- VG-2: every cited code is in the catalog;
- VG-3: the verdict equals the verdict the highest cited severity maps to (info PASS, warn
  WARN, review REVIEW, fail FAIL);
- VG-4: a PASS cites at least one info-severity code.

On the verification path a violation is a registry-entry contract failure at the link and authorization checks
(registry_link false, ``registry_entry_contract_violation``, OFFLINE_FAIL, exit 1); the
renderer refuses to narrate such an entry.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from authorization_kit import IssuerKey, fixture_trust_registry, write_json
from bundle_builder import Bundle
from siblings import needs

from loquitur.verify.narrative import render_narrative_from_codes
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_registry import verify_registry_entry_trust

RECEIPT_STATUS = {"PASS": "pass", "WARN": "warning", "REVIEW": "review", "FAIL": "fail"}

# label: (entry verdict, reason codes, (status, exit code, registry_link))
LINK_ROWS = {
    # verdict and grounds disagree: refused
    "pass-citing-a-fail-code": ("PASS", ["AUTHORIZATION_ISSUER_KEY_REVOKED"], ("OFFLINE_FAIL", 1, False)),
    "pass-citing-a-review-code": ("PASS", ["NEEDS_REVIEW"], ("OFFLINE_FAIL", 1, False)),
    "pass-citing-info-and-warn": ("PASS", ["INTEGRITY_OK", "MARK_STALE"], ("OFFLINE_FAIL", 1, False)),
    "pass-citing-only-warn": ("PASS", ["MARK_STALE"], ("OFFLINE_FAIL", 1, False)),
    "fail-citing-only-info": ("FAIL", ["INTEGRITY_OK"], ("OFFLINE_FAIL", 1, False)),
    "warn-citing-only-info": ("WARN", ["INTEGRITY_OK"], ("OFFLINE_FAIL", 1, False)),
    "review-citing-a-fail-code": ("REVIEW", ["AUTHORIZATION_ISSUER_KEY_REVOKED"], ("OFFLINE_FAIL", 1, False)),
    "review-citing-only-warn": ("REVIEW", ["MARK_STALE"], ("OFFLINE_FAIL", 1, False)),
    # verdict equal to its grounds: the link holds and the committed verdict decides
    "pass-citing-info": ("PASS", ["INTEGRITY_OK"], ("OFFLINE_OK", 0, True)),
    "pass-citing-two-info": ("PASS", ["INTEGRITY_OK", "REQUIRED_CLAIMS_PRESENT"], ("OFFLINE_OK", 0, True)),
    "warn-citing-info-and-warn": ("WARN", ["INTEGRITY_OK", "MARK_STALE"], ("OFFLINE_REVIEW", 2, True)),
    "review-citing-info-warn-review": (
        "REVIEW",
        ["INTEGRITY_OK", "MARK_STALE", "NEEDS_REVIEW"],
        ("OFFLINE_REVIEW", 2, True),
    ),
    "fail-citing-a-fail-code": (
        "FAIL",
        ["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"],
        ("OFFLINE_FAIL", 1, True),
    ),
}


def test_an_entry_whose_verdict_is_not_the_verdict_of_its_grounds_fails_its_contract(tmp_path: Path) -> None:
    got, expected = {}, {}
    for label, (verdict, codes, (status, exit_code, linked)) in LINK_ROWS.items():
        bundle = Bundle().edit(
            "verification_receipt.json",
            lambda r, v=verdict, c=codes: r.update(status=RECEIPT_STATUS[v], reason_codes=c),
        )
        bundle.seal()
        root = bundle.write(tmp_path / label / "bundle")
        entry = bundle.link_entry(tmp_path / label / "entry.json", verdict=verdict, reason_codes=codes)
        report = verify_path(root, registry_entry_path=entry).to_dict()
        got[label] = {
            "status": report["status"],
            "exit_code": report["exit_code"],
            "registry_link": report["checks"]["registry_link"],
            "contract_violation": "registry_entry_contract_violation" in [e["code"] for e in report["errors"]],
        }
        expected[label] = {
            "status": status,
            "exit_code": exit_code,
            "registry_link": linked,
            "contract_violation": not linked,
        }
    assert got == expected


def test_the_violation_is_named_and_the_authorization_entry_contract_applies_it_too(tmp_path: Path) -> None:
    bundle = Bundle().edit(
        "verification_receipt.json", lambda r: r.update(reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"])
    )
    bundle.seal()
    root = bundle.write(tmp_path / "bundle")
    entry_path = bundle.link_entry(tmp_path / "entry.json", reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"])
    report = verify_path(root, registry_entry_path=entry_path).to_dict()
    assert "registry_entry_contract_violation:registry_entry.verdict:verdict_contradicts_grounds" in report["notes"]

    # The library entry point for authorization holds the entry to the same contract before authorization.
    key = IssuerKey()
    entry = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "authorization_valid_registry_entry.json").read_text()
    )
    entry["reason_codes"] = ["AUTHORIZATION_ISSUER_KEY_REVOKED"]
    key.sign_entry(entry)
    registry = fixture_trust_registry()
    registry["entries"][0]["public_key_hex"] = key.public_key_hex
    result = verify_registry_entry_trust(entry, trust_registry_path=write_json(tmp_path / "trust.json", registry))
    assert (result.authorization_status, result.authorization_holds) == ("INVALID_REGISTRY_ENTRY", False)


RENDER_ROWS = {
    "unknown-code-beside-a-known-one": (("INTEGRITY_OK", "NOT_A_REAL_CODE"), "PASS", "does not define"),
    "only-an-unknown-code": (("NOT_A_REAL_CODE",), "PASS", "does not define"),
    "no-code": ((), "PASS", "cites no reason code"),
    "a-code-twice": (("INTEGRITY_OK", "INTEGRITY_OK"), "PASS", "more than once"),
    "fail-over-info": (("INTEGRITY_OK",), "FAIL", "inconsistent with its reason codes"),
    "review-over-warn": (("MARK_STALE",), "REVIEW", "inconsistent with its reason codes"),
    "pass-under-fail": (
        ("INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"),
        "PASS",
        "inconsistent with its reason codes",
    ),
    "verdict-outside-the-four": (("INTEGRITY_OK",), "pass", "outside the closed vocabulary"),
    "warn-citing-only-warn": (("MARK_STALE",), "WARN", None),
    "fail-citing-a-fail-code": (("AUTHORIZATION_ISSUER_KEY_REVOKED",), "FAIL", None),
}


# The renderer composes from the catalog loquitur-schemas carries, which only the optional
# [narrative] extra installs. tests/conftest.py skips the narrative modules by name; this one test
# of the renderer lives here, beside the verdict rule it shares, so it says so itself, and the
# test-base job, which installs `.[dev]` without the extra, skips it.
_NARRATIVE_EXTRA = importlib.util.find_spec("loquitur.schemas") is not None


@needs(_NARRATIVE_EXTRA, "narrative rendering needs the optional [narrative] extra (loquitur-schemas)")
@pytest.mark.parametrize("label", sorted(RENDER_ROWS))
def test_the_renderer_applies_the_same_equality_to_an_entry(label: str) -> None:
    codes, verdict, refusal = RENDER_ROWS[label]
    if refusal is None:
        rendered = render_narrative_from_codes(codes, verdict=verdict, verdict_context="registry_entry")
        assert rendered.technical and f"{verdict} verdict" in rendered.technical
    else:
        with pytest.raises(ValueError, match=refusal):
            render_narrative_from_codes(codes, verdict=verdict, verdict_context="registry_entry")
