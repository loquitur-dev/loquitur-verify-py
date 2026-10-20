"""Tests for the compliance and executive narrative renderers.

These extend the technical-only test suite with audience-
specific invariants:

- Compliance narrative composes verdict lead + per-code paragraphs
  (consequence + required_action) + closing line. Voice is assertive.
- Executive narrative composes a single compact block (verdict lead +
  optional aggregated per-code summary + optional closing action). Voice
  is assertive non-technical with no jargon.
- Both are byte-deterministic across runs.
- Both are wired through render_verdict_narrative when their audience is
  selected.
- report_dict_with_narrative supports audience selection across all three.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from loquitur.verify import (
    render_verdict_narrative,
)
from loquitur.verify.narrative import (
    NarrativeRefusedError,
    render_compliance_narrative,
    render_executive_narrative,
    report_dict_with_narrative,
)
from loquitur.verify.runner import (
    STATUS_OFFLINE_FAIL,
    STATUS_OFFLINE_OK,
    STATUS_OFFLINE_REVIEW,
    VERDICT_FAIL,
    VERDICT_PASS,
    VERDICT_REVIEW,
    OfflineVerificationReport,
    verify_path,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ALL_FIXTURES = (
    "valid_bundle.zip",
    "tampered_manifest_bundle.zip",
    "tampered_canonical_input_bundle.zip",
    "missing_canonical_input_bundle.zip",
)


# ---------------------------------------------------------------------------
# Compliance audience
# ---------------------------------------------------------------------------
def test_render_compliance_for_pass_mentions_pass_outcome() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_compliance_narrative(report)
    assert narrative is not None
    assert "passes offline verification" in narrative


def test_render_compliance_for_fail_mentions_fail_and_action() -> None:
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_compliance_narrative(report)
    assert narrative is not None
    assert "fails offline verification" in narrative
    # Closing line must instruct a concrete action.
    assert "Reject the bundle" in narrative


def test_render_compliance_for_review_blocks_advancement() -> None:
    report = verify_path(FIXTURES / "missing_canonical_input_bundle.zip")
    narrative = render_compliance_narrative(report)
    assert narrative is not None
    assert "requires review" in narrative
    assert "Do not advance" in narrative


def test_render_compliance_includes_paragraph_per_active_code() -> None:
    """One paragraph per active code, plus lead and closing."""
    from loquitur.verify.narrative import infer_active_reason_codes

    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_compliance_narrative(report)
    assert narrative is not None
    paragraphs = narrative.split("\n\n")
    active = infer_active_reason_codes(report)
    # lead + N reason-code paragraphs + closing
    assert len(paragraphs) == 2 + len(active)


def test_render_compliance_paragraph_includes_consequence_and_action() -> None:
    """Each compliance paragraph contains both the consequence wording and
    the required action wording from the catalog."""
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_compliance_narrative(report)
    assert narrative is not None
    entry = catalog.get("INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH")
    assert entry.compliance.consequence in narrative
    assert entry.compliance.required_action in narrative


def test_render_compliance_uses_assertive_voice() -> None:
    """Compliance narrative leans on assertive markers across all fixtures.

    Across the union of all fixture compliance narratives, assertive markers
    (must, cannot, do not, require, does not) should appear at least once
    per fixture. Soft markers should be rare.
    """
    for fixture in ALL_FIXTURES:
        report = verify_path(FIXTURES / fixture)
        narrative = render_compliance_narrative(report)
        assert narrative is not None
        text = narrative.lower()
        assertive_count = sum(
            text.count(token) for token in ("must", "cannot", "do not", "require", "does not", "is not")
        )
        assert assertive_count >= 1, f"{fixture}: compliance narrative lacks assertive markers"


# ---------------------------------------------------------------------------
# Executive audience
# ---------------------------------------------------------------------------
def test_render_executive_for_pass_is_concise_and_positive() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_executive_narrative(report)
    assert narrative is not None
    assert "valid" in narrative.lower()
    # Executive PASS should be very short: no per-code summary, no closing
    # action. Single sentence around 80 chars.
    assert len(narrative) <= 200


def test_render_executive_for_fail_contains_lead_and_action() -> None:
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_executive_narrative(report)
    assert narrative is not None
    assert "rejected" in narrative.lower()
    assert "issuer must" in narrative.lower()


def test_render_executive_for_review_states_review_and_action() -> None:
    report = verify_path(FIXTURES / "missing_canonical_input_bundle.zip")
    narrative = render_executive_narrative(report)
    assert narrative is not None
    assert "requires review" in narrative
    assert "issuer must" in narrative.lower()


def test_render_executive_avoids_technical_jargon() -> None:
    """Executive narrative must not contain hashes, RFCs, schema names."""
    forbidden = (
        "SHA-256",
        "RFC 8785",
        "RFC-8785",
        "JCS",
        "manifest.sha256",
        "p1.json",
        "canonical_input.json",
        "envelope_env1",
        "loquitur.reason_codes",
    )
    for fixture in ALL_FIXTURES:
        report = verify_path(FIXTURES / fixture)
        narrative = render_executive_narrative(report)
        assert narrative is not None
        for token in forbidden:
            assert token not in narrative, f"{fixture}: executive narrative leaks jargon {token!r}"


def test_render_executive_is_single_block_no_double_newlines() -> None:
    """Executive output is a single block, never multi-paragraph."""
    for fixture in ALL_FIXTURES:
        report = verify_path(FIXTURES / fixture)
        narrative = render_executive_narrative(report)
        assert narrative is not None
        assert "\n\n" not in narrative, f"{fixture}: executive narrative is multi-paragraph"


def test_render_executive_length_bounds() -> None:
    """Executive narrative respects soft length bounds.

    Schema declares per-entry summary 30-400 chars. Aggregate executive
    output may chain per-code summaries; the cap is 800 chars, which catches
    accidental aggregation explosions.
    """
    for fixture in ALL_FIXTURES:
        report = verify_path(FIXTURES / fixture)
        narrative = render_executive_narrative(report)
        assert narrative is not None
        assert 30 <= len(narrative) <= 800, f"{fixture}: executive length {len(narrative)} outside [30, 800]"


# ---------------------------------------------------------------------------
# Determinism (compliance + executive)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fixture", ALL_FIXTURES)
def test_compliance_narrative_is_byte_deterministic(fixture: str) -> None:
    report = verify_path(FIXTURES / fixture)
    hashes = {hashlib.sha256(render_compliance_narrative(report).encode()).hexdigest() for _ in range(10)}
    assert len(hashes) == 1


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
def test_executive_narrative_is_byte_deterministic(fixture: str) -> None:
    report = verify_path(FIXTURES / fixture)
    hashes = {hashlib.sha256(render_executive_narrative(report).encode()).hexdigest() for _ in range(10)}
    assert len(hashes) == 1


# ---------------------------------------------------------------------------
# Public API: render_verdict_narrative wires all three audiences
# ---------------------------------------------------------------------------
def test_render_verdict_narrative_all_audiences_populated() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_verdict_narrative(report, audiences=("technical", "compliance", "executive"))
    assert narrative.technical is not None
    assert narrative.compliance is not None
    assert narrative.executive is not None


def test_render_verdict_narrative_compliance_only() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_verdict_narrative(report, audiences=("compliance",))
    assert narrative.technical is None
    assert narrative.compliance is not None
    assert narrative.executive is None


def test_render_verdict_narrative_executive_only() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_verdict_narrative(report, audiences=("executive",))
    assert narrative.technical is None
    assert narrative.compliance is None
    assert narrative.executive is not None


def test_render_verdict_narrative_unknown_audience_is_silently_ignored() -> None:
    """Asking for a non-existent audience does not raise; only known audiences
    are populated. Future audiences must extend this list explicitly."""
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_verdict_narrative(report, audiences=("does_not_exist",))
    # No known audience selected
    assert narrative.technical is None
    assert narrative.compliance is None
    assert narrative.executive is None


# ---------------------------------------------------------------------------
# report_dict_with_narrative across all three audiences
# ---------------------------------------------------------------------------
def test_to_dict_with_narrative_all_audiences() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    d = report_dict_with_narrative(report, audiences=("technical", "compliance", "executive"))
    assert d["narrative"]["technical"] is not None
    assert d["narrative"]["compliance"] is not None
    assert d["narrative"]["executive"] is not None


def test_to_dict_with_narrative_compliance_only() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    d = report_dict_with_narrative(report, audiences=("compliance",))
    assert d["narrative"]["technical"] is None
    assert d["narrative"]["compliance"] is not None
    assert d["narrative"]["executive"] is None


# ---------------------------------------------------------------------------
# Verdict lead correctness
# ---------------------------------------------------------------------------
def _synthetic_report(status: str, verdict: str) -> OfflineVerificationReport:
    return OfflineVerificationReport(
        status=status,
        verdict=verdict,
        input_path="<synthetic>",
        input_type=None,
        bundle_root_name=None,
    )


def test_compliance_lead_for_each_status() -> None:
    pass_n = render_compliance_narrative(_synthetic_report(STATUS_OFFLINE_OK, VERDICT_PASS))
    fail_n = render_compliance_narrative(_synthetic_report(STATUS_OFFLINE_FAIL, VERDICT_FAIL))

    assert "passes offline verification" in pass_n
    assert "fails offline verification" in fail_n
    # A REVIEW with no grounds is refused (verdict-grounds.md section 7.2).
    with pytest.raises(NarrativeRefusedError):
        render_compliance_narrative(_synthetic_report(STATUS_OFFLINE_REVIEW, VERDICT_REVIEW))


def test_executive_lead_for_each_status() -> None:
    pass_n = render_executive_narrative(_synthetic_report(STATUS_OFFLINE_OK, VERDICT_PASS))
    fail_n = render_executive_narrative(_synthetic_report(STATUS_OFFLINE_FAIL, VERDICT_FAIL))

    assert "valid" in pass_n.lower()
    assert "rejected" in fail_n.lower()
    with pytest.raises(NarrativeRefusedError):
        render_executive_narrative(_synthetic_report(STATUS_OFFLINE_REVIEW, VERDICT_REVIEW))


# ---------------------------------------------------------------------------
# Cross-audience invariants
# ---------------------------------------------------------------------------
def test_three_audiences_produce_distinct_outputs() -> None:
    """The three audience outputs must differ: they are not the same content
    relabeled. The same input report gives three distinct surfaces."""
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    n = render_verdict_narrative(report, audiences=("technical", "compliance", "executive"))
    assert n.technical != n.compliance
    assert n.compliance != n.executive
    assert n.technical != n.executive


def test_executive_always_shorter_than_technical() -> None:
    """Executive narrative is always strictly shorter than technical."""
    for fixture in ALL_FIXTURES:
        report = verify_path(FIXTURES / fixture)
        n = render_verdict_narrative(report, audiences=("technical", "compliance", "executive"))
        assert len(n.executive) < len(n.technical), (
            f"{fixture}: executive {len(n.executive)} not shorter than technical {len(n.technical)}"
        )
