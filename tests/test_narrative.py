"""Tests for the verdict technical narrative renderer.

Invariants enforced:

- Reason code inference is deterministic: the same report gives the same active codes
  in the same order, every invocation.
- Technical narrative output is byte-identical for the same active codes
  set and verdict status across runs.
- The narrative composes a verdict lead, one paragraph per active reason
  code in canonical category order, and a closing line.
- ``to_dict()`` carries no ``narrative`` key: the report a caller reads has
  one shape whether or not a narrative is rendered.
- ``report_dict_with_narrative()`` is opt-in and adds the narrative section.
- Graceful degradation: if the schemas package is uninstalled, the renderer
  returns ``None`` rather than raising.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from loquitur.verify import (
    VerdictNarrative,
    infer_active_reason_codes,
    render_verdict_narrative,
)
from loquitur.verify.narrative import (
    _CANONICAL_CATEGORY_ORDER,
    NarrativeRefusedError,
    _canonical_order,
    render_narrative_from_codes,
    render_technical_narrative,
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


# ---------------------------------------------------------------------------
# Reason code inference
# ---------------------------------------------------------------------------
def test_infer_active_codes_for_valid_bundle_is_integrity_ok() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    codes = infer_active_reason_codes(report)
    assert codes == ("INTEGRITY_OK",)


def test_infer_active_codes_for_tampered_manifest_bundle() -> None:
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    codes = infer_active_reason_codes(report)
    assert "INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH" in codes


def test_infer_active_codes_for_tampered_canonical_input_bundle() -> None:
    report = verify_path(FIXTURES / "tampered_canonical_input_bundle.zip")
    codes = infer_active_reason_codes(report)
    assert "INTEGRITY_OFFLINE_INPUT_HASH_MISMATCH" in codes


def test_infer_active_codes_for_missing_canonical_input_bundle() -> None:
    report = verify_path(FIXTURES / "missing_canonical_input_bundle.zip")
    codes = infer_active_reason_codes(report)
    assert "OFFLINE_CANONICAL_INPUT_MISSING" in codes


def test_infer_active_codes_is_deterministic_across_runs() -> None:
    """The same report gives the same codes tuple, every call. Order matters."""
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    runs = [infer_active_reason_codes(report) for _ in range(10)]
    distinct = {tuple(r) for r in runs}
    assert len(distinct) == 1, f"non-deterministic: {distinct}"


def test_infer_active_codes_returns_canonical_category_order() -> None:
    """Codes sort by category index, then alphabetically inside a category.

    It exercises the ordering function itself with codes drawn from different categories,
    not the first and last members of _CANONICAL_CATEGORY_ORDER, which would be a statement
    about the constant rather than about the sorting; so it survives vocabulary growth and
    fails if the ordering actually changes.
    """
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    by_category: dict[str, str] = {}
    for code in sorted(catalog.entries):
        by_category.setdefault(catalog.entries[code].category, code)

    # One code per category, deliberately fed in reverse canonical order.
    sample = [by_category[c] for c in reversed(_CANONICAL_CATEGORY_ORDER) if c in by_category]
    assert len(sample) >= 5, "too few categories represented; the assertion would be weak"

    ordered = _canonical_order(sample)
    positions = [_CANONICAL_CATEGORY_ORDER.index(catalog.entries[c].category) for c in ordered]
    assert positions == sorted(positions), f"codes are not in canonical category order: {list(ordered)}"


def test_every_ordered_category_is_known_to_the_renderer() -> None:
    """A category the renderer does not know sorts to the end regardless of severity.

    _canonical_order resolves an unknown category inside a bare except that returns a
    sentinel index, indistinguishable from an unknown code, so a catalog category
    missing from the ordering table degrades silently rather than failing.
    """
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    categories = {entry.category for entry in catalog.entries.values()}
    unknown = sorted(categories - set(_CANONICAL_CATEGORY_ORDER))
    assert not unknown, (
        f"catalog declares categories the renderer cannot order: {unknown}. "
        "Add them to _CANONICAL_CATEGORY_ORDER, deliberately choosing the position."
    )


# ---------------------------------------------------------------------------
# Technical narrative composition
# ---------------------------------------------------------------------------
def test_render_technical_for_valid_bundle_mentions_pass() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_technical_narrative(report)
    assert narrative is not None
    assert "PASS verdict" in narrative


def test_render_technical_for_fail_bundle_mentions_fail() -> None:
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_technical_narrative(report)
    assert narrative is not None
    assert "FAIL verdict" in narrative


def test_render_technical_for_review_bundle_mentions_review() -> None:
    report = verify_path(FIXTURES / "missing_canonical_input_bundle.zip")
    narrative = render_technical_narrative(report)
    assert narrative is not None
    assert "REVIEW verdict" in narrative


def test_render_technical_includes_paragraph_per_active_code() -> None:
    """One paragraph per active reason code, plus lead and closing."""
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_technical_narrative(report)
    assert narrative is not None
    paragraphs = narrative.split("\n\n")
    active = infer_active_reason_codes(report)
    # lead + N reason-code paragraphs + closing
    assert len(paragraphs) == 2 + len(active)


def test_render_technical_paragraph_uses_catalog_headline_and_detail() -> None:
    """Each reason-code paragraph starts with the catalog headline."""
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_technical_narrative(report)
    expected_headline = catalog.get("INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH").technical.headline
    assert expected_headline in narrative


def test_render_technical_avoids_softening_voice() -> None:
    """Technical narrative does not introduce hedging language not in the catalog.

    The renderer composes from catalog content; it should not add 'maybe',
    'possibly', 'perhaps' on top of catalog wording.
    """
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    narrative = render_technical_narrative(report)
    assert narrative is not None
    forbidden = (" maybe ", " possibly ", " perhaps ", " might ")
    for token in forbidden:
        assert token not in narrative.lower(), f"hedging token {token!r} in narrative"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "fixture",
    [
        "valid_bundle.zip",
        "tampered_manifest_bundle.zip",
        "tampered_canonical_input_bundle.zip",
        "missing_canonical_input_bundle.zip",
    ],
)
def test_technical_narrative_is_byte_deterministic(fixture: str) -> None:
    """The same report gives a byte-identical narrative across many invocations."""
    report = verify_path(FIXTURES / fixture)
    hashes = set()
    for _ in range(10):
        narrative = render_technical_narrative(report)
        hashes.add(hashlib.sha256(narrative.encode("utf-8")).hexdigest())
    assert len(hashes) == 1, f"non-deterministic on {fixture}: {hashes}"


def test_render_verdict_narrative_returns_dataclass() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_verdict_narrative(report)
    assert isinstance(narrative, VerdictNarrative)


def test_render_verdict_narrative_default_only_technical() -> None:
    """The default render produces technical only; compliance/executive are None."""
    report = verify_path(FIXTURES / "valid_bundle.zip")
    narrative = render_verdict_narrative(report)
    assert narrative.technical is not None
    assert narrative.compliance is None
    assert narrative.executive is None


# ---------------------------------------------------------------------------
# to_dict() carries no narrative
# ---------------------------------------------------------------------------
def test_to_dict_does_not_include_narrative_field() -> None:
    """``to_dict`` carries no ``narrative`` key; a narrative is opt-in via
    ``report_dict_with_narrative``."""
    report = verify_path(FIXTURES / "valid_bundle.zip")
    d = report.to_dict()
    assert "narrative" not in d


def test_to_dict_with_narrative_includes_narrative_field() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    d = report_dict_with_narrative(report)
    assert "narrative" in d
    assert isinstance(d["narrative"], dict)
    assert "technical" in d["narrative"]
    assert d["narrative"]["technical"] is not None


def test_to_dict_with_narrative_preserves_other_fields() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    base = report.to_dict()
    extended = report_dict_with_narrative(report)

    # Every key in base must be in extended with the same value.
    for key, value in base.items():
        assert key in extended
        assert extended[key] == value


# ---------------------------------------------------------------------------
# Audience-specific opt-out
# ---------------------------------------------------------------------------
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


def test_verdict_lead_for_pass_status() -> None:
    report = _synthetic_report(STATUS_OFFLINE_OK, VERDICT_PASS)
    narrative = render_technical_narrative(report)
    assert narrative is not None
    assert "PASS verdict" in narrative


def test_a_review_with_no_grounds_is_refused_not_narrated() -> None:
    """verdict-grounds.md section 7.2: a REVIEW run that gives the renderer no catalog code is refused."""
    report = _synthetic_report(STATUS_OFFLINE_REVIEW, VERDICT_REVIEW)
    assert infer_active_reason_codes(report) == ()
    with pytest.raises(NarrativeRefusedError):
        render_technical_narrative(report)


def test_verdict_lead_for_fail_status() -> None:
    report = _synthetic_report(STATUS_OFFLINE_FAIL, VERDICT_FAIL)
    narrative = render_technical_narrative(report)
    assert narrative is not None
    assert "FAIL verdict" in narrative


# ---------------------------------------------------------------------------
# VerdictNarrative dataclass
# ---------------------------------------------------------------------------
def test_verdict_narrative_to_dict_has_three_audience_fields() -> None:
    n = VerdictNarrative(technical="x", compliance="y", executive="z")
    d = n.to_dict()
    assert set(d.keys()) == {"technical", "compliance", "executive"}


def test_verdict_narrative_is_empty_when_all_none() -> None:
    n = VerdictNarrative()
    assert n.is_empty
    assert not VerdictNarrative(technical="x").is_empty


def test_verdict_narrative_is_frozen() -> None:
    n = VerdictNarrative(technical="x")
    with pytest.raises(Exception):
        n.technical = "y"  # type: ignore[misc]


def test_a_verdict_that_cites_nothing_is_refused() -> None:
    """`loquitur-schemas` rejects it; this package must not print it.

    The schema says `reason_codes` "should be non-empty" and constrains every entry to the
    catalog enum. A renderer accepting an empty list, or a list whose only member the
    catalog does not know, would print "The registry entry records a PASS verdict against
    the issuer's policy" with nothing underneath it, and two packages published together
    would disagree about the property LCP-0008 exists to establish: that a substance-free
    PASS is unrepresentable.
    """
    with pytest.raises(ValueError, match="cites no reason code"):
        render_narrative_from_codes((), verdict="PASS", verdict_context="registry_entry")
    with pytest.raises(ValueError, match="does not define"):
        render_narrative_from_codes(("NOT_A_REAL_CODE",), verdict="PASS", verdict_context="registry_entry")


def test_a_verdict_outside_the_closed_four_is_refused_not_downgraded() -> None:
    """An unrecognized verdict is a rejection, not a downgrade.

    `BANANA`, a lowercase `pass` and the empty string each rendered "The registry entry
    records a FAIL verdict". Fail-closed in routing, which is the right direction, but the
    sentence states something false about what the entry records:
    verification-vocabularies.md forbids exactly this coercion.
    """
    for verdict in ("BANANA", "pass", ""):
        with pytest.raises(ValueError, match="outside the closed vocabulary"):
            render_narrative_from_codes(("INTEGRITY_OK",), verdict=verdict, verdict_context="registry_entry")


def test_an_unknown_code_beside_a_known_one_is_refused() -> None:
    """An entry's verdict is the verdict its grounds derive, and an unknown code has no severity.

    Catalog drift is not tolerated when one cited code is known: a
    code whose severity this catalog cannot give may be the one that raises the derived verdict,
    so the entry cannot be shown to be grounded, and the verification path refuses the same
    entry (VG-2). The renderer applies the same rule.
    """
    with pytest.raises(ValueError, match="does not define"):
        render_narrative_from_codes(
            ("INTEGRITY_OK", "NOT_A_REAL_CODE"), verdict="PASS", verdict_context="registry_entry"
        )
