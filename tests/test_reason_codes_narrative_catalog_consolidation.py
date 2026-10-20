"""Source-level gates for verifier narrative consolidation.

The verifier may infer active reason codes and choose template keys. It must not
own the verdict lead/closing prose; that prose belongs to the reason-code
catalog in loquitur-schemas.
"""

from __future__ import annotations

from pathlib import Path

VERIFY_ROOT = Path(__file__).resolve().parents[1]
NARRATIVE_SOURCE = VERIFY_ROOT / "src" / "loquitur" / "verify" / "narrative.py"


def test_verifier_uses_catalog_templates_for_verdict_prose() -> None:
    source = NARRATIVE_SOURCE.read_text(encoding="utf-8")

    assert "catalog.template(" in source
    assert "def _technical_verdict_lead" not in source
    assert "def _compliance_verdict_lead" not in source
    assert "def _executive_verdict_lead" not in source
    assert "def _technical_closing" not in source
    assert "def _compliance_closing" not in source
    assert "def _executive_closing_action" not in source


def test_catalog_verdict_sentences_are_not_hardcoded_in_verifier() -> None:
    # Verdict leads and closings belong to the reason-code catalog: the verifier's source
    # carries none of these sentences as a literal.
    source = NARRATIVE_SOURCE.read_text(encoding="utf-8")

    catalog_literals = (
        "The bundle passes offline verification.",
        "The bundle fails offline verification.",
        "The registry entry records a REVIEW verdict.",
        "No further integrity action is required",
        "Reject the bundle. Require the issuer",
        "The verification record is rejected and cannot be relied upon.",
    )
    for literal in catalog_literals:
        assert literal not in source, literal
