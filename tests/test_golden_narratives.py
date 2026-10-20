"""Golden deterministic narrative tests.

For every scenario in tools/build_golden.py:

- Render live narratives via the public renderer API
- Compare byte-identical against the committed golden file
- Run 10 consecutive renders and assert no drift across runs

This is the call-blocking regression gate for the verdict explainability
layer. Any change to the catalog wording, the renderer composition logic,
the canonical category order, or the verdict-context wording surfaces here
as a test failure with a clear diff.

When a wording change is intentional, regenerate goldens with::

    python tools/build_golden.py

and commit the regenerated files alongside the renderer change. The test
suite then ratifies the new baseline.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from narrative_bundles import BUNDLE_CHANGES, changed_bundle

from loquitur.verify.narrative import (
    render_narrative_from_codes,
    render_verdict_narrative,
)
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import read_trust_root_document

GOLDEN_DIR = Path(__file__).resolve().parent / "golden_narratives"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
AUDIENCES: tuple[str, ...] = ("technical", "compliance", "executive")


def _scenario_dirs() -> list[Path]:
    """Return the scenario directories under golden_narratives/, sorted."""
    # A __pycache__ directory, should one appear here, would make any exact-count assertion
    # downstream fail for a reason unrelated to the scenarios. Excluded by name rather than by
    # tolerating a floor.
    return sorted(p for p in GOLDEN_DIR.iterdir() if p.is_dir() and p.name != "__pycache__")


def _read_meta(scenario_dir: Path) -> dict:
    return json.loads((scenario_dir / "meta.json").read_text(encoding="utf-8"))


def _read_golden(scenario_dir: Path, audience: str) -> str:
    """Read committed golden output. Trailing newline stripped for comparison."""
    text = (scenario_dir / f"{audience}.txt").read_text(encoding="utf-8")
    # Build script writes with trailing newline; renderer output does not have
    # a trailing newline. Strip exactly one to align.
    if text.endswith("\n"):
        text = text[:-1]
    return text


def _authorization_report(meta: dict):
    """Run an authorization scenario, on a changed copy of its bundle when it names a change."""
    roots = {}
    if "trust_root_filename" in meta:
        roots["trust_roots"] = read_trust_root_document(FIXTURES_DIR / meta["trust_root_filename"])
    with changed_bundle(FIXTURES_DIR / meta["bundle_dirname"], meta.get("bundle_change")) as bundle:
        return verify_path(
            bundle,
            registry_entry_path=FIXTURES_DIR / meta["registry_entry_filename"],
            trust_registry_path=FIXTURES_DIR / meta["trust_registry_filename"],
            evaluation_time=meta.get("evaluation_time", "2026-05-10T00:00:00Z"),
            **roots,
        )


def _render_for_meta(meta: dict) -> dict[str, str]:
    """Render live narratives for a scenario meta block."""
    if meta["context"] == "offline_verification":
        report = verify_path(FIXTURES_DIR / meta["bundle_filename"])
        narrative = render_verdict_narrative(report, audiences=AUDIENCES)
    elif meta["context"] == "authorization":
        # Rendered through the whole link and authorization path with real trust material, so the golden
        # is the text a counterparty receives rather than what a synthetic code list
        # would produce. Authorization is where a renderer can narrate an intact bundle as
        # a damaged one.
        report = _authorization_report(meta)
        narrative = render_verdict_narrative(report, audiences=AUDIENCES)
    elif meta["context"] == "registry_entry":
        narrative = render_narrative_from_codes(
            reason_codes=meta["reason_codes"],
            verdict=meta["verdict"],
            audiences=AUDIENCES,
            verdict_context="registry_entry",
        )
    else:
        raise ValueError(f"unknown context: {meta['context']!r}")
    return {
        "technical": narrative.technical or "",
        "compliance": narrative.compliance or "",
        "executive": narrative.executive or "",
    }


# ---------------------------------------------------------------------------
# Inventory invariants
# ---------------------------------------------------------------------------
def test_golden_directory_contains_at_least_nine_scenarios() -> None:
    """The initial golden set ships nine scenarios. Future scenarios may add more."""
    dirs = _scenario_dirs()
    # A single floor over all scenarios would let most of the authorization scenarios
    # be deleted with the suite green, so each context carries its own floor.
    assert len(dirs) >= 17, f"expected at least 17 scenarios, found {len(dirs)}"
    by_context: dict[str, int] = {}
    for meta in _all_metas():
        by_context[meta["context"]] = by_context.get(meta["context"], 0) + 1
    assert by_context.get("offline_verification", 0) >= 4, by_context
    assert by_context.get("registry_entry", 0) >= 5, by_context
    assert by_context.get("authorization", 0) >= 8, by_context


def test_every_scenario_has_meta_and_three_audience_files() -> None:
    """Each scenario directory has meta.json + technical.txt + compliance.txt
    + executive.txt. No partial scenarios."""
    for scenario_dir in _scenario_dirs():
        assert (scenario_dir / "meta.json").is_file(), scenario_dir
        for audience in AUDIENCES:
            assert (scenario_dir / f"{audience}.txt").is_file(), f"{scenario_dir} missing {audience}.txt"


VERDICT_WORDS = re.compile(r"\b(PASS|WARN|REVIEW|FAIL)\b")


def test_every_scenario_names_the_verdict_it_carries() -> None:
    """A scenario's id ends with its verdict, and the first verdict its description names is that
    verdict; a registry scenario's meta.json declares the same verdict. A scenario is named by its
    content, so a reader can tell what each golden shows from its name alone."""
    for scenario_dir in _scenario_dirs():
        meta = _read_meta(scenario_dir)
        verdict = scenario_dir.name.rsplit("_", 1)[-1].upper()
        assert verdict in ("PASS", "WARN", "REVIEW", "FAIL"), scenario_dir.name
        named = VERDICT_WORDS.search(meta["description"])
        assert named is not None and named.group(1) == verdict, (scenario_dir.name, meta["description"])
        if "verdict" in meta:
            assert meta["verdict"] == verdict, (scenario_dir.name, meta["verdict"])


def test_scenario_meta_has_required_fields() -> None:
    """Every meta.json declares scenario_id, description, context."""
    for scenario_dir in _scenario_dirs():
        meta = _read_meta(scenario_dir)
        assert meta["scenario_id"] == scenario_dir.name
        assert meta["description"]
        assert meta["context"] in ("offline_verification", "authorization", "registry_entry")
        if meta["context"] == "offline_verification":
            assert "bundle_filename" in meta
        elif meta["context"] == "authorization":
            assert "bundle_dirname" in meta
            assert "registry_entry_filename" in meta
            assert "trust_registry_filename" in meta
            assert meta.get("bundle_change") in (None, *BUNDLE_CHANGES), meta.get("bundle_change")
        else:
            assert "reason_codes" in meta
            assert "verdict" in meta


# ---------------------------------------------------------------------------
# Byte-identical comparison
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "scenario_dir",
    _scenario_dirs(),
    ids=lambda p: p.name,
)
def test_live_narrative_matches_golden_byte_identical(scenario_dir: Path) -> None:
    """Live renderer output equals the committed golden, byte for byte.

    This is the central regression gate. If this fails, either the renderer
    drifted or the catalog drifted. The fix is one of:
      1. The drift is a bug: fix it; goldens are correct.
      2. The drift is intentional: regenerate goldens via tools/build_golden.py
         and commit alongside the renderer change.
    """
    meta = _read_meta(scenario_dir)
    live = _render_for_meta(meta)
    for audience in AUDIENCES:
        golden = _read_golden(scenario_dir, audience)
        assert live[audience] == golden, (
            f"\n--- DRIFT in {scenario_dir.name} / {audience} ---\n"
            f"Run: python tools/build_golden.py\n"
            f"to regenerate if the change is intentional.\n"
        )


@pytest.mark.parametrize(
    "scenario_dir",
    _scenario_dirs(),
    ids=lambda p: p.name,
)
def test_live_narrative_is_deterministic_across_runs(scenario_dir: Path) -> None:
    """10 consecutive live renders produce byte-identical output."""
    meta = _read_meta(scenario_dir)
    hashes: dict[str, set[str]] = {a: set() for a in AUDIENCES}
    for _ in range(10):
        live = _render_for_meta(meta)
        for audience in AUDIENCES:
            hashes[audience].add(hashlib.sha256(live[audience].encode("utf-8")).hexdigest())
    for audience, hash_set in hashes.items():
        assert len(hash_set) == 1, f"{scenario_dir.name}/{audience} non-deterministic: {hash_set}"


# ---------------------------------------------------------------------------
# Coverage invariants: ensure scenario set covers verdict outcomes
# ---------------------------------------------------------------------------
def _all_metas() -> list[dict]:
    return [_read_meta(p) for p in _scenario_dirs()]


def test_scenarios_cover_pass_review_fail_outcomes() -> None:
    """The scenario set must include at least one PASS, one REVIEW, one FAIL."""
    verdicts = set()
    for meta in _all_metas():
        if meta["context"] == "offline_verification":
            from loquitur.verify.runner import verify_path as _vp

            report = _vp(FIXTURES_DIR / meta["bundle_filename"])
            verdicts.add(report.verdict)
        elif meta["context"] == "authorization":
            report = _authorization_report(meta)
            verdicts.add(report.verdict)
        else:
            verdicts.add(meta["verdict"])
    assert "PASS" in verdicts
    assert "REVIEW" in verdicts
    assert "FAIL" in verdicts


def test_scenarios_cover_both_verdict_contexts() -> None:
    """At least one scenario in each context: offline_verification and registry_entry."""
    contexts = {meta["context"] for meta in _all_metas()}
    assert "offline_verification" in contexts
    assert "registry_entry" in contexts
    # Without this context no golden covers an authorization failure, the case a renderer
    # can narrate as a proof-integrity failure.
    assert "authorization" in contexts


def test_scenarios_cover_multi_code_aggregation() -> None:
    """At least one scenario has 3+ active reason codes: the multi-code
    aggregation case the renderer must handle correctly."""
    multi_code_seen = False
    for meta in _all_metas():
        if meta["context"] == "registry_entry" and len(meta["reason_codes"]) >= 3:
            multi_code_seen = True
            break
    assert multi_code_seen


# ---------------------------------------------------------------------------
# Catalog-touched invariants
# ---------------------------------------------------------------------------
def test_catalog_wording_change_surfaces_as_drift() -> None:
    """If any reason code emits a paragraph that contains a fragment from the
    catalog headline, then catalog drift surfaces as a
    test_live_narrative_matches_golden_byte_identical failure. This documents the contract.
    """
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    # Pick a scenario known to emit at least one named code
    scenario_dir = GOLDEN_DIR / "registry_07_synthetic_conflict_review"
    technical = (scenario_dir / "technical.txt").read_text(encoding="utf-8")
    headline = catalog.get("CONFLICTING_EVIDENCE_DETECTED").technical.headline
    assert headline in technical, (
        "Golden technical.txt must contain the catalog headline. If this "
        "fails the catalog wording diverged from goldens."
    )


# ---------------------------------------------------------------------------
# Audience differentiation across all scenarios
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "scenario_dir",
    _scenario_dirs(),
    ids=lambda p: p.name,
)
def test_three_audiences_remain_byte_distinct(scenario_dir: Path) -> None:
    """For every scenario, the three audience outputs differ from each other."""
    technical = _read_golden(scenario_dir, "technical")
    compliance = _read_golden(scenario_dir, "compliance")
    executive = _read_golden(scenario_dir, "executive")
    assert technical != compliance, scenario_dir.name
    assert compliance != executive, scenario_dir.name
    assert technical != executive, scenario_dir.name


@pytest.mark.parametrize(
    "scenario_dir",
    _scenario_dirs(),
    ids=lambda p: p.name,
)
def test_executive_remains_shortest(scenario_dir: Path) -> None:
    """Executive is the shortest of the three audience outputs in every scenario."""
    technical = _read_golden(scenario_dir, "technical")
    compliance = _read_golden(scenario_dir, "compliance")
    executive = _read_golden(scenario_dir, "executive")
    assert len(executive) < len(technical), scenario_dir.name
    assert len(executive) < len(compliance), scenario_dir.name
