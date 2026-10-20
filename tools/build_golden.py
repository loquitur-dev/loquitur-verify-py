"""Build script for the verdict narrative golden fixtures.

This script regenerates the golden narrative outputs for every scenario
covered by the test suite. Run it manually after any catalog wording change
or any renderer behavior change, then commit the regenerated golden files.

The CI test suite (test_golden_narratives.py) compares the live renderer
output against these committed golden files for byte identity. A drift in
any direction surfaces as a test failure with a clear diff.

Usage, from the repository root, with ``loquitur-schemas`` importable::

    python tools/build_golden.py

Both halves matter. The path is relative to the repository root. And without
``loquitur-schemas`` every renderer entry point returns ``None``, and the coalescers below
turn that into empty strings: a run would empty every golden file, and the suite would
stay green afterwards, because tests/conftest.py skips the narrative modules on the same
missing import. ``_require_catalog`` refuses that run before anything is written, and an
empty render aborts the file it would have blanked.
Read ``git diff`` after running anyway: a wording change should touch the files you
expected.

Determinism: for the offline and registry scenarios this script reads only the
bundled catalog data and the fixture bundle ZIPs. The eight authorization
scenarios additionally read a fixture bundle directory and its registry-entry and
trust-registry JSON. No timestamps, no random state, no machine-dependent strings
enter the golden output. The same catalog version and the same scenarios give byte-identical
golden files.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from loquitur.verify.narrative import (
    render_narrative_from_codes,
    render_verdict_narrative,
)
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import read_trust_root_document

TESTS_DIR = Path(__file__).resolve().parents[1] / "tests"
GOLDEN_DIR = TESTS_DIR / "golden_narratives"
FIXTURES_DIR = TESTS_DIR / "fixtures"

# The named bundle changes live beside the tests, which import them the same way.
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
from narrative_bundles import changed_bundle  # noqa: E402

AUDIENCES: tuple[str, ...] = ("technical", "compliance", "executive")


def _require_catalog() -> None:
    """Refuse to regenerate unless the catalog that supplies the wording is loadable.

    Every ``render`` below coalesces ``None`` to ``""``. Without ``loquitur-schemas``
    that is what the renderer returns, so the script would overwrite the entire corpus
    with empty files and exit 0, and the suite would stay green, because
    tests/conftest.py skips the narrative modules on the same missing import. An
    empty golden compares equal to an empty live render. The corpus is the only
    regression gate on the wording a counterparty reads, so a regeneration that cannot
    produce wording must fail before it touches a single file.
    """
    try:
        from loquitur.schemas import load_reason_codes_catalog

        load_reason_codes_catalog()
    except Exception as exc:  # noqa: BLE001 - reported to the operator, not handled
        raise SystemExit(
            f"refusing to regenerate goldens: the reason-code catalog is unavailable ({exc}). "
            'Install the narrative extra (pip install -e ".[narrative]") and re-run. '
            "No golden file was written."
        ) from exc


@dataclass(frozen=True)
class OfflineScenario:
    """Scenario driven by an actual bundle ZIP through the offline verifier."""

    scenario_id: str
    bundle_filename: str
    description: str

    def render(self) -> dict[str, str]:
        report = verify_path(FIXTURES_DIR / self.bundle_filename)
        narrative = render_verdict_narrative(report, audiences=AUDIENCES)
        return {
            "technical": narrative.technical or "",
            "compliance": narrative.compliance or "",
            "executive": narrative.executive or "",
        }


@dataclass(frozen=True)
class RegistryEntryScenario:
    """Scenario driven by a synthetic (reason_codes, verdict) pair."""

    scenario_id: str
    reason_codes: tuple[str, ...]
    verdict: str
    description: str

    def render(self) -> dict[str, str]:
        narrative = render_narrative_from_codes(
            reason_codes=self.reason_codes,
            verdict=self.verdict,
            audiences=AUDIENCES,
            verdict_context="registry_entry",
        )
        return {
            "technical": narrative.technical or "",
            "compliance": narrative.compliance or "",
            "executive": narrative.executive or "",
        }


# The operator's evaluation time every authorization scenario is judged at: inside the windows of
# the valid fixture trust registry. Without one, authorization is never established.
AUTHORIZATION_EVALUATION_TIME = "2026-05-10T00:00:00Z"


@dataclass(frozen=True)
class AuthorizationScenario:
    """Scenario driven end-to-end through link and authorization with real trust material.

    Offline scenarios and synthetic code lists cover no authorization failure, and that is
    where a renderer can go wrong: an intact bundle with a revoked key must not be narrated
    as a damaged bundle. These run the whole path, so the golden text is what a counterparty
    actually receives rather than what a synthetic code list would produce.
    """

    scenario_id: str
    bundle_dirname: str
    registry_entry_filename: str
    trust_registry_filename: str
    description: str
    # A change named in tests/narrative_bundles.py, applied to a copy of the bundle.
    bundle_change: str | None = None
    # A trust-root document pinned for the run, and the evaluation time it is judged at; a run
    # with no pinned root is a REVIEW (trust_registry_root_not_pinned).
    trust_root_filename: str | None = None
    evaluation_time: str = AUTHORIZATION_EVALUATION_TIME

    def render(self) -> dict[str, str]:
        roots = {}
        if self.trust_root_filename is not None:
            roots["trust_roots"] = read_trust_root_document(FIXTURES_DIR / self.trust_root_filename)
        with changed_bundle(FIXTURES_DIR / self.bundle_dirname, self.bundle_change) as bundle:
            report = verify_path(
                bundle,
                registry_entry_path=FIXTURES_DIR / self.registry_entry_filename,
                trust_registry_path=FIXTURES_DIR / self.trust_registry_filename,
                evaluation_time=self.evaluation_time,
                **roots,
            )
        narrative = render_verdict_narrative(report, audiences=AUDIENCES)
        return {
            "technical": narrative.technical or "",
            "compliance": narrative.compliance or "",
            "executive": narrative.executive or "",
        }


SCENARIOS: tuple = (
    # 1-4: offline_verification context driven by actual fixture ZIPs
    OfflineScenario(
        scenario_id="offline_01_valid_bundle_pass",
        bundle_filename="valid_bundle.zip",
        description="Clean PASS: integrity verified end-to-end on a valid bundle.",
    ),
    OfflineScenario(
        scenario_id="offline_02_tampered_manifest_fail",
        bundle_filename="tampered_manifest_bundle.zip",
        description="FAIL: manifest content edited after sidecar hash produced.",
    ),
    OfflineScenario(
        scenario_id="offline_03_tampered_canonical_input_fail",
        bundle_filename="tampered_canonical_input_bundle.zip",
        description="FAIL: canonical_input.json modified after receipt issuance.",
    ),
    OfflineScenario(
        scenario_id="offline_04_missing_canonical_input_review",
        bundle_filename="missing_canonical_input_bundle.zip",
        description="REVIEW: canonical_input.json absent — replay incomplete.",
    ),
    # 5-9: registry_entry context driven by synthetic codes (synthetic registry scenarios)
    RegistryEntryScenario(
        scenario_id="registry_05_synthetic_clean_pass",
        reason_codes=("INTEGRITY_OK", "REQUIRED_CLAIMS_PRESENT", "REQUIRED_EVIDENCE_PRESENT", "FRESHNESS_OK"),
        verdict="PASS",
        description="Synthetic PASS: integrity, required claims, required evidence and freshness all hold.",
    ),
    RegistryEntryScenario(
        scenario_id="registry_06_synthetic_material_change_warn",
        reason_codes=("INTEGRITY_OK", "REQUIRED_CLAIMS_PRESENT", "MATERIAL_CHANGE_DETECTED"),
        verdict="WARN",
        description="Synthetic WARN: a supersession whose material change is above the policy threshold.",
    ),
    RegistryEntryScenario(
        scenario_id="registry_07_synthetic_conflict_review",
        reason_codes=("INTEGRITY_OK", "CONFLICTING_EVIDENCE_DETECTED"),
        verdict="REVIEW",
        description="Synthetic REVIEW: two documents of the bundle make conflicting claims.",
    ),
    RegistryEntryScenario(
        scenario_id="registry_08_synthetic_stale_warn",
        reason_codes=("INTEGRITY_OK", "MARK_STALE"),
        verdict="WARN",
        description="Synthetic WARN: the evidence is older than the policy freshness threshold.",
    ),
    RegistryEntryScenario(
        scenario_id="registry_09_synthetic_multi_code_review",
        reason_codes=(
            "INTEGRITY_OK",
            "CONFLICTING_EVIDENCE_DETECTED",
            "MARK_STALE",
            "MATERIAL_CHANGE_DETECTED",
        ),
        verdict="REVIEW",
        description="Synthetic REVIEW with several codes: a conflict, stale evidence and a material change in one bundle.",
    ),
    # 10-17: authorization context, driven end-to-end with real trust material.
    # The bundle is byte-perfect in every one of these: what differs is authority.
    AuthorizationScenario(
        scenario_id="authorization_10_verified_pass",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_quickstart_trust_registry.json",
        description="PASS with trust verified: authorized active key, in scope, within every window.",
        trust_root_filename="authorization_quickstart_trust_root.json",
        evaluation_time="2026-05-20T00:00:00Z",
    ),
    AuthorizationScenario(
        scenario_id="authorization_11_revoked_key_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_revoked_trust_registry.json",
        description="FAIL: evidence intact, issuer key revoked - a containment action after suspected compromise.",
    ),
    AuthorizationScenario(
        scenario_id="authorization_12_suspended_key_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_suspended_trust_registry.json",
        description="FAIL: evidence intact, issuer key on a reversible administrative hold.",
    ),
    AuthorizationScenario(
        scenario_id="authorization_13_expired_key_review",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_expired_trust_registry.json",
        description=(
            "REVIEW: evidence intact, issuer key expired before the operator's evaluation time; with no "
            "attested signing time a window is a question, not a failure."
        ),
    ),
    AuthorizationScenario(
        scenario_id="authorization_14_not_yet_effective_key_review",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_not_yet_effective_trust_registry.json",
        description=(
            "REVIEW: evidence intact, issuer key not yet authorized at the operator's evaluation time; with no "
            "attested signing time a window is a question, not a failure."
        ),
    ),
    AuthorizationScenario(
        scenario_id="authorization_15_scope_mismatch_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_disallowed_asset_type_trust_registry.json",
        description="FAIL: evidence intact, key valid and active, but not authorized for this asset type.",
    ),
    AuthorizationScenario(
        scenario_id="authorization_16_unknown_issuer_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_unknown_issuer_registry_entry.json",
        trust_registry_filename="authorization_valid_trust_registry.json",
        description="FAIL: evidence intact, issuer absent from the supplied trust registry.",
    ),
    AuthorizationScenario(
        scenario_id="authorization_17_signature_mismatch_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_signature_mismatch_registry_entry.json",
        trust_registry_filename="authorization_valid_trust_registry.json",
        description="FAIL: bundle consistent, but the registry entry signature does not verify.",
    ),
    # 18-20: the same out-of-scope signer beside a bundle whose integrity does not hold. Every
    # authorization code's wording starts from an intact record, so none of them is cited: the
    # integrity grounds are.
    AuthorizationScenario(
        scenario_id="authorization_18_declared_member_missing_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_disallowed_asset_type_trust_registry.json",
        description="FAIL: a declared member is missing, so the record is not called undamaged beside the scope finding.",
        bundle_change="declared_member_removed",
    ),
    AuthorizationScenario(
        scenario_id="authorization_19_envelope_incomplete_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_disallowed_asset_type_trust_registry.json",
        description="FAIL: the envelope sidecar is missing, so the record is not called undamaged beside the scope finding.",
        bundle_change="envelope_sidecar_removed",
    ),
    AuthorizationScenario(
        scenario_id="authorization_20_p1_absent_fail",
        bundle_dirname="link_valid_bundle",
        registry_entry_filename="authorization_valid_registry_entry.json",
        trust_registry_filename="authorization_disallowed_asset_type_trust_registry.json",
        description="FAIL: the P1 layer is absent, so the record is not called undamaged beside the scope finding.",
        bundle_change="p1_replaced_by_directory",
    ),
)


def write_golden_files() -> None:
    """Render every scenario to disk under ``golden_narratives/<scenario_id>/``."""
    _require_catalog()
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for scenario in SCENARIOS:
        scenario_dir = GOLDEN_DIR / scenario.scenario_id
        scenario_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
        }
        if isinstance(scenario, OfflineScenario):
            meta["context"] = "offline_verification"
            meta["bundle_filename"] = scenario.bundle_filename
        elif isinstance(scenario, AuthorizationScenario):
            meta["context"] = "authorization"
            meta["bundle_dirname"] = scenario.bundle_dirname
            meta["registry_entry_filename"] = scenario.registry_entry_filename
            meta["trust_registry_filename"] = scenario.trust_registry_filename
            if scenario.bundle_change is not None:
                meta["bundle_change"] = scenario.bundle_change
            if scenario.trust_root_filename is not None:
                meta["trust_root_filename"] = scenario.trust_root_filename
                meta["evaluation_time"] = scenario.evaluation_time
        else:
            meta["context"] = "registry_entry"
            meta["reason_codes"] = list(scenario.reason_codes)
            meta["verdict"] = scenario.verdict
        # newline="\n" explicitly. .gitattributes normalizes this repository to LF, and
        # write_text without it emits CRLF on Windows, so every regeneration would leave the
        # working tree differing from bytes that were already correct. Line-ending drift
        # is not cosmetic in a project whose artifacts commit to the SHA-256 of file bytes.
        (scenario_dir / "meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        narratives = scenario.render()
        for audience in AUDIENCES:
            # Second gate, per file. ``_require_catalog`` catches the whole corpus going
            # blank at once; this catches one scenario or one audience rendering empty:
            # a partial catalog, or an audience whose composition path returns None. An
            # empty golden is a test that passes while asserting nothing, so it is never
            # worth writing.
            if not narratives[audience].strip():
                raise SystemExit(
                    f"refusing to write an empty golden: {scenario.scenario_id}/{audience}.txt rendered no text."
                )
            (scenario_dir / f"{audience}.txt").write_text(narratives[audience] + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    write_golden_files()
    print(
        f"Wrote {len(SCENARIOS)} scenarios × {len(AUDIENCES)} audiences "
        f"= {len(SCENARIOS) * len(AUDIENCES)} golden files to {GOLDEN_DIR}"
    )
