"""A bundle whose manifest is missing is narrated as missing its manifest.

The runner records a manifest it could not find as ``manifest_verification_failed`` with the
message ``manifest_missing``; no report error has the code ``manifest_missing``. The narrative
infers OFFLINE_MANIFEST_MISSING from that recorded fact, so the reader is told the inventory
is missing instead of only that the wrapper and its contents disagree.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from loquitur.verify import infer_active_reason_codes, render_verdict_narrative
from loquitur.verify.runner import STATUS_OFFLINE_FAIL, verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _bundle_without_manifest(tmp_path: Path) -> Path:
    # A directory named manifest.json keeps the root marker in the listing (a directory input
    # is matched by name) while no regular manifest member is there to read.
    root = tmp_path / "bundle"
    shutil.copytree(FIXTURES / "valid_bundle", root)
    (root / "manifest.json").unlink()
    (root / "manifest.json").mkdir()
    return root


def test_a_missing_manifest_is_inferred_from_the_recorded_error(tmp_path: Path) -> None:
    report = verify_path(_bundle_without_manifest(tmp_path))
    assert report.status == STATUS_OFFLINE_FAIL
    assert report.manifest is None
    assert [(e["code"], e.get("message")) for e in report.errors] == [
        ("manifest_verification_failed", "manifest_missing")
    ]
    assert "OFFLINE_MANIFEST_MISSING" in infer_active_reason_codes(report)


def test_the_narrative_says_the_inventory_is_missing(tmp_path: Path) -> None:
    report = verify_path(_bundle_without_manifest(tmp_path))
    narrative = render_verdict_narrative(report, audiences=("executive",))
    assert "missing its inventory of contents" in narrative.executive


def test_a_missing_manifest_sidecar_is_not_narrated_as_a_missing_manifest(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    shutil.copytree(FIXTURES / "valid_bundle", root)
    (root / "manifest.sha256").unlink()
    report = verify_path(root)
    assert report.manifest is None
    assert "OFFLINE_MANIFEST_MISSING" not in infer_active_reason_codes(report)
