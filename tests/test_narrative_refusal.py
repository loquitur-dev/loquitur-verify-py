"""A narrative no catalog code grounds is refused, never published (verdict-grounds.md section 7.2).

An OFFLINE_REVIEW run whose components each reported cleanly gives the report renderers no
catalog code: a bundle with a member at a reserved name is one. Every audience refuses, the
public entry point carries the refusal instead of a narrative, the command line prints it, and
the run's exit code is the one it has without a narrative.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from bundle_builder import Bundle

from loquitur.verify.cli import main
from loquitur.verify.narrative import (
    NarrativeRefusedError,
    infer_active_reason_codes,
    render_compliance_narrative,
    render_executive_narrative,
    render_technical_narrative,
    render_verdict_narrative,
    report_dict_with_narrative,
)
from loquitur.verify.runner import verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _groundless_review(tmp_path: Path) -> Path:
    bundle = Bundle(FIXTURES / "valid_bundle")
    bundle.members["attestations/a.json"] = b"{}"
    return bundle.write(tmp_path / "bundle")


def _cli(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    saved = sys.stdout
    try:
        sys.stdout = out
        code = main(argv)
    finally:
        sys.stdout = saved
    return code, out.getvalue()


def test_the_run_is_a_review_with_no_inferred_code(tmp_path: Path) -> None:
    report = verify_path(_groundless_review(tmp_path))
    assert report.status == "OFFLINE_REVIEW"
    assert report.review_reasons == ("bundle_reserved_member",)
    assert infer_active_reason_codes(report) == ()


@pytest.mark.parametrize(
    "render", [render_technical_narrative, render_compliance_narrative, render_executive_narrative]
)
def test_every_audience_refuses(tmp_path: Path, render) -> None:
    report = verify_path(_groundless_review(tmp_path))
    with pytest.raises(NarrativeRefusedError, match="section 7.2"):
        render(report)


def test_the_entry_point_carries_the_refusal_and_no_narrative(tmp_path: Path) -> None:
    report = verify_path(_groundless_review(tmp_path))
    rendered = render_verdict_narrative(report, audiences=("technical", "compliance", "executive")).to_dict()
    assert (rendered["technical"], rendered["compliance"], rendered["executive"]) == (None, None, None)
    assert "section 7.2" in rendered["refused"]
    payload = report_dict_with_narrative(report, audiences=("technical",))
    assert payload["narrative"]["technical"] is None
    assert payload["narrative"]["refused"] == rendered["refused"]


def test_a_grounded_run_carries_no_refusal_member() -> None:
    report = verify_path(FIXTURES / "valid_bundle.zip")
    rendered = render_verdict_narrative(report, audiences=("technical",)).to_dict()
    assert "refused" not in rendered
    assert rendered["technical"].startswith("Offline verification produced a PASS verdict.")


def test_the_command_line_prints_the_refusal_and_keeps_the_exit_code(tmp_path: Path) -> None:
    bundle = str(_groundless_review(tmp_path))
    plain_code, _ = _cli([bundle, "--pretty"])
    code, out = _cli([bundle, "--pretty", "--narrative=technical,executive"])
    assert code == plain_code == 2
    assert out.count("(refused: no catalog reason code grounds this verdict") == 2
    assert "REVIEW verdict" not in out


def _failed_with_integrity_intact(tmp_path: Path, case: str):
    """A failed run whose integrity check holds: a link that does not hold, a committed FAIL
    verdict, or a trust registry refused as malformed."""
    bundle = Bundle()
    if case == "committed-fail":
        bundle.edit(
            "verification_receipt.json",
            lambda r: r.update(status="fail", reason_codes=["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"]),
        )
    root = bundle.seal().write(tmp_path / "bundle")
    entry = tmp_path / "entry.json"
    if case == "link-mismatch":
        bundle.link_entry(entry, manifest_hash="sha256:" + "0" * 64)
    elif case == "committed-fail":
        bundle.link_entry(entry, verdict="FAIL", reason_codes=["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"])
    else:
        bundle.link_entry(entry)
    kwargs = {}
    if case == "malformed-trust-registry":
        registry = tmp_path / "trust_registry.json"
        registry.write_text('{"object_type":"trust_registry"}', encoding="utf-8")
        kwargs = {"trust_registry_path": registry, "evaluation_time": "2026-05-10T00:00:00Z"}
    return verify_path(root, registry_entry_path=entry, **kwargs)


@pytest.mark.parametrize("case", ["link-mismatch", "committed-fail", "malformed-trust-registry"])
def test_a_failure_with_integrity_established_is_not_narrated_as_an_integrity_failure(
    tmp_path: Path, case: str
) -> None:
    """reason-codes.md section 9: narrated as an integrity failure, such a run would tell the reader
    that an intact bundle is not internally consistent and should be regenerated. With no other
    code it grounds nothing, and the narrative is refused (verdict-grounds.md section 7.2)."""
    report = _failed_with_integrity_intact(tmp_path, case)
    assert (report.status, "integrity" in report.checks_established) == ("OFFLINE_FAIL", True)
    assert "INTEGRITY_OFFLINE_FAIL" not in infer_active_reason_codes(report)
    rendered = render_verdict_narrative(report, audiences=("technical", "compliance", "executive")).to_dict()
    assert (rendered["technical"], rendered["compliance"], rendered["executive"]) == (None, None, None)
    assert "section 7.2" in rendered["refused"]
