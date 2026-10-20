"""Tests for CLI integration of the verdict narrative flag.

Invariants enforced:

- Without ``--narrative``, the CLI renders no narrative: the JSON report
  carries no ``narrative`` key and the pretty output no narrative section.
- With ``--narrative=<audiences>``, JSON output includes a ``narrative``
  object with the requested audience fields populated and the unselected
  audiences set to ``null``.
- With ``--narrative=<audiences>`` in pretty mode, the human-readable output
  appends one section per requested audience after the existing checks.
- Audience parsing accepts comma-separated values, deduplicates while
  preserving order, rejects unknown values with a clear error and a
  non-zero exit code.
- The exit code follows the verdict status whether or not ``--narrative`` is
  given.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from loquitur.verify.cli import (
    VALID_NARRATIVE_AUDIENCES,
    _parse_narrative_audiences,
    build_parser,
    main,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Audience parsing
# ---------------------------------------------------------------------------
def test_parse_single_audience() -> None:
    assert _parse_narrative_audiences("technical") == ("technical",)


def test_parse_multiple_audiences_preserves_order() -> None:
    assert _parse_narrative_audiences("compliance,technical") == (
        "compliance",
        "technical",
    )


def test_parse_audiences_tolerates_whitespace() -> None:
    assert _parse_narrative_audiences("technical , compliance ,executive") == (
        "technical",
        "compliance",
        "executive",
    )


def test_parse_audiences_deduplicates() -> None:
    assert _parse_narrative_audiences("technical,technical,compliance") == (
        "technical",
        "compliance",
    )


def test_parse_unknown_audience_raises() -> None:
    import argparse

    with pytest.raises(argparse.ArgumentTypeError, match="unknown narrative audience"):
        _parse_narrative_audiences("invalid")


def test_parse_empty_value_raises() -> None:
    import argparse

    with pytest.raises(argparse.ArgumentTypeError, match="requires at least one audience"):
        _parse_narrative_audiences("")


def test_parse_only_whitespace_raises() -> None:
    import argparse

    with pytest.raises(argparse.ArgumentTypeError, match="requires at least one audience"):
        _parse_narrative_audiences("   ")


def test_parse_all_three_audiences() -> None:
    assert _parse_narrative_audiences("technical,compliance,executive") == ("technical", "compliance", "executive")


def test_valid_audiences_constant_matches_module() -> None:
    """The CLI's accepted audience set matches the canonical narrative module."""
    assert VALID_NARRATIVE_AUDIENCES == ("technical", "compliance", "executive")


# ---------------------------------------------------------------------------
# Output without --narrative
# ---------------------------------------------------------------------------
def _run_cli_capture(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI ``main`` and capture stdout/stderr/exit_code."""
    import sys

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    saved_stdout, saved_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout = stdout_buf
        sys.stderr = stderr_buf
        try:
            code = main(argv)
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 0
    finally:
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def test_json_without_narrative_flag_has_no_narrative_key() -> None:
    """Without --narrative, the JSON report carries no narrative key."""
    code, out, _err = _run_cli_capture([str(FIXTURES / "valid_bundle.zip"), "--json"])
    assert code == 0
    payload = json.loads(out)
    assert "narrative" not in payload


def test_pretty_without_narrative_flag_has_no_narrative_section() -> None:
    """Without --narrative, the pretty output carries no narrative section."""
    code, out, _err = _run_cli_capture([str(FIXTURES / "valid_bundle.zip")])
    assert code == 0
    assert "narrative." not in out


# ---------------------------------------------------------------------------
# JSON output: with narrative
# ---------------------------------------------------------------------------
def test_json_with_narrative_technical_populates_only_technical() -> None:
    code, out, _err = _run_cli_capture([str(FIXTURES / "valid_bundle.zip"), "--json", "--narrative=technical"])
    assert code == 0
    payload = json.loads(out)
    assert "narrative" in payload
    assert payload["narrative"]["technical"] is not None
    assert payload["narrative"]["compliance"] is None
    assert payload["narrative"]["executive"] is None


def test_json_with_narrative_all_three() -> None:
    code, out, _err = _run_cli_capture(
        [
            str(FIXTURES / "valid_bundle.zip"),
            "--json",
            "--narrative=technical,compliance,executive",
        ]
    )
    assert code == 0
    payload = json.loads(out)
    assert payload["narrative"]["technical"] is not None
    assert payload["narrative"]["compliance"] is not None
    assert payload["narrative"]["executive"] is not None


def test_json_narrative_content_uses_catalog_wording() -> None:
    """Narrative content comes from the catalog, not from a CLI-local string."""
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    code, out, _err = _run_cli_capture(
        [
            str(FIXTURES / "tampered_manifest_bundle.zip"),
            "--json",
            "--narrative=technical",
        ]
    )
    payload = json.loads(out)
    technical = payload["narrative"]["technical"]
    expected_headline = catalog.get("INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH").technical.headline
    assert expected_headline in technical


# ---------------------------------------------------------------------------
# Pretty output: with narrative
# ---------------------------------------------------------------------------
def test_pretty_with_narrative_technical_appends_section() -> None:
    code, out, _err = _run_cli_capture([str(FIXTURES / "valid_bundle.zip"), "--narrative=technical"])
    assert code == 0
    assert "narrative.technical:" in out
    assert "PASS verdict" in out


def test_pretty_with_narrative_three_audiences_appends_three_sections() -> None:
    code, out, _err = _run_cli_capture(
        [
            str(FIXTURES / "valid_bundle.zip"),
            "--narrative=technical,compliance,executive",
        ]
    )
    assert code == 0
    assert "narrative.technical:" in out
    assert "narrative.compliance:" in out
    assert "narrative.executive:" in out


def test_pretty_narrative_sections_appear_in_requested_order() -> None:
    """The order of narrative sections in pretty output matches request order."""
    code, out, _err = _run_cli_capture(
        [
            str(FIXTURES / "valid_bundle.zip"),
            "--narrative=executive,technical,compliance",
        ]
    )
    assert code == 0
    pos_exec = out.index("narrative.executive:")
    pos_tech = out.index("narrative.technical:")
    pos_comp = out.index("narrative.compliance:")
    assert pos_exec < pos_tech < pos_comp


# ---------------------------------------------------------------------------
# Exit codes are unaffected by the narrative flag
# ---------------------------------------------------------------------------
def test_exit_code_unchanged_by_narrative_on_pass() -> None:
    code_no_narr, _, _ = _run_cli_capture([str(FIXTURES / "valid_bundle.zip")])
    code_narr, _, _ = _run_cli_capture([str(FIXTURES / "valid_bundle.zip"), "--narrative=technical"])
    assert code_no_narr == code_narr == 0


def test_exit_code_unchanged_by_narrative_on_fail() -> None:
    code_no_narr, _, _ = _run_cli_capture([str(FIXTURES / "tampered_manifest_bundle.zip")])
    code_narr, _, _ = _run_cli_capture([str(FIXTURES / "tampered_manifest_bundle.zip"), "--narrative=compliance"])
    assert code_no_narr == code_narr
    assert code_narr != 0


def test_exit_code_unchanged_by_narrative_on_review() -> None:
    code_no_narr, _, _ = _run_cli_capture([str(FIXTURES / "missing_canonical_input_bundle.zip")])
    code_narr, _, _ = _run_cli_capture(
        [
            str(FIXTURES / "missing_canonical_input_bundle.zip"),
            "--narrative=executive",
        ]
    )
    assert code_no_narr == code_narr


# ---------------------------------------------------------------------------
# Argument parsing failures exit with usage error
# ---------------------------------------------------------------------------
def test_invalid_audience_exits_with_usage_error() -> None:
    code, _out, err = _run_cli_capture(
        [
            str(FIXTURES / "valid_bundle.zip"),
            "--narrative=banana",
            "--json",
        ]
    )
    assert code != 0
    assert "unknown narrative audience" in err


def test_empty_audience_value_exits_with_usage_error() -> None:
    code, _out, err = _run_cli_capture(
        [
            str(FIXTURES / "valid_bundle.zip"),
            "--narrative=",
            "--json",
        ]
    )
    assert code != 0
    assert "at least one audience" in err


# ---------------------------------------------------------------------------
# Combined with --accept-review
# ---------------------------------------------------------------------------
def test_accept_review_combines_with_narrative() -> None:
    code, out, _err = _run_cli_capture(
        [
            str(FIXTURES / "missing_canonical_input_bundle.zip"),
            "--accept-review",
            "canonical_input_not_provided",
            "--narrative=executive",
        ]
    )
    # Every review reason of the run is accepted, so the process exits 0; the narrative flag does
    # not interfere.
    assert code == 0
    assert "narrative.executive:" in out


# ---------------------------------------------------------------------------
# Help text mentions narrative flag
# ---------------------------------------------------------------------------
def test_help_text_documents_narrative_flag() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "--narrative" in help_text
    assert "technical" in help_text
    assert "compliance" in help_text
    assert "executive" in help_text
