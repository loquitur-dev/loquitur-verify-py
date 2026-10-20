from __future__ import annotations

import json
from pathlib import Path

import pytest

from loquitur.verify.cli import main
from loquitur.verify.runner import EXIT_OFFLINE_FAIL, EXIT_OFFLINE_OK, EXIT_OFFLINE_REVIEW, verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"

EXPECTED_FIXTURES = {
    "valid_bundle": {
        "status": "OFFLINE_OK",
        "verdict": "PASS",
        "exit_code": EXIT_OFFLINE_OK,
        "checks": {
            "manifest_sha256": True,
            "manifest_files": True,
            "p1_input_hash": True,
            "envelope_links": True,
        },
        "note": "registry_entry_not_provided",
    },
    "tampered_manifest_bundle": {
        "status": "OFFLINE_FAIL",
        "verdict": "FAIL",
        "exit_code": EXIT_OFFLINE_FAIL,
        "checks": {
            "manifest_sha256": False,
            "manifest_files": True,
            "p1_input_hash": True,
            # False: the envelope links to a manifest that failed its sidecar, and a link
            # holds only against a manifest that verified, never against the stale sidecar
            # beside it.
            "envelope_links": False,
        },
        "note": "manifest_integrity_failed",
    },
    "tampered_canonical_input_bundle": {
        "status": "OFFLINE_FAIL",
        "verdict": "FAIL",
        "exit_code": EXIT_OFFLINE_FAIL,
        "checks": {
            "manifest_sha256": True,
            "manifest_files": True,
            "p1_input_hash": False,
            "envelope_links": True,
        },
        "note": "input_hash_mismatch",
    },
    "missing_canonical_input_bundle": {
        "status": "OFFLINE_REVIEW",
        "verdict": "REVIEW",
        "exit_code": EXIT_OFFLINE_REVIEW,
        "checks": {
            "manifest_sha256": True,
            "manifest_files": True,
            "canonical_input_present": False,
            "p1_input_hash": None,
            "envelope_links": True,
        },
        "note": "canonical_input_not_provided",
    },
}


def _fixture_paths(name: str) -> tuple[Path, Path]:
    return FIXTURES / name, FIXTURES / f"{name}.zip"


@pytest.mark.parametrize("fixture_name,expected", EXPECTED_FIXTURES.items())
def test_golden_fixture_directories_have_expected_status(fixture_name: str, expected: dict[str, object]) -> None:
    bundle_dir, _archive = _fixture_paths(fixture_name)

    report = verify_path(bundle_dir)
    payload = report.to_dict()

    assert report.status == expected["status"]
    assert report.verdict == expected["verdict"]
    assert report.exit_code == expected["exit_code"]
    for check_name, check_value in expected["checks"].items():
        assert payload["checks"][check_name] is check_value
    assert expected["note"] in payload["notes"]
    assert payload["registry"]["status"] == "REGISTRY_ENTRY_NOT_PROVIDED"
    assert payload["registry"]["signature_supported"] is False


@pytest.mark.parametrize("fixture_name,expected", EXPECTED_FIXTURES.items())
def test_golden_fixture_zip_archives_have_expected_status(fixture_name: str, expected: dict[str, object]) -> None:
    _bundle_dir, archive = _fixture_paths(fixture_name)

    report = verify_path(archive)
    payload = report.to_dict()

    assert report.status == expected["status"]
    assert report.verdict == expected["verdict"]
    assert report.exit_code == expected["exit_code"]
    assert payload["input"]["type"] == "zip"
    for check_name, check_value in expected["checks"].items():
        assert payload["checks"][check_name] is check_value


@pytest.mark.parametrize("fixture_name,expected", EXPECTED_FIXTURES.items())
def test_cli_json_contract_against_golden_zip_fixtures(
    fixture_name: str,
    expected: dict[str, object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _bundle_dir, archive = _fixture_paths(fixture_name)

    exit_code = main([str(archive), "--json"])

    captured = capsys.readouterr()
    assert captured.err == ""
    assert exit_code == expected["exit_code"]
    payload = json.loads(captured.out)
    assert payload["tool"] == "loquitur-verify"
    assert payload["checks_requested"] == ["structure", "integrity"]
    assert payload["status"] == expected["status"]
    assert payload["verdict"] == expected["verdict"]
    assert payload["checks"]["registry_signature"] == "UNSUPPORTED"


def test_missing_canonical_input_fixture_can_be_accepted_for_its_reason(capsys: pytest.CaptureFixture[str]) -> None:
    _bundle_dir, archive = _fixture_paths("missing_canonical_input_bundle")

    exit_code = main([str(archive), "--json", "--accept-review", "canonical_input_not_provided"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["review_reasons"] == ["canonical_input_not_provided"]
    assert exit_code == EXIT_OFFLINE_OK
    assert payload["status"] == "OFFLINE_REVIEW"
    assert payload["verdict"] == "REVIEW"


def test_fixture_readme_documents_expected_statuses() -> None:
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")

    for fixture_name, expected in EXPECTED_FIXTURES.items():
        assert fixture_name in readme
        assert expected["status"] in readme
        assert f"`{expected['exit_code']}`" in readme


def _fixture_readme_row(*names: str) -> tuple[str, int]:
    """Status and exit code of the first fixture README table row whose first cell names every one of ``names``."""
    for line in (FIXTURES / "README.md").read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and all(name in cells[0] for name in names):
            return cells[1].strip("`"), int(cells[2].strip("`"))
    raise AssertionError(f"the fixture README has no row naming {names}")


def test_fixture_readme_gives_the_authorization_pair_the_outcome_it_actually_produces() -> None:
    # A row can name a status the command does not return: an unpinned trust root is
    # refused rather than assumed, so the pair `authorization_valid_registry_entry.json` +
    # `authorization_valid_trust_registry.json` returns OFFLINE_REVIEW / exit 2, not OFFLINE_OK.
    # test_fixture_readme_documents_expected_statuses cannot see that, because it only
    # checks that each status string appears somewhere in the file. This runs the command
    # the row describes and compares the row with it.
    status, exit_code = _fixture_readme_row(
        "authorization_valid_registry_entry.json", "authorization_valid_trust_registry.json"
    )
    report = verify_path(
        FIXTURES / "link_valid_bundle",
        registry_entry_path=FIXTURES / "authorization_valid_registry_entry.json",
        trust_registry_path=FIXTURES / "authorization_valid_trust_registry.json",
    ).to_dict()
    assert (report["status"], report["exit_code"]) == (status, exit_code)
