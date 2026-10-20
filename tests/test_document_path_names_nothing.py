"""Nothing found at a supplied document path refuses the run as a whole (report-contract.md section 5.3).

A registry entry or a trust registry the operator names by a path at which nothing is found is
input_not_found, HOST_FAILURE, exit 5, as a bundle path is: nothing else is evaluated, and the
first whole-input row is reported whatever the bundle would have given. Something found that is
not a regular file keeps its own outcome, and the trust-root document is outside this rule.
"""

from __future__ import annotations

from pathlib import Path

from authorization_kit import BUNDLE, fixture_entry, fixture_trust_registry, write_json

from loquitur.verify import cli
from loquitur.verify.runner import verify_path


def _surface(report: dict) -> tuple:
    return (
        report["status"],
        report["verdict"],
        report["exit_code"],
        report["outcome"]["reason"],
        [error["code"] for error in report["errors"]],
        report["checks_requested"],
        report["checks_established"],
        report["review_reasons"],
        report["trust_registry"],
    )


def test_a_registry_entry_path_that_names_nothing_is_input_not_found(tmp_path: Path) -> None:
    report = verify_path(BUNDLE, registry_entry_path=tmp_path / "absent.json").to_dict()
    assert _surface(report) == (
        "HOST_FAILURE",
        None,
        5,
        "input_not_found",
        ["input_not_found"],
        ["structure", "integrity", "link"],
        [],
        [],
        None,
    )


def test_a_trust_registry_path_that_names_nothing_is_input_not_found(tmp_path: Path) -> None:
    entry = write_json(tmp_path / "entry.json", fixture_entry())
    report = verify_path(
        BUNDLE,
        registry_entry_path=entry,
        trust_registry_path=tmp_path / "absent.json",
        evaluation_time="2026-05-10T00:00:00Z",
    ).to_dict()
    assert _surface(report) == (
        "HOST_FAILURE",
        None,
        5,
        "input_not_found",
        ["input_not_found"],
        ["structure", "integrity", "link", "authorization"],
        [],
        [],
        None,
    )
    assert report["evaluation_time"] == "2026-05-10T00:00:00Z"


def test_a_library_given_a_trust_registry_path_naming_nothing_and_no_entry_is_input_not_found(tmp_path: Path) -> None:
    report = verify_path(BUNDLE, trust_registry_path=tmp_path / "absent.json").to_dict()
    assert _surface(report)[:5] == ("HOST_FAILURE", None, 5, "input_not_found", ["input_not_found"])
    assert report["checks_requested"] == ["structure", "integrity", "authorization"]


def test_input_not_found_comes_first_whatever_the_bundle_gives(tmp_path: Path) -> None:
    not_a_zip = tmp_path / "bundle.zip"
    not_a_zip.write_bytes(b"not a zip archive")
    report = verify_path(not_a_zip, registry_entry_path=tmp_path / "absent.json").to_dict()
    assert [error["code"] for error in report["errors"]] == ["input_not_found"]


def test_a_document_path_naming_a_directory_keeps_its_own_outcome(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory"
    directory.mkdir()
    as_entry = verify_path(BUNDLE, registry_entry_path=directory).to_dict()
    assert as_entry["status"] == "OFFLINE_FAIL"
    assert "registry_link_verification_failed" in [error["code"] for error in as_entry["errors"]]
    entry = write_json(tmp_path / "entry.json", fixture_entry())
    as_registry = verify_path(BUNDLE, registry_entry_path=entry, trust_registry_path=directory).to_dict()
    assert as_registry["status"] == "OFFLINE_FAIL"
    assert as_registry["trust_registry"]["authorization_status"] == "INVALID_TRUST_REGISTRY"


def test_the_command_line_exits_5(tmp_path: Path, capsys) -> None:
    registry = write_json(tmp_path / "registry.json", fixture_trust_registry())
    code = cli.main(
        [str(BUNDLE), "--json", "--registry-entry", str(tmp_path / "absent.json"), "--trust-registry", str(registry)]
    )
    assert code == 5
    capsys.readouterr()
