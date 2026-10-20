from __future__ import annotations

import math
import tempfile
import zipfile
from pathlib import Path

import pytest

from loquitur.verify.archive import BundleRootError, extracted_zip, find_bundle_root, safe_extract_zip
from loquitur.verify.canonical import (
    CanonicalizationError,
    JsonLoadError,
    canonical_json_bytes,
    file_sha256,
    loads_json_bytes,
)
from loquitur.verify.runner import (
    EXIT_HOST_FAILURE,
    EXIT_INTERNAL_ERROR,
    exit_code_for_status,
    verify_path,
)


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def test_canonical_helpers_reject_non_jcs_values_and_bad_json(tmp_path: Path) -> None:
    with pytest.raises(CanonicalizationError, match="integer outside"):
        canonical_json_bytes({"too_large": 9_007_199_254_740_992})
    with pytest.raises(CanonicalizationError, match="non-finite"):
        canonical_json_bytes({"nan": math.nan})
    with pytest.raises(CanonicalizationError, match="keys must be strings"):
        canonical_json_bytes({1: "not-json-object-key"})
    with pytest.raises(CanonicalizationError, match="unsupported"):
        canonical_json_bytes({"set": {"x"}})

    with pytest.raises(JsonLoadError, match="invalid_json_encoding"):
        loads_json_bytes(b"\xff", name="bad.json")
    with pytest.raises(JsonLoadError, match="invalid_json"):
        loads_json_bytes(b"{", name="bad.json")

    large_file = tmp_path / "large.bin"
    large_file.write_bytes((b"abc123" * 200_000) + b"tail")
    assert len(file_sha256(large_file)) == 64


def test_archive_helpers_cover_keep_extracted_and_invalid_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The kept extraction lands in the temporary directory tempfile names; pointing that at
    # tmp_path leaves nothing behind in the host's own temporary directory once pytest cleans up.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/p1.json": b"{}"})

    destination = tmp_path / "dest"
    members = safe_extract_zip(archive, destination)
    assert members == ["bundle/manifest.json", "bundle/p1.json"]
    assert (destination / "bundle" / "manifest.json").exists()

    with pytest.raises(BundleRootError, match="invalid_bundle_root_marker"):
        find_bundle_root(destination, marker_name="nested/manifest.json")

    with extracted_zip(archive, keep_extracted=True) as extracted:
        kept = extracted
        assert (kept / "bundle" / "manifest.json").exists()
    assert kept.exists()
    assert kept.name in {child.name for child in tmp_path.iterdir()}


def test_runner_reports_expected_input_and_archive_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.zip"
    missing_report = verify_path(missing)
    # Nothing found at the input path is a host-class refusal (report-contract.md section 5.3).
    assert missing_report.status == "HOST_FAILURE"
    assert missing_report.exit_code == EXIT_HOST_FAILURE
    assert missing_report.errors[0]["code"] == "input_not_found"

    not_zip = tmp_path / "not-a-zip.zip"
    not_zip.write_bytes(b"not a zip")
    invalid_report = verify_path(not_zip)
    assert invalid_report.status == "OFFLINE_FAIL"
    assert invalid_report.input_type == "zip"
    assert invalid_report.errors[0]["code"] == "invalid_zip"

    unsafe = tmp_path / "unsafe.zip"
    _write_zip(unsafe, {"../escape.txt": b"bad"})
    unsafe_report = verify_path(unsafe)
    assert unsafe_report.status == "OFFLINE_FAIL"
    assert unsafe_report.errors[0]["code"] == "archive_unsafe_member"

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    empty_report = verify_path(empty_dir)
    assert empty_report.status == "OFFLINE_FAIL"
    assert empty_report.errors[0]["code"] == "bundle_root_invalid"

    weird_file = tmp_path / "bundle.txt"
    weird_file.write_text("plain", encoding="utf-8")
    file_report = verify_path(weird_file)
    assert file_report.status == "OFFLINE_FAIL"
    assert file_report.errors[0]["code"] == "invalid_zip"

    assert exit_code_for_status("UNKNOWN_STATUS") == EXIT_INTERNAL_ERROR
