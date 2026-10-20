"""The report names the bundle root only where the input gives it a name.

A ZIP whose manifest.json sits at the archive's top level has no root folder: the bundle is
the archive's top level, which the verifier extracts into a fresh temporary directory. Naming
that directory would put a random host temporary name in the report, so two runs over the
same archive would differ. Such a run reports ``bundle_root_name`` as null; a ZIP with one
top-level folder and a directory input keep the folder's name.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from loquitur.verify.runner import verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE = FIXTURES / "valid_bundle"


def _zip(path: Path, prefix: str) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member in sorted(BUNDLE.rglob("*")):
            if member.is_file():
                archive.writestr(prefix + member.relative_to(BUNDLE).as_posix(), member.read_bytes())
    return path


def _report(path: Path) -> dict:
    return verify_path(path).to_dict()


def test_a_top_level_zip_reports_no_root_name_and_the_same_report_twice(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "top.zip", "")
    first = _report(archive)
    second = _report(archive)
    assert first["status"] == "OFFLINE_OK"
    assert first["input"]["bundle_root_name"] is None
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_a_zip_with_one_folder_reports_the_folder_name(tmp_path: Path) -> None:
    report = _report(_zip(tmp_path / "wrapped.zip", "evidence_folder/"))
    assert report["status"] == "OFFLINE_OK"
    assert report["input"]["bundle_root_name"] == "evidence_folder"


def test_a_directory_input_reports_the_directory_name() -> None:
    report = _report(BUNDLE)
    assert report["input"]["bundle_root_name"] == "valid_bundle"
