"""What the bundle is: the directory given, or the folder a ZIP holds, and nothing beside it.

bundle-objects.md §1 says "A bundle is a directory, or a ZIP archive containing one", and
two readings of it give opposite verdicts on the same bytes:
  * a directory argument searched for a single child folder carrying manifest.json would
    verify the folder as the bundle, and any file beside it would be neither verified nor
    reported;
  * a ZIP holding bundle/ and an uncommitted file beside it would verify OFFLINE_OK with
    extra_files [] if only the selected folder were inventoried.
The rule: a directory argument must itself be the bundle root, and a file of a ZIP outside
the selected root makes the run REVIEW, reported by name.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from bundle_builder import Bundle

from loquitur.verify import cli
from loquitur.verify.runner import verify_path


def _report(path: Path) -> dict:
    report = verify_path(path).to_dict()
    assert cli.main([str(path), "--json"]) == report["exit_code"]
    return report


def _zip(tmp_path: Path, extra: dict[str, bytes], prefix: str = "bundle/") -> Path:
    bundle = Bundle().seal()
    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, data in bundle.members.items():
            zf.writestr(prefix + name, data)
        for name, data in extra.items():
            zf.writestr(name, data)
    return archive


@pytest.mark.parametrize(
    "extra",
    [{"uncommitted-evidence.txt": b"peer\n"}, {"annex/uncommitted-evidence.txt": b"peer\n"}],
    ids=["peer-file", "peer-directory"],
)
def test_a_file_beside_the_bundle_folder_in_a_zip_is_reported_and_reviewed(tmp_path: Path, extra: dict) -> None:
    report = _report(_zip(tmp_path, extra))
    assert report["status"] == "OFFLINE_REVIEW"
    assert "container_extra_files" in report["notes"]
    assert report["input"]["container_extra_files"] == sorted(extra)
    assert report["manifest"]["extra_files"] == []
    assert report["outcome"]["reason"] == "container_extra_files"


@pytest.mark.parametrize("prefix", ["bundle/", ""], ids=["nested", "top-level"])
def test_a_zip_holding_only_the_bundle_verifies(tmp_path: Path, prefix: str) -> None:
    report = _report(_zip(tmp_path, {}, prefix=prefix))
    assert report["status"] == "OFFLINE_OK"
    assert report["input"]["container_extra_files"] == []


def test_an_extra_file_inside_the_bundle_folder_is_still_an_undeclared_member(tmp_path: Path) -> None:
    report = _report(_zip(tmp_path, {"bundle/uncommitted-evidence.txt": b"inside\n"}))
    assert report["status"] == "OFFLINE_REVIEW"
    assert report["manifest"]["extra_files"] == ["uncommitted-evidence.txt"]
    assert report["input"]["container_extra_files"] == []


@pytest.mark.parametrize("peer", [False, True], ids=["alone", "with-a-peer-file"])
def test_a_directory_holding_a_bundle_folder_is_not_a_bundle(tmp_path: Path, peer: bool) -> None:
    wrapper = tmp_path / "input"
    Bundle().seal().write(wrapper / "bundle")
    if peer:
        (wrapper / "peer.txt").write_bytes(b"peer\n")
    report = _report(wrapper)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0]["code"] == "bundle_root_invalid"
    assert report["outcome"]["category"] == "unsupported_input_failure"
    # The bundle folder itself, given as the argument, is the bundle.
    assert _report(wrapper / "bundle")["status"] == "OFFLINE_OK"


def test_a_directory_whose_marker_differs_in_case_is_not_a_bundle_root(tmp_path: Path) -> None:
    root = Bundle().seal().write(tmp_path / "bundle")
    (root / "manifest.json").rename(root / "MANIFEST.JSON")
    report = _report(root)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0]["code"] == "bundle_root_invalid"
