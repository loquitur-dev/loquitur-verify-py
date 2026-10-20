from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from loquitur.verify.archive import (
    ArchiveLoadError,
    ArchiveSafetyLimitError,
    BundleRootError,
    InvalidZipError,
    UnsafeZipMemberError,
    extracted_zip,
    find_bundle_root,
    read_zip_member_bytes,
    safe_extract_zip,
    validate_zip_members,
)


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def test_validate_zip_members_returns_normalized_file_names(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/docs/readme.txt": b"ok"})

    assert validate_zip_members(archive) == ["bundle/manifest.json", "bundle/docs/readme.txt"]


def test_safe_extract_zip_rejects_zip_slip_member(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    _write_zip(archive, {"../escape.txt": b"owned"})

    with pytest.raises(UnsafeZipMemberError):
        safe_extract_zip(archive, tmp_path / "out")

    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize(
    "member_name",
    [
        "/absolute.txt",
        "C:/windows.txt",
        r"C:\\windows.txt",
        "nested/../../escape.txt",
        "//unc/share.txt",
    ],
)
def test_safe_extract_zip_rejects_unsafe_member_forms(tmp_path: Path, member_name: str) -> None:
    archive = tmp_path / "bad.zip"
    _write_zip(archive, {member_name: b"owned"})

    with pytest.raises(UnsafeZipMemberError):
        safe_extract_zip(archive, tmp_path / "out")


def test_normalizer_rejects_nul_member_name() -> None:
    from loquitur.verify import archive

    with pytest.raises(UnsafeZipMemberError):
        archive._normalize_zip_member_name("bad\x00name.txt")


def test_safe_extract_zip_extracts_normal_bundle(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/p1.json": b"{}"})

    members = safe_extract_zip(archive, tmp_path / "out")

    assert members == ["bundle/manifest.json", "bundle/p1.json"]
    assert (tmp_path / "out" / "bundle" / "manifest.json").read_bytes() == b"{}"
    assert (tmp_path / "out" / "bundle" / "p1.json").read_bytes() == b"{}"


def test_find_bundle_root_supports_direct_and_single_nested_root(tmp_path: Path) -> None:
    direct = tmp_path / "direct"
    direct.mkdir()
    (direct / "manifest.json").write_text("{}", encoding="utf-8")
    assert find_bundle_root(direct) == direct

    nested_parent = tmp_path / "nested"
    (nested_parent / "bundle-a").mkdir(parents=True)
    (nested_parent / "bundle-a" / "manifest.json").write_text("{}", encoding="utf-8")
    assert find_bundle_root(nested_parent) == nested_parent / "bundle-a"


def test_find_bundle_root_rejects_missing_or_ambiguous_marker(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    with pytest.raises(BundleRootError, match="bundle_root_marker_missing"):
        find_bundle_root(missing)

    ambiguous = tmp_path / "ambiguous"
    (ambiguous / "a").mkdir(parents=True)
    (ambiguous / "b").mkdir(parents=True)
    (ambiguous / "a" / "manifest.json").write_text("{}", encoding="utf-8")
    (ambiguous / "b" / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(BundleRootError, match="ambiguous_bundle_root"):
        find_bundle_root(ambiguous)


def test_find_bundle_root_counts_only_a_file_named_like_the_marker(tmp_path: Path) -> None:
    # bundle-objects.md section 1: a ZIP level carries manifest.json only through a file entry.
    # A directory named manifest.json, empty or holding the bundle, never marks a root.
    beside = tmp_path / "beside"
    (beside / "manifest.json").mkdir(parents=True)
    (beside / "w").mkdir()
    (beside / "w" / "manifest.json").write_text("{}", encoding="utf-8")
    assert find_bundle_root(beside) == beside / "w"

    wrapper = tmp_path / "wrapper"
    (wrapper / "manifest.json").mkdir(parents=True)
    (wrapper / "manifest.json" / "manifest.json").write_text("{}", encoding="utf-8")
    assert find_bundle_root(wrapper) == wrapper / "manifest.json"

    peer = tmp_path / "peer"
    (peer / "w").mkdir(parents=True)
    (peer / "w" / "manifest.json").write_text("{}", encoding="utf-8")
    (peer / "x" / "manifest.json").mkdir(parents=True)
    assert find_bundle_root(peer) == peer / "w"

    only = tmp_path / "only"
    (only / "manifest.json").mkdir(parents=True)
    with pytest.raises(BundleRootError, match="bundle_root_marker_missing"):
        find_bundle_root(only)


def test_read_zip_member_bytes_reads_safe_member_without_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, {"bundle/manifest.json": b'{"ok": true}'})

    assert read_zip_member_bytes(archive, "bundle/manifest.json") == b'{"ok": true}'

    with pytest.raises(ArchiveLoadError, match="zip_member_missing"):
        read_zip_member_bytes(archive, "bundle/missing.json")

    with pytest.raises(UnsafeZipMemberError):
        read_zip_member_bytes(archive, "../escape.txt")


def test_read_zip_member_bytes_enforces_max_bytes(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, {"bundle/large.bin": b"abcdef"})

    with pytest.raises(ArchiveLoadError, match="zip_member_too_large"):
        read_zip_member_bytes(archive, "bundle/large.bin", max_bytes=3)


def test_extracted_zip_context_cleans_up_temp_directory(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, {"manifest.json": b"{}"})

    with extracted_zip(archive) as extracted:
        extracted_path = extracted
        assert (extracted / "manifest.json").exists()

    assert not extracted_path.exists()


def test_invalid_zip_is_reported_as_expected_archive_error(tmp_path: Path) -> None:
    archive = tmp_path / "not-a-zip.zip"
    archive.write_bytes(b"not a zip")

    with pytest.raises(InvalidZipError):
        validate_zip_members(archive)


def test_safe_extract_zip_rejects_duplicate_folded_paths(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bundle/manifest.json", b"{}")
        zf.writestr("bundle/MANIFEST.JSON", b"duplicate")

    with pytest.raises(UnsafeZipMemberError, match="duplicate_path"):
        safe_extract_zip(archive, tmp_path / "out")


def test_safe_extract_zip_rejects_symlink_like_members(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("bundle/link")
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("bundle/manifest.json", b"{}")
        zf.writestr(info, b"target")

    with pytest.raises(UnsafeZipMemberError, match="symlink"):
        safe_extract_zip(archive, tmp_path / "out")


def test_validate_zip_members_rejects_excessive_file_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from loquitur.verify import archive as archive_mod

    monkeypatch.setattr(archive_mod, "MAX_ZIP_FILE_COUNT", 1)
    archive = tmp_path / "too_many.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/p1.json": b"{}"})

    with pytest.raises(ArchiveSafetyLimitError, match="zip_too_many_files"):
        validate_zip_members(archive)


def test_validate_zip_members_rejects_oversized_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from loquitur.verify import archive as archive_mod

    monkeypatch.setattr(archive_mod, "MAX_ZIP_MEMBER_UNCOMPRESSED_BYTES", 3)
    archive = tmp_path / "oversized.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/large.bin": b"abcdef"})

    with pytest.raises(ArchiveSafetyLimitError, match="zip_member_too_large"):
        validate_zip_members(archive)


def test_validate_zip_members_rejects_excessive_total_uncompressed_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from loquitur.verify import archive as archive_mod

    monkeypatch.setattr(archive_mod, "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES", 5)
    archive = tmp_path / "too_large_total.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/p1.json": b"abcdef"})

    with pytest.raises(ArchiveSafetyLimitError, match="zip_total_uncompressed_size_too_large"):
        validate_zip_members(archive)


def test_validate_zip_members_rejects_suspicious_compression_ratio_of_a_small_member(tmp_path: Path) -> None:
    # 2 KiB deflated to a few bytes: above 100:1, and the bound has no size floor.
    archive = tmp_path / "suspicious_ratio.zip"
    _write_zip(archive, {"bundle/manifest.json": b"{}", "bundle/repeated.txt": b"A" * 2048})

    with pytest.raises(ArchiveSafetyLimitError, match="zip_suspicious_compression_ratio"):
        validate_zip_members(archive)


def test_verify_path_reports_archive_safety_failure_without_stack_trace(tmp_path: Path) -> None:
    pytest.importorskip("rfc8785")
    from loquitur.verify.runner import verify_path

    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bundle/manifest.json", b"{}")
        zf.writestr("bundle/MANIFEST.JSON", b"duplicate")

    report = verify_path(archive).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0]["code"] == "archive_unsafe_member"
    assert report["errors"][0]["type"] == "UnsafeZipMemberError"
    assert "Traceback" not in str(report)
    assert "issuer" not in str(report["errors"]).lower()
    assert "anchor" not in str(report["errors"]).lower()


def test_verify_path_names_an_input_that_is_neither_a_directory_nor_a_file(tmp_path: Path) -> None:
    """A path stat can see and neither branch can open.

    exists() says yes and is_dir() and is_file() both say no, so a dispatch with no branch
    for it would append nothing. The report that followed would be OFFLINE_FAIL with an
    empty `errors` tuple and an empty `notes` tuple, which _outcome_category would label
    proof_integrity_failure: an integrity verdict on a bundle that was never
    opened. The null device reaches it on Windows, by its device path: a path is read in the file
    namespace (report-contract.md section 5.3), where ``nul`` is an ordinary name. A FIFO reaches it
    everywhere else.
    """
    pytest.importorskip("rfc8785")
    from loquitur.verify.runner import verify_path

    if os.name == "nt":
        target = Path("\\\\.\\nul")
    else:
        target = tmp_path / "fifo"
        os.mkfifo(target)

    report = verify_path(target).to_dict()

    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"] == [{"code": "unsupported_input"}]
    assert report["outcome"]["category"] == "unsupported_input_failure"
    assert report["outcome"]["reason"] == "unsupported_input"
