"""A directory bundle may not contain links: symbolic links, junctions or reparse points.

threat-model.md section 1 requires that no path derived from attacker-controlled bytes resolve
outside the extraction directory, and a ZIP member that is a symlink is refused. A directory
bundle is held to the same rule, because a reader that follows links fails it:
  * the inventory would descend a junction to a directory outside the root and write the
    names of the files it found there into manifest.extra_files;
  * a junction loop, or a single dangling junction, would abort the inventory with an OSError
    reported as manifest_read_failed, for a byte-perfect manifest;
  * a declared member reached through an alias inside the bundle would verify under two names;
  * on POSIX, a structural member such as manifest.json could be a symlink to a file
    outside the root and would be read through it.
Links are refused anywhere in the bundle, and reported by their own names only.

Links are made at test time: junctions on Windows (no privilege needed), symbolic links on
POSIX. A case skips, with the reason, only when the host refuses to create a directory link.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from bundle_builder import Bundle, sha

from loquitur.verify import cli
from loquitur.verify.runner import verify_path

SENTINEL = b"outside the bundle root\n"


def _directory_link(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
        else:
            os.symlink(target, link, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"a directory link could not be created on this host: {exc}")


def _remove_link(path: Path) -> None:
    """Remove one link itself, never what it names.

    POSIX removes a symbolic link with unlink(2) whatever it points at: rmdir(2) on a link to a
    directory fails with ENOTDIR, and ``is_dir()`` follows the link and answers True, so a
    helper that chose by ``is_dir()`` would fail on Linux. Windows removes a junction or a directory symbolic link
    as a directory, and a file symbolic link as a file, and the link's own attributes say which.
    """
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    if os.name == "nt" and attributes & stat.FILE_ATTRIBUTE_DIRECTORY:
        os.rmdir(path)
    else:
        os.unlink(path)


def _remove_links(root: Path) -> None:
    """Remove every link under ``root`` without following it, so tmp_path cleanup cannot."""
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = Path(directory) / name
            status = os.lstat(path)
            if stat.S_ISLNK(status.st_mode) or getattr(status, "st_file_attributes", 0) & 0x400:
                _remove_link(path)


@pytest.fixture
def outside(tmp_path: Path):
    directory = tmp_path / "outside"
    directory.mkdir()
    (directory / "sentinel.txt").write_bytes(SENTINEL)
    (directory / "other-outside-name.txt").write_bytes(b"other\n")
    yield directory


@pytest.fixture
def cleanup(tmp_path: Path):
    yield
    _remove_links(tmp_path)


def _declared_bundle(tmp_path: Path, *declared: str) -> Path:
    bundle = Bundle()
    bundle.edit("manifest.json", lambda m: m["files"].update({name: "sha256:" + sha(SENTINEL) for name in declared}))
    return bundle.seal().write(tmp_path / "bundle")


def _report(root: Path) -> dict:
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


def _assert_refused(report: dict, link_name: str) -> None:
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_files"] is False
    assert report["errors"][0] == {"code": "unsafe_bundle_member"}
    assert f"unsafe_bundle_member:link:{link_name}" in report["notes"]
    assert report["outcome"]["category"] == "archive_safety_failure"
    serialized = json.dumps(report)
    assert "other-outside-name.txt" not in serialized


def test_a_declared_member_through_a_link_to_outside_is_refused(tmp_path: Path, outside: Path, cleanup) -> None:
    root = _declared_bundle(tmp_path / "linked", "attached/sentinel.txt")
    _directory_link(root / "attached", outside)
    report = _report(root)
    _assert_refused(report, "attached")
    check = next(c for c in report["manifest"]["file_checks"] if c["name"] == "attached/sentinel.txt")
    assert check["error"] == "unsafe_bundle_member"
    assert check["actual_sha256"] is None
    # What is not a link inside the bundle still verifies: the root itself reached through a
    # link, and a hard link to the same outside file (indistinguishable from a regular file).
    real = Bundle().seal().write(tmp_path / "real")
    _directory_link(tmp_path / "via", real)
    assert _report(tmp_path / "via")["status"] == "OFFLINE_OK"
    hard = _declared_bundle(tmp_path / "hard", "attached.txt")
    try:
        os.link(outside / "sentinel.txt", hard / "attached.txt")
    except OSError:  # pragma: no cover - a filesystem without hard links holds no such case
        return
    assert _report(hard)["status"] == "OFFLINE_OK"


def test_an_intermediate_link_component_is_refused(tmp_path: Path, outside: Path, cleanup) -> None:
    root = _declared_bundle(tmp_path, "sub/link/sentinel.txt")
    (root / "sub").mkdir()
    _directory_link(root / "sub" / "link", outside)
    _assert_refused(_report(root), "sub/link")


def test_a_link_to_a_sibling_sharing_the_root_name_prefix_is_refused(tmp_path: Path, cleanup) -> None:
    root = _declared_bundle(tmp_path, "attached/sentinel.txt")
    evil = tmp_path / "bundle-evil"
    evil.mkdir()
    (evil / "sentinel.txt").write_bytes(SENTINEL)
    _directory_link(root / "attached", evil)
    _assert_refused(_report(root), "attached")


def test_a_dangling_link_is_refused_not_misreported_as_a_manifest_read(tmp_path: Path, cleanup) -> None:
    root = _declared_bundle(tmp_path, "attached/sentinel.txt")
    target = tmp_path / "gone"
    target.mkdir()
    _directory_link(root / "attached", target)
    target.rmdir()
    report = _report(root)
    _assert_refused(report, "attached")
    assert report["checks"]["manifest_sha256"] is True
    assert "manifest_read_failed" not in json.dumps(report["errors"])


def test_an_alias_inside_the_bundle_is_refused(tmp_path: Path, cleanup) -> None:
    bundle = Bundle()
    bundle.members["real/sentinel.txt"] = SENTINEL
    bundle.edit("manifest.json", lambda m: m["files"].update({"real/sentinel.txt": "", "alias/sentinel.txt": ""}))
    bundle.seal()
    bundle.edit("manifest.json", lambda m: m["files"].update({"alias/sentinel.txt": sha(SENTINEL)})).seal(files=False)
    root = bundle.write(tmp_path / "bundle")
    _directory_link(root / "alias", root / "real")
    _assert_refused(_report(root), "alias")


def test_an_undeclared_link_to_outside_is_refused_and_lists_no_outside_name(
    tmp_path: Path, outside: Path, cleanup
) -> None:
    root = Bundle().seal().write(tmp_path / "bundle")
    _directory_link(root / "attached", outside)
    report = _report(root)
    _assert_refused(report, "attached")
    assert report["manifest"]["extra_files"] == []


def test_a_link_loop_is_refused(tmp_path: Path, cleanup) -> None:
    root = Bundle().seal().write(tmp_path / "bundle")
    _directory_link(root / "loop", root)
    report = _report(root)
    _assert_refused(report, "loop")
    assert report["checks"]["manifest_sha256"] is True


def test_a_structural_member_that_is_a_link_is_refused(tmp_path: Path, cleanup) -> None:
    """manifest.json as a file symlink to a copy outside the root.

    Creating a file symlink needs a privilege Windows withholds by default (WinError 1314).
    Where the host refuses it, the structural name is made a junction instead: a different
    link type, the same rule, and a run of the suite never reports a host-dependent skip.
    """
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    outside_manifest = tmp_path / "outside-manifest" / "manifest.json"
    outside_manifest.parent.mkdir()
    outside_manifest.write_bytes(bundle.members["manifest.json"])
    (root / "manifest.json").unlink()
    try:
        os.symlink(outside_manifest, root / "manifest.json")
    except OSError:
        _directory_link(root / "manifest.json", outside_manifest.parent)
    report = _report(root)
    assert report["status"] == "OFFLINE_FAIL"
    # The link refuses the member, and the manifest layer, which cannot read it, is refused after it.
    assert [error["code"] for error in report["errors"]] == ["unsafe_bundle_member", "manifest_verification_failed"]
    assert "unsafe_bundle_member:link:manifest.json" in report["notes"]


def test_the_inventory_names_links_and_never_descends_them(tmp_path: Path, outside: Path, cleanup) -> None:
    from loquitur.verify.members import bundle_inventory

    root = Bundle().seal().write(tmp_path / "bundle")
    _directory_link(root / "attached", outside)
    inventory = bundle_inventory(root)
    assert inventory.links == ("attached",)
    assert not any(name.startswith("attached/") for name in inventory.files)


def test_a_read_through_a_link_is_refused_by_the_reader_itself(tmp_path: Path, outside: Path, cleanup) -> None:
    from loquitur.verify.members import read_member_bytes

    root = Bundle().seal().write(tmp_path / "bundle")
    _directory_link(root / "attached", outside)
    with pytest.raises(OSError, match="unsafe_bundle_member:link:attached"):
        read_member_bytes(root, "attached/sentinel.txt")
