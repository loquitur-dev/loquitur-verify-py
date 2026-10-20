"""A path is read as it is written (report-contract.md section 5.3).

The verifier hands each path it is given, the input and every supplied document, to the file
system as it is written. On Windows it reads the path in the file namespace, step by step as
section 5.3 gives it, which is also how loquitur-verify-ts reads it, so both reference verifiers
read the same entry: a name keeps a trailing dot or space, ``NUL`` in a directory is an entry of
that name, and a path longer than MAX_PATH is found. The Win32 layer reads each of these
differently. A path whose root is ``\\\\.\\`` is read with ``\\\\?\\`` too, as section 5.3
gives it, in both verifiers.

Nothing is found at a path longer than the host lets a path or a name be, nor at the empty path.
"""

from __future__ import annotations

import contextlib
import errno
import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE, fixture_entry, fixture_trust_registry, write_json
from bundle_builder import Bundle

from loquitur.verify.host_path import file_namespace, host_path
from loquitur.verify.runner import verify_path

WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32", reason="the Win32 path layer that rewrites a path exists on Windows only"
)

# Each path as a Windows host reads it in the file namespace, given the working directory
# C:\work\dir and, for drive D:, the working directory D:\elsewhere. The cases that do not depend
# on the working directory are the ones Node's path.win32.toNamespacedPath gives, byte for byte,
# except the two prefixes it leaves to the Win32 layer: a \\.\ root, which is read with \\?\ in
# its place, and a share whose server's name begins with "." or "?", read with \\?\UNC\.
READINGS = [
    ("bundle.", "\\\\?\\C:\\work\\dir\\bundle."),
    ("bundle ", "\\\\?\\C:\\work\\dir\\bundle "),
    ("NUL", "\\\\?\\C:\\work\\dir\\NUL"),
    ("C:\\data\\nul", "\\\\?\\C:\\data\\nul"),
    ("C:/data//x/./y/../z/", "\\\\?\\C:\\data\\x\\z"),
    ("..\\..\\..\\..\\q", "\\\\?\\C:\\q"),
    ("C:\\", "\\\\?\\C:\\"),
    ("C:", "\\\\?\\C:\\work\\dir"),
    ("C:x", "\\\\?\\C:\\work\\dir\\x"),
    ("D:x", "\\\\?\\D:\\elsewhere\\x"),
    ("E:x", "\\\\?\\E:\\x"),
    ("\\x", "\\\\?\\C:\\x"),
    ("\\\\server\\share\\a\\..\\..\\b", "\\\\?\\UNC\\server\\share\\b"),
    ("\\\\server\\share", "\\\\?\\UNC\\server\\share\\"),
    ("\\\\server", "\\\\?\\C:\\server"),
    ("\\\\?\\C:\\x\\..\\y", "\\\\?\\C:\\y"),
    ("\\\\?\\C:\\", "\\\\?\\C:"),
    ("\\\\.\\C:\\", "\\\\?\\C:"),
    ("\\\\.\\nul", "\\\\?\\nul"),
    ("\\\\.\\C:\\x\\..\\..\\y", "\\\\?\\y"),
    ("\\\\.\\C:\\d\\b ", "\\\\?\\C:\\d\\b "),
    ("\\\\.\\C:\\d\\b.", "\\\\?\\C:\\d\\b."),
    ("//./C:/d/./b ", "\\\\?\\C:\\d\\b "),
    ("\\\\.\\UNC\\server\\share\\x", "\\\\?\\UNC\\server\\share\\x"),
    ("\\\\.\\C:\\..\\..", "\\\\?\\"),
    ("\\\\.foo\\share\\x", "\\\\?\\UNC\\.foo\\share\\x"),
    ("\\\\?foo\\share\\x", "\\\\?\\UNC\\?foo\\share\\x"),
    ("//?/C:/x", "\\\\?\\C:\\x"),
    ("\\\\?\\", "\\\\?\\C:\\?"),
    ("", ""),
]


@pytest.mark.parametrize(("path", "reading"), READINGS)
def test_the_windows_reading_of_a_path_step_by_step(path: str, reading: str) -> None:
    drives = {"D:": "D:\\elsewhere"}
    assert file_namespace(path, "C:\\work\\dir", lambda drive: drives.get(drive.upper())) == reading


def _surface(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": report["status"],
        "reason": report["outcome"]["reason"],
        "errors": [error["code"] for error in report["errors"]],
    }


def _copy_into(source: Path, destination: str) -> None:
    """Copy the directory ``source`` to ``destination``, a path in the file namespace."""
    shutil.copytree(host_path(source), destination)


@WINDOWS_ONLY
@pytest.mark.parametrize("name", ["bundle.", "bundle ", "NUL"])
def test_an_input_whose_name_the_win32_layer_rewrites_is_read_as_it_is_written(tmp_path: Path, name: str) -> None:
    source = Bundle().seal().write(tmp_path / "source")
    written = host_path(tmp_path) + "\\" + name
    _copy_into(source, written)
    try:
        # The Win32 layer would read "bundle." and "bundle " as "bundle", which is not there, and
        # "NUL" as the null device: input_not_found and unsupported_input, where the bundle is valid.
        assert _surface(verify_path(str(tmp_path / name)).to_dict()) == _surface(verify_path(source).to_dict())
        assert _surface(verify_path(source).to_dict())["status"] == "OFFLINE_OK"
    finally:
        shutil.rmtree(written)  # by its file-namespace path: the Win32 layer cannot name it


@WINDOWS_ONLY
@pytest.mark.parametrize(
    ("stored", "written"),
    [("bundle.", "bundle."), ("bundle ", "bundle "), ("bundle", "bundle "), ("bundle", "bundle.")],
)
def test_an_input_under_the_device_prefix_is_read_as_it_is_written(tmp_path: Path, stored: str, written: str) -> None:
    """A path whose root is \\\\.\\ names the entry written, as \\\\?\\ does.

    Read through the Win32 layer, which drops a trailing dot from every name and a trailing space
    from the last, ``bundle `` and ``bundle.`` would verify the directory ``bundle``, and
    ``bundle.`` itself would not be found.
    """
    source = Bundle().seal().write(tmp_path / "source")
    stored_at = host_path(tmp_path) + "\\" + stored
    _copy_into(source, stored_at)
    try:
        surface = _surface(verify_path("\\\\.\\" + str(tmp_path) + "\\" + written).to_dict())
    finally:
        shutil.rmtree(stored_at)
    if stored == written:
        assert surface == _surface(verify_path(source).to_dict())
        assert surface["status"] == "OFFLINE_OK"
    else:
        assert surface["errors"] == ["input_not_found"]


@WINDOWS_ONLY
@pytest.mark.parametrize(("stored", "written"), [("entry.json.", "entry.json."), ("entry.json", "entry.json ")])
def test_a_document_under_the_device_prefix_is_read_as_it_is_written(tmp_path: Path, stored: str, written: str) -> None:
    entry = write_json(tmp_path / "entry.json", fixture_entry())
    apart = tmp_path / "apart"
    apart.mkdir()
    shutil.copyfile(entry, host_path(apart) + "\\" + stored)
    try:
        surface = _surface(verify_path(BUNDLE, registry_entry_path="\\\\.\\" + str(apart) + "\\" + written).to_dict())
    finally:
        os.remove(host_path(apart) + "\\" + stored)
    plain = _surface(verify_path(BUNDLE, registry_entry_path=entry).to_dict())
    assert plain["errors"] == []
    if stored == written:
        assert surface == plain
    else:
        assert surface["errors"] == ["input_not_found"]


@WINDOWS_ONLY
def test_a_device_prefix_with_no_name_below_it_names_nothing(tmp_path: Path) -> None:
    drive = str(tmp_path)[:2]
    assert _surface(verify_path("\\\\.\\" + drive + "\\..\\..").to_dict())["errors"] == ["input_not_found"]


@WINDOWS_ONLY
def test_an_input_longer_than_max_path_is_found(tmp_path: Path) -> None:
    source = Bundle().seal().write(tmp_path / "source")
    deep = str(tmp_path)
    while len(deep) < 300:
        deep += "\\" + "d" * 40
    _copy_into(source, host_path(deep))
    try:
        assert len(deep) > 260
        # Read through the Win32 layer, the path is refused as not found: input_not_found.
        assert _surface(verify_path(deep).to_dict())["status"] == "OFFLINE_OK"
    finally:
        shutil.rmtree(host_path(str(tmp_path) + "\\" + "d" * 40))


@WINDOWS_ONLY
def test_the_null_device_is_named_by_its_device_path(tmp_path: Path) -> None:
    assert _surface(verify_path("\\\\.\\nul").to_dict())["errors"] == ["unsupported_input"]
    assert _surface(verify_path(str(tmp_path / "NUL")).to_dict())["errors"] == ["input_not_found"]


@WINDOWS_ONLY
def test_a_document_path_is_read_as_it_is_written(tmp_path: Path) -> None:
    entry = write_json(tmp_path / "entry.json", fixture_entry())
    trust = write_json(tmp_path / "trust.json", fixture_trust_registry())
    plain = _surface(verify_path(BUNDLE, registry_entry_path=entry, trust_registry_path=trust).to_dict())
    # In a directory of their own, so that no file carries the names without their last character.
    apart = tmp_path / "apart"
    apart.mkdir()
    shutil.copyfile(entry, host_path(apart) + "\\entry.json.")
    shutil.copyfile(trust, host_path(apart) + "\\trust.json ")
    try:
        written = verify_path(
            BUNDLE, registry_entry_path=str(apart / "entry.json."), trust_registry_path=str(apart / "trust.json ")
        ).to_dict()
    finally:
        os.remove(host_path(apart) + "\\entry.json.")
        os.remove(host_path(apart) + "\\trust.json ")
    # The Win32 layer would read both names without their last character, which names no file
    # there: registry_link_verification_failed, where the documents are the same as the plain run's.
    assert _surface(written) == plain
    assert plain["errors"] == []


@contextlib.contextmanager
def _stat_says_too_long(monkeypatch: pytest.MonkeyPatch, target: str) -> Iterator[None]:
    """os.stat fails with ENAMETOOLONG on ``target``: a path longer than the host lets any path be."""
    real_stat = os.stat
    wanted = Path(host_path(target))

    def stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, (str, os.PathLike)) and Path(os.fspath(path)) == wanted:
            raise OSError(errno.ENAMETOOLONG, "File name too long", os.fspath(path))
        return real_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", stat)
        yield


def test_a_path_longer_than_the_host_allows_finds_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ENAMETOOLONG is nothing found: no entry can have such a path. Read as a host failure, it
    would make the input filesystem_error and a registry entry an unread document."""
    long_input = str(tmp_path / "bundle")
    with _stat_says_too_long(monkeypatch, long_input):
        as_input = _surface(verify_path(long_input).to_dict())["errors"]
    entry = str(tmp_path / "entry.json")
    with _stat_says_too_long(monkeypatch, entry):
        as_entry = _surface(verify_path(BUNDLE, registry_entry_path=entry).to_dict())["errors"]
    assert (as_input, as_entry) == (["input_not_found"], ["input_not_found"])


def test_the_empty_input_path_names_nothing() -> None:
    # Path("") is Path("."), so read through Path the empty path would be the working directory.
    assert _surface(verify_path("").to_dict())["errors"] == ["input_not_found"]


# report-contract.md section 5.3, step 1: a path that begins with a drive letter and ":" and no
# separator is taken against the working directory the host keeps for that drive, else against
# the working directory when it is on that drive, else against the drive's root. A working
# directory on a share is on no drive; loquitur-verify-ts holds the same table.
DRIVE_RELATIVE_READINGS = [
    # (path, working directory, directory kept for drive D:, reading)
    ("D:x", "\\\\server\\share\\work", None, "\\\\?\\D:\\x"),
    ("D:", "\\\\server\\share\\work", None, "\\\\?\\D:\\"),
    ("D:x\\..\\..\\y", "\\\\server\\share\\work", None, "\\\\?\\D:\\y"),
    ("D:x", "\\\\server\\share\\work", "D:\\kept", "\\\\?\\D:\\kept\\x"),
    ("D:x", "C:\\work", "C:\\elsewhere", "\\\\?\\D:\\x"),
    ("D:x", "D:\\work", None, "\\\\?\\D:\\work\\x"),
    ("d:x", "D:\\work", None, "\\\\?\\d:\\work\\x"),
    ("D:x", "D:\\work", "D:\\kept", "\\\\?\\D:\\kept\\x"),
    ("D:..\\..\\x", "D:\\a", None, "\\\\?\\D:\\x"),
    ("D:\\x", "\\\\server\\share\\work", "D:\\kept", "\\\\?\\D:\\x"),
    ("D:/x", "\\\\server\\share\\work", "D:\\kept", "\\\\?\\D:\\x"),
]


@pytest.mark.parametrize(("path", "cwd", "kept", "reading"), DRIVE_RELATIVE_READINGS)
def test_a_drive_relative_path_is_taken_against_the_drives_directory_else_its_root(
    path: str, cwd: str, kept: str | None, reading: str
) -> None:
    assert file_namespace(path, cwd, lambda drive: kept if drive.upper() == "D:" else None) == reading


# Paths and working directories the table at the top does not reach, each read as Node's
# path.win32.toNamespacedPath reads it with process.cwd() answering that working directory, byte
# for byte: the "." shortcut to a working directory on a share, a lone separator, a share root
# with no share name, and the device roots with no name below them. The last rows take a working
# directory no Windows host gives, relative or rooted with no drive, where the reading stays
# relative or rooted and a reading of two characters or fewer hands the path over as written.
OTHER_READINGS = [
    # (path, working directory, reading)
    (".", "\\\\server\\share\\work", "\\\\?\\UNC\\server\\share\\work"),
    (".", "C:\\work\\dir", "\\\\?\\C:\\work\\dir"),
    ("\\", "C:\\work\\dir", "\\\\?\\C:\\"),
    ("/", "C:\\work\\dir", "\\\\?\\C:\\"),
    ("\\\\server\\", "C:\\work\\dir", "\\\\?\\C:\\server"),
    ("\\\\server\\\\", "C:\\work\\dir", "\\\\?\\C:\\server"),
    ("\\\\server\\share\\", "C:\\work\\dir", "\\\\?\\UNC\\server\\share\\"),
    ("\\\\?\\UNC\\server\\share\\x", "C:\\work\\dir", "\\\\?\\UNC\\server\\share\\x"),
    ("\\\\.\\", "C:\\work\\dir", "\\\\?\\C:\\"),
    ("\\\\.", "C:\\work\\dir", "\\\\?\\C:\\"),
    ("\\\\?", "C:\\work\\dir", "\\\\?\\C:\\?"),
    ("x", "work", "work\\x"),
    ("..\\..\\x", "work", "..\\x"),
    ("..\\..\\..\\x", "work", "..\\..\\x"),
    ("..", "work", ".."),
    ("a\\..\\..", "work", "a\\..\\.."),
    ("a\\..", "b\\..", "a\\.."),
    ("\\abc", "\\b", "\\abc"),
    ("\\a", "\\b", "\\a"),
    ("\\a\\..\\c", "/b", "\\a\\..\\c"),
]


@pytest.mark.parametrize(("path", "cwd", "reading"), OTHER_READINGS)
def test_the_windows_reading_of_the_other_roots_and_working_directories(path: str, cwd: str, reading: str) -> None:
    assert file_namespace(path, cwd) == reading


@pytest.mark.skipif(sys.platform == "win32", reason="the path is handed over unchanged on POSIX only")
def test_a_posix_host_is_handed_the_path_unchanged() -> None:
    assert host_path("bundle.") == "bundle."
    assert host_path(Path("a") / "NUL") == os.fspath(Path("a") / "NUL")


@WINDOWS_ONLY
def test_a_share_root_that_folds_is_handed_over_as_written() -> None:
    # Resolved, \\?\UNC\..\C:\d would be read as C:\d; kept as written, it names nothing.
    for path in ("\\\\..\\C:\\d", "\\\\?\\UNC\\..\\C:\\d", "\\\\server\\.\\d"):
        assert host_path(path) == path
