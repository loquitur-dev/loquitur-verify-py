"""A host failure is not an absence (report-contract.md section 5.3).

When the host fails an operation for any reason other than finding nothing at a path, the
verifier reports the failure, never the absence of what it looked for and never a finding about
content it did not read:

* failing to inspect or list the input, or to read an archive given as the input, refuses the
  input itself: filesystem_error;
* failing to list a directory on a member's path, or to inspect an entry on it, leaves the member
  unread: the reading layer's ``*_read_failed`` error;
* failing to inspect a registry entry's or a trust registry's path leaves the document unread;
* failing to read a member the host let the verifier find leaves the member unread and present:
  its layer is refused with its ``*_read_failed`` error and the presence flags record what was
  found (bundle-objects.md section 6).

A path at which nothing is found (no entry, a component that is not a directory, a link that
resolves to nothing or to itself) is absence. The root marker is matched exactly in the input's
listing, so a host that ignores letter case does not decide it.

The failures are injected where the verifier calls the host, so they hold on every host; the last
tests make the listing failures real where the host can, and say why they are skipped where not.
"""

from __future__ import annotations

import contextlib
import errno
import os
import subprocess
import sys
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE, fixture_entry, fixture_trust_registry, write_json
from bundle_builder import Bundle

import loquitur.verify.archive as archive
import loquitur.verify.runner as runner
from loquitur.verify.host_path import host_path
from loquitur.verify.runner import verify_path


def _host(path: Path) -> Path:
    """The path the verifier hands the host for ``path``, read as it is written (report-contract.md section 5.3)."""
    return Path(host_path(path))


def _denied(path: object) -> PermissionError:
    return PermissionError(errno.EACCES, "Permission denied", os.fspath(path))


def _surface(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": report["status"],
        "reason": report["outcome"]["reason"],
        "errors": [error["code"] for error in report["errors"]],
    }


def _bundle_with_subdirectory(root: Path) -> Path:
    """The link fixture bundle with one more declared member, sub/extra.json."""
    bundle = Bundle()
    bundle.set_json("sub/extra.json", {"note": "declared, inside a subdirectory"})
    bundle.edit("manifest.json", lambda m: m["files"].update({"sub/extra.json": ""}))
    bundle.seal()
    return bundle.write(root / "bundle")


@contextlib.contextmanager
def _refusing_listing(monkeypatch: pytest.MonkeyPatch, refused: Callable[[str], bool]) -> Iterator[list[str]]:
    """os.listdir and os.scandir fail with EACCES on every directory ``refused`` selects."""
    real_listdir, real_scandir = os.listdir, os.scandir
    seen: list[str] = []

    def listdir(path: Any = ".") -> list[str]:
        if refused(os.fspath(path)):
            seen.append(os.fspath(path))
            raise _denied(path)
        return real_listdir(path)

    def scandir(path: Any = ".") -> Any:
        if refused(os.fspath(path)):
            seen.append(os.fspath(path))
            raise _denied(path)
        return real_scandir(path)

    with monkeypatch.context() as patch:
        patch.setattr(os, "listdir", listdir)
        patch.setattr(os, "scandir", scandir)
        yield seen


class _Uninspectable:
    """A directory entry whose inspection the host refuses, as under a directory without search permission."""

    def __init__(self, entry: os.DirEntry[str]) -> None:
        self.name = entry.name
        self.path = entry.path

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        raise _denied(self.path)

    def is_symlink(self) -> bool:
        raise _denied(self.path)


@contextlib.contextmanager
def _refusing_inspection(monkeypatch: pytest.MonkeyPatch, root: Path) -> Iterator[list[str]]:
    """Every entry under ``root`` is listed and cannot be inspected: a POSIX directory with read
    permission and no search permission."""
    real_lstat, real_scandir = os.lstat, os.scandir
    prefix = os.fspath(_host(root)) + os.sep
    seen: list[str] = []

    def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(path).startswith(prefix):
            seen.append(os.fspath(path))
            raise _denied(path)
        return real_lstat(path, *args, **kwargs)

    @contextlib.contextmanager
    def scandir(path: Any = ".") -> Iterator[list[Any]]:
        with real_scandir(path) as entries:
            yield [_Uninspectable(entry) for entry in entries]

    with monkeypatch.context() as patch:
        patch.setattr(os, "lstat", lstat)
        patch.setattr(os, "scandir", scandir)
        yield seen


def test_the_baseline_verifies(tmp_path: Path) -> None:
    root = _bundle_with_subdirectory(tmp_path)
    assert _surface(verify_path(root).to_dict()) == {
        "status": "OFFLINE_OK",
        "reason": "local_integrity_checks_passed",
        "errors": [],
    }


def test_an_input_directory_the_host_fails_to_list_is_refused_as_filesystem_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bundle_with_subdirectory(tmp_path)
    entry = Bundle().link_entry(tmp_path / "entry.json")
    want = {"status": "HOST_FAILURE", "reason": "filesystem_error", "errors": ["filesystem_error"]}
    for kwargs in ({}, {"registry_entry_path": entry}):
        with _refusing_listing(monkeypatch, lambda p: Path(p) == _host(root)) as seen:
            assert _surface(verify_path(root, **kwargs).to_dict()) == want
        assert seen, "the host was never asked to list the input"


def test_an_input_the_host_fails_to_inspect_is_refused_as_filesystem_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bundle_with_subdirectory(tmp_path)
    with _refusing_stat_of(monkeypatch, root):
        report = verify_path(root).to_dict()
    assert _surface(report) == {"status": "HOST_FAILURE", "reason": "filesystem_error", "errors": ["filesystem_error"]}


def test_a_declared_member_in_a_directory_the_host_fails_to_list_is_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bundle_with_subdirectory(tmp_path)
    with _refusing_listing(monkeypatch, lambda p: Path(p) == _host(root) / "sub") as seen:
        report = verify_path(root).to_dict()
    assert seen
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "reason": "bundle_inventory_failed",
        "errors": ["bundle_inventory_failed", "manifest_read_failed"],
    }


def _bundle_with_undeclared_directory(root: Path) -> Path:
    """The link fixture bundle with an empty directory no manifest declares: sub."""
    bundle_root = Bundle().seal().write(root / "bundle")
    (bundle_root / "sub").mkdir()
    return bundle_root


def test_an_undeclared_directory_the_host_fails_to_list_is_a_host_failure_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """bundle_inventory_failed is the host's (report-contract.md section 5.3), and an inventory that
    fails takes the place of a link and of nothing else (bundle-objects.md section 1): it fails no
    layer, so the run is HOST_FAILURE, exit 5, never OFFLINE_FAIL, as loquitur-verify-ts reports it.
    The file check is not established, and the manifest's own checks still hold."""
    root = _bundle_with_undeclared_directory(tmp_path)
    with _refusing_listing(monkeypatch, lambda p: Path(p) == _host(root) / "sub") as seen:
        report = verify_path(root).to_dict()
    assert seen
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "reason": "bundle_inventory_failed",
        "errors": ["bundle_inventory_failed"],
    }
    assert report["exit_code"] == 5
    assert "manifest_integrity_failed" not in report["notes"]
    assert report["checks"]["manifest_files"] is False
    assert report["checks"]["manifest_sha256"] is True


def test_the_manifest_layer_reads_the_runs_failed_enumeration_and_walks_nothing_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The enumeration that decided the run is the one the manifest layer reads: a second walk of a
    bundle the host failed to list once could answer otherwise, and establish a file check over an
    inventory the run reports as failed."""
    root = _bundle_with_undeclared_directory(tmp_path)
    refusals: list[str] = []

    def first_listing_of_sub(path: str) -> bool:
        if Path(path) == _host(root) / "sub" and not refusals:
            refusals.append(path)
            return True
        return False

    with _refusing_listing(monkeypatch, first_listing_of_sub) as seen:
        report = verify_path(root).to_dict()
    assert seen == refusals
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "reason": "bundle_inventory_failed",
        "errors": ["bundle_inventory_failed"],
    }
    assert report["checks"]["manifest_files"] is False


def test_members_the_host_fails_to_inspect_are_unread_in_every_layer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bundle_with_subdirectory(tmp_path)
    with _refusing_inspection(monkeypatch, root) as seen:
        report = verify_path(root).to_dict()
    assert seen
    # Each layer reports its own read failure, the receipt's at every level; none reports a
    # member as absent or as failing its contract: manifest.json is not "not a regular
    # member" here, and the receipt is not missing.
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "reason": "bundle_inventory_failed",
        "errors": [
            "bundle_inventory_failed",
            "manifest_read_failed",
            "p1_read_failed",
            "envelope_read_failed",
            "registry_link_read_failed",
        ],
    }
    assert report["checks"] == _UNINSPECTED_CHECKS


# The checks of a run whose every member the host refused to inspect: each bundle layer is
# refused with its read error, so its checks are false and never null (bundle-objects.md
# section 6), the presence flags are false because the verifier saw no member, and no signature
# was evaluated.
_UNINSPECTED_CHECKS = {
    "manifest_sha256": False,
    "manifest_files": False,
    "p1_sha256": False,
    "canonical_input_present": False,
    "p1_input_hash": False,
    "envelope_present": False,
    "envelope_sha256": False,
    "envelope_links": False,
    "registry_signature": "UNSUPPORTED",
    "registry_link": None,
    "trust_registry": None,
}


# A presence flag records what the verifier saw (bundle-objects.md section 6), and a host failure
# is never reported as absence (report-contract.md section 5.3). A member the host lets the
# verifier find and then fails to read is present: the layer that reads it is refused with its
# read error, so that layer's checks are false, and canonical_input_present and envelope_present
# still say what was found. One row per member of the link fixture bundle.
_READ = {
    "manifest_sha256": True,
    "manifest_files": True,
    "p1_sha256": True,
    "canonical_input_present": True,
    "p1_input_hash": True,
    "envelope_present": True,
    "envelope_sha256": True,
    "envelope_links": True,
    "registry_signature": "UNSUPPORTED",
    "registry_link": None,
    "trust_registry": None,
}
_MANIFEST_REFUSED = {"manifest_sha256": False, "manifest_files": False, "envelope_links": False}
_P1_REFUSED = {**_MANIFEST_REFUSED, "p1_sha256": False, "p1_input_hash": False}
_ENVELOPE_REFUSED = {"envelope_sha256": False, "envelope_links": False}

_UNREAD_MEMBER_ROWS = {
    # manifest.json is read for itself and manifest.sha256 against it; either failure refuses
    # the manifest layer, and the envelope's links, which name the manifest's digest, fail.
    "manifest.json": (["manifest_read_failed"], _MANIFEST_REFUSED),
    "manifest.sha256": (["manifest_read_failed"], _MANIFEST_REFUSED),
    # A declared member: the manifest layer reads it for its digest, then the P1 layer.
    "p1.json": (["manifest_read_failed", "p1_read_failed"], _P1_REFUSED),
    "p1.sha256": (["manifest_read_failed", "p1_read_failed"], _P1_REFUSED),
    "canonical_input.json": (["manifest_read_failed", "p1_read_failed"], _P1_REFUSED),
    "envelope_env1.json": (["envelope_read_failed"], _ENVELOPE_REFUSED),
    "envelope.sha256": (["envelope_read_failed"], _ENVELOPE_REFUSED),
    # The receipt is read by the link; the bundle layers are untouched.
    "verification_receipt.json": (["registry_link_read_failed"], {}),
}


@contextlib.contextmanager
def _refusing_read_of(monkeypatch: pytest.MonkeyPatch, target: Path) -> Iterator[list[str]]:
    """Opening ``target`` fails with EACCES; it can still be listed and inspected, as a file
    another process holds open without sharing, or one without read permission."""
    real_open = open
    seen: list[str] = []

    def refusing_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and Path(os.fspath(file)) == _host(target):
            seen.append(os.fspath(file))
            raise _denied(file)
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", refusing_open)
        patch.setattr("io.open", refusing_open)
        yield seen


@pytest.mark.parametrize("member", sorted(_UNREAD_MEMBER_ROWS))
def test_a_member_the_host_fails_to_read_is_still_reported_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, member: str
) -> None:
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    entry = bundle.link_entry(tmp_path / "entry.json")
    assert member in {path.name for path in root.iterdir()}
    assert verify_path(root).to_dict()["checks"] == _READ
    errors, refused = _UNREAD_MEMBER_ROWS[member]
    with _refusing_read_of(monkeypatch, root / member) as seen:
        offline = verify_path(root).to_dict()
        linked = verify_path(root, registry_entry_path=entry).to_dict()
    assert seen, f"the host was never asked to read {member}"
    assert _surface(offline)["errors"] == errors
    assert offline["checks"] == {**_READ, **refused}
    # The flags do not depend on the level: a registry entry beside the bundle changes neither.
    assert _surface(linked)["errors"] == errors
    assert (linked["checks"]["canonical_input_present"], linked["checks"]["envelope_present"]) == (True, True)


def test_an_absent_member_stays_absent_beside_a_member_the_host_fails_to_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flag follows the member, not the failure: the rows above do not hold by a flag that is
    true whenever a layer is refused."""
    without_input = Bundle()
    del without_input.members["canonical_input.json"]
    without_input.edit("manifest.json", lambda m: m["files"].pop("canonical_input.json"))
    without_envelope = Bundle()
    del without_envelope.members["envelope_env1.json"]
    del without_envelope.members["envelope.sha256"]
    flags = {}
    for name, bundle in (("no canonical input", without_input), ("no envelope", without_envelope)):
        root = bundle.seal().write(tmp_path / name)
        with _refusing_read_of(monkeypatch, root / "p1.json") as seen:
            report = verify_path(root).to_dict()
        assert seen
        assert _surface(report)["errors"] == ["manifest_read_failed", "p1_read_failed"]
        flags[name] = (report["checks"]["canonical_input_present"], report["checks"]["envelope_present"])
    assert flags == {"no canonical input": (False, True), "no envelope": (True, False)}


@pytest.mark.parametrize("spelling", ["MANIFEST.JSON", "Manifest.json", "manifest.JSON"])
def test_the_root_marker_is_matched_exactly_whatever_the_hosts_letter_case(tmp_path: Path, spelling: str) -> None:
    bundle = Bundle()
    bundle.members[spelling] = bundle.members.pop("manifest.json")
    root = bundle.write(tmp_path / "bundle")
    assert _surface(verify_path(root).to_dict()) == {
        "status": "OFFLINE_FAIL",
        "reason": "bundle_root_invalid",
        "errors": ["bundle_root_invalid"],
    }


def _self_link(path: Path) -> bool:
    """Make ``path`` a link to itself: a junction on Windows, a symbolic link elsewhere."""
    if sys.platform == "win32":
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(path)], capture_output=True)
        return made.returncode == 0
    os.symlink(path, path)
    return True


def _remove_link(path: Path) -> None:
    with contextlib.suppress(OSError):
        os.rmdir(path) if sys.platform == "win32" else os.unlink(path)


def test_an_input_that_is_a_link_resolving_to_itself_names_nothing(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    if not _self_link(loop):
        pytest.skip("this host cannot make a link to itself")
    try:
        report = verify_path(loop).to_dict()
    finally:
        _remove_link(loop)
    assert _surface(report) == {"status": "HOST_FAILURE", "reason": "input_not_found", "errors": ["input_not_found"]}


def test_a_path_holding_a_nul_names_nothing(tmp_path: Path) -> None:
    """A path no entry can have finds nothing, as the input and as a registry entry's path.

    report-contract.md section 5.3 counts the path among those at which nothing is found,
    which is what this verifier reports, as loquitur-verify-ts does.
    """
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    trust = write_json(tmp_path / "trust.json", fixture_trust_registry())
    nul_entry = str(tmp_path / "entry\x00.json")
    runs = {
        "input": _surface(verify_path(str(tmp_path / "bundle\x00name")).to_dict())["errors"],
        "entry": _surface(verify_path(root, registry_entry_path=nul_entry).to_dict())["errors"],
        "entry beside a trust registry": _surface(
            verify_path(root, registry_entry_path=nul_entry, trust_registry_path=trust).to_dict()
        )["errors"],
    }
    assert runs == {
        "input": ["input_not_found"],
        "entry": ["input_not_found"],
        "entry beside a trust registry": ["input_not_found"],
    }


@contextlib.contextmanager
def _refusing_stat_of(monkeypatch: pytest.MonkeyPatch, target: Path) -> Iterator[None]:
    """os.stat fails with EACCES on ``target``: a document path the host cannot inspect."""
    real_stat = os.stat

    def stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, (str, os.PathLike)) and Path(os.fspath(path)) == _host(target):
            raise _denied(path)
        return real_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", stat)
        yield


def test_a_registry_entry_path_the_host_fails_to_inspect_is_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_path = write_json(tmp_path / "entry.json", fixture_entry())
    trust_path = write_json(tmp_path / "trust.json", fixture_trust_registry())
    with _refusing_stat_of(monkeypatch, entry_path):
        alone = verify_path(BUNDLE, registry_entry_path=entry_path).to_dict()
        beside_trust = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    assert _surface(alone)["errors"] == ["registry_link_read_failed"]
    # report-contract.md section 5.3: a host failure to read the entry is that error alone, a
    # host outcome, also with a trust registry.
    assert _surface(beside_trust)["errors"] == ["registry_link_read_failed"]
    assert (alone["status"], beside_trust["status"]) == ("HOST_FAILURE", "HOST_FAILURE")


def test_a_trust_registry_path_the_host_fails_to_inspect_is_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_path = write_json(tmp_path / "entry.json", fixture_entry())
    trust_path = write_json(tmp_path / "trust.json", fixture_trust_registry())
    baseline = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    # The link holds, so the trust registry is read: what follows measures its path.
    assert baseline["trust_registry"] is not None
    assert baseline["trust_registry"]["authorization_status"] != "INVALID_TRUST_REGISTRY"
    with _refusing_stat_of(monkeypatch, trust_path):
        report = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    # report-contract.md section 5.3: a host failure, not INVALID_TRUST_REGISTRY, a finding about
    # bytes nobody read; the registry is not evaluated.
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "reason": "trust_registry_read_failed",
        "errors": ["trust_registry_read_failed"],
    }
    assert report["trust_registry"] is None


def _zipped_bundle(tmp_path: Path) -> Path:
    """A sealed bundle as a ZIP archive at its top level, which verifies OFFLINE_OK."""
    source = Bundle().seal().write(tmp_path / "source")
    archive_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as handle:
        for member in sorted(source.rglob("*")):
            if member.is_file():
                handle.write(member, member.relative_to(source).as_posix())
    assert _surface(verify_path(archive_path).to_dict())["status"] == "OFFLINE_OK"
    return archive_path


def test_an_archive_the_host_fails_to_read_is_refused_as_filesystem_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = _zipped_bundle(tmp_path)

    real_open = open

    def refusing_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and Path(os.fspath(file)) == _host(archive_path):
            raise _denied(file)
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", refusing_open)
        patch.setattr("io.open", refusing_open)
        report = verify_path(archive_path).to_dict()
    # Not invalid_zip: zipfile.is_zipfile answers False for a read that failed.
    assert _surface(report) == {"status": "HOST_FAILURE", "reason": "filesystem_error", "errors": ["filesystem_error"]}


class _ChunkedRead:
    """The archive's file object, counting the reads and the bytes, failing from read ``fail_at`` on."""

    def __init__(self, handle: Any, fail_at: int | None) -> None:
        self.handle, self.fail_at = handle, fail_at
        self.reads = self.size = 0

    def read(self, size: int = -1) -> bytes:
        if self.fail_at is not None and self.reads >= self.fail_at:
            raise OSError(errno.EIO, "Input/output error")
        self.reads += 1
        data: bytes = self.handle.read(size)
        self.size += len(data)
        return data

    def __enter__(self) -> _ChunkedRead:
        return self

    def __exit__(self, *exc: object) -> None:
        self.handle.close()


def _read_in_chunks(
    monkeypatch: pytest.MonkeyPatch, archive_path: Path, fail_at: int | None
) -> tuple[dict[str, Any], list[_ChunkedRead]]:
    """verify_path over the archive, whose read-through takes 64-byte chunks through _ChunkedRead."""
    real = runner.open_for_reading
    opened: list[_ChunkedRead] = []

    def open_in_chunks(path: Any) -> Any:
        if Path(os.fspath(path)) != _host(archive_path):
            return real(path)
        opened.append(_ChunkedRead(real(path), fail_at))
        return opened[-1]

    with monkeypatch.context() as patch:
        patch.setattr(runner, "_READ_THROUGH_CHUNK", 64)
        patch.setattr(runner, "open_for_reading", open_in_chunks)
        report = verify_path(archive_path).to_dict()
    return report, opened


def test_an_archive_whose_later_chunk_the_host_fails_to_read_is_refused_as_filesystem_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first chunk reads; the second fails. The read-through goes on past the first chunk, so
    # the failure refuses the input as the failure of the first read does.
    archive_path = _zipped_bundle(tmp_path)
    report, opened = _read_in_chunks(monkeypatch, archive_path, fail_at=1)
    assert [read.reads for read in opened] == [1]
    assert _surface(report) == {"status": "HOST_FAILURE", "reason": "filesystem_error", "errors": ["filesystem_error"]}


def test_the_read_through_reads_every_byte_of_the_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive_path = _zipped_bundle(tmp_path)
    report, opened = _read_in_chunks(monkeypatch, archive_path, fail_at=None)
    assert _surface(report)["status"] == "OFFLINE_OK"
    [read] = opened
    size = archive_path.stat().st_size
    assert size > 64 * 2, size
    # Every byte, in 64-byte chunks, and the empty read at the end that stops the loop.
    assert read.size == size
    assert read.reads == -(-size // 64) + 1


def test_an_extraction_the_host_fails_to_write_is_archive_load_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = Bundle().seal().write(tmp_path / "source")
    archive_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as handle:
        for member in sorted(source.rglob("*")):
            if member.is_file():
                handle.write(member, member.relative_to(source).as_posix())

    def no_space(*args: Any, **kwargs: Any) -> str:
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(archive.tempfile, "mkdtemp", no_space)
        report = verify_path(archive_path).to_dict()
    # Neither the input nor its bytes: the archive cannot be loaded for another reason. It is
    # not filesystem_error, a refusal of an input the host had read.
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "reason": "archive_load_failed",
        "errors": ["archive_load_failed"],
    }


def _deny_listing(directory: Path) -> Callable[[], None] | str:
    """Deny the current user the listing of ``directory`` for real, or say why this host cannot."""
    if sys.platform == "win32":
        user = os.environ.get("USERNAME")
        if not user:
            return "USERNAME is not set, so no access-control entry can name the current user"
        denied = subprocess.run(
            ["icacls", str(directory), "/deny", f"{user}:(RD)"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if denied.returncode != 0:
            return f"icacls cannot deny the listing here: {denied.stderr or denied.stdout}"
        return lambda: subprocess.run(["icacls", str(directory), "/remove:d", user], capture_output=True)
    directory.chmod(0o311)
    return lambda: directory.chmod(0o755)


@pytest.mark.parametrize(
    ("target", "errors"),
    [
        ("", ["filesystem_error"]),
        ("sub", ["bundle_inventory_failed", "manifest_read_failed"]),
        ("undeclared", ["bundle_inventory_failed"]),
    ],
    ids=["the input directory", "a subdirectory holding a declared member", "an undeclared empty subdirectory"],
)
def test_the_listing_failures_made_real_on_this_host(tmp_path: Path, target: str, errors: list[str]) -> None:
    if target == "undeclared":
        root = _bundle_with_undeclared_directory(tmp_path)
        target = "sub"
    else:
        root = _bundle_with_subdirectory(tmp_path)
    directory = root / target if target else root
    restore = _deny_listing(directory)
    if isinstance(restore, str):
        pytest.skip(restore)
    try:
        try:
            os.listdir(directory)
        except PermissionError:
            pass
        else:
            pytest.skip("this host still lists the directory (a privileged user), so the case is not made")
        report = verify_path(root).to_dict()
        assert (report["status"], [error["code"] for error in report["errors"]]) == ("HOST_FAILURE", errors)
    finally:
        restore()


@pytest.mark.skipif(sys.platform == "win32", reason="a directory without search permission is a POSIX state")
def test_members_the_host_fails_to_inspect_made_real_on_this_host(tmp_path: Path) -> None:
    root = _bundle_with_subdirectory(tmp_path)
    root.chmod(0o644)
    try:
        try:
            os.lstat(root / "manifest.json")
        except PermissionError:
            pass
        else:
            pytest.skip("this host still inspects the entries (a privileged user), so the case is not made")
        assert _surface(verify_path(root).to_dict())["errors"] == [
            "bundle_inventory_failed",
            "manifest_read_failed",
            "p1_read_failed",
            "envelope_read_failed",
            "registry_link_read_failed",
        ]
    finally:
        root.chmod(0o755)


def test_the_refused_content_list_names_no_host_error() -> None:
    """docs/outcome-categories.md lists refused content as OFFLINE_FAIL / exit 1; a host error there
    would tell a reader that a run the host failed judged the evidence."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "outcome-categories.md").read_text(encoding="utf-8")
    section = text.split("## Messages that name refused content", 1)[1].split("\n\n")[2]
    named = {line[3:].split("`", 1)[0].split(":", 1)[0] for line in section.splitlines() if line.startswith("- `")}
    assert "bundle_member_name_invalid" in named
    assert named & set(runner.ERROR_CODES)
    assert not named & runner.HOST_ERROR_CODES
