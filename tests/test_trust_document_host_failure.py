"""A trust registry or trust-root document the host fails to read is a host failure.

report-contract.md section 5.3: a host failure on the operator's path is never reported as the
absence of what the verifier looked for, nor as a finding about bytes it did not read. A trust
registry the host fails to read, where the run reads it, is ``trust_registry_read_failed``: the
registry is not evaluated and the report's ``trust_registry`` is ``null``. A trust-root document
the host fails to read is ``trust_root_read_failed``: root authentication is not evaluated, and
a command line does not refuse the invocation with exit 64. Both rows are host rows, so the run
is ``HOST_FAILURE``, exit 5, unless something else fails (section 3.1). A path that names no
regular file is not this question and keeps its outcome.

The run format of the conformance corpus cannot stage a host state (conformance-testing.md
section 6), so these rows are held here: by an injected failure on every host, and on Windows by
a real sharing violation, the file held open with no sharing by another handle.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE, EVALUATION_TIME, FIXTURES, fixture_entry, fixture_trust_registry, write_json

from loquitur.verify.cli import main
from loquitur.verify.host_path import host_path
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import (
    DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
    DOCUMENT_READ_FAILED,
    TrustRootDocumentUnreadableError,
)

# The quickstart material: an entry, a trust registry its root signed, and that root. The run over
# them is OFFLINE_OK at the quickstart's evaluation time.
QUICKSTART_BUNDLE = FIXTURES / "link_valid_bundle"
QUICKSTART_ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
QUICKSTART_TRUST = FIXTURES / "authorization_quickstart_trust_registry.json"
QUICKSTART_ROOT = FIXTURES / "authorization_quickstart_trust_root.json"
QUICKSTART_TIME = "2026-05-20T00:00:00Z"


def _surface(report: dict[str, Any]) -> dict[str, Any]:
    trust = report["trust_registry"]
    return {
        "status": report["status"],
        "exit_code": report["exit_code"],
        "reason": report["outcome"]["reason"],
        "errors": [error["code"] for error in report["errors"]],
        "authorization": None if trust is None else trust["authorization_status"],
        "root": None if trust is None else trust["trust_registry_root_signature_status"],
    }


@contextlib.contextmanager
def _refusing_open_of(monkeypatch: pytest.MonkeyPatch, target: Path) -> Iterator[None]:
    """Opening ``target`` fails with EACCES: a regular file the host refuses to read."""
    real_open = os.open
    held = Path(host_path(target))

    def refusing(path: Any, *args: Any, **kwargs: Any) -> int:
        if isinstance(path, (str, os.PathLike)) and Path(os.fspath(path)) == held:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path, *args, **kwargs)

    real_builtin_open = open

    def refusing_builtin(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and Path(os.fspath(file)) == held:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(file))
        return real_builtin_open(file, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", refusing)
        patch.setattr("builtins.open", refusing_builtin)
        patch.setattr("io.open", refusing_builtin)
        yield


def _run_cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any] | None]:
    code = main(["--json", *argv])
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else None)


def _quickstart_argv(root: Path, trust: Path = QUICKSTART_TRUST, entry: Path = QUICKSTART_ENTRY) -> list[str]:
    return [
        "--registry-entry",
        str(entry),
        "--trust-registry",
        str(trust),
        "--trust-root",
        str(root),
        "--evaluation-time",
        QUICKSTART_TIME,
        str(QUICKSTART_BUNDLE),
    ]


def test_the_quickstart_run_holds_before_any_host_failure(capsys: pytest.CaptureFixture[str]) -> None:
    code, report = _run_cli(capsys, *_quickstart_argv(QUICKSTART_ROOT))
    assert code == 0
    assert report is not None
    assert _surface(report)["status"] == "OFFLINE_OK"
    assert _surface(report)["root"] == "ROOT_SIGNATURE_VALID"


def test_a_trust_registry_the_host_fails_to_read_is_host_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_path = write_json(tmp_path / "entry.json", fixture_entry())
    trust_path = write_json(tmp_path / "trust.json", fixture_trust_registry())
    baseline = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    # The link holds, so the trust registry is read: what follows measures that read.
    assert baseline["trust_registry"] is not None
    with _refusing_open_of(monkeypatch, trust_path):
        report = verify_path(
            BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path, evaluation_time=EVALUATION_TIME
        ).to_dict()
    # Not OFFLINE_FAIL with INVALID_TRUST_REGISTRY: nothing about the registry was read.
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "exit_code": 5,
        "reason": "trust_registry_read_failed",
        "errors": ["trust_registry_read_failed"],
        "authorization": None,
        "root": None,
    }
    assert report["checks_established"] == []
    assert report["checks"]["trust_registry"] is None


def test_a_trust_registry_beside_a_link_that_does_not_hold_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # trust-registry-authorization.md section 1: beside a link that fails the registry is not read,
    # so a host that would fail to read it fails nothing.
    entry = fixture_entry()
    entry["manifest_sha256"] = "sha256:" + "0" * 64
    entry_path = write_json(tmp_path / "entry.json", entry)
    trust_path = write_json(tmp_path / "trust.json", fixture_trust_registry())
    plain = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    with _refusing_open_of(monkeypatch, trust_path):
        refused = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    assert _surface(refused) == _surface(plain)
    assert "trust_registry_read_failed" not in _surface(refused)["errors"]


def test_a_trust_registry_path_the_host_fails_to_inspect_is_host_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_path = write_json(tmp_path / "entry.json", fixture_entry())
    trust_path = write_json(tmp_path / "trust.json", fixture_trust_registry())
    held = Path(host_path(trust_path))
    real_stat = os.stat

    def stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, (str, os.PathLike)) and Path(os.fspath(path)) == held:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", stat)
        report = verify_path(BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path).to_dict()
    assert _surface(report)["errors"] == ["trust_registry_read_failed"]
    assert _surface(report)["status"] == "HOST_FAILURE"
    assert report["trust_registry"] is None


def test_a_trust_registry_path_that_names_a_directory_keeps_its_outcome(tmp_path: Path) -> None:
    # Out of scope here: a path that names something that is not a regular file is row 1 of
    # trust-registry-authorization.md section 6. Nothing found at the path is
    # input_not_found (tests/test_document_path_names_nothing.py).
    entry_path = write_json(tmp_path / "entry.json", fixture_entry())
    (tmp_path / "trust-directory").mkdir()
    report = verify_path(
        BUNDLE, registry_entry_path=entry_path, trust_registry_path=tmp_path / "trust-directory"
    ).to_dict()
    assert _surface(report)["status"] == "OFFLINE_FAIL"
    assert _surface(report)["authorization"] == "INVALID_TRUST_REGISTRY"


def test_a_trust_root_document_the_host_fails_to_read_is_reported_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root_path = tmp_path / "root.json"
    root_path.write_bytes(QUICKSTART_ROOT.read_bytes())
    with _refusing_open_of(monkeypatch, root_path):
        code, report = _run_cli(capsys, *_quickstart_argv(root_path))
    # Not exit 64 with no report: the invocation is well formed and the host failed it.
    assert code == 5
    assert report is not None
    assert _surface(report) == {
        "status": "HOST_FAILURE",
        "exit_code": 5,
        "reason": "trust_root_read_failed",
        "errors": ["trust_root_read_failed"],
        "authorization": "AUTHORIZED_ACTIVE_KEY",
        # Root authentication was not evaluated: neither pinned nor absent.
        "root": "ROOT_SIGNATURE_NOT_EVALUATED",
    }
    assert report["review_reasons"] == []
    assert report["checks_established"] == []


def test_the_library_takes_the_two_values_for_a_trust_root_document() -> None:
    report = verify_path(
        QUICKSTART_BUNDLE,
        registry_entry_path=QUICKSTART_ENTRY,
        trust_registry_path=QUICKSTART_TRUST,
        trust_roots=DOCUMENT_READ_FAILED,
        evaluation_time=QUICKSTART_TIME,
    ).to_dict()
    assert _surface(report)["errors"] == ["trust_root_read_failed"]
    assert (_surface(report)["status"], _surface(report)["root"]) == ("HOST_FAILURE", "ROOT_SIGNATURE_NOT_EVALUATED")
    assert report["trust_registry"]["trust_registry_root_signature_verified"] is False
    with pytest.raises(TrustRootDocumentUnreadableError):
        verify_path(
            QUICKSTART_BUNDLE,
            registry_entry_path=QUICKSTART_ENTRY,
            trust_registry_path=QUICKSTART_TRUST,
            trust_roots=DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
        )


def test_an_unread_trust_root_document_masks_no_failure_of_the_registry(tmp_path: Path) -> None:
    # Each row is judged on its own: a trust registry that fails still fails the run, and the host
    # failure is reported beside it (report-contract.md section 3.1, rule 4 before rule 5).
    trust = json.loads(QUICKSTART_TRUST.read_text(encoding="utf-8"))
    trust["entries"][0]["status"] = "revoked"
    trust["entries"][0]["revoked_at"] = trust["entries"][0]["effective_from"]
    trust_path = write_json(tmp_path / "trust.json", trust)
    report = verify_path(
        QUICKSTART_BUNDLE,
        registry_entry_path=QUICKSTART_ENTRY,
        trust_registry_path=trust_path,
        trust_roots=DOCUMENT_READ_FAILED,
        evaluation_time=QUICKSTART_TIME,
    ).to_dict()
    assert _surface(report)["status"] == "OFFLINE_FAIL"
    assert _surface(report)["errors"] == ["trust_root_read_failed"]
    assert _surface(report)["authorization"] in {"ISSUER_KEY_REVOKED", "INVALID_TRUST_REGISTRY"}
    assert _surface(report)["root"] == "ROOT_SIGNATURE_NOT_EVALUATED"


def test_a_trust_root_path_that_names_nothing_is_still_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, report = _run_cli(capsys, *_quickstart_argv(tmp_path / "absent.json"))
    assert (code, report) == (64, None)


# A real sharing violation: another handle holds the file open and shares nothing
# (report-contract.md section 5.3 names a sharing violation as a host failure).
@contextlib.contextmanager
def _held_without_sharing(path: Path) -> Iterator[None]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    generic_read, open_existing, share_none = 0x80000000, 3, 0
    handle = create(str(path), generic_read, share_none, None, open_existing, 0, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        raise OSError(ctypes.get_last_error(), "CreateFileW failed", str(path))
    try:
        yield
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.skipif(sys.platform != "win32", reason="a sharing violation is a Windows host state")
@pytest.mark.parametrize(
    ("held", "reason"),
    [
        ("entry", "registry_link_read_failed"),
        ("trust", "trust_registry_read_failed"),
        ("root", "trust_root_read_failed"),
    ],
)
def test_each_document_held_without_sharing_is_host_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], held: str, reason: str
) -> None:
    paths = {"entry": tmp_path / "entry.json", "trust": tmp_path / "trust.json", "root": tmp_path / "root.json"}
    for name, source in (("entry", QUICKSTART_ENTRY), ("trust", QUICKSTART_TRUST), ("root", QUICKSTART_ROOT)):
        paths[name].write_bytes(source.read_bytes())
    argv = _quickstart_argv(paths["root"], trust=paths["trust"], entry=paths["entry"])
    code, report = _run_cli(capsys, *argv)
    assert (code, report and report["status"]) == (0, "OFFLINE_OK")
    with _held_without_sharing(paths[held]):
        code, report = _run_cli(capsys, *argv)
    assert code == 5
    assert report is not None
    assert (report["status"], report["exit_code"], report["outcome"]["reason"]) == ("HOST_FAILURE", 5, reason)
    assert [error["code"] for error in report["errors"]] == [reason]
