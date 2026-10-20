"""The conformance adapter hands every document path to the verifier as it is written (report-contract.md section 5.3).

The adapter hands the bundle, the registry entry, the trust registry and the trust-root document
on as the strings written, as the command line, the library and loquitur-verify-ts read them. A
``pathlib.Path`` is a rewriting of the string before the host reads it: it drops a trailing
separator, and on Windows under Python 3.11 it reads ``\\\\.\\\\name`` as a path below the drive's
root, so an adapter that converted the paths would have the conformance corpus read files the
written paths do not name.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE

from loquitur.verify.cli import main
from loquitur.verify.host_path import host_path
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import TrustRootDocumentUnreadableError, read_trust_root_document

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
ADAPTER = ROOT / "tools" / "conformance_adapter.py"
ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
TRUST = FIXTURES / "authorization_valid_trust_registry.json"
ROOTS = FIXTURES / "authorization_quickstart_trust_root.json"
INSTANT = "2026-05-01T12:00:00Z"


def _names_a_regular_file(written: str) -> bool:
    """Whether the host, reading ``written`` as the verifier reads a path, finds a regular file."""
    try:
        return stat.S_ISREG(os.stat(host_path(written)).st_mode)
    except OSError:
        return False


def _rewritten(path: Path) -> str:
    """A string naming no regular file as it is written, which ``Path`` turns into ``path`` itself.

    Two forms. A separator after the file's name asks a POSIX host for a directory and finds
    none, and ``Path`` drops it; a Windows host drops it too, so there it proves nothing. On
    Windows, the device prefix with the drive dropped and a second separator: the file
    namespace holds nothing of that name, and ``Path`` under Python 3.11 reads it as the path
    below the drive's root. From 3.12, whose ``pathlib`` parses paths anew, ``Path`` keeps that
    form as written, and no form is left that ``Path`` rewrites into the file while the host
    finds nothing: the defect these tests pin cannot occur there, and they say so rather than
    fail their own guard.
    """
    text = str(path.resolve())
    forms = ["\\\\.\\\\" + text[3:]] if sys.platform == "win32" else []
    forms.append(text + os.sep)
    for written in forms:
        if Path(written).resolve() == path.resolve() and not _names_a_regular_file(written):
            return written
    pytest.skip(
        f"on {sys.platform} under Python {sys.version_info.major}.{sys.version_info.minor} no path"
        " form tried is rewritten by Path into the file while the host finds no regular file,"
        " so an adapter that parsed its flags as Path values would read what the host reads"
    )


def _surface(report: dict[str, Any]) -> tuple[str, str, list[str]]:
    return report["status"], report["outcome"]["reason"], [error["code"] for error in report["errors"]]


def _adapter(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ADAPTER), "--bundle", str(BUNDLE), *args],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        timeout=120,
        stdin=subprocess.DEVNULL,
    )


def _cli(*args: str) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main([str(BUNDLE), "--json", *args])


@pytest.mark.parametrize("flag", ["--registry-entry", "--trust-registry"])
def test_the_adapter_reads_a_document_path_as_it_is_written(flag: str) -> None:
    written = _rewritten(ENTRY if flag == "--registry-entry" else TRUST)
    entry = written if flag == "--registry-entry" else str(ENTRY)
    trust = written if flag == "--trust-registry" else str(TRUST)
    library = _surface(verify_path(str(BUNDLE), registry_entry_path=entry, trust_registry_path=trust).to_dict())
    plain = _surface(verify_path(str(BUNDLE), registry_entry_path=str(ENTRY), trust_registry_path=str(TRUST)).to_dict())
    # The written path names no regular file, so the run is not the plain run.
    assert library != plain
    adapter = _adapter("--registry-entry", entry, "--trust-registry", trust)
    assert adapter.returncode == 0, adapter.stderr
    # With the flag parsed as a Path, the adapter would read the document the plain path names.
    assert _surface(json.loads(adapter.stdout)) == library


def test_the_adapter_reads_a_trust_root_path_as_it_is_written() -> None:
    written = _rewritten(ROOTS)
    with pytest.raises(TrustRootDocumentUnreadableError):
        read_trust_root_document(written)
    args = ("--registry-entry", str(ENTRY), "--trust-registry", str(TRUST), "--evaluation-time", INSTANT)
    assert _cli(*args, "--trust-root", written) == 64
    adapter = _adapter(*args, "--trust-root", written)
    # With the flag parsed as a Path, the adapter would read the pinned roots and write a report.
    assert (adapter.returncode, adapter.stdout == "") == (64, True), adapter.stderr
    assert "names no regular file" in adapter.stderr
    assert _adapter(*args, "--trust-root", str(ROOTS)).returncode == 0
