"""A trust-root path that names no regular file is refused before it is read (report-contract.md section 4).

The trust-root document is held to the rule the trust registry and the registry entry follow,
by the command line and by the conformance adapter alike: it is read only when its path names a
regular file. Read without asking, a pipe or a FIFO serving a valid document would be read as
that document, and a path naming the console input device would wait for input that never
comes.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

from authorization_kit import BUNDLE, write_json

from loquitur.verify.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
ADAPTER = ROOT / "tools" / "conformance_adapter.py"


@contextlib.contextmanager
def _serving(data: bytes, tmp_path: Path) -> Iterator[str]:
    """A path that names no regular file and reads as ``data``: a named pipe on Windows, a FIFO elsewhere."""
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes as wt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateNamedPipeW.restype = wt.HANDLE
        kernel32.CreateNamedPipeW.argtypes = [wt.LPCWSTR, *[wt.DWORD] * 6, ctypes.c_void_p]
        kernel32.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]
        kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        kernel32.FlushFileBuffers.argtypes = [wt.HANDLE]
        kernel32.DisconnectNamedPipe.argtypes = [wt.HANDLE]
        kernel32.CloseHandle.argtypes = [wt.HANDLE]
        path = f"\\\\.\\pipe\\loquitur-verify-test-{os.getpid()}-{id(tmp_path)}"

        def serve() -> None:
            while True:
                handle = kernel32.CreateNamedPipeW(path, 0x2, 0, 255, 65536, 65536, 0, None)
                if not handle or handle == ctypes.c_void_p(-1).value:
                    return
                kernel32.ConnectNamedPipe(handle, None)
                written = wt.DWORD()
                kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)
                kernel32.FlushFileBuffers(handle)
                kernel32.DisconnectNamedPipe(handle)
                kernel32.CloseHandle(handle)

        for _ in range(4):
            threading.Thread(target=serve, daemon=True).start()
        yield path
        return
    fifo = tmp_path / "roots.fifo"
    os.mkfifo(fifo)

    def feed() -> None:
        with open(fifo, "wb") as handle:
            handle.write(data)

    threading.Thread(target=feed, daemon=True).start()
    try:
        yield str(fifo)
    finally:
        # Release a writer still waiting for a reader, so its thread ends.
        with contextlib.suppress(OSError):
            os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))


def test_a_trust_root_path_that_names_no_regular_file_is_refused_before_it_is_read(tmp_path: Path) -> None:
    """report-contract.md section 4: a trust-root path that names no regular file is a document
    that cannot be read, exit 64 with no report.

    Read without asking what the path names, a pipe serving a valid trust-root document would
    be read as that document, and the run would go on to a report; a path naming the console
    input device would wait for input that never comes.
    """
    roots = (FIXTURES / "authorization_quickstart_trust_root.json").read_bytes()
    entry = FIXTURES / "authorization_valid_registry_entry.json"
    trust = FIXTURES / "authorization_valid_trust_registry.json"
    with _serving(roots, tmp_path) as served:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = main(
                [
                    str(BUNDLE),
                    "--json",
                    "--registry-entry",
                    str(entry),
                    "--trust-registry",
                    str(trust),
                    "--trust-root",
                    served,
                ]
            )
        assert code == 64, stderr.getvalue()
        assert "names no regular file" in stderr.getvalue()
        adapter = subprocess.run(
            [
                sys.executable,
                str(ADAPTER),
                "--bundle",
                str(BUNDLE),
                "--registry-entry",
                str(entry),
                "--trust-registry",
                str(trust),
                "--trust-root",
                served,
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            encoding="utf-8",
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
    assert (adapter.returncode, adapter.stdout) == (64, ""), adapter.stderr
    assert "names no regular file" in adapter.stderr
    # The same document from a regular file is read, so the refusal is about the path.
    regular = write_json(tmp_path / "roots.json", json.loads(roots))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert main(
            [
                str(BUNDLE),
                "--json",
                "--registry-entry",
                str(entry),
                "--trust-registry",
                str(trust),
                "--trust-root",
                str(regular),
            ]
        ) in (0, 1, 2)
