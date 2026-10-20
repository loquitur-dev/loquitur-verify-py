"""The human-readable summary never turns an encoding limit of stdout into a verdict.

The summary prints the bundle path as the caller gave it. Where stdout is a file or a pipe, its
encoding is the host's locale encoding, which need not represent every character of that
path. A strict encoder raising there would end the run with a traceback and exit 1, which the
exit-code taxonomy reserves for ``OFFLINE_FAIL``, for evidence that verified. A character the
stream cannot encode is written as a backslash escape, and the exit code is the verdict's.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from loquitur.verify import cli

FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Outside ASCII and outside every single-byte Windows code page.
NAME = "bündle-验证.zip"


@pytest.mark.parametrize(
    ("fixture", "expected_exit_code", "expected_line"),
    [
        ("valid_bundle.zip", 0, "Loquitur offline verification: OFFLINE_OK / PASS"),
        ("tampered_manifest_bundle.zip", 1, "Loquitur offline verification: OFFLINE_FAIL / FAIL"),
        ("missing_canonical_input_bundle.zip", 2, "Loquitur offline verification: OFFLINE_REVIEW / REVIEW"),
    ],
)
def test_a_path_the_stream_cannot_encode_keeps_the_verdict_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fixture: str, expected_exit_code: int, expected_line: str
) -> None:
    bundle = tmp_path / NAME
    shutil.copyfile(FIXTURES / fixture, bundle)
    raw = io.BytesIO()
    stdout = io.TextIOWrapper(raw, encoding="ascii", errors="strict", newline="\n")
    monkeypatch.setattr(sys, "stdout", stdout)

    exit_code = cli.main([str(bundle)])

    stdout.flush()
    text = raw.getvalue().decode("ascii")
    assert exit_code == expected_exit_code
    assert expected_line in text.splitlines()
    assert "\\u9a8c\\u8bc1" in text, "the path is written with the characters it holds, escaped"


def test_the_installed_command_line_under_a_strict_ascii_stdout(tmp_path: Path) -> None:
    bundle = tmp_path / NAME
    shutil.copyfile(FIXTURES / "valid_bundle.zip", bundle)
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}

    result = subprocess.run(
        [sys.executable, "-m", "loquitur.verify.cli", str(bundle)],
        capture_output=True,
        env=env,
        check=False,
    )

    assert b"Traceback" not in result.stderr, result.stderr.decode("utf-8", "replace")
    assert result.returncode == 0
    assert b"Loquitur offline verification: OFFLINE_OK / PASS" in result.stdout.splitlines()[0]
