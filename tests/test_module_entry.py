"""``python -m loquitur.verify`` is the command line: the same output and the same exit codes."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from loquitur.verify import __version__
from loquitur.verify.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _module(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "loquitur.verify", *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


def test_the_module_prints_the_version_of_the_script() -> None:
    run = _module("--version")
    assert run.returncode == 0
    assert run.stdout.strip() == f"loquitur-verify {__version__}"


@pytest.mark.parametrize(
    ("fixture", "exit_code", "status"),
    [
        ("valid_bundle.zip", 0, "OFFLINE_OK"),
        ("tampered_manifest_bundle.zip", 1, "OFFLINE_FAIL"),
        ("no_such_bundle.zip", 5, "HOST_FAILURE"),
    ],
)
def test_the_module_reports_and_exits_as_main_does(
    fixture: str, exit_code: int, status: str, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _module(str(FIXTURES / fixture), "--json")
    assert run.returncode == exit_code
    assert json.loads(run.stdout)["status"] == status
    assert main([str(FIXTURES / fixture), "--json"]) == exit_code
    assert capsys.readouterr().out == run.stdout


def test_a_usage_error_exits_64() -> None:
    assert _module().returncode == 64


def test_importing_the_module_runs_nothing() -> None:
    module = importlib.import_module("loquitur.verify.__main__")
    assert module.main is main
