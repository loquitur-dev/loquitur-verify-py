"""Broken-pipe CLI contract tests.

Piping CLI output into a consumer that stops reading early (``head``,
``less`` quitting) raises ``BrokenPipeError`` inside report writing. The CLI
contract is the exit-code taxonomy: a truncated-output condition must not
surface a raw traceback and must not alter the verdict exit code.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from loquitur.verify import cli

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class _BrokenPipeStdout:
    """Test double simulating a pipe whose read end closed immediately."""

    def write(self, _text: str) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError

    def fileno(self) -> int:
        # A stream without a real descriptor says so with io.UnsupportedOperation, as io.StringIO
        # does; the detach helper and the argument parser must both tolerate it.
        raise io.UnsupportedOperation("fileno")


@pytest.mark.parametrize(
    ("bundle_name", "expected_exit_code"),
    [
        ("valid_bundle.zip", 0),
        ("tampered_manifest_bundle.zip", 1),
        ("missing_canonical_input_bundle.zip", 2),
    ],
)
def test_broken_pipe_preserves_verdict_exit_code(
    monkeypatch: pytest.MonkeyPatch, bundle_name: str, expected_exit_code: int
) -> None:
    monkeypatch.setattr(sys, "stdout", _BrokenPipeStdout())
    exit_code = cli.main([str(FIXTURES / bundle_name)])
    assert exit_code == expected_exit_code


def test_broken_pipe_preserves_exit_code_in_json_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _BrokenPipeStdout())
    exit_code = cli.main([str(FIXTURES / "valid_bundle.zip"), "--json"])
    assert exit_code == 0
