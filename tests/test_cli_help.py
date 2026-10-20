from __future__ import annotations

import pytest

from loquitur.verify.cli import main


def test_cli_help_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "usage: loquitur-verify" in out
    assert "Verify a Loquitur evidence bundle offline." in out


def test_cli_version_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("loquitur-verify ")
