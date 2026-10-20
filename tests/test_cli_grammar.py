"""The command-line grammar (report-contract.md section 4.1) and the summary's output safety.

Each option is given at most once, by its full name, with a non-empty value; anything else is a
usage error, exit 64 and no report. The summary escapes what the evidence controls, and a
stdout that cannot be written does not change the exit code.
"""

from __future__ import annotations

import errno
import io
import sys
from pathlib import Path

import pytest

from loquitur.verify.cli import main
from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE = str(FIXTURES / "link_valid_bundle")
ENTRY = str(FIXTURES / "authorization_valid_registry_entry.json")
TRUST = str(FIXTURES / "authorization_valid_trust_registry.json")


def _usage_error(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    return captured.err


@pytest.mark.parametrize(
    "argv",
    [
        [BUNDLE, "--registry-entry", ENTRY, "--registry-entry", ENTRY],
        [BUNDLE, "--registry-entry", ENTRY, f"--registry-entry={ENTRY}"],
        [BUNDLE, "--registry-entry", ENTRY, "--trust-registry", TRUST, "--trust-registry", TRUST],
        [BUNDLE, "--registry-entry", ENTRY, "--trust-registry", TRUST, "--trust-root", TRUST, "--trust-root", TRUST],
        [
            BUNDLE,
            "--registry-entry",
            ENTRY,
            "--trust-registry",
            TRUST,
            "--evaluation-time",
            "not-an-instant",
            "--evaluation-time",
            "2026-05-10T00:00:00Z",
        ],
        [BUNDLE, "--json", "--json"],
        [BUNDLE, "--accept-review", "envelope_not_provided", "--accept-review", "envelope_not_provided"],
    ],
    ids=["entry", "entry_equals_form", "trust_registry", "trust_root", "instant", "json", "accept_review"],
)
def test_a_repeated_option_is_a_usage_error(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert "more than once" in _usage_error(argv, capsys)


@pytest.mark.parametrize("prefix", ["--reg", "--registry", "--trust-reg", "--js"])
def test_an_option_given_by_a_prefix_is_a_usage_error(prefix: str, capsys: pytest.CaptureFixture[str]) -> None:
    argv = [BUNDLE, prefix] if prefix == "--js" else [BUNDLE, prefix, ENTRY]
    _usage_error(argv, capsys)


@pytest.mark.parametrize(
    "argv",
    [
        [BUNDLE, "--registry-entry", ""],
        [BUNDLE, "--registry-entry="],
        [BUNDLE, "--registry-entry", ENTRY, "--trust-registry", ""],
        [BUNDLE, "--registry-entry", ENTRY, "--trust-registry", TRUST, "--trust-root", ""],
        [BUNDLE, "--registry-entry", ENTRY, "--trust-registry", TRUST, "--evaluation-time", ""],
        [BUNDLE, "--accept-review", ""],
        [""],
    ],
    ids=["entry", "entry_equals_form", "trust_registry", "trust_root", "instant", "accept_review", "bundle"],
)
def test_an_empty_value_is_a_usage_error(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    _usage_error(argv, capsys)


# The instant is YYYY-MM-DDTHH:MM:SSZ with an uppercase Z; any
# other form is refused before anything is evaluated.
@pytest.mark.parametrize(
    "instant",
    ["2026-05-01T12:00:00z", "2026-05-01t12:00:00Z", "2026-05-01T12:00:00+00:00", "2026-05-01", "2026-02-30T00:00:00Z"],
)
def test_an_instant_not_of_the_exact_form_is_refused(instant: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(EvaluationTimeError):
        operator_evaluation_time(instant)
    code = main([BUNDLE, "--registry-entry", ENTRY, "--trust-registry", TRUST, "--evaluation-time", instant, "--json"])
    assert code == 64
    assert capsys.readouterr().out == ""


def test_the_cli_returns_64_for_a_lowercase_z(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [BUNDLE, "--registry-entry", ENTRY, "--trust-registry", TRUST, "--evaluation-time", "2026-05-01T12:00:00z"]
    )
    assert code == 64
    assert capsys.readouterr().out == ""


# report-contract.md section 4: the list names review reasons, each once, with no empty element.
@pytest.mark.parametrize(
    "value",
    [
        "not_a_review_reason",
        "envelope_not_provided,",
        ",envelope_not_provided",
        "envelope_not_provided,,bundle_extra_files",
        "envelope_not_provided,envelope_not_provided",
        "envelope_not_provided, bundle_extra_files",
        "ENVELOPE_NOT_PROVIDED",
    ],
    ids=["unknown", "trailing-empty", "leading-empty", "inner-empty", "repeated", "space", "uppercase"],
)
def test_an_accept_review_list_that_is_not_a_set_of_review_reasons_is_a_usage_error(
    value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _usage_error([BUNDLE, "--accept-review", value], capsys)


def test_accept_review_takes_every_review_reason(capsys: pytest.CaptureFixture[str]) -> None:
    from loquitur.verify.runner import REVIEW_REASONS

    assert main([BUNDLE, "--json", "--accept-review", ",".join(REVIEW_REASONS)]) == 0
    assert len(REVIEW_REASONS) == 14


# The summary escapes every character that is not printable.
def test_the_summary_escapes_what_the_caller_and_the_bundle_control(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["no-such-bundle\nLoquitur offline verification: OFFLINE_OK - PASS\x1b[2K"])
    out = capsys.readouterr().out
    # A path that names nothing is a host outcome (report-contract.md section 3), exit 5.
    assert code == 5
    assert "\nLoquitur offline verification: OFFLINE_OK" not in out
    assert "\x1b" not in out
    assert "no-such-bundle\\nLoquitur offline verification: OFFLINE_OK - PASS\\x1b[2K" in out


# A stdout that cannot be written keeps the verdict's exit code.
class _FailingStdout(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError(errno.EINVAL, "Invalid argument")

    def fileno(self) -> int:
        raise io.UnsupportedOperation("fileno")


@pytest.mark.parametrize("output", ["--json", "--pretty"])
def test_a_stdout_that_cannot_be_written_keeps_the_exit_code(monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    monkeypatch.setattr(sys, "stdout", _FailingStdout())
    assert main([BUNDLE, output]) == 0


def test_a_closed_stdout_keeps_the_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", None)
    assert main([BUNDLE, "--json"]) == 0
