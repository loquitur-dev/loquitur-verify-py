"""Every digest the report restates names its algorithm.

report-contract.md section 6: every digest the report restates is written in the
self-describing form of canonicalization-and-hashing.md section 2, ``sha256:<hex>``. The
sidecars a bundle carries (manifest.sha256, p1.sha256, envelope.sha256) hold 64 bare hex
characters, and the report restates what it compared: the expected value read from the sidecar
and the value it recomputed. This holds both, and the receipt digest of the link section, to
the self-describing form, and walks the whole report so that a digest restated anywhere else in
bare form is found too.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from loquitur.verify.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SELF_DESCRIBING = re.compile(r"sha256:[0-9a-f]{64}")
BARE = re.compile(r"[0-9a-f]{64}")

RESTATED = {
    ("manifest", "manifest_sha256_expected"),
    ("manifest", "manifest_sha256_actual"),
    ("p1", "p1_sha256_expected"),
    ("p1", "p1_sha256_actual"),
    ("p1", "input_hash_expected"),
    ("p1", "input_hash_actual"),
    ("envelope", "envelope_sha256_expected"),
    ("envelope", "envelope_sha256_actual"),
    ("registry_link", "receipt_sha256_actual"),
}


def _report(argv: list[str]) -> dict[str, Any]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        main([*argv, "--json"])
    return json.loads(out.getvalue())


def _bare_digests(value: Any, path: str = "$") -> list[str]:
    if isinstance(value, dict):
        return [found for key, item in value.items() for found in _bare_digests(item, f"{path}.{key}")]
    if isinstance(value, list):
        return [found for index, item in enumerate(value) for found in _bare_digests(item, f"{path}[{index}]")]
    if isinstance(value, str) and BARE.fullmatch(value):
        return [path]
    return []


@pytest.fixture(scope="module")
def link_report() -> dict[str, Any]:
    return _report(
        [str(FIXTURES / "link_valid_bundle"), "--registry-entry", str(FIXTURES / "link_valid_registry_entry.json")]
    )


def test_each_restated_digest_names_its_algorithm(link_report: dict[str, Any]) -> None:
    assert link_report["status"] == "OFFLINE_OK", link_report["status"]
    wrong = {
        f"{section}.{member}": link_report[section][member]
        for section, member in RESTATED
        if not SELF_DESCRIBING.fullmatch(str(link_report[section][member]))
    }
    assert not wrong, wrong


def test_no_digest_is_restated_bare_anywhere_in_the_report(link_report: dict[str, Any]) -> None:
    assert _bare_digests(link_report) == []


def test_a_sidecar_compared_digest_is_the_recomputed_digest_with_its_algorithm(link_report: dict[str, Any]) -> None:
    """The prefix is a spelling of the value, not a different value: the expected and the actual still agree."""
    sidecar = (FIXTURES / "link_valid_bundle" / "manifest.sha256").read_text(encoding="utf-8").split()[0]
    assert BARE.fullmatch(sidecar), sidecar
    assert link_report["manifest"]["manifest_sha256_expected"] == f"sha256:{sidecar}"
    assert link_report["manifest"]["manifest_sha256_actual"] == f"sha256:{sidecar}"
