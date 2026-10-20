"""The checks block of a run whose input is refused as a whole.

When the input itself is refused (report-contract.md section 5.3, input_not_found to
filesystem_error), no layer runs. The per-check results are informative (section 2 there), and
bundle-objects.md section 6 states them for such a run: every bundle check false, the two
presence flags false, registry_signature UNSUPPORTED because no signature was evaluated, and
registry_link and trust_registry false when the caller asked for that level and null when it
did not. loquitur-verify-ts holds the same rows in test/refused-input-checks.test.ts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loquitur.verify import cli
from loquitur.verify.runner import verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
TRUST_REGISTRY = FIXTURES / "authorization_valid_trust_registry.json"

BUNDLE_CHECKS_FALSE = {
    "manifest_sha256": False,
    "manifest_files": False,
    "p1_sha256": False,
    "canonical_input_present": False,
    "p1_input_hash": False,
    "envelope_present": False,
    "envelope_sha256": False,
    "envelope_links": False,
    "registry_signature": "UNSUPPORTED",
}

LEVELS = {
    "offline": ({}, {"registry_link": None, "trust_registry": None}),
    "link": ({"registry_entry_path": ENTRY}, {"registry_link": False, "trust_registry": None}),
    "authorization": (
        {"registry_entry_path": ENTRY, "trust_registry_path": TRUST_REGISTRY},
        {"registry_link": False, "trust_registry": False},
    ),
}


def _inputs(tmp_path: Path) -> dict[str, Path]:
    empty = tmp_path / "empty"
    empty.mkdir()
    return {"input_not_found": tmp_path / "absent", "bundle_root_invalid": empty}


@pytest.mark.parametrize("level", sorted(LEVELS))
def test_a_refused_input_reports_the_shared_checks_shape(tmp_path: Path, level: str) -> None:
    options, level_checks = LEVELS[level]
    for code, path in _inputs(tmp_path).items():
        report = verify_path(path, **options).to_dict()
        assert [error["code"] for error in report["errors"]] == [code]
        assert report["checks"] == {**BUNDLE_CHECKS_FALSE, **level_checks}, code
        argv = [str(path), "--json"]
        if "registry_entry_path" in options:
            argv += ["--registry-entry", str(options["registry_entry_path"])]
        if "trust_registry_path" in options:
            argv += ["--trust-registry", str(options["trust_registry_path"])]
        # Nothing found at the input path is the host's (HOST_FAILURE, exit 5); an empty directory
        # is content (OFFLINE_FAIL, exit 1). report-contract.md section 5.3.
        assert cli.main(argv) == report["exit_code"] == (5 if code == "input_not_found" else 1)
