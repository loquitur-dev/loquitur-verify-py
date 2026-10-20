"""The documented entry points of the Python API import from ``loquitur.verify``.

README.md "Python API" names them. They are loaded on first use, so importing the package reads
neither the runner nor the narrative renderer, and the narrative renderer's read of
``loquitur-schemas`` stays lazy (the verdict path does not depend on it).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import loquitur.verify
from loquitur.verify import errors as errors_module
from loquitur.verify import evaluation_time, runner, trust_root

ENTRY_POINTS = {
    "verify_path": runner,
    "OfflineVerificationReport": runner,
    "exit_code_for_status": runner,
    "read_trust_root_document": trust_root,
    "TrustRootError": trust_root,
    "DOCUMENT_READ_FAILED": trust_root,
    "EvaluationTimeError": evaluation_time,
    "LoquiturVerifyError": errors_module,
}


@pytest.mark.parametrize("name", sorted(ENTRY_POINTS))
def test_an_entry_point_is_the_object_of_its_module(name: str) -> None:
    assert getattr(loquitur.verify, name) is getattr(ENTRY_POINTS[name], name)


def test_verify_path_returns_the_exported_report_class() -> None:
    from loquitur.verify import OfflineVerificationReport, verify_path

    report = verify_path("tests/fixtures/valid_bundle.zip")
    assert isinstance(report, OfflineVerificationReport)


def test_an_unknown_name_is_an_attribute_error() -> None:
    with pytest.raises(AttributeError):
        loquitur.verify.not_an_entry_point  # noqa: B018


def _modules_after(statement: str) -> set[str]:
    code = f"import sys\n{statement}\nprint(*sorted(sys.modules))"
    run = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=True)
    return set(run.stdout.split())


def test_importing_the_package_loads_no_entry_point() -> None:
    loaded = _modules_after("import loquitur.verify")
    assert "loquitur.verify.runner" not in loaded
    assert "loquitur.verify.narrative" not in loaded


def test_importing_the_runner_loads_neither_the_narrative_nor_the_schemas() -> None:
    loaded = _modules_after("from loquitur.verify import verify_path, TrustRootError, exit_code_for_status")
    assert "loquitur.verify.runner" in loaded
    assert "loquitur.verify.narrative" not in loaded
    assert not {name for name in loaded if name == "loquitur.schemas" or name.startswith("loquitur.schemas.")}
