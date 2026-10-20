from __future__ import annotations

import pytest
from repository import CI, RELEASE, ROOT, tool
from repository import pyproject as _pyproject
from repository import workflow as _load

BUILD_CHECKS = ROOT / "docs" / "maintainers" / "build-checks.md"


def test_package_metadata_is_a_controlled_alpha_preview_not_production() -> None:
    project = _pyproject()["project"]
    assert project["name"] == "loquitur-verify"
    assert project["version"] == "0.1.0"
    # The description is the PyPI Summary: it must describe the package, not gate it.
    assert "TestPyPI" not in project["description"]
    assert "Loquitur" in project["description"]
    assert project["dependencies"] == ["cryptography>=48.0.1,<51", "rfc8785>=0.1.4,<0.2"]
    classifiers = set(project["classifiers"])
    assert "Development Status :: 3 - Alpha" in classifiers
    assert "Development Status :: 4 - Beta" not in classifiers


def _claimed_pythons() -> list[str]:
    """The Python versions the classifiers claim, oldest first."""
    prefix = "Programming Language :: Python :: "
    claimed = [c.removeprefix(prefix) for c in _pyproject()["project"]["classifiers"] if c.startswith(prefix + "3.")]
    return sorted(claimed, key=lambda version: int(version.split(".")[1]))


def test_the_python_versions_claimed_are_the_ones_ci_runs() -> None:
    # A classifier is a claim on the project page: each one is a version every CI matrix runs, and
    # every version a matrix runs is claimed. The floor is the oldest of them.
    claimed = _claimed_pythons()
    matrices = [
        job["strategy"]["matrix"]["python-version"]
        for job in _load(CI)["jobs"].values()
        if "python-version" in job.get("strategy", {}).get("matrix", {})
    ]
    assert matrices, "ci.yml declares no Python matrix, so this test would check nothing"
    for matrix in matrices:
        assert matrix == claimed, f"a CI matrix runs {matrix}, the classifiers claim {claimed}"
    assert _pyproject()["project"]["requires-python"] == f">={claimed[0]}"


def test_the_python_versions_claimed_are_the_ones_the_readme_states() -> None:
    claimed = _claimed_pythons()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f'(`requires-python = ">={claimed[0]}"`)' in readme
    assert f"on Linux with Python {claimed[0]} to {claimed[-1]}" in " ".join(readme.split())


def test_readme_status_is_conservative_and_not_publication_ready() -> None:
    # The README is the package's long description: it states the status, a preview, and what
    # the package does. How a release reaches an index is the release procedure's, and no gate,
    # index or readiness level of that procedure is named here.
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Package status: **0.1.0 preview**." in text.splitlines()
    assert "candidate" not in text
    lowered = text.lower()
    for word in ("testpypi", "publication gate", "release gate", "approved package index", "pilot"):
        assert word not in lowered, word


# Words of a package-index procedure. The build checks document states the checks that build the
# package and check what was built; how a release reaches an index is the release procedure's,
# and the published documents name no index, no upload and no readiness level of it.
INDEX_PROCEDURE_WORDS = ("testpypi", "pypi", "upload", "pilot", "sdk", "soc2")


def test_build_checks_run_the_local_checks_without_uploading_or_overclaiming_authorization() -> None:
    # Runs of whitespace read as one space, so a phrase matches across a wrapped line.
    text = " ".join(BUILD_CHECKS.read_text(encoding="utf-8").split())
    required = [
        "python -m pip install -e ../loquitur-schemas",
        "python -m pytest -q",
        "python tools/local_wheel_gate.py",
        "python -m build",
        "python -m twine check dist/*",
        "structure, integrity, link and authorization checks remain local and read only the material supplied",
        "does not prove trust-registry root authenticity",
    ]
    for phrase in required:
        assert phrase in text, phrase
    assert "twine upload" not in text


def test_build_checks_keep_the_no_claim_boundary() -> None:
    text = " ".join(BUILD_CHECKS.read_text(encoding="utf-8").split())
    assert "does not imply production readiness" in text
    assert "registry finality verification" in text
    assert "valuation correctness" in text
    assert "regulatory compliance" in text
    assert "oracle behavior" in text
    lowered = text.lower()
    for word in INDEX_PROCEDURE_WORDS:
        assert word not in lowered, word


def test_build_checks_build_the_wheel_the_way_reproducibility_is_shown() -> None:
    # The document names tools/local_wheel_gate.py --check-reproducible and fixes
    # SOURCE_DATE_EPOCH for the build it checks, or the wheel it checks is not the wheel whose
    # reproducibility the gate can show.
    text = BUILD_CHECKS.read_text(encoding="utf-8")
    assert "python tools/local_wheel_gate.py --check-reproducible" in text
    gate = tool("local_wheel_gate")
    assert f"SOURCE_DATE_EPOCH={gate.REPRODUCIBLE_EPOCH} PYTHONHASHSEED=0 python -m build" in text


def test_build_checks_say_which_checks_only_a_maintainer_runs() -> None:
    # The coverage report and `twine check` are run by hand. The document says no workflow runs
    # them, so a workflow that starts running one changes that sentence with it.
    text = " ".join(BUILD_CHECKS.read_text(encoding="utf-8").split())
    assert "The coverage report and `twine check` run only when these commands are run by hand" in text
    assert "no workflow runs either of them" in text
    for workflow in (CI, RELEASE):
        _load(workflow)  # skips in the source distribution, which does not ship .github/
        code = workflow.read_text(encoding="utf-8")
        for command in ("twine", "coverage report", "coverage run"):
            assert command not in code, (workflow.name, command)


@pytest.mark.parametrize("document", ["docs/maintainers/build-checks.md"])
def test_every_release_document_runs_as_written(document: str) -> None:
    # A release document builds the artifacts and checks them with twine. A document that
    # builds without the fixed epoch checks a wheel other than the one whose reproducibility
    # the gate shows, and one that runs `twine check` before installing twine stops there,
    # since no extra of this package provides it.
    gate = tool("local_wheel_gate")
    lines = [line.strip() for line in (ROOT / document).read_text(encoding="utf-8").splitlines()]
    builds = [line for line in lines if line.endswith("python -m build")]
    assert builds, f"{document} does not build the artifacts"
    reproducible = f"SOURCE_DATE_EPOCH={gate.REPRODUCIBLE_EPOCH} PYTHONHASHSEED=0 python -m build"
    assert all(line == reproducible for line in builds), builds
    check = lines.index("python -m twine check dist/*")
    assert "python -m pip install twine" in lines[:check], f"{document} checks with twine before installing it"


# The source distribution ships its own test suite and its own tools, and a reviewer is meant
# to be able to run them as shipped: `local_wheel_gate.py --check-dist` extracts the sdist into
# a clean environment and requires the suite to pass there. MANIFEST.in grafts tests, tools and
# docs and names root files one by one, so a root artifact a shipped test reads
# (GOVERNANCE.md, which tools/check_public_boundary.py asks every tree who maintains it, or
# CONFORMANCE_CONSUMER.json, which the README is held to) can be left out, and the shipped
# tests then fail on extraction. The rule below is the one rule that covers the class:
# whatever a shipped test or tool reads from the root is shipped.
# Files the build backend always puts in the sdist are not MANIFEST.in's to name.
ALWAYS_SHIPPED = frozenset({"pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in", "PKG-INFO"})


def _root_files_read_by_what_is_shipped() -> set[str]:
    manifest_sources = [
        path
        for directory in ("tests", "tools")
        for path in sorted((ROOT / directory).rglob("*.py"))
        if "__pycache__" not in path.parts
    ]
    corpus = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in manifest_sources)
    root_files = {path.name for path in ROOT.iterdir() if path.is_file()} - ALWAYS_SHIPPED
    return {name for name in root_files if f'"{name}"' in corpus or f"'{name}'" in corpus}


def test_the_sdist_ships_every_root_artifact_its_own_tests_and_tools_read() -> None:
    needed = _root_files_read_by_what_is_shipped()
    # Anti-vacuity: an empty set would satisfy every assertion below and prove nothing. The two
    # named here are root artifacts the shipped suite reads.
    assert {"GOVERNANCE.md", "CONFORMANCE_CONSUMER.json"} <= needed, needed
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    included = {line.split(None, 1)[1].strip() for line in manifest.splitlines() if line.startswith("include ")}
    missing = sorted(name for name in needed if name not in included)
    assert not missing, (
        f"MANIFEST.in does not ship {missing}, which the shipped tests or tools read from the "
        f"root; an extracted source distribution cannot run its own suite without them"
    )


# The gate that runs the extracted sdist's suite declares the configuration it measures: a
# fresh environment holding the sdist and pytest, with no sibling repository beside it and
# LOQUITUR_REQUIRE_SIBLINGS unset. Inherited from whoever runs it, that variable would turn
# the skips of the modules that need a sibling into failures, so one artifact could be green
# in one place and red in another. A gate whose subject is the artifact cannot take its
# configuration from the operator, so it removes the variable from the child environment
# rather than hoping it is absent.
def test_the_extracted_suite_runs_without_the_workspace_sibling_requirement() -> None:
    gate = tool("local_wheel_gate")
    supplied = {"PATH": "/usr/bin", gate.SIBLINGS_ENV: "1", "PYTHONUTF8": "1"}
    produced = gate.extracted_suite_environment(supplied)
    assert gate.SIBLINGS_ENV not in produced
    # Anti-vacuity: an empty environment would satisfy the line above and starve the child.
    assert produced == {"PATH": "/usr/bin", "PYTHONUTF8": "1"}
    for spelling in ("true", "yes", "on", "0", ""):
        assert gate.SIBLINGS_ENV not in gate.extracted_suite_environment({gate.SIBLINGS_ENV: spelling})


def test_the_extracted_suite_is_the_only_place_that_environment_is_built() -> None:
    # One rule per concept: the pytest run in check_sdist_is_self_verifying is the subject of
    # the rule, and it is the only subprocess whose environment is filtered. A second filtered
    # call would be a second rule about what the gate measures.
    source = (ROOT / "tools" / "local_wheel_gate.py").read_text(encoding="utf-8")
    assert source.count("extracted_suite_environment()") == 1
    # The one call adds PYTHONIOENCODING, so the child writes the UTF-8 its output is read as.
    assert source.count('env={**extracted_suite_environment(), "PYTHONIOENCODING": "utf-8"}') == 1
