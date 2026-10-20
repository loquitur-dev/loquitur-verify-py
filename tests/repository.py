"""Files of this repository that several test modules read: the workflows, pyproject.toml, the tools.

Each is read here once, so a test module does not import a private helper of another test module,
and a change to how one of them is read is made in one place.

Not a test module: pytest collects test_*.py, and this is imported by them, as siblings.py is.
"""

from __future__ import annotations

import functools
import importlib.util
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
CI = WORKFLOWS / "ci.yml"


@functools.cache
def workflow(path: Path) -> dict[str, Any]:
    """A workflow file, parsed. The source distribution does not ship .github/: there it skips."""
    if not path.is_file():
        if (ROOT / "PKG-INFO").is_file():
            pytest.skip("the source distribution does not ship .github/; the workflows are held in the repository")
        pytest.fail(f"{path.relative_to(ROOT).as_posix()} is missing")
    import yaml  # the dev extra installs it; imported here so that an extracted sdist collects every module

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), path
    return document


# The Wycheproof vector file, which MANIFEST.in keeps out of the source distribution (NOTICE).
WYCHEPROOF_FILE = "tests/vectors/ecdsa_secp256k1_sha256_p1363_test.json"


def in_source_distribution() -> bool:
    """True when this tree is an extracted source distribution, not the repository."""
    return (ROOT / "PKG-INFO").is_file()


def require_repository_file(relative: str, why: str) -> Path:
    """A file the repository holds and the source distribution leaves out: skipped there, failed here."""
    path = ROOT / relative
    if not path.is_file():
        if in_source_distribution():
            pytest.skip(f"the source distribution does not ship {relative}: {why}")
        pytest.fail(f"{relative} is missing")
    return path


def pyproject() -> dict[str, Any]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


@functools.cache
def tool(name: str) -> ModuleType:
    """tools/<name>.py, loaded once. The tools are scripts, not a package, so they are loaded by path."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    assert spec is not None and spec.loader is not None, name
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flat(relative: str) -> str:
    """The text of a file of this repository with every run of whitespace read as one space."""
    return " ".join((ROOT / relative).read_text(encoding="utf-8").split())
