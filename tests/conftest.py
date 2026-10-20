"""Pytest collection guard for the optional ``[narrative]`` extra.

The verifier is intentionally distributable and testable without
``loquitur-schemas``. Narrative rendering is an optional feature gated behind
the ``narrative`` extra; the production code degrades gracefully (returns
``None``) when ``loquitur-schemas`` is absent. The narrative *tests*, however,
assert on rendered content and therefore require the extra to be installed.

Without this guard, a checkout installed without the extra (the base package
alone) and then tested fails those modules with an opaque ``TypeError`` from
``None`` rendering, which says nothing about the verifier. This conftest collects
the narrative-only modules in every configuration and, when the optional
dependency is not importable, skips each of their tests with the reason, so:

  * base matrix (no extra)      -> narrative tests collected and skipped, each named;
  * narrative/dev matrix (extra)-> narrative tests run.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable

import pytest
from siblings import required_message, siblings_required

_NARRATIVE_ONLY_MODULES = (
    "test_cli_narrative.py",
    "test_golden_narratives.py",
    "test_narrative.py",
    "test_narrative_compliance_executive.py",
    "test_narrative_authorization.py",
    "test_narrative_manifest_missing.py",
    "test_narrative_refusal.py",
)


def _schemas_available() -> bool:
    return importlib.util.find_spec("loquitur.schemas") is not None


# ``collect_ignore`` is the wrong instrument for this. It drops the five modules BEFORE
# collection, so a base run would report a clean green with no line anywhere saying that a
# large part of the suite had been removed, and the base matrix is exactly that run. The
# modules themselves import fine without ``loquitur-schemas``; only their assertions on
# rendered content need it. So collect them and skip each test individually instead: the
# collected count is the same in both configurations, every dropped test names itself in
# the summary, and a narrative module that stops importing at all turns the base matrix red
# rather than disappearing from it.
_NARRATIVE_EXTRA_ABSENT = "narrative rendering needs the optional [narrative] extra (loquitur-schemas)"
_NEEDS_NARRATIVE_EXTRA = pytest.mark.skip(reason=_NARRATIVE_EXTRA_ABSENT)

# Where LOQUITUR_REQUIRE_SIBLINGS is set, the workspace says loquitur-schemas is installed, and
# its absence is a broken install rather than the base matrix: those tests fail instead, each
# with the same reason. A mark can only skip, so the failure is raised when the test is called.
_REQUIRED_BUT_ABSENT: set[str] = set()


def pytest_collection_modifyitems(items: Iterable[pytest.Item]) -> None:
    if _schemas_available():
        return
    for item in items:
        if item.path.name in _NARRATIVE_ONLY_MODULES:
            if siblings_required():
                _REQUIRED_BUT_ABSENT.add(item.nodeid)
            else:
                item.add_marker(_NEEDS_NARRATIVE_EXTRA)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item: pytest.Item) -> None:
    if item.nodeid in _REQUIRED_BUT_ABSENT:
        pytest.fail(required_message(_NARRATIVE_EXTRA_ABSENT), pytrace=False)
