"""The fixed Hypothesis profile of the property tests (tests/test_properties_*.py).

Every property module imports this one before it defines a test, so every property test runs
under the same profile: derandomized (the examples are a function of the test alone, the same
on every run and every host), no example database (nothing a previous run found changes what
the next run tries), no deadline (a slow Windows host is not a failure) and a bounded number
of examples, so the whole property suite stays within about a minute.

A larger budget is opt-in: the environment variable LOQUITUR_PROPERTY_EXAMPLES, an integer,
raises max_examples of every property test to that number (never lowers it). The runs are
the maintainer's own testing, carried out with the help of AI tools, which is internal
verification and not an audit.
"""

from __future__ import annotations

import os

import pytest

# Hypothesis is in the dev extra, not a runtime dependency. The published sdist's own test run
# installs the sdist and pytest alone, so there the property modules are skipped, with this reason.
pytest.importorskip("hypothesis", reason="the property tests need the dev extra (hypothesis)")

from hypothesis import HealthCheck, settings  # noqa: E402

PROFILE = "loquitur-fixed"
EXAMPLES_ENV = "LOQUITUR_PROPERTY_EXAMPLES"
DEFAULT_EXAMPLES = 200


def _requested() -> int:
    raw = os.environ.get(EXAMPLES_ENV, "").strip()
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{EXAMPLES_ENV} must be an integer, not {raw!r}") from exc


def budget(default: int) -> int:
    """``default`` examples, or LOQUITUR_PROPERTY_EXAMPLES when that is larger."""
    return max(default, _requested())


settings.register_profile(
    PROFILE,
    derandomize=True,
    database=None,
    deadline=None,
    max_examples=budget(DEFAULT_EXAMPLES),
    print_blob=False,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(PROFILE)
