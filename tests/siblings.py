"""Sibling repositories these tests read, and what their absence means.

loquitur-verify-py is deliberately standalone: a base install has no loquitur-schemas, and a
single-repository clone has no sibling checkout beside it. Tests that compare this package
with a sibling skip there, because the absence is not a defect of this repository.

A workspace that assembles every repository sets LOQUITUR_REQUIRE_SIBLINGS, and there the
same absence is a defect, a checkout or an install that failed, which a skip reports as
a gate that passed. The cross-repository drift and equivalence modules, the differential
against the reference signer and the narrative modules come through here, so none of them
skips where the variable is set.

Not a test module: pytest collects test_*.py, and this is imported by them, as
import_guards.py is.
"""

from __future__ import annotations

import functools
import importlib
import os
from collections.abc import Callable
from types import ModuleType
from typing import NoReturn, TypeVar

import pytest

REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"

_Test = TypeVar("_Test", bound=Callable[..., object])


def siblings_required() -> bool:
    return os.environ.get(REQUIRE_SIBLINGS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def required_message(message: str) -> str:
    return f"{REQUIRE_SIBLINGS_ENV} is set, but {message}"


def absent(message: str) -> NoReturn:
    """Skip for an absent sibling, or fail when the workspace requires every sibling.

    Usable at module level: a skip there skips the module, and a failure there is a
    collection error that names the sibling, which stops the session before any test runs,
    as a workspace missing a sibling it requires should.
    """
    __tracebackhide__ = True  # report the calling test module, not this helper
    if siblings_required():
        pytest.fail(required_message(message), pytrace=False)
    pytest.skip(message, allow_module_level=True)


def import_sibling(module: str, message: str) -> ModuleType:
    """``pytest.importorskip`` for a module that a sibling repository provides."""
    __tracebackhide__ = True
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        absent(f"{message} ({module} is not importable: {exc})")


def needs(present: bool, message: str) -> Callable[[_Test], _Test]:
    """A ``skipif`` that fails instead when the workspace requires every sibling.

    A mark is decided at import and can only skip, so when the sibling is required and
    absent the test is wrapped to fail with the same message.
    """

    def decorate(test: _Test) -> _Test:
        if present:
            return test
        if not siblings_required():
            return pytest.mark.skip(reason=message)(test)

        @functools.wraps(test)
        def fail(*args: object, **kwargs: object) -> object:
            __tracebackhide__ = True
            pytest.fail(required_message(message), pytrace=False)

        return fail  # type: ignore[return-value]

    return decorate
