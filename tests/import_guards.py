"""The allow-list of the verdict path.

The verdict path contains no network access and no AI. This module says what that sentence
means as imports, as one rule with three clauses. A module may be imported by the verifier,
or loaded while it is imported, when it is

  1. a module of the standard library that is not one of NETWORK_STDLIB_MODULES (the
     modules through which the standard library reaches a network, listed once here);
  2. a module of the ``loquitur`` namespace, which holds this package and the published
     packages beside it; or
  3. a top-level module provided by a distribution in the runtime dependency closure of this
     package: the distributions pyproject.toml declares under ``dependencies`` and under the
     runtime extras named in RUNTIME_EXTRAS, followed through the metadata of what is
     installed. The base closure is ``rfc8785`` and ``cryptography`` with what it requires; the
     ``narrative`` extra adds
     ``loquitur-schemas`` and what it requires, when it is installed.

Everything else is refused, whatever it is called: a model SDK, a web framework, a validator,
a numeric library, a module of an unpublished repository. An allow-list needs no list of the
things it refuses, so this file names none of them, and a package that does not exist yet is
refused by the same rule as one that does. A deny-list of named packages could only refuse what
someone had remembered to enumerate, and its enumeration would itself be text this repository
has no reason to carry.

tools/check_verdict_path_isolation.py applies the rule to every module of the package by
reading its syntax tree, which catches an import that a lazy function body would hide from
the runtime check, and to what a fresh import loads; the functions at the end apply it in
this process to what an import loads, for the tests and the CI job that use them.
"""

from __future__ import annotations

import importlib.metadata
import re
import sys
import tomllib
from collections.abc import Iterable
from functools import cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PYPROJECT = REPO / "pyproject.toml"

# The optional-dependency groups of pyproject.toml that are runtime features rather than
# tooling. `dev` is tooling: nothing the verifier runs imports it, and its distributions
# (pytest, build, coverage, the key-minting library the tests use) stay outside the allow-list
# even where they are installed, which is what makes the test suite's own imports refused.
RUNTIME_EXTRAS = ("narrative",)

# The modules through which the standard library reaches a network. An entry covers the
# module and everything under it: `http` covers `http.client` and `http.server`;
# `urllib.request` covers nothing else in `urllib`, whose `parse` is text processing.
# `asyncio` is refused whole: its streams and transports are network APIs and the verifier
# has no use for an event loop. `_socket` and `_ssl` are the extension modules behind
# `socket` and `ssl`, listed so that importing them directly is not a way around the rule.
NETWORK_STDLIB_MODULES = frozenset(
    {
        "socket",
        "_socket",
        "ssl",
        "_ssl",
        "socketserver",
        "http",
        "urllib.request",
        "urllib.robotparser",
        "asyncio",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "nntplib",
        "telnetlib",
        "xmlrpc",
        "wsgiref",
        "webbrowser",
        "multiprocessing.connection",
    }
)

# The project's own namespace: clause 2.
PROJECT_NAMESPACE = "loquitur"

_REQUIREMENT = re.compile(r"^\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[(?P<extras>[^\]]*)\])?")
_EXTRA_MARKER = re.compile(r"""extra\s*==\s*['"](?P<extra>[^'"]+)['"]""")


def normalize_distribution_name(name: str) -> str:
    """The normalized form of a distribution name: `Loquitur_Schemas` -> `loquitur-schemas`."""

    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirement(text: str) -> tuple[str, frozenset[str], str | None]:
    """(normalized name, extras requested of it, the extra marker it is conditional on)."""

    head, _, marker = text.partition(";")
    match = _REQUIREMENT.match(head)
    if match is None:
        raise ValueError(f"cannot read the requirement {text!r}")
    extras = frozenset(part.strip().lower() for part in (match.group("extras") or "").split(",") if part.strip())
    condition = _EXTRA_MARKER.search(marker)
    return normalize_distribution_name(match.group("name")), extras, condition.group("extra") if condition else None


def _project_table(pyproject: Path) -> dict:
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]


def declared_runtime_requirements(pyproject: Path = PYPROJECT) -> list[str]:
    """The requirement strings pyproject.toml declares for the base install and RUNTIME_EXTRAS."""

    project = _project_table(pyproject)
    requirements = list(project.get("dependencies", ()))
    for extra in RUNTIME_EXTRAS:
        requirements.extend(project.get("optional-dependencies", {}).get(extra, ()))
    return requirements


def _top_level_modules(distribution: importlib.metadata.Distribution) -> frozenset[str]:
    declared = distribution.read_text("top_level.txt")
    if declared:
        return frozenset(line.strip() for line in declared.splitlines() if line.strip())
    inferred: set[str] = set()
    for file in distribution.files or ():
        parts = file.parts
        if not parts or parts[0].endswith((".dist-info", ".egg-info")) or parts[0] in {"..", "__pycache__"}:
            continue
        if len(parts) == 1:
            if parts[0].endswith(".py"):
                inferred.add(parts[0][: -len(".py")])
            elif ".so" in parts[0] or ".pyd" in parts[0]:
                inferred.add(parts[0].split(".", 1)[0])
        else:
            inferred.add(parts[0])
    return frozenset(inferred)


@cache
def runtime_dependency_closure(pyproject: Path = PYPROJECT) -> dict[str, frozenset[str]]:
    """Every distribution of the runtime closure, mapped to the top-level modules it provides.

    Followed from pyproject.toml through the metadata of what is installed. A declared
    distribution that is not installed contributes nothing, which can only shrink the
    allow-list; missing_base_dependencies reports the case the tool treats as a failure.
    """

    closure: dict[str, frozenset[str]] = {}
    queue = [_parse_requirement(text)[:2] for text in declared_runtime_requirements(pyproject)]
    seen: set[tuple[str, frozenset[str]]] = set()
    while queue:
        name, extras = queue.pop(0)
        if (name, extras) in seen:
            continue
        seen.add((name, extras))
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        closure[name] = _top_level_modules(distribution)
        for text in distribution.requires or ():
            required, required_extras, condition = _parse_requirement(text)
            if condition is None or condition.lower() in extras:
                queue.append((required, required_extras))
    return closure


def missing_base_dependencies(pyproject: Path = PYPROJECT) -> list[str]:
    """Base dependencies pyproject.toml declares that are not installed: the closure cannot be read."""

    missing = []
    for text in _project_table(pyproject).get("dependencies", ()):
        name = _parse_requirement(text)[0]
        try:
            importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(name)
    return missing


@cache
def allowed_third_party_modules() -> frozenset[str]:
    """The top-level modules clause 3 allows."""

    return frozenset(module for modules in runtime_dependency_closure().values() for module in modules)


def disallowed_reason(module: str) -> str | None:
    """Why the verdict path may not import ``module``, or None when the allow-list admits it."""

    root = module.partition(".")[0]
    if module == "__main__" or root == PROJECT_NAMESPACE:
        return None
    if root in sys.stdlib_module_names:
        for entry in NETWORK_STDLIB_MODULES:
            if module == entry or module.startswith(entry + "."):
                return "network"
        return None
    if root in allowed_third_party_modules():
        return None
    return f"outside the runtime dependency closure [{', '.join(sorted(runtime_dependency_closure()))}]"


def is_forbidden_on_the_verdict_path(module: str) -> bool:
    """True for a module name the allow-list refuses."""

    return disallowed_reason(module) is not None


def _forbidden_modules_loaded(extra: Iterable[str] = ()) -> set[str]:
    """Return the modules present in ``sys.modules`` that the allow-list refuses.

    This module is not on the verdict path and is left out of its own answer. It
    loads `socket` itself: importlib.metadata parses distribution metadata with `email`,
    whose `utils` imports `socket`. In a fresh interpreter the eviction below removes it
    before the verifier is imported, so a verifier that imported `socket` is still seen
    (tests/test_verdict_path_isolation.py plants exactly that); under pytest the runner has
    loaded `socket` before this module is read, and the snapshot carries it either way.
    """

    names = set(extra)
    return {
        name
        for name in tuple(sys.modules)
        if name != __name__
        and (name in names or (is_forbidden_on_the_verdict_path(name) and not _embedded_in_allowed_extension(name)))
    }


def _embedded_in_allowed_extension(name: str) -> bool:
    """True for a module an allowed distribution's compiled extension registers under its own name.

    ``cryptography``'s compiled bindings register their OpenSSL module as ``_openssl`` (and
    ``_openssl.lib``): a module with no file and no import spec, found by no importer, that is
    an attribute of a module of the allowed distribution. It is that distribution's code, not a
    module the verifier imported, so the rule admits it. A module that has a file or an import
    spec is judged by its name alone.
    """

    module = sys.modules.get(name)
    if module is None or getattr(module, "__spec__", None) is not None or getattr(module, "__file__", None):
        return False
    parent, _, _ = name.rpartition(".")
    if parent and _embedded_in_allowed_extension(parent):
        return True
    allowed = allowed_third_party_modules()
    for owner_name, owner in tuple(sys.modules.items()):
        if owner_name.partition(".")[0] not in allowed or owner is None:
            continue
        if any(value is module for value in tuple(vars(owner).values())):
            return True
    return False


def snapshot_forbidden_modules(extra: Iterable[str] = ()) -> set[str]:
    """Return the refused modules already loaded before the import under test.

    Under a test runner the snapshot holds the runner itself; in a fresh interpreter it holds
    what site customization loaded at start-up (an editable-install finder, a build tool's
    shim). The invariant is that importing ``loquitur.verify`` must not load a refused
    module; it is not that the ambient interpreter starts empty. A module already loaded
    cannot be seen arriving, which is why a fresh interpreter evicts the snapshot with
    evict_preloaded_forbidden_modules before the import, and why the tool does the same.
    """

    return _forbidden_modules_loaded(extra)


def evict_preloaded_forbidden_modules() -> set[str]:
    """Remove every refused module from ``sys.modules`` so that an import of it is visible.

    The module objects stay alive wherever they are referenced (a finder on ``sys.meta_path``
    keeps working); only the cache entry goes, so a later ``import`` of the same name executes
    it again and puts it back, where the check sees it. For a fresh interpreter only: under a
    test runner the runner's own modules are in the snapshot and must stay where they are.
    """

    evicted = _forbidden_modules_loaded()
    for name in evicted:
        del sys.modules[name]
    return evicted


def assert_no_new_forbidden_modules_loaded(before: set[str], extra: Iterable[str] = ()) -> None:
    after = _forbidden_modules_loaded(extra)
    newly_loaded = sorted(after - before)
    if newly_loaded:
        # Raised, not asserted. The CI isolation gate runs this body through `python -`,
        # and `python -O` or PYTHONOPTIMIZE=1 deletes an `assert` statement outright:
        # the job would print "verifier import isolation OK" having checked nothing.
        # A gate an environment variable can silence is not a gate.
        reasons = ", ".join(f"{name} ({disallowed_reason(name)})" for name in newly_loaded)
        raise AssertionError(f"importing the verifier loaded modules the verdict-path allow-list refuses: {reasons}")
