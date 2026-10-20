"""A RecursionError is a fault of the host, never a verdict, at every catch that guards a read,
a parse or a cryptographic step (report-contract.md section 4).

Every document and value is held to input strictness rule 6's 64 levels by an iterative scan
before the verifier recurses on it, so a RecursionError says the host's recursion limit is too
small for a value the protocol admits. It propagates out of the library, and the command line
reports it as an internal error. A catch that contained it would turn the same valid run, made
with little stack left, into a failed check.

Two proofs, each site by site. The first reads every ``except`` clause of the package and
requires that none catches a RecursionError, apart from the three places that handle one on
purpose: the command line's two contract boundaries and the narrative renderer, which runs on a
report already made and decides no verdict. The second raises a RecursionError from the call each
main catch guards (the input inspection, the inventory, a member's path and bytes, the strict JSON
decoder, the signing payload and the curve arithmetic) and requires that very error to come out of
``verify_path``. The faults are injected with monkeypatch from the test; the package has no hook.
"""

from __future__ import annotations

import ast
import builtins
import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import loquitur.verify.canonical as canonical
import loquitur.verify.members as members
import loquitur.verify.secp256k1 as secp256k1
import loquitur.verify.trust_registry as trust_registry
from loquitur.verify.runner import verify_path

# The clauses read are those of the package the guarded calls below run: the imported one.
PACKAGE = Path(members.__file__).resolve().parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE_DIR = FIXTURES / "link_valid_bundle"
VALID_ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
VALID_TRUST = FIXTURES / "authorization_valid_trust_registry.json"

# The handlers that take a RecursionError on purpose, by module, and why.
#   cli.py: the command line's contract boundaries turn a fault of the tool into the internal
#     error report (one for the trust-root file, one around verify_path).
#   narrative.py: the narrative is rendered from a report already made; a catalog lookup it
#     cannot make leaves a paragraph out and decides nothing.
DELIBERATE = {"cli.py": 2, "narrative.py": 7}


def _resolve(expression: ast.expr, namespace: dict[str, Any]) -> tuple[type[BaseException], ...]:
    value = eval(compile(ast.Expression(expression), "<except>", "eval"), namespace)  # noqa: S307
    return value if isinstance(value, tuple) else (value,)


def _reraises(handler: ast.ExceptHandler) -> bool:
    # Only a clause that does nothing but re-raise is passed over: one that might return first
    # on some path could still contain the fault.
    return len(handler.body) == 1 and isinstance(handler.body[0], ast.Raise) and handler.body[0].exc is None


def handlers_catching_recursion(source: str, namespace: dict[str, Any]) -> list[int]:
    """Line numbers of the ``except`` clauses in ``source`` that would contain a RecursionError."""
    found: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ExceptHandler) or _reraises(node):
            continue
        caught = (BaseException,) if node.type is None else _resolve(node.type, namespace)
        if any(issubclass(RecursionError, kind) for kind in caught):
            found.append(node.lineno)
    return found


def _namespace(module_name: str) -> dict[str, Any]:
    module = importlib.import_module(f"loquitur.verify.{module_name}")
    return {**vars(builtins), **vars(module)}


def _modules() -> list[Path]:
    return sorted(p for p in PACKAGE.glob("*.py") if p.name != "__init__.py")


def test_no_catch_of_the_package_contains_a_recursion_error_but_the_deliberate_ones() -> None:
    checked = 0
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        checked += sum(isinstance(n, ast.ExceptHandler) for n in ast.walk(ast.parse(source)))
        lines = handlers_catching_recursion(source, _namespace(path.stem))
        assert len(lines) == DELIBERATE.get(path.name, 0), f"{path.name}: clauses at {lines} contain a RecursionError"
    assert checked >= 100, f"only {checked} except clauses were read; the check is thin"


@pytest.mark.parametrize("kind", ["Exception", "RuntimeError", "RecursionError", "BaseException"])
def test_the_clause_reader_finds_a_clause_widened_to_contain_the_fault(kind: str) -> None:
    # Non-vacuity of the reader above: every handler of members.py, widened one at a time, is
    # reported, so a catch that came to contain the fault could not pass unseen.
    source = (PACKAGE / "members.py").read_text(encoding="utf-8")
    namespace = _namespace("members")
    assert handlers_catching_recursion(source, namespace) == []
    # A clause that only re-raises contains nothing, however wide; every other one is widened.
    clauses = [
        n
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.ExceptHandler) and n.type is not None and not _reraises(n)
    ]
    assert clauses, "members.py has no typed except clause to widen"
    lines = source.split("\n")
    for clause in clauses:
        row = clause.lineno - 1
        typed = ast.get_source_segment(source, clause.type)
        assert typed is not None and typed in lines[row]
        widened = list(lines)
        widened[row] = lines[row].replace(f"except {typed}", f"except {kind}", 1)
        assert handlers_catching_recursion("\n".join(widened), namespace) == [clause.lineno]


# --- the guarded calls, each made to raise the fault --------------------------------------------


def _from(name: str) -> bool:
    # Frames are walked directly: inspect.stack() would ask the file system, which is patched.
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_name == name:
            return True
        frame = frame.f_back
    return False


def _raise_once(original: Callable[..., Any], site: str, raised: list[RecursionError]) -> Callable[..., Any]:
    def replacement(*args: Any, **kwargs: Any) -> Any:
        if not raised and _from(site):
            raised.append(RecursionError("maximum recursion depth exceeded"))
            raise raised[0]
        return original(*args, **kwargs)

    return replacement


def _fault_propagates(
    monkeypatch: pytest.MonkeyPatch, holder: Any, attribute: str, site: str, authorization_files: bool
) -> None:
    raised: list[RecursionError] = []
    monkeypatch.setattr(holder, attribute, _raise_once(getattr(holder, attribute), site, raised))
    documents = {"registry_entry_path": VALID_ENTRY, "trust_registry_path": VALID_TRUST} if authorization_files else {}
    with pytest.raises(RecursionError) as caught:
        verify_path(BUNDLE_DIR, **documents)
    assert raised, f"{attribute} was never called from {site}: the test would measure nothing"
    assert caught.value is raised[0]


SITES = [
    # (holder, attribute, the function whose catch guards the call, needs the authorization documents)
    (members.os, "stat", "inspect_path", False),
    (members.os, "scandir", "bundle_inventory", False),
    (members.os, "lstat", "member_path", False),
    (members.os, "lstat", "read_member_bytes", False),
    (canonical.json, "loads", "loads_json_bytes", False),
    (trust_registry, "signing_message_bytes", "_verify_signature", True),
    (secp256k1, "parse_uncompressed_public_key", "verify_digest", True),
]


@pytest.mark.parametrize(
    ("holder", "attribute", "site", "authorization_files"), SITES, ids=[f"{s[2]}-{s[1]}" for s in SITES]
)
def test_a_recursion_error_from_a_guarded_call_comes_out_of_verify_path(
    monkeypatch: pytest.MonkeyPatch, holder: Any, attribute: str, site: str, authorization_files: bool
) -> None:
    baseline = verify_path(
        BUNDLE_DIR,
        **({"registry_entry_path": VALID_ENTRY, "trust_registry_path": VALID_TRUST} if authorization_files else {}),
    )
    assert baseline.status in {"OFFLINE_OK", "OFFLINE_REVIEW"}, (
        "the baseline run is not the valid run the fault is injected into"
    )
    _fault_propagates(monkeypatch, holder, attribute, site, authorization_files)
