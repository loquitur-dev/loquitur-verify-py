"""The public API parity map, tools/public_api_parity.json, against what this package exports.

The map lists every export of ``loquitur.verify.__all__``, every member of a result an exported
function returns, and every member of the report ``verify_path`` writes that carries a verdict, a
status, an authorization, a signature, a root or a trust result, each with its counterpart in
loquitur-verify-ts or none and the reason. A member carries one when the last segment of its name
matches the map's ``carrier_pattern``. These tests fail when such a member or an export is missing
from the map, when the map names something this package no longer has, and, where the sibling is
checked out, when the map differs from loquitur-verify-ts scripts/public-api-parity.json, which must
be the same file byte for byte (LOQUITUR_REQUIRE_SIBLINGS makes the sibling required).

The differential harness of loquitur-conformance calls each pair's operations through the
test-only adapters; tests/test_differential_adapter.py holds this side of them.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import re
import typing
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import IssuerKey, authorization_material, run_authorization
from siblings import absent

import loquitur.verify

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "tools" / "public_api_parity.json"
SIBLING_MAP = ROOT.parent / "loquitur-verify-ts" / "scripts" / "public-api-parity.json"
PREFIX = "loquitur.verify."
REPORT = "report:"


def _map() -> dict[str, Any]:
    return json.loads(MAP_PATH.read_text(encoding="utf-8"))


def _py_names() -> list[str]:
    return [name for pair in _map()["pairs"] for name in pair["py"]]


def _carries(name: str) -> bool:
    return re.search(_map()["carrier_pattern"], name.rsplit(".", 1)[-1]) is not None


def _resolve(dotted: str) -> Any:
    """The object a dotted name of the package names: the longest importable module, then attributes."""
    parts = dotted.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            target: Any = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        for attribute in parts[cut:]:
            if inspect.isclass(target):
                fields = (
                    {field.name for field in dataclasses.fields(target)} if dataclasses.is_dataclass(target) else set()
                )
                target = attribute if attribute in fields else inspect.getattr_static(target, attribute)
            else:
                target = getattr(target, attribute)
        return target
    raise ImportError(dotted)


def _members(cls: type) -> list[str]:
    """The fields and properties of a result class."""
    fields = [field.name for field in dataclasses.fields(cls)] if dataclasses.is_dataclass(cls) else []
    properties = [name for name, value in inspect.getmembers(cls) if isinstance(value, property)]
    return fields + properties


def _result_classes() -> dict[str, type]:
    """The classes the exported functions return, by their dotted names."""
    found: dict[str, type] = {}
    for name in loquitur.verify.__all__:
        exported = getattr(loquitur.verify, name)
        if not inspect.isfunction(exported):
            continue
        returned = typing.get_type_hints(exported).get("return")
        if inspect.isclass(returned):
            found[f"{returned.__module__}.{returned.__qualname__}"] = returned
    return found


def _report() -> dict[str, Any]:
    """A report with every section written: an authorization run over the link fixture bundle."""
    import tempfile

    entry, registry = authorization_material(IssuerKey())
    with tempfile.TemporaryDirectory() as directory:
        return run_authorization(Path(directory), entry, registry)


def _leaves(value: dict[str, Any], path: str = "") -> list[str]:
    """Every member of the report that holds a value rather than a section, as a dotted path."""
    out: list[str] = []
    for key, member in value.items():
        name = f"{path}.{key}" if path else key
        if isinstance(member, dict) and key != "vocabularies":
            out.extend(_leaves(member, name))
        else:
            out.append(name)
    return out


def test_the_map_is_one_document_with_disjoint_unique_names() -> None:
    document = _map()
    assert document["schema_version"] == "loquitur.public_api_parity.v1"
    ids = [pair["id"] for pair in document["pairs"]]
    assert len(ids) == len(set(ids))
    py = _py_names() + document["py_not_carrying"]["names"]
    assert len(py) == len(set(py)), "a name of this package is listed twice"
    for pair in document["pairs"]:
        assert pair["carries"], pair["id"]
        assert pair["py"] or pair.get("py_reason"), pair["id"]
        assert pair["ts"] or pair.get("ts_reason"), pair["id"]
    raw = MAP_PATH.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf") and raw.endswith(b"\n") and b"\r" not in raw


def test_every_export_is_in_the_map() -> None:
    listed = {name.removeprefix(PREFIX) for name in _py_names() + _map()["py_not_carrying"]["names"]}
    missing = sorted(set(loquitur.verify.__all__) - listed)
    assert not missing, f"exported and not in tools/public_api_parity.json: {missing}"


def test_every_name_the_map_lists_is_still_there() -> None:
    report = set(_leaves(_report()))
    gone = []
    for name in _py_names() + _map()["py_not_carrying"]["names"]:
        if name.startswith(REPORT):
            if name.removeprefix(REPORT) not in report:
                gone.append(name)
            continue
        assert name.startswith(PREFIX), name
        short = name.removeprefix(PREFIX)
        if "." not in short:
            if short not in loquitur.verify.__all__:
                gone.append(name)
            continue
        try:
            _resolve(name)
        except (ImportError, AttributeError):
            gone.append(name)
    assert not gone, f"tools/public_api_parity.json names what this package no longer has: {gone}"


def test_every_carrying_member_of_a_returned_result_is_in_the_map() -> None:
    listed = set(_py_names()) | set(_map()["py_not_carrying"]["names"])
    classes = _result_classes()
    assert {name.rsplit(".", 1)[-1] for name in classes} >= {
        "TrustRegistryVerificationResult",
        "RegistryLinkVerificationResult",
    }
    missing = [
        f"{dotted}.{member}"
        for dotted, cls in classes.items()
        for member in _members(cls)
        if _carries(member) and f"{dotted}.{member}" not in listed
    ]
    assert not missing, f"result members that carry a result and are not in the map: {missing}"


def test_every_carrying_report_member_is_in_the_map() -> None:
    listed = set(_py_names()) | set(_map()["py_not_carrying"]["names"])
    missing = [f"{REPORT}{leaf}" for leaf in _leaves(_report()) if _carries(leaf) and f"{REPORT}{leaf}" not in listed]
    assert not missing, f"report members that carry a result and are not in the map: {missing}"


def test_the_trust_registry_result_has_no_ok() -> None:
    """The member the cryptographic review found misread: the map names authorization_holds, never ok."""
    assert "loquitur.verify.trust_registry.TrustRegistryVerificationResult.ok" not in _py_names()
    assert "loquitur.verify.trust_registry.TrustRegistryVerificationResult.authorization_holds" in _py_names()


def test_the_registry_link_result_has_no_ok() -> None:
    """The link result's ok read True for a link in REVIEW: the map names link_holds, never ok."""
    assert "loquitur.verify.registry_link.RegistryLinkVerificationResult.ok" not in _py_names()
    assert "loquitur.verify.registry_link.RegistryLinkVerificationResult.link_holds" in _py_names()


def test_the_map_is_the_sibling_map() -> None:
    if not SIBLING_MAP.is_file():
        absent(f"loquitur-verify-ts is not checked out beside this repository ({SIBLING_MAP} is missing)")
    assert MAP_PATH.read_bytes() == SIBLING_MAP.read_bytes(), (
        "tools/public_api_parity.json and loquitur-verify-ts scripts/public-api-parity.json differ"
    )


@pytest.mark.parametrize(
    "pattern_case", [("verdict", True), ("trust_registry_path", False), ("authorization_holds", True)]
)
def test_the_carrier_pattern_reads_the_last_segment(pattern_case: tuple[str, bool]) -> None:
    name, carries = pattern_case
    assert _carries(f"report:trust_registry.{name}") is carries
