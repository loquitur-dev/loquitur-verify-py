"""A layer's refusal reads the same on both paths that judge it.

The verification row of a layer (report-contract.md section 5.3) is judged by the layer when the
host reads every member it reads, and over the members the host did read when it failed to read
another. Both paths apply the layer's one rule list, so a refusal carries the same words whichever
path judged it. Each case here is run twice: once with every member readable, once with the host
failing to read another member of the same layer, injected where the verifier opens it.

The canonicalization refusals are not reachable from a document read under input strictness; a
permissive loader stands in for any path that would let such a value through.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from bundle_builder import Bundle

from loquitur.verify import envelope, manifest
from loquitur.verify.host_path import host_path
from loquitur.verify.runner import verify_path


@contextlib.contextmanager
def _refusing_read_of(monkeypatch: pytest.MonkeyPatch, target: Path) -> Iterator[list[str]]:
    """Opening ``target`` fails with EACCES; it can still be listed and inspected."""
    real_open = open
    host_target = Path(host_path(target))
    seen: list[str] = []

    def refusing_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and Path(os.fspath(file)) == host_target:
            seen.append(os.fspath(file))
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(file))
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", refusing_open)
        patch.setattr("io.open", refusing_open)
        yield seen


def _permissive(data: bytes, *, name: str = "json") -> object:
    """A loader that lets a lone surrogate through, standing in for any path that does."""
    return json.loads(data.decode("utf-8"))


def _splice(document: bytes, member_text: str) -> bytes:
    body = document.decode("utf-8")
    return (body[:-1] + "," + member_text + "}").encode("utf-8")


def _not_strict(name: str, *, seal_first: bool = True) -> Callable[[], Bundle]:
    def make() -> Bundle:
        bundle = Bundle().seal() if seal_first else Bundle()
        bundle.members[name] = b'{"s": '
        return bundle if seal_first else bundle.seal()

    return make


def _uncanonicalisable(name: str, member: str) -> Callable[[], Bundle]:
    def make() -> Bundle:
        bundle = Bundle().seal()
        bundle.members[name] = _splice(bundle.members[name], f'"{member}": "\\ud800"')
        return bundle

    return make


def _p1_breaking_its_contract() -> Bundle:
    return Bundle().edit("p1.json", lambda p1: p1.update({"unexpected": 1})).seal()


# name: (bundle, the member the host fails to read on the second path, the row, the module whose
# loader is made permissive, or None)
_CASES: dict[str, tuple[Callable[[], Bundle], str, str, Any]] = {
    "manifest not strict JSON": (_not_strict("manifest.json"), "manifest.sha256", "manifest_verification_failed", None),
    "manifest that cannot be canonicalised": (
        _uncanonicalisable("manifest.json", "hostile"),
        "manifest.sha256",
        "manifest_verification_failed",
        manifest,
    ),
    "P1 breaking its contract": (_p1_breaking_its_contract, "canonical_input.json", "p1_verification_failed", None),
    "canonical input not strict JSON": (
        _not_strict("canonical_input.json", seal_first=False),
        "p1.json",
        "p1_verification_failed",
        None,
    ),
    "envelope not strict JSON": (
        _not_strict("envelope_env1.json"),
        "envelope.sha256",
        "envelope_verification_failed",
        None,
    ),
    "envelope that cannot be canonicalised": (
        _uncanonicalisable("envelope_env1.json", "asset_id"),
        "envelope.sha256",
        "envelope_verification_failed",
        envelope,
    ),
}


def _row(report: dict[str, Any], code: str) -> dict[str, Any]:
    rows = [error for error in report["errors"] if error["code"] == code]
    assert len(rows) == 1, (code, report["errors"])
    return rows[0]


@pytest.mark.parametrize("case", sorted(_CASES))
def test_a_refusal_reads_the_same_on_both_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    make, unread, code, loader_module = _CASES[case]
    root = make().write(tmp_path / "bundle")
    if loader_module is not None:
        monkeypatch.setattr(loader_module, "loads_json_bytes", _permissive)

    every_member_read = verify_path(root).to_dict()
    with _refusing_read_of(monkeypatch, root / unread) as seen:
        one_member_unread = verify_path(root).to_dict()
    assert seen, f"the host was never asked to read {unread}"

    read_row = code.replace("_verification_failed", "_read_failed")
    assert read_row not in [error["code"] for error in every_member_read["errors"]]
    _row(one_member_unread, read_row)
    judged_by_the_layer = _row(every_member_read, code)
    judged_over_what_was_read = _row(one_member_unread, code)
    assert judged_over_what_was_read == judged_by_the_layer
