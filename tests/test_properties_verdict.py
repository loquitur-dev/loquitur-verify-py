"""Metamorphic properties of the verdict, over a valid fixture bundle (small example budget).

Each example runs ``runner.verify_path``, the whole verification the command line runs, over
tests/fixtures/link_valid_bundle (PASS as it is) after one generated change. Keys are minted in
memory for the run (tests/authorization_kit.py) and never written. These properties are the
maintainer's own testing, not an audit.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from functools import cache
from typing import Any

import property_profile
import pytest
from authorization_kit import BUNDLE, IssuerKey, authorization_material, write_json
from hypothesis import given, settings
from hypothesis import strategies as st

from loquitur.verify.runner import verify_path

DECLARED = sorted(json.loads((BUNDLE / "manifest.json").read_text(encoding="utf-8"))["files"])


@cache
def _issuer_key() -> IssuerKey:
    return IssuerKey()


def test_the_fixture_bundle_passes_unchanged() -> None:
    """The base of the properties below: without a change, the bundle is PASS."""
    assert verify_path(BUNDLE).to_dict()["verdict"] == "PASS"
    assert DECLARED


@settings(max_examples=property_profile.budget(60))
@given(st.data())
def test_changing_any_byte_of_a_declared_member_never_passes(
    tmp_path_factory: pytest.TempPathFactory, data: st.DataObject
) -> None:
    """Any one byte of any member the manifest declares, changed to any other value, makes the run other than PASS.

    The manifest commits to every declared member by digest, so no single-byte change can keep
    the verdict; shows that no byte of a declared member is outside the verdict's reach.
    """
    root = tmp_path_factory.mktemp("bundle") / "bundle"
    shutil.copytree(BUNDLE, root)
    name = data.draw(st.sampled_from(DECLARED), label="member")
    original = (root / name).read_bytes()
    index = data.draw(st.integers(0, len(original) - 1), label="index")
    replacement = data.draw(st.integers(0, 255).filter(lambda byte: byte != original[index]), label="byte")
    changed = bytearray(original)
    changed[index] = replacement
    (root / name).write_bytes(bytes(changed))
    report = verify_path(root).to_dict()
    assert report["verdict"] != "PASS", (name, index, replacement)
    assert report["exit_code"] != 0


_INSTANTS = st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1)).map(
    lambda moment: moment.strftime("%Y-%m-%dT%H:%M:%SZ")
)
_STATUSES = st.sampled_from(["active", "revoked", "suspended", "expired", "retired"])


def _mutate_registry(registry: dict[str, Any], status: str, window: tuple[str, str] | None) -> None:
    registry["entries"][0]["status"] = status
    if window is not None:
        registry["entries"][0]["effective_from"], registry["entries"][0]["expires_at"] = sorted(window)


@settings(max_examples=property_profile.budget(30))
@given(
    evaluation_time=st.one_of(st.none(), st.just("2026-05-10T00:00:00Z"), _INSTANTS),
    status=_STATUSES,
    window=st.one_of(st.none(), st.tuples(_INSTANTS, _INSTANTS)),
)
def test_a_trust_registry_without_a_trust_root_never_passes(
    tmp_path_factory: pytest.TempPathFactory,
    evaluation_time: str | None,
    status: str,
    window: tuple[str, str] | None,
) -> None:
    """A run with a trust registry and no trust root is never PASS, whatever the registry says.

    Without a pinned root nothing establishes who wrote the trust registry (trust-root.md
    section 6), so an authorization read from it can at most be REVIEW: shows that no evaluation
    time, key status or validity window turns an unpinned registry into a pass, including the
    one where the issuer's key is active and the signature holds.
    """
    directory = tmp_path_factory.mktemp("authorization")
    entry, registry = authorization_material(
        _issuer_key(), trust=lambda document: _mutate_registry(document, status, window)
    )
    report = verify_path(
        BUNDLE,
        registry_entry_path=write_json(directory / "entry.json", entry),
        trust_registry_path=write_json(directory / "trust_registry.json", registry),
        evaluation_time=evaluation_time,
        trust_roots=(),
    ).to_dict()
    assert report["verdict"] != "PASS"
    assert report["exit_code"] != 0
