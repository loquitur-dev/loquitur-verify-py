"""Canonicalization failures are refused content, never a verifier fault.

The strict loader refuses 1e400, unsafe integers, lone surrogates and deep nesting in
every document it reads, so a bundle cannot carry them to the canonicalizer. These
tests reach the canonicalization sites anyway, by handing them values the loader would have
refused, because the containment must not depend on the order in which two layers happen to
run. Without the containment:
  * a lone surrogate in a member NAME would escape rfc8785 as UnicodeEncodeError;
  * a value nested past the interpreter stack would escape as RecursionError;
  * an unguarded call to canonical_json_sha256 in manifest.py or envelope.py would let either
    class escape verify_path, and the CLI would report INTERNAL_ERROR with exit 3.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_builder import Bundle

from loquitur.verify import cli, envelope, manifest
from loquitur.verify.canonical import CanonicalizationError, canonical_json_bytes
from loquitur.verify.envelope import EnvelopeVerificationError, verify_envelope
from loquitur.verify.manifest import ManifestVerificationError, verify_manifest
from loquitur.verify.runner import verify_path


def _deep(depth: int) -> list:
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


def test_every_canonicalization_failure_is_a_canonicalization_error() -> None:
    # The member-name and depth rows, which escape without the containment, run in one table
    # with a surrogate value, inf and an unsafe integer.
    rows = {
        "surrogate-key": {"\udc00x": 1},
        "nested-surrogate-key": {"outer": {"\ud800": 1}},
        "surrogate-value": {"s": "\ud800"},
        "surrogate-in-array": ["x\udfff"],
        "inf": {"n": float("inf")},
        "unsafe-int": {"n": 9007199254740993},
        "depth-5000": _deep(5000),
    }
    got = {}
    for label, value in rows.items():
        try:
            canonical_json_bytes(value)
        except CanonicalizationError:
            got[label] = "CanonicalizationError"
        except Exception as exc:  # noqa: BLE001 - the escape is the defect a row detects
            got[label] = f"escaped {type(exc).__name__}"
        else:
            got[label] = "serialized"
    assert got == dict.fromkeys(rows, "CanonicalizationError")


def _deep_object(depth: int) -> dict:
    """An object of exactly ``depth`` levels: the empty object has depth 1."""
    value: dict = {}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


def test_the_canonicalizer_refuses_exactly_what_nesting_rule_6_refuses() -> None:
    """Depth 64 serializes and depth 65 is refused, whatever the interpreter.

    canonicalization-and-hashing.md, input strictness rule 6: a scalar has depth 0, a container
    one more than its deepest member, depth 64 is valid and 65 is not, and no host stack or
    recursion limit decides the outcome. A bound taken from the interpreter would serialize a
    65-level value everywhere, and refuse a 700-level one under Python 3.11 while serializing it
    under 3.12 and 3.13, which inline comprehensions and so spend half the frames per level.
    """
    # A list that contains itself is walked only to the bound, never forever, and is refused
    # by the bound, not through RecursionError.
    loop: list = []
    loop.append(loop)
    got = {}
    # _deep(n) wraps an empty list, itself of depth 1, n times: its depth is n + 1.
    for label, value in {
        "list-64": _deep(63),
        "object-64": _deep_object(64),
        "list-65": _deep(64),
        "object-65": _deep_object(65),
        "list-700": _deep(699),
        "tuple-65": (_deep(63),),
        "contains-itself": loop,
    }.items():
        try:
            canonical_json_bytes(value)
        except CanonicalizationError as exc:
            got[label] = str(exc)
        else:
            got[label] = "serialized"
    refused = "canonical_json_failed:nesting_too_deep"
    assert got == {
        "list-64": "serialized",
        "object-64": "serialized",
        "list-65": refused,
        "object-65": refused,
        "list-700": refused,
        "tuple-65": refused,
        "contains-itself": refused,
    }


def _permissive(data: bytes, *, name: str = "json") -> object:
    """A loader that lets a hostile value through, standing in for any path that does."""
    return json.loads(data.decode("utf-8"))


_HOSTILE_TEXT = {
    "surrogate-key": '"\\udc00x": 1',
    "surrogate-value": '"hostile": "\\ud800"',
    "1e400": '"hostile": 1e400',
    "unsafe-int": '"hostile": 9007199254740993',
    "depth-700": '"hostile": ' + "[" * 700 + "]" * 700,
}


def _splice(document: bytes, member_text: str) -> bytes:
    body = document.decode("utf-8")
    return (body[:-1] + "," + member_text + "}").encode("utf-8")


@pytest.mark.parametrize("label", sorted(_HOSTILE_TEXT))
def test_a_manifest_that_cannot_be_canonicalized_is_a_manifest_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str
) -> None:
    bundle = Bundle().seal()
    bundle.members["manifest.json"] = _splice(bundle.members["manifest.json"], _HOSTILE_TEXT[label])
    root = bundle.write(tmp_path / "bundle")
    monkeypatch.setattr(manifest, "loads_json_bytes", _permissive)

    with pytest.raises(ManifestVerificationError, match="^manifest_canonicalize_failed:"):
        verify_manifest(root)

    report = verify_path(root)
    payload = report.to_dict()
    assert report.status == "OFFLINE_FAIL"
    assert payload["checks"]["manifest_sha256"] is False
    assert payload["errors"][0]["code"] == "manifest_verification_failed"
    assert payload["errors"][0]["message"].startswith("manifest_canonicalize_failed:")
    assert payload["outcome"]["category"] == "malformed_input_failure"
    assert cli.main([str(root), "--json"]) == 1


@pytest.mark.parametrize("label", sorted(_HOSTILE_TEXT))
def test_an_envelope_that_cannot_be_canonicalized_is_an_envelope_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str
) -> None:
    bundle = Bundle().seal()
    # asset_id is an allowed envelope member, so a hostile STRING passes the closed contract and
    # reaches the digest comparison. The other values do not: since the optional members carry
    # declared types (bundle-objects.md §4), a float, an unsafe integer or an array in asset_id
    # is a shape failure, as an unknown member name is. Both are refused content; which of the
    # two paths refuses it is what this row records.
    text = _HOSTILE_TEXT[label].replace('"hostile"', '"asset_id"')
    bundle.members["envelope_env1.json"] = _splice(bundle.members["envelope_env1.json"], text)
    root = bundle.write(tmp_path / "bundle")
    monkeypatch.setattr(envelope, "loads_json_bytes", _permissive)

    if label == "surrogate-value":
        with pytest.raises(EnvelopeVerificationError, match="^envelope_canonicalize_failed:"):
            verify_envelope(root)
    else:
        # A shape failure: reported, never raised.
        result = verify_envelope(root)
        assert result.status == "OFFLINE_FAIL"
        assert result.envelope_sha256_ok is False

    report = verify_path(root)
    assert report.status == "OFFLINE_FAIL"
    assert report.to_dict()["outcome"]["category"] != "internal_error"
    assert cli.main([str(root), "--json"]) == 1
