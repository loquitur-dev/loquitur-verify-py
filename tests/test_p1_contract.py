"""P1's closed contract: the input-key projection, the input hash form, the sidecar, the size.

bundle-objects.md §3 says ik MUST be a non-empty array of strings, and the whole-input
fallback of canonicalization-and-hashing.md applies only when ik is absent: a P1 declaring
ik "asset_id", 42, null or {"asset_id": 1} would otherwise commit to every key of the input
under a declaration that named none of them. Every bundle below is sealed around its one
defect, with ih computed over what a whole-input fallback would hash, so only the contract
can refuse it. The rows that accept (an absent ik over the whole input, a key absent from the
input as null) and the other refusals (an empty ik, the 1024-byte bound) run in the same test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_builder import Bundle, jcs, sha

from loquitur.verify import cli
from loquitur.verify.runner import verify_path


def _verify(tmp_path: Path, bundle: Bundle) -> dict:
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


def _with_ik(value: object, *, drop: bool = False) -> Bundle:
    bundle = Bundle()
    whole = sha(jcs(bundle.json("canonical_input.json")))

    def mutate(p1: dict) -> None:
        if drop:
            p1.pop("ik")
        else:
            p1["ik"] = value
        p1["ih"] = "sha256:" + whole

    return bundle.edit("p1.json", mutate).seal()


def _messages(report: dict) -> str:
    return json.dumps(report["errors"])


def test_the_input_key_projection(tmp_path: Path) -> None:
    got, want = {}, {}
    not_a_list = {
        "string": "asset_id",
        "number": 42,
        "null": None,
        "mixed": ["asset_id", 42],
        "object": {"asset_id": 1},
        "list-of-null": [None],
        "nested-list": [["asset_id"]],
    }
    for label, value in not_a_list.items():
        report = _verify(tmp_path / label, _with_ik(value))
        got[label] = (
            report["status"],
            "p1_input_key_projection_not_a_string_list" in _messages(report),
            "p1_input_key_projection_not_a_string_list" in report["notes"],
        )
        want[label] = ("OFFLINE_FAIL", True, False)
    duplicate = Bundle()
    canonical_input = duplicate.json("canonical_input.json")
    duplicate.edit(
        "p1.json",
        lambda p: p.update(
            ik=["asset_type", "asset_type"], ih="sha256:" + sha(jcs({"asset_type": canonical_input["asset_type"]}))
        ),
    )
    report = _verify(tmp_path / "duplicate", duplicate.seal())
    got["duplicate"] = (report["status"], "p1_input_key_projection_duplicate" in _messages(report))
    want["duplicate"] = ("OFFLINE_FAIL", True)
    report = _verify(tmp_path / "empty", _with_ik([]))
    got["empty"] = (report["status"], "p1_empty_input_key_projection" in _messages(report))
    want["empty"] = ("OFFLINE_FAIL", True)
    # Only an absent ik means the whole canonical input.
    report = _verify(tmp_path / "absent", _with_ik(None, drop=True))
    got["absent"] = (report["status"], report["p1"]["input_keys"])
    want["absent"] = ("OFFLINE_OK", sorted(Bundle().json("canonical_input.json")))
    # A key listed in ik and absent from the input maps to null.
    absent_key = Bundle().edit("p1.json", lambda p: p.update(ik=p["ik"] + ["absent_key"])).reproject().seal()
    projected = {key: absent_key.json("canonical_input.json").get(key) for key in absent_key.json("p1.json")["ik"]}
    got["absent-key"] = (
        projected["absent_key"],
        absent_key.json("p1.json")["ih"] == "sha256:" + sha(jcs(projected)),
        _verify(tmp_path / "absent-key", absent_key)["status"],
    )
    want["absent-key"] = (None, True, "OFFLINE_OK")
    assert got == want


@pytest.mark.parametrize("spell", [str.upper, lambda d: " " + d, None], ids=["uppercase", "padded", "absent"])
def test_an_input_hash_outside_its_form_fails_the_p1_contract(tmp_path: Path, spell) -> None:
    # ih is part of P1's closed contract. A malformed ih refuses the P1, not only the input hash
    # (a note): p1_sha256 and the envelope's P1 link are false, as in loquitur-verify-ts.
    if spell is None:
        bundle = Bundle().edit("p1.json", lambda p: p.pop("ih")).seal()
    else:
        bundle = Bundle().edit("p1.json", lambda p: p.update(ih=spell(p["ih"]))).seal()
    report = _verify(tmp_path, bundle)
    assert report["status"] == "OFFLINE_FAIL"
    assert "p1_ih_missing_or_invalid" in _messages(report)
    assert report["checks"]["p1_sha256"] is False
    assert report["checks"]["p1_input_hash"] is False
    assert report["checks"]["envelope_links"] is False


def test_the_p1_sidecar_is_read_as_written_and_canonical_p1_is_bounded(tmp_path: Path) -> None:
    got, want = {}, {}
    spellings = {"trailing-newline": lambda d: d + "\n", "uppercase": str.upper, "leading-space": lambda d: " " + d}
    for label, spell in spellings.items():
        bundle = Bundle().seal()
        bundle.members["p1.sha256"] = spell(bundle.members["p1.sha256"].decode()).encode()
        bundle.seal(p1=False)
        report = _verify(tmp_path / label, bundle)
        got[label] = (report["status"], report["checks"]["p1_sha256"])
        want[label] = ("OFFLINE_FAIL", False)
    # Canonical P1 is at most 1024 bytes (bundle-objects.md §3).
    report = _verify(tmp_path / "1024", _p1_of_size(1024))
    got["1024-bytes"] = report["status"]
    want["1024-bytes"] = "OFFLINE_OK"
    report = _verify(tmp_path / "1025", _p1_of_size(1025))
    got["1025-bytes"] = (report["status"], report["checks"]["p1_sha256"], "p1_too_large" in _messages(report))
    want["1025-bytes"] = ("OFFLINE_FAIL", False, True)
    assert got == want


def _p1_of_size(size: int) -> Bundle:
    bundle = Bundle()
    p1 = bundle.json("p1.json")
    padding = size - len(jcs({**p1, "ik": p1["ik"] + ["k"]}))
    bundle.edit("p1.json", lambda p: p.update(ik=p["ik"] + ["k" + "x" * padding]))
    bundle.reproject()
    assert len(jcs(bundle.json("p1.json"))) == size
    return bundle.seal()
