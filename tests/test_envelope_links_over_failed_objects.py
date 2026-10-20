"""An envelope link holds only against a manifest or P1 that verified.

bundle-objects.md §4 holds a link only when the object it names parsed, satisfied its closed
contract and matched its sidecar, as loquitur-verify-ts does. A sidecar nothing verified is not
a digest to link against: comparing the P1 link against p1.sha256 beside a P1 refused for its
contract, a P1 whose sidecar did not match, or no P1 at all, or the manifest link against
manifest.sha256 beside a refused manifest, would report envelope_links true over an object the
same run refused. The manifest's declared files and the canonical input are not part of that object,
so a tampered member or canonical input leaves the links as they are.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bundle_builder import Bundle, jcs, sha

from loquitur.verify.runner import verify_path


def _checks(tmp_path: Path, bundle: Bundle) -> dict:
    report = verify_path(bundle.write(tmp_path / "bundle")).to_dict()
    return {**report["checks"], "status": report["status"], "notes": report["notes"]}


def _p1_ik(value: object) -> Bundle:
    bundle = Bundle()
    whole = sha(jcs(bundle.json("canonical_input.json")))
    return bundle.edit("p1.json", lambda p: p.update(ik=value, ih=whole)).seal()


@pytest.mark.parametrize(
    "build",
    [
        lambda: _p1_ik("asset_id"),
        lambda: _p1_ik([]),
        lambda: Bundle().edit("p1.json", lambda p: p.update(smuggled=1)).seal(),
    ],
    ids=["ik-string", "ik-empty", "unexpected-member"],
)
def test_a_link_to_a_p1_that_failed_its_contract_is_false(tmp_path: Path, build) -> None:
    checks = _checks(tmp_path, build())
    assert checks["status"] == "OFFLINE_FAIL"
    assert checks["envelope_sha256"] is True
    assert checks["envelope_links"] is False
    assert "envelope_p1_link_unverifiable" in checks["notes"]


def test_a_link_to_an_absent_p1_or_one_whose_sidecar_does_not_match_is_false(tmp_path: Path) -> None:
    absent = Bundle().seal()
    del absent.members["p1.json"]
    mismatched = Bundle().seal()
    mismatched.members["p1.sha256"] = b"0" * 64
    got = {
        name: (checks["p1_sha256"], checks["envelope_links"])
        for name, checks in (
            ("absent", _checks(tmp_path / "absent", absent)),
            ("sidecar-mismatch", _checks(tmp_path / "mismatch", mismatched.seal(p1=False))),
        )
    }
    assert got == {"absent": (False, False), "sidecar-mismatch": (False, False)}


def test_a_link_to_a_manifest_that_failed_its_contract_is_false(tmp_path: Path) -> None:
    bundle = Bundle().edit("manifest.json", lambda m: m.update(smuggled="x")).seal()
    checks = _checks(tmp_path / "smuggled", bundle)
    assert checks["manifest_sha256"] is True
    assert checks["envelope_links"] is False
    assert "envelope_manifest_link_unverifiable" in checks["notes"]
    # A bundle_id that is not a string fails the contract too, and its bundle_id link with it.
    not_a_string = _checks(
        tmp_path / "bundle-id", Bundle().edit("manifest.json", lambda m: m.update(bundle_id=False)).seal()
    )
    assert not_a_string["envelope_links"] is False


def test_a_changed_manifest_breaks_the_links_and_a_changed_member_or_input_does_not(tmp_path: Path) -> None:
    # The manifest changes after sealing; its sidecar and the envelope still name the old one.
    changed_manifest = Bundle().seal().edit("manifest.json", lambda m: m.update(schema_version="changed"))
    tampered_input = Bundle().edit("canonical_input.json", lambda o: o.update(currency="USD")).seal()
    unreadable_input = Bundle()
    unreadable_input.members["canonical_input.json"] = b"not valid JSON"
    tampered_member = Bundle()
    tampered_member.members["extra.txt"] = b"declared\n"
    tampered_member.edit("manifest.json", lambda m: m["files"].update({"extra.txt": ""})).seal()
    tampered_member.members["extra.txt"] = b"tampered\n"
    rows = {
        "changed-manifest": (changed_manifest, "manifest_sha256"),
        "tampered-canonical-input": (tampered_input, "p1_input_hash"),
        "unreadable-canonical-input": (unreadable_input.seal(), "p1_input_hash"),
        "tampered-declared-member": (tampered_member, "manifest_files"),
    }
    got = {}
    for name, (bundle, failed_check) in rows.items():
        checks = _checks(tmp_path / name, bundle)
        got[name] = (checks["status"], checks[failed_check], checks["envelope_links"])
    assert got == {
        "changed-manifest": ("OFFLINE_FAIL", False, False),
        "tampered-canonical-input": ("OFFLINE_FAIL", False, True),
        "unreadable-canonical-input": ("OFFLINE_FAIL", False, True),
        "tampered-declared-member": ("OFFLINE_FAIL", False, True),
    }
