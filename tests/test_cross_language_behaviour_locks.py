"""Locks on behavior both reference verifiers share, held on the Python side.

Each lock below is a point where two readings of the protocol give different answers on the
same bytes. loquitur-verify-ts asserts its side of each pair; these tests hold the Python side
in place, so neither half of the agreement can move alone:
  * a JSON member named __proto__ is an ordinary member (RFC 8259, RFC 8785): it is kept in
    canonical bytes, in the P1 projection, in a receipt and in manifest.files;
  * a canonical_input.json that is present but is not a JSON object, or does not parse, fails
    the input hash; only a file that is absent leaves it unevaluated;
  * The link check compares reason codes as exact multisets, so a NUL-joined or comma-joined code, or a
    duplicated one, is not the list it resembles, while order does not matter.

A lock pins nothing this package changed, so on its own it would pass without any change. Each
test therefore runs its locks beside a refusal on the same surface that this package makes:
a lone surrogate in a member name, a present ik that is not a list, a receipt outside its
contract at the structure check, a canonical input carrying 1e400 outside the projection, and a padded reason
code. Every test fails without that refusal.
"""

from __future__ import annotations

from pathlib import Path

from bundle_builder import Bundle, jcs, nested_text, sha, with_raw_member

from loquitur.verify import cli
from loquitur.verify.canonical import CanonicalizationError, canonical_json_bytes, loads_json_bytes
from loquitur.verify.runner import verify_path


def _report(tmp_path: Path, bundle: Bundle, entry: Path | None = None) -> dict:
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root, registry_entry_path=entry).to_dict()
    argv = [str(root), "--json"] + (["--registry-entry", str(entry)] if entry else [])
    assert cli.main(argv) == report["exit_code"]
    return report


def _outcome(report: dict, *checks: str) -> tuple:
    return (report["status"], *(report["checks"][name] for name in checks))


# ---------------------------------------------------------------- __proto__ is a member


def _canonical(value: object) -> object:
    try:
        return canonical_json_bytes(value)
    except CanonicalizationError:
        return "CanonicalizationError"
    except Exception as exc:  # noqa: BLE001 - an escaping exception is what the refusal row detects
        return f"escaped {type(exc).__name__}"


def test_a_member_name_is_canonicalised_as_written() -> None:
    # The reference bytes are RFC 8785's, independent of this package.
    assert jcs({"__proto__": {"hidden": "A"}}) == b'{"__proto__":{"hidden":"A"}}'
    rows = {
        # Locks: __proto__ is kept.
        "top-level": ('{"__proto__":{"hidden":"A"}}', b'{"__proto__":{"hidden":"A"}}'),
        "nested": ('{"x":{"__proto__":1,"value":1}}', b'{"x":{"__proto__":1,"value":1}}'),
        "in-array": ('[{"__proto__":null}]', b'[{"__proto__":null}]'),
        "scalar": ('{"__proto__":"s","a":1}', b'{"__proto__":"s","a":1}'),
    }
    got = {name: _canonical(loads_json_bytes(text.encode("utf-8"), name="probe")) for name, (text, _) in rows.items()}
    got["reference-hex"] = _canonical(loads_json_bytes(b'{"__proto__":{"hidden":"A"}}', name="probe")).hex()
    # Refused here: a member name that is not a Unicode string is refused, not an escape.
    got["lone-surrogate-name"] = _canonical({"\udc00x": 1})
    assert got == {
        **{name: expected for name, (_, expected) in rows.items()},
        "reference-hex": "7b225f5f70726f746f5f5f223a7b2268696464656e223a2241227d7d",
        "lone-surrogate-name": "CanonicalizationError",
    }


def test_a_proto_member_and_inherited_names_project_as_members(tmp_path: Path) -> None:
    got, want = {}, {}
    projected = Bundle().edit("canonical_input.json", lambda o: o.update({"__proto__": {"hidden": "A"}}))
    projected.edit("p1.json", lambda p: p.update(ik=p["ik"] + ["__proto__"])).reproject().seal()
    report = _report(tmp_path / "projected", projected)
    got["projected-proto"] = (report["status"], "__proto__" in report["p1"]["input_keys"])
    want["projected-proto"] = ("OFFLINE_OK", True)
    whole = Bundle().edit("canonical_input.json", lambda o: o.update({"__proto__": {"hidden": "A"}}))
    whole.edit("p1.json", lambda p: p.pop("ik")).reproject().seal()
    got["whole-input-proto"] = _report(tmp_path / "whole", whole)["status"]
    want["whole-input-proto"] = "OFFLINE_OK"
    for name in ("constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"):
        bundle = Bundle().edit("p1.json", lambda p, n=name: p.update(ik=p["ik"] + [n])).reproject().seal()
        got[f"absent-{name}"] = _report(tmp_path / f"absent-{name}", bundle)["status"]
        want[f"absent-{name}"] = "OFFLINE_OK"
    # Refused here: ik "__proto__" as a string, not a list, is refused rather than verified over
    # the whole input.
    as_string = Bundle()
    whole_hash = sha(jcs(as_string.json("canonical_input.json")))
    as_string.edit("p1.json", lambda p: p.update(ik="__proto__", ih=whole_hash)).seal()
    got["ik-string"] = _report(tmp_path / "ik-string", as_string)["status"]
    want["ik-string"] = "OFFLINE_FAIL"
    assert got == want


def test_a_proto_member_added_to_a_committed_object_breaks_it(tmp_path: Path) -> None:
    receipt = Bundle().seal()
    entry = receipt.link_entry(tmp_path / "receipt-entry.json")
    receipt.edit("verification_receipt.json", lambda r: r.update({"__proto__": {"status": "pass"}}))
    manifest = Bundle().seal()
    manifest_entry = manifest.link_entry(tmp_path / "manifest-entry.json")
    manifest.members["__proto__"] = b"smuggled"
    manifest.edit("manifest.json", lambda m: m["files"].update({"__proto__": sha(b"smuggled")}))
    got = {
        "receipt-link": _outcome(_report(tmp_path / "receipt-link", receipt, entry), "registry_link"),
        "manifest-link": _outcome(
            _report(tmp_path / "manifest-link", manifest, manifest_entry), "manifest_sha256", "registry_link"
        ),
        # Refused here: the same receipt with no entry is refused at the structure check for its closed contract.
        "receipt-structure": _outcome(_report(tmp_path / "receipt-structure", receipt), "registry_link"),
    }
    assert got == {
        "receipt-link": ("OFFLINE_FAIL", False),
        "manifest-link": ("OFFLINE_FAIL", False, False),
        "receipt-structure": ("OFFLINE_FAIL", None),
    }


# ---------------------------------------------------------------- a present canonical input is evaluated


def test_a_present_canonical_input_is_evaluated_and_only_an_absent_one_is_not(tmp_path: Path) -> None:
    rows: dict[str, tuple[bytes, bool]] = {
        "number": (b"1", False),
        "string": (b'"x"', False),
        "true": (b"true", False),
        "null": (b"null", False),
        "array": (b"[1,2]", False),
        "truncated": (b'{"asset_type":', False),
        "duplicate-key": (b'{"asset_type":"property","asset_type":"fund_nav"}', False),
        "depth-20000": (nested_text(20000).encode(), False),
        "number-no-ik": (b"1", True),
    }
    got, want = {}, {}
    for name, (raw, drop_ik) in rows.items():
        bundle = Bundle()
        bundle.members["canonical_input.json"] = raw
        if drop_ik:
            bundle.edit("p1.json", lambda p: p.pop("ik"))
        got[name] = _outcome(_report(tmp_path / name, bundle.seal()), "canonical_input_present", "p1_input_hash")
        want[name] = ("OFFLINE_FAIL", True, False)
    # Refused here: 1e400 outside the projection does not load as infinity and verify.
    overflow = Bundle()
    overflow.members["canonical_input.json"] = with_raw_member(overflow.json("canonical_input.json"), "zz", "1e400")
    got["overflow-unprojected"] = _outcome(
        _report(tmp_path / "overflow", overflow.seal()), "canonical_input_present", "p1_input_hash"
    )
    want["overflow-unprojected"] = ("OFFLINE_FAIL", True, False)
    undeclared = Bundle()
    del undeclared.members["canonical_input.json"]
    undeclared.edit("manifest.json", lambda m: m["files"].pop("canonical_input.json"))
    got["absent-undeclared"] = _outcome(
        _report(tmp_path / "absent-undeclared", undeclared.seal()), "canonical_input_present", "p1_input_hash"
    )
    want["absent-undeclared"] = ("OFFLINE_REVIEW", False, None)
    declared = Bundle().seal()
    del declared.members["canonical_input.json"]
    got["absent-declared"] = _outcome(
        _report(tmp_path / "absent-declared", declared), "manifest_files", "canonical_input_present"
    )
    want["absent-declared"] = ("OFFLINE_FAIL", False, False)
    assert got == want


# ---------------------------------------------------------------- reason codes as exact multisets


def _reason_codes_case(tmp_path: Path, receipt_codes: list[str], entry_codes: list[str]) -> dict:
    bundle = Bundle().edit("verification_receipt.json", lambda r: r.update(reason_codes=receipt_codes)).seal()
    entry = bundle.link_entry(tmp_path / "entry.json", reason_codes=entry_codes)
    return _report(tmp_path, bundle, entry)


def _reason_codes_ok(report: dict) -> bool:
    return next(c for c in report["registry_link"]["checks"] if c["name"] == "reason_codes")["ok"]


def test_reason_codes_are_compared_as_exact_multisets(tmp_path: Path) -> None:
    pair = ["AUTHORIZATION_VERIFIED", "INTEGRITY_OK"]
    rows = {
        "nul-joined": (["AUTHORIZATION_VERIFIED\u0000INTEGRITY_OK"], pair),
        "space-joined": (["AUTHORIZATION_VERIFIED INTEGRITY_OK"], pair),
        "comma-joined": (["AUTHORIZATION_VERIFIED,INTEGRITY_OK"], pair),
        "duplicated": (["INTEGRITY_OK", "INTEGRITY_OK"], ["INTEGRITY_OK"]),
        "reordered": (["INTEGRITY_OK", "AUTHORIZATION_VERIFIED"], pair),
        # Refused here: a padded code is not trimmed into the code it pads, and does not link.
        "padded": ([" INTEGRITY_OK "], ["INTEGRITY_OK"]),
    }
    got = {}
    for name, (receipt_codes, entry_codes) in rows.items():
        report = _reason_codes_case(tmp_path / name, receipt_codes, entry_codes)
        got[name] = (report["status"], report["checks"]["registry_link"], _reason_codes_ok(report))
    refused = ("OFFLINE_FAIL", False, False)
    assert got == {
        "nul-joined": refused,
        "space-joined": refused,
        "comma-joined": refused,
        "duplicated": refused,
        "reordered": ("OFFLINE_OK", True, True),
        "padded": refused,
    }
