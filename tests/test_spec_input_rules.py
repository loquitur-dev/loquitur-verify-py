"""Input rules, held to loquitur-protocol bundle-objects.md and canonicalization-and-hashing.md.

These rules are written there as text and tables: the
whitespace set W, the portable member-name rule, the nesting bound, exact UTF-8, calendar instants, the
bundle root and the file beside it, both envelope names, and a canonical input that is present and
unreadable. Each table and each number is read from the sibling checkout (spec_tables.py) and
checked against this verifier: W against every Unicode code point, the grammar against every name
of its table, the nesting bound at the bound and one past it, and the calendar against every
instant of its table in a receipt, a trust-root document and an operator's instant.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest
from bundle_builder import Bundle, nested_text
from spec_tables import code, document, table

from loquitur.verify.canonical import JsonLoadError, loads_json_bytes
from loquitur.verify.contract_validation import contract_errors
from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time
from loquitur.verify.manifest import UnsafeManifestPathError, _normalize_manifest_path, is_blank
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import TrustRootError, parse_trust_roots

BUNDLE_OBJECTS = "bundle-objects.md"
HASHING = "canonicalization-and-hashing.md"


def _code_points(cell: str) -> range:
    match = re.fullmatch(r"U\+([0-9A-F]{4,6})(?: to U\+([0-9A-F]{4,6}))?", cell)
    assert match, cell
    first = int(match.group(1), 16)
    return range(first, int(match.group(2) or match.group(1), 16) + 1)


def test_the_whitespace_set_w_is_the_one_this_verifier_uses() -> None:
    text = document(BUNDLE_OBJECTS)
    specified = {point for row in table(text, ["W"]) for point in _code_points(row["W"])}
    implemented = {point for point in range(0x110000) if is_blank(chr(point))}
    assert specified == implemented
    flat = " ".join(text.split())
    for outside in re.findall(r"(U\+[0-9A-F]{4}) and (U\+[0-9A-F]{4}) are not in W", flat)[0]:
        assert int(outside[2:], 16) not in implemented


def test_the_portable_member_name_rule() -> None:
    rows = table(document(BUNDLE_OBJECTS), ["member name", "a portable member name"])
    got, expected = {}, {}
    for row in rows:
        name = json.loads(code(row["member name"]))
        try:
            _normalize_manifest_path(name)
            got[name] = True
        except UnsafeManifestPathError:
            got[name] = False
        expected[name] = row["a portable member name"] == "yes"
    assert got == expected
    assert set(expected.values()) == {True, False}


def _sealed(tmp_path: Path, change) -> dict[str, Any]:
    bundle = Bundle()
    change(bundle)
    bundle.seal()
    return verify_path(bundle.write(tmp_path / "bundle")).to_dict()


def test_the_nesting_bound(tmp_path: Path) -> None:
    flat = " ".join(document(HASHING).split())
    bound = int(re.search(r"\*\*Nesting depth at most (\d+)\.\*\* A scalar has depth 0", flat).group(1))
    assert f"A document of depth {bound} is valid, and one of depth {bound + 1} or more is invalid" in flat
    loads_json_bytes(nested_text(bound).encode())
    with pytest.raises(JsonLoadError):
        loads_json_bytes(nested_text(bound + 1).encode())
    # In an unprojected member of the canonical input: {"deep": <arrays>} is one level deeper.
    within = _sealed(
        tmp_path / "within",
        lambda b: b.edit("canonical_input.json", lambda c: c.update(deep=json.loads(nested_text(bound - 1)))),
    )
    beyond = _sealed(tmp_path / "beyond", lambda b: b.members.update({"canonical_input.json": _with_deep(b, bound)}))
    assert (within["status"], beyond["status"]) == ("OFFLINE_OK", "OFFLINE_FAIL")


def _with_deep(bundle: Bundle, depth: int) -> bytes:
    body = json.dumps(bundle.json("canonical_input.json"), separators=(",", ":"))
    return (body[:-1] + ',"deep":' + nested_text(depth) + "}").encode()


def test_utf8_exactly() -> None:
    flat = " ".join(document(HASHING).split())
    assert "invalid UTF-8 is invalid, and so is a leading byte-order mark" in flat
    loads_json_bytes(b"{}")
    for data in (b"\xef\xbb\xbf{}", b'{"a":"\xff"}'):
        with pytest.raises(JsonLoadError):
            loads_json_bytes(data)


def test_instants_are_calendar_instants(tmp_path: Path) -> None:
    rows = table(document(HASHING), ["instant", "calendar instant"])
    receipt = Bundle().json("verification_receipt.json")
    got, expected = {}, {}
    for row in rows:
        instant = code(row["instant"])
        refused = []
        refused.append(
            any(
                "calendar" in error
                for error in contract_errors("verification_receipt", {**receipt, "verified_at": instant})
            )
        )
        try:
            parse_trust_roots(
                {
                    "object_type": "trust_root_document",
                    "schema_version": "v1",
                    "roots": [
                        {
                            "key_id": "r",
                            "key_type": "secp256k1",
                            "public_key_hex": "04" + "11" * 64,
                            "not_before": instant,
                            "not_after": "2999-01-01T00:00:00Z",
                        }
                    ],
                }
            )
            refused.append(False)
        except TrustRootError:
            refused.append(True)
        try:
            operator_evaluation_time(instant)
            refused.append(False)
        except EvaluationTimeError:
            refused.append(True)
        got[instant] = refused
        expected[instant] = [row["calendar instant"] == "no"] * 3
    assert got == expected
    assert {row["calendar instant"] for row in rows} == {"yes", "no"}
    # At load, at every level: a receipt at the structure check.
    report = _sealed(
        tmp_path / "structure",
        lambda b: b.edit("verification_receipt.json", lambda r: r.update(verified_at="2026-02-30T00:00:00Z")),
    )
    assert (report["status"], [e["code"] for e in report["errors"]]) == (
        "OFFLINE_FAIL",
        ["verification_receipt_contract_violation"],
    )


def test_the_bundle_root_both_envelope_names_and_an_unreadable_canonical_input(tmp_path: Path) -> None:
    flat = " ".join(document(BUNDLE_OBJECTS).split())
    assert "A directory given to a verifier is itself the bundle root" in flat
    assert (
        "This version defines no other name for any of them: `envelope.json`, in particular, is an ordinary member name."
        in flat
    )
    assert (
        "both reference verifiers report `canonical_input_present` `true`, `p1_input_hash` `false` and `p1_sha256` `false`"
        in flat
    )

    source = Bundle().seal().write(tmp_path / "source" / "bundle")
    wrapper = verify_path(source.parent).to_dict()
    archive = tmp_path / "peer.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for member in sorted(source.rglob("*")):
            handle.write(member, "bundle/" + member.relative_to(source).as_posix())
        handle.writestr("beside.txt", b"x")
    peer = verify_path(archive).to_dict()
    both = _sealed(tmp_path / "both", lambda b: b.members.update({"envelope.json": b.members["envelope_env1.json"]}))
    unreadable = _sealed(tmp_path / "ci", lambda b: b.members.update({"canonical_input.json": b"[1]"}))
    assert (wrapper["status"], [e["code"] for e in wrapper["errors"]]) == ("OFFLINE_FAIL", ["bundle_root_invalid"])
    assert (peer["status"], peer["outcome"]["reason"]) == ("OFFLINE_REVIEW", "container_extra_files")
    # envelope.json beside the envelope is an undeclared member, never a second envelope.
    assert (both["status"], both["errors"], both["review_reasons"]) == ("OFFLINE_REVIEW", [], ["bundle_extra_files"])
    checks = unreadable["checks"]
    assert (
        unreadable["status"],
        checks["canonical_input_present"],
        checks["p1_input_hash"],
        checks["p1_sha256"],
        checks["envelope_links"],
    ) == (
        "OFFLINE_FAIL",
        True,
        False,
        False,
        True,
    )
