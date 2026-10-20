"""The manifest's closed contract: member types, emptiness, digest form, names.

Every case is a bundle sealed around its one defect (tests/bundle_builder.py), so the
refusal can only come from the rule under test. Rows whose outcome does not depend on these
rules (a string schema_version, a whitespace-only bundle_id other than U+FEFF, a prefixed
digest, an absolute name, names inside the grammar) run in the same test as the rows the rules
refuse, so every test fails without its rule. Without these rules:
  * bundle_id and schema_version of any JSON type would verify, and str() coercion would make
    bundle_id 7 match an envelope carrying 7 or "7";
  * "non-empty after trimming" would mean whatever str.strip() removes, which is not what
    ECMAScript's trim() removes, so the two verifiers would disagree on U+001F, U+0085 and
    U+FEFF;
  * an uppercase or padded digest in manifest.files, or in manifest.sha256, would be folded
    into a valid one and match;
  * a manifest declaring manifest.json or manifest.sha256 would have the key dropped silently;
  * "./x", "sub\\x", "x.", "x:stream" and device names would be rewritten or passed to the
    filesystem, which resolves them to some other file.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bundle_builder import Bundle, sha

from loquitur.verify import cli, manifest
from loquitur.verify.manifest import verify_manifest
from loquitur.verify.members import fold_member_name
from loquitur.verify.runner import verify_path


def _verify(tmp_path: Path, bundle: Bundle) -> dict:
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


def _manifest_with(**fields: object) -> Bundle:
    return Bundle().edit("manifest.json", lambda m: m.update(fields)).seal()


# ---------------------------------------------------------------- member types


def test_schema_version_is_the_constant_of_this_bundle_version(tmp_path: Path) -> None:
    """bundle-objects.md section 2: schema_version is exactly loquitur.bundle.v1.

    A well-formed later version fires the version gate (exit 4); every other string, and every
    other type, is a rejection of the manifest.
    """
    refused_type = ("OFFLINE_FAIL", "manifest_invalid_field_type:schema_version")
    refused_value = ("OFFLINE_FAIL", "manifest_invalid_schema_version")
    rows = {
        "number": (1, refused_type),
        "boolean": (True, refused_type),
        "array": (["loquitur.bundle.v1"], refused_type),
        "object": ({"v": 1}, refused_type),
        "empty-string": ("", refused_value),
        "spaces": ("  ", refused_value),
        "u3000": ("\u3000", refused_value),
        "u200b": ("\u200b", refused_value),
        "old-fixture-name": ("manifest.fixture.v1", refused_value),
        "bundle-v1": ("bundle-v1", refused_value),
        "padded": (" loquitur.bundle.v1", refused_value),
        "uppercase": ("LOQUITUR.BUNDLE.V1", refused_value),
        "leading-zero": ("loquitur.bundle.v01", refused_value),
        "this-version": ("loquitur.bundle.v1", ("OFFLINE_OK", None)),
        "later-version": ("loquitur.bundle.v2", ("UNSUPPORTED_VERSION", None)),
    }
    got = {}
    for label, (value, _) in rows.items():
        report = _verify(tmp_path / label, _manifest_with(schema_version=value))
        shape = (report["manifest"] or {}).get("shape_errors", [])
        errors = [e for e in shape if "schema_version" in e]
        got[label] = (report["status"], errors[0] if errors else None)
    assert got == {label: expected for label, (_, expected) in rows.items()}


@pytest.mark.parametrize(
    "value",
    [None, 7, "", "A" * 64, "a" * 63, "a" * 65, "g" * 64, " " + "a" * 63],
    ids=["absent", "number", "empty", "uppercase", "63", "65", "not-hex", "padded"],
)
def test_the_nonce_is_64_lowercase_hex_characters(tmp_path: Path, value) -> None:
    """bundle-objects.md section 2 (N8a): a manifest without that nonce is refused by its contract."""
    bundle = Bundle().edit("manifest.json", lambda m: m.pop("nonce") if value is None else m.update(nonce=value))
    report = _verify(tmp_path, bundle.seal())
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_sha256"] is False or report["manifest"]["shape_errors"]
    assert any("nonce" in error for error in report["manifest"]["shape_errors"]), report["manifest"]["shape_errors"]
    assert report["outcome"]["reason"] == "manifest_integrity_failed"


def test_a_nonce_of_this_form_is_accepted(tmp_path: Path) -> None:
    report = _verify(tmp_path, Bundle().edit("manifest.json", lambda m: m.update(nonce="0f" * 32)).seal())
    assert report["status"] == "OFFLINE_OK"


@pytest.mark.parametrize(
    "value", [7, False, True, {"id": "x"}, ["x"]], ids=["number", "false", "true", "object", "array"]
)
def test_a_bundle_id_that_is_not_a_string_is_refused(tmp_path: Path, value: object) -> None:
    # seal() writes the same value into the envelope, so the envelope link would hold by
    # str() coercion; only the type rule can refuse it.
    report = _verify(tmp_path, _manifest_with(bundle_id=value))
    assert report["status"] == "OFFLINE_FAIL"
    assert "manifest_invalid_field_type:bundle_id" in report["manifest"]["shape_errors"]


# ---------------------------------------------------------------- the whitespace set W


def test_the_whitespace_set_is_the_union_of_python_strip_and_ecmascript_trim() -> None:
    expected = {
        *range(0x09, 0x0E),
        *range(0x1C, 0x21),
        0x85,
        0xA0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
        0xFEFF,
    }
    assert {ord(ch) for ch in manifest.WHITESPACE_W} == expected


def test_a_bundle_id_is_empty_only_when_made_of_the_whitespace_set(tmp_path: Path) -> None:
    empty = ("OFFLINE_FAIL", ["manifest_empty_field:bundle_id"])
    rows = {
        "empty": ((), empty),
        "spaces": ((0x20, 0x20, 0x20), empty),
        "tab-newline": ((0x09, 0x0A), empty),
        "u001f": ((0x1F,), empty),
        "u0085": ((0x85,), empty),
        "u00a0": ((0xA0,), empty),
        "u2028": ((0x2028,), empty),
        "u3000": ((0x3000,), empty),
        "ufeff": ((0xFEFF,), empty),
        # Outside W: a bundle_id, and a padded one is not trimmed into another.
        "u200b": ((0x200B,), ("OFFLINE_OK", [])),
        "u180e": ((0x180E,), ("OFFLINE_OK", [])),
        "padded": (tuple(map(ord, " padded-id ")), ("OFFLINE_OK", [])),
    }
    got = {}
    for label, (code_points, _) in rows.items():
        report = _verify(tmp_path / label, _manifest_with(bundle_id="".join(map(chr, code_points))))
        got[label] = (report["status"], report["manifest"]["shape_errors"])
    assert got == {label: expected for label, (_, expected) in rows.items()}


# ---------------------------------------------------------------- digest form


def test_a_file_digest_is_compared_as_written(tmp_path: Path) -> None:
    spellings = {
        "uppercase": str.upper,
        "mixed-case": lambda d: d[:10].upper() + d[10:],
        "padded": lambda d: "  " + d + "\n",
        "prefixed": lambda d: "sha256:" + d,
    }
    got = {}
    for label, spell in spellings.items():
        bundle = Bundle().seal()
        bundle.edit("manifest.json", lambda m, s=spell: m["files"].update({"p1.json": s(m["files"]["p1.json"])}))
        bundle.seal(p1=False, files=False)
        report = _verify(tmp_path / label, bundle)
        check = next(c for c in report["manifest"]["file_checks"] if c["name"] == "p1.json")
        got[label] = (
            report["status"],
            report["checks"]["manifest_files"],
            "manifest_invalid_file_digest:p1.json" in report["manifest"]["shape_errors"],
            check["expected_sha256"] == bundle.json("manifest.json")["files"]["p1.json"],
            check["ok"],
        )
    assert got == dict.fromkeys(spellings, ("OFFLINE_FAIL", False, True, True, False))


@pytest.mark.parametrize(
    "spell", [str.upper, lambda d: d + "\n", lambda d: " " + d], ids=["uppercase", "newline", "leading-space"]
)
def test_the_manifest_sidecar_is_compared_as_written(tmp_path: Path, spell) -> None:
    bundle = Bundle().seal()
    bundle.members["manifest.sha256"] = spell(bundle.members["manifest.sha256"].decode()).encode()
    report = _verify(tmp_path, bundle)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_sha256"] is False


def test_a_list_form_files_map_is_refused(tmp_path: Path) -> None:
    bundle = Bundle().seal()
    bundle.edit("manifest.json", lambda m: m.update(files=[{"name": k, "sha256": v} for k, v in m["files"].items()]))
    bundle.seal(p1=False, files=False)
    report = _verify(tmp_path, bundle)
    assert report["status"] == "OFFLINE_FAIL"
    assert "manifest_files_not_an_object" in report["manifest"]["shape_errors"]
    # Declares nothing: no entry is hashed, and manifest_files is false, as in loquitur-verify-ts.
    assert report["manifest"]["file_checks"] == []
    assert report["checks"]["manifest_files"] is False


# ---------------------------------------------------------------- self-declaration


@pytest.mark.parametrize("key", ["manifest.json", "MANIFEST.JSON", "manifest.sha256", "Manifest.Sha256"])
def test_a_manifest_declaring_itself_or_its_sidecar_is_refused(tmp_path: Path, key: str) -> None:
    report = _verify(
        tmp_path, Bundle().edit("manifest.json", lambda m: m["files"].update({key: "sha256:" + "0" * 64})).seal()
    )
    assert report["status"] == "OFFLINE_FAIL"
    assert f"manifest_self_referential_member:{key}" in report["manifest"]["shape_errors"]
    # Still never hashed: no digest of a manifest can sit inside that manifest.
    assert key not in [check["name"] for check in report["manifest"]["file_checks"]]


def test_the_self_declaration_test_folds_ascii_letter_case_only() -> None:
    # ASCII letter case is the only folding of member names (bundle-objects.md section 2). With
    # full Unicode lower-casing, U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE lower-cases to "i"
    # and U+0307, and U+212A KELVIN SIGN to "k": one name would mean one key here and another in
    # a verifier that folds A to Z only.
    assert manifest._self_referential("MANIFEST.JSON") is True
    assert manifest._self_referential("Manifest.Sha256") is True
    assert manifest._self_referential("MAN\u0130FEST.JSON") is False
    assert fold_member_name("\u212a") == "\u212a" != "\u212a".lower()
    assert fold_member_name("\u0130") == "\u0130" != "\u0130".lower()
    assert fold_member_name("MAN\u0130FEST.JSON") == "man\u0130fest.json"


def test_a_dotted_capital_i_spelling_of_manifest_json_is_an_ordinary_declaration(tmp_path: Path) -> None:
    # Not a self-declaration (no manifest_self_referential_member shape error): the portable
    # member-name rule decides it like any other key, and refuses it, U+0130 being outside the
    # POSIX portable filename character set.
    key = "MAN\u0130FEST.JSON"
    report = _verify(
        tmp_path, Bundle().edit("manifest.json", lambda m: m["files"].update({key: "sha256:" + "0" * 64})).seal()
    )
    assert report["status"] == "OFFLINE_FAIL"
    assert report["manifest"]["shape_errors"] == []
    check = next(c for c in report["manifest"]["file_checks"] if c["name"] == key)
    assert check["error"] == "unsafe_manifest_path"
    assert report["checks"]["manifest_files"] is False


@pytest.mark.parametrize(
    "name", [" manifest.json", "\u3000manifest.json", "\u00a0manifest.json"], ids=["space", "u3000", "u00a0"]
)
def test_a_padded_look_alike_of_manifest_json_is_not_a_self_declaration(tmp_path: Path, name: str) -> None:
    # Only the two keys themselves, in any letter case, are self-declarations. The key is not
    # trimmed first, so a member named " manifest.json" is not dropped unhashed as one. It is not
    # a portable member name either (bundle-objects.md section 2): the key fails the file check
    # and is not read, and the inventory refuses the entry from its listed name.
    bundle = Bundle()
    bundle.members[name] = b"a member, not the manifest\n"
    bundle.members["sub/manifest.json"] = b"{}"
    bundle.edit("manifest.json", lambda m: m["files"].update({name: "", "sub/manifest.json": ""})).seal()
    report = _verify(tmp_path, bundle)
    assert report["status"] == "OFFLINE_FAIL", report
    assert [error["code"] for error in report["errors"]] == ["bundle_member_name_invalid"]
    assert report["manifest"]["shape_errors"] == []
    assert report["checks"]["manifest_files"] is False
    checks = {check["name"]: check["error"] for check in report["manifest"]["file_checks"]}
    assert (checks[name], checks["sub/manifest.json"]) == ("unsafe_manifest_path", None)


@pytest.mark.parametrize("key", ["./manifest.json", ".\\manifest.json"], ids=["dot-slash", "dot-backslash"])
def test_a_path_spelling_of_manifest_json_is_an_unsafe_name_not_a_self_declaration(tmp_path: Path, key: str) -> None:
    # "./" and "\\" are not folded away before the self-declaration test. They are names outside
    # the member-name grammar: manifest_files false, and a manifest that satisfies its contract
    # and its sidecar still anchors the envelope link, as in loquitur-verify-ts.
    report = _verify(
        tmp_path, Bundle().edit("manifest.json", lambda m: m["files"].update({key: "sha256:" + "0" * 64})).seal()
    )
    assert report["status"] == "OFFLINE_FAIL"
    assert report["manifest"]["shape_errors"] == []
    check = next(c for c in report["manifest"]["file_checks"] if c["name"] == key)
    assert check["error"] == "unsafe_manifest_path"
    assert report["checks"]["manifest_files"] is False
    assert report["checks"]["envelope_links"] is True


# ---------------------------------------------------------------- member-name grammar


_OUTSIDE_THE_GRAMMAR = {
    "dot-slash": ("./member.txt", "member.txt"),
    "inner-dot": ("sub/./member.txt", "sub/member.txt"),
    "empty-segment": ("sub//member.txt", "sub/member.txt"),
    "backslash": ("sub\\member.txt", "sub/member.txt"),
    "trailing-dot": ("member.txt.", "member.txt"),
    "trailing-space": ("member.txt ", "member.txt"),
    "alternate-data-stream": ("p1.json:hidden", None),
    "device-nul": ("NUL", None),
    "device-con-in-subdir": ("sub/CON.txt", None),
    "device-com1-with-extension": ("com1.log", None),
    "device-lpt9-mixed-case": ("Lpt9", None),
    "control-character": ("tab\tname.txt", None),
    "absolute": ("/member.txt", "member.txt"),
    "traversal": ("sub/../member.txt", "member.txt"),
}


def test_the_member_name_grammar(tmp_path: Path) -> None:
    content = b"member\n"
    got = {}
    for label, (declared, on_disk) in _OUTSIDE_THE_GRAMMAR.items():
        bundle = Bundle()
        if on_disk:
            bundle.members[on_disk] = content
        bundle.edit("manifest.json", lambda m, d=declared: m["files"].update({d: sha(content)})).seal()
        report = _verify(tmp_path / label, bundle)
        check = next((c for c in report["manifest"]["file_checks"] if c["name"] == declared), {})
        got[label] = (report["status"], report["checks"]["manifest_files"], check.get("error"))
    expected = dict.fromkeys(_OUTSIDE_THE_GRAMMAR, ("OFFLINE_FAIL", False, "unsafe_manifest_path"))
    # Names inside the grammar verify.
    for index, name in enumerate(["sub/member.txt", "CONSOLE.txt", "nul-terminated.txt", "a.b.c", "..x"]):
        bundle = Bundle()
        bundle.members[name] = content
        bundle.edit("manifest.json", lambda m, n=name: m["files"].update({n: ""})).seal()
        got[name] = _verify(tmp_path / f"inside-{index}", bundle)["status"]
        expected[name] = "OFFLINE_OK"
    assert got == expected


def test_verify_manifest_reports_every_contract_error_at_once(tmp_path: Path) -> None:
    bundle = Bundle().edit(
        "manifest.json",
        lambda m: (m.update(bundle_id=7, schema_version=[]), m["files"].update({"manifest.sha256": "X" * 64})),
    )
    root = bundle.seal(files=False).write(tmp_path / "bundle")
    errors = verify_manifest(root).shape_errors
    assert "manifest_invalid_field_type:bundle_id" in errors
    assert "manifest_invalid_field_type:schema_version" in errors
    assert "manifest_self_referential_member:manifest.sha256" in errors
    assert "manifest_invalid_file_digest:manifest.sha256" in errors
