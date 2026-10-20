"""The portable member-name rule (loquitur-protocol bundle-objects.md sections 1 and 2).

One rule decides every member name: a key of manifest.files, the path of an entry of a directory
bundle and the name of an archive entry (the archive rows are in test_spec_archive_intake.py). A
directory bundle's listing is judged by its names before any entry in it is inspected, so an entry
outside the rule is never handed to the host; and the bundle root is the path given, read through
that path, whatever the host resolves it to.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from bundle_builder import Bundle

from loquitur.verify import members
from loquitur.verify.members import (
    BundleInventoryError,
    MemberNameConflicts,
    bundle_inventory,
    conflicting_names,
    member_name_problem,
)
from loquitur.verify.runner import verify_path


def _report(root: Path) -> dict[str, Any]:
    return verify_path(root).to_dict()


# ---- the rule, clause by clause ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("at", "past"),
    [
        ("A" * 255, "A" * 256),
        ("/".join(["d" * 49] * 5) + "/x.jso", "/".join(["d" * 49] * 5) + "/x.json"),
        ("x.CON", "CON.x"),
        ("COM0", "com1"),
        ("LPT", "lpt9.txt"),
        ("auxiliary", "Aux"),
        ("nul_", "NuL.tar.gz"),
        ("a-", "-a"),
        ("a/b-", "a/-b"),
        (".a", "a."),
        ("..a", ".."),
        ("a_b", "a~b"),
        ("a.b", "a b"),
        ("ab", "a\u00e9"),
    ],
)
def test_each_clause_at_its_boundary_and_one_past_it(at: str, past: str) -> None:
    assert member_name_problem(at) is None
    assert member_name_problem(past) is not None


def test_conflicts_fold_ascii_letter_case_and_nothing_else() -> None:
    assert conflicting_names(["a.json", "A.JSON", "b.json"]) == {"a.json", "A.JSON"}
    assert conflicting_names(["a", "A/b"]) == {"a", "A/b"}
    assert conflicting_names(["a", "a/b"]) == {"a", "a/b"}
    assert conflicting_names(["Data/x.json", "data/y.json", "data/z.json"]) == {
        "Data/x.json",
        "data/y.json",
        "data/z.json",
    }
    assert conflicting_names(["data/x.json", "data/y.json", "dat/a.json"]) == set()
    tracker = MemberNameConflicts()
    assert [tracker.add(name, directory=d) for name, d in [("a", True), ("a/b", False), ("A/c", False)]] == [
        False,
        False,
        True,
    ]


# ---- manifest keys -------------------------------------------------------------------------------


def test_two_keys_that_conflict_fail_the_file_check_and_neither_is_read(tmp_path: Path) -> None:
    bundle = Bundle()
    bundle.members["x.json"] = b"{}"
    bundle.edit("manifest.json", lambda m: m["files"].update({"x.json": "", "X.JSON": ""})).seal()
    report = _report(bundle.write(tmp_path / "bundle"))
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_files"] is False
    checks = {check["name"]: check["error"] for check in report["manifest"]["file_checks"]}
    assert (checks["x.json"], checks["X.JSON"]) == ("member_name_conflict", "member_name_conflict")


# ---- directory bundles ---------------------------------------------------------------------------


class _FakeEntry:
    """A listed entry whose inspection is recorded, to show which names reach the host."""

    def __init__(self, directory: str, name: str, inspected: list[str]) -> None:
        self.name = name
        self.path = os.path.join(directory, name)
        self._inspected = inspected

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        self._inspected.append(self.name)
        return os.stat(__file__)

    def is_symlink(self) -> bool:
        self._inspected.append(self.name)
        return False


class _FakeListing:
    def __init__(self, entries: list[_FakeEntry]) -> None:
        self._entries = entries

    def __enter__(self) -> list[_FakeEntry]:
        return self._entries

    def __exit__(self, *_: object) -> None:
        return None


@pytest.mark.parametrize(
    ("names", "detail"),
    [
        (["manifest.json", "a b.json"], "member_name_not_portable"),
        (["manifest.json", "x\ufdd0.json"], "member_name_not_portable"),
        (["manifest.json", "x\udcff.json"], "member_name_not_portable"),
        (["manifest.json", "MANIFE~1.JSO"], "member_name_not_portable"),
        (["manifest.json", "con.txt"], "member_name_not_portable"),
        (["manifest.json", "p1.json", "P1.JSON"], "member_name_conflict"),
        (["manifest.json", "s" * 256], "member_name_not_portable"),
    ],
)
def test_a_listing_is_judged_by_its_names_before_any_entry_is_inspected(
    monkeypatch: pytest.MonkeyPatch, names: list[str], detail: str
) -> None:
    inspected: list[str] = []
    monkeypatch.setattr(
        members.os, "scandir", lambda directory: _FakeListing([_FakeEntry(directory, n, inspected) for n in names])
    )
    with pytest.raises(BundleInventoryError, match=detail):
        bundle_inventory(Path("root"))
    assert inspected == []


def test_a_portable_listing_is_inspected(monkeypatch: pytest.MonkeyPatch) -> None:
    inspected: list[str] = []
    names = ["manifest.json", "p1.json", "s" * 255]
    monkeypatch.setattr(
        members.os, "scandir", lambda directory: _FakeListing([_FakeEntry(directory, n, inspected) for n in names])
    )
    assert bundle_inventory(Path("root")).files == tuple(sorted(names))
    assert sorted(set(inspected)) == sorted(names)


@pytest.mark.parametrize("name", ["a b.json", "caf\u00e9.json", "x~1.json", "-x.json", "nul.txt"])
def test_an_entry_outside_the_rule_fails_the_run_not_reviews_it(tmp_path: Path, name: str) -> None:
    # Not an undeclared member, OFFLINE_REVIEW: no manifest can declare it, and the run fails
    # without the entry being inspected (bundle-objects.md section 1).
    root = Bundle().seal().write(tmp_path / "bundle")
    target = root / name
    try:
        target.write_bytes(b"undeclared\n")
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this host cannot make {name!r}: {exc}")
    if name not in os.listdir(root):  # pragma: no cover - a host that stored it under another name
        pytest.skip(f"this host stored {name!r} under another name")
    report = _report(root)
    assert (report["status"], [error["code"] for error in report["errors"]]) == (
        "OFFLINE_FAIL",
        ["bundle_member_name_invalid"],
    )


# ---- the root is the path given ------------------------------------------------------------------


def _link_directory(target: Path, link: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_a_root_reached_through_a_link_whose_target_holds_u10ffff_verifies(tmp_path: Path) -> None:
    # The root may be reached through a link, and is read through the path given, never through
    # the path it resolves to. Here the resolved path holds U+10FFFF, which is not handed to the
    # host, and the two verifiers give one report.
    plain = tmp_path / "plain"
    Bundle().seal().write(plain / "bundle")
    target = tmp_path / "t\U0010ffff"
    try:
        shutil.move(plain, target)
        _link_directory(target / "bundle", tmp_path / "to-bundle")
        _link_directory(target, tmp_path / "to-parent")
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this host cannot make the link: {exc}")
    got = {
        label: (report["status"], report["outcome"]["reason"], report["errors"])
        for label, report in {
            "junction-root": _report(tmp_path / "to-bundle"),
            "under-junction": _report(tmp_path / "to-parent" / "bundle"),
        }.items()
    }
    ok = ("OFFLINE_OK", "local_integrity_checks_passed", [])
    assert got == {"junction-root": ok, "under-junction": ok}


# ---- an inventory that fails masks a link and nothing else ----------------------------------------


@pytest.mark.parametrize(
    ("link", "name", "expected"),
    [
        ("lnk", "z/a b.json", ["bundle_member_name_invalid"]),
        ("z/lnk", "a/a b.json", ["bundle_member_name_invalid"]),
        ("a/lnk", "z/a b.json", ["bundle_member_name_invalid"]),
        ("z/lnk", "a b.json", ["bundle_member_name_invalid"]),
        ("lnk", "z/ab.json", ["unsafe_bundle_member"]),
    ],
    ids=["link-at-root", "link-listed-after", "link-listed-before", "name-at-root", "control-portable-name"],
)
def test_a_link_beside_a_name_outside_the_rule_reports_the_inventory_failure_not_the_link(
    tmp_path: Path, link: str, name: str, expected: list[str]
) -> None:
    # bundle-objects.md section 1: which entries a verifier meets before a refused listing depends
    # on the order it lists directories in, so a link met first is not reported; a link is judged
    # only over a complete inventory. The control row, a portable name, reports the link.
    outside = tmp_path / "outside"
    outside.mkdir()
    root = Bundle().seal().write(tmp_path / "bundle")
    (root / link).parent.mkdir(parents=True, exist_ok=True)
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    try:
        _link_directory(outside, root / link)
        (root / name).write_bytes(b"undeclared\n")
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this host cannot make the link or the name: {exc}")
    report = _report(root)
    assert (report["status"], [error["code"] for error in report["errors"]]) == ("OFFLINE_FAIL", expected)


@pytest.mark.parametrize("with_link", [False, True], ids=["name-only", "name-and-link"])
def test_a_failed_inventory_masks_no_other_error(tmp_path: Path, with_link: bool) -> None:
    # bundle-objects.md section 1: a failed inventory takes the place of unsafe_bundle_member only.
    # Every other row of report-contract.md section 5.3 is still judged on its own, so a manifest
    # that is not JSON beside a refused name is reported beside bundle_member_name_invalid.
    root = Bundle().seal().write(tmp_path / "bundle")
    (root / "manifest.json").write_bytes(b"{")
    (root / "a b.json").write_bytes(b"undeclared\n")
    if with_link:
        outside = tmp_path / "outside"
        outside.mkdir()
        try:
            _link_directory(outside, root / "lnk")
        except OSError as exc:  # pragma: no cover - depends on the host
            pytest.skip(f"this host cannot make the link: {exc}")
    report = _report(root)
    codes = [error["code"] for error in report["errors"]]
    assert (report["status"], codes) == ("OFFLINE_FAIL", ["bundle_member_name_invalid", "manifest_verification_failed"])


# ---- a path that is not a sequence of Unicode scalar values finds nothing -------------------------


def test_a_given_path_holding_a_surrogate_finds_nothing(tmp_path: Path) -> None:
    # report-contract.md section 5.3: a path holding a surrogate code point is not handed to the
    # host: Node.js writes U+FFFD in its place, and would read another entry than the one given.
    # Both verifiers find nothing there, for the input and for a document.
    # The entry exists: on Windows its name holds the lone code unit, on POSIX the byte 0x80.
    plain = tmp_path / "plain"
    Bundle().seal().write(plain)
    named = tmp_path / "t\udc80"
    document = tmp_path / "e\udc80.json"
    try:
        shutil.move(plain, named)
        document.write_bytes(b"{}")
    except (OSError, UnicodeError) as exc:  # pragma: no cover - a host that refuses such names
        pytest.skip(f"this host cannot make such names: {exc}")
    assert _report(tmp_path / ("t" + chr(0xFFFD)))["errors"][0]["code"] == "input_not_found"
    report = _report(named)
    assert (report["status"], [error["code"] for error in report["errors"]]) == ("HOST_FAILURE", ["input_not_found"])
    assert members.path_names_regular_file(document) is False
    assert members.has_surrogate("t\udc80") and members.has_surrogate("\ud800")
    assert not members.has_surrogate("t" + chr(0xFFFD) + chr(0x1F600))
