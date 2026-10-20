"""Member names resolve exactly, and a member is bounded at 20 MiB, in a directory bundle.

On Windows a name the directory does not contain can still open a file: "P1.JSON" opens
p1.json, and a trailing dot is dropped. Opened by name, a manifest declaring "P1.JSON" would
verify its digest against p1.json while the inventory, which compares exactly, reports p1.json
as undeclared, so the same bytes would give REVIEW here and FAIL on a case-sensitive
filesystem. Declared and structural names therefore resolve against the directory listing code
unit for code unit. Separately, bundle-objects.md §5 bounds a member at 20 MiB, and a declared
member of a directory bundle is held to that bound as a ZIP member is.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from bundle_builder import Bundle, sha

from loquitur.verify import cli
from loquitur.verify.runner import verify_path

MAX_MEMBER_BYTES = 20 * 1024 * 1024  # bundle-objects.md §5


def _report(root: Path) -> dict:
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


def test_a_case_variant_declared_name_is_missing(tmp_path: Path) -> None:
    bundle = Bundle().seal()
    digest = sha(bundle.members["p1.json"])
    bundle.edit("manifest.json", lambda m: (m["files"].pop("p1.json"), m["files"].update({"P1.JSON": digest})))
    bundle.seal(p1=False, files=False)
    report = _report(bundle.write(tmp_path / "bundle"))
    assert report["status"] == "OFFLINE_FAIL"
    check = next(c for c in report["manifest"]["file_checks"] if c["name"] == "P1.JSON")
    assert check["error"] == "file_missing"


@pytest.mark.parametrize("name", ["MANIFEST.JSON", "Manifest.json"])
def test_a_structural_member_resolves_by_its_exact_name(tmp_path: Path, name: str) -> None:
    root = Bundle().seal().write(tmp_path / "bundle")
    (root / "manifest.json").rename(root / name)
    report = verify_path(root).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0]["code"] == "bundle_root_invalid" or report["checks"]["manifest_sha256"] is False


@pytest.mark.parametrize("name", ["P1.sha256", "Envelope.sha256"])
def test_a_case_variant_sidecar_is_not_the_sidecar(tmp_path: Path, name: str) -> None:
    root = Bundle().seal().write(tmp_path / "bundle")
    canonical = name.lower()
    (root / canonical).rename(root / name)
    report = verify_path(root).to_dict()
    assert report["status"] == "OFFLINE_FAIL"


def test_a_declared_member_over_20_mib_is_too_large(tmp_path: Path) -> None:
    bundle = Bundle()
    bundle.members["big.bin"] = b"\0" * (MAX_MEMBER_BYTES + 1)
    bundle.edit("manifest.json", lambda m: m["files"].update({"big.bin": ""})).seal()
    report = _report(bundle.write(tmp_path / "over" / "bundle"))
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_files"] is False
    check = next(c for c in report["manifest"]["file_checks"] if c["name"] == "big.bin")
    assert check["error"] == "member_too_large"
    # Exactly 20 MiB is inside the bound; an undeclared member over it is inventoried, not read.
    exact = Bundle()
    exact.members["big.bin"] = b"\0" * MAX_MEMBER_BYTES
    exact.edit("manifest.json", lambda m: m["files"].update({"big.bin": ""})).seal()
    assert _report(exact.write(tmp_path / "exact" / "bundle"))["status"] == "OFFLINE_OK"
    undeclared = Bundle().seal()
    undeclared.members["big.bin"] = b"\0" * (MAX_MEMBER_BYTES + 1)
    report = _report(undeclared.write(tmp_path / "undeclared" / "bundle"))
    assert (report["status"], report["manifest"]["extra_files"]) == ("OFFLINE_REVIEW", ["big.bin"])


def test_a_structural_member_over_20_mib_is_unreadable(tmp_path: Path) -> None:
    bundle = Bundle().seal()
    bundle.members["canonical_input.json"] = bundle.members["canonical_input.json"] + b" " * MAX_MEMBER_BYTES
    report = _report(bundle.seal(p1=False).write(tmp_path / "bundle"))
    assert report["status"] == "OFFLINE_FAIL"
    assert "member_too_large:canonical_input.json" in str(report["errors"])


def _non_unicode_name(directory: Path, stem: str) -> Path:
    """A path in ``directory`` whose last name is not a Unicode string, or a skip.

    Windows names are UTF-16 and may hold a lone surrogate; POSIX names are bytes and may be
    invalid UTF-8, which Python surfaces as a surrogate escape. A filesystem that refuses such a
    name (APFS, for one) cannot hold this case.
    """
    if sys.platform == "win32":
        return directory / (stem + "\udc00")
    try:
        return Path(os.fsdecode(os.path.join(os.fsencode(directory), os.fsencode(stem) + b"\xff")))
    except (UnicodeError, ValueError) as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"no non-UTF-8 names on this host: {exc}")


@pytest.mark.parametrize("where", ["root-file", "subdirectory-file", "directory"])
def test_a_member_name_that_is_not_unicode_fails_the_inventory(tmp_path: Path, where: str) -> None:
    # Such a name cannot be declared (no manifest can carry it) and loquitur-verify-ts cannot
    # even inspect the entry, whose name its runtime replaces with U+FFFD. Both fail the
    # inventory (OFFLINE_FAIL); listing it as an undeclared member here would be OFFLINE_REVIEW.
    root = Bundle().seal().write(tmp_path / "bundle")
    parent = root
    if where == "subdirectory-file":
        parent = root / "sub"
        parent.mkdir()
    target = _non_unicode_name(parent, "x")
    try:
        if where == "directory":
            os.mkdir(target)
            (target / "inside.txt").write_bytes(b"inside\n")
        else:
            target.write_bytes(b"undeclared\n")
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this filesystem refuses a name that is not Unicode: {exc}")
    report = _report(root)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["exit_code"] == 1
    assert "bundle_member_name_invalid" in [error["code"] for error in report["errors"]]
    assert report["checks"]["manifest_files"] is False
    assert report["manifest"]["extra_files"] == []


def test_a_non_unicode_name_beside_a_declared_u_fffd_name_fails_the_inventory(tmp_path: Path) -> None:
    # The name loquitur-verify-ts's runtime would report for the entry above, declared and
    # present: the look-alike does not make the undeclared entry a second copy of it.
    bundle = Bundle()
    bundle.members["\ufffd.txt"] = b"declared\n"
    root = (
        bundle.edit("manifest.json", lambda m: m["files"].update({"\ufffd.txt": ""})).seal().write(tmp_path / "bundle")
    )
    try:
        _non_unicode_name(root, "").with_name(_non_unicode_name(root, "").name + ".txt").write_bytes(b"lone\n")
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this filesystem refuses a name that is not Unicode: {exc}")
    report = _report(root)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_files"] is False


NONCHARACTERS = ["\ufdd0", "\ufdef", "\ufffe", "\uffff", "\U0001fffe", "\U0010ffff"]


@pytest.mark.parametrize("character", NONCHARACTERS)
def test_a_name_holding_a_noncharacter_is_not_a_portable_member_name(character: str) -> None:
    from loquitur.verify.members import member_name_problem

    assert member_name_problem(f"x{character}.json") == "character_outside_portable_set"
    assert member_name_problem(f"sub{character}/x.json") == "character_outside_portable_set"


@pytest.mark.parametrize("character", ["\ufdcf", "\ufdf0", "\ufffd", "\U0010fffd", "\ue000"])
def test_the_code_points_beside_the_noncharacters_are_refused_too(character: str) -> None:
    # The rule refuses every code point beyond the portable set, not a list of them.
    from loquitur.verify.members import member_name_problem

    assert member_name_problem(f"x{character}.json") == "character_outside_portable_set"


@pytest.mark.parametrize("character", ["\ufdd0", "\U0010ffff"])
@pytest.mark.parametrize("where", ["root-file", "subdirectory-file", "directory"])
def test_a_member_name_holding_a_noncharacter_fails_the_inventory(tmp_path: Path, where: str, character: str) -> None:
    # No manifest can declare such a name (bundle-objects.md sections 1 and 2), and Node.js on
    # Windows stops the process on a path holding U+10FFFF, so a verifier that handed the entry
    # to the host would abort there where this one would list it as undeclared (OFFLINE_REVIEW).
    root = Bundle().seal().write(tmp_path / "bundle")
    parent = root
    if where == "subdirectory-file":
        parent = root / "sub"
        parent.mkdir()
    target = parent / f"x{character}"
    try:
        if where == "directory":
            os.mkdir(target)
            (target / "inside.txt").write_bytes(b"inside\n")
        else:
            target.write_bytes(b"undeclared\n")
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this filesystem refuses a noncharacter in a name: {exc}")
    report = _report(root)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["exit_code"] == 1
    assert "bundle_member_name_invalid" in [error["code"] for error in report["errors"]]
    assert report["manifest"]["extra_files"] == []


def test_a_path_holding_a_noncharacter_finds_nothing(tmp_path: Path) -> None:
    # report-contract.md section 5.3: such a path is not handed to the host, so a bundle and a
    # document under a directory so named are not found, as for a path holding a NUL.
    from loquitur.verify.members import inspect_path, path_names_regular_file

    parent = tmp_path / "in\U0010ffff"
    try:
        parent.mkdir()
    except OSError as exc:  # pragma: no cover - depends on the host
        pytest.skip(f"this filesystem refuses a noncharacter in a name: {exc}")
    root = Bundle().seal().write(parent / "bundle")
    (parent / "doc.json").write_bytes(b"{}")
    assert inspect_path(parent) is None
    assert path_names_regular_file(parent / "doc.json") is False
    report = _report(root)
    assert report["status"] == "HOST_FAILURE"
    assert [error["code"] for error in report["errors"]] == ["input_not_found"]
