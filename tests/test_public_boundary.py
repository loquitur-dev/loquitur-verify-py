"""The public-boundary checker: it passes here, it names what it finds, and it clears nothing it does
not read.

The checker is one file, byte for byte the same in loquitur-protocol (as
tools/check_public_spec_boundary.py) and in loquitur-schemas, loquitur-verify-py and
loquitur-verify-ts (as tools/check_public_boundary.py). The comparison with the other copies skips
without the siblings and fails instead when LOQUITUR_REQUIRE_SIBLINGS is set.

Every needle in this file is assembled from fragments, because the checker scans tests/ too.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"
COPIES = {
    "loquitur-protocol": "tools/check_public_spec_boundary.py",
    "loquitur-schemas": "tools/check_public_boundary.py",
    "loquitur-verify-py": "tools/check_public_boundary.py",
    "loquitur-verify-ts": "tools/check_public_boundary.py",
}
# The copy beside this file, under either of its two names, whatever the checkout directory is called.
TOOL = next(
    (ROOT / path for path in sorted(set(COPIES.values())) if (ROOT / path).is_file()),
    ROOT / "tools/check_public_boundary.py",
)

DISCLOSURE = "".join(("BEGIN PR", "IVATE KEY"))
PERIMETER = "".join(("/v1/in", "ternal/"))
GOVERNANCE_NOTE = "This repository is maintained by its owner, one person, not a team.\n"


def _load():
    spec = importlib.util.spec_from_file_location("boundary_checker", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load()


def _required() -> bool:
    return os.environ.get(REQUIRE_SIBLINGS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _tree(root: Path, reviewed: list[dict] | None = None, files: dict[str, bytes] | None = None) -> Path:
    """A scratch repository: a governance note, a configuration and ``files``."""
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "GOVERNANCE.md").write_text(GOVERNANCE_NOTE, encoding="utf-8")
    config = {
        "archive_member_lists": [],
        "corpus_lock": None,
        "forbidden_roots": [],
        "needle_lists": ["disclosure", "private_perimeter"],
        "reviewed": reviewed or [],
        "schema_version": "loquitur.public_boundary.v1",
    }
    (root / "tools/public_boundary.json").write_text(json.dumps(config), encoding="utf-8")
    for rel, content in (files or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(content)
    return root


def _zip(members: dict[str, bytes], extra: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.extra = extra
            archive.writestr(info, data)
    return buffer.getvalue()


def test_this_repository_passes_the_checker() -> None:
    result = subprocess.run(
        [sys.executable, str(TOOL)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "public_boundary_ok" in result.stdout


def test_the_tool_is_identical_to_every_other_copy() -> None:
    if ROOT.name not in COPIES:
        message = f"{ROOT.name} is not a checkout of a repository that carries this tool"
        if _required():
            pytest.fail(message)
        pytest.skip(message)
    mine = TOOL.read_bytes()
    compared = 0
    absent = []
    for repository, path in COPIES.items():
        if repository == ROOT.name:
            continue
        other = WORKSPACE / repository / path
        if not other.is_file():
            if _required():
                pytest.fail(f"{other} is not checked out beside this repository")
            absent.append(repository)
            continue
        assert other.read_bytes() == mine, f"{repository}/{path} differs from this copy"
        compared += 1
    if compared == 0:
        pytest.skip(f"no other copy is checked out beside this repository: {', '.join(absent)}")


@pytest.mark.parametrize(
    "content",
    [f"see {PERIMETER} for the service\n", f'{{"k": "{DISCLOSURE}"}}\n'],
    ids=["perimeter", "disclosure"],
)
def test_a_needle_in_text_is_named(tmp_path: Path, content: str) -> None:
    root = _tree(tmp_path, files={"docs/note.md": content.encode()})
    failures = checker.check(root)
    assert len(failures) == 1 and "in docs/note.md" in failures[0], failures


def _gzip_with_fextra(payload: bytes, extra: bytes) -> bytes:
    body = gzip.compress(payload, mtime=0)
    # FLG.FEXTRA set, then XLEN and the field after the ten-byte header.
    return body[:3] + bytes([body[3] | 0x04]) + body[4:10] + struct.pack("<H", len(extra)) + extra + body[10:]


UNREVIEWED_CONTAINERS = {
    "zip-without-needle": _zip({"a.txt": b"nothing here\n"}),
    "zip-with-needle": _zip({"a.txt": DISCLOSURE.encode()}),
    "zip64-extra-field": _zip({"a.txt": b"x"}, extra=struct.pack("<HH", 0x0001, 16) + DISCLOSURE.encode()[:16]),
    "nested-zip": _zip({"inner.zip": _zip({"leak.txt": DISCLOSURE.encode()})}),
    "gzip-fextra": _gzip_with_fextra(b"plain\n", DISCLOSURE.encode()),
    "utf-16": f'{{"k": "{DISCLOSURE}"}}'.encode("utf-16"),
    "control-bytes": b"text\x00with a nul\n",
}


@pytest.mark.parametrize("name", sorted(UNREVIEWED_CONTAINERS))
def test_a_file_that_is_not_text_is_not_cleared_whatever_it_holds(tmp_path: Path, name: str) -> None:
    root = _tree(tmp_path, files={"tests/fixtures/data.bin": UNREVIEWED_CONTAINERS[name]})
    failures = checker.check(root)
    assert failures == [
        "not text and no reviewed digest, so not cleared: tests/fixtures/data.bin (sha256 "
        + hashlib.sha256(UNREVIEWED_CONTAINERS[name]).hexdigest()
        + ")"
    ]


def test_a_reviewed_digest_clears_exactly_those_bytes(tmp_path: Path) -> None:
    blob = UNREVIEWED_CONTAINERS["zip-without-needle"]
    entry = {"path": "tests/fixtures/data.bin", "reason": "a fixture", "sha256": hashlib.sha256(blob).hexdigest()}
    root = _tree(tmp_path, reviewed=[entry], files={"tests/fixtures/data.bin": blob})
    assert checker.check(root) == []
    (root / "tests/fixtures/data.bin").write_bytes(blob + b"\x00")
    [failure] = checker.check(root)
    assert "is not the bytes its review recorded" in failure


BUNDLE = {"manifest.json": b'{"files": []}\n', "sub/p1.json": b"{}\n"}


def test_a_zip_that_is_the_packing_of_its_directory_is_cleared(tmp_path: Path) -> None:
    packed = checker.packing("bundle", BUNDLE)
    files = {f"tests/fixtures/bundle/{name}": data for name, data in BUNDLE.items()}
    root = _tree(tmp_path, files={**files, "tests/fixtures/bundle.zip": packed})
    assert checker.check(root) == []
    assert checker.text_of(packed) is None, "the packing is text, so this test would measure nothing"


@pytest.mark.parametrize(
    "change",
    ["one-byte-more", "a-file-the-directory-lacks", "a-deflated-packing", "another-name"],
)
def test_a_zip_that_is_not_the_packing_of_its_directory_is_not_cleared(tmp_path: Path, change: str) -> None:
    packed = {
        "one-byte-more": checker.packing("bundle", BUNDLE) + b"\x00",
        "a-file-the-directory-lacks": checker.packing("bundle", {**BUNDLE, "extra.txt": b"x\n"}),
        "a-deflated-packing": _zip({f"bundle/{name}": data for name, data in BUNDLE.items()}),
        "another-name": checker.packing("bundle", BUNDLE),
    }[change]
    target = "tests/fixtures/other.zip" if change == "another-name" else "tests/fixtures/bundle.zip"
    files = {f"tests/fixtures/bundle/{name}": data for name, data in BUNDLE.items()}
    root = _tree(tmp_path, files={**files, target: packed})
    digest = hashlib.sha256(packed).hexdigest()
    assert checker.check(root) == [f"not text and no reviewed digest, so not cleared: {target} (sha256 {digest})"]


def test_a_needle_in_a_packed_directory_is_named(tmp_path: Path) -> None:
    content = {**BUNDLE, "p2.json": DISCLOSURE.encode()}
    files = {f"tests/fixtures/bundle/{name}": data for name, data in content.items()}
    root = _tree(tmp_path, files={**files, "tests/fixtures/bundle.zip": checker.packing("bundle", content)})
    assert checker.check(root) == [f"forbidden substring {DISCLOSURE!r} in tests/fixtures/bundle/p2.json"]


def test_pack_writes_the_packing_the_checker_clears(tmp_path: Path) -> None:
    files = {f"tests/fixtures/bundle/{name}": data for name, data in BUNDLE.items()}
    root = _tree(tmp_path, files=files)
    assert checker.main(["--pack", str(root / "tests/fixtures/bundle")]) == 0
    assert (root / "tests/fixtures/bundle.zip").read_bytes() == checker.packing("bundle", BUNDLE)
    assert checker.check(root) == []


@pytest.mark.parametrize("blob", [b"\x00", b"\x00" * 4096], ids=["one", "many"])
def test_a_file_of_nul_bytes_only_is_cleared(tmp_path: Path, blob: bytes) -> None:
    root = _tree(tmp_path, files={"tests/fixtures/big.bin": blob})
    assert checker.check(root) == []


@pytest.mark.parametrize("blob", [b"\x00" * 64 + b"\x01", b"\x00" * 64 + DISCLOSURE.encode()], ids=["byte", "needle"])
def test_a_file_of_nul_bytes_and_anything_else_is_not_cleared(tmp_path: Path, blob: bytes) -> None:
    root = _tree(tmp_path, files={"tests/fixtures/big.bin": blob})
    digest = hashlib.sha256(blob).hexdigest()
    assert checker.check(root) == [
        f"not text and no reviewed digest, so not cleared: tests/fixtures/big.bin (sha256 {digest})"
    ]


def test_a_review_of_what_provenance_clears_is_reported(tmp_path: Path) -> None:
    blob = b"\x00" * 16
    entry = {"path": "tests/fixtures/big.bin", "reason": "zeros", "sha256": hashlib.sha256(blob).hexdigest()}
    root = _tree(tmp_path, reviewed=[entry], files={"tests/fixtures/big.bin": blob})
    assert checker.check(root) == [
        f"{checker.CONFIG} reviews tests/fixtures/big.bin, which its provenance clears; remove the review"
    ]


def test_a_review_of_a_file_that_is_absent_is_reported(tmp_path: Path) -> None:
    entry = {"path": "tests/fixtures/gone.bin", "reason": "a fixture", "sha256": "0" * 64}
    root = _tree(tmp_path, reviewed=[entry])
    assert checker.check(root) == [f"{checker.CONFIG} reviews tests/fixtures/gone.bin, which this run did not meet"]


@pytest.mark.parametrize(
    "entry",
    [{"path": "a", "sha256": "0" * 64}, {"path": "a", "reason": " ", "sha256": "0" * 64}],
    ids=["no-reason", "blank-reason"],
)
def test_a_review_without_a_reason_is_reported(tmp_path: Path, entry: dict) -> None:
    root = _tree(tmp_path, reviewed=[entry], files={"a": b"text\n"})
    assert any("needs exactly path, sha256 and a reason" in failure for failure in checker.check(root))


@pytest.mark.parametrize("line", ["begin 644 x\n", "begin 7 x\n", "begin-base64 644 x\n", "begin\tanything\n"])
def test_an_encoded_block_in_text_is_not_cleared(tmp_path: Path, line: str) -> None:
    root = _tree(tmp_path, files={"docs/note.md": ("text\n" + line + "M86)C\n`\nend\n").encode()})
    assert checker.check(root) == ["an encoded block is not read, so not cleared: docs/note.md"]


def test_a_governance_note_that_claims_a_team_is_named(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "GOVERNANCE.md").write_text("This repository is maintained by a core team.\n", encoding="utf-8")
    failures = checker.check(root)
    assert any("claims a team" in failure for failure in failures)
    assert any("does not say who maintains" in failure for failure in failures)


def test_a_configuration_with_unknown_keys_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    path = root / "tools/public_boundary.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    config["skip"] = ["docs/"]
    path.write_text(json.dumps(config), encoding="utf-8")
    [failure] = checker.check(root)
    assert "cannot be read" in failure


def _cited(root: Path) -> list[str]:
    return [failure for failure in checker.check(root) if " cites " in failure]


def test_a_test_the_prose_cites_that_nothing_holds_is_named(tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "repo",
        files={
            "docs/note.md": b"The rule is held by tests/test_gone.py.\n",
            "tools/run.py": b"# The rule is held by test_gone_rule.\nX = 1\n",
            "schema.json": b'{"description": "held by tests/test_gone_schema.py", "root": "test_support"}\n',
        },
    )
    assert _cited(root) == [
        "docs/note.md cites tests/test_gone.py, which neither this repository"
        " nor a published repository it names holds",
        "schema.json cites tests/test_gone_schema.py, which neither this repository"
        " nor a published repository it names holds",
        "tools/run.py cites test_gone_rule, which neither this repository nor a published repository it names holds",
    ]


def test_a_cited_test_this_repository_holds_is_cleared(tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "repo",
        files={
            "tests/test_here.py": b"def test_here_holds() -> None:\n    pass\n",
            "docs/note.md": b"See tests/test_here.py::test_here_holds and tests/fixtures/NAME.\n",
            "tests/fixtures/a.json": b"{}\n",
        },
    )
    assert _cited(root) == []


def test_a_cited_test_is_held_by_the_published_repository_named_beside_it(tmp_path: Path) -> None:
    sibling = tmp_path / "loquitur-schemas"
    (sibling / "tests").mkdir(parents=True)
    (sibling / "tests/test_there.py").write_bytes(b"def test_there_holds() -> None:\n    pass\n")
    root = _tree(
        tmp_path / "repo",
        files={
            "docs/held.md": b"loquitur-schemas holds tests/test_there.py and test_there_holds.\n",
            "docs/lacked.md": b"loquitur-schemas holds tests/test_not_there.py.\n",
            "docs/unpublished.md": b"loquitur-conformance holds tests/test_private.py.\n",
            "docs/absent.md": b"loquitur-verify-ts holds tests/test_elsewhere.py.\n",
        },
    )
    assert _cited(root) == [
        "docs/lacked.md cites tests/test_not_there.py, which neither this repository"
        " nor a published repository it names holds",
        "docs/unpublished.md cites tests/test_private.py, which neither this repository"
        " nor a published repository it names holds",
    ]


def test_code_and_the_changelog_are_not_read_for_citations(tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "repo",
        files={
            "tools/run.py": b'PATH = "tests/test_gone.py"\n\n\ndef f() -> str:\n    return "test_gone_name"\n',
            f"{checker._PAST_STATES}.md": b"Moved tests/test_gone.py away.\n",
            "src/a.ts": b'const p = "tests/test_gone.py"; // nothing cited here\n',
        },
    )
    assert _cited(root) == []


# What prints as nothing, one of each kind: a format character, a non-ASCII space, a
# default-ignorable code point outside the categories, a filler, U+2800 and two noncharacters.
INVISIBLE_PLANTS = (0x200B, 0x00A0, 0x034F, 0x3164, 0x2800, 0xFDD0, 0x1FFFF)


@pytest.mark.parametrize("code", INVISIBLE_PLANTS, ids=[f"U+{code:04X}" for code in INVISIBLE_PLANTS])
def test_a_literal_invisible_character_in_text_is_named(tmp_path: Path, code: int) -> None:
    root = _tree(tmp_path, files={"docs/note.md": ("first line\nab" + chr(code) + "c\n").encode()})
    assert checker.check(root) == [f"invisible character U+{code:04X} at docs/note.md:2:3; write it as an escape"]


def test_an_escaped_invisible_character_and_visible_neighbours_are_cleared(tmp_path: Path) -> None:
    visible = "".join(chr(code) for code in (0x00E9, 0x3042, 0x1F600, 0xFDCF, 0xFDF0, 0xFFFD, 0x2801))
    content = "a tab" + chr(9) + "an escape \\u200b and " + visible + chr(13) + chr(10)
    root = _tree(tmp_path, files={"docs/note.md": content.encode()})
    assert checker.check(root) == []


def _own_config() -> dict:
    """This repository's configuration, the rows the tests below plant against."""
    return json.loads((ROOT / "tools/public_boundary.json").read_text(encoding="utf-8"))


# The rows each kind of repository configures. The specification repository is the one whose copy
# of the tool is named check_public_spec_boundary.py; the package repositories configure the same
# rows as each other. A row deleted from, or added to, a configuration is a change this table
# records in the same commit.
SPECIFICATION_ROWS = {
    "archive_member_lists": ["disclosure", "private_perimeter"],
    "forbidden_roots": [
        "*.dist-info",
        "*.egg-info",
        ".eggs",
        "build",
        "dist",
        "docs-site",
        "examples",
        "exports",
        "logs",
        "node_modules",
        "openapi",
        "outputs",
        "runtime",
        "schemas",
        "scripts",
        "test_support",
        "verify",
        "verify-ts",
        "website",
    ],
    "needle_lists": ["claim_discipline", "private_perimeter"],
}
PACKAGE_ROWS = {
    "archive_member_lists": [],
    "forbidden_roots": [],
    "needle_lists": ["disclosure", "private_perimeter"],
}


def test_the_configuration_holds_the_rows_this_kind_of_repository_configures() -> None:
    expected = SPECIFICATION_ROWS if TOOL.name == "check_public_spec_boundary.py" else PACKAGE_ROWS
    config = _own_config()
    assert {key: config[key] for key in expected} == expected


def _configured_tree(root: Path, config: dict, files: dict[str, bytes]) -> Path:
    _tree(root, files=files)
    scratch = {**config, "archive_member_lists": [], "corpus_lock": None, "reviewed": []}
    (root / "tools/public_boundary.json").write_text(json.dumps(scratch), encoding="utf-8")
    return root


def _planted_root(pattern: str) -> str:
    return pattern.replace("*", "planted")


def test_each_configured_forbidden_root_is_reported(tmp_path: Path) -> None:
    config = _own_config()
    missing = []
    for index, pattern in enumerate(config["forbidden_roots"]):
        name = _planted_root(pattern)
        root = _configured_tree(tmp_path / str(index), config, {f"{name}/x.txt": b"text\n"})
        if f"forbidden root path present: {name}" not in checker.check(root):
            missing.append(pattern)
    assert not missing, missing


def test_each_needle_of_each_configured_needle_list_is_reported(tmp_path: Path) -> None:
    config = _own_config()
    needles = [(name, needle) for name in config["needle_lists"] for needle in checker.NEEDLE_LISTS[name]]
    assert needles, "this repository's configuration applies no needle"
    files = {f"docs/plant-{index}.md": f"x {needle} x\n".encode() for index, (_, needle) in enumerate(needles)}
    failures = checker.check(_configured_tree(tmp_path, config, files))
    missing = [
        (name, needle)
        for index, (name, needle) in enumerate(needles)
        if f"forbidden substring {needle!r} in docs/plant-{index}.md" not in failures
    ]
    assert not missing, missing


def test_each_configured_archive_member_list_is_applied_to_members(tmp_path: Path) -> None:
    config = _own_config()
    root = _configured_tree(tmp_path, config, {})
    for name in config["archive_member_lists"]:
        for needle in checker.NEEDLE_LISTS[name]:
            members = {"vectors/plant.json": f"x {needle} x\n".encode()}
            failures = checker.member_failures(
                root, members, checker._needles(config["archive_member_lists"]), checker.Clearing([])
            )
            assert f"forbidden substring {needle!r} in vectors/plant.json" in failures, (name, needle)


def test_the_clearance_routes_are_one_ordered_table() -> None:
    """The routes that clear a file that is not text, in the order the module docstring numbers them,
    each with where it applies. The first route that answers decides, so the order is the precedence."""
    assert [(name, domains) for name, domains, _ in checker.CLEARANCE_ROUTES] == [
        ("packed", ("file",)),
        ("corpus", ("file",)),
        ("crafted", ("member",)),
        ("spliced", ("member",)),
        ("zero-filled", ("file", "member")),
        ("reviewed", ("file", "member")),
    ]
    numbered = re.findall(r"^[0-9]\. ([a-z-]+) \(", checker.__doc__, re.M)
    assert numbered == [name for name, _, _ in checker.CLEARANCE_ROUTES]


def test_each_file_route_records_what_it_cleared(tmp_path: Path) -> None:
    blob = UNREVIEWED_CONTAINERS["zip-without-needle"]
    entry = {"path": "tests/fixtures/data.bin", "reason": "a fixture", "sha256": hashlib.sha256(blob).hexdigest()}
    files = {f"tests/fixtures/bundle/{name}": data for name, data in BUNDLE.items()}
    files.update(
        {
            "tests/fixtures/bundle.zip": checker.packing("bundle", BUNDLE),
            "tests/fixtures/data.bin": blob,
            "tests/fixtures/zeros.bin": b"\x00" * 8,
            "tests/fixtures/other.bin": b"\x00\x01",
        }
    )
    root = _tree(tmp_path, reviewed=[entry], files=files)
    clearing = checker.Clearing([entry])
    config = checker.load_config(root)
    clearing.context.update(root=root, config=config, files=checker.tracked_files(root), archive_needles=[])
    expected = {
        "tests/fixtures/bundle.zip": "packed",
        "tests/fixtures/data.bin": "reviewed",
        "tests/fixtures/zeros.bin": "zero-filled",
        "tests/fixtures/bundle/manifest.json": "searched",
        "tests/fixtures/other.bin": "not-cleared",
    }
    for rel, route in expected.items():
        findings = clearing.clear("file", rel, (root / rel).read_bytes(), [DISCLOSURE])
        assert (clearing.cleared_by[rel], bool(findings)) == (route, route == "not-cleared"), rel


def test_a_typescript_test_path_the_prose_cites_must_be_held(tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "repo",
        files={
            "test/held.test.ts": b"// a test\n",
            "docs/held.md": b"The rule is held by test/held.test.ts.\n",
            "docs/gone.md": b"The rule is held by test/gone.test.ts.\n",
            "src/a.ts": b'it("test/title.test.ts is a title, not a citation", () => {});\n',
        },
    )
    assert _cited(root) == [
        "docs/gone.md cites test/gone.test.ts, which neither this repository nor a published repository it names holds"
    ]
