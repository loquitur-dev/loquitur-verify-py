"""tools/release_checks.py, the release workflow's checks of the version and the changelog.

A CHANGELOG.md section is found by one rule: its heading line is exactly `## [X.Y.Z]` or
`## [X.Y.Z] - YYYY-MM-DD`, the dated form a published copy carries. The verify job's check and the
release notes of the draft release both go through it, and both refuse a section with no text, so
a changelog the check passes is one the release job can take its notes from.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from repository import ROOT, tool

release_checks = tool("release_checks")

ACCEPTED = ["## [0.1.0]", "## [0.1.0] - 2026-10-20"]
REFUSED = [
    "## [0.1.0]rc",
    "## [0.1.0] — 2026-10-20",
    "## [0.1.0] – 2026-10-20",
    "## [0.1.0] -2026-10-20",
    "## [0.1.0]  - 2026-10-20",
    "## [0.1.0] - 2026-10",
    "## [0.1.0] - 2026-10-20 (yanked)",
    "## [0.1.0] ",
    "### [0.1.0]",
    "## 0.1.0",
    "## [0.1.01]",
    "## [0x1y0]",
    # Digits other than ASCII ones are not a date of the form.
    "## [0.1.0] - \u0662\u0660\u0662\u0666-10-20",
    "## [0.1.0] - \uff12\uff10\uff12\uff16-10-20",
]


def _tree(root: Path, heading: str, *, version: str = "0.1.0", declared: str | None = None) -> Path:
    """A scratch repository: pyproject.toml and _version.py at a version, and a CHANGELOG.md."""
    (root / "src/loquitur/verify").mkdir(parents=True)
    (root / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
    (root / "src/loquitur/verify/_version.py").write_text(f'__version__ = "{declared or version}"\n', encoding="utf-8")
    changelog = f"# Changelog\n\n## Unreleased\n\n- next\n\n{heading}\n\n- first\n\n## [0.0.9]\n\n- older\n"
    (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return root


@pytest.mark.parametrize("heading", ACCEPTED)
def test_the_heading_of_a_version_is_found_in_both_forms(heading: str, tmp_path: Path) -> None:
    assert release_checks.is_section_heading(heading, "0.1.0")
    root = _tree(tmp_path, heading)
    assert release_checks.problems(root) == []
    assert release_checks.problems(root, tag="v0.1.0") == []
    assert release_checks.section((root / "CHANGELOG.md").read_text(encoding="utf-8"), "0.1.0") == "- first"


@pytest.mark.parametrize("heading", REFUSED)
def test_no_other_line_heads_the_section(heading: str, tmp_path: Path) -> None:
    assert not release_checks.is_section_heading(heading, "0.1.0")
    root = _tree(tmp_path, heading)
    assert release_checks.problems(root) == ["CHANGELOG.md has no section headed ## [0.1.0] or ## [0.1.0] - YYYY-MM-DD"]
    assert release_checks.section((root / "CHANGELOG.md").read_text(encoding="utf-8"), "0.1.0") is None


@pytest.mark.parametrize("heading", ACCEPTED)
def test_a_section_with_no_text_is_refused_by_the_check(heading: str, tmp_path: Path) -> None:
    root = _tree(tmp_path, heading)
    (root / "CHANGELOG.md").write_text(f"# Changelog\n\n{heading}\n\n## [0.0.9]\n\n- older\n", encoding="utf-8")
    assert release_checks.problems(root) == ["CHANGELOG.md has no text under ## [0.1.0]"]
    assert release_checks.problems(root, tag="v0.1.0") == ["CHANGELOG.md has no text under ## [0.1.0]"]


def test_a_tag_other_than_the_version_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path, "## [0.1.0]")
    assert release_checks.problems(root, tag="v0.1.1") == [
        "the tag v0.1.1 is not v0.1.0, the version in pyproject.toml"
    ]


def test_a_version_module_that_disagrees_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path, "## [0.1.0]", declared="0.1.1")
    assert release_checks.problems(root) == ["src/loquitur/verify/_version.py does not declare 0.1.0"]


@pytest.mark.parametrize("version", ["0.01.0", "0.1.0rc1", "0.1", "v0.1.0"])
def test_a_version_that_is_not_x_y_z_is_refused(version: str, tmp_path: Path) -> None:
    root = _tree(tmp_path, f"## [{version}]", version=version)
    assert release_checks.problems(root) == [f"pyproject.toml declares {version}, not X.Y.Z with no leading zeros"]


def test_the_notes_are_the_text_of_the_section_and_an_empty_one_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _tree(tmp_path, "## [0.1.0] - 2026-10-20")
    monkeypatch.setattr(release_checks, "ROOT", root)
    assert release_checks.main(["notes", "0.1.0"]) == 0
    assert capsys.readouterr().out == "- first\n"
    (root / "CHANGELOG.md").write_text("## [0.1.0]\n\n## [0.0.9]\n\n- older\n", encoding="utf-8")
    assert release_checks.main(["notes", "0.1.0"]) == 1
    assert release_checks.main(["notes", "0.2.0"]) == 1
    assert capsys.readouterr().err.splitlines() == [
        "CHANGELOG.md has no text under ## [0.1.0]",
        "CHANGELOG.md has no section headed ## [0.2.0] or ## [0.2.0] - YYYY-MM-DD",
    ]


def test_this_repository_passes_the_check() -> None:
    assert release_checks.problems(ROOT) == []
    assert release_checks.main(["notes", release_checks.version(ROOT)]) == 0
