#!/usr/bin/env python3
"""The release workflow's checks of the version and the changelog, in one place.

.github/workflows/release.yml runs this file, which is not part of the package: the wheel
ships src/loquitur only. `check` refuses a version that is not X.Y.Z, a `_version.py` that
declares another one, a tag other than `vX.Y.Z` and a CHANGELOG.md with no section for it or a
section with no text. `version` prints the version, for the jobs after the check. `notes` prints
the text of the version's CHANGELOG.md section, the release notes of the draft release, and
refuses it by the same rule as `check`, so a section `check` passes is one `notes` prints.

A section is found by one rule, the one the release workspace writes: its heading line is
exactly `## [X.Y.Z]` or `## [X.Y.Z] - YYYY-MM-DD`, in ASCII digits.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def is_section_heading(line: str, version: str) -> bool:
    """Whether `line` is the heading of the CHANGELOG.md section of `version`."""
    return re.fullmatch(rf"## \[{re.escape(version)}\](?: - \d{{4}}-\d{{2}}-\d{{2}})?", line, re.ASCII) is not None


def section(changelog: str, version: str) -> str | None:
    """The text under the heading of `version`, up to the next `## ` heading; None without one."""
    lines = changelog.splitlines()
    start = next((index for index, line in enumerate(lines) if is_section_heading(line, version)), None)
    if start is None:
        return None
    body = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    return "\n".join(body).strip("\n")


def changelog_problem(changelog: str, version: str) -> str | None:
    """Why `changelog` cannot give the release notes of `version`: no section, or one with no text."""
    text = section(changelog, version)
    if text is None:
        return f"CHANGELOG.md has no section headed ## [{version}] or ## [{version}] - YYYY-MM-DD"
    if not text.strip():
        return f"CHANGELOG.md has no text under ## [{version}]"
    return None


def version(root: Path) -> str:
    """The version pyproject.toml declares."""
    return tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def problems(root: Path, tag: str | None = None) -> list[str]:
    """What stops a release of the version pyproject.toml declares, tagged `tag` when given."""
    found = []
    current = version(root)
    if not VERSION.fullmatch(current):
        found.append(f"pyproject.toml declares {current}, not X.Y.Z with no leading zeros")
    module = (root / "src/loquitur/verify/_version.py").read_text(encoding="utf-8")
    declared = re.search(r'^__version__ = "([^"]+)"$', module, re.M)
    if declared is None or declared.group(1) != current:
        found.append(f"src/loquitur/verify/_version.py does not declare {current}")
    if tag is not None and tag != f"v{current}":
        found.append(f"the tag {tag} is not v{current}, the version in pyproject.toml")
    changelog = changelog_problem((root / "CHANGELOG.md").read_text(encoding="utf-8"), current)
    if changelog is not None:
        found.append(changelog)
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The release workflow's checks of the version and the changelog.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check the version, _version.py, the tag and the CHANGELOG section")
    check.add_argument("--tag", help="the pushed tag; left out on a dry run")
    commands.add_parser("version", help="print the version pyproject.toml declares")
    notes = commands.add_parser("notes", help="print the CHANGELOG.md section of a version")
    notes.add_argument("version")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(version(ROOT))
        return 0
    if args.command == "notes":
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        problem = changelog_problem(changelog, args.version)
        if problem is not None:
            print(problem, file=sys.stderr)
            return 1
        print(section(changelog, args.version))
        return 0
    found = problems(ROOT, tag=args.tag)
    if found:
        print("\n".join(found), file=sys.stderr)
        return 1
    print(f"version {version(ROOT)}: pyproject.toml, _version.py and CHANGELOG.md agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
