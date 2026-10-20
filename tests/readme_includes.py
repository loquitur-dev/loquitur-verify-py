"""The include markers of README.md, and the form of the blocks between them.

A block between ``<!-- lq-include: NAME -->`` and ``<!-- lq-include-end: NAME -->`` is included
whole, by name, into pages built from the documentation of several repositories, so the text
exists once. There it stands without the rest of its README, so it opens a section and stays
inside it, closes every code fence it opens, links to no anchor of its own page, does not call
that page "this README" or its repository "this repository", and sends the reader to no section
of its page by name.

Each check returns its problems, one message each, and an empty list when there is none.
``lines`` defaults to the README.md at the root of the repository that holds this module, which
is the same, byte for byte, in every repository whose README carries the markers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"
MARKER = re.compile(r"<!-- lq-include(?P<end>-end)?: (?P<name>\S+) -->")
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
FENCE = re.compile(r" {0,3}(?P<fence>`{3,}|~{3,})")
# An ATX heading of level 1 or 2, indented at most three spaces; its text may be empty.
SECTION = re.compile(r" {0,3}#{1,2}(?:[ \t]|$)")
# The underline of a setext heading, which is of level 1 (`=`) or 2 (`-`) whatever its length.
SETEXT_UNDERLINE = re.compile(r" {0,3}(?:=+|-+)[ \t]*")
# A line an underline does not make a heading of: blank, a list item, a quote, an indented code
# line or an ATX heading. Under any other line of text, the underline does.
NOT_HEADING_TEXT = re.compile(r"\s*$| {0,3}(?:[-*+]|[0-9]{1,9}[.)])(?:[ \t]|$)| {0,3}>| {4}|\t| {0,3}#{1,6}(?:[ \t]|$)")
# A link reference definition, `[label]: destination`, indented at most three spaces.
DEFINITION = re.compile(r" {0,3}\[(?P<label>[^\]]+)\]:[ \t]*<?(?P<destination>\S*)")
# A reference link: full `[text][label]`, collapsed `[label][]` or shortcut `[label]`.
REFERENCE = re.compile(r"\[(?P<text>[^\]]*)\](?:\[(?P<label>[^\]]*)\])?(?![(:])")
# An HTML link to an anchor: `href="#..."`, quoted either way or not at all.
HREF = re.compile(r"""\bhref\s*=\s*["']?#""", re.IGNORECASE)
# Words that name the page a block stands on, which on the page it is included into is another.
SELF = ("this readme", "this repository")
# A section sent to by its quoted name: `see "Name"`, or `"Name" below` or `above`.
SECTION_NAME = re.compile(r'\bsee "[^"]+"|"[^"]+" (?:below|above)\b', re.IGNORECASE)


@dataclass(frozen=True)
class Block:
    """One included block: its name, the line number of its opening marker, and its lines."""

    name: str
    start: int
    body: tuple[str, ...]

    def numbered(self) -> list[tuple[int, str]]:
        """The block's lines with their line numbers in the README."""
        return list(enumerate(self.body, start=self.start + 1))


def _lines(lines: list[str] | None) -> list[str]:
    return README.read_text(encoding="utf-8").splitlines() if lines is None else lines


def _parse(lines: list[str]) -> tuple[list[Block], list[str]]:
    """The complete blocks in order, and the problems of the markers themselves."""
    blocks: list[Block] = []
    problems: list[str] = []
    open_name: str | None = None
    open_line = 0
    for number, line in enumerate(lines, start=1):
        if "lq-include" not in line:
            continue
        match = MARKER.fullmatch(line)
        if match is None:
            problems.append(f"README.md:{number}: malformed include marker {line!r}")
        elif match["end"] is None:
            if open_name is not None:
                problems.append(f"README.md:{number}: {match['name']!r} opens inside {open_name!r}")
            open_name, open_line = match["name"], number
        elif match["name"] != open_name:
            opened = f"{open_name!r} is open" if open_name else "no block is open"
            problems.append(f"README.md:{number}: {match['name']!r} closes, but {opened}")
        else:
            blocks.append(Block(open_name, open_line, tuple(lines[open_line : number - 1])))
            open_name = None
    if open_name is not None:
        problems.append(f"README.md:{open_line}: {open_name!r} is never closed")
    return blocks, problems


def _fenced(body: tuple[str, ...]) -> tuple[list[bool], str | None]:
    """For each line, whether it is a code fence or inside one; and the fence left open, if any."""
    inside: list[bool] = []
    fence: str | None = None
    for line in body:
        match = FENCE.match(line)
        if fence is None:
            fence = match["fence"] if match else None
            inside.append(fence is not None)
            continue
        inside.append(True)
        if match and match["fence"][0] == fence[0] and len(match["fence"]) >= len(fence):
            if not line[match.end() :].strip():
                fence = None
    return inside, fence


def blocks(lines: list[str] | None = None) -> list[Block]:
    """Every complete block, in the order of the README."""
    return _parse(_lines(lines))[0]


def pairing(lines: list[str] | None = None) -> list[str]:
    """Every marker is well formed, and each block is closed by its own name before another opens."""
    return _parse(_lines(lines))[1]


def names(lines: list[str] | None = None) -> list[str]:
    """Each name is lowercase letters and digits in words joined by hyphens, and names one block."""
    problems: list[str] = []
    seen: set[str] = set()
    for block in blocks(lines):
        if not NAME.fullmatch(block.name):
            problems.append(f"README.md:{block.start}: {block.name!r} is not lowercase words joined by hyphens")
        if block.name in seen:
            problems.append(f"README.md:{block.start}: {block.name!r} names a block already")
        seen.add(block.name)
    return problems


def placement(lines: list[str] | None = None) -> list[str]:
    """Each block opens a section: its marker follows a `## ` heading and one blank line."""
    lines = _lines(lines)
    problems: list[str] = []
    for block in blocks(lines):
        before = lines[max(block.start - 3, 0) : block.start - 1]
        if len(before) != 2 or not before[0].startswith("## ") or before[1].strip():
            problems.append(f"README.md:{block.start}: {block.name!r} does not open under a '## ' heading")
    return problems


def _label(text: str) -> str:
    """A link label as Markdown matches it: case folded, with its runs of whitespace as one space."""
    return " ".join(text.split()).casefold()


def sections(lines: list[str] | None = None) -> list[str]:
    """Each block holds text and stays inside its section: no heading of level 1 or 2 outside a fence.

    Such a heading is an ATX heading, `# ` or `## ` indented at most three spaces, or a setext
    heading, a line of text underlined with `=` or `-`.
    """
    problems: list[str] = []
    for block in blocks(lines):
        if not any(line.strip() for line in block.body):
            problems.append(f"README.md:{block.start}: {block.name!r} includes nothing")
        inside, _ = _fenced(block.body)
        for index, ((number, line), fenced) in enumerate(zip(block.numbered(), inside, strict=True)):
            if fenced:
                continue
            setext = (
                index > 0
                and not inside[index - 1]
                and SETEXT_UNDERLINE.fullmatch(line) is not None
                and NOT_HEADING_TEXT.match(block.body[index - 1]) is None
            )
            if SECTION.match(line) or setext:
                problems.append(f"README.md:{number}: {block.name!r} runs into another section")
    return problems


def fences(lines: list[str] | None = None) -> list[str]:
    """Each block closes every code fence it opens."""
    problems: list[str] = []
    for block in blocks(lines):
        _, fence = _fenced(block.body)
        if fence is not None:
            problems.append(f"README.md:{block.start}: {block.name!r} leaves a {fence} code fence open")
    return problems


def anchor_links(lines: list[str] | None = None) -> list[str]:
    """No block links to an anchor: on the page it is included into, the anchor is not there.

    An anchor link is an inline link `](#`, an HTML `href="#`, a reference definition whose
    destination is an anchor, or a reference link whose definition, in the block or anywhere else
    in the README, is one.
    """
    lines = _lines(lines)
    anchors = {
        _label(match["label"])
        for line in lines
        if (match := DEFINITION.match(line)) is not None and match["destination"].startswith("#")
    }
    problems: list[str] = []
    for block in blocks(lines):
        inside, _ = _fenced(block.body)
        for (number, line), fenced in zip(block.numbered(), inside, strict=True):
            definition = None if fenced else DEFINITION.match(line)
            linked = "](#" in line or (
                not fenced
                and (
                    HREF.search(line) is not None
                    or (definition is not None and definition["destination"].startswith("#"))
                    or (
                        definition is None
                        and any(
                            _label(match["label"] or match["text"]) in anchors for match in REFERENCE.finditer(line)
                        )
                    )
                )
            )
            if linked:
                problems.append(f"README.md:{number}: {block.name!r} links to an anchor of its own page")
    return problems


def self_reference(lines: list[str] | None = None) -> list[str]:
    """No block says "this README" or "this repository": on the page it is included into, that names the wrong page."""
    return [
        f"README.md:{number}: {block.name!r} says {phrase!r}"
        for block in blocks(lines)
        for number, line in block.numbered()
        for phrase in SELF
        if phrase in line.lower()
    ]


def section_references(lines: list[str] | None = None) -> list[str]:
    """No block sends the reader to a section by name: the page it is included into may not have it."""
    return [
        f"README.md:{number}: {block.name!r} refers to a section by name: {match.group()!r}"
        for block in blocks(lines)
        for number, line in block.numbered()
        for match in SECTION_NAME.finditer(line)
    ]
