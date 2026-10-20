"""Tables of the protocol's normative documents, read by the tests that hold this verifier to them.

loquitur-protocol states several rules as Markdown tables: the link comparisons
(registry-link.md), the authorization order and vocabulary
(trust-registry-authorization.md) and the report's reason surface (report-contract.md). A test
that restated those tables here would check the verifier against a copy, and the copy and the
specification could part without anything noticing. These helpers read the tables from the
sibling checkout instead, so a row changed in the specification fails the test until the
verifier follows it, and a behavior changed in the verifier fails it until the specification
does.

The sibling is absent in a single-repository clone: the tests skip there, and fail instead when
LOQUITUR_REQUIRE_SIBLINGS is set (siblings.py).

Not a test module: pytest collects test_*.py, and this is imported by them.
"""

from __future__ import annotations

import re
from pathlib import Path

from siblings import absent

SPECIFICATION = Path(__file__).resolve().parents[2] / "loquitur-protocol" / "docs" / "specification"
# A reference to another specification document is a link to its file, [`x.md`](x.md). The link is
# markup: the tests read the text a reader sees, the document name in a code span.
DOCUMENT_LINK = re.compile(r"\[`([^`\]]+\.md)`\]\(\1\)")


def document(name: str) -> str:
    """The text of ``docs/specification/<name>`` in the sibling loquitur-protocol checkout."""
    path = SPECIFICATION / name
    if not path.is_file():
        absent(f"loquitur-protocol is not checked out beside this repository: {path} is missing")
    return DOCUMENT_LINK.sub(r"`\1`", path.read_text(encoding="utf-8"))


def _cells(line: str) -> list[str]:
    # A cell may carry an escaped pipe (\|) inside code; it is not a separator.
    parts = re.split(r"(?<!\\)\|", line.strip())
    return [part.strip().replace("\\|", "|") for part in parts[1:-1]]


def tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Every Markdown table of ``text`` as (header cells, body rows)."""
    found: list[tuple[list[str], list[list[str]]]] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if (
            line.lstrip().startswith("|")
            and index + 1 < len(lines)
            and re.fullmatch(r"\s*\|(\s*:?-{3,}:?\s*\|)+\s*", lines[index + 1])
        ):
            header = _cells(line)
            rows: list[list[str]] = []
            index += 2
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                rows.append(_cells(lines[index]))
                index += 1
            found.append((header, rows))
            continue
        index += 1
    return found


def sections(text: str) -> dict[str, str]:
    """The body of each ``## `` section of a document, by its title.

    A document that states one kind of rule per section carries several tables with the same
    header (document-contracts.md gives every document the same member columns), and
    ``table`` refuses that on purpose. Reading one section at a time keeps each table addressed
    by the section that owns it.
    """
    found: dict[str, str] = {}
    title: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if title is not None:
                found[title] = "\n".join(body)
            title, body = line[3:].strip(), []
        else:
            body.append(line)
    if title is not None:
        found[title] = "\n".join(body)
    return found


def table(text: str, header: list[str]) -> list[dict[str, str]]:
    """The one table of ``text`` whose header is exactly ``header``, as a list of row mappings."""
    matching = [rows for cells, rows in tables(text) if cells == header]
    assert len(matching) == 1, f"expected exactly one table headed {header}, found {len(matching)}"
    rows = matching[0]
    assert rows, f"the table headed {header} has no rows"
    for row in rows:
        assert len(row) == len(header), f"row {row} does not have the {len(header)} cells of {header}"
    return [dict(zip(header, row, strict=True)) for row in rows]


def code(cell: str) -> str:
    """The content of a cell that is one code span, such as `OFFLINE_OK`."""
    match = re.fullmatch(r"`([^`]*)`", cell)
    assert match, f"expected one code span, got {cell!r}"
    return match.group(1)


def codes(cell: str) -> list[str]:
    """Every code span of a cell, in order."""
    return re.findall(r"`([^`]*)`", cell)
