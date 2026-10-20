"""Every tracked text file writes an invisible character as an escape.

A test that pins the whitespace set W, a byte-order mark or a bidirectional override needs those
code points, and a literal one inside a string literal is a character a reader of the file cannot
see: review passes over it, a copy carries it into another file, and nothing tells it apart from a
stray paste. A rule nothing holds does not stay held. This holds it, over every file git tracks,
because tracked files are what a publication copies.

An escape denotes the same code point: the values a suite asserts do not change, only the bytes of
the source file. The rule covers what prints as nothing: the control, format and line or
paragraph separators, every space that is not U+0020, every Default_Ignorable_Code_Point of Unicode
(variation selectors and the Hangul and Khmer fillers among them) and U+2800 (the blank braille
pattern), and the 66 noncharacters, which input strictness rule 9 refuses in any document. It does
not cover unassigned or private-use code points, which print as a box rather than as nothing and
which the canonicalization vectors carry as pinned data.
"""

from __future__ import annotations

import subprocess
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Written as escapes here too, because this file is read by the rule it states.
READABLE_CONTROLS = (chr(9), chr(10), chr(13))  # tab, newline, carriage return
SPACE = chr(32)
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")

# Default_Ignorable_Code_Point (Unicode DerivedCoreProperties.txt) as ranges, the categories above
# aside, plus U+2800. unicodedata does not expose the property, so it is written out here.
DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),  # Hangul choseong and jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180B, 0x180F),  # Mongolian free variation selectors and vowel separator
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x2800, 0x2800),  # braille pattern blank: not default-ignorable, but prints as nothing
    (0x3164, 0x3164),  # Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),  # tags and variation selectors supplement
)


def _default_ignorable(code: int) -> bool:
    return any(low <= code <= high for low, high in DEFAULT_IGNORABLE)


def _noncharacter(code: int) -> bool:
    return 0xFDD0 <= code <= 0xFDEF or code & 0xFFFE == 0xFFFE


def _invisible(text: str) -> list[tuple[int, int, str]]:
    """Every code point of ``text`` that prints as nothing, as (line, column, code point)."""
    found: list[tuple[int, int, str]] = []
    for number, line in enumerate(text.split(chr(10)), start=1):
        for column, character in enumerate(line, start=1):
            if character in READABLE_CONTROLS:
                continue
            category = unicodedata.category(character)
            code = ord(character)
            if (
                category in INVISIBLE_CATEGORIES
                or (category == "Zs" and character != SPACE)
                or _default_ignorable(code)
                or _noncharacter(code)
            ):
                found.append((number, column, f"U+{code:04X}"))
    return found


def _tracked_files() -> list[Path]:
    """Every file git tracks; outside a checkout, every file of the tree."""
    try:
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):  # a copy taken without the git history
        return [path for path in sorted(ROOT.rglob("*")) if path.is_file() and ".git" not in path.parts]
    return [ROOT / name for name in listed.split(chr(0)) if name]


def test_the_rule_sees_an_invisible_character_and_passes_ordinary_text() -> None:
    """The detector finds what the rule is about, passes text that is all visible, and reads files."""
    sample = "key_id" + chr(0x00A0) + "=" + chr(0xFEFF) + chr(0x2028)
    assert [hit[2] for hit in _invisible(sample)] == ["U+00A0", "U+FEFF", "U+2028"]
    # The default-ignorable code points outside those categories, the fillers, U+2800 and the
    # noncharacters (the three rule 9 once held literally among them).
    others = (0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x2800, 0x3164, 0xFE00, 0xFE0F, 0xFFA0, 0xE0100)
    nonchars = (0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF)
    for code in others + nonchars:
        assert _invisible("a" + chr(code) + "b") == [(1, 2, f"U+{code:04X}")], hex(code)
    for code in (0x00E9, 0x3042, 0x1F600, 0xFDCF, 0xFDF0, 0xFFFD, 0x1FFFD, 0x2801):
        assert _invisible("a" + chr(code) + "b") == [], hex(code)
    assert _invisible("a tab" + chr(9) + "a newline" + chr(10) + "a space and a hyphen -") == []
    assert len(_tracked_files()) > 10, "the sweep below would hold over almost nothing"


def test_no_tracked_file_holds_a_literal_invisible_character() -> None:
    findings: list[str] = []
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # not UTF-8 text: an archive, an image, a binary fixture
        findings += [
            f"{path.relative_to(ROOT).as_posix()}:{line}:{column}: {point}" for line, column, point in _invisible(text)
        ]
    assert not findings, "a reader of the file cannot see these; write them as escapes: " + ", ".join(findings)
