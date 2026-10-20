"""Properties of the portable member-name rule and of the ASCII letter-case fold.

``members.member_name_problem`` decides every member name the verifier meets (a manifest key, a
directory entry, an archive entry) and ``members.fold_member_name`` is the only folding of member
names (bundle-objects.md section 2). The model below is a second reading of section 2, rules 1 to
4, written in this test without the production code. These properties are the maintainer's own
testing, carried out with the help of AI tools, which is internal verification and not an audit.
"""

from __future__ import annotations

import property_profile  # noqa: F401  (loads the fixed profile before any test is defined)
from hypothesis import given
from hypothesis import strategies as st

from loquitur.verify.members import fold_member_name, member_name_problem

_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_PORTABLE = set(_UPPER + _LOWER + "0123456789._-")
_DEVICES = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


def _ascii_lower(text: str) -> str:
    return "".join(_LOWER[_UPPER.index(c)] if c in _UPPER else c for c in text)


def portable(name: str) -> bool:
    """bundle-objects.md section 2, rules 1 to 4, read directly."""
    for segment in name.split("/"):
        # Rule 1: non-empty, POSIX portable filename characters only.
        if not segment or not set(segment) <= _PORTABLE:
            return False
        # Rule 2: not "." or "..", no trailing ".", no leading "-".
        if segment in (".", "..") or segment.endswith(".") or segment.startswith("-"):
            return False
        # Rule 3: the part before the first "." is no Windows device name, ASCII case ignored.
        if _ascii_lower(segment.partition(".")[0]) in _DEVICES:
            return False
    # Rule 4: at most 255 bytes.
    return len(name.encode("utf-8")) <= 255


_SEGMENT_PIECES = st.sampled_from(
    [
        "a",
        "Z",
        "9",
        ".",
        "..",
        "_",
        "-",
        "x-",
        ".hidden",
        "con",
        "CON",
        "Con",
        "nul.txt",
        "COM1",
        "com0",
        "lpt9.log",
        "LPT10",
        "aux.",
        "conin",
        "console",
        "\u212a",  # KELVIN SIGN, which Unicode lower-cases to "k"
        "\u0130",
        "\u00e9",
        "e\u0301",
        " ",
        "\\",
        ":",
        "~",
        "<",
        "*",
        "\t",
        "\u0000",
        "\u3000",
        "\U0001f600",
    ]
)
_SEGMENTS = st.lists(st.one_of(_SEGMENT_PIECES, st.text("abcXYZ019._-", max_size=6)), max_size=4).map("".join)
_NAMES = st.one_of(
    st.lists(_SEGMENTS, min_size=1, max_size=4).map("/".join),
    st.text(max_size=12),
    # Names near the 255-byte bound.
    st.integers(240, 270).map(lambda size: ("a" * 50 + "/") * (size // 51) + "b" * (size % 51)),
)


@given(_NAMES)
def test_the_portable_predicate_agrees_with_the_specification_model(name: str) -> None:
    """Over generated names, ``member_name_problem`` admits a name exactly when the model of rules 1 to 4 does.

    Shows that the predicate holds no rule the specification lacks and lacks none it holds, for
    device names in any letter case, segments of dots, non-ASCII look-alikes and the length bound.
    """
    assert (member_name_problem(name) is None) is portable(name), name


@given(st.text())
def test_the_fold_is_idempotent_and_changes_only_a_to_z(text: str) -> None:
    """The fold reads A to Z as a to z, changes nothing else, and folding twice is folding once."""
    folded = fold_member_name(text)
    assert fold_member_name(folded) == folded
    assert len(folded) == len(text)
    for before, after in zip(text, folded, strict=True):
        if "A" <= before <= "Z":
            assert after == chr(ord(before) + 32)
        else:
            assert after == before


@given(st.sampled_from(["\u212a", "\u0130", "\u00c9", "\u0391", "\u1e9e", "\u2160"]), st.text(max_size=6))
def test_the_fold_is_not_unicode_lower_casing(character: str, around: str) -> None:
    """Letters outside A to Z keep their case, where ``str.lower`` would change them."""
    text = around + character + around
    assert fold_member_name(text).count(character) == text.count(character)
    assert character.lower() != character
