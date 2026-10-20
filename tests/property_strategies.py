"""Hypothesis strategies shared by the property tests: JSON values the protocol admits.

Strings mix every Unicode scalar value with characters chosen for the places a JSON reader or a
canonicalizer can go wrong: the quote, the backslash and control characters (written as
escapes), combining marks, astral characters (a surrogate pair in UTF-16, and in an escaped
spelling), U+2028 and U+2029. Noncharacters are left out: they are refused at load (input
strictness rule 9), and the refusal has a property of its own. Integers stay within the safe
range, floats are finite and are not integer values beyond it, and containers nest a few levels.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

SAFE_INTEGER_MAX = 2**53 - 1

# U+FDD0 to U+FDEF and every code point whose low 16 bits are FFFE or FFFF.
NONCHARACTERS = tuple(range(0xFDD0, 0xFDF0)) + tuple(
    (plane << 16) | low for plane in range(17) for low in (0xFFFE, 0xFFFF)
)
_NONCHARACTER_SET = frozenset(NONCHARACTERS)

_CHOSEN = st.sampled_from(
    [
        '"',
        "\\",
        "/",
        "\u0000",
        "\u0008",
        "\u001f",
        "\u007f",
        "\u0301",  # COMBINING ACUTE ACCENT
        "\u0308",  # COMBINING DIAERESIS
        "\u20dd",  # COMBINING ENCLOSING CIRCLE
        "\u00e9",
        "\u2028",
        "\u2029",
        "\ufeff",
        "\U0001f600",
        "\U00010000",
        "\U0010fffd",
    ]
)

characters = st.one_of(st.characters(codec="utf-8"), _CHOSEN).filter(lambda c: ord(c) not in _NONCHARACTER_SET)

texts = st.text(characters, max_size=12)

integers = st.integers(min_value=-SAFE_INTEGER_MAX, max_value=SAFE_INTEGER_MAX)

floats = st.floats(allow_nan=False, allow_infinity=False).filter(
    lambda value: not (value.is_integer() and abs(value) > SAFE_INTEGER_MAX)
)

scalars = st.one_of(st.none(), st.booleans(), integers, floats, texts)


def _containers(children: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    return st.one_of(st.lists(children, max_size=4), st.dictionaries(texts, children, max_size=4))


json_values = st.recursive(scalars, _containers, max_leaves=16)

json_objects = st.dictionaries(texts, json_values, max_size=6)
