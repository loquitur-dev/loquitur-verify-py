"""Properties of the strict JSON loader and the canonicalizer, over generated documents.

Each test runs the verifier's own production functions, ``loads_json_bytes`` (the loader every
document read from disk goes through) and ``canonical_json_bytes``, over values Hypothesis
generates under the fixed profile of tests/property_profile.py. The properties are the
maintainer's own testing of canonicalization-and-hashing.md sections 1 and 6, carried out with the
help of AI tools, which is internal verification and not an audit.
"""

from __future__ import annotations

import json

import property_profile  # noqa: F401  (loads the fixed profile before any test is defined)
import pytest
from bundle_builder import nested_text
from hypothesis import given
from hypothesis import strategies as st
from property_strategies import NONCHARACTERS, SAFE_INTEGER_MAX, characters, json_values, texts

from loquitur.verify.canonical import (
    MAX_JSON_NESTING_DEPTH,
    JsonLoadError,
    canonical_json_bytes,
    loads_json_bytes,
)


def _refusal(data: bytes) -> str:
    with pytest.raises(JsonLoadError) as caught:
        loads_json_bytes(data, name="doc")
    return str(caught.value)


def _escaped(text: str) -> str:
    """``text`` as JSON string content with every code unit written as a \\uXXXX escape."""
    units = text.encode("utf-16-be")
    return "".join(f"\\u{int.from_bytes(units[i : i + 2], 'big'):04x}" for i in range(0, len(units), 2))


@given(json_values)
def test_canonical_bytes_are_a_fixed_point_of_load_then_canonicalize(value: object) -> None:
    """Loading canonical bytes and canonicalizing the result gives the same bytes.

    Shows that the loader admits every canonical document the canonicalizer emits and reads
    back the value it was made from, as far as the canonical form can tell: no character,
    escape or number changes on the way round.
    """
    canonical = canonical_json_bytes(value)
    assert canonical_json_bytes(loads_json_bytes(canonical)) == canonical


@given(json_values, st.booleans())
def test_canonicalization_is_idempotent_whatever_the_input_spelling(value: object, ascii_only: bool) -> None:
    """A document in any JSON spelling of a value canonicalizes to the value's canonical bytes.

    ``json.dumps`` writes the value with other whitespace, member order and, with ensure_ascii,
    every non-ASCII character as an escape (astral characters as surrogate-pair escapes). Shows
    that canonicalizing is idempotent and that the spelling of the input never reaches the
    canonical bytes.
    """
    canonical = canonical_json_bytes(value)
    spelled = json.dumps(value, ensure_ascii=ascii_only, indent=1).encode("utf-8")
    once = canonical_json_bytes(loads_json_bytes(spelled))
    assert once == canonical
    assert canonical_json_bytes(loads_json_bytes(once)) == once


@given(texts.filter(bool), json_values, json_values)
def test_a_member_name_repeated_after_escape_decoding_is_refused(key: str, first: object, second: object) -> None:
    """Two member names that are one name once escapes are decoded are a duplicate (rule 1).

    The second spelling writes every code unit as an escape, so the two names differ as bytes and
    agree as strings. Shows that duplicates are found on the decoded name, never on its spelling.
    """
    literal = json.dumps(key, ensure_ascii=False)
    document = "{" + literal + ":" + json.dumps(first) + ',"' + _escaped(key) + '":' + json.dumps(second) + "}"
    assert _refusal(document.encode("utf-8")).startswith("duplicate_json_key:doc:")


@given(st.integers(0xD800, 0xDFFF), texts, texts, st.booleans())
def test_a_lone_surrogate_escape_is_refused(code: int, before: str, after: str, in_name: bool) -> None:
    """An escaped surrogate that is not half of a pair is refused, in a value or a member name (rule 4).

    The text around it is written without escapes, so nothing can pair with it. Shows that a
    string which is no sequence of Unicode scalar values never loads.
    """
    if 0xD800 <= code <= 0xDBFF:
        after = ""  # a high surrogate followed by nothing pairs with nothing
    body = json.dumps(before, ensure_ascii=False)[1:-1] + f"\\u{code:04x}" + json.dumps(after, ensure_ascii=False)[1:-1]
    document = '{"' + body + '":0}' if in_name else '{"k":"' + body + '"}'
    assert _refusal(document.encode("utf-8")) == "json_lone_surrogate:doc"


@given(st.sampled_from(NONCHARACTERS), texts, st.booleans(), st.booleans())
def test_a_noncharacter_is_refused_written_or_escaped(code: int, around: str, escaped: bool, in_name: bool) -> None:
    """A noncharacter is refused, written as UTF-8 or as an escape, in a value or a name (rule 9)."""
    character = chr(code)
    spelled = _escaped(character) if escaped else character
    body = json.dumps(around, ensure_ascii=False)[1:-1] + spelled
    document = '{"' + body + '":0}' if in_name else '{"k":["' + body + '"]}'
    assert _refusal(document.encode("utf-8")) == "json_noncharacter:doc"


@given(json_values)
def test_a_byte_order_mark_prefix_is_refused(value: object) -> None:
    """Canonical bytes behind a UTF-8 byte order mark do not load (rule 7: UTF-8 with no BOM)."""
    canonical = canonical_json_bytes(value)
    loads_json_bytes(canonical)
    with pytest.raises(JsonLoadError):
        loads_json_bytes(b"\xef\xbb\xbf" + canonical, name="doc")


_INVALID_UTF8 = [
    b"\xff",
    b"\xfe",
    b"\x80",
    b"\xc0\x80",  # overlong NUL
    b"\xc1\xbf",
    b"\xe0\x80\x80",  # overlong
    b"\xed\xa0\x80",  # an encoded surrogate (CESU-8)
    b"\xf4\x90\x80\x80",  # beyond U+10FFFF
    b"\xe2\x82",  # truncated
    b"\xf0\x9f\x98",  # truncated
]


@given(json_values, st.sampled_from(_INVALID_UTF8), texts)
def test_bytes_that_are_not_utf8_are_refused(value: object, invalid: bytes, around: str) -> None:
    """A document carrying a byte sequence that is not UTF-8 inside a string is refused (rule 7)."""
    inner = json.dumps(around, ensure_ascii=False).encode("utf-8")
    document = b'{"a":' + canonical_json_bytes(value) + b',"b":' + inner[:1] + invalid + inner[1:] + b"}"
    assert _refusal(document) == "invalid_json_encoding:doc"


@given(st.one_of(st.integers(min_value=SAFE_INTEGER_MAX + 1), st.integers(max_value=-SAFE_INTEGER_MAX - 1)))
def test_an_integer_beyond_the_safe_range_is_refused(number: int) -> None:
    """An integer of magnitude above 2^53 - 1 is refused, and the nearest safe integer loads (rule 2)."""
    assert _refusal(b'{"n":' + str(number).encode() + b"}") == "json_integer_outside_safe_range:doc"
    loads_json_bytes(b'{"n":' + str(max(-SAFE_INTEGER_MAX, min(SAFE_INTEGER_MAX, number))).encode() + b"}")


def _nested(kinds: list[bool], leaf: str) -> str:
    text = leaf
    for is_object in reversed(kinds):
        text = '{"k":' + text + "}" if is_object else "[" + text + "]"
    return text


@given(st.lists(st.booleans(), min_size=MAX_JSON_NESTING_DEPTH, max_size=MAX_JSON_NESTING_DEPTH), texts)
def test_depth_64_loads_and_depth_65_is_refused(kinds: list[bool], leaf: str) -> None:
    """Any mix of arrays and objects nested 64 deep loads, and one level more is refused (rule 6).

    Strings at the leaf may hold brackets, which do not count towards the depth.
    """
    scalar = json.dumps(leaf + "[{")
    assert MAX_JSON_NESTING_DEPTH == 64
    loaded = loads_json_bytes(_nested(kinds, scalar).encode("utf-8"))
    assert canonical_json_bytes(loaded)
    for outer in (True, False):
        assert _refusal(_nested([outer, *kinds], scalar).encode("utf-8")) == "json_nesting_too_deep:doc"
    assert _refusal(nested_text(65).encode()) == "json_nesting_too_deep:doc"


@given(characters)
def test_every_generated_character_is_admitted(character: str) -> None:
    """The generator's alphabet holds no character the loader refuses, so the fixed-point
    property above is never vacuous for a character it draws."""
    assert loads_json_bytes(json.dumps(character).encode("utf-8")) == character
