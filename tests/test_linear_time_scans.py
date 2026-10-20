"""Two scans over party-supplied input run in linear time, and keep their answers.

The nesting-depth pre-scan read an unterminated string by retrying from every later quote, and
the uniqueItems check compared every item with every earlier one: both were quadratic in input
the protocol does not bound (a member's text, a trust registry's entries), so a document of a
few hundred kilobytes stalled a run for minutes. A stall on document content is a defect of the
verifier, not a verdict. The bounds below are generous for any host and far below what the
quadratic scans took at these sizes.
"""

from __future__ import annotations

import time

import pytest

from loquitur.verify.canonical import MAX_JSON_NESTING_DEPTH, JsonLoadError, _nesting_exceeds, loads_json_bytes
from loquitur.verify.contract_validation import _has_duplicates

_BOUND_SECONDS = 2.0


def _elapsed(call) -> float:
    start = time.perf_counter()
    call()
    return time.perf_counter() - start


def test_an_unterminated_string_is_scanned_in_linear_time() -> None:
    # 128 KiB of escaped quotes inside a string that never closes, then brackets. A quadratic
    # scan takes about 45 s at 32 KiB and four times longer per doubling.
    text = '"' + '\\"' * 65536 + "[" * 65
    assert _elapsed(lambda: _nesting_exceeds(text, MAX_JSON_NESTING_DEPTH)) < _BOUND_SECONDS


def test_an_unterminated_string_is_a_parse_error_not_a_depth_error() -> None:
    text = '"' + '\\"' * 4096 + "[" * 65
    assert _nesting_exceeds(text, MAX_JSON_NESTING_DEPTH) is False
    with pytest.raises(JsonLoadError) as caught:
        loads_json_bytes(text.encode("utf-8"), name="doc")
    assert str(caught.value).startswith("invalid_json:doc:")


@pytest.mark.parametrize(
    ("text", "too_deep"),
    [
        ("[" * 64 + "]" * 64, False),  # depth 64, empty innermost array
        ("[" * 64 + "{}" + "]" * 64, True),  # depth 65, empty innermost object
        ('["' + "[" * 100 + '"]', False),  # brackets inside a string do not count
        ('"\\\\"' + "[" * 65 + "]" * 65, True),  # an escaped backslash closes nothing early
    ],
)
def test_the_depth_rule_counts_brackets_outside_strings(text: str, too_deep: bool) -> None:
    assert _nesting_exceeds(text, MAX_JSON_NESTING_DEPTH) is too_deep


def test_unique_items_is_checked_in_linear_time() -> None:
    # 200 000 distinct strings: a pairwise scan takes about 5 s for 20 000.
    items = [f"code-{index}" for index in range(200_000)]
    assert _elapsed(lambda: _has_duplicates(items)) < _BOUND_SECONDS
    assert _has_duplicates(items) is False
    assert _has_duplicates([*items, "code-7"]) is True


@pytest.mark.parametrize(
    ("items", "duplicated"),
    [
        ([1, 1.0], True),  # numbers compare by value
        ([True, 1], False),  # a boolean is never a number
        ([False, 0], False),
        ([None, None], True),
        ([[1, 2], [2, 1]], False),  # arrays compare in order
        ([[1, 2], [1, 2.0]], True),
        ([{"a": 1, "b": 2}, {"b": 2, "a": 1}], True),  # objects compare by members
        ([{"a": 1}, {"a": True}], False),
        (["1", 1], False),
    ],
)
def test_unique_items_keeps_json_equality(items: list, duplicated: bool) -> None:
    assert _has_duplicates(items) is duplicated
