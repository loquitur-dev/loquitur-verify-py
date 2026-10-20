"""Properties of the operator's evaluation time, over generated strings.

``evaluation_time.operator_evaluation_time`` is the function the command line and the library
call on ``--evaluation-time`` / ``evaluation_time``; it accepts a calendar instant of the form
``YYYY-MM-DDTHH:MM:SSZ`` and refuses everything else (canonicalization-and-hashing.md section 6,
rule 8; trust-registry-authorization.md section 2). The model of the form below is written from
the specification text. These properties are the maintainer's own testing, carried out with the help of AI tools, which is
internal verification and not an audit.
"""

from __future__ import annotations

import calendar
from datetime import datetime

import property_profile  # noqa: F401  (loads the fixed profile before any test is defined)
from hypothesis import given
from hypothesis import strategies as st

from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time

_DIGITS = frozenset("0123456789")


def accepted(value: object) -> bool:
    try:
        return operator_evaluation_time(value) == value
    except EvaluationTimeError:
        return False


def _instant(moment: datetime) -> str:
    return f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}Z"


def _model(value: str) -> bool:
    """The form and the calendar, from the specification: ASCII digits, fixed punctuation, a real instant."""
    if len(value) != 20 or value[4] != "-" or value[7] != "-" or value[10] != "T":
        return False
    if value[13] != ":" or value[16] != ":" or value[19] != "Z":
        return False
    fields = [value[0:4], value[5:7], value[8:10], value[11:13], value[14:16], value[17:19]]
    if not all(set(field) <= _DIGITS for field in fields):
        return False
    year, month, day, hour, minute, second = (int(field) for field in fields)
    if year < 1 or not 1 <= month <= 12 or hour > 23 or minute > 59 or second > 59:
        return False
    return 1 <= day <= calendar.monthrange(year, month)[1]


@given(st.datetimes(min_value=datetime(1, 1, 1), max_value=datetime(9999, 12, 31, 23, 59, 59)))
def test_every_calendar_instant_from_year_0001_is_accepted(moment: datetime) -> None:
    """Every instant of the proleptic Gregorian calendar, years 0001 to 9999, written in the form, is accepted as written."""
    assert accepted(_instant(moment.replace(microsecond=0)))


@given(st.integers(min_value=1, max_value=9999), st.integers(0, 23), st.integers(0, 59), st.integers(0, 59))
def test_february_29_only_in_a_leap_year(year: int, hour: int, minute: int, second: int) -> None:
    """February 29 is accepted exactly in the Gregorian leap years (1900 is not one, 2000 is)."""
    value = f"{year:04d}-02-29T{hour:02d}:{minute:02d}:{second:02d}Z"
    assert accepted(value) is calendar.isleap(year)


@given(st.datetimes(min_value=datetime(1, 1, 1), max_value=datetime(9999, 12, 31, 23, 59, 59)))
def test_second_60_is_refused(moment: datetime) -> None:
    """A leap second, second 60, is never an instant here, at the end of a day or anywhere else."""
    assert not accepted(_instant(moment)[:17] + "60Z")


_SHAPE_ALPHABET = st.sampled_from(list("0123456789-T:Z tz+.\u0660\u0661\uff10\u0969") + ["\U0001d7ce"])


@given(st.text(_SHAPE_ALPHABET, min_size=0, max_size=24))
def test_a_string_is_accepted_exactly_when_the_model_accepts_it(value: str) -> None:
    """Over strings of digits (ASCII and others), separators and near-miss letters, the parser agrees with the model."""
    assert accepted(value) is _model(value)


@given(
    st.datetimes(min_value=datetime(1, 1, 1), max_value=datetime(9999, 12, 31, 23, 59, 59)),
    st.lists(st.tuples(st.integers(0, 19), _SHAPE_ALPHABET), min_size=1, max_size=3),
)
def test_a_valid_instant_with_characters_replaced_is_accepted_exactly_when_the_model_accepts_it(
    moment: datetime, replacements: list[tuple[int, str]]
) -> None:
    """Near misses (month 13, day 32, hour 24, a separator moved, a non-ASCII digit): the parser agrees with the model."""
    characters = list(_instant(moment))
    for index, character in replacements:
        characters[index] = character
    value = "".join(characters)
    assert accepted(value) is _model(value)


_MUTATIONS = [
    lambda v: v[:-1],  # no zone designator
    lambda v: v[:-1] + "z",
    lambda v: v[:-1] + "+00:00",
    lambda v: v[:10] + "t" + v[11:],
    lambda v: v[:10] + " " + v[11:],
    lambda v: v[:-1] + ".000Z",  # fractional seconds
    lambda v: "+" + v,
    lambda v: "0" + v,  # a five-digit year
    lambda v: v[:10],  # a date alone
    lambda v: v + "\n",
    lambda v: " " + v,
    lambda v: v.replace("-", "", 1),
    lambda v: v.replace("0", "\u0660"),  # ARABIC-INDIC DIGIT ZERO for every 0
]


@given(
    st.datetimes(min_value=datetime(1, 1, 1), max_value=datetime(9999, 12, 31, 23, 59, 59)),
    st.sampled_from(range(len(_MUTATIONS))),
)
def test_any_other_shape_of_a_valid_instant_is_refused(moment: datetime, mutation: int) -> None:
    """A valid instant in any other shape (another zone, separator, precision, width or digit set) is refused."""
    value = _MUTATIONS[mutation](_instant(moment))
    if value == _instant(moment):
        return  # the digit mutation of a value holding no 0
    assert not accepted(value)


@given(st.one_of(st.none(), st.integers(), st.floats(), st.binary(), st.lists(st.text())))
def test_a_value_that_is_not_a_string_is_refused(value: object) -> None:
    """Only a string is an evaluation time."""
    assert not accepted(value)


def test_year_0000_is_refused() -> None:
    """Year 0000 has the form and is not an instant of the calendar the protocol uses."""
    assert not accepted("0000-01-01T00:00:00Z")
    assert accepted("0001-01-01T00:00:00Z")
