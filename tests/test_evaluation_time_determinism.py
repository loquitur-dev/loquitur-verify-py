"""The authorization verdict must not depend on the host.

A guard of ``value.endswith("Z")`` does not imply the shape: ``datetime.fromisoformat``
also accepts ``2026-05-10Z``, and for a date-only input it returns a NAIVE datetime.
``.astimezone(UTC)`` then reinterprets that naive value as the host's local time, so the
same signed evidence would evaluate up to ~26 hours apart on two counterparties'
machines: flipping key-expiry checks, and making the published ``evaluation_time``
unreplayable.

Every test here is written to fail if the strict parse is removed: a test that still
passes after the control is removed proves nothing about the control.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time
from loquitur.verify.trust_registry import (
    TrustRegistryVerificationError,
    _parse_instant,
)

# Every one of these ends in "Z", so an endswith("Z") guard admits them all. Each is either
# parsed as naive (and therefore reinterpreted as host-local) or is a format the
# normative schema pattern does not permit.
FORMS_THAT_MUST_BE_REFUSED = [
    pytest.param("2026-05-10Z", id="date-only-parses-naive"),
    pytest.param("20260510T000000Z", id="iso-basic-format"),
    pytest.param("2026-W19-1T00:00:00Z", id="iso-week-date"),
    pytest.param("2026-05-10 00:00:00Z", id="space-separator"),
    pytest.param("2026-05-10T00:00:00.500Z", id="fractional-seconds"),
    pytest.param("2026-05-10T00:00:00z", id="lowercase-designator"),
    pytest.param("2026-05-10T00:00:00+00:00", id="explicit-offset-not-z"),
    pytest.param("2026-05-10T00:00Z", id="minute-precision"),
    pytest.param("2026-13-45T99:99:99Z", id="impossible-calendar-values"),
]


@pytest.mark.parametrize("value", FORMS_THAT_MUST_BE_REFUSED)
def test_only_the_normative_instant_form_is_accepted(value: str) -> None:
    with pytest.raises(TrustRegistryVerificationError):
        _parse_instant(value, field_name="registry_entry.effective_at")


def test_the_normative_form_is_accepted() -> None:
    parsed = _parse_instant("2026-05-10T00:00:00Z", field_name="registry_entry.effective_at")
    assert parsed == datetime(2026, 5, 10, 0, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        "2026-05-10T00:00:00Z",
        "1970-01-01T00:00:00Z",
        "2099-12-31T23:59:59Z",
    ],
)
def test_parsed_instants_are_always_utc_aware(value: str) -> None:
    """The root property: a naive datetime can never leave this function.

    Host-dependence entered through a naive value reaching ``.astimezone``. Asserting
    tz-awareness closes the class, not just the one input that exposed it.
    """
    parsed = _parse_instant(value, field_name="x")
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == UTC.utcoffset(None)


def test_the_parsed_value_matches_the_literal_text_not_a_converted_one() -> None:
    """A zone must be *attached*, never converted.

    If the implementation ever calls ``astimezone`` on a naive value, the parsed hour
    silently shifts by the host's offset and this assertion fails on every machine that
    is not on UTC.
    """
    parsed = _parse_instant("2026-05-10T13:45:07Z", field_name="x")
    assert (parsed.year, parsed.month, parsed.day) == (2026, 5, 10)
    assert (parsed.hour, parsed.minute, parsed.second) == (13, 45, 7)


def test_non_string_input_is_refused_rather_than_coerced() -> None:
    for value in (None, 0, 1747000000, [], {}, True):
        with pytest.raises(TrustRegistryVerificationError):
            _parse_instant(value, field_name="x")


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("2026-02-30T00:00:00Z", id="day-out-of-range"),
        pytest.param("2026-13-01T00:00:00Z", id="month-out-of-range"),
        pytest.param("2026-06-30T23:59:60Z", id="leap-second"),
    ],
)
def test_the_evaluation_time_parser_refuses_calendar_impossibilities_as_its_own_error(value: str) -> None:
    """The operator's evaluation time, held to the same contract as the documents' instants.

    The pattern fixes the shape and not the calendar, so these three reach ``strptime``, and must
    not escape as the bare ``ValueError`` it raises: the command line maps EvaluationTimeError to
    a usage error (exit 64), and a library caller catches it by name.
    """
    with pytest.raises(EvaluationTimeError) as excinfo:
        operator_evaluation_time(value)
    assert type(excinfo.value) is EvaluationTimeError
