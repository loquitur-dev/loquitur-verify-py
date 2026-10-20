"""The evaluation time of an authorization run: the operator's, and only the operator's.

A key is authorized, or not, at an instant, and the choice of instant decides the outcome
(loquitur-protocol ``trust-registry-authorization.md`` §2). The operator supplies it: on the
command line as ``--evaluation-time`` and in this library as ``evaluation_time``, and the report
states it as ``evaluation_time``. It is a calendar instant of the form ``YYYY-MM-DDTHH:MM:SSZ``;
any other value is refused before any evidence is read.

The issuer's own dates (``effective_at``, ``issued_at``, ``anchored_at``) take part in no
authorization decision, and this version of the protocol defines no time-stamp token and no other
source of time. Without an evaluation time, the rows of the evaluation that read it are skipped,
and authorization is not established (the review reason ``evaluation_time_not_provided``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .errors import LoquiturVerifyError

_UTC_INSTANT_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class EvaluationTimeError(ValueError, LoquiturVerifyError):
    """A supplied evaluation time is empty, not a string, or not a calendar instant of the exact form."""


def parse_calendar_instant(value: Any) -> datetime | None:
    """``value`` as a UTC datetime when it is a calendar instant of the exact form, else None.

    The one parser of the verifier's instants. The pattern fixes the shape, in ASCII digits only,
    and strptime the calendar: February 30 and a second 60 match the pattern and are not
    instants. The zone is attached, never converted, so no host's local time enters the result.
    """
    if not isinstance(value, str) or not _UTC_INSTANT_RE.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def operator_evaluation_time(value: Any) -> str:
    """The operator's evaluation time, refused with EvaluationTimeError unless it is a calendar instant.

    Returned as written: it is the value the report states.
    """
    if not isinstance(value, str) or value == "":
        raise EvaluationTimeError("the evaluation time must be a non-empty string of the form YYYY-MM-DDTHH:MM:SSZ")
    if parse_calendar_instant(value) is None:
        raise EvaluationTimeError(
            f"the evaluation time is not a calendar instant of the form YYYY-MM-DDTHH:MM:SSZ: {value!r}"
        )
    return value
