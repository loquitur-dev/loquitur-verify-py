"""A verdict is the verdict its reason codes derive (verdict-grounds.md VG-1 to VG-7).

``summary_violated_rules`` holds a verification summary to all seven rules. The rest of this
module holds a registry entry's verdict to the four that bind it.

An entry commits to a verdict and cites the reason codes that ground it, and the two are not
independent: an entry with verdict PASS citing AUTHORIZATION_ISSUER_KEY_REVOKED, or one with
verdict FAIL citing only INTEGRITY_OK, is refused. There is one rule, applied wherever an
entry is read, by the verification path and the narrative renderer alike:

- VG-1: the entry cites at least one code and no code twice;
- VG-2: every cited code is in the catalog;
- VG-3: the verdict equals the verdict the highest cited severity maps to;
- VG-4: a PASS cites at least one info-severity code.

VG-1 and VG-2 are preconditions and stop the check, as verdict-grounds.md section 5 orders; VG-3
and VG-4 are evaluated together. A verdict outside the closed vocabulary breaks VG-3, and is
judged after VG-1 and VG-2 like the rest of that rule: it is reported as out of vocabulary and as
contradicting its grounds, since no such value equals the verdict the grounds derive. The verifier
reads severities from the catalog table generated into schema_contract.py; the renderer passes
the catalog it narrates from.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from .schema_contract import REASON_CODE_SEVERITY

SEVERITY_ORDER = ("info", "warn", "review", "fail")
VERDICT_FOR_SEVERITY = {"info": "PASS", "warn": "WARN", "review": "REVIEW", "fail": "FAIL"}
VERDICTS = frozenset(VERDICT_FOR_SEVERITY.values())
STATUS_FOR_SEVERITY = {"info": "pass", "warn": "warning", "review": "review", "fail": "fail"}
STATUSES = frozenset(STATUS_FOR_SEVERITY.values())
# The severities a reader has to act on, whose codes a summary must give context for (VG-6).
ACTIONABLE_SEVERITIES = frozenset({"review", "fail"})
SUMMARY_RULES = ("VG-1", "VG-2", "VG-3", "VG-4", "VG-5", "VG-6", "VG-7")


@dataclass(frozen=True)
class GroundsViolation:
    """One violation: the rule, the entry field it concerns, a short code and a sentence."""

    rule: str
    field: str
    code: str
    message: str


def verdict_grounds_violations(
    verdict: Any,
    reason_codes: Any,
    severity_of: Callable[[str], str | None] = REASON_CODE_SEVERITY.get,
) -> list[GroundsViolation]:
    """Every way ``verdict`` is not the verdict ``reason_codes`` derive; empty when it is."""
    codes: Sequence[Any] = reason_codes if isinstance(reason_codes, (list, tuple)) else ()
    if not codes:
        return [
            GroundsViolation(
                "VG-1",
                "reason_codes",
                "reason_codes_absent",
                f"verdict {verdict!r} cites no reason code; a verdict must carry the grounds it rests on",
            )
        ]
    # Compared as JSON values, as the summary path compares them: 1, 1.0 and 1e0 are one entry.
    identities = [_json_identity(code) for code in codes]
    cited = Counter(identities)
    repeated = sorted(
        {
            code if isinstance(code, str) else repr(code)
            for code, key in zip(codes, identities, strict=True)
            if cited[key] > 1
        }
    )
    if repeated:
        return [
            GroundsViolation(
                "VG-1",
                "reason_codes",
                "reason_codes_duplicated",
                f"verdict {verdict!r} cites {', '.join(repeated)} more than once",
            )
        ]
    # By position, not keyed by the code: a code that is an array or an object is unhashable, and
    # a mapping keyed by it would raise TypeError where the rule asks for a VG-2 violation.
    severities = [severity_of(code) if isinstance(code, str) else None for code in codes]
    unknown = [repr(code) for code, severity in zip(codes, severities, strict=True) if severity not in SEVERITY_ORDER]
    if unknown:
        return [
            GroundsViolation(
                "VG-2",
                "reason_codes",
                "reason_code_not_in_catalog",
                f"verdict {verdict!r} cites reason codes the catalog does not define: {', '.join(unknown)}",
            )
        ]
    # VG-2 above returned unless every severity is one of SEVERITY_ORDER, so none is None here.
    highest = cast(str, max(severities, key=SEVERITY_ORDER.index))
    violations: list[GroundsViolation] = []
    # The type first: a membership test against a frozenset raises TypeError for an unhashable
    # verdict, and a verdict that is an array or an object is a finding, not a fault.
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        violations.append(
            GroundsViolation(
                "VG-3",
                "verdict",
                "verdict_outside_vocabulary",
                f"verdict {verdict!r} is outside the closed vocabulary {sorted(VERDICTS)}; "
                "an unrecognised verdict is a rejection, not a downgrade",
            )
        )
    if verdict != VERDICT_FOR_SEVERITY[highest]:
        violations.append(
            GroundsViolation(
                "VG-3",
                "verdict",
                "verdict_contradicts_grounds",
                f"verdict {verdict!r} is inconsistent with its reason codes: their highest severity "
                f"{highest!r} derives verdict {VERDICT_FOR_SEVERITY[highest]!r}",
            )
        )
    if verdict == "PASS" and "info" not in severities:
        violations.append(
            GroundsViolation(
                "VG-4",
                "verdict",
                "pass_without_affirmative_ground",
                "verdict 'PASS' cites no info-severity reason code",
            )
        )
    return violations


def _json_identity(value: Any) -> str:
    """A key under which two entries are equal exactly when they are the same JSON value.

    A string is keyed as itself. Anything else is serialized with the members of each object
    sorted by name and every number written as the binary64 value it is read as
    (canonicalization-and-hashing.md: every comparison reads that value), so 1, 1.0 and 1e0 are
    one entry, cited twice, as loquitur-verify-ts finds, as are ``2**60`` and ``float(2**60)``,
    and two objects that differ only in member order are one entry. Booleans are not numbers in
    JSON and are left alone.

    Unlike RFC 8785 canonicalization the key never refuses a value: a lone surrogate, a
    noncharacter, an integer beyond 2^53 - 1 or a deep nesting is keyed by its value too, so two
    such entries that are equal are found equal. NaN and the infinities are keyed as ``nan``,
    ``inf`` and ``-inf``, which no finite number is written as; an integer too large for binary64
    is read, as binary64 rounds it, as the infinity of its sign. The walk is iterative, so no
    value depth reaches the interpreter stack. The keys are the ones loquitur-schemas'
    ``json_value_key`` gives; the verdict path does not import that package, so it is mirrored.
    """
    if isinstance(value, str):
        return "s:" + value
    parts: list[str] = []
    # Each pending item is either a fragment written as it stands or a value still to write.
    pending: list[tuple[bool, Any]] = [(False, value)]
    while pending:
        is_fragment, item = pending.pop()
        if is_fragment:
            parts.append(item)
        elif item is None or isinstance(item, (bool, str)):
            # ensure_ascii escapes a lone surrogate instead of failing to encode it.
            parts.append(json.dumps(item))
        elif isinstance(item, (int, float)):
            parts.append(_binary64_spelling(item))
        elif isinstance(item, (list, tuple)):
            pending.append((True, "]"))
            for index in reversed(range(len(item))):
                pending.append((False, item[index]))
                if index:
                    pending.append((True, ","))
            pending.append((True, "["))
        elif isinstance(item, Mapping):
            members = sorted(
                ((name if isinstance(name, str) else repr(name), member) for name, member in item.items()),
                key=lambda pair: pair[0],
            )
            pending.append((True, "}"))
            for index in reversed(range(len(members))):
                name, member = members[index]
                pending.append((False, member))
                pending.append((True, json.dumps(name) + ":"))
                if index:
                    pending.append((True, ","))
            pending.append((True, "{"))
        else:
            # Not a JSON value at all; keyed by its repr, in a form no JSON value is written as.
            parts.append("?" + json.dumps(repr(item)))
    return "j:" + "".join(parts)


def _binary64_spelling(number: int | float) -> str:
    """How ``_json_identity`` writes ``number``: the binary64 value it is read as."""
    try:
        reading = float(number)
    except OverflowError:
        reading = math.inf if number > 0 else -math.inf
    if math.isfinite(reading) and reading.is_integer():
        # -0.0 is written 0, as RFC 8785 writes it.
        return str(int(reading))
    return repr(reading)


def summary_violated_rules(
    summary: Any,
    severity_of: Callable[[str], str | None] = REASON_CODE_SEVERITY.get,
) -> list[str]:
    """The rules of verdict-grounds.md section 3 that a verification summary violates, in rule order.

    Empty when it satisfies all seven. The evaluation order is section 5's: a violation of VG-1
    (no codes, codes that are not an array, a code cited twice) or of VG-2 (a code the catalog
    does not define) is the only rule reported; VG-3 to VG-7 are then judged together. A
    document that is not a JSON object cites nothing (VG-1). VG-1 is applied here whether or not
    the document was validated against its schema. A status outside the closed vocabulary breaks
    VG-3. Severities come from the protocol catalog the verifier carries.
    """
    if not isinstance(summary, Mapping):
        return ["VG-1"]
    raw_codes = summary.get("reason_codes")
    codes: Sequence[Any] = raw_codes if isinstance(raw_codes, (list, tuple)) else ()
    if not codes:
        return ["VG-1"]
    if len({_json_identity(code) for code in codes}) != len(codes):
        return ["VG-1"]
    severities = [severity_of(code) if isinstance(code, str) else None for code in codes]
    if any(severity not in SEVERITY_ORDER for severity in severities):
        return ["VG-2"]
    # VG-2 above returned unless every severity is one of SEVERITY_ORDER, so none is None here.
    highest = cast(str, max(severities, key=SEVERITY_ORDER.index))
    status = summary.get("status")
    violated: set[str] = set()
    if not isinstance(status, str) or status not in STATUSES or status != STATUS_FOR_SEVERITY[highest]:
        violated.add("VG-3")
    if status == "pass" and "info" not in severities:
        violated.add("VG-4")
    # key_checks is array-or-object-or-null: absent, [], {} and null are all empty, and so is a
    # value of any other type, which the rules read as absent (section 1: they apply to any JSON
    # value, schema-valid or not). A string or true is not a key check.
    key_checks = summary.get("key_checks")
    if status == "pass" and not (isinstance(key_checks, (list, tuple, Mapping)) and key_checks):
        violated.add("VG-5")
    # A reason_context that is not an array is treated as absent: no entry for VG-7, and the
    # obligations of VG-6 stay unmet.
    raw_context = summary.get("reason_context")
    context = raw_context if isinstance(raw_context, (list, tuple)) else ()
    # An entry that is not an object, has no code, or whose code is not a string names no catalog
    # code: None stands for it, so VG-7 counts it and VG-6 is explained by no such entry.
    context_codes = [
        entry["code"] if isinstance(entry, Mapping) and isinstance(entry.get("code"), str) else None
        for entry in context
    ]
    explained = {code for code in context_codes if code is not None}
    if any(
        severity in ACTIONABLE_SEVERITIES and code not in explained
        for code, severity in zip(codes, severities, strict=True)
    ):
        violated.add("VG-6")
    if any(code is None or severity_of(code) not in SEVERITY_ORDER for code in context_codes):
        violated.add("VG-7")
    return [rule for rule in SUMMARY_RULES if rule in violated]


def registry_entry_grounds_errors(entry: Any) -> list[str]:
    """The entry-contract errors (``registry_entry.<field>:<code>``) for its verdict and grounds.

    Only a verdict and reason codes that satisfy the schema are judged here: a verdict outside
    the enum, an empty or duplicated list and a code outside the catalog enum are already
    contract errors of their own, and are not reported twice.
    """
    if not isinstance(entry, dict):
        return []
    verdict, codes = entry.get("verdict"), entry.get("reason_codes")
    # The type first, as verdict_grounds_violations above does. A
    # membership test against a frozenset raises TypeError for an unhashable value, so an entry
    # whose verdict is an array or an object would escape verify_path as INTERNAL_ERROR, exit 3,
    # over refused content. Refused content is a verdict, not a fault.
    if not isinstance(verdict, str) or verdict not in VERDICTS or not isinstance(codes, list) or not codes:
        return []
    if any(not isinstance(code, str) or code not in REASON_CODE_SEVERITY for code in codes):
        return []
    if len(set(codes)) != len(codes):
        return []
    return [f"registry_entry.{v.field}:{v.code}" for v in verdict_grounds_violations(verdict, codes)]
