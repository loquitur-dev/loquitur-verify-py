"""Enforce the normative value contract against a document, with no runtime dependency.

Mirroring only the *names* of the closed field set would check presence and absence and
leave `verdict`, `privacy_classification`, `asset_type`, `workflow` and every identifier
pattern unenforced. This verifier, the one a counterparty runs offline and whose verdict
reaches a compliance report, would then authorize documents the public schema rejects.

This module applies the generated tables in `schema_contract.py`. It is a deliberately
small subset of JSON Schema: exactly the keywords the normative schemas use, and
nothing more. The generator refuses to emit a keyword this validator cannot enforce,
so the two cannot drift apart in the direction that loses a constraint.

Semantics follow JSON Schema 2020-12, because the conformance oracle is a real
jsonschema implementation and this must agree with it:
  * `pattern` is an ECMA-262 search in which `$` asserts the absolute end of the string
    (canonicalization-and-hashing.md, input strictness rule 5). It is applied here with
    `re.fullmatch`, not `re.search`. Python's `$` also matches before a final newline, so
    `re.search` would accept `"reg_...\\n"`: OFFLINE_OK, PASS and exit 0 for an entry the
    schema rejects. Anchoring as
    `^X$` is what makes `fullmatch` and the ECMA-262 search agree on where a match starts
    and ends, but not on what `X` matches: `\\d`, `\\w` and `\\s` are Unicode in Python, `.`
    matches `\\r`, and `(?i)` or `a{,3}` is not the same expression in the two dialects. So
    `tools/generate_schema_contract.py` emits a pattern only if it is anchored that way,
    written in a grammar both dialects read alike (printable ASCII: literals, syntax-
    character escapes, positive classes of literals and ranges, groups, alternation and
    repeats), and parsed by Python into only those constructs. For such a pattern the two
    make the same decision on every string, so the equivalence is enforced where the tables
    are made rather than assumed here. An oracle that runs the schemas through Python's `re`
    inherits the same looser `$`; where it does, the rule decides, not the oracle;
  * `type: "integer"` accepts a float with no fractional part;
  * booleans are not integers;
  * a string held to the protocol instant pattern (PROTOCOL_INSTANT_PATTERN) must also be a
    calendar instant, reported as `<path>:calendar`. The pattern admits February 30, April 31,
    February 29 of a common year, second 60 and year 0000; none of them is an instant, and a
    document that carries one is refused wherever it is loaded, not only where the instant is
    evaluated. JSON Schema cannot express the calendar, so the rule is keyed to the pattern
    every protocol schema gives its instants.
"""

from __future__ import annotations

import re
from typing import Any

from .evaluation_time import parse_calendar_instant
from .schema_contract import SCHEMA_CONTRACTS

_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}

# The instant pattern of registry_entry, trust_registry and verification_receipt, character for
# character as the schemas write it.
PROTOCOL_INSTANT_PATTERN = (
    r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)Z$"
)


def is_calendar_instant(value: str) -> bool:
    """True when ``value``, already in the instant pattern, names a real UTC instant.

    ``strptime`` refuses a day past the end of its month, February 29 of a common year, second
    60 and year 0000 (below ``datetime.MINYEAR``).
    """
    return parse_calendar_instant(value) is not None


def _compiled(pattern: str) -> re.Pattern[str]:
    cached = _PATTERN_CACHE.get(pattern)
    if cached is None:
        cached = _PATTERN_CACHE[pattern] = re.compile(pattern)
    return cached


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    if expected == "integer":
        # A bool is an int in Python but never an integer in JSON Schema. A float with
        # no fractional part is an integer in 2020-12, and JCS serializes 1.0 as 1, so
        # rejecting it here would disagree with the canonical form the protocol commits to.
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and value.is_integer()
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    # Unreachable while the generator gates the keyword set; fail closed regardless.
    return False


def _errors_for(node: dict[str, Any], value: Any, path: str) -> list[str]:
    errors: list[str] = []

    expected_type = node.get("type")
    if expected_type is not None:
        types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_type_matches(value, t) for t in types):
            # A wrong type makes every other keyword meaningless; stop here so the
            # caller sees one actionable error rather than a cascade.
            return [f"{path}:type"]

    if "const" in node and value != node["const"]:
        errors.append(f"{path}:const")
    if "enum" in node and value not in node["enum"]:
        errors.append(f"{path}:enum")

    if isinstance(value, str):
        pattern = node.get("pattern")
        if pattern is not None and not _compiled(pattern).fullmatch(value):
            errors.append(f"{path}:pattern")
        elif pattern == PROTOCOL_INSTANT_PATTERN and not is_calendar_instant(value):
            errors.append(f"{path}:calendar")
        min_length = node.get("minLength")
        if min_length is not None and len(value) < min_length:
            errors.append(f"{path}:minLength")
        max_length = node.get("maxLength")
        if max_length is not None and len(value) > max_length:
            errors.append(f"{path}:maxLength")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = node.get("minimum")
        if minimum is not None and value < minimum:
            errors.append(f"{path}:minimum")
        maximum = node.get("maximum")
        if maximum is not None and value > maximum:
            errors.append(f"{path}:maximum")

    if isinstance(value, list):
        min_items = node.get("minItems")
        if min_items is not None and len(value) < min_items:
            errors.append(f"{path}:minItems")
        max_items = node.get("maxItems")
        if max_items is not None and len(value) > max_items:
            errors.append(f"{path}:maxItems")
        if node.get("uniqueItems") is True and _has_duplicates(value):
            errors.append(f"{path}:uniqueItems")
        item_schema = node.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(_errors_for(item_schema, item, f"{path}[{index}]"))

    if isinstance(value, dict):
        min_properties = node.get("minProperties")
        if min_properties is not None and len(value) < min_properties:
            errors.append(f"{path}:minProperties")
        names = node.get("propertyNames")
        if isinstance(names, dict):
            for name in value:
                if _errors_for(names, name, f"{path}.{name}"):
                    errors.append(f"{path}.{name}:propertyNames")
        for name in node.get("required", ()):
            if name not in value:
                errors.append(f"{path}.{name}:required")
        properties = node.get("properties") or {}
        for name, sub_schema in properties.items():
            if name in value:
                errors.extend(_errors_for(sub_schema, value[name], f"{path}.{name}"))
        additional = node.get("additionalProperties")
        if additional is False:
            for name in sorted(set(value) - set(properties)):
                errors.append(f"{path}.{name}:additionalProperties")
        elif isinstance(additional, dict):
            for name in sorted(set(value) - set(properties)):
                errors.extend(_errors_for(additional, value[name], f"{path}.{name}"))

    if "oneOf" in node:
        # Sibling keywords still apply: an early return here would be a fail-open.
        matches = sum(1 for branch in node["oneOf"] if not _errors_for(branch, value, path))
        if matches != 1:
            errors.append(f"{path}:oneOf")

    return errors


def _json_key(value: Any) -> Any:
    """A hashable key equal for two values exactly when JSON Schema calls them equal.

    Numbers compare by value (1 and 1.0 are equal), a boolean is never a number, arrays compare
    in order and objects by their members. The depth is bounded by input strictness rule 6, so
    the recursion is too.
    """
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, (int, float)):
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, list):
        return ("array", tuple(_json_key(item) for item in value))
    if isinstance(value, dict):
        return ("object", frozenset((name, _json_key(item)) for name, item in value.items()))
    return ("other", id(value))


def _has_duplicates(items: list[Any]) -> bool:
    """True when two items are equal. Linear in the number of items: a set of keys, not a scan."""
    seen: set[Any] = set()
    for item in items:
        key = _json_key(item)
        if key in seen:
            return True
        seen.add(key)
    return False


def contract_errors(contract_name: str, document: Any) -> list[str]:
    """Return every contract violation in `document`. Empty list means conformant.

    Raises KeyError for an unknown contract name rather than returning "no errors":
    a validator that silently passes an unrecognized document type is a fail-open.
    """
    node = SCHEMA_CONTRACTS[contract_name]
    return sorted(_errors_for(node, document, contract_name))
