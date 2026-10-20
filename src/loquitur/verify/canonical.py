"""Deterministic JSON canonicalization helpers for the public verifier.

This module intentionally contains only verifier-safe primitives. It must not
import modules of an unpublished repository.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from os import PathLike
from typing import Any

import rfc8785

from .errors import LoquiturVerifyError

_JS_SAFE_INT_MAX = 9_007_199_254_740_991


class CanonicalizationError(ValueError, LoquiturVerifyError):
    """Raised when an object cannot be encoded as deterministic JSON."""


class JsonLoadError(ValueError, LoquiturVerifyError):
    """Raised when a JSON document cannot be parsed."""


def _prepare_for_jcs(value: Any, *, path: str = "$") -> Any:
    if value is None:
        return None
    if type(value) is bool:
        return value
    if isinstance(value, str):
        # Refused here rather than left to rfc8785, which reports a lone surrogate in a
        # value as its own CanonicalizationError but in a member NAME as UnicodeEncodeError
        # from its UTF-16 key sort: an exception no caller catches, and exit 3.
        if _LONE_SURROGATE_RE.search(value):
            raise CanonicalizationError(f"{path}: lone surrogate is not valid Unicode")
        if _NONCHARACTER_RE.search(value):
            raise CanonicalizationError(f"{path}: noncharacter is not admitted (input strictness rule 9)")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > _JS_SAFE_INT_MAX:
            raise CanonicalizationError(f"{path}: integer outside RFC8785/ECMAScript safe range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"{path}: non-finite float not allowed")
        if value.is_integer() and abs(value) > _JS_SAFE_INT_MAX:
            raise CanonicalizationError(f"{path}: integer-valued number outside RFC8785/ECMAScript safe range")
        if value == 0.0:
            return 0.0
        return float(value)
    if isinstance(value, (list, tuple)):
        return [_prepare_for_jcs(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: JSON object keys must be strings")
            if _LONE_SURROGATE_RE.search(key):
                raise CanonicalizationError(f"{path}: member name with a lone surrogate is not valid Unicode")
            if _NONCHARACTER_RE.search(key):
                raise CanonicalizationError(f"{path}: member name with a noncharacter is not admitted")
            out[key] = _prepare_for_jcs(item, path=f"{path}.{key}")
        return out
    raise CanonicalizationError(f"{path}: unsupported JSON value type: {type(value).__name__}")


def _value_nesting_exceeds(value: Any, limit: int) -> bool:
    """True when an in-memory value nests containers deeper than ``limit``. Never recurses.

    The depth is the one input strictness rule 6 defines for a document: a scalar has depth 0
    and a list, tuple or dict one more than its deepest member. The walk stops at ``limit + 1``,
    so a value that contains itself is answered too.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            children: Any = item.values()
        elif isinstance(item, (list, tuple)):
            children = item
        else:
            continue
        if depth + 1 > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC8785/JCS canonical JSON bytes for a JSON-compatible value.

    Every refusal of the value is a CanonicalizationError, a UnicodeError included, so a
    caller that catches CanonicalizationError, as every caller here does, catches every
    refusal.

    A value nested deeper than MAX_JSON_NESTING_DEPTH is refused before any recursive step
    runs. The bound is not the interpreter's: the preparation walk and rfc8785 recurse per
    level, so a recursion-limit bound would be set by how many frames a level costs, which
    differs between Python 3.11 and 3.12, where comprehensions are inlined.

    A RecursionError is therefore never a property of the value: every value that reaches the
    recursive steps is one the protocol admits, and only a host whose recursion limit was
    lowered below what 64 levels cost can raise it. It propagates as itself, a fault of the
    host, which the command line reports as an internal error with exit 3, and never becomes
    ``nesting_too_deep``, a verdict on a value that keeps the rule.
    """

    if _value_nesting_exceeds(value, MAX_JSON_NESTING_DEPTH):
        raise CanonicalizationError("canonical_json_failed:nesting_too_deep")
    try:
        return rfc8785.dumps(_prepare_for_jcs(value))
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError(f"canonical_json_failed:{exc}") from exc
    except UnicodeError as exc:
        raise CanonicalizationError(f"canonical_json_failed:{type(exc).__name__}") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    return sha256_hex(canonical_json_bytes(value))


def file_sha256(path: str | PathLike[str]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class _DuplicateJsonKeyError(Exception):
    """Internal marker: duplicate member name found during strict JSON load."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _object_pairs_reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateJsonKeyError(key)
        obj[key] = value
    return obj


def _reject_json_constant(name: str) -> Any:
    raise ValueError(f"non_finite_json_number:{name}")


# The deepest JSON document any member or host document may carry. A scalar has depth 0 and
# an array or object has depth 1 + the depth of its deepest child, so 64 admits every
# object the protocol defines with a wide margin (the deepest in the corpus, the fixtures
# and the schemas is 8). The limit is not whatever the interpreter stack allows: the json
# decoder gives up near 1000 levels, rfc8785 near 500, and a host that lowers
# sys.getrecursionlimit moves both, so the same valid bundle would PASS, FAIL or crash with
# exit 3 depending on where it ran.
MAX_JSON_NESTING_DEPTH = 64

# Tokens that can change the nesting depth: a string, which is skipped whole so that brackets
# inside it do not count, or a single bracket. The closing quote is optional and captured: the
# string alternative always matches at its first attempt, so an unterminated string is one token
# that runs to the end of the text, found in linear time, instead of a failed match retried from
# every later quote (which would make the scan quadratic).
_DEPTH_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*(")?|[\[\]{}]', re.DOTALL)
_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")
# Input strictness rule 9 (RFC 7493 section 2.1): the 66 noncharacters, U+FDD0 to U+FDEF and
# every code point whose low 16 bits are FFFE or FFFF, written literally or as an escape. The
# class is built from code points so the source holds no literal noncharacter.
_NONCHARACTER_RE = re.compile(
    "["
    + re.escape(chr(0xFDD0))
    + "-"
    + re.escape(chr(0xFDEF))
    + "".join(re.escape(chr((plane << 16) | low)) for plane in range(17) for low in (0xFFFE, 0xFFFF))
    + "]"
)


def _parse_float_exact(spelling: str) -> float:
    """Read a number token with a fraction or an exponent, refusing excess precision.

    canonicalization-and-hashing.md, "No excess precision": a number is valid only when the
    decimal value it spells equals the decimal value of the RFC 8785 serialization of the
    binary64 value nearest to it. Python's repr of a float and ECMAScript's Number-to-String
    give the same shortest round-trip digits, so the comparison is between two exact decimals:
    2.0000000000000001 (read as 2) and 4.9e-325 (read as 0) are refused, 1E2 and 0.1 are not,
    and -0.0 equals 0. A token that overflows to infinity is left to rule 3.

    The two decimals are read from the characters alone (_spelled_decimal), never through
    decimal.Decimal: an exponent such as 0e99999999999999999999 or 1e-99999999999999999999 is
    beyond Decimal's range, and the first spells exactly zero (valid) while the second spells a
    non-zero value read as 0 (excess precision).
    """
    value = float(spelling)
    if math.isfinite(value) and _spelled_decimal(spelling) != _spelled_decimal(repr(value)):
        raise ValueError("json_excess_precision")
    return value


def _spelled_decimal(spelling: str) -> tuple[bool, str, int | None] | None:
    """The decimal value a number spelling names, read from its characters with exact integers.

    None for zero, whatever its sign or exponent; otherwise (negative, digits, exponent) with
    no leading or trailing zero in ``digits``, so two spellings name the same value exactly when
    their results are equal. Accepts the JSON number grammar and Python's float repr. An
    exponent too long for int() (more than _MAX_EXPONENT_DIGITS digits) is None: no finite,
    non-zero binary64 value is spelled with one, so the comparison fails as it should.

    The exponent's sign and leading zeros are taken off before its digits are counted or
    converted, so int() only ever reads the significant digits: 1e followed by 5000 zeros and
    a 1 names 10, and int() of all 5001 digits would be refused by the interpreter's limit on
    decimal digits (4300 by default) although the value is tiny.
    """
    rest = spelling
    negative = rest.startswith("-")
    if negative:
        rest = rest[1:]
    exponent_text = ""
    mark = max(rest.find("e"), rest.find("E"))
    if mark >= 0:
        exponent_text = rest[mark + 1 :]
        rest = rest[:mark]
    whole, _, fraction = rest.partition(".")
    digits = whole + fraction
    stripped = digits.rstrip("0")
    trailing = len(digits) - len(stripped)
    stripped = stripped.lstrip("0")
    if not stripped:
        return None
    exponent_negative = exponent_text.startswith("-")
    exponent_digits = exponent_text.lstrip("+-").lstrip("0")
    if len(exponent_digits) > _MAX_EXPONENT_DIGITS:
        return (negative, stripped, None)
    exponent_value = int(exponent_digits or "0")
    if exponent_negative:
        exponent_value = -exponent_value
    exponent = exponent_value - len(fraction) + trailing
    return (negative, stripped, exponent)


def _parse_int_bounded(spelling: str) -> int:
    """Read an integer token, refusing one too long for the safe range before int() runs.

    The JSON grammar admits no leading zero, so an integer token with more than sixteen digits
    is at least 10^16, beyond 2^53 - 1, and breaks input strictness rule 2. Refusing it here
    gives the rule's own refusal for every length: int() of more than 4300 decimal digits is
    refused by the interpreter with a message that names its own limit, not the rule.
    """
    if len(spelling.lstrip("-")) > _JS_SAFE_INT_DIGITS:
        raise ValueError("json_integer_outside_safe_range")
    return int(spelling)


# 2^53 - 1 has sixteen decimal digits.
_JS_SAFE_INT_DIGITS = 16

# Longer than any exponent a finite, non-zero binary64 needs once the fraction's length is
# taken off, and well inside int()'s default limit on decimal digits (4300).
_MAX_EXPONENT_DIGITS = 1000


def _nesting_exceeds(text: str, limit: int) -> bool:
    """True when brackets outside strings nest deeper than ``limit``. Never recurses; linear.

    An empty array or object has depth 1 (canonicalization-and-hashing.md, input strictness
    rule 6), which is what counting brackets gives. An unterminated string ends the scan with
    False: the document is not JSON, and the parser reports it as a parse error, not a depth
    error.
    """
    if text.count("[") + text.count("{") <= limit:
        return False
    depth = 0
    for match in _DEPTH_TOKEN_RE.finditer(text):
        token = match.group()
        if token in "[{":
            depth += 1
            if depth > limit:
                return True
        elif token in "]}":
            depth -= 1
        elif match.group(1) is None:
            return False
    return False


def _strictness_violation(value: Any) -> str | None:
    """Input strictness rules 2 to 4 over a whole parsed document, keys included.

    Iterative, so no document shape reaches the interpreter stack. Rule 9 (noncharacters) is
    checked with rule 4, in values and member names. Rule 2 is by value: an
    integer beyond 2^53 - 1 is invalid whether it is spelled 9007199254740993, 1e16 or
    9007199254740992.0. Rule 3 covers the overflow the json decoder turns into infinity
    (1e400), which parse_constant never sees. Rule 4 covers member names as well as
    values: a lone surrogate in a key never reaches rfc8785, where it would escape as
    UnicodeEncodeError.
    """
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, bool) or item is None:
            continue
        if isinstance(item, str):
            if _LONE_SURROGATE_RE.search(item):
                return "json_lone_surrogate"
            if _NONCHARACTER_RE.search(item):
                return "json_noncharacter"
        elif isinstance(item, int):
            if abs(item) > _JS_SAFE_INT_MAX:
                return "json_integer_outside_safe_range"
        elif isinstance(item, float):
            if not math.isfinite(item):
                return "non_finite_json_number:overflow"
            if item.is_integer() and abs(item) > _JS_SAFE_INT_MAX:
                return "json_integer_outside_safe_range"
        elif isinstance(item, dict):
            for key, child in item.items():
                if _LONE_SURROGATE_RE.search(key):
                    return "json_lone_surrogate"
                if _NONCHARACTER_RE.search(key):
                    return "json_noncharacter"
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return None


def loads_json_bytes(data: bytes, *, name: str = "json") -> Any:
    """Strict JSON load of an untrusted document.

    Refused, each as JsonLoadError naming the document:
      * bytes that are not UTF-8 (a BOM reaches the parser and is refused there);
      * duplicate member names, which make the committed value ambiguous across parsers
        (last-wins or first-wins; I-JSON, RFC 7493 section 2.3);
      * nesting deeper than MAX_JSON_NESTING_DEPTH, found by a scan that does not recurse;
      * NaN and +/-Infinity, spelled as constants or reached by overflow such as 1e400;
      * any number whose value is an integer of magnitude above 2^53 - 1;
      * a lone surrogate in any string or member name;
      * a noncharacter in any string or member name (rule 9);
      * a number that spells more precision than its binary64 value holds (2.0000000000000001,
        4.9e-325, 9007199254740992.5), refused rather than rounded.

    These are canonicalization-and-hashing.md input strictness rules 2 to 4 and 9 and the
    excess-precision rule. They apply to the whole document at load, not only to the part a later step hashes: a value
    outside the P1 projection is still part of the document the manifest commits to.

    The decoder runs only on a document the scan admits, so a RecursionError from it is a
    fault of the host, never of the document, and propagates as itself rather than as
    ``json_nesting_too_deep``: under Python 3.11 a lowered recursion limit can stop a
    64-level document, and from 3.12 the C decoder ignores the limit.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonLoadError(f"invalid_json_encoding:{name}") from exc
    if _nesting_exceeds(text, MAX_JSON_NESTING_DEPTH):
        raise JsonLoadError(f"json_nesting_too_deep:{name}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs_reject_duplicates,
            parse_constant=_reject_json_constant,
            parse_float=_parse_float_exact,
            parse_int=_parse_int_bounded,
        )
    except _DuplicateJsonKeyError as exc:
        raise JsonLoadError(f"duplicate_json_key:{name}:{exc.key}") from exc
    except json.JSONDecodeError as exc:
        raise JsonLoadError(f"invalid_json:{name}:{exc.msg}") from exc
    except ValueError as exc:
        raise JsonLoadError(f"{exc}:{name}") from exc
    violation = _strictness_violation(value)
    if violation is not None:
        raise JsonLoadError(f"{violation}:{name}")
    return value
