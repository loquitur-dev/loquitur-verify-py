"""Generate the value-level contract tables that loquitur-verify enforces.

Why generated rather than hand-written
--------------------------------------
A hand-written mirror of the closed field set of registry_entry.schema.json carries
the field names and easily loses `required`, every `enum` and every `pattern`: the
verifier would then authorize entries the normative contract rejects, such as a
registry entry carrying `verdict: "BANANA"` and `privacy_classification: "SECRET"`.

A hand-maintained mirror of a contract will drift; that is what a mirror does. So the
tables are generated from the schema and checked in, and a test regenerates them and
compares. This package imports nothing from loquitur-schemas at runtime: the
dependency is at build time only, which is what the standalone constraint requires.

Generation is fail-closed: any schema keyword this generator does not understand
raises instead of being skipped. A constraint silently dropped during generation would
let the verifier accept what the schema refuses.

Run: python tools/generate_schema_contract.py [--check]
"""

from __future__ import annotations

import argparse
import json
import pprint
import sys
import warnings
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parents[1]
SCHEMA_DIR = HERE.parent / "loquitur-schemas/src/loquitur/schemas/data"
TARGET = HERE / "src/loquitur/verify/schema_contract.py"

CONTRACTS = ("registry_entry", "trust_registry", "verification_receipt")
# The schema a registered vocabulary document satisfies (verification-vocabularies.md section 6),
# by the name its contract table carries and its path under SCHEMA_DIR. A vocabulary an operator
# supplies is held to it before any evidence is read.
VOCABULARY_CONTRACT = ("registered_vocabulary", "registered_vocabularies/schema.json")
# The reason-code catalog the registry entry's `reason_codes` enum is drawn from. Its severities
# decide the verdict an entry's grounds derive (verdict-grounds.md VG-3), which JSON Schema
# cannot express, so the code-to-severity table is generated beside the contracts.
CATALOG = SCHEMA_DIR / "reason_codes_catalog/v2.0/catalog.json"
SEVERITIES = ("info", "warn", "review", "fail")

# Keywords that constrain a value and are therefore extracted.
ENFORCED = {
    "type",
    "enum",
    "const",
    "pattern",
    "minLength",
    "minItems",
    "uniqueItems",
    "items",
    "properties",
    "required",
    "additionalProperties",
    "oneOf",
    "minimum",
    "maximum",
    "maxLength",
    "maxItems",
    "minProperties",
    "propertyNames",
    "$ref",
}
# Keywords that carry no validation meaning. `$defs` holds the definitions a `$ref` names; each is
# extracted where it is referenced, so the table carries no reference.
ANNOTATIONS = {
    "$id",
    "$schema",
    "$defs",
    "title",
    "description",
    "example",
    "examples",
    "deprecated",
    "default",
    "$comment",
}


class UnsupportedSchemaKeyword(RuntimeError):
    """Raised when the schema uses a keyword the generator cannot faithfully express."""


def require_whole_string_anchoring(pattern: str, *, path: str) -> None:
    """Refuse a `pattern` that `contract_validation` could not enforce with `re.fullmatch`.

    JSON Schema applies `pattern` as an unanchored ECMA-262 search in which `$` asserts the
    absolute end of the string (canonicalization-and-hashing.md, input strictness rule 5).
    Python's `re.search` lets `$` match before a final newline as well, so applying the
    schemas' patterns with it would accept `"reg_...\\n"`, which the schema, loquitur-schemas'
    validator and the TypeScript verifier all reject. The validator therefore uses
    `re.fullmatch`, and that cannot reproduce the ECMA-262 decision unless the pattern has
    the form `^X$`: one `^` first, one `$` last, no alternation at the top level (`^a|b$` is
    `(^a)|(b$)`), no other anchor inside `X`, and no inline flag that changes what `^` or
    `$` mean. Every pattern the schemas carry has that form. A future one that does not
    must stop generation here, where someone can decide how to enforce it, rather than be
    enforced under a different reading.

    The form is necessary, not sufficient. It settles where the match may start and end;
    it says nothing about what `X` matches, and there Python and ECMA-262 also part company
    (`\\d` and `\\w` are Unicode in Python, `.` matches `\\r`, `(?i)` is Python-only syntax).
    `require_ecma_equivalent_pattern` applies this check together with the two that close
    those differences, and it is the one generation calls.

    The decision is made with the standard library's own regular-expression parser, on
    the structure the engine will execute rather than on the spelling of the string.
    """
    from re import _constants, _parser  # stdlib internals; acceptable in build-time tooling

    refusal = (
        f"{path}: pattern {pattern!r} is not anchored to the whole string as ^...$ with no "
        "top-level alternation, so re.fullmatch would not reproduce the ECMA-262 decision "
        "the schema defines. Extend the generator and the validator together."
    )
    try:
        parsed = _parser.parse(pattern)
    except Exception as exc:  # a pattern Python cannot parse cannot be enforced either
        raise UnsupportedSchemaKeyword(f"{refusal} ({exc})") from exc
    if parsed.state.flags & (_constants.SRE_FLAG_MULTILINE | _constants.SRE_FLAG_VERBOSE):
        raise UnsupportedSchemaKeyword(refusal)
    items = list(parsed)
    if (
        len(items) < 2
        or items[0] != (_constants.AT, _constants.AT_BEGINNING)
        or items[-1] != (_constants.AT, _constants.AT_END)
    ):
        raise UnsupportedSchemaKeyword(refusal)

    def has_anchor(node: Any) -> bool:
        if isinstance(node, _parser.SubPattern):
            node = list(node)
        if isinstance(node, (list, tuple)):
            if len(node) == 2 and node[0] is _constants.AT:
                return True
            return any(has_anchor(child) for child in node)
        return False

    if has_anchor(items[1:-1]):
        raise UnsupportedSchemaKeyword(refusal)


# The characters that are syntax outside a bracket class, in both dialects. Outside a class
# each of them is only admitted escaped (`\\.`), except `^` first, `$` last and the grouping,
# alternation and quantifier syntax the reader below consumes itself.
_SYNTAX_CHARACTERS = frozenset("^$\\.*+?()[]{}|")
# The escapes both dialects read as the literal character, with or without the `u` flag:
# ECMA-262's IdentityEscape under `u` is a SyntaxCharacter or `/`, and inside a class `-`.
_ESCAPABLE_OUTSIDE_CLASS = frozenset("^$\\.*+?()[]{}|/")
_ESCAPABLE_INSIDE_CLASS = _ESCAPABLE_OUTSIDE_CLASS | {"-"}


def require_portable_pattern_spelling(pattern: str, *, path: str) -> None:
    """Refuse a `pattern` whose spelling Python's `re` and ECMA-262 could read differently.

    The same string is not always the same expression in the two dialects. `a{,3}` is a
    repeat in Python and the literal text `a{,3}` in ECMA-262 without the `u` flag; `\\d` is
    any Unicode decimal digit in Python and `[0-9]` in ECMA-262; `(?P<n>...)`, `(?#...)`,
    `(?i)`, `a++` and `(?>...)` are Python syntax that ECMA-262 refuses to compile; `\\-`
    outside a class and an unescaped `]` or `}` are errors under `u` and literals without
    it; a character outside the Basic Multilingual Plane is one character to Python and two
    code units to ECMA-262 without `u`, which changes what a following quantifier repeats
    and what a negated class accepts.

    So a pattern is admitted only if it is written in a small grammar that both dialects,
    with and without `u`, read as the same expression:

      * printable ASCII only (U+0020 to U+007E);
      * `^` as the first character and `$` as the last, nowhere else unescaped;
      * a literal character, or a backslash followed by one of ``^$\\.*+?()[]{}|/``;
      * a positive bracket class `[...]` of such characters (plus `\\-`) and ranges `a-z`,
        with an unescaped `-` only first or last, no `[` inside, no `^` first, not empty,
        and none of the doubled punctuators `--`, `&&`, `||`, `~~`;
      * a capturing group `(...)` or a non-capturing group `(?:...)`;
      * `|`;
      * a quantifier `*`, `+`, `?`, `{n}`, `{n,}` or `{n,m}`, optionally followed by `?`,
        and only after a character, a class or a group.

    `.`, class escapes (`\\d`, `\\w`, `\\s` and their negations), `\\b`, back-references,
    look-arounds, named groups, inline flags, possessive repeats and every other escape
    fall outside it and stop generation. `require_portable_pattern_structure` then checks
    the same pattern on the tree Python's parser builds, so a spelling this reader
    misjudged still has to produce an admitted structure.
    """

    def refuse(position: int, why: str) -> UnsupportedSchemaKeyword:
        return UnsupportedSchemaKeyword(
            f"{path}: pattern {pattern!r} at offset {position}: {why}. Python's re and ECMA-262 "
            "are only known to read the same expression in the portable grammar "
            "require_portable_pattern_spelling documents; extend the generator and the "
            "validator together."
        )

    for position, character in enumerate(pattern):
        if not " " <= character <= "~":
            raise refuse(position, f"{character!r} is not printable ASCII")
    if len(pattern) < 2 or pattern[0] != "^" or pattern[-1] != "$":
        raise refuse(0, "the pattern is not written as ^...$")
    # An escape in the body that would consume the final `$` is refused below, where an
    # escape must end before `body_end`.

    body_end = len(pattern) - 1
    position = 1
    # Whether the previous token can carry a quantifier: a character, a class or a group.
    quantifiable = False
    depth = 0

    def read_class(start: int) -> int:
        """Return the offset just after the class that opens at `start`."""
        index = start + 1
        if index < body_end and pattern[index] in "^]":
            raise refuse(index, "a negated or empty bracket class")
        first = True
        while True:
            if index >= body_end:
                raise refuse(start, "an unterminated bracket class")
            character = pattern[index]
            if character == "]":
                return index + 1
            if pattern[index : index + 2] in {"--", "&&", "||", "~~"}:
                raise refuse(index, "a doubled punctuator inside a bracket class")
            if character == "[":
                raise refuse(index, "'[' inside a bracket class")
            if character == "-":
                if not (first or pattern[index + 1] == "]"):
                    raise refuse(index, "an unescaped '-' that is neither first, last nor a range")
                index += 1
                first = False
                continue
            index = read_class_atom(index)
            if pattern[index] == "-" and pattern[index + 1] != "]":
                if pattern[index + 1] == "-":
                    raise refuse(index + 1, "an unescaped '-' as the end of a range")
                index = read_class_atom(index + 1)
                if pattern[index] == "-" and pattern[index + 1] != "]":
                    raise refuse(index, "a range followed by '-'")
            first = False

    def read_class_atom(index: int) -> int:
        character = pattern[index]
        if character == "\\":
            if index + 1 >= body_end or pattern[index + 1] not in _ESCAPABLE_INSIDE_CLASS:
                raise refuse(index, "an escape inside a bracket class other than a syntax character")
            return index + 2
        if character in "[]":
            raise refuse(index, f"an unescaped {character!r} as a class member")
        return index + 1

    while position < body_end:
        character = pattern[position]
        if character == "\\":
            if position + 1 >= body_end or pattern[position + 1] not in _ESCAPABLE_OUTSIDE_CLASS:
                raise refuse(position, "an escape other than a syntax character or '/'")
            position += 2
            quantifiable = True
        elif character == "[":
            position = read_class(position)
            quantifiable = True
        elif character == "(":
            if pattern.startswith("(?", position):
                if not pattern.startswith("(?:", position):
                    raise refuse(position, "a group other than (...) or (?:...)")
                position += 3
            else:
                position += 1
            depth += 1
            quantifiable = False
        elif character == ")":
            if depth == 0:
                raise refuse(position, "an unbalanced ')'")
            depth -= 1
            position += 1
            quantifiable = True
        elif character == "|":
            position += 1
            quantifiable = False
        elif character in "*+?{":
            if not quantifiable:
                raise refuse(position, "a quantifier with nothing to repeat")
            if character == "{":
                close = pattern.find("}", position)
                bounds = pattern[position + 1 : close] if close != -1 else ""
                low, comma, high = bounds.partition(",")
                if (
                    close == -1
                    or close >= body_end
                    or not low.isdigit()
                    or not low.isascii()
                    or (high and not (high.isdigit() and high.isascii()))
                ):
                    raise refuse(position, "a brace that is not a quantifier {n}, {n,} or {n,m}")
                position = close + 1
            else:
                position += 1
            if position < body_end and pattern[position] == "?":
                position += 1
            if position < body_end and pattern[position] in "*+?{":
                raise refuse(position, "a quantifier applied to a quantifier")
            quantifiable = False
        elif character in _SYNTAX_CHARACTERS:
            raise refuse(position, f"an unescaped {character!r}")
        else:
            position += 1
            quantifiable = True
    if depth != 0:
        raise refuse(body_end, "an unbalanced '('")


def require_portable_pattern_structure(pattern: str, *, path: str) -> None:
    """Refuse a `pattern` whose parsed structure falls outside what both dialects decide alike.

    The tree comes from the standard library's own parser, so this looks at what `re` will
    execute, independently of how `require_portable_pattern_spelling` read the string. Below
    the leading `^` and trailing `$` it admits only:

      * LITERAL, for a printable ASCII character;
      * IN, a positive class whose members are LITERAL or RANGE over printable ASCII;
      * MAX_REPEAT and MIN_REPEAT (greedy and lazy repeats);
      * SUBPATTERN, a group that adds and removes no flag;
      * BRANCH, an alternation, which between the anchors can only come from a group.

    It refuses everything else, among them ANY (`.`, which in Python also matches `\\r`,
    U+2028 and U+2029 where ECMA-262 does not), CATEGORY (`\\d`, `\\w`, `\\s`, Unicode in
    Python and ASCII or a different set in ECMA-262), NEGATE and NOT_LITERAL (a negated
    class, which counts code points in Python and code units in ECMA-262 without `u`),
    GROUPREF, ASSERT, ASSERT_NOT, ATOMIC_GROUP and POSSESSIVE_REPEAT. The global flags must
    be exactly the default for a str pattern, UNICODE, so IGNORECASE, ASCII, LOCALE, DOTALL,
    MULTILINE and VERBOSE, set inline, are refused.

    For a pattern that passes this and the anchoring and spelling checks, every construct
    left matches a fixed set of ASCII characters or composes such sets, both engines
    backtrack through every alternative, and none of those constructs can see captures,
    so `re.fullmatch` and an ECMA-262 search for `^X$` accept the same strings.
    """
    from re import _constants, _parser  # stdlib internals; acceptable in build-time tooling

    def refuse(why: str) -> UnsupportedSchemaKeyword:
        return UnsupportedSchemaKeyword(
            f"{path}: pattern {pattern!r} parses to {why}, which Python's re and ECMA-262 do not "
            "decide alike on every string. Extend the generator and the validator together."
        )

    try:
        with warnings.catch_warnings():
            # `[a&&b]` and its kind parse with a FutureWarning about set operations; the
            # spelling check refuses them, so the warning would only be noise here.
            warnings.simplefilter("ignore", FutureWarning)
            parsed = _parser.parse(pattern)
    except Exception as exc:
        raise UnsupportedSchemaKeyword(f"{path}: pattern {pattern!r} does not parse ({exc})") from exc
    if parsed.state.flags != _constants.SRE_FLAG_UNICODE:
        raise refuse(f"global flags {parsed.state.flags:#x} rather than UNICODE alone")
    items = list(parsed)
    if (
        len(items) < 2
        or items[0] != (_constants.AT, _constants.AT_BEGINNING)
        or items[-1] != (_constants.AT, _constants.AT_END)
    ):
        raise refuse("something other than ^...$ at the top level")

    def printable(code: Any, what: str) -> None:
        if not isinstance(code, int) or not 0x20 <= code <= 0x7E:
            raise refuse(f"{what} {code!r} outside printable ASCII")

    def walk(sequence: Any) -> None:
        for op, argument in sequence:
            if op is _constants.LITERAL:
                printable(argument, "LITERAL")
            elif op is _constants.IN:
                for member_op, member in argument:
                    if member_op is _constants.LITERAL:
                        printable(member, "a class LITERAL")
                    elif member_op is _constants.RANGE:
                        printable(member[0], "a RANGE start")
                        printable(member[1], "a RANGE end")
                    else:
                        raise refuse(f"a class member {member_op}")
            elif op in (_constants.MAX_REPEAT, _constants.MIN_REPEAT):
                _low, _high, body = argument
                walk(body)
            elif op is _constants.SUBPATTERN:
                _group, add_flags, del_flags, body = argument
                if add_flags or del_flags:
                    raise refuse("a group that changes flags")
                walk(body)
            elif op is _constants.BRANCH:
                # Python's parser keeps no node for a non-capturing group, so the BRANCH of
                # `^(?:a|b)$` sits between the anchors at the top level. An alternation
                # written at the top level, `^a|b$`, instead parses to one BRANCH that
                # contains both anchors, and the anchoring check above has refused it.
                _unused, alternatives = argument
                for alternative in alternatives:
                    walk(alternative)
            else:
                raise refuse(str(op))

    walk(items[1:-1])


def require_ecma_equivalent_pattern(pattern: str, *, path: str) -> None:
    """Refuse a `pattern` unless `re.fullmatch` decides it as the ECMA-262 search does.

    Three checks, each fail-closed, and a pattern must pass all of them: the spelling both
    dialects read as the same expression (`require_portable_pattern_spelling`), the
    whole-string anchoring (`require_whole_string_anchoring`) and the structure both
    engines decide alike (`require_portable_pattern_structure`).
    """
    # The spelling is read first: it needs no parse, so a pattern outside the portable
    # grammar is refused before Python's parser can warn about, or misread, its syntax.
    require_portable_pattern_spelling(pattern, path=path)
    require_whole_string_anchoring(pattern, path=path)
    require_portable_pattern_structure(pattern, path=path)


def extract(node: Any, *, path: str, root: Any = None) -> Any:
    """Reduce a schema node to the constraints the verifier enforces.

    A `$ref` names a definition of the same document, `#/$defs/<name>`, and stands alone in its
    node; the definition is extracted in its place. Any other reference is refused.
    """
    if not isinstance(node, dict):
        raise UnsupportedSchemaKeyword(f"{path}: expected an object schema node")
    root = node if root is None else root
    if "$ref" in node:
        reference = node["$ref"]
        if set(node) - ANNOTATIONS != {"$ref"} or not isinstance(reference, str):
            raise UnsupportedSchemaKeyword(f"{path}: a $ref stands alone in its node")
        prefix = "#/$defs/"
        definitions = root.get("$defs") if isinstance(root, dict) else None
        name = reference[len(prefix) :] if reference.startswith(prefix) else None
        if name is None or not isinstance(definitions, dict) or name not in definitions:
            raise UnsupportedSchemaKeyword(f"{path}: $ref {reference!r} names no definition of this document")
        return extract(definitions[name], path=f"{path}<{name}>", root=root)

    unknown = set(node) - ENFORCED - ANNOTATIONS
    if unknown:
        raise UnsupportedSchemaKeyword(
            f"{path}: unsupported keyword(s) {sorted(unknown)}. Extend the generator and "
            "the validator together: silently dropping a constraint is the defect this "
            "generator exists to prevent."
        )

    out: dict[str, Any] = {}
    for key in (
        "type",
        "enum",
        "const",
        "pattern",
        "minLength",
        "minItems",
        "uniqueItems",
        "required",
        "additionalProperties",
        "minimum",
        "maximum",
        "maxLength",
        "maxItems",
        "minProperties",
    ):
        if key in node:
            out[key] = node[key]
    if "pattern" in out:
        require_ecma_equivalent_pattern(out["pattern"], path=f"{path}.pattern")

    if isinstance(node.get("additionalProperties"), dict):
        out["additionalProperties"] = extract(node["additionalProperties"], path=f"{path}.*", root=root)
    if "propertyNames" in node:
        out["propertyNames"] = extract(node["propertyNames"], path=f"{path}<names>", root=root)
    if "properties" in node:
        out["properties"] = {
            name: extract(sub, path=f"{path}.{name}", root=root) for name, sub in node["properties"].items()
        }
    if "items" in node:
        out["items"] = extract(node["items"], path=f"{path}[]", root=root)
    if "oneOf" in node:
        out["oneOf"] = [extract(sub, path=f"{path}|{index}", root=root) for index, sub in enumerate(node["oneOf"])]
    return out


def build_severities() -> tuple[str, dict[str, str]]:
    """The catalog's vocabulary identifier and each code's severity, fail-closed."""
    if not CATALOG.is_file():
        raise SystemExit(
            f"reason-code catalog not found: {CATALOG}\n"
            "loquitur-schemas must be checked out alongside this repository to regenerate the tables."
        )
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    severities: dict[str, str] = {}
    for code, entry in catalog["entries"].items():
        if entry.get("code") != code or entry.get("severity") not in SEVERITIES:
            raise UnsupportedSchemaKeyword(f"catalog entry {code!r} has no usable code and severity")
        severities[code] = entry["severity"]
    registry_entry = json.loads((SCHEMA_DIR / "registry_entry.schema.json").read_text(encoding="utf-8"))
    if sorted(registry_entry["properties"]["reason_codes"]["items"]["enum"]) != sorted(severities):
        raise UnsupportedSchemaKeyword("registry_entry reason_codes enum and the catalog name different codes")
    return catalog["reason_code_vocabulary"], dict(sorted(severities.items()))


def build() -> dict[str, Any]:
    contracts: dict[str, Any] = {}
    for name in CONTRACTS:
        source = SCHEMA_DIR / f"{name}.schema.json"
        if not source.is_file():
            raise SystemExit(
                f"schema not found: {source}\n"
                "loquitur-schemas must be checked out alongside this repository "
                "to regenerate the contract."
            )
        contracts[name] = extract(json.loads(source.read_text(encoding="utf-8")), path=name)
    name, relative = VOCABULARY_CONTRACT
    source = SCHEMA_DIR / relative
    if not source.is_file():
        raise SystemExit(
            f"schema not found: {source}\n"
            "loquitur-schemas must be checked out alongside this repository to regenerate the contract."
        )
    contracts[name] = extract(json.loads(source.read_text(encoding="utf-8")), path=name)
    return contracts


HEADER = '''"""Value-level contract tables mirrored from the normative JSON Schemas.

GENERATED FILE - do not edit by hand.
Regenerate with: python tools/generate_schema_contract.py

This package must not import loquitur-schemas at runtime, so the normative contract
is mirrored here. It is generated rather than transcribed because a hand-written
mirror easily carries only the field names and loses `required`, `enum` and
`pattern`, which would let this verifier authorize documents the public contract
rejects. `tests/test_schema_contract_is_current.py` fails if this file and the
schemas ever disagree.
"""

from __future__ import annotations

from typing import Any

SCHEMA_CONTRACTS: dict[str, Any] = '''

SEVERITY_HEADER = """
# The reason-code catalog (reason_codes_catalog/v2.0/catalog.json): its vocabulary identifier and
# the severity of every code the registry entry's `reason_codes` enum admits. verdict_grounds.py
# derives an entry's verdict from these (verdict-grounds.md VG-3).
REASON_CODE_VOCABULARY = """


def render(contracts: dict[str, Any]) -> str:
    # Python literals, not JSON: `false`/`true`/`null` are not Python names, and a
    # generated module that does not import is a build break rather than a subtle bug.
    body = pprint.pformat(contracts, indent=4, width=98, sort_dicts=True)
    vocabulary, severities = build_severities()
    table = pprint.pformat(severities, indent=4, width=98, sort_dicts=True)
    rendered = (
        HEADER
        + body
        + "\n"
        + SEVERITY_HEADER
        + repr(vocabulary)
        + "\n\nREASON_CODE_SEVERITY: dict[str, str] = "
        + table
        + "\n"
    )
    compile(rendered, str(TARGET), "exec")  # generation fails rather than emitting a broken module
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit non-zero if the checked-in file is stale")
    args = parser.parse_args()

    rendered = render(build())
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != rendered:
            print("schema_contract.py is stale; run python tools/generate_schema_contract.py", file=sys.stderr)
            return 1
        print("schema_contract.py is current")
        return 0

    TARGET.write_text(rendered, encoding="utf-8", newline="")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
