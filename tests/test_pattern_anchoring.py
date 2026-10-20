"""A value with a trailing newline does not match a schema pattern.

canonicalization-and-hashing.md, input strictness rule 5: a `pattern` is ECMA-262, `$`
asserts the absolute end of the string, and an implementation whose engine lets `$` match
before a final newline MUST NOT accept a value carrying one. Python's `re` is that engine.
The schemas spell their end anchor `$`. Applied with `re.search`, `registry_entry_id =
"reg_...\\n"` would return OFFLINE_OK, PASS and exit 0 while loquitur-schemas' validator and
the TypeScript verifier reject it, and no string in the corpus or the fixtures ends in a
newline, which is the one case where the readings differ.

So the case is written down here once per class of pattern the contract carries (an
identifier, a `sha256:`-prefixed hash, bare hex for the signature, an instant, a public key
and a version), both where the contract is applied and through the verifier a counterparty
runs, and the table's patterns are held to a form for which `re.fullmatch` is the ECMA-262
decision. Anchoring alone is not that form: `^\\d{4}$` is anchored, and Python's `\\d` accepts
Arabic-Indic digits that ECMA-262's rejects. So generation also holds each pattern to a
spelling both dialects read as the same expression and to a parsed structure both engines
decide alike, and the cases for those checks are written down here too.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from loquitur.verify.contract_validation import contract_errors
from loquitur.verify.runner import EXIT_OFFLINE_FAIL, verify_path
from loquitur.verify.schema_contract import SCHEMA_CONTRACTS

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests/fixtures"
BUNDLE_DIR = FIXTURES / "link_valid_bundle"
LINK_ENTRY = FIXTURES / "link_valid_registry_entry.json"
AUTH_ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
AUTH_TRUST = FIXTURES / "authorization_valid_trust_registry.json"
RECEIPT = BUNDLE_DIR / "verification_receipt.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _generator():
    # Loading the module needs no sibling checkout; only build() reads loquitur-schemas.
    spec = importlib.util.spec_from_file_location(
        "_generate_schema_contract_anchoring", REPO / "tools/generate_schema_contract.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _patterns(node: Any, path: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}

    def walk(value: Any, where: str) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("pattern"), str):
                found.setdefault(value["pattern"], []).append(where)
            for key, child in value.items():
                walk(child, f"{where}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{where}[{index}]")

    walk(node, path)
    return found


def _table_patterns() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name, node in SCHEMA_CONTRACTS.items():
        for pattern, paths in _patterns(node, name).items():
            found.setdefault(pattern, []).extend(paths)
    return found


# (contract, fixture, location of the string inside the document, error the contract reports)
CONTRACT_CASES = [
    ("registry_entry", AUTH_ENTRY, ("registry_entry_id",), "registry_entry.registry_entry_id:pattern"),
    ("registry_entry", AUTH_ENTRY, ("receipt_id",), "registry_entry.receipt_id:pattern"),
    ("registry_entry", AUTH_ENTRY, ("issuer_id",), "registry_entry.issuer_id:pattern"),
    ("registry_entry", AUTH_ENTRY, ("manifest_hash",), "registry_entry.manifest_hash:pattern"),
    ("registry_entry", AUTH_ENTRY, ("issued_at",), "registry_entry.issued_at:pattern"),
    ("registry_entry", AUTH_ENTRY, ("policy_version",), "registry_entry.policy_version:pattern"),
    # The signature string sits under a oneOf; a branch whose pattern fails is not a match,
    # so the error is reported on the oneOf, which is where the schema puts the choice.
    ("registry_entry", AUTH_ENTRY, ("signature", "signature"), "registry_entry.signature:oneOf"),
    ("trust_registry", AUTH_TRUST, ("trust_registry_id",), "trust_registry.trust_registry_id:pattern"),
    ("trust_registry", AUTH_TRUST, ("registry_operator_id",), "trust_registry.registry_operator_id:pattern"),
    ("trust_registry", AUTH_TRUST, ("registry_version",), "trust_registry.registry_version:pattern"),
    (
        "trust_registry",
        AUTH_TRUST,
        ("entries", 0, "public_key_hex"),
        "trust_registry.entries[0].public_key_hex:pattern",
    ),
    # The receipt is validated against its own generated contract whenever it is present.
    ("verification_receipt", RECEIPT, ("manifest_sha256",), "verification_receipt.manifest_sha256:pattern"),
]


def _with_trailing_newline(document: dict[str, Any], location: tuple[Any, ...]) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    parent: Any = changed
    for step in location[:-1]:
        parent = parent[step]
    assert isinstance(parent[location[-1]], str)
    parent[location[-1]] += "\n"
    return changed


@pytest.mark.parametrize(("contract", "fixture", "location", "error"), CONTRACT_CASES)
def test_the_contract_rejects_a_trailing_newline(
    contract: str, fixture: Path, location: tuple[Any, ...], error: str
) -> None:
    document = _load(fixture)
    assert contract_errors(contract, document) == [], "the premise: the unmodified fixture conforms"
    assert contract_errors(contract, _with_trailing_newline(document, location)) == [error]


def test_the_cases_above_cover_every_pattern_the_contract_carries() -> None:
    """A pattern added to a schema later must arrive with its own trailing-newline case."""

    import re

    patterns = set(_table_patterns())
    covered: set[str] = set()
    for _contract, fixture, location, _error in CONTRACT_CASES:
        value: Any = _load(fixture)
        for step in location:
            value = value[step]
        # A case exercises the patterns its unmodified value satisfies.
        covered.update(pattern for pattern in patterns if re.fullmatch(pattern, value))
    # Instants and issuer identifiers are covered through the registry entry; the trust
    # registry carries the same two patterns.
    assert covered == patterns, sorted(patterns - covered)


def test_every_pattern_in_the_table_is_anchored_to_the_whole_string() -> None:
    """A form without which `re.fullmatch` and the ECMA-262 search cannot decide alike."""

    generator = _generator()
    patterns = _table_patterns()
    assert len(patterns) >= 10
    for pattern, paths in patterns.items():
        generator.require_whole_string_anchoring(pattern, path=paths[0])


@pytest.mark.parametrize(
    "pattern",
    [
        "^a|b$",  # (^a)|(b$): the search accepts "ax", fullmatch does not
        "reg_[a-z]+$",  # unanchored start: the search accepts "xreg_a", fullmatch does not
        "^reg_[a-z]+",  # unanchored end
        "(?m)^a$",  # multiline changes what both anchors mean
        "^a$\\n?$",  # an anchor inside the body
        "^(a|b$)$",  # the same, inside a group
        "^[a-",  # does not parse
    ],
)
def test_generation_refuses_a_pattern_fullmatch_would_read_differently(pattern: str) -> None:
    generator = _generator()
    with pytest.raises(generator.UnsupportedSchemaKeyword):
        generator.extract({"type": "string", "pattern": pattern}, path="probe")


def test_every_pattern_in_the_table_is_one_fullmatch_decides_as_ecma_262_does() -> None:
    """Anchoring is necessary, not sufficient; generation applies all three checks."""

    generator = _generator()
    patterns = _table_patterns()
    assert len(patterns) >= 10
    for pattern, paths in patterns.items():
        generator.require_ecma_equivalent_pattern(pattern, path=paths[0])


# Anchored as ^X$, and still read differently. Each passes the anchoring check alone, and each
# was measured against node's RegExp, with and without the `u` flag, on the string beside it.
ANCHORED_BUT_NOT_EQUIVALENT = [
    ("^\\d{4}$", "\u0662\u0660\u0662\u0666"),  # Arabic-Indic digits: Python True, ECMA false
    ("^\\w+$", "\u00e9"),  # Python True, ECMA false
    ("^.+$", "a\r"),  # Python True, ECMA false
    ("^\\s$", "\x1c"),  # Python True, ECMA false
    ("^[\\d]{2}$", "\u0662\u0660"),  # the class escape inside a class: Python True, ECMA false
    ("(?i)^k$", "\u212a"),  # Kelvin sign: Python True; ECMA refuses to compile the pattern
]


@pytest.mark.parametrize(("pattern", "witness"), ANCHORED_BUT_NOT_EQUIVALENT)
def test_generation_refuses_an_anchored_pattern_python_reads_differently(pattern: str, witness: str) -> None:
    import re

    generator = _generator()
    assert re.fullmatch(pattern, witness), "the premise: Python accepts the witness"
    generator.require_whole_string_anchoring(pattern, path="probe")  # the premise: anchored
    with pytest.raises(generator.UnsupportedSchemaKeyword):
        generator.extract({"type": "string", "pattern": pattern}, path="probe")


# Refused by the spelling check. The tree Python builds for each is admissible, which is why
# the spelling is read at all: the difference is in how the other dialect parses the string.
SPELLING_ONLY = [
    "^a{,3}$",  # a repeat in Python, the literal text "a{,3}" in ECMA-262 without u
    "^(?P<n>a)$",  # a named group in Python, a syntax error in ECMA-262
    "^a]$",  # a literal in Python and in ECMA-262 without u, an error with u
    "^a}$",  # the same
    "^a\\-$",  # an identity escape Python and non-u ECMA-262 allow and u refuses
    "^[a-c-e]$",  # a '-' after a range: a literal without u, an error with u
    "^\\x41$",  # an escape outside the portable set
    "^[a&&b]$",  # a doubled punctuator: a literal in Python and ECMA-262, set syntax under v
]

# Refused by the structure check, on the tree Python's parser builds.
STRUCTURE_ONLY_EVEN_IF_SPELLING_MISJUDGED = [
    "^.+$",
    "^\\d{4}$",
    "^[\\d]{2}$",
    "(?i)^k$",
    "^(?i:k)$",
    "^[^a]$",  # a negated class: code points in Python, code units in ECMA-262 without u
    "^\u00e9$",
    "^a++$",
    "^(?>a)$",
    "^(a)\\1$",
    "^(?=a)a$",
]


@pytest.mark.parametrize("pattern", SPELLING_ONLY + STRUCTURE_ONLY_EVEN_IF_SPELLING_MISJUDGED)
def test_generation_refuses_a_pattern_outside_the_portable_form(pattern: str) -> None:
    generator = _generator()
    with pytest.raises(generator.UnsupportedSchemaKeyword):
        generator.extract({"type": "string", "pattern": pattern}, path="probe")


@pytest.mark.parametrize("pattern", SPELLING_ONLY)
def test_the_spelling_check_alone_refuses_what_the_tree_cannot_show(pattern: str) -> None:
    generator = _generator()
    try:
        generator.require_portable_pattern_structure(pattern, path="probe")
    except generator.UnsupportedSchemaKeyword:
        pytest.fail("the premise: Python's tree for this pattern is admissible")
    with pytest.raises(generator.UnsupportedSchemaKeyword):
        generator.require_portable_pattern_spelling(pattern, path="probe")


@pytest.mark.parametrize("pattern", STRUCTURE_ONLY_EVEN_IF_SPELLING_MISJUDGED)
def test_the_structure_check_alone_refuses_a_construct_either_way_it_is_spelled(pattern: str) -> None:
    generator = _generator()
    with pytest.raises(generator.UnsupportedSchemaKeyword):
        generator.require_portable_pattern_structure(pattern, path="probe")


@pytest.mark.parametrize(
    "pattern",
    [
        "^(?:a|bc)*?x{2,}[A-Z_.-]+$",
        "^\\.\\/\\[\\]\\{\\}\\(\\)\\|\\*\\+\\?\\^\\$\\\\$",
        "^[-a\\-\\]z]{0,3}$",
        "^()(a|)$",
        "^ a/b-c $",
    ],
)
def test_the_portable_form_is_not_narrower_than_it_says(pattern: str) -> None:
    """The checks refuse what they document, not everything a little unusual."""

    _generator().require_ecma_equivalent_pattern(pattern, path="probe")


def _write(tmp_path: Path, name: str, document: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _check(payload: dict[str, Any], name: str) -> dict[str, Any]:
    return next(check for check in payload["registry_link"]["checks"] if check["name"] == name)


@pytest.mark.parametrize(
    "field",
    [
        "registry_entry_id",  # identifier
        "manifest_hash",  # sha256:-prefixed hash
        "issued_at",  # instant
        "policy_version",  # version
    ],
)
def test_the_verifier_fails_a_link_entry_whose_field_ends_in_a_newline(tmp_path: Path, field: str) -> None:
    entry = _with_trailing_newline(_load(LINK_ENTRY), (field,))
    report = verify_path(BUNDLE_DIR, registry_entry_path=_write(tmp_path, "entry.json", entry))
    payload = report.to_dict()

    assert (report.status, report.verdict, report.exit_code) == ("OFFLINE_FAIL", "FAIL", EXIT_OFFLINE_FAIL)
    assert payload["outcome"]["reason"] == "registry_entry_contract_violation"
    assert payload["checks"]["registry_link"] is False
    contract = _check(payload, "registry_entry_contract")
    assert contract["ok"] is False
    assert f"registry_entry.{field}:pattern" in json.dumps(contract)


def test_the_verifier_fails_a_signature_that_ends_in_a_newline(tmp_path: Path) -> None:
    """Bare hex. `bytes.fromhex` skips whitespace, so without the contract this verified."""

    entry = _with_trailing_newline(_load(AUTH_ENTRY), ("signature", "signature"))
    report = verify_path(
        BUNDLE_DIR,
        registry_entry_path=_write(tmp_path, "entry.json", entry),
        trust_registry_path=AUTH_TRUST,
    )
    payload = report.to_dict()

    assert (report.status, report.verdict, report.exit_code) == ("OFFLINE_FAIL", "FAIL", EXIT_OFFLINE_FAIL)
    assert payload["outcome"]["reason"] == "registry_entry_contract_violation"
    assert "registry_entry.signature:oneOf" in json.dumps(_check(payload, "registry_entry_contract"))


def test_the_verifier_fails_a_trust_registry_public_key_that_ends_in_a_newline(tmp_path: Path) -> None:
    trust = _with_trailing_newline(_load(AUTH_TRUST), ("entries", 0, "public_key_hex"))
    report = verify_path(
        BUNDLE_DIR,
        registry_entry_path=AUTH_ENTRY,
        trust_registry_path=_write(tmp_path, "trust.json", trust),
    )
    payload = report.to_dict()

    assert (report.status, report.verdict, report.exit_code) == ("OFFLINE_FAIL", "FAIL", EXIT_OFFLINE_FAIL)
    assert payload["outcome"]["reason"] == "trust_registry_verification_failed"
    assert payload["trust_registry"]["authorization_status"] == "INVALID_TRUST_REGISTRY"
