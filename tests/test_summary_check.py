"""The verification-summary check: verdict-grounds.md VG-1 to VG-7, in the order of section 5.

summary_violated_rules returns the rules a summary violates, in rule order; a violation of VG-1 or
VG-2 is the only rule it lists. The conformance adapter answers a summary run with the same list
(conformance-testing.md section 4.1).
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from loquitur.verify.verdict_grounds import _json_identity, summary_violated_rules, verdict_grounds_violations

ADAPTER = Path(__file__).resolve().parents[1] / "tools" / "conformance_adapter.py"


def _summary(**members: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "object_type": "verification_summary",
        "schema_version": "loquitur.verification_summary.v1",
        "bundle_id": "bundle-1",
        "reason_code_vocabulary_version": "loquitur.reason_codes.v1",
        "status": "pass",
        "reason_codes": ["INTEGRITY_OK"],
        "key_checks": ["integrity"],
    }
    document.update(members)
    return {key: value for key, value in document.items() if value is not _ABSENT}


_ABSENT = object()
_CONTEXT = [{"code": "AUTHORIZATION_ISSUER_KEY_REVOKED", "subject": "issuer key"}]

CASES = [
    ("conforming pass", _summary(), []),
    (
        "conforming fail with context",
        _summary(
            status="fail",
            reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"],
            key_checks=_ABSENT,
            reason_context=_CONTEXT,
        ),
        [],
    ),
    ("context for a code not cited", _summary(reason_context=_CONTEXT), []),
    ("not an object", ["INTEGRITY_OK"], ["VG-1"]),
    ("no codes", _summary(reason_codes=[]), ["VG-1"]),
    ("codes absent", _summary(reason_codes=_ABSENT), ["VG-1"]),
    ("codes not an array", _summary(reason_codes="INTEGRITY_OK"), ["VG-1"]),
    ("a code cited twice", _summary(reason_codes=["INTEGRITY_OK", "INTEGRITY_OK"]), ["VG-1"]),
    ("a code twice beside an unknown one", _summary(reason_codes=["X", "X", "NOT_A_REAL_CODE"]), ["VG-1"]),
    ("an unknown code", _summary(reason_codes=["INTEGRITY_OK", "NOT_A_REAL_CODE"]), ["VG-2"]),
    ("a code that is not a string", _summary(reason_codes=["INTEGRITY_OK", 7]), ["VG-2"]),
    # Numbers compare by the binary64 value they are read as: 1 and 1.0 are one entry cited twice,
    # as loquitur-verify-ts finds; two different numbers are not.
    ("one number in two spellings", _summary(reason_codes=[1, 1.0]), ["VG-1"]),
    ("one object in two spellings", _summary(reason_codes=[{"a": 1}, {"a": 1.0}]), ["VG-1"]),
    ("two different numbers", _summary(reason_codes=[1, 2]), ["VG-2"]),
    (
        "an unknown code beside a contradicted status",
        _summary(status="fail", reason_codes=["NOT_A_REAL_CODE"], key_checks=_ABSENT),
        ["VG-2"],
    ),
    (
        "pass citing a fail code",
        _summary(reason_codes=["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"], reason_context=_CONTEXT),
        ["VG-3"],
    ),
    ("fail citing only info", _summary(status="fail"), ["VG-3"]),
    ("status outside the vocabulary", _summary(status="PASS"), ["VG-3"]),
    ("status absent", _summary(status=_ABSENT), ["VG-3"]),
    (
        "pass citing only warn, no key_checks",
        _summary(reason_codes=["FRESHNESS_WARNING"], key_checks=_ABSENT),
        ["VG-3", "VG-4", "VG-5"],
    ),
    ("pass with key_checks {}", _summary(key_checks={}), ["VG-5"]),
    ("pass with key_checks []", _summary(key_checks=[]), ["VG-5"]),
    ("pass with key_checks null", _summary(key_checks=None), ["VG-5"]),
    ("pass with no key_checks", _summary(key_checks=_ABSENT), ["VG-5"]),
    # A value that is not an array, an object or null is treated as absent (verdict-grounds.md
    # section 1: the rules apply to any JSON value), whatever its truth in the host language.
    ("pass with key_checks a string", _summary(key_checks="integrity"), ["VG-5"]),
    ("pass with key_checks true", _summary(key_checks=True), ["VG-5"]),
    ("pass with key_checks a number", _summary(key_checks=1), ["VG-5"]),
    ("pass with key_checks an empty string", _summary(key_checks=""), ["VG-5"]),
    ("pass with key_checks false", _summary(key_checks=False), ["VG-5"]),
    ("pass with key_checks an object", _summary(key_checks={"integrity": True}), []),
    (
        "fail without context",
        _summary(status="fail", reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"], key_checks=_ABSENT),
        ["VG-6"],
    ),
    (
        "context entry naming an unknown code",
        _summary(reason_context=[{"code": "NOT_A_REAL_CODE"}]),
        ["VG-7"],
    ),
    (
        "fail without context and context naming an unknown code",
        _summary(
            status="fail",
            reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"],
            key_checks=_ABSENT,
            reason_context=[{"code": "NOT_A_REAL_CODE"}, {"code": 7}],
        ),
        ["VG-6", "VG-7"],
    ),
    # An entry that is not an object, has no code, or whose code is not a string names no
    # catalog code: it violates VG-7, and it explains no cited code for VG-6.
    ("context entry without a code", _summary(reason_context=[{"subject": "issuer key"}]), ["VG-7"]),
    ("context entry with a null code", _summary(reason_context=[{"code": None}]), ["VG-7"]),
    ("context entry not an object", _summary(reason_context=["INTEGRITY_OK"]), ["VG-7"]),
    ("context entry null", _summary(reason_context=[None]), ["VG-7"]),
    ("context entry an array", _summary(reason_context=[["INTEGRITY_OK"]]), ["VG-7"]),
    (
        "fail explained only by a string entry",
        _summary(
            status="fail",
            reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"],
            key_checks=_ABSENT,
            reason_context=["AUTHORIZATION_ISSUER_KEY_REVOKED"],
        ),
        ["VG-6", "VG-7"],
    ),
    # A reason_context that is not an array is treated as absent: no entry for VG-7, and VG-6
    # stays unmet.
    ("context an object", _summary(reason_context={"code": "NOT_A_REAL_CODE"}), []),
    ("context a string", _summary(reason_context="NOT_A_REAL_CODE"), []),
    (
        "fail with context an object naming the code",
        _summary(
            status="fail",
            reason_codes=["AUTHORIZATION_ISSUER_KEY_REVOKED"],
            key_checks=_ABSENT,
            reason_context=_CONTEXT[0],
        ),
        ["VG-6"],
    ),
]


@pytest.mark.parametrize(("document", "expected"), [case[1:] for case in CASES], ids=[case[0] for case in CASES])
def test_the_rules_a_summary_violates(document: Any, expected: list[str]) -> None:
    assert summary_violated_rules(document) == expected


# Values RFC 8785 canonicalization refuses (a noncharacter, an integer beyond 2^53 - 1, a lone
# surrogate), each cited twice as one JSON value: in another member order, or with a number in
# another spelling of the same binary64 value. A refusal does not make two equal entries
# distinct, as loquitur-verify-ts and loquitur-schemas find. In memory only: no JSON text the
# adapter reads is needed to hold the rule.
_UNCANONICAL_DUPLICATES = [
    [{"a": "\uffff", "b": 1}, {"b": 1, "a": "\uffff"}],
    [2**60, float(2**60)],
    [2**60 + 1, float(2**60)],
    [[1, "\ufdd0"], [1.0, "\ufdd0"]],
    [["\ud800", 1], ["\ud800", 1.0]],
]
_UNCANONICAL_IDS = [
    "noncharacter-member-order",
    "big-integer",
    "big-integer-rounded",
    "noncharacter-array",
    "lone-surrogate",
]


@pytest.mark.parametrize("codes", _UNCANONICAL_DUPLICATES, ids=_UNCANONICAL_IDS)
def test_one_json_value_canonicalization_refuses_is_still_cited_twice(codes: list[Any]) -> None:
    assert summary_violated_rules(_summary(reason_codes=codes)) == ["VG-1"]


def test_a_lone_surrogate_code_cited_twice_is_duplicated() -> None:
    violations = verdict_grounds_violations("PASS", ["\ud800", "\ud800"])
    assert [(v.rule, v.code) for v in violations] == [("VG-1", "reason_codes_duplicated")]


# The keys loquitur-schemas' json_value_key gives for the same values, written out: the verdict
# path does not import that package and the function is not part of its public surface, so the
# mirror is held to fixed keys rather than to the other implementation.
_EXPECTED_KEYS = [
    ({"b": 1, "a": "\uffff"}, r'j:{"a":"\uffff","b":1}'),
    (2**60, "j:1152921504606846976"),
    (float(2**60), "j:1152921504606846976"),
    (2**60 + 1, "j:1152921504606846976"),
    ([1.0, "\ufdd0"], r'j:[1,"\ufdd0"]'),
    (["\ud800", 1.0], r'j:["\ud800",1]'),
    (-0.0, "j:0"),
    (0.1, "j:0.1"),
    (10**400, "j:inf"),
    (-(10**400), "j:-inf"),
    (math.nan, "j:nan"),
    (True, "j:true"),
    (None, "j:null"),
    ((1, 2), "j:[1,2]"),
    ("\ud800", "s:\ud800"),
]


@pytest.mark.parametrize(("value", "key"), _EXPECTED_KEYS, ids=[ascii(value) for value, _ in _EXPECTED_KEYS])
def test_the_identity_key_is_the_schemas_key(value: Any, key: str) -> None:
    assert _json_identity(value) == key


def test_the_identity_key_walks_a_deep_value_without_recursion() -> None:
    deep: list[Any] = []
    for _ in range(5000):
        deep = [deep]
    assert _json_identity(deep) == "j:" + "[" * 5001 + "]" * 5001


def test_the_warn_code_used_above_has_severity_warn() -> None:
    from loquitur.verify.schema_contract import REASON_CODE_SEVERITY

    assert REASON_CODE_SEVERITY["FRESHNESS_WARNING"] == "warn"
    assert REASON_CODE_SEVERITY["AUTHORIZATION_ISSUER_KEY_REVOKED"] == "fail"


def _adapter(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(ADAPTER), *args], capture_output=True, text=True, check=False)


@pytest.mark.parametrize(("document", "expected"), [case[1:] for case in CASES], ids=[case[0] for case in CASES])
def test_the_adapter_answers_a_summary_run(tmp_path: Path, document: Any, expected: list[str]) -> None:
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    done = _adapter("--summary", str(path))
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"violated_rules": expected}


def test_the_adapter_takes_a_summary_alone(tmp_path: Path) -> None:
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(_summary()), encoding="utf-8")
    assert _adapter("--summary", str(path), "--bundle", str(tmp_path)).returncode == 64


def test_the_adapter_refuses_a_summary_it_cannot_parse(tmp_path: Path) -> None:
    path = tmp_path / "summary.json"
    path.write_text('{"status": "pass", "status": "fail"}', encoding="utf-8")
    assert _adapter("--summary", str(path)).returncode == 64
