"""Guards whose type half or status label no test held: verdict grounds, the renderer, root status.

Each test holds one rule that a change to the source could break while every other test still
passed; the comment above it names the rule and where the specification states it.
"""

from __future__ import annotations

import pytest

from loquitur.verify.narrative import render_narrative_from_codes
from loquitur.verify.trust_root import (
    STATUS_MALFORMED_SIGNATURE,
    STATUS_UNSUPPORTED_ALGORITHM,
    TrustRootKey,
    verify_trust_registry_root_signature,
)
from loquitur.verify.verdict_grounds import (
    registry_entry_grounds_errors,
    summary_violated_rules,
    verdict_grounds_violations,
)

_ROOT = TrustRootKey(
    key_id="root-1",
    key_type="secp256k1",
    public_key_hex="041dd90173ecb1ce0bf3f2d04f78a4b8cbc3a35ef7cce82f898e39038f874bd5f50209dcd9dfdcfa1fdac4ddfb20846974708c4e3cef6670fcef2a50f61db9e9ff",
    not_before="2026-04-01T00:00:00Z",
    not_after="2026-07-01T00:00:00Z",
)


# A verdict that is not a string is outside the vocabulary and is the
# finding (verdict-grounds.md section 4), never a TypeError from the membership test.
@pytest.mark.parametrize("verdict", [[], {}, ["PASS"], {"PASS": 1}, 1, None, True])
def test_a_verdict_that_is_not_a_string_is_outside_the_vocabulary(verdict: object) -> None:
    violations = verdict_grounds_violations(verdict, ["INTEGRITY_OK"])
    # Both VG-3 findings: out of vocabulary, and so not the verdict the grounds derive.
    assert [(violation.rule, violation.code) for violation in violations] == [
        ("VG-3", "verdict_outside_vocabulary"),
        ("VG-3", "verdict_contradicts_grounds"),
    ]


# verdict-grounds.md section 5: the vocabulary check is part of VG-3 and comes after the VG-1 and
# VG-2 preconditions, which stop the check.
@pytest.mark.parametrize("verdict", ["NOT_A_VERDICT", "pass", [], None])
def test_a_verdict_outside_the_vocabulary_is_judged_after_the_preconditions(verdict: object) -> None:
    assert [(v.rule, v.code) for v in verdict_grounds_violations(verdict, [])] == [("VG-1", "reason_codes_absent")]
    assert [(v.rule, v.code) for v in verdict_grounds_violations(verdict, ["INTEGRITY_OK", "INTEGRITY_OK"])] == [
        ("VG-1", "reason_codes_duplicated")
    ]
    assert [(v.rule, v.code) for v in verdict_grounds_violations(verdict, ["NOT_A_REAL_CODE"])] == [
        ("VG-2", "reason_code_not_in_catalog")
    ]


@pytest.mark.parametrize("verdict", [[], {}, 1])
def test_the_entry_grounds_leave_a_verdict_that_is_not_a_string_to_the_schema(verdict: object) -> None:
    assert registry_entry_grounds_errors({"verdict": verdict, "reason_codes": ["INTEGRITY_OK"]}) == []


# VG-1 compares the cited codes as JSON values on the entry path as on the summary path: 1, 1.0 and
# 1e0 are one entry, so a code cited so is cited twice.
@pytest.mark.parametrize(
    "codes",
    [[1, 1.0], [1, 1e0, "INTEGRITY_OK"], [[1], [1.0]], [{"a": 1, "b": 2}, {"b": 2, "a": 1.0}], [2**60, float(2**60)]],
)
def test_a_code_cited_twice_as_one_json_value_is_vg_1(codes: list[object]) -> None:
    violations = verdict_grounds_violations("PASS", codes)
    assert [(v.rule, v.code) for v in violations] == [("VG-1", "reason_codes_duplicated")]
    assert summary_violated_rules({"reason_codes": codes}) == ["VG-1"]


@pytest.mark.parametrize("codes", [[1, True], [1, "1"], [[1], [2]]])
def test_codes_that_are_different_json_values_are_not_a_repeat(codes: list[object]) -> None:
    rules = {v.rule for v in verdict_grounds_violations("PASS", codes)}
    assert "VG-1" not in rules


# A cited code that is an array or an object is not in the catalog (VG-2).
@pytest.mark.parametrize("code", [["x"], {"a": 1}, 7, None, True])
def test_a_reason_code_that_is_not_a_string_is_not_in_the_catalog(code: object) -> None:
    violations = verdict_grounds_violations("PASS", ["INTEGRITY_OK", code])
    assert [violation.rule for violation in violations] == ["VG-2"]


# Reason codes that are not an array are absent (VG-1), and the renderer refuses
# them instead of rendering an object's member names or raising TypeError.
@pytest.mark.parametrize("reason_codes", [{"INTEGRITY_OK": True}, None, 7, True, "INTEGRITY_OK"])
def test_the_renderer_refuses_reason_codes_that_are_not_an_array(reason_codes: object) -> None:
    with pytest.raises(ValueError, match="reason_codes must be an array"):
        render_narrative_from_codes(reason_codes, "PASS", verdict_context="registry_entry")  # type: ignore[arg-type]


# trust-root.md section 5 keeps an algorithm that is not permitted
# (row 4) apart from the form of the value (rows 3 and 5). Only the status tells them apart.
@pytest.mark.parametrize("algorithm", ["ed25519", "secp256k1_ecdsa_sha512", "unknown_alg"])
def test_a_root_signature_with_an_algorithm_outside_the_allowlist_is_unsupported(algorithm: str) -> None:
    registry = {"signature": {"algorithm": algorithm, "key_id": "root-1", "signature": "0" * 128}}
    result = verify_trust_registry_root_signature(registry, evaluated_at="2026-05-01T12:00:00Z", roots=(_ROOT,))
    assert result.ok is False
    assert result.status == STATUS_UNSUPPORTED_ALGORITHM


def test_a_root_signature_whose_value_is_not_compact_hex_is_malformed() -> None:
    registry = {"signature": {"algorithm": "secp256k1_ecdsa_sha256", "key_id": "root-1", "signature": "z" * 128}}
    result = verify_trust_registry_root_signature(registry, evaluated_at="2026-05-01T12:00:00Z", roots=(_ROOT,))
    assert result.status == STATUS_MALFORMED_SIGNATURE
