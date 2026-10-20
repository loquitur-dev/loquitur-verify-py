"""I-JSON input strictness (canonicalization-and-hashing.md, "Input strictness"; RFC 7493).

Rule 9 refuses the 66 noncharacters in any string or member name, written literally or as an
escape. The excess-precision rule refuses a number whose spelled decimal value differs from the
RFC 8785 serialization of the binary64 value it is read as, so a document is never rounded into
a value it did not spell. Exponent forms are read by value. A leading byte order mark makes the
document invalid; U+FEFF inside a string is a scalar value. The texts are built from code points
so that no literal noncharacter or invisible character is written in this file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_builder import Bundle, with_raw_member

from loquitur.verify.canonical import CanonicalizationError, JsonLoadError, canonical_json_bytes, loads_json_bytes
from loquitur.verify.runner import verify_path


def _escape(code_point: int) -> str:
    """The JSON escape of one code point, as a surrogate pair above the BMP."""
    backslash = chr(0x5C)
    if code_point < 0x10000:
        return f"{backslash}u{code_point:04x}"
    v = code_point - 0x10000
    return f"{backslash}u{0xD800 + (v >> 10):04x}{backslash}u{0xDC00 + (v & 0x3FF):04x}"


NONCHARACTERS = [*range(0xFDD0, 0xFDF0)] + [(plane << 16) | low for plane in range(17) for low in (0xFFFE, 0xFFFF)]

REFUSED = {
    "excess-precision-2": ("2.0000000000000001", "json_excess_precision"),
    "underflow-to-zero": ("4.9e-325", "json_excess_precision"),
    "excess-digits": ("0.30000000000000004441", "json_excess_precision"),
    "half-above-2p53": ("9007199254740992.5", "json_excess_precision"),
    "large-integer-valued": ("1.5e300", "json_integer_outside_safe_range"),
    "overflow": ("1e400", "non_finite_json_number"),
    "nonchar-escape-value": ('{"a":"' + _escape(0xFDD0) + '"}', "json_noncharacter"),
    "nonchar-escape-name": ('{"' + _escape(0xFDD0) + '":1}', "json_noncharacter"),
    "nonchar-literal-ffff": ('["' + chr(0xFFFF) + '"]', "json_noncharacter"),
    "nonchar-pair-1fffe": ('["' + _escape(0x1FFFE) + '"]', "json_noncharacter"),
    "nonchar-literal-10ffff-name": ('{"x' + chr(0x10FFFF) + '":0}', "json_noncharacter"),
}
ACCEPTED = {
    "0.1": "0.1",
    "1.0": "1.0",
    "1e0": "1e0",
    "1E2": "1E2",
    "1e+2": "1e+2",
    "minus-zero": "-0",
    "minus-zero-fraction": "-0.0",
    "shortest-0.3-sum": "0.30000000000000004",
    "bom-inside-string": '["' + _escape(0xFEFF) + '"]',
    "below-the-noncharacters": '["' + _escape(0xFDCF) + '"]',
    "above-the-noncharacters": '["' + _escape(0xFDF0) + '"]',
    "fffd": '["' + _escape(0xFFFD) + '"]',
}


def _outcome(text: str | bytes) -> str:
    data = text if isinstance(text, bytes) else text.encode("utf-8")
    try:
        loads_json_bytes(data, name="probe")
    except JsonLoadError as exc:
        return str(exc)
    return "loaded"


def test_each_refused_spelling_is_refused_with_its_rule() -> None:
    got = {label: _outcome(text) for label, (text, _code) in REFUSED.items()}
    assert {label: out.split(":")[0] for label, out in got.items()} == {
        label: code for label, (_text, code) in REFUSED.items()
    }


def test_each_accepted_spelling_loads() -> None:
    assert {label: _outcome(text) for label, text in ACCEPTED.items()} == dict.fromkeys(ACCEPTED, "loaded")


def test_exponent_forms_are_read_by_value() -> None:
    assert loads_json_bytes(b"[1E2, 1e+2, 100, 1.5E-1]") == [100.0, 100.0, 100, 0.15]
    assert canonical_json_bytes(loads_json_bytes(b"[1E2, -0]")) == b"[100,0]"


def test_every_noncharacter_is_refused_as_an_escape_and_literally() -> None:
    assert len(NONCHARACTERS) == 66
    escaped = {hex(cp): _outcome('["' + _escape(cp) + '"]') for cp in NONCHARACTERS}
    literal = {hex(cp): _outcome('{"' + chr(cp) + '":1}') for cp in NONCHARACTERS}
    assert escaped == dict.fromkeys(escaped, "json_noncharacter:probe")
    assert literal == dict.fromkeys(literal, "json_noncharacter:probe")


def test_a_leading_byte_order_mark_is_refused() -> None:
    assert _outcome(b"\xef\xbb\xbf{}").startswith("invalid_json:probe")


def test_the_canonicalizer_refuses_a_noncharacter_in_a_value_handed_over() -> None:
    for value in ({"a": chr(0xFDEF)}, {chr(0xFFFE): 1}, [chr(0x10FFFF)]):
        with pytest.raises(CanonicalizationError):
            canonical_json_bytes(value)
    assert (
        canonical_json_bytes({"a": chr(0xFEFF)})
        == json.dumps({"a": chr(0xFEFF)}, ensure_ascii=False).replace(" ", "").encode()
    )


@pytest.mark.parametrize(
    ("label", "raw", "code"),
    [
        ("excess-precision", "2.0000000000000001", "json_excess_precision"),
        ("noncharacter", '"' + _escape(0xFDD0) + '"', "json_noncharacter"),
    ],
)
def test_a_bundle_member_breaking_a_rule_fails_the_run(tmp_path: Path, label: str, raw: str, code: str) -> None:
    """Outside the P1 projection too: the rule holds for the whole document the manifest commits to."""
    bundle = Bundle().seal()
    bundle.members["canonical_input.json"] = with_raw_member(bundle.json("canonical_input.json"), "not_projected", raw)
    bundle.seal(p1=False)
    report = verify_path(bundle.write(tmp_path / label)).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert f"{code}:canonical_input.json" in json.dumps(report)
