"""Number tokens whose exponent is long only because of its leading zeros.

canonicalization-and-hashing.md section 6, "Exponent forms": an exponent is ``e`` or ``E``, an
optional sign and one or more digits. ``1e`` followed by 5000 zeros and a ``1`` names 10, which
binary64 holds exactly, so the token is valid. The strict loader once converted every digit of
the exponent with int(), which the interpreter refuses above 4300 decimal digits, so such a
token refused the whole document where loquitur-verify-ts loads it. The members below are those
committed by their canonical digest rather than their bytes (a bundle member outside the P1
projection, the verification receipt, the envelope), so the re-spelling breaks no digest, and
each must give the outcome its plain spelling gives.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bundle_builder import Bundle, jcs, with_raw_member

from loquitur.verify.canonical import JsonLoadError, loads_json_bytes
from loquitur.verify.runner import verify_path

ZEROS = "0" * 5000


def _loaded(text: str) -> object:
    try:
        return loads_json_bytes(text.encode("ascii"), name="probe")
    except JsonLoadError as exc:
        return str(exc)


def test_the_loader_reads_the_value_and_not_the_spelling_length() -> None:
    assert _loaded(f"[1e{ZEROS}1, 1E+{ZEROS}1, 1e-{ZEROS}1, 1.5e+{ZEROS}2, 1e{ZEROS}, -2e-{ZEROS}]") == [
        10.0,
        10.0,
        0.1,
        150.0,
        1.0,
        -2.0,
    ]
    # Excess precision and overflow are still decided by the value.
    assert _loaded(f"[1e-{ZEROS}400]") == "json_excess_precision:probe"
    assert _loaded(f"[1e{ZEROS}400]") == "non_finite_json_number:overflow:probe"


def test_an_integer_token_too_long_for_int_is_refused_by_rule_2() -> None:
    assert _loaded("[1" + "0" * 5000 + "]") == "json_integer_outside_safe_range:probe"
    assert _loaded("[-1" + "0" * 5000 + "]") == "json_integer_outside_safe_range:probe"
    assert _loaded("[10000000000000000]") == "json_integer_outside_safe_range:probe"
    assert _loaded("[9007199254740991, -9007199254740991]") == [9007199254740991, -9007199254740991]


def _summary(report: dict) -> tuple:
    return (
        report["status"],
        report["verdict"],
        report["exit_code"],
        sorted({error["code"] for error in report["errors"]}),
        report.get("registry_link", {}).get("status") if isinstance(report.get("registry_link"), dict) else None,
    )


def _respell(data: bytes, plain: str, spelled: str) -> bytes:
    text = data.decode("utf-8")
    assert text.count(plain) == 1
    return text.replace(plain, spelled).encode("utf-8")


# Each re-spelling names the value its plain spelling names: 1, 1 and 10.
SPELLINGS = {
    "positive": ("1", f"1e{ZEROS}"),
    "negative": ("1", f"10e-{ZEROS}1"),
    "signed-positive": ("10", f"1e+{ZEROS}1"),
}


@pytest.mark.parametrize("label", SPELLINGS)
def test_a_bundle_member_outside_the_projection(tmp_path: Path, label: str) -> None:
    plain, spelled = SPELLINGS[label]
    reports = {}
    for name, value in (("plain", plain), ("spelled", spelled)):
        bundle = Bundle().seal()
        bundle.members["canonical_input.json"] = with_raw_member(
            bundle.json("canonical_input.json"), "not_projected", value
        )
        bundle.seal(p1=False)
        reports[name] = _summary(verify_path(bundle.write(tmp_path / name)).to_dict())
    assert reports["plain"][0] == "OFFLINE_OK"
    assert reports["spelled"] == reports["plain"]


@pytest.mark.parametrize("label", ["positive", "negative"])
def test_the_verification_receipt(tmp_path: Path, label: str) -> None:
    _, spelled = SPELLINGS[label]
    reports = {}
    for name in ("plain", "spelled"):
        bundle = Bundle().seal()
        if name == "spelled":
            bundle.members["verification_receipt.json"] = _respell(
                bundle.members["verification_receipt.json"], '"policy_version":1', '"policy_version":' + spelled
            )
        root = bundle.write(tmp_path / name / "bundle")
        entry = bundle.link_entry(tmp_path / name / "entry.json")
        reports[name] = _summary(verify_path(root, registry_entry_path=entry).to_dict())
    assert "verification_receipt_contract_violation" not in reports["plain"][3]
    assert reports["spelled"] == reports["plain"]


@pytest.mark.parametrize("label", ["positive", "negative"])
def test_the_envelope(tmp_path: Path, label: str) -> None:
    _, spelled = SPELLINGS[label]
    bundle = Bundle().seal()
    plain_report = _summary(verify_path(bundle.write(tmp_path / "plain")).to_dict())
    envelope = bundle.members["envelope_env1.json"]
    bundle.members["envelope_env1.json"] = _respell(envelope, '"v":1', '"v":' + spelled)
    # The sidecar commits to the canonical bytes, which the re-spelling does not change.
    assert jcs(bundle.json("envelope_env1.json")) == envelope
    spelled_report = _summary(verify_path(bundle.write(tmp_path / "spelled")).to_dict())
    assert plain_report[0] == "OFFLINE_OK"
    assert spelled_report == plain_report
