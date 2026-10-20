"""Number tokens whose exponent is beyond any decimal library's range.

canonicalization-and-hashing.md, "No excess precision", decides a number by the decimal value
it spells. 0e99999999999999999999 and 0e1000000000000000000 spell exactly zero and are valid;
1e-99999999999999999999 spells a non-zero value that is read as 0, which is excess precision;
1e99999999999999999999 overflows to infinity, which is rule 3. The strict loader decides these
values without a decimal library, whose exponent range they exceed, so every one of them ends in
a verdict and none in exit 3. Each row below is the outcome loquitur-verify-ts gives on the same
bytes, for a bundle member, the registry entry and the trust registry.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest
from authorization_kit import BUNDLE, EVALUATION_TIME, IssuerKey, authorization_material
from bundle_builder import Bundle, with_raw_member

from loquitur.verify.canonical import JsonLoadError, loads_json_bytes
from loquitur.verify.cli import main
from loquitur.verify.runner import verify_path

TOKENS = {
    "zero-huge-exponent": "0e99999999999999999999",
    "nonzero-tiny-exponent": "1e-99999999999999999999",
    "zero-exponent-1e18": "0e1000000000000000000",
    "nonzero-huge-exponent": "1e99999999999999999999",
}
# The refusal each token gets from the strict loader; None when the token loads, as 0.
REFUSAL = {
    "zero-huge-exponent": None,
    "nonzero-tiny-exponent": "json_excess_precision",
    "zero-exponent-1e18": None,
    "nonzero-huge-exponent": "non_finite_json_number:overflow",
}


def _loaded(text: str) -> object:
    try:
        return loads_json_bytes(f"[{text}]".encode("ascii"), name="probe")
    except JsonLoadError as exc:
        return str(exc)


def test_the_loader_decides_each_token_by_its_spelled_value() -> None:
    got = {label: _loaded(token) for label, token in TOKENS.items()}
    assert got == {label: ([0.0] if refusal is None else f"{refusal}:probe") for label, refusal in REFUSAL.items()}


def test_an_exponent_too_long_for_int_is_still_decided() -> None:
    long = "9" * 5000
    assert _loaded(f"0e{long}") == [0.0]
    assert _loaded(f"0e-{long}") == [0.0]
    assert _loaded(f"1e-{long}") == "json_excess_precision:probe"
    assert _loaded(f"1e{long}") == "non_finite_json_number:overflow:probe"


def test_ordinary_spellings_are_unchanged() -> None:
    assert _loaded("1E2, 1e+2, 1.0e+0, 10.0e-1, 0.00e5, 1e-5, 5e-324, -0.0") == [
        100.0,
        100.0,
        1.0,
        1.0,
        0.0,
        1e-05,
        5e-324,
        -0.0,
    ]
    for refused in ("2.0000000000000001", "4.9e-325", "9007199254740992.5", "0.30000000000000004441"):
        assert _loaded(refused) == "json_excess_precision:probe"


def _summary(report: dict) -> tuple:
    trust = report.get("trust_registry") or {}
    return (
        report["status"],
        report["exit_code"],
        sorted({error["code"] for error in report["errors"]}),
        trust.get("authorization_status"),
    )


# Status, exit code, error codes and trust-registry authorization status, as loquitur-verify-ts
# gives them on the same files (verifyBundle with readDocumentPath for each document).
MEMBER = {
    "zero-huge-exponent": ("OFFLINE_OK", 0, [], None),
    "nonzero-tiny-exponent": ("OFFLINE_FAIL", 1, ["p1_verification_failed"], None),
    "zero-exponent-1e18": ("OFFLINE_OK", 0, [], None),
    "nonzero-huge-exponent": ("OFFLINE_FAIL", 1, ["p1_verification_failed"], None),
}
# The entry carries an extra member "x", so a token that loads still breaks the entry's contract;
# one the loader refuses fails the link before the contract is read.
ENTRY = {
    "zero-huge-exponent": ("OFFLINE_FAIL", 1, ["registry_entry_contract_violation"], None),
    "nonzero-tiny-exponent": ("OFFLINE_FAIL", 1, ["registry_link_verification_failed"], None),
    "zero-exponent-1e18": ("OFFLINE_FAIL", 1, ["registry_entry_contract_violation"], None),
    "nonzero-huge-exponent": ("OFFLINE_FAIL", 1, ["registry_link_verification_failed"], None),
}
TRUST = dict.fromkeys(TOKENS, ("OFFLINE_FAIL", 1, [], "INVALID_TRUST_REGISTRY"))


def _refusals(report: dict) -> list[str]:
    text = json.dumps(report)
    return [code for code in ("json_excess_precision", "non_finite_json_number:overflow") if code in text]


@pytest.mark.parametrize("label", TOKENS)
def test_a_bundle_member(tmp_path: Path, label: str) -> None:
    bundle = Bundle().seal()
    bundle.members["canonical_input.json"] = with_raw_member(
        bundle.json("canonical_input.json"), "not_projected", TOKENS[label]
    )
    bundle.seal(p1=False)
    report = verify_path(bundle.write(tmp_path / "bundle")).to_dict()
    assert (_summary(report), _refusals(report)) == (MEMBER[label], [REFUSAL[label]] if REFUSAL[label] else [])


def _documents(tmp_path: Path, label: str, where: str) -> tuple[Path, Path]:
    key = IssuerKey()
    # Signed with "x": 0, whose canonical bytes are those of a token that spells zero.
    entry, registry = authorization_material(key, entry=(lambda e: e.update(x=0)) if where == "entry" else None)
    if where == "trust":
        registry["x"] = 0
    texts = {"entry": json.dumps(entry), "trust": json.dumps(registry)}
    if where in texts:
        texts[where] = texts[where].replace('"x": 0', '"x": ' + TOKENS[label])
    entry_path, trust_path = tmp_path / "entry.json", tmp_path / "trust_registry.json"
    entry_path.write_text(texts["entry"], encoding="utf-8")
    trust_path.write_text(texts["trust"], encoding="utf-8")
    return entry_path, trust_path


@pytest.mark.parametrize("label", TOKENS)
@pytest.mark.parametrize("where", ["entry", "trust"])
def test_the_registry_entry_and_the_trust_registry(tmp_path: Path, label: str, where: str) -> None:
    entry_path, trust_path = _documents(tmp_path, label, where)
    report = verify_path(
        BUNDLE, registry_entry_path=entry_path, trust_registry_path=trust_path, evaluation_time=EVALUATION_TIME
    ).to_dict()
    expected = (ENTRY if where == "entry" else TRUST)[label]
    assert (_summary(report), _refusals(report)) == (expected, [REFUSAL[label]] if REFUSAL[label] else [])


def test_the_command_line_never_exits_3(tmp_path: Path) -> None:
    codes = {}
    for label in TOKENS:
        bundle = Bundle().seal()
        bundle.members["canonical_input.json"] = with_raw_member(
            bundle.json("canonical_input.json"), "not_projected", TOKENS[label]
        )
        bundle.seal(p1=False)
        root = bundle.write(tmp_path / label / "bundle")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            codes[label] = main([str(root), "--json"])
    assert codes == {label: MEMBER[label][1] for label in TOKENS}


@pytest.mark.parametrize("label", ["nonzero-tiny-exponent", "nonzero-huge-exponent"])
def test_a_trust_root_or_vocabulary_document_is_a_usage_error(tmp_path: Path, label: str) -> None:
    document = tmp_path / "document.json"
    document.write_text('{"x":' + TOKENS[label] + "}", encoding="utf-8")
    entry_path, trust_path = _documents(tmp_path, "zero-huge-exponent", "none")
    base = [str(BUNDLE), "--registry-entry", str(entry_path), "--trust-registry", str(trust_path), "--json"]
    codes = {}
    for option in ("--trust-root", "--workflow-vocabulary"):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            codes[option] = main([*base, option, str(document)])
    assert codes == {"--trust-root": 64, "--workflow-vocabulary": 64}
