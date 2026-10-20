"""Strict JSON parse boundary: duplicate keys, non-finite numbers, value-based
safe-integer rule.

Protocol rule (spec: canonicalization-and-hashing.md, "Input strictness"):
duplicate object member names and non-finite numbers are invalid at parse
time; a number is read as its nearest IEEE 754 binary64 value, and any number
whose value is an integer with magnitude beyond 2^53 - 1 is invalid regardless
of spelling. These tests lock the verify-side
enforcement, including end-to-end: a bundle whose manifest contains a
duplicated key with the *same* value must fail at parse, not be silently repaired.
It parses (last-wins) to an object whose canonical hash still matches the stored
one, so only strictness refuses it.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from bundle_builder import Bundle, nested_text, with_raw_member

from loquitur.verify.canonical import (
    CanonicalizationError,
    JsonLoadError,
    canonical_json_bytes,
    loads_json_bytes,
)
from loquitur.verify.runner import exit_code_for_status, verify_path

FIXTURES = Path(__file__).parent / "fixtures"


# ---------- unit: strict parse ----------


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a": 1, "a": 2}',
        b'{"outer": {"k": 1, "k": 2}}',
        b'[{"x": 1, "x": 1}]',
        b'{"a": 1, "\\u0061": 2}',  # escape-equivalent duplicate: "\u0061" == "a"
    ],
)
def test_duplicate_object_keys_rejected(payload: bytes) -> None:
    with pytest.raises(JsonLoadError, match="duplicate_json_key"):
        loads_json_bytes(payload, name="probe")


@pytest.mark.parametrize("payload", [b'{"n": NaN}', b'{"n": Infinity}', b'{"n": -Infinity}'])
def test_non_finite_constants_rejected(payload: bytes) -> None:
    with pytest.raises(JsonLoadError, match="non_finite_json_number"):
        loads_json_bytes(payload, name="probe")


def test_clean_document_still_loads() -> None:
    assert loads_json_bytes(b'{"a": 1, "b": {"a": 1}}', name="probe") == {"a": 1, "b": {"a": 1}}


def test_sibling_objects_may_repeat_key_names() -> None:
    value = loads_json_bytes(b'[{"k": 1}, {"k": 2}]', name="probe")
    assert value == [{"k": 1}, {"k": 2}]


# ---------- unit: value-based safe-integer rule ----------


@pytest.mark.parametrize(
    "value",
    [1e16, float(2**53), -1e300, 2**53, -(2**53)],
    ids=["float-1e16", "float-2^53", "float--1e300", "int-2^53", "int--2^53"],
)
def test_integer_valued_numbers_beyond_safe_range_rejected(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"n": value})


@pytest.mark.parametrize(
    "value, expected",
    [
        (9007199254740991, b'{"n":9007199254740991}'),
        (9007199254740991.0, b'{"n":9007199254740991}'),
        (0.5, b'{"n":0.5}'),
    ],
)
def test_safe_and_fractional_numbers_accepted(value: object, expected: bytes) -> None:
    assert canonical_json_bytes({"n": value}) == expected


# ---------- unit: the number model is binary64, and rounding is refused ----------


@pytest.mark.parametrize(
    "spelled",
    [
        b"2.0000000000000001",  # the nearest binary64 value is 2
        b"9007199254740991.4",  # read as 2^53 - 1, which it does not spell
        b"4.9e-325",  # below the smallest subnormal: read as 0
    ],
)
def test_a_number_spelling_more_than_its_binary64_value_is_refused(spelled: bytes) -> None:
    """canonicalization-and-hashing.md, "No excess precision": rounding is refused, not applied."""
    with pytest.raises(JsonLoadError, match="^json_excess_precision:probe$"):
        loads_json_bytes(b'{"n": ' + spelled + b"}", name="probe")


@pytest.mark.parametrize(
    "spelled, value",
    [(b"2", 2), (b"2.0", 2.0), (b"9007199254740991.0", 9007199254740991.0), (b"5e-324", 5e-324), (b"1E2", 100.0)],
)
def test_a_number_spelling_its_binary64_value_is_read_as_it(spelled: bytes, value: float) -> None:
    assert loads_json_bytes(b'{"n": ' + spelled + b"}", name="probe") == {"n": value}


@pytest.mark.parametrize(
    "spelled, reason",
    [
        (b"9007199254740992.5", "json_excess_precision"),  # read as 2^53, which it does not spell
        (b"9007199254740993", "json_integer_outside_safe_range"),  # read as 2^53, which rule 2 refuses
        (b"1.5e300", "json_integer_outside_safe_range"),
        (b"1e400", "non_finite_json_number"),  # its nearest binary64 value is infinite
    ],
)
def test_the_rules_read_the_binary64_value_not_the_digits(spelled: bytes, reason: str) -> None:
    with pytest.raises(JsonLoadError, match=reason):
        loads_json_bytes(b'{"n": ' + spelled + b"}", name="probe")


# ---------- end-to-end: strictness is the only defense for same-value duplicates ----------


def _write_manifest_with_duplicate_key(manifest_path: Path) -> None:
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = list(obj.items())
    first_key, first_value = items[0]
    parts = [
        f"{json.dumps(first_key)}: {json.dumps(first_value)}",
        f"{json.dumps(first_key)}: {json.dumps(first_value)}",
    ]
    parts += [f"{json.dumps(k)}: {json.dumps(v)}" for k, v in items[1:]]
    duplicated = "{" + ", ".join(parts) + "}"
    # Sanity: under last-wins this parses to the ORIGINAL object, so every hash
    # in the bundle still matches. Only parse-time strictness can reject it.
    assert json.loads(duplicated) == obj
    manifest_path.write_text(duplicated, encoding="utf-8")


def test_bundle_with_duplicate_manifest_key_fails_closed(tmp_path: Path) -> None:
    bundle = tmp_path / "valid_bundle"
    shutil.copytree(FIXTURES / "valid_bundle", bundle)
    _write_manifest_with_duplicate_key(bundle / "manifest.json")

    report = verify_path(bundle)
    assert report.status == "OFFLINE_FAIL"
    assert exit_code_for_status(report.status) == 1


# ---------- input strictness rules 2 to 4 and the depth bound, at load ----------
#
# Rules 2 to 4 hold at load, not only in the canonicalizer, which sees only the part of a
# document that is hashed: 1e400 outside the P1 projection would verify PASS, and inside
# the manifest or the envelope it would escape verify_path as CanonicalizationError and
# make the CLI exit 3. Depth is bounded by the scan, not by the interpreter stack, where
# 500 levels stop the canonicalizer, 1000 the decoder, and a host's recursion limit moves
# both.
#
# Rows that hold either way (20000 levels fail in the decoder, documents inside the bounds
# load) run in the same test as the rows the load-time rules refuse, so each test fails
# without those rules.


_STRICT_LOAD_ROWS = dict(
    zip(
        [
            "1e400",
            "minus-1e400",
            "unsafe-int",
            "minus-2p53",
            "1e16",
            "2p53-float",
            "nested-1e300",
            "lone-high",
            "lone-low-after-text",
            "lone-key",
            "reversed-pair",
            "depth-65",
            "object-depth-65",
            "depth-600",
            "depth-20000",
        ],
        [
            ('{"n": 1e400}', "non_finite_json_number"),
            ('{"n": -1e400}', "non_finite_json_number"),
            ('{"n": 9007199254740993}', "json_integer_outside_safe_range"),
            ('{"n": -9007199254740992}', "json_integer_outside_safe_range"),
            ('{"n": 1e16}', "json_integer_outside_safe_range"),
            ('{"n": 9007199254740992.0}', "json_integer_outside_safe_range"),
            ('{"n": [1, {"m": 1e300}]}', "json_integer_outside_safe_range"),
            ('{"s": "\\ud800"}', "json_lone_surrogate"),
            ('{"s": "x\\udfff"}', "json_lone_surrogate"),
            ('{"\\udc00x": 1}', "json_lone_surrogate"),
            ('["\\ude00\\ud83d"]', "json_lone_surrogate"),
            ("[" * 65 + "]" * 65, "json_nesting_too_deep"),
            ('{"a":' + "[" * 64 + "]" * 64 + "}", "json_nesting_too_deep"),
            ("[" * 600 + "]" * 600, "json_nesting_too_deep"),
            ("[" * 20000 + "]" * 20000, "json_nesting_too_deep"),
        ],
        strict=True,
    )
)
_INSIDE_THE_BOUNDS = {
    "max-safe-int": '{"n": 9007199254740991}',
    "max-safe-float": '{"n": -9007199254740991.0}',
    "fraction": '{"n": 1.5}',
    "tiny": '{"n": 1e-300}',
    "surrogate-pair": '{"s": "\\ud83d\\ude00"}',
    "brackets-in-string": '{"s": "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["}',
    "depth-64": "[" * 64 + "]" * 64,
    "object-64": '{"a":' + "[" * 63 + "]" * 63 + "}",
}


def _load_outcome(text: str) -> str:
    try:
        loads_json_bytes(text.encode("utf-8"), name="probe")
    except JsonLoadError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001 - an escaping exception is what a refusal row detects
        return f"escaped {type(exc).__name__}"
    return "loaded"


def test_strictness_violations_are_refused_at_load_and_documents_inside_the_bounds_load() -> None:
    got = {label: _load_outcome(text) for label, (text, _code) in _STRICT_LOAD_ROWS.items()}
    mismatched = {
        label: outcome
        for label, outcome in got.items()
        if re.fullmatch(f"{_STRICT_LOAD_ROWS[label][1]}(:[a-z]+)?:probe", outcome) is None
    }
    assert mismatched == {}
    assert {label: _load_outcome(text) for label, text in _INSIDE_THE_BOUNDS.items()} == dict.fromkeys(
        _INSIDE_THE_BOUNDS, "loaded"
    )


def _decoder_out_of_stack(monkeypatch: pytest.MonkeyPatch, marker: str) -> list[str]:
    """Make the loader's decoder raise RecursionError on any text carrying ``marker``.

    This is the state a host reaches when its recursion limit cannot hold a document the
    protocol admits. Lowering ``sys.setrecursionlimit`` does not reach it on every version: the
    C decoder honors the limit under Python 3.11 and ignores it from 3.12. Raising the
    decoder's error directly is the same state on every version. Returns the texts the decoder
    was handed.
    """
    import loquitur.verify.canonical as canonical

    real_loads = json.loads
    seen: list[str] = []

    def loads(text: str, **kwargs: object) -> object:
        if marker in text:
            seen.append(text)
            raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
        return real_loads(text, **kwargs)

    monkeypatch.setattr(canonical, "json", SimpleNamespace(loads=loads, JSONDecodeError=json.JSONDecodeError))
    return seen


def test_the_depth_bound_is_decided_before_the_decoder_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """65 and 150 levels are refused by the scan: the decoder, out of stack here, never sees them."""
    seen = _decoder_out_of_stack(monkeypatch, "[")
    for depth in (65, 150):
        with pytest.raises(JsonLoadError, match="json_nesting_too_deep:probe$"):
            loads_json_bytes(("[" * depth + "]" * depth).encode(), name="probe")
    assert seen == []


def test_a_decoder_out_of_stack_on_an_admitted_document_is_a_host_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A RecursionError on a document within the bound propagates; it is never a nesting code.

    It is not refused as ``json_nesting_too_deep``, a rule the 64-level document keeps, which
    would make the outcome depend on the recursion limit and the interpreter version.
    """
    seen = _decoder_out_of_stack(monkeypatch, "[")
    text = "[" * 64 + "]" * 64
    with pytest.raises(RecursionError):
        loads_json_bytes(text.encode(), name="probe")
    assert seen == [text]


def test_a_canonicalizer_out_of_stack_on_an_admitted_value_is_a_host_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same for canonical_json_bytes: 65 levels is refused by the bound, 64 out of stack propagates."""
    import loquitur.verify.canonical as canonical

    def exhausted(value: object) -> bytes:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(canonical.rfc8785, "dumps", exhausted)
    with pytest.raises(CanonicalizationError, match="nesting_too_deep"):
        canonical_json_bytes(json.loads(nested_text(65)))
    with pytest.raises(RecursionError):
        canonical_json_bytes(json.loads(nested_text(64)))


_HOSTILE_VALUES = {
    "1e400": "1e400",
    "unsafe-int": "9007199254740993",
    "1e16": "1e16",
    "2p53-float": "9007199254740992.0",
    "lone-surrogate-value": '"\\ud800"',
    "depth-65": nested_text(65),
    "depth-600": nested_text(600),
    "depth-20000": nested_text(20000),
}
_EXPECTED_CODE = {
    "1e400": "non_finite_json_number",
    "unsafe-int": "json_integer_outside_safe_range",
    "1e16": "json_integer_outside_safe_range",
    "2p53-float": "json_integer_outside_safe_range",
    "lone-surrogate-value": "json_lone_surrogate",
    "lone-surrogate-key": "json_lone_surrogate",
    "depth-65": "json_nesting_too_deep",
    "depth-600": "json_nesting_too_deep",
    "depth-20000": "json_nesting_too_deep",
}
# (member, key the hostile value is written under). canonical_input.json's key is outside
# the P1 projection, so nothing that member contributes to a digest is affected by it.
_MEMBERS = {
    "manifest.json": "schema_version",
    "p1.json": "ih",
    "canonical_input.json": "not_projected",
    "envelope_env1.json": "asset_id",
    "verification_receipt.json": "status",
}


def _hostile_bundle(tmp_path: Path, member: str, label: str) -> tuple[Path, Path | None]:
    bundle = Bundle().seal()
    entry = None
    if member == "verification_receipt.json":
        entry = bundle.link_entry(tmp_path / "entry.json")
    obj = bundle.json(member)
    if label == "lone-surrogate-key":
        # json.dumps escapes the key, so the member carries the six characters \udc00.
        raw_bytes = with_raw_member(obj, "\udc00x", "1")
    else:
        raw_bytes = with_raw_member(obj, _MEMBERS[member], _HOSTILE_VALUES[label])
    bundle.members[member] = raw_bytes
    if member == "canonical_input.json":
        # Reseal everything but P1, so the hostile value is the only thing wrong.
        bundle.seal(p1=False)
    return bundle.write(tmp_path / "bundle"), entry


@pytest.mark.parametrize("member", sorted(_MEMBERS))
def test_a_hostile_member_fails_the_run_and_never_escapes(tmp_path: Path, member: str) -> None:
    from loquitur.verify import cli

    failures = {}
    for label in sorted(_EXPECTED_CODE):
        root, entry = _hostile_bundle(tmp_path / label, member, label)
        kwargs = {"registry_entry_path": entry} if entry else {}
        try:
            payload = verify_path(root, **kwargs).to_dict()
        except Exception as exc:  # noqa: BLE001 - an escape is one of the defects a row detects
            failures[label] = f"escaped {type(exc).__name__}"
            continue
        argv = [str(root), "--json"] + (["--registry-entry", str(entry)] if entry else [])
        observed = (
            payload["status"],
            payload["outcome"]["category"] != "internal_error",
            _EXPECTED_CODE[label] in json.dumps(payload),
            cli.main(argv),
        )
        if observed != ("OFFLINE_FAIL", True, True, 1):
            failures[label] = observed
    assert failures == {}


def test_a_value_outside_the_projection_is_still_refused(tmp_path: Path) -> None:
    """1e400 outside the projection is refused.

    Input strictness covers the whole canonical input, not only the values the projection hashes.
    """
    root, _entry = _hostile_bundle(tmp_path / "unprojected", "canonical_input.json", "1e400")
    report = verify_path(root)
    assert report.status == "OFFLINE_FAIL"
    assert report.to_dict()["checks"]["canonical_input_present"] is True
    assert report.to_dict()["checks"]["p1_input_hash"] is False
    # A projected value exactly at the depth bound still verifies.
    bundle = Bundle()
    bundle.edit("canonical_input.json", lambda o: o.update(deep=json.loads(nested_text(63))))
    bundle.edit("p1.json", lambda p: p.update(ik=p["ik"] + ["deep"]))
    root = bundle.reproject().seal().write(tmp_path / "projected" / "bundle")
    assert verify_path(root).status == "OFFLINE_OK"


def test_a_hostile_member_fails_whatever_the_decoder_can_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A 100-level member is refused by the scan, so a decoder out of stack does not decide it."""
    bundle = Bundle().seal()
    bundle.members["manifest.json"] = with_raw_member(bundle.json("manifest.json"), "schema_version", nested_text(100))
    root = bundle.write(tmp_path / "bundle")
    seen = _decoder_out_of_stack(monkeypatch, "[[[[")
    report = verify_path(root)
    assert seen == []
    assert report.status == "OFFLINE_FAIL"
    assert "json_nesting_too_deep:manifest.json" in json.dumps(report.to_dict())


def test_a_host_out_of_stack_on_a_valid_bundle_is_an_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A valid bundle whose 64-level member the host cannot decode: no verdict, exit 3.

    The library raises the host's RecursionError; the command line reports INTERNAL_ERROR with
    exit 3, the code report-contract.md reserves for a fault of the tool. The member keeps
    rule 6, so neither may name a nesting code, and no status may be a verdict on the evidence.
    """
    from loquitur.verify import cli

    bundle = Bundle()
    bundle.edit("canonical_input.json", lambda o: o.update(deep=json.loads(nested_text(63))))
    bundle.edit("p1.json", lambda p: p.update(ik=p["ik"] + ["deep"]))
    root = bundle.reproject().seal().write(tmp_path / "bundle")
    assert verify_path(root).status == "OFFLINE_OK"
    _decoder_out_of_stack(monkeypatch, "[" * 60)
    with pytest.raises(RecursionError):
        verify_path(root)
    capsys.readouterr()
    assert cli.main([str(root), "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert (payload["status"], payload["exit_code"]) == ("INTERNAL_ERROR", 3)
    assert [error["code"] for error in payload["errors"]] == ["internal_error"]
    assert "nesting" not in json.dumps(payload)


def test_a_host_out_of_stack_on_the_trust_root_document_is_an_internal_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The trust-root document is read before the bundle; the same host fault there is exit 3 too.

    The command line's internal-error boundary holds the reading of the trust-root document as
    well as the bundle's verification: outside it, the fault would end the process with a
    traceback and exit 1. The same run with a decoder that can hold the document ends in a
    verdict.
    """
    from authorization_kit import BUNDLE

    from loquitur.verify import cli

    fixtures = Path(__file__).parent / "fixtures"
    argv = [
        str(BUNDLE),
        "--json",
        "--registry-entry",
        str(fixtures / "authorization_valid_registry_entry.json"),
        "--trust-registry",
        str(fixtures / "authorization_valid_trust_registry.json"),
        "--evaluation-time",
        "2026-05-10T00:00:00Z",
        "--trust-root",
        str(fixtures / "authorization_quickstart_trust_root.json"),
    ]
    assert cli.main(argv) in (0, 1, 2)
    capsys.readouterr()
    roots = (fixtures / "authorization_quickstart_trust_root.json").read_text(encoding="utf-8")
    _decoder_out_of_stack(monkeypatch, roots[:40])
    assert cli.main(argv) == 3
    payload = json.loads(capsys.readouterr().out)
    assert (payload["status"], payload["exit_code"]) == ("INTERNAL_ERROR", 3)
    assert [error["code"] for error in payload["errors"]] == ["internal_error"]


def test_a_hostile_member_inside_a_zip_fails_the_run(tmp_path: Path) -> None:
    import zipfile

    bundle = Bundle().seal()
    bundle.members["manifest.json"] = with_raw_member(bundle.json("manifest.json"), "schema_version", "1e400")
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, data in bundle.members.items():
            zf.writestr(f"bundle/{name}", data)
    report = verify_path(archive)
    assert report.status == "OFFLINE_FAIL"
    assert report.to_dict()["outcome"]["category"] != "internal_error"


def test_a_host_registry_entry_nested_too_deep_fails_the_run(tmp_path: Path) -> None:
    got = {}
    for depth in (65, 20000):
        bundle = Bundle().seal()
        root = bundle.write(tmp_path / str(depth) / "bundle")
        entry = bundle.link_entry(tmp_path / str(depth) / "entry.json")
        text = entry.read_text(encoding="utf-8")
        entry.write_text(text[:-1] + ',"x":' + nested_text(depth - 1) + "}", encoding="utf-8")
        payload = verify_path(root, registry_entry_path=entry).to_dict()
        got[depth] = (payload["status"], "json_nesting_too_deep" in json.dumps(payload))
    assert got == {65: ("OFFLINE_FAIL", True), 20000: ("OFFLINE_FAIL", True)}


def test_the_cli_reads_the_trust_root_document_strictly(tmp_path: Path) -> None:
    """The CLI reads the trust-root document strictly: json.loads would take the last of two duplicates."""
    from loquitur.verify import cli

    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    entry = bundle.link_entry(tmp_path / "entry.json")
    key = "04" + "11" * 64
    roots = tmp_path / "roots.json"
    item = (
        '{"key_id":"r1","key_type":"secp256k1","public_key_hex":"%s",'
        '"not_before":"2020-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z"}'
    )
    head = '{"object_type":"trust_root_document","schema_version":"v1",'
    roots.write_text(head + '"roots":[' + item % key + '],"roots":[' + item % key + "]}", encoding="utf-8")
    trust = FIXTURES / "authorization_valid_trust_registry.json"
    argv = [
        str(root),
        "--json",
        "--registry-entry",
        str(entry),
        "--trust-registry",
        str(trust),
        "--trust-root",
        str(roots),
    ]
    assert cli.main(argv) == 64


def test_an_envelope_that_is_not_strict_json_leaves_the_issuer_signature_status_as_evaluated(tmp_path: Path) -> None:
    """checks.registry_signature reports the issuer signature the trust-registry step evaluated.

    The signature is the registry entry's, and an authorization run evaluates it whatever the envelope holds,
    so beside an envelope that is not strict JSON the check and the report's
    trust_registry.signature_status both read VALID_SIGNATURE, as in the TypeScript verifier;
    report-contract.md section 6 keeps UNSUPPORTED for a run that evaluated no signature.
    """
    from authorization_kit import BUNDLE, IssuerKey, authorization_material, write_json

    bundle = tmp_path / "bundle"
    shutil.copytree(BUNDLE, bundle)
    (bundle / "envelope_env1.json").write_bytes(b'{"not": "closed"')
    entry, registry = authorization_material(IssuerKey())
    report = verify_path(
        bundle,
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
        trust_registry_path=write_json(tmp_path / "trust_registry.json", registry),
    ).to_dict()
    assert report["outcome"]["reason"] == "envelope_verification_failed"
    assert report["checks"]["envelope_present"] is True
    assert report["trust_registry"]["signature_status"] == "VALID_SIGNATURE"
    assert report["checks"]["registry_signature"] == "VALID_SIGNATURE"
