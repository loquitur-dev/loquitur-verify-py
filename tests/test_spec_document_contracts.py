"""Every row of the member appendix, executed against this verifier.

loquitur-protocol docs/specification/document-contracts.md lists every member of every document
a verifier loads: whether it is required, its type, the values it may take, example values that
break it, and the outcome a run reports when it is broken. This module reads those tables from
the sibling checkout (spec_tables.py) and runs each row: the member is removed when it is
required, each refused value is put in its place, and the report's normative surface (status,
verdict, exit code, `outcome.reason` and the ordered error codes) is compared with the
outcome the appendix gives.

The locks matter as much as the refusals: a member that is not required is removed and the run
must be unchanged, and a member whose type admits `null` is set to `null` and the run must be
unchanged. Without them a verifier that refused everything would pass.

The sibling is absent in a single-repository clone. There every test skips, with the reason, and
the module still collects them: reading the appendix at import and skipping as a whole would
make it a module that collected nothing, which the CI job `test-base` fails. When
LOQUITUR_REQUIRE_SIBLINGS is set the absence fails instead, at collection (siblings.py).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import IssuerKey, fixture_entry, fixture_trust_registry, write_json
from bundle_builder import Bundle, jcs, sha
from siblings import siblings_required
from spec_tables import SPECIFICATION, code, codes, document, sections, tables

from loquitur.verify.registered_vocabularies import REGISTERED_VOCABULARIES
from loquitur.verify.runner import verify_path

APPENDIX = "document-contracts.md"
MEMBER_HEADER = ["member", "required", "type", "value", "refused", "outcome", "rule"]
CASE_HEADER = ["case", "outcome", "rule"]
OUTCOME_HEADER = ["outcome", "`status`", "`verdict`", "`outcome.reason`", "`errors`", "exit", "rule"]
INPUT_HEADER = ["input", "required", "form", "refused", "outcome", "rule"]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ABSENT = object()
# Whether the tables below are read at collection. Without the sibling, and without the
# workspace requiring it, they are empty: each parametrized test then collects as one skipped
# item, and the fixture below skips every other test with the reason. When the workspace
# requires the sibling, reading it anyway fails the collection by name.
APPENDIX_READABLE = (SPECIFICATION / APPENDIX).is_file() or siblings_required()


@pytest.fixture(autouse=True)
def _the_appendix_is_present() -> None:
    document(APPENDIX)


# The section of the appendix each document's rows live in, by the start of the section title.
DOCUMENTS = {
    "`manifest.json`": "manifest",
    "`p1.json`": "p1",
    "`canonical_input.json`": "canonical_input",
    "The digest sidecars": "sidecar",
    "`envelope_env1.json`": "envelope",
    "`verification_receipt.json`": "receipt",
    "The registry entry": "entry",
    "The trust registry": "trust",
    "The trust-root document": "roots",
    "The registered vocabulary document": "vocabulary",
}
# A well-formed parent for the members nested under one. These are examples, not rules: the
# rules are the rows of the members themselves.
VALID_ANCHOR = {"method": "blockchain_transaction", "system": "testnet-v1.0", "anchor_reference": "tx-1"}
VALID_SIGNATURE = {
    "algorithm": "secp256k1_ecdsa_sha256",
    "key_id": "demo-key-link",
    "payload_id": "registry_entry_signing_payload_v2",
    "payload_version": 2,
    "signature": "ab" * 64,
}
VALID_ROOT = {
    "key_id": "root-1",
    "key_type": "secp256k1",
    "public_key_hex": "04" + "ab" * 64,
    "not_before": "2020-01-01T00:00:00Z",
    "not_after": "2030-01-01T00:00:00Z",
    "status": "active",
}


# ---------------------------------------------------------------- reading the appendix


def _rows(header: list[str]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    if not APPENDIX_READABLE:
        return out
    for title, body in sections(document(APPENDIX)).items():
        for cells, rows in tables(body):
            if cells == header:
                out.setdefault(title, []).extend(dict(zip(cells, row, strict=True)) for row in rows)
    return out


def _document_of(title: str) -> str | None:
    for prefix, name in DOCUMENTS.items():
        if title.split(". ", 1)[-1].startswith(prefix):
            return name
    return None


def member_rows() -> list[tuple[str, dict[str, str]]]:
    return [(_document_of(title), row) for title, rows in _rows(MEMBER_HEADER).items() for row in rows]


def case_rows() -> list[tuple[str, dict[str, str]]]:
    return [(_document_of(title), row) for title, rows in _rows(CASE_HEADER).items() for row in rows]


def outcomes() -> dict[str, dict[str, Any]]:
    """The appendix's outcome table as {id: the normative surface of a run}."""
    out = {}
    for _title, rows in _rows(OUTCOME_HEADER).items():
        for row in rows:
            if row["`status`"] == "none":
                out[code(row["outcome"])] = {"exit_code": 64, "report": False}
                continue
            out[code(row["outcome"])] = {
                "status": code(row["`status`"]),
                # A non-evidence status has no verdict (report-contract.md section 3).
                "verdict": None if code(row["`verdict`"]) == "null" else code(row["`verdict`"]),
                "exit_code": int(code(row["exit"])),
                "reason": code(row["`outcome.reason`"]),
                "errors": [] if row["`errors`"] == "none" else [code(row["`errors`"])],
            }
    assert out, "the appendix carries no outcome table"
    return out


OUTCOMES = outcomes() if APPENDIX_READABLE else {}


# The normative report surface this suite compares, keyed as this module keys it and named as
# `document-contracts.md` §14 names it. One mapping, so the section's cell and the fields a run
# is actually compared on cannot drift apart.
SURFACE_FIELDS = {
    "status": "status",
    "verdict": "verdict",
    "exit_code": "exit_code",
    "reason": "outcome.reason",
    "errors": "errors[].code",
}


def surface(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": report["status"],
        "verdict": report["verdict"],
        "exit_code": report["exit_code"],
        "reason": report["outcome"]["reason"],
        "errors": [error["code"] for error in report["errors"]],
    }


def refused_values(row: dict[str, str]) -> list[Any]:
    if row["refused"] == "-":
        return []
    return [span if span.startswith("<") else json.loads(span) for span in codes(row["refused"])]


def nullable(row: dict[str, str]) -> bool:
    return "`null`" in row["type"]


# One value of each JSON type, for the `type` column of a row (document-contracts.md §1). The
# column is a rule: a value whose type the cell does not admit is refused with the row's
# outcome, and a row whose `value` cell is `-` states no rule beyond its type, so a value of a
# type it admits is accepted. Reading the cell rather than the `refused` examples is what makes
# widening a cell fail: the value moves to the accepted side, where the verifier refuses it.
TYPE_SAMPLE: dict[str, Any] = {
    "null": None,
    "boolean": True,
    "integer": 1,
    "number": 1.5,
    "string": "x",
    "array": [],
    "object": {},
}


def admitted_types(row: dict[str, str]) -> set[str]:
    """The JSON types the row's `type` cell admits; `number` admits `integer` as well."""
    found = {name for name in codes(row["type"]) if name in TYPE_SAMPLE}
    return found | {"integer"} if "number" in found else found


def path_of(row: dict[str, str]) -> str:
    return row["member"].strip("`").replace("[i]", "[0]")


# ---------------------------------------------------------------- applying a mutation


def set_path(node: Any, path: str, value: Any) -> None:
    parts: list[Any] = [
        int(token[1:-1]) if token.startswith("[") else token for token in re.findall(r"[^.\[\]]+|\[\d+\]", path)
    ]
    for part in parts[:-1]:
        node = node[part]
    if value is ABSENT:
        if isinstance(node, list):
            del node[parts[-1]]
        else:
            node.pop(parts[-1], None)
    else:
        node[parts[-1]] = value


def sealed_bundle() -> Bundle:
    return Bundle().seal()


def bundle_with(document_name: str, path: str, value: Any) -> Bundle:
    """The fixture bundle with one member changed, every other digest recomputed."""
    bundle = Bundle()
    if document_name == "p1":
        p1 = bundle.json("p1.json")
        set_path(p1, path, value)
        bundle.set_json("p1.json", p1)
        if path == "ik":
            # An honest producer that changes the projection recomputes the input hash over it.
            # Without this the `ik` row would be testing `ih` instead: every change of the
            # projection, refused or not, would leave the recorded digest behind. A projection
            # no producer could hash (`1`, an object, a number in the list) keeps the
            # digest it had, which is the only thing a producer could have written.
            keys = p1.get("ik")
            if "ik" not in p1 or (isinstance(keys, list) and all(isinstance(key, str) for key in keys)):
                bundle.reproject()
        return bundle.seal()
    if document_name == "canonical_input":
        bundle.members["canonical_input.json"] = value if isinstance(value, bytes) else jcs(value)
        return bundle.seal()
    bundle.seal()
    if document_name == "manifest":
        manifest = bundle.json("manifest.json")
        set_path(manifest, path, value)
        bundle.set_json("manifest.json", manifest)
        return _reseal_over_manifest(bundle)
    if document_name == "envelope":
        envelope = bundle.json("envelope_env1.json")
        set_path(envelope, path, value)
        bundle.set_json("envelope_env1.json", envelope)
        return bundle.reseal_envelope_sidecar()
    if document_name == "receipt":
        receipt = bundle.json("verification_receipt.json")
        set_path(receipt, path, value)
        return bundle.set_json("verification_receipt.json", receipt)
    if document_name == "sidecar":
        digest = bundle.members[path].decode()
        # `value` is a marker of the `refused` column, or the raw bytes a `bytes` row's type
        # run writes as the whole file.
        bundle.members[path] = (
            value
            if isinstance(value, bytes)
            else {
                "<upper>": digest.upper(),
                "<newline>": digest + "\n",
                "<other>": sha(b"another object"),
            }[value].encode()
        )
        # A sidecar may itself be a declared member (`p1.sha256` is), so the manifest's own
        # digests are recomputed over the changed bytes: the manifest still holds, and the
        # sidecar is the only thing that does not. The sidecar under test is never resealed.
        manifest = bundle.json("manifest.json")
        for name in manifest["files"]:
            if name in bundle.members:
                manifest["files"][name] = "sha256:" + sha(bundle.members[name])
        bundle.set_json("manifest.json", manifest)
        if path != "manifest.sha256":
            bundle.members["manifest.sha256"] = bundle.manifest_digest().encode()
        envelope = bundle.json("envelope_env1.json")
        envelope["bundle_manifest_sha256"] = "sha256:" + bundle.manifest_digest()
        bundle.set_json("envelope_env1.json", envelope)
        if path != "envelope.sha256":
            bundle.reseal_envelope_sidecar()
        receipt = bundle.json("verification_receipt.json")
        receipt["manifest_sha256"] = "sha256:" + bundle.manifest_digest()
        return bundle.set_json("verification_receipt.json", receipt)
    raise AssertionError(document_name)


def _reseal_over_manifest(bundle: Bundle) -> Bundle:
    """Recompute what commits to the manifest, leaving the manifest's own members as they are."""
    manifest = bundle.json("manifest.json")
    digest = bundle.manifest_digest()
    bundle.members["manifest.sha256"] = digest.encode()
    if "envelope_env1.json" in bundle.members:
        envelope = bundle.json("envelope_env1.json")
        envelope["bundle_manifest_sha256"] = "sha256:" + digest
        if isinstance(manifest, dict):
            envelope["bundle_id"] = manifest.get("bundle_id")
        bundle.set_json("envelope_env1.json", envelope)
        bundle.reseal_envelope_sidecar()
    if "verification_receipt.json" in bundle.members:
        receipt = bundle.json("verification_receipt.json")
        receipt["manifest_sha256"] = "sha256:" + digest
        bundle.set_json("verification_receipt.json", receipt)
    return bundle


def prepared_entry(bundle: Bundle, path: str) -> dict[str, Any]:
    entry = json.loads((FIXTURES / "link_valid_registry_entry.json").read_text(encoding="utf-8"))
    entry["manifest_hash"] = "sha256:" + bundle.manifest_digest()
    entry["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))
    if path.startswith("anchor."):
        entry["anchor"] = dict(VALID_ANCHOR)
    if path.startswith("signature."):
        entry["signature"] = dict(VALID_SIGNATURE)
    return entry


def run_bundle(tmp_path: Path, bundle: Bundle) -> dict[str, Any]:
    return verify_path(bundle.write(tmp_path / "bundle")).to_dict()


def run_entry(tmp_path: Path, entry: Any) -> dict[str, Any]:
    bundle = sealed_bundle()
    return verify_path(
        bundle.write(tmp_path / "bundle"),
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
    ).to_dict()


def run_trust(tmp_path: Path, change=None) -> dict[str, Any]:
    """An authorization run over the fixture bundle, the entry signed by a key made for this run.

    ``change`` receives the fixture trust registry once that key's public half is in it, and
    returns the document to verify against: the same object changed in place, or another value
    entirely for the cases where the document is not a trust registry at all.
    """
    key = IssuerKey()
    bundle = sealed_bundle()
    entry = fixture_entry()
    entry["manifest_hash"] = "sha256:" + bundle.manifest_digest()
    entry["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))
    key.sign_entry(entry)
    registry: Any = fixture_trust_registry()
    registry["entries"][0]["public_key_hex"] = key.public_key_hex
    if change is not None:
        registry = change(registry)
    return verify_path(
        bundle.write(tmp_path / "bundle"),
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
        trust_registry_path=write_json(tmp_path / "trust.json", registry),
    ).to_dict()


def run_cli(tmp_path: Path, *arguments: str) -> tuple[int, dict[str, Any] | None]:
    bundle = sealed_bundle()
    command = [
        sys.executable,
        "-m",
        "loquitur.verify.cli",
        str(bundle.write(tmp_path / "bundle")),
        "--json",
        *arguments,
    ]
    finished = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=False,
    )
    try:
        return finished.returncode, json.loads(finished.stdout)
    except ValueError:
        return finished.returncode, None


def changed(path: str, value: Any):
    """A ``change`` for run_trust: the document with ``path`` set to ``value``."""

    def apply(registry: dict[str, Any]) -> dict[str, Any]:
        set_path(registry, path, value)
        return registry

    return apply


# ---------------------------------------------------------------- the rows


def _expect(got: dict[str, Any], outcome: str, label: str) -> None:
    assert got == {name: value for name, value in OUTCOMES[outcome].items()}, f"{label}: expected {outcome}"


def _run_member(tmp_path: Path, document_name: str, path: str, value: Any) -> dict[str, Any]:
    if document_name == "entry":
        bundle = sealed_bundle()
        entry = prepared_entry(bundle, path)
        set_path(entry, path, value)
        return surface(run_entry(tmp_path, entry))
    if document_name == "trust":
        return surface(run_trust(tmp_path, changed(path, value)))
    return surface(run_bundle(tmp_path, bundle_with(document_name, path, value)))


def _valid_surface(tmp_path: Path, document_name: str) -> dict[str, Any]:
    """What a run over unmutated material reports, which every lock must reproduce."""
    if document_name == "entry":
        return surface(run_entry(tmp_path, prepared_entry(sealed_bundle(), "")))
    if document_name == "trust":
        return surface(run_trust(tmp_path))
    return surface(run_bundle(tmp_path, sealed_bundle()))


# A refused example of a row that the version gate reads first (section 1a): the value is well
# formed, so the gate fires before the row is reached. The section's own text names this pair
# (registry_entry_signing_payload_v2 with 3 is an unsupported version); the row's example
# predates the gate.
GATED_REFUSALS = {("entry", "signature.payload_version", "3"): "unsupported-version"}


MEMBER_CASES = [
    (document_name, row)
    for document_name, row in member_rows()
    if document_name is not None and document_name not in ("roots", "vocabulary")
]


@pytest.mark.parametrize(
    ("document_name", "row"),
    MEMBER_CASES,
    ids=[f"{name}-{row['member'].strip('`')}" for name, row in MEMBER_CASES],
)
def test_every_refused_value_of_a_row_is_refused(tmp_path: Path, document_name: str, row: dict[str, str]) -> None:
    outcome = code(row["outcome"])
    path = path_of(row)
    for index, value in enumerate(refused_values(row)):
        got = _run_member(tmp_path / f"refused{index}", document_name, path, value)
        expected = GATED_REFUSALS.get((document_name, path, json.dumps(value)), outcome)
        _expect(got, expected, f"{document_name}.{path} = {value!r}")
    if row["required"] == "yes" and row["type"] != "bytes":
        got = _run_member(tmp_path / "absent", document_name, path, ABSENT)
        _expect(got, outcome, f"{document_name}.{path} absent")


@pytest.mark.parametrize(
    ("document_name", "row"),
    [(name, row) for name, row in MEMBER_CASES if row["required"] == "no" or nullable(row)],
    ids=[
        f"{name}-{row['member'].strip('`')}" for name, row in MEMBER_CASES if row["required"] == "no" or nullable(row)
    ],
)
def test_an_optional_member_may_be_absent_and_a_nullable_one_null(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    path = path_of(row)
    if row["member"] == "the document":
        # A row for the document as a whole: what its absence means is its section's case table.
        return
    valid = _valid_surface(tmp_path / "valid", document_name)
    if row["required"] == "no" and row["type"] != "bytes":
        assert _run_member(tmp_path / "absent", document_name, path, ABSENT) == valid, f"{path} may be absent"
    if nullable(row) and row["required"] == "no":
        assert _run_member(tmp_path / "null", document_name, path, None) == valid, f"{path} may be null"


TYPE_CASES = [(name, row) for name, row in MEMBER_CASES if row["type"] != "bytes"]


@pytest.mark.parametrize(
    ("document_name", "row"),
    TYPE_CASES,
    ids=[f"{name}-{row['member'].strip('`')}" for name, row in TYPE_CASES],
)
def test_the_type_cell_of_a_row_decides_every_json_type(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    """Every type the cell refuses is refused; every type it admits is accepted where it may be.

    The `refused` column is a sample of examples someone chose. The `type` cell is the rule, and
    this runs it: one value of each of the seven JSON types, refused with the row's outcome when
    the cell does not admit the type, and (for a row whose `value` cell is `-`, which states no
    rule beyond the type) accepted when it does. Widening a cell therefore fails here rather
    than quietly dropping a case from a column of chosen examples.

    The number of comparisons is asserted, because a loop over the types a cell refuses runs
    nothing at all for a cell that refuses none. Without that assertion a cell widened to admit
    every JSON type passes this test having compared nothing: a claim of coverage that is not
    coverage, which is the defect this whole appendix exists to refuse.
    """
    outcome = code(row["outcome"])
    path = path_of(row)
    admitted = admitted_types(row)
    assert admitted, f"{row['member']}: the type cell names no JSON type"
    valid = _valid_surface(tmp_path / "valid", document_name) if row["value"] == "-" else None
    compared = 0
    for name, value in TYPE_SAMPLE.items():
        if name not in admitted:
            got = _run_member(tmp_path / f"refused-{name}", document_name, path, value)
            _expect(got, outcome, f"{document_name}.{path} = {value!r} ({name})")
            compared += 1
        elif valid is not None and not (name == "null" and row["required"] == "yes"):
            got = _run_member(tmp_path / f"accepted-{name}", document_name, path, value)
            assert got == valid, f"{document_name}.{path} = {value!r} ({name}) is a value the row admits"
            compared += 1
    assert compared, f"{document_name}.{path}: its type cell decided no value, so this compared nothing"


BYTES_CASES = [(name, row) for name, row in MEMBER_CASES if row["type"] == "bytes"]


@pytest.mark.parametrize(
    ("document_name", "row"),
    BYTES_CASES,
    ids=[f"{name}-{row['member'].strip('`')}" for name, row in BYTES_CASES],
)
def test_the_type_cell_of_a_bytes_row_refuses_every_json_type(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    """A `bytes` cell admits no JSON type, and this runs that: every type, as the file's bytes.

    A `bytes` row describes a file rather than a JSON member, so there is no member to give a
    value of some type. Its cell still states a rule, and the rule is that the file is not JSON
    at all: the canonical form of a value of any JSON type, written as the whole file, is
    refused with the row's outcome. Running that is what keeps every member row of the appendix
    under the second check of §1 rather than under an exemption, and it is a comparison the
    `refused` column does not make: that column holds three digest-shaped byte strings.
    """
    outcome = code(row["outcome"])
    path = path_of(row)
    assert not admitted_types(row), f"{row['member']}: a `bytes` cell names no JSON type"
    compared = 0
    for name, value in TYPE_SAMPLE.items():
        got = _run_member(tmp_path / f"json-{name}", document_name, path, jcs(value))
        _expect(got, outcome, f"{document_name}.{path} holds the bytes of {value!r} ({name})")
        compared += 1
    assert compared == len(TYPE_SAMPLE), f"{document_name}.{path}: not every JSON type was written"


# ---------------------------------------------------------------- the case tables


def _undeclare(bundle: Bundle, name: str) -> Bundle:
    manifest = bundle.json("manifest.json")
    manifest["files"].pop(name, None)
    bundle.set_json("manifest.json", manifest)
    return bundle


def _case_bundle(case: str) -> Bundle:
    """The fixture bundle changed as the named case describes, sealed afterwards."""
    bundle = Bundle()
    if case == "manifest-not-an-object":
        bundle.seal()
        bundle.members["manifest.json"] = jcs([1])
        return bundle
    if case == "manifest-schema-version-is-a-later-version":
        bundle.seal()
        manifest = bundle.json("manifest.json")
        manifest["schema_version"] = "loquitur.bundle.v2"
        bundle.set_json("manifest.json", manifest)
        return _reseal_over_manifest(bundle)
    if case == "manifest-declares-a-member-the-bundle-does-not-carry":
        manifest = bundle.json("manifest.json")
        manifest["files"]["absent.json"] = "a" * 64
        bundle.set_json("manifest.json", manifest)
        return _reseal_over_manifest(bundle.seal())
    if case == "manifest-files-map-is-empty":
        bundle.seal()
        manifest = bundle.json("manifest.json")
        manifest["files"] = {}
        bundle.set_json("manifest.json", manifest)
        return _reseal_over_manifest(bundle)
    if case == "manifest-files-map-declares-some-of-the-members":
        # The member stays in the bundle and leaves the map: the file check still holds over
        # what is declared, and completeness is what the run reports.
        bundle.seal()
        _undeclare(bundle, "canonical_input.json")
        return _reseal_over_manifest(bundle)
    if case == "manifest-declares-a-digest-that-is-not-the-members":
        bundle.seal()
        manifest = bundle.json("manifest.json")
        manifest["files"]["p1.json"] = "sha256:" + "a" * 64
        bundle.set_json("manifest.json", manifest)
        return _reseal_over_manifest(bundle)
    if case == "p1-not-an-object":
        bundle.members["p1.json"] = jcs([1])
        return bundle.seal()
    if case == "p1-over-the-canonical-size-bound":
        canonical_input = bundle.json("canonical_input.json")
        for index in range(40):
            canonical_input[f"member_with_a_long_name_{index:03d}"] = index
        bundle.set_json("canonical_input.json", canonical_input)
        p1 = bundle.json("p1.json")
        p1["ik"] = sorted(canonical_input)
        bundle.set_json("p1.json", p1)
        return bundle.reproject().seal()
    if case == "p1-ih-is-not-the-digest-of-the-projection":
        p1 = bundle.json("p1.json")
        p1["ih"] = "sha256:" + "a" * 64
        bundle.set_json("p1.json", p1)
        return bundle.seal()
    if case == "p1-absent":
        bundle.members.pop("p1.json")
        _undeclare(bundle, "p1.json")
        return bundle.seal()
    if case == "canonical-input-declared-and-absent":
        bundle.members.pop("canonical_input.json")
        return bundle.seal()
    if case == "canonical-input-undeclared-and-absent":
        bundle.members.pop("canonical_input.json")
        _undeclare(bundle, "canonical_input.json")
        return bundle.seal()
    if case == "manifest-sidecar-absent":
        bundle.seal()
        bundle.members.pop("manifest.sha256")
        return bundle
    if case == "p1-sidecar-absent":
        bundle.members.pop("p1.sha256")
        _undeclare(bundle, "p1.sha256")
        return bundle.seal(p1=False)
    if case == "envelope-sidecar-absent":
        bundle.seal()
        bundle.members.pop("envelope.sha256")
        return bundle
    if case == "envelope-and-sidecar-absent":
        bundle.seal()
        bundle.members.pop("envelope.sha256")
        bundle.members.pop("envelope_env1.json")
        return bundle
    if case == "envelope-not-an-object":
        bundle.seal()
        bundle.members["envelope_env1.json"] = jcs([1])
        bundle.members["envelope.sha256"] = sha(jcs([1])).encode()
        return bundle
    if case == "envelope-absent-sidecar-present":
        bundle.seal()
        bundle.members.pop("envelope_env1.json")
        return bundle
    if case == "envelope-json-is-an-ordinary-member":
        # The former second envelope name is an undeclared member like any other.
        bundle.seal()
        bundle.members["envelope.json"] = bundle.members["envelope_env1.json"]
        return bundle
    if case == "receipt-not-an-object":
        bundle.seal()
        bundle.members["verification_receipt.json"] = jcs([1])
        return bundle
    if case == "receipt-carries-a-member-the-schema-does-not-name":
        bundle.seal()
        receipt = bundle.json("verification_receipt.json")
        receipt["spare"] = 1
        return bundle.set_json("verification_receipt.json", receipt)
    raise AssertionError(case)


BUNDLE_CASES = {
    "manifest-not-an-object",
    "manifest-schema-version-is-a-later-version",
    "manifest-declares-a-member-the-bundle-does-not-carry",
    "manifest-declares-a-digest-that-is-not-the-members",
    "manifest-files-map-is-empty",
    "manifest-files-map-declares-some-of-the-members",
    "p1-not-an-object",
    "p1-over-the-canonical-size-bound",
    "p1-ih-is-not-the-digest-of-the-projection",
    "p1-absent",
    "canonical-input-declared-and-absent",
    "canonical-input-undeclared-and-absent",
    "manifest-sidecar-absent",
    "p1-sidecar-absent",
    "envelope-sidecar-absent",
    "envelope-and-sidecar-absent",
    "envelope-not-an-object",
    "envelope-absent-sidecar-present",
    "envelope-json-is-an-ordinary-member",
    "receipt-not-an-object",
    "receipt-carries-a-member-the-schema-does-not-name",
}
ENTRY_CASES: dict[str, Any] = {
    "entry-not-an-object": [1],
    "entry-is-json-null": None,
    "entry-carries-a-member-the-schema-does-not-name": {"spare": 1},
    "entry-verdict-is-not-the-verdict-its-reason-codes-derive": {"verdict": "WARN"},
}
TRUST_CASES = {
    "trust-registry-not-an-object": lambda registry: [1],
    "trust-registry-carries-a-member-the-schema-does-not-name": changed("spare", 1),
    "trust-registry-entry-is-not-an-object": changed("entries[0]", "x"),
}


def _vocabulary_case(case: str) -> bytes | Any:
    """The workflow vocabulary changed as a case of section 15 describes, and the option it is given to."""
    document = json.loads(REGISTERED_VOCABULARIES["workflow"])
    first = next(iter(document["values"].values()))
    if case == "vocabulary-not-an-object":
        return [document]
    if case == "vocabulary-schema-version-is-a-later-version":
        document["schema_version"] = "v2"
    elif case == "vocabulary-carries-a-member-the-format-does-not-name":
        document["note"] = "x"
    elif case == "vocabulary-value-carries-a-member-the-format-does-not-name":
        first["note"] = "x"
    elif case == "vocabulary-names-a-value-twice":
        name = next(iter(document["values"]))
        text = json.dumps(first)
        return REGISTERED_VOCABULARIES["workflow"].replace(
            f'"{name}": {{'.encode(), f'"{name}": {text},\n    "{name}": {{'.encode(), 1
        )
    elif case == "vocabulary-asset-types-on-a-value-of-another-kind":
        document = json.loads(REGISTERED_VOCABULARIES["asset_type"])
        next(iter(document["values"].values()))["asset_types"] = ["fund_nav"]
        return ("--asset-type-vocabulary", document)
    elif case != "vocabulary-registers-another-kind":
        raise AssertionError(case)
    if case == "vocabulary-registers-another-kind":
        return ("--asset-type-vocabulary", document)
    return document


VOCABULARY_CASES = {
    "vocabulary-not-an-object",
    "vocabulary-registers-another-kind",
    "vocabulary-schema-version-is-a-later-version",
    "vocabulary-carries-a-member-the-format-does-not-name",
    "vocabulary-value-carries-a-member-the-format-does-not-name",
    "vocabulary-names-a-value-twice",
    "vocabulary-asset-types-on-a-value-of-another-kind",
}
ALL_CASES = BUNDLE_CASES | set(ENTRY_CASES) | set(TRUST_CASES) | VOCABULARY_CASES


def test_every_case_of_the_appendix_is_executed_here() -> None:
    """A case the appendix names and this module does not run would pass by not being run."""
    named = {code(row["case"]) for _document, row in case_rows()}
    assert named == ALL_CASES, sorted(named ^ ALL_CASES)


CASE_ROWS = [(code(row["case"]), code(row["outcome"])) for _document, row in case_rows()]


@pytest.mark.parametrize(("case", "outcome"), CASE_ROWS, ids=[case for case, _ in CASE_ROWS])
def test_every_case_of_the_appendix_has_its_outcome(tmp_path: Path, case: str, outcome: str) -> None:
    if case in VOCABULARY_CASES:
        assert OUTCOMES[outcome] == {"exit_code": 64, "report": False}, case
        given = _vocabulary_case(case)
        option, document = given if isinstance(given, tuple) else ("--workflow-vocabulary", given)
        assert _run_vocabulary(tmp_path, option, document) == (64, None), case
        return
    if case in BUNDLE_CASES:
        got = surface(run_bundle(tmp_path, _case_bundle(case)))
    elif case in ENTRY_CASES:
        value = ENTRY_CASES[case]
        entry = prepared_entry(sealed_bundle(), "")
        if isinstance(value, dict):
            entry.update(value)
        else:
            entry = value
        got = surface(run_entry(tmp_path, entry))
    else:
        got = surface(run_trust(tmp_path, TRUST_CASES[case]))
    _expect(got, outcome, case)


# ---------------------------------------------------------------- the trust-root document


ROOT_ROWS = [(document_name, row) for document_name, row in member_rows() if document_name == "roots"]


def _root_document(row: dict[str, str], value: Any) -> Any:
    member = row["member"].strip("`")
    if member == "the document":
        return value
    if member == "roots":
        return root_document(value)
    root = dict(VALID_ROOT)
    set_path(root, member.removeprefix("roots[i]."), value)
    return root_document([root])


def root_document(roots: Any) -> dict[str, Any]:
    """A trust-root document of this version around ``roots`` (trust-root.md section 3)."""
    document = {"object_type": "trust_root_document", "schema_version": "v1", "roots": roots}
    if roots is ABSENT:
        del document["roots"]
    return document


@pytest.mark.parametrize(
    ("document_name", "row"), ROOT_ROWS, ids=[row["member"].strip("`") for _name, row in ROOT_ROWS]
)
def test_every_refused_trust_root_document_is_refused_by_the_command_line(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    outcome = OUTCOMES[code(row["outcome"])]
    assert outcome == {"exit_code": 64, "report": False}, row
    for index, value in enumerate(refused_values(row)):
        roots = write_json(tmp_path / f"roots{index}.json", _root_document(row, value))
        exit_code, report = run_cli(
            tmp_path / f"run{index}",
            "--registry-entry",
            str(FIXTURES / "authorization_valid_registry_entry.json"),
            "--trust-registry",
            str(FIXTURES / "authorization_valid_trust_registry.json"),
            "--trust-root",
            str(roots),
        )
        assert (exit_code, report) == (64, None), f"trust root {row['member']} = {value!r}"
    if row["required"] == "yes" and row["member"] != "the document":
        roots = write_json(tmp_path / "absent.json", _root_document(row, ABSENT))
        exit_code, report = run_cli(
            tmp_path / "absent",
            "--registry-entry",
            str(FIXTURES / "authorization_valid_registry_entry.json"),
            "--trust-registry",
            str(FIXTURES / "authorization_valid_trust_registry.json"),
            "--trust-root",
            str(roots),
        )
        assert (exit_code, report) == (64, None), f"trust root {row['member']} absent"


def _run_root(tmp_path: Path, row: dict[str, str], value: Any) -> tuple[int, dict[str, Any] | None]:
    roots = write_json(tmp_path / "roots.json", _root_document(row, value))
    return run_cli(
        tmp_path / "run",
        "--registry-entry",
        str(FIXTURES / "authorization_valid_registry_entry.json"),
        "--trust-registry",
        str(FIXTURES / "authorization_valid_trust_registry.json"),
        "--trust-root",
        str(roots),
    )


@pytest.mark.parametrize(
    ("document_name", "row"), ROOT_ROWS, ids=[row["member"].strip("`") for _name, row in ROOT_ROWS]
)
def test_the_type_cell_of_a_trust_root_row_decides_every_json_type(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    """§11's `type` column is a rule this verifier runs, as §3 to §10's columns are.

    The trust-root document has no report: the command line refuses it with exit 64 and prints
    nothing, so these rows are run through the command line rather than through the library.
    That is the only difference. One value of every JSON type the cell refuses is refused here,
    so widening a cell moves a value onto the accepted side, where it is read as a trust root
    and this fails. Every row of §11 states a value rule, so there is no acceptance direction to
    run: what a well-formed document does is the lock below.

    The number of comparisons is asserted for the reason it is asserted for the other sections:
    a cell that refuses no type would otherwise pass this having compared nothing.
    """
    outcome = OUTCOMES[code(row["outcome"])]
    assert outcome == {"exit_code": 64, "report": False}, row
    admitted = admitted_types(row)
    assert admitted, f"{row['member']}: the type cell names no JSON type"
    assert row["value"] != "-", f"{row['member']}: §11 rows state a value rule"
    compared = 0
    for name, value in TYPE_SAMPLE.items():
        if name in admitted:
            continue
        got = _run_root(tmp_path / f"refused-{name}", row, value)
        assert got == (64, None), f"trust root {row['member']} = {value!r} ({name})"
        compared += 1
    assert compared, f"{row['member']}: its type cell decided no value, so this compared nothing"


def test_a_well_formed_trust_root_document_is_read(tmp_path: Path) -> None:
    """The lock under the rows above: this document is refused for its content, not for being one."""
    exit_code, report = run_cli(
        tmp_path,
        "--registry-entry",
        str(FIXTURES / "authorization_valid_registry_entry.json"),
        "--trust-registry",
        str(FIXTURES / "authorization_valid_trust_registry.json"),
        "--trust-root",
        str(write_json(tmp_path / "roots.json", root_document([dict(VALID_ROOT)]))),
    )
    assert exit_code != 64 and report is not None


# ---------------------------------------------------------------- the registered vocabulary document


VOCABULARY_ROWS = [(document_name, row) for document_name, row in member_rows() if document_name == "vocabulary"]


def _vocabulary_document(row: dict[str, str], value: Any) -> dict[str, Any]:
    """The protocol's workflow vocabulary with the row's member set to ``value`` in every value."""
    document = json.loads(REGISTERED_VOCABULARIES["workflow"])
    member = row["member"].strip("`")
    targets = list(document["values"].values()) if member.startswith("values.*.") else [document]
    name = member.removeprefix("values.*.")
    for target in targets:
        if value is ABSENT:
            target.pop(name, None)
        else:
            target[name] = value
    return document


def _run_vocabulary(tmp_path: Path, option: str, document: Any) -> tuple[int, dict[str, Any] | None]:
    path = tmp_path / "vocabulary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(document, bytes):
        path.write_bytes(document)
    else:
        write_json(path, document)
    return run_cli(tmp_path / "run", option, str(path))


@pytest.mark.parametrize(
    ("document_name", "row"), VOCABULARY_ROWS, ids=[row["member"].strip("`") for _name, row in VOCABULARY_ROWS]
)
def test_every_refused_vocabulary_document_is_refused_by_the_command_line(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    """Section 15: each refused value of a row, and an absent required member, is exit 64 and no report."""
    assert OUTCOMES[code(row["outcome"])] == {"exit_code": 64, "report": False}, row
    for index, value in enumerate(refused_values(row)):
        got = _run_vocabulary(tmp_path / f"refused{index}", "--workflow-vocabulary", _vocabulary_document(row, value))
        assert got == (64, None), f"vocabulary {row['member']} = {value!r}"
    if row["required"] != "no":
        got = _run_vocabulary(tmp_path / "absent", "--workflow-vocabulary", _vocabulary_document(row, ABSENT))
        assert got == (64, None), f"vocabulary {row['member']} absent"


@pytest.mark.parametrize(
    ("document_name", "row"), VOCABULARY_ROWS, ids=[row["member"].strip("`") for _name, row in VOCABULARY_ROWS]
)
def test_the_type_cell_of_a_vocabulary_row_decides_every_json_type(
    tmp_path: Path, document_name: str, row: dict[str, str]
) -> None:
    """Section 15's `type` column is run as section 11's is: every type it refuses is exit 64."""
    admitted = admitted_types(row)
    assert admitted, f"{row['member']}: the type cell names no JSON type"
    compared = 0
    for name, value in TYPE_SAMPLE.items():
        if name in admitted:
            continue
        got = _run_vocabulary(tmp_path / f"refused-{name}", "--workflow-vocabulary", _vocabulary_document(row, value))
        assert got == (64, None), f"vocabulary {row['member']} = {value!r} ({name})"
        compared += 1
    assert compared, f"{row['member']}: its type cell decided no value, so this compared nothing"


def test_a_well_formed_vocabulary_document_is_read(tmp_path: Path) -> None:
    """The lock under the rows above: the protocol's own document is accepted for every kind."""
    for kind, option in (
        ("asset_type", "--asset-type-vocabulary"),
        ("workflow", "--workflow-vocabulary"),
        ("anchoring_method", "--anchoring-method-vocabulary"),
    ):
        exit_code, report = _run_vocabulary(tmp_path / kind, option, REGISTERED_VOCABULARIES[kind])
        assert exit_code == 0 and report is not None, kind
        assert report["vocabularies"][kind]["source"] == "operator", kind


# ---------------------------------------------------------------- the verifier's own inputs


def _input_invocations(tmp_path: Path) -> dict[str, list[list[str]]]:
    """The refusals the inputs table names, as command lines, by the input each one is about."""
    entry = str(FIXTURES / "authorization_valid_registry_entry.json")
    registry = str(FIXTURES / "authorization_valid_trust_registry.json")
    roots = str(write_json(tmp_path / "roots.json", root_document([dict(VALID_ROOT)])))
    workflow_vocabulary = json.loads(REGISTERED_VOCABULARIES["workflow"])
    asset_type_vocabulary = json.loads(REGISTERED_VOCABULARIES["asset_type"])
    return {
        "the bundle": [["--no-bundle"], ["--second-bundle"], ["--empty-bundle"]],
        "the registry entry": [],
        "the trust registry": [["--trust-registry", registry]],
        "the trust roots": [
            ["--trust-root", roots],
            [
                "--registry-entry",
                entry,
                "--trust-registry",
                registry,
                "--trust-root",
                str(write_json(tmp_path / "bad.json", root_document([]))),
            ],
        ],
        "the asset-type vocabulary": [
            ["--asset-type-vocabulary", str(tmp_path / "absent-vocabulary.json")],
            ["--asset-type-vocabulary", str(write_json(tmp_path / "workflow.json", workflow_vocabulary))],
            ["--asset-type-vocabulary", str(write_json(tmp_path / "malformed.json", {"kind": "asset_type"}))],
        ],
        "the workflow vocabulary": [
            ["--workflow-vocabulary", str(tmp_path / "absent-vocabulary.json")],
            ["--workflow-vocabulary", str(write_json(tmp_path / "asset_type.json", asset_type_vocabulary))],
            ["--workflow-vocabulary", str(write_json(tmp_path / "malformed-workflow.json", {"kind": "workflow"}))],
        ],
        "the anchoring-method vocabulary": [
            ["--anchoring-method-vocabulary", str(tmp_path)],
            ["--anchoring-method-vocabulary", str(write_json(tmp_path / "asset_type-2.json", asset_type_vocabulary))],
            ["--anchoring-method-vocabulary", str(write_json(tmp_path / "malformed-method.json", []))],
        ],
        "the evaluation time": [
            ["--evaluation-time", "2026-05-10T00:00:00Z"],
            ["--registry-entry", entry, "--trust-registry", registry, "--evaluation-time", ""],
            ["--registry-entry", entry, "--trust-registry", registry, "--evaluation-time", "2026-02-30T00:00:00Z"],
        ],
        "any option": [
            ["--registry-entry", entry, "--registry-entry", entry],
            ["--registry-entry", entry, f"--registry-entry={entry}"],
            ["--reg", entry],
            ["--attested-time", "2026-05-10T00:00:00Z"],
            ["--tsa-token", str(write_json(tmp_path / "token.bin", {}))],
            ["--registry-entry", ""],
        ],
    }


def test_every_refused_invocation_of_the_inputs_table_exits_64(tmp_path: Path) -> None:
    rows = {row["input"]: row for _title, rows in _rows(INPUT_HEADER).items() for row in rows}
    invocations = _input_invocations(tmp_path)
    assert set(rows) == set(invocations), sorted(set(rows) ^ set(invocations))
    for name, row in rows.items():
        if row["outcome"] == "-":
            assert not invocations[name], name
            continue
        assert code(row["outcome"]) == "input-refused", row
        for index, arguments in enumerate(invocations[name]):
            exit_code, report = _run_input(tmp_path / f"{name.replace(' ', '-')}{index}", arguments)
            assert (exit_code, report) == (64, None), f"{name}: {arguments}"


def _run_input(tmp_path: Path, arguments: list[str]) -> tuple[int, dict[str, Any] | None]:
    bundle = sealed_bundle().write(tmp_path / "bundle")
    command = [sys.executable, "-m", "loquitur.verify.cli", "--json"]
    if arguments == ["--no-bundle"]:
        pass
    elif arguments == ["--second-bundle"]:
        command += [str(bundle), str(bundle)]
    elif arguments == ["--empty-bundle"]:
        command += [""]
    else:
        command += [str(bundle), *arguments]
    finished = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=False,
    )
    try:
        return finished.returncode, json.loads(finished.stdout)
    except ValueError:
        return finished.returncode, None


def test_every_member_table_row_was_executed() -> None:
    """Every section of the appendix but the trust-root one is executed above."""
    titles = {title for title in _rows(MEMBER_HEADER)}
    covered = {title for title in titles if _document_of(title) is not None}
    assert titles - covered == set(), sorted(titles - covered)
    assert len(MEMBER_CASES) >= 80, len(MEMBER_CASES)


# ---------------------------------------------------------------- what this suite covers

COVERAGE_SECTION = "14. What each suite runs"
SUITE_HEADER = ["suite", "member rows", "case rows", "input rows", "report surface compared"]
THIS_SUITE = "tests/test_spec_document_contracts.py"


def _suite_row() -> dict[str, Any]:
    """§14's row for this suite: its counts as numbers and its surface as a list of names."""
    rows = [row for rows in _rows(SUITE_HEADER).values() for row in rows]
    found = [row for row in rows if THIS_SUITE in codes(row["suite"])]
    assert len(found) == 1, f"§14 names {len(found)} suites at {THIS_SUITE}"
    row = found[0]
    return {
        "member rows": int(row["member rows"]),
        "case rows": int(row["case rows"]),
        "input rows": 0 if row["input rows"] == "-" else int(row["input rows"]),
        "surface": codes(row["report surface compared"]),
    }


def test_this_suite_runs_what_section_14_says_it_runs(tmp_path: Path) -> None:
    """§14 is where the appendix states its own coverage, and this holds this suite's row.

    Every number in that row is compared with what this module runs: the member rows it drives
    through the library, the §11 rows it drives through the command line, the case rows, the
    input rows, and the fields a run is compared on, taken from a real report rather than from
    a list written twice. A row claiming a coverage this module does not have fails here, so
    the sentence cannot outrun the suite.
    """
    claimed = _suite_row()
    assert len(MEMBER_CASES) + len(ROOT_ROWS) + len(VOCABULARY_ROWS) == claimed["member rows"]
    # And every one of those rows has its `type` cell run. The three lists that carry a type
    # case partition the member rows, so a row that stopped reaching all three would leave this
    # short of the count above rather than going unrun in silence.
    assert len(TYPE_CASES) + len(BYTES_CASES) + len(ROOT_ROWS) + len(VOCABULARY_ROWS) == claimed["member rows"]
    assert len(CASE_ROWS) == claimed["case rows"]
    # Counted as rows, not as the set of their names: a set folds a duplicated row away, and
    # the table is read into a dictionary by that name elsewhere in this module.
    assert len([row for rows in _rows(INPUT_HEADER).values() for row in rows]) == claimed["input rows"]
    ran = surface(run_bundle(tmp_path, sealed_bundle()))
    assert [SURFACE_FIELDS[name] for name in ran] == claimed["surface"], sorted(ran)
