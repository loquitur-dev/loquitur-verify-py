"""The link check, held to loquitur-protocol docs/specification/registry-link.md.

The specification states the link check as tables: the entry's grounds (section 2), the comparisons and
which of them are hard (section 3), the exact spellings each comparison reads (section 4), the
three values of the link result (section 5) and the effect of the committed verdict (section 6).
Every row is read from the sibling checkout (spec_tables.py) and run through verify_path over a
sealed copy of the link fixture bundle, so a row the verifier does not follow fails here, and so
does a row changed in the specification alone. The narrative renderer is held to the same
grounds table: one rule for a verdict and its codes, wherever an entry is read.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from authorization_kit import IssuerKey, authorization_material, write_json
from bundle_builder import Bundle, jcs, sha, with_raw_member
from siblings import import_sibling
from spec_tables import code, document, table

import loquitur.verify.registry_link as registry_link
from loquitur.verify.narrative import render_narrative_from_codes
from loquitur.verify.runner import verify_path

SPEC = "registry-link.md"
RECEIPT_STATUS = {"PASS": "pass", "WARN": "warning", "REVIEW": "review", "FAIL": "fail"}
# Grounds a verdict derives from, for rows that only need an entry with a given verdict.
GROUNDS = {
    "PASS": ["INTEGRITY_OK"],
    "WARN": ["INTEGRITY_OK", "FRESHNESS_WARNING"],
    "REVIEW": ["INTEGRITY_OK", "NEEDS_REVIEW"],
    "FAIL": ["INTEGRITY_OK", "INTEGRITY_OFFLINE_FAIL"],
}
# A report-only restatement of the committed verdict, not a comparison of the link (section 6).
REPORT_ONLY_CHECKS = {"registry_entry_verdict"}


def _run(
    tmp_path: Path,
    *,
    entry: Callable[[dict[str, Any]], Any] | None = None,
    receipt: Callable[[dict[str, Any]], Any] | None = None,
    raw_receipt: tuple[str, str] | None = None,
    bundle: Callable[[Bundle], Any] | None = None,
    trust: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """verify_path at the link check over the fixture bundle, the receipt and the entry each changed as given.

    The entry's two digests are bound to the bundle as sealed, so only the change under test
    differs; ``raw_receipt`` splices one receipt member in as JSON text after sealing.
    """
    sealed = Bundle()
    if receipt is not None:
        sealed.edit("verification_receipt.json", receipt)
    if bundle is not None:
        bundle(sealed)
    sealed.seal()
    if raw_receipt is not None:
        key, text = raw_receipt
        sealed.members["verification_receipt.json"] = with_raw_member(
            sealed.json("verification_receipt.json"), key, text
        )
    root = sealed.write(tmp_path / "bundle")
    document_path = sealed.link_entry(tmp_path / "entry.json")
    if entry is not None:
        value = json.loads(document_path.read_text(encoding="utf-8"))
        entry(value)
        document_path.write_text(json.dumps(value), encoding="utf-8")
    kwargs: dict[str, Any] = {"registry_entry_path": document_path}
    if trust is not None:
        kwargs["trust_registry_path"] = write_json(tmp_path / "trust.json", trust)
    return verify_path(root, **kwargs).to_dict()


def _link_checks(report: dict[str, Any]) -> dict[str, Any]:
    return {check["name"]: check["ok"] for check in report["registry_link"]["checks"]}


def _grounded(verdict: str, codes: list[str]) -> dict[str, Any]:
    """Entry and receipt changes that give both documents this verdict and these codes."""
    return {
        "entry": lambda e: e.update(verdict=verdict, reason_codes=list(codes)),
        "receipt": lambda r: r.update(status=RECEIPT_STATUS[verdict], reason_codes=list(codes)),
    }


def test_the_grounds_table_is_the_contract_of_an_entry_and_of_the_narrative(tmp_path: Path) -> None:
    import_sibling("loquitur.schemas", "the narrative renderer composes from the catalog loquitur-schemas carries")
    rows = table(document(SPEC), ["verdict", "reason codes", "grounds hold"])
    assert {row["grounds hold"] for row in rows} == {"yes", "no"}
    got, expected = {}, {}
    for index, row in enumerate(rows):
        verdict, codes = code(row["verdict"]), json.loads(code(row["reason codes"]))
        holds = row["grounds hold"] == "yes"
        report = _run(tmp_path / str(index), **_grounded(verdict, codes))
        try:
            narrated = render_narrative_from_codes(codes, verdict).technical is not None
        except ValueError:
            narrated = False
        label = f"{verdict} {codes}"
        got[label] = (
            report["checks"]["registry_link"],
            "registry_entry_contract_violation" in [e["code"] for e in report["errors"]],
            narrated,
        )
        expected[label] = (holds, not holds, holds)
    assert got == expected


def test_the_comparisons_and_the_hard_set_are_the_implementations(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["check", "hard", "registry-entry operand", "other operand", "holds when"])
    specified = {code(row["check"]): row["hard"] for row in rows}
    assert set(specified.values()) == {"yes", "no"}
    report = _run(tmp_path / "valid")
    checks = _link_checks(report)
    assert report["checks"]["registry_link"] is True
    assert set(checks) - REPORT_ONLY_CHECKS == set(specified)
    assert all(checks[name] is True for name in specified)
    assert {name for name, hard in specified.items() if hard == "yes"} == set(registry_link._HARD_CHECK_NAMES)

    other_digest = "0" * 64
    only_this_check_fails: dict[str, dict[str, Any]] = {
        "registry_entry_contract": {"entry": lambda e: e.update(smuggled="x")},
        "verification_receipt_contract": {"receipt": lambda r: r.update(smuggled="x")},
        "manifest_hash": {"entry": lambda e: e.update(manifest_hash="sha256:" + other_digest)},
        "receipt_manifest_sha256": {"raw_receipt": ("manifest_sha256", json.dumps(other_digest))},
        "receipt_hash": {"entry": lambda e: e.update(receipt_hash="sha256:" + other_digest)},
        "receipt_bundle_id": {"receipt": lambda r: r.update(bundle_id="another_bundle")},
        "receipt_p1_sha256": {"receipt": lambda r: r.update(p1_sha256=other_digest)},
        "policy_id": {"receipt": lambda r: r.update(policy_id="loquitur.policy.other")},
        "policy_version": {"receipt": lambda r: r.update(policy_version=2)},
        # Both names carry a const, so the two cannot differ without breaking a contract too.
        "reason_code_catalog_version": {"entry": lambda e: e.update(reason_code_catalog_version="other.v1")},
        "reason_codes": {"receipt": lambda r: r.update(reason_codes=["INTEGRITY_OK", "FRESHNESS_OK"])},
        "asset_type": {"receipt": lambda r: r.update(asset_type="fund_nav")},
        "status_verdict": {"receipt": lambda r: r.update(status="review")},
    }
    assert set(only_this_check_fails) == set(specified)
    contracts = {"registry_entry_contract", "verification_receipt_contract"}
    for name, change in only_this_check_fails.items():
        report = _run(tmp_path / name, **change)
        checks = _link_checks(report)
        assert report["checks"]["registry_link"] is False, name
        assert checks[name] is not True, (name, checks)
        others = {other: ok for other, ok in checks.items() if other not in contracts | {name} | REPORT_ONLY_CHECKS}
        assert all(ok is True for ok in others.values()), (name, checks)


def _spelling(cell: str, digest: str) -> Any:
    # A value too long to write in a cell is described: `"1"` followed by 4400 `"0"`, then `".0.0"`.
    described = re.fullmatch(r'`"([^"`]*)"` followed by (\d+) `"([^"`]*)"`, then `"([^"`]*)"`', cell)
    if described:
        head, count, repeated, tail = described.groups()
        return head + repeated * int(count) + tail
    text = code(cell).replace("<manifest digest>", digest).replace("<MANIFEST DIGEST>", digest.upper())
    return json.loads(text)


def test_the_spelling_cases(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["case", "field", "registry entry", "receipt", "link holds"])
    digest = Bundle().seal().manifest_digest()
    got, expected = {}, {}
    for row in rows:
        case, field = code(row["case"]), code(row["field"])
        changes: dict[str, Any] = {}
        if field == "manifest_sha256":
            # The receipt's own copy of the digest, in a form its contract refuses (a bare digest).
            assert row["registry entry"] == "none", case
            receipt_text = code(row["receipt"]).replace("<manifest digest>", digest)
            changes["raw_receipt"] = (field, receipt_text)
            report = _run(tmp_path / case, **changes)
            got[case] = report["checks"]["registry_link"]
            expected[case] = row["link holds"] == "yes"
            continue
        entry_value = _spelling(row["registry entry"], digest)
        if field == "status":
            receipt_status = json.loads(code(row["receipt"]))
            codes = GROUNDS.get(entry_value, ["INTEGRITY_OK"])
            changes["entry"] = lambda e, v=entry_value, c=codes: e.update(verdict=v, reason_codes=c)
            changes["receipt"] = lambda r, s=receipt_status, c=codes: r.update(status=s, reason_codes=c)
        elif field == "manifest_hash":
            assert row["receipt"] == "none", case
            changes["entry"] = lambda e, v=entry_value: e.update(manifest_hash=v)
        else:
            receipt_text = code(row["receipt"])
            changes["entry"] = lambda e, f=field, v=entry_value: e.update({f: v})
            changes["raw_receipt"] = (field, receipt_text)
        report = _run(tmp_path / case, **changes)
        got[case] = report["checks"]["registry_link"]
        expected[case] = row["link holds"] == "yes"
    assert got == expected


def test_the_three_values_of_the_link_result(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["`registry_link`", "when"])
    assert [row["`registry_link`"] for row in rows] == ["`null`", "`false`", "`true`"]
    missing_receipt = {"bundle": lambda b: b.members.pop("verification_receipt.json")}

    def run_without_entry(path: Path) -> dict[str, Any]:
        sealed = Bundle().seal()
        return verify_path(sealed.write(path / "bundle")).to_dict()

    def run_with_absent_entry_file(path: Path) -> dict[str, Any]:
        sealed = Bundle().seal()
        return verify_path(sealed.write(path / "bundle"), registry_entry_path=path / "absent.json").to_dict()

    def run_with_entry_directory(path: Path) -> dict[str, Any]:
        sealed = Bundle().seal()
        (path / "entry-directory").mkdir(parents=True)
        return verify_path(sealed.write(path / "bundle"), registry_entry_path=path / "entry-directory").to_dict()

    def run_with_entry_text(text: str) -> Callable[[Path], dict[str, Any]]:
        def run(path: Path) -> dict[str, Any]:
            sealed = Bundle().seal()
            entry = path / "entry.json"
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_text(text, encoding="utf-8")
            return verify_path(sealed.write(path / "bundle"), registry_entry_path=entry).to_dict()

        return run

    runs: dict[str, list[tuple[Callable[[Path], dict[str, Any]], str]]] = {
        "null": [
            (run_without_entry, "OFFLINE_OK"),
            # Nothing to link: a question, not a finding (verification_receipt_not_provided).
            (lambda p: _run(p, **missing_receipt), "OFFLINE_REVIEW"),
            (run_with_entry_directory, "OFFLINE_FAIL"),
        ],
        "false": [
            (run_with_entry_text("null"), "OFFLINE_FAIL"),
            (run_with_entry_text("{"), "OFFLINE_FAIL"),
            (lambda p: _run(p, raw_receipt=("policy_version", '"1"')), "OFFLINE_FAIL"),
            (lambda p: _run(p, entry=lambda e: e.update(verdict="BANANA")), "OFFLINE_FAIL"),
            (lambda p: _run(p, receipt=lambda r: r.update(policy_id="another")), "OFFLINE_FAIL"),
        ],
        "true": [(lambda p: _run(p), "OFFLINE_OK")],
    }
    values = {"null": None, "false": False, "true": True}
    for value, cases in runs.items():
        for index, (run, status) in enumerate(cases):
            report = run(tmp_path / value / str(index))
            assert (report["checks"]["registry_link"], report["status"]) == (values[value], status), (value, index)
    # Nothing found at the entry's path refuses the run as a whole: the table does not apply, and
    # the link is refused with the input, false because an entry was supplied.
    refused = run_with_absent_entry_file(tmp_path / "refused")
    assert (refused["checks"]["registry_link"], refused["status"]) == (False, "HOST_FAILURE")


def test_the_rows_of_the_link_result_are_read_in_order(tmp_path: Path) -> None:
    """Where a row of null and a row of false both hold, the first row gives the value."""
    assert "the first whose condition holds gives the value" in " ".join(document(SPEC).split())

    def without_receipt(entry_text: str | None, *, contract_break: bool = False) -> Callable[[Path], dict[str, Any]]:
        def run(path: Path) -> dict[str, Any]:
            sealed = Bundle()
            sealed.members.pop("verification_receipt.json")
            sealed.seal()
            entry = sealed.link_entry(path / "entry.json") if entry_text is None else path / "entry.json"
            if entry_text is not None:
                entry.parent.mkdir(parents=True, exist_ok=True)
                entry.write_text(entry_text, encoding="utf-8")
            if contract_break:
                value = json.loads(entry.read_text(encoding="utf-8"))
                value["verdict"] = "BANANA"
                entry.write_text(json.dumps(value), encoding="utf-8")
            return verify_path(sealed.write(path / "bundle"), registry_entry_path=entry).to_dict()

        return run

    def alone_with_broken_receipt(path: Path) -> dict[str, Any]:
        sealed = Bundle().seal()
        sealed.members["verification_receipt.json"] = with_raw_member(
            sealed.json("verification_receipt.json"), "policy_version", '"1"'
        )
        return verify_path(sealed.write(path / "bundle")).to_dict()

    cases = {
        "bundle alone, receipt breaks its contract": alone_with_broken_receipt,
        "entry JSON null, no receipt": without_receipt("null"),
        "entry not strict JSON, no receipt": without_receipt("{"),
        "entry an array, no receipt": without_receipt("[]"),
        "entry breaks its contract, no receipt": without_receipt(None, contract_break=True),
    }
    got = {}
    for index, (name, run) in enumerate(cases.items()):
        report = run(tmp_path / str(index))
        got[name] = (report["checks"]["registry_link"], report["status"])
    # An entry that is not an object is refused for the entry. An object entry that breaks its
    # contract is judged only beside a receipt (report-contract.md section 5.3), so without one
    # it is a run with nothing to link: OFFLINE_REVIEW, verification_receipt_not_provided.
    assert got == {
        name: (None, "OFFLINE_REVIEW" if name == "entry breaks its contract, no receipt" else "OFFLINE_FAIL")
        for name in cases
    }


def test_the_committed_verdict(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["entry verdict", "effect on the run"])
    effects = {"none": "OFFLINE_OK", "at least `OFFLINE_REVIEW`": "OFFLINE_REVIEW", "`OFFLINE_FAIL`": "OFFLINE_FAIL"}
    got, expected = {}, {}
    for row in rows:
        verdict = code(row["entry verdict"])
        report = _run(tmp_path / verdict, **_grounded(verdict, GROUNDS[verdict]))
        got[verdict] = (report["status"], report["checks"]["registry_link"])
        expected[verdict] = (effects[row["effect on the run"]], True)
    assert set(got) == set(RECEIPT_STATUS)
    assert got == expected


def test_an_entry_that_breaks_its_contract_commits_nothing(tmp_path: Path) -> None:
    """Section 6: the committed verdict bounds the run only once the entry satisfies its contract."""
    got = {}
    for verdict in ("FAIL", "WARN"):
        # The verdict is the committed one, and the grounds contradict it: the contract breaks.
        report = _run(
            tmp_path / verdict,
            entry=lambda e, v=verdict: e.update(verdict=v, reason_codes=["INTEGRITY_OK"]),
            receipt=lambda r, v=verdict: r.update(status=RECEIPT_STATUS[v]),
        )
        got[verdict] = (
            report["status"],
            [error["code"] for error in report["errors"]],
            "registry_entry_verdict_requires_review" in report["notes"],
        )
    assert got == {
        "FAIL": ("OFFLINE_FAIL", ["registry_entry_contract_violation"], False),
        "WARN": ("OFFLINE_FAIL", ["registry_entry_contract_violation"], False),
    }


def test_a_trust_registry_beside_a_link_that_does_not_hold_reaches_no_conclusion(tmp_path: Path) -> None:
    text = document(SPEC)
    assert "the trust registry reaches no conclusion" in " ".join(text.split())
    key = IssuerKey()
    _entry, registry = authorization_material(key)
    got = {}
    for label, change in {
        "entry-contract": {"entry": lambda e: e.update(smuggled="x")},
        "link-does-not-hold": {"receipt": lambda r: r.update(policy_id="another")},
        "malformed-trust-registry": {
            "entry": lambda e: e.update(smuggled="x"),
            "trust": {**registry, "object_type": "not_a_trust_registry"},
        },
    }.items():
        change.setdefault("trust", registry)
        report = _run(tmp_path / label, **change)
        got[label] = (
            report["status"],
            report["checks"]["registry_link"],
            report["checks"]["trust_registry"],
            report["checks"]["registry_signature"],
            report["trust_registry"],
        )
    assert got == {label: ("OFFLINE_FAIL", False, None, "UNSUPPORTED", None) for label in got}

    sealed = Bundle().seal()
    alone = verify_path(
        sealed.write(tmp_path / "alone" / "bundle"), trust_registry_path=write_json(tmp_path / "t.json", registry)
    ).to_dict()
    assert (alone["status"], [e["code"] for e in alone["errors"]], alone["checks"]["trust_registry"]) == (
        "OFFLINE_FAIL",
        ["trust_registry_requires_registry_entry"],
        None,
    )


def test_the_manifest_digest_is_recomputed_not_read_from_the_sidecar(tmp_path: Path) -> None:
    """Section 4: a manifest sidecar that does not match fails the manifest layer, not the link.

    That holds for every sidecar that is present and is not the digest, one that is not UTF-8
    included; only an absent sidecar, or a manifest that cannot be loaded, leaves no digest.
    """
    sidecars: dict[str, bytes | None] = {
        "another-digest": sha(jcs({"not": "the manifest"})).encode(),
        "sixty-five-bytes": b"0" * 65,
        "not-utf-8": bytes([0xFF]) * 64,
        "absent": None,
    }
    got = {}
    for label, sidecar in sidecars.items():
        sealed = Bundle().seal()
        if sidecar is None:
            del sealed.members["manifest.sha256"]
        else:
            sealed.members["manifest.sha256"] = sidecar
        root = sealed.write(tmp_path / label / "bundle")
        entry = sealed.link_entry(tmp_path / label / "entry.json")
        report = verify_path(root, registry_entry_path=entry).to_dict()
        got[label] = (report["status"], report["checks"]["manifest_sha256"], report["checks"]["registry_link"])
    assert got == {
        "another-digest": ("OFFLINE_FAIL", False, True),
        "sixty-five-bytes": ("OFFLINE_FAIL", False, True),
        "not-utf-8": ("OFFLINE_FAIL", False, True),
        "absent": ("OFFLINE_FAIL", False, False),
    }


def _authorization_bound(
    path: Path, key: IssuerKey, *, entry: Callable[[dict[str, Any]], Any], receipt: Callable | None, trust: Callable
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """An authorization run over the fixture bundle, its receipt changed as given, the entry bound to it and signed."""
    sealed = Bundle()
    if receipt is not None:
        sealed.edit("verification_receipt.json", receipt)
    sealed.seal()
    bound = {
        "manifest_hash": "sha256:" + sealed.manifest_digest(),
        "receipt_hash": "sha256:" + sha(jcs(sealed.json("verification_receipt.json"))),
    }
    document_, registry = authorization_material(key, entry=lambda e: (e.update(bound), entry(e)), trust=trust)
    root = sealed.write(path / "bundle")
    report = verify_path(
        root,
        registry_entry_path=write_json(path / "entry.json", document_),
        trust_registry_path=write_json(path / "trust.json", registry),
    ).to_dict()
    return report, document_, registry


def test_an_entry_names_a_key_and_a_policy(tmp_path: Path) -> None:
    """Section 2: issuer_key_id and policy_id are not empty under W, at the link check and at the authorization check alike.

    A value made only of the whitespace set W satisfies the schema's minLength and names nothing:
    the entry breaks its contract, the link does not hold and no trust registry is read beside it.
    A value that is not empty is compared as written, so a leading space is still a key id.
    """
    import loquitur.verify.trust_registry as trust_registry

    rows = table(document(SPEC), ["member", "value", "contract holds"])
    assert {code(row["member"]) for row in rows} == {
        "issuer_key_id",
        "policy_id",
        "signature.key_id",
        "anchor.system",
        "anchor.anchor_reference",
    }
    assert {row["contract holds"] for row in rows} == {"yes", "no"}
    key = IssuerKey()
    got, expected = {}, {}
    for index, row in enumerate(rows):
        member, value = code(row["member"]), json.loads(code(row["value"]))
        holds = row["contract holds"] == "yes"

        def entry(e: dict[str, Any], m: str = member, v: str = value) -> None:
            if m.startswith("anchor."):
                # The anchor is outside the signing payload; a complete one carries the value.
                e["anchor"] = {"method": "blockchain_transaction", "system": "testnet", "anchor_reference": "tx-1"}
                e["anchor"][m.removeprefix("anchor.")] = v
                return
            if m == "signature.key_id":
                if not isinstance(e.get("signature"), dict):
                    # The link fixture carries no signature; the rule reads the object when present.
                    e["signature"] = {
                        "algorithm": "secp256k1_ecdsa_sha256",
                        "key_id": e["issuer_key_id"],
                        "payload_id": "registry_entry_signing_payload_v2",
                        "payload_version": 2,
                        "signature": "00" * 64,
                    }
                e["signature"]["key_id"] = v
                return
            e[m] = v
            if m == "issuer_key_id" and isinstance(e.get("signature"), dict):
                e["signature"]["key_id"] = v

        # The receipt's policy_id follows the entry's where the row holds, so the comparison holds
        # too; where the row does not hold, the receipt keeps its own (a receipt with such a value
        # breaks its own contract, which is registry-link.md's rule for the receipt).
        receipt = (lambda r, v=value: r.update(policy_id=v)) if member == "policy_id" and holds else None
        trust = (lambda t, v=value: t["entries"][0].update(issuer_key_id=v)) if member == "issuer_key_id" else None
        link_report = _run(tmp_path / f"{index}-link", entry=entry, receipt=receipt)
        authorization_files, signed, registry = _authorization_bound(
            tmp_path / f"{index}-authorization", key, entry=entry, receipt=receipt, trust=trust
        )
        library = trust_registry.verify_registry_entry_trust(
            signed, trust_registry_path=write_json(tmp_path / f"{index}-library.json", registry)
        )
        label = f"{member} {value!r}"
        got[label] = (
            link_report["status"],
            link_report["checks"]["registry_link"],
            [error["code"] for error in link_report["errors"]],
            authorization_files["status"],
            authorization_files["checks"]["registry_link"],
            authorization_files["checks"]["trust_registry"],
            [error["code"] for error in authorization_files["errors"]],
            library.authorization_status,
        )
        expected[label] = (
            ("OFFLINE_OK", True, [], "OFFLINE_REVIEW", True, True, [], "AUTHORIZED_ACTIVE_KEY")
            if holds
            else (
                "OFFLINE_FAIL",
                False,
                ["registry_entry_contract_violation"],
                "OFFLINE_FAIL",
                False,
                None,
                ["registry_entry_contract_violation"],
                "INVALID_REGISTRY_ENTRY",
            )
        )
    assert got == expected
