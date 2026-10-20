"""The authorization check, held to loquitur-protocol docs/specification/trust-registry-authorization.md.

The specification states the authorization check as tables: the operator's evaluation time (section
2), the trust registry's coherence (section 3), the lifecycle states and the inclusive windows
(section 4), the evaluation order with the authorization and signature status and the effect of
every row (section 6) and the closed vocabularies (section 8). Each table is read from the sibling checkout (spec_tables.py).

Every row of the order table has one change to the authorization fixtures that makes that row's condition
hold, run through verify_path with an issuer key made for the test, or through the signature step
itself for the rows an earlier contract makes unreachable in a bundle verification. Every pair of
those changes is then run combined. A model of each row's condition, written from the
specification, says which rows the combined documents meet, and the run must report the one the
table lists first among them. Every two neighboring rows of the table lead at least one combined
run, or are listed with the reason they cannot hold together, so swapping any two rows of the
table changes what some run must report.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import itertools
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import (
    BUNDLE,
    EVALUATION_TIME,
    IssuerKey,
    authorization_material,
    fixture_entry,
    fixture_trust_registry,
    run_authorization,
    write_json,
)
from spec_tables import code, codes, document, table

import loquitur.verify.trust_registry as trust_registry
from loquitur.verify.cli import main
from loquitur.verify.evaluation_time import EvaluationTimeError
from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import parse_trust_roots, trust_registry_signing_bytes

SPEC = "trust-registry-authorization.md"
AUTHORIZED = "AUTHORIZED_ACTIVE_KEY"
Change = Callable[[dict[str, Any]], Any]


def _status_cell(cell: str) -> str | None:
    value = code(cell)
    return None if value == "null" else value


ORDER_HEADER = ["#", "condition", "`authorization_status`", "`signature_status`", "effect"]


def _order() -> dict[str, tuple[str | None, str | None]]:
    rows = table(document(SPEC), ORDER_HEADER)
    return {
        row["#"]: (_status_cell(row["`authorization_status`"]), _status_cell(row["`signature_status`"])) for row in rows
    }


def _effects() -> dict[str, str]:
    """Each row's effect on the run: "failure", "holds", or the review reason it names."""
    effects = {}
    for row in table(document(SPEC), ORDER_HEADER):
        cell = row["effect"]
        effects[row["#"]] = code(cell.removeprefix("review: ")) if cell.startswith("review: ") else cell
    return effects


# ---- changes to the fixtures, one per condition -------------------------------------------------


def _trust(change: Change) -> dict[str, Change]:
    return {"trust": change}


def _entry(change: Change) -> dict[str, Change]:
    return {"entry": change}


def _key(**fields: Any) -> Change:
    return lambda registry: registry["entries"][0].update(fields)


def _registry(**fields: Any) -> Change:
    return lambda registry: registry.update(fields)


def _duplicate(registry: dict[str, Any]) -> None:
    twin = copy.deepcopy(registry["entries"][0])
    twin["notes"] = "the same issuer and key, listed twice"
    registry["entries"].append(twin)


def _flip_signature_value(entry: dict[str, Any]) -> bool:
    """Change the last character of the signature value; False when there is no value to change."""
    signature = entry.get("signature")
    if not isinstance(signature, dict) or not isinstance(signature.get("signature"), str):
        return False
    value = signature["signature"]
    signature["signature"] = value[:-1] + ("0" if value[-1] != "0" else "1")
    return True


def _signature(**fields: Any) -> Change:
    def change(entry: dict[str, Any]) -> None:
        if isinstance(entry.get("signature"), dict):
            entry["signature"].update(fields)

    return change


def _upper_case_value(entry: dict[str, Any]) -> None:
    signature = entry.get("signature")
    if isinstance(signature, dict) and isinstance(signature.get("signature"), str):
        signature["signature"] = signature["signature"].upper()


# Row number -> the change that makes that row's condition hold, applied by verify_path. The
# operator's evaluation time of every run is EVALUATION_TIME (2026-05-10T00:00:00Z), and the windows
# of rows 9 to 12 are moved one second past it.
PATH_ROWS: dict[str, dict[str, Any]] = {
    "1": {"absent_trust_registry": True},
    "3": _trust(_registry(object_type="not_a_trust_registry")),
    "4": _trust(_key(issuer_id="issuer_someone_else")),
    "5": _trust(_key(issuer_key_id="another-key")),
    "6": _trust(_duplicate),
    "7": _trust(_key(status="revoked", revoked_at="2026-05-01T00:00:00Z", revocation_reason="compromised")),
    "8": _trust(_key(status="suspended")),
    "9": _trust(_registry(effective_at="2026-05-10T00:00:01Z")),
    "10": _trust(_registry(expires_at="2026-05-09T23:59:59Z")),
    "11": _trust(_key(effective_from="2026-05-10T00:00:01Z")),
    "12": _trust(_key(expires_at="2026-05-09T23:59:59Z")),
    "13": _trust(_key(allowed_asset_types=["fund_nav"])),
    "14": _entry(lambda e: e.update(signature=None)),
    # The entry's contract admits any well-formed algorithm identifier: the verifier's allowlist
    # refuses the pair at row 16.
    "16": _entry(_signature(algorithm="ed25519")),
    "18": _entry(_signature(key_id="another-key")),
    "20": {"after_signing": _flip_signature_value},
    "—": {},
}

# The changes of rows 14 to 20 for the signature step on its own: "before" runs before the entry is
# signed, so the signature covers it; "after" runs after. Rows 15 and 19 are reached only here: the
# version gate of the signing payload and the key lookup refuse them earlier in a bundle
# verification (section 6). Row 17 is too: the entry's schema gives signature.signature the
# pattern ^[a-f0-9]{128}$, so the entry's contract refuses a value of another form before the trust
# registry is evaluated. Section 6 names only rows 15 and 19 as unreachable in a bundle.
STEP_CHANGES: dict[str, tuple[str, Callable[[dict[str, Any]], Any]]] = {
    "14": ("before", lambda e: e.update(signature=None)),
    "15": ("before", _signature(payload_version=3)),
    "16": ("before", _signature(algorithm="ed25519")),
    "17": ("after", _upper_case_value),
    "18": ("before", _signature(key_id="another-key")),
    "19": ("before", lambda e: e.update(issuer_key_id="another-key")),
    "20": ("after", _flip_signature_value),
}
UNREACHABLE_IN_A_BUNDLE = {"15", "17", "19"}

# Row 2 is decided before the trust registry's contract, by verify_registry_entry_trust.
LIBRARY_ROWS = {"2"}
AUTHORISED_KEY_ID = "demo-key-2"
# The pairs of the verifier's allowlist (canonicalization-and-hashing.md section 4).
ALLOWED_PAIRS = {("secp256k1_ecdsa_sha256", "secp256k1")}


# ---- the conditions of the order table, as the specification states them ----------------------
#
# A model of each row's condition over the documents a run reads, written from sections 2 to 6 of
# the specification and not from the implementation: which rows the documents meet. Every run,
# single or combined, must report the row the table lists first among the rows its documents
# meet. A row moved in the table therefore fails every run in which it and a row it passes both
# hold; test_every_adjacent_pair_of_rows_is_decided_by_a_run requires such a run for every two
# neighboring rows that can hold together.


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _evaluation_time_of(entry: dict[str, Any]) -> datetime:
    """Section 2: the operator's evaluation time. The entry's own dates are never read."""
    return _instant(EVALUATION_TIME)


def _contradicts_itself(registry: dict[str, Any]) -> bool:
    """Section 3, for the fields the changes of this module reach: object type and coherence."""
    if registry.get("object_type") != "trust_registry":
        return True
    expires_at = _instant(registry["expires_at"])
    if _instant(registry["effective_at"]) > expires_at or _instant(registry["issued_at"]) > expires_at:
        return True
    for item in registry["entries"]:
        revocation = item.get("revoked_at") is not None or item.get("revocation_reason") is not None
        if item["status"] in {"active", "suspended"} and revocation:
            return True
        if item["status"] == "revoked" and item.get("revoked_at") is None:
            return True
        if _instant(item["effective_from"]) > _instant(item["expires_at"]):
            return True
    return False


SIGNATURE_VALUE = re.compile(r"[0-9a-f]{128}")
SEC1_POINT = re.compile(r"0[23][0-9a-f]{64}|04[0-9a-f]{128}")


def _point(public_key_hex: Any) -> tuple[int, int] | None:
    """Section 6, row 6: the secp256k1 point a key encodes in a SEC1 form, decoded by pyca/cryptography."""
    from cryptography.hazmat.primitives.asymmetric import ec

    if not isinstance(public_key_hex, str) or not SEC1_POINT.fullmatch(public_key_hex):
        return None
    try:
        numbers = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(public_key_hex))
    except ValueError:
        return None
    return numbers.public_numbers().x, numbers.public_numbers().y


def _shares_point(found: dict[str, Any], entries: list[dict[str, Any]]) -> bool:
    point = _point(found["public_key_hex"])
    return point is not None and any(
        other is not found and _point(other["public_key_hex"]) == point for other in entries
    )


def _signature_rows(
    entry: dict[str, Any], authorised_key_id: str | None, *, tampered: bool, key_type: str | None = "secp256k1"
) -> set[str]:
    """Rows 14 to 20: the signature step, against the key the trust entry authorizes."""
    signature = entry.get("signature")
    if not isinstance(signature, dict):
        return {"14"}
    met = set()
    if (signature.get("payload_id"), signature.get("payload_version")) != ("registry_entry_signing_payload_v2", 2):
        met.add("15")
    if key_type is not None and (signature.get("algorithm"), key_type) not in ALLOWED_PAIRS:
        met.add("16")
    if not (isinstance(signature.get("signature"), str) and SIGNATURE_VALUE.fullmatch(signature["signature"])):
        met.add("17")
    if authorised_key_id is not None and signature.get("key_id") != authorised_key_id:
        met.add("18")
    if authorised_key_id is not None and entry.get("issuer_key_id") != authorised_key_id:
        met.add("19")
    if tampered:
        met.add("20")
    return met


def _path_rows(entry: dict[str, Any], registry: dict[str, Any] | None, *, tampered: bool) -> set[str]:
    """Every row whose condition the entry and the trust registry of a bundle verification meet."""
    if registry is None:
        return {"1"} | _signature_rows(entry, None, tampered=tampered)
    met = set()
    if _contradicts_itself(registry):
        met.add("3")
    issuer = [item for item in registry["entries"] if item["issuer_id"] == entry["issuer_id"]]
    keys = [item for item in issuer if item["issuer_key_id"] == entry["issuer_key_id"]]
    if not issuer:
        met.add("4")
    elif not keys:
        met.add("5")
    elif len(keys) > 1 or _shares_point(keys[0], registry["entries"]):
        met.add("6")
    at = _evaluation_time_of(entry)
    conditions = {
        "7": any(item["status"] == "revoked" for item in keys),
        "8": any(item["status"] == "suspended" for item in keys),
        "9": at < _instant(registry["effective_at"]),
        "10": at > _instant(registry["expires_at"]),
        "11": any(at < _instant(item["effective_from"]) for item in keys),
        "12": any(at > _instant(item["expires_at"]) for item in keys),
        "13": any(
            entry["asset_type"] not in item["allowed_asset_types"] or entry["workflow"] not in item["allowed_workflows"]
            for item in keys
        ),
    }
    met |= {row for row, holds in conditions.items() if holds}
    authorised = keys[0]["issuer_key_id"] if keys else None
    key_type = keys[0]["key_type"] if keys else None
    return met | _signature_rows(entry, authorised, tampered=tampered, key_type=key_type)


def _first(met: set[str], listed: list[str]) -> str:
    """The row of the table that decides a run meeting ``met``.

    The last row, "—", is the table's "otherwise": its condition holds for every run, so it takes
    part in the order like any row, and a row listed after it would never decide anything.
    """
    return min(met | {"—"}, key=listed.index)


def _combine(*changes: dict[str, Any]) -> dict[str, Any]:
    combined: dict[str, Any] = {}
    for change in changes:
        for kind, value in change.items():
            if kind in {"entry", "trust", "after_signing"} and kind in combined:
                first = combined[kind]
                combined[kind] = lambda doc, a=first, b=value: (a(doc), b(doc))[-1]
            else:
                combined[kind] = value
    return combined


def _material(key: IssuerKey, change: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, bool]:
    """The entry and trust registry a change produces, and whether the signed value was changed."""
    entry, registry = authorization_material(key, entry=change.get("entry"), trust=change.get("trust"))
    tampered = bool(change["after_signing"](entry)) if "after_signing" in change else False
    return entry, (None if change.get("absent_trust_registry") else registry), tampered


def _run_documents(
    tmp_path: Path, entry: dict[str, Any], registry: dict[str, Any] | None, **kwargs: Any
) -> dict[str, Any]:
    if registry is None:
        # Row 1: what the trust registry's path names is no regular file. Nothing found there
        # refuses the run as a whole instead (report-contract.md section 5.3).
        (tmp_path / "trust-directory").mkdir(parents=True, exist_ok=True)
        return verify_path(
            BUNDLE,
            registry_entry_path=write_json(tmp_path / "entry.json", entry),
            trust_registry_path=tmp_path / "trust-directory",
            **kwargs,
        ).to_dict()
    return run_authorization(tmp_path, entry, registry, **kwargs)


def _run_path(tmp_path: Path, key: IssuerKey, change: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    entry, registry, _ = _material(key, change)
    return _run_documents(tmp_path, entry, registry, **kwargs)


def _statuses(report: dict[str, Any]) -> tuple[str | None, str | None]:
    trust = report["trust_registry"] or {}
    return trust.get("authorization_status"), trust.get("signature_status")


def _step_entry(key: IssuerKey, *rows: str) -> tuple[dict[str, Any], bool]:
    """The fixture entry with the step changes of ``rows``, signed between the two phases."""
    entry = fixture_entry()
    for row in rows:
        phase, change = STEP_CHANGES[row]
        if phase == "before":
            change(entry)
    if isinstance(entry.get("signature"), dict):
        key.sign_entry(entry)
    tampered = False
    for row in rows:
        phase, change = STEP_CHANGES[row]
        if phase == "after":
            applied = change(entry)
            if row == "20":
                tampered = bool(applied)
    return entry, tampered


def _step(key: IssuerKey, entry: dict[str, Any]) -> tuple[str, str]:
    status = trust_registry._verify_signature(
        entry, key.public_key_hex, expected_key_id=AUTHORISED_KEY_ID, key_type="secp256k1"
    ).status
    return AUTHORIZED, status


def _library(tmp_path: Path, key: IssuerKey, *, entry: Change | None, trust: Change | None, absent: bool) -> tuple:
    document_entry, registry = authorization_material(key)
    if entry is not None:
        entry(document_entry)
    if trust is not None:
        trust(registry)
    if absent:
        path = tmp_path / "trust-directory"
        path.mkdir(parents=True)
    else:
        path = write_json(tmp_path / "trust.json", registry)
    result = trust_registry.verify_registry_entry_trust(document_entry, trust_registry_path=path)
    return result.authorization_status, result.signature_status


def test_every_row_of_the_evaluation_order(tmp_path: Path) -> None:
    order = _order()
    listed = list(order)
    assert set(order) == set(PATH_ROWS) | UNREACHABLE_IN_A_BUNDLE | LIBRARY_ROWS, sorted(order)
    key = IssuerKey()
    got: dict[str, Any] = {}
    reports: dict[str, dict[str, Any]] = {}
    for row, change in PATH_ROWS.items():
        entry, registry, tampered = _material(key, change)
        # Each change makes exactly its own row's condition hold: the model and the fixtures agree.
        assert _path_rows(entry, registry, tampered=tampered) == ({row} if row != "—" else set()), row
        report = _run_documents(tmp_path / f"row-{row}", entry, registry)
        reports[row] = report
        got[row] = _statuses(report)
    for row in sorted(UNREACHABLE_IN_A_BUNDLE, key=listed.index):
        entry, tampered = _step_entry(key, row)
        assert _signature_rows(entry, AUTHORISED_KEY_ID, tampered=tampered) == {row}, row
        got[row] = _step(key, entry)
    got["2"] = _library(tmp_path / "row-2", key, entry=lambda e: e.update(smuggled="x"), trust=None, absent=False)
    assert got == order

    # Row 16 from the trust entry's side: a key type the allowlist does not pair with the algorithm.
    entry, registry, _ = _material(key, _trust(_key(key_type="ed25519")))
    assert _path_rows(entry, registry, tampered=False) == {"16"}
    assert _statuses(_run_documents(tmp_path / "row-16-key-type", entry, registry)) == order["16"]

    # Section 9: the run's outcome follows the row's effect. A row that holds leaves the run in
    # review only because no root was supplied; a review row names its reason; a failure fails.
    effects = _effects()
    for row, report in reports.items():
        authorization, signature = order[row]
        effect = effects[row]
        observed = (
            report["status"],
            report["checks"]["trust_registry"],
            report["checks"]["registry_signature"],
            report["trust_registry"]["trust_registry_root_signature_status"],
            tuple(report["review_reasons"]),
        )
        if effect == "holds":
            expected = (
                "OFFLINE_REVIEW",
                True,
                "VALID_SIGNATURE",
                "NO_PINNED_TRUST_ROOT",
                ("trust_registry_root_not_pinned",),
            )
        elif effect == "failure":
            expected = ("OFFLINE_FAIL", False, signature or "UNSUPPORTED", "ROOT_SIGNATURE_NOT_EVALUATED", ())
        else:
            expected = ("OFFLINE_REVIEW", False, "UNSUPPORTED", "ROOT_SIGNATURE_NOT_EVALUATED", (effect,))
        assert observed == expected, row


# Neighboring rows of the table whose conditions cannot hold together without an earlier row
# holding too, so that no run can show which of the two comes first.
EXCLUSIVE = {
    frozenset({"4", "5"}): "row 5 looks among the issuer's entries, which row 4 finds absent",
    frozenset({"5", "6"}): "row 6 needs the key found, which row 5 finds absent",
    frozenset({"7", "8"}): "a key found once has one status; found twice, row 6 decides first",
    frozenset({"9", "10"}): "both hold only for an inverted registry window, which row 3 refuses first",
    frozenset({"11", "12"}): "both hold only for an inverted key window, which row 3 refuses first",
    frozenset({"14", "15"}): "row 15 reads a signature object, which row 14 finds absent",
}


def _combined_runs(tmp_path: Path, key: IssuerKey, listed: list[str]) -> dict[str, tuple[set[str], tuple]]:
    """Every change alone and every pair of changes, as the rows its documents meet and the statuses reported."""
    runs: dict[str, tuple[set[str], tuple]] = {}
    path_rows = [row for row in PATH_ROWS if row != "—"]
    for row in [*path_rows, "—"]:
        entry, registry, tampered = _material(key, PATH_ROWS[row])
        runs[f"path {row}"] = (
            _path_rows(entry, registry, tampered=tampered),
            _statuses(
                _run_documents(tmp_path / f"path-{path_rows.index(row) if row != '—' else 'none'}", entry, registry)
            ),
        )
    for row in STEP_CHANGES:
        entry, tampered = _step_entry(key, row)
        runs[f"step {row}"] = (_signature_rows(entry, AUTHORISED_KEY_ID, tampered=tampered), _step(key, entry))
    for first, second in itertools.combinations(path_rows, 2):
        # The later row's change is applied first, so a duplicate copies a revoked key, and so on.
        entry, registry, tampered = _material(key, _combine(PATH_ROWS[second], PATH_ROWS[first]))
        label = f"path {first}+{second}"
        runs[label] = (
            _path_rows(entry, registry, tampered=tampered),
            _statuses(_run_documents(tmp_path / label.replace(" ", "-"), entry, registry)),
        )
    for first, second in itertools.combinations(sorted(STEP_CHANGES, key=listed.index), 2):
        entry, tampered = _step_entry(key, first, second)
        runs[f"step {first}+{second}"] = (
            _signature_rows(entry, AUTHORISED_KEY_ID, tampered=tampered),
            _step(key, entry),
        )
    smuggled = lambda e: e.update(smuggled="x")  # noqa: E731
    runs["library 1+2"] = ({"1", "2"}, _library(tmp_path / "1+2", key, entry=smuggled, trust=None, absent=True))
    runs["library 2+3"] = (
        {"2", "3"},
        _library(
            tmp_path / "2+3", key, entry=smuggled, trust=_registry(object_type="not_a_trust_registry"), absent=False
        ),
    )
    return runs


@pytest.fixture(scope="module")
def combined_runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[set[str], tuple]]:
    return _combined_runs(tmp_path_factory.mktemp("combined"), IssuerKey(), list(_order()))


def test_the_first_row_among_those_a_run_meets_decides(combined_runs: dict[str, tuple[set[str], tuple]]) -> None:
    """Every change alone and every pair combined: the first row its documents meet is reported."""
    order = _order()
    listed = list(order)
    runs = combined_runs
    got = {label: statuses for label, (_, statuses) in runs.items()}
    expected = {label: order[_first(met, listed)] for label, (met, _) in runs.items()}
    assert got == expected


def test_every_adjacent_pair_of_rows_is_decided_by_a_run(combined_runs: dict[str, tuple[set[str], tuple]]) -> None:
    """Two neighboring rows either lead some combined run, or cannot hold together.

    A run decides a pair when the pair are the first two rows, in the table's order, among those
    its documents meet: swapping those two rows changes the row that run must report. Swapping any
    two rows of the table swaps at least one such neighboring pair.
    """
    order = _order()
    listed = list(order)
    decided = set()
    for met, _ in combined_runs.values():
        leading = sorted(met | {"—"}, key=listed.index)[:2]
        if len(leading) == 2:
            decided.add(frozenset(leading))
    neighbours = {frozenset(pair) for pair in zip(listed, listed[1:], strict=False)}
    undecided = sorted((sorted(pair, key=listed.index) for pair in neighbours - decided - set(EXCLUSIVE)), key=str)
    assert not undecided, f"neighbouring rows no run decides and no reason excludes: {undecided}"
    assert set(EXCLUSIVE) <= neighbours, "an exclusion names rows that are not neighbours"


COHERENCE = {
    "active-with-revoked-at": _key(revoked_at="2026-05-01T00:00:00Z"),
    "active-with-revocation-reason": _key(revocation_reason="compromised"),
    "suspended-with-revoked-at": _key(status="suspended", revoked_at="2026-05-01T00:00:00Z"),
    "suspended-with-revocation-reason": _key(status="suspended", revocation_reason="compromised"),
    "revoked-without-revoked-at": _key(status="revoked", revoked_at=None),
    "key-window-inverted": _key(effective_from="2026-06-01T00:00:00Z"),
    "key-window-one-second": _key(effective_from="2026-05-10T00:00:00Z", expires_at="2026-05-10T00:00:00Z"),
    "registry-window-inverted": _registry(effective_at="2026-06-01T00:00:00Z"),
    "registry-issued-after-expiry": _registry(issued_at="2026-06-01T00:00:00Z"),
    "registry-issued-in-advance": _registry(issued_at="2026-04-01T00:00:00Z"),
    "second-entry-contradicts": lambda registry: registry["entries"].append(
        {**copy.deepcopy(registry["entries"][0]), "issuer_key_id": "another-key", "revoked_at": "2026-05-01T00:00:00Z"}
    ),
    # The registry's free strings, not empty under W (section 3; bundle-objects.md, "Free strings").
    "entry-issuer-key-id-blank": _key(issuer_key_id=" "),
    "entry-display-name-blank": _key(issuer_display_name="\u00a0"),
    "entry-notes-blank": _key(notes="\u3000"),
    "entry-revocation-reason-blank": _key(status="revoked", revoked_at="2026-05-01T00:00:00Z", revocation_reason=" "),
    "signature-key-id-blank": lambda registry: registry["signature"].update(key_id="\t"),
    "entry-notes-zero-width-space": _key(notes="\u200b"),
}


def test_the_coherence_of_a_trust_registry(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["case", "trust registry", "contract holds"])
    key = IssuerKey()
    assert {code(row["case"]) for row in rows} == set(COHERENCE)
    got, expected = {}, {}
    for row in rows:
        case = code(row["case"])
        got[case] = _statuses(_run_path(tmp_path / case, key, _trust(COHERENCE[case])))[0]
        expected[case] = AUTHORIZED if row["contract holds"] == "yes" else "INVALID_TRUST_REGISTRY"
    assert got == expected


def test_lifecycle_states_decide_whatever_the_instant(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["status", "meaning", "may authorize"])
    states = {
        "active": {},
        "suspended": _trust(_key(status="suspended")),
        # revoked_at later than the evaluation time: revoked all the same.
        "revoked": _trust(_key(status="revoked", revoked_at="2026-06-01T00:00:00Z")),
    }
    key = IssuerKey()
    assert [code(row["status"]) for row in rows] == list(states)
    got = {status: _statuses(_run_path(tmp_path / status, key, states[status]))[0] for status in states}
    expected = {
        code(row["status"]): AUTHORIZED
        if row["may authorize"].startswith("yes")
        else {"suspended": "ISSUER_KEY_SUSPENDED", "revoked": "ISSUER_KEY_REVOKED"}[code(row["status"])]
        for row in rows
    }
    assert got == expected


WINDOWS = {
    "key-effective-from-equal": _key(effective_from="2026-05-10T00:00:00Z"),
    "key-expires-at-equal": _key(expires_at="2026-05-10T00:00:00Z"),
    "registry-effective-at-equal": _registry(effective_at="2026-05-10T00:00:00Z"),
    "registry-expires-at-equal": _registry(expires_at="2026-05-10T00:00:00Z"),
    "key-expires-at-one-second-after": _key(expires_at="2026-05-09T23:59:59Z"),
}


def test_both_windows_include_their_bounds(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["case", "evaluation time", "authorized"])
    key = IssuerKey()
    assert {code(row["case"]) for row in rows} == set(WINDOWS)
    got, expected = {}, {}
    for row in rows:
        case = code(row["case"])
        report = _run_path(tmp_path / case, key, _trust(WINDOWS[case]))
        got[case] = (_statuses(report)[0] == AUTHORIZED, report["status"])
        # Authorized, the run is in review only for the root no run here supplies; not authorized,
        # the window leaves authorization not established, which is a review too (section 9).
        assert row["authorized"] in {"yes", "no, and the run is `OFFLINE_REVIEW` (§9)"}, row["authorized"]
        expected[case] = (row["authorized"] == "yes", "OFFLINE_REVIEW")
    assert got == expected
    assert _run_path(tmp_path / "beyond", key, _trust(WINDOWS["key-expires-at-one-second-after"]))[
        "review_reasons"
    ] == ["issuer_key_outside_validity_window"]


def test_the_evaluation_time(tmp_path: Path) -> None:
    """Section 2: authorization is judged at the operator's evaluation time, and only at it."""
    rows = table(document(SPEC), ["case", "operator evaluation time", "key window holds it", "outcome"])
    key = IssuerKey()
    # The key's window ends at 2026-05-20T00:00:00Z here, before the registry's, so a time one second
    # after it is outside the key's window and inside the registry's.
    key_until = "2026-05-20T00:00:00Z"
    cases: dict[str, tuple[dict[str, Any], str | None]] = {
        "operator-time": ({}, "2026-05-20T00:00:00Z"),
        "no-time-active-key": ({}, None),
        "no-time-revoked-key": (_trust(_key(status="revoked", revoked_at="2026-05-01T00:00:00Z")), None),
        "operator-time-key-expired": (_trust(_key(expires_at=key_until)), "2026-05-20T00:00:01Z"),
    }
    assert [code(row["case"]) for row in rows] == list(cases)
    got, expected = {}, {}
    for row in rows:
        case = code(row["case"])
        change, evaluation_time = cases[case]
        written = row["operator evaluation time"]
        if written == "none":
            assert evaluation_time is None, case
        elif written == "one second after the key's `expires_at`":
            assert (_instant(evaluation_time) - _instant(key_until)).total_seconds() == 1, case
        else:
            assert code(written) == evaluation_time, case
        report = _run_path(tmp_path / case, key, change, evaluation_time=evaluation_time)
        assert report["evaluation_time"] == evaluation_time, case
        outcome = codes(row["outcome"])
        if row["outcome"].startswith("authorization judged at"):
            got[case] = (report["trust_registry"]["authorization_status"], report["evaluation_time"])
            expected[case] = (AUTHORIZED, outcome[0])
        elif outcome[1] in {"ISSUER_KEY_REVOKED"}:
            got[case] = (report["status"], report["trust_registry"]["authorization_status"])
            expected[case] = tuple(outcome)
        else:
            got[case] = (report["status"], report["review_reasons"][0])
            expected[case] = tuple(outcome)
    assert got == expected


def test_no_source_of_the_time_but_the_operator(tmp_path: Path) -> None:
    """Section 2: no time-stamp token and no issuer date is a source of the evaluation time.

    The command line refuses the former --tsa-token option with exit 64 and no report, and the
    library refuses an evaluation time that is not a calendar instant, a time claiming another
    source included, before it reads anything: the bundle and trust registry paths do not exist.
    The entry's own dates never move the outcome: the same documents with the entry's
    effective_at and issued_at moved outside every window still authorize at the operator's time.
    """
    flat = " ".join(document(SPEC).split())
    for sentence in (
        "**Issuer dates never decide authorization.**",
        "This version of the protocol defines no time-stamp token and no other attestation of time",
        "the operator's evaluation time is the only time a verifier reads.",
    ):
        assert sentence in flat, sentence

    key = IssuerKey()
    entry, registry = authorization_material(key)
    entry_path = write_json(tmp_path / "entry.json", entry)
    registry_path = write_json(tmp_path / "trust_registry.json", registry)
    token = tmp_path / "token.tsr"
    token.write_bytes(bytes([0x30, 0x03, 0x02, 0x01, 0x00]))
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            exit_code = main(
                [str(BUNDLE), "--registry-entry", str(entry_path), "--trust-registry", str(registry_path)]
                + ["--tsa-token", str(token), "--evaluation-time", EVALUATION_TIME, "--json"]
            )
        except SystemExit as exc:
            exit_code = int(exc.code)
    assert (exit_code, out.getvalue()) == (64, "")

    for claimed in ({"instant": EVALUATION_TIME, "source": "tsa"}, "2026-05-10T00:00:00+00:00", ""):
        with pytest.raises(EvaluationTimeError):
            verify_path(
                tmp_path / "no-such-bundle",
                registry_entry_path=entry_path,
                trust_registry_path=registry_path,
                evaluation_time=claimed,
            )
    report = run_authorization(tmp_path / "operator", entry, registry)
    assert report["evaluation_time"] == EVALUATION_TIME
    assert "evaluation_time_source" not in report["trust_registry"]
    # Issuer dates far outside every window: the run does not move.
    dated, _ = authorization_material(
        key, entry=lambda e: e.update(effective_at="2001-01-01T00:00:00Z", issued_at="2001-01-01T00:00:00Z")
    )
    moved = run_authorization(tmp_path / "issuer-dates", dated, registry)
    assert (moved["status"], _statuses(moved)) == (report["status"], _statuses(report))


def test_the_vocabularies_are_the_implementations() -> None:
    text = document(SPEC)
    authorization = [code(row["`authorization_status`"]) for row in table(text, ["`authorization_status`"])]
    signature = [code(row["`signature_status`"]) for row in table(text, ["`signature_status`"])]

    def constants(prefix: str) -> set[str]:
        return {value for name, value in vars(trust_registry).items() if name.startswith(prefix)}

    assert len(set(authorization)) == len(authorization) and set(authorization) == constants("AUTH_STATUS_")
    assert len(set(signature)) == len(signature) and set(signature) == constants("SIG_STATUS_")
    # A report carries no other summary of these statuses: the former trust_status is gone.
    assert constants("TRUST_STATUS_") == set()
    assert "trust_status" not in codes(text)
    for authorization_status, signature_status in _order().values():
        assert authorization_status in authorization
        assert signature_status is None or signature_status in signature
    assert "ROOT_SIGNATURE_NOT_EVALUATED" in codes(text)


def test_root_authentication_decides_a_run_whose_key_is_authorized(tmp_path: Path) -> None:
    """Section 9: no root, REVIEW; a root that did not sign the registry, FAIL; the root that did, OK."""
    key, root, stranger = IssuerKey(), IssuerKey(), IssuerKey()
    entry, registry = authorization_material(key)
    registry["signature"]["key_id"] = "root-1"
    registry["signature"]["signature"] = root.sign_digest(
        hashlib.sha256(trust_registry_signing_bytes(registry)).digest()
    )

    def roots(signer: IssuerKey) -> tuple:
        return parse_trust_roots(
            {
                "object_type": "trust_root_document",
                "schema_version": "v1",
                "roots": [
                    {
                        "key_id": "root-1",
                        "key_type": "secp256k1",
                        "public_key_hex": signer.public_key_hex,
                        "not_before": "2026-01-01T00:00:00Z",
                        "not_after": "2027-01-01T00:00:00Z",
                    }
                ],
            }
        )

    got = {}
    for label, kwargs in {
        "no-root": {},
        "other-root": {"trust_roots": roots(stranger)},
        "signing-root": {"trust_roots": roots(root)},
    }.items():
        report = run_authorization(tmp_path / label, entry, registry, **kwargs)
        got[label] = (report["status"], report["trust_registry"]["trust_registry_root_signature_status"])
    assert got == {
        "no-root": ("OFFLINE_REVIEW", "NO_PINNED_TRUST_ROOT"),
        "other-root": ("OFFLINE_FAIL", "ROOT_SIGNATURE_INVALID"),
        "signing-root": ("OFFLINE_OK", "ROOT_SIGNATURE_VALID"),
    }
    assert fixture_trust_registry()["entries"][0]["issuer_key_id"] == "demo-key-2"


def test_the_key_identifiers_of_rows_18_and_19_are_compared_as_written() -> None:
    """Rows 18 and 19 compare the key ids exactly (section 5), whatever they hold.

    A key id made only of the whitespace set W is still a value compared as written: whether the
    entry's contract accepts one is row 2's question, not a reason to change the comparison.
    """
    flat = " ".join(document(SPEC).split())
    assert (
        "Both comparisons, and the key comparisons of rows 18 and 19 of §6, are exact equality of code units: "
        "nothing is trimmed, case-folded or normalised" in flat
    )
    order = _order()
    key = IssuerKey()
    # (authorized issuer_key_id, entry issuer_key_id, signature key_id) -> the row that decides
    cases = {
        "whitespace-ids-differ-in-the-signature": ((" ", " ", "\u00a0"), "18"),
        "whitespace-ids-differ-in-the-entry": ((" ", "\u00a0", " "), "19"),
        "whitespace-ids-agree": ((" ", " ", " "), "—"),
        "signature-id-with-a-trailing-space": (("demo-key-2", "demo-key-2", "demo-key-2 "), "18"),
    }
    got, expected = {}, {}
    for label, ((authorised, entry_id, signature_id), row) in cases.items():
        entry = fixture_entry()
        entry["issuer_key_id"] = entry_id
        entry["signature"]["key_id"] = signature_id
        key.sign_entry(entry)
        got[label] = trust_registry._verify_signature(
            entry, key.public_key_hex, expected_key_id=authorised, key_type="secp256k1"
        ).status
        expected[label] = order[row][1]
    assert got == expected


def test_equal_bounds_are_a_window_for_a_trust_registry_and_malformed_for_a_trust_root(tmp_path: Path) -> None:
    """Section 3 and trust-root.md section 3 state two rules for equal bounds, each beside the other.

    A trust registry's window, and a key's, with equal bounds is a valid window of one second; a
    trust root whose not_before equals its not_after is malformed. Both documents say so, and this
    verifier applies both.
    """
    from loquitur.verify.trust_root import TrustRootError

    registry_side = " ".join(document(SPEC).split())
    root_side = " ".join(document("trust-root.md").split())
    assert "A window whose bounds are equal is a window of one second, and is valid;" in registry_side
    assert (
        "A root whose `not_before` equals its `not_after` is malformed; a trust-registry window with equal bounds is not."
        in root_side
    )

    key = IssuerKey()
    instant = "2026-05-10T00:00:00Z"  # the fixture entry's effective_at
    one_second = {
        "key": _trust(_key(effective_from=instant, expires_at=instant)),
        "registry": _trust(_registry(effective_at=instant, expires_at=instant, issued_at=instant)),
    }
    got = {label: _statuses(_run_path(tmp_path / label, key, change))[0] for label, change in one_second.items()}
    assert got == {"key": AUTHORIZED, "registry": AUTHORIZED}

    def root(not_before: str, not_after: str) -> dict[str, Any]:
        return {
            "object_type": "trust_root_document",
            "schema_version": "v1",
            "roots": [
                {
                    "key_id": "root-1",
                    "key_type": "secp256k1",
                    "public_key_hex": key.public_key_hex,
                    "not_before": not_before,
                    "not_after": not_after,
                }
            ],
        }

    assert parse_trust_roots(root("2026-05-10T00:00:00Z", "2026-05-10T00:00:01Z"))
    with pytest.raises(TrustRootError):
        parse_trust_roots(root(instant, instant))
