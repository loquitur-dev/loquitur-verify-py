"""Every instant of every protocol document is a calendar instant, whenever the document is loaded.

The schemas give each instant the pattern
``^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)Z$``,
which admits values that are not instants: February 30, April 31, February 29 of a common
year, second 60, year 0000. Refused only where the verifier evaluates them (the registry
entry's instants on the authorization path and the trust registry's windows), a receipt dated February 30
would verify at every level, an entry issued on February 30 would link at the link check, and a trust
registry issued on February 30 would be trusted.

So the calendar belongs to the document's contract, at every level, with the document's own
contract-violation outcome: a receipt is ``verification_receipt_contract_violation``, a
registry entry ``registry_entry_contract_violation`` (registry_link false), a trust registry
``INVALID_TRUST_REGISTRY`` (trust_registry false), a trust-root document ``TrustRootError``
(``--trust-root`` exit 64). Leap days of leap years remain instants.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from authorization_kit import IssuerKey, authorization_material, outcome, run_authorization
from bundle_builder import Bundle

from loquitur.verify.contract_validation import contract_errors
from loquitur.verify.evaluation_time import parse_calendar_instant
from loquitur.verify.runner import verify_path
from loquitur.verify.schema_contract import SCHEMA_CONTRACTS
from loquitur.verify.trust_root import TrustRootError, parse_trust_roots

INSTANT_PATTERN = r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)Z$"
NOT_INSTANTS = {
    "feb30": "2026-02-30T12:00:00Z",
    "apr31": "2026-04-31T12:00:00Z",
    "feb29-common-year": "2026-02-29T12:00:00Z",
    "second60": "2026-04-29T12:00:60Z",
    "year0000": "0000-01-01T00:00:00Z",
}
LEAP_DAY = "2028-02-29T12:00:00Z"

FAIL = {"status": "OFFLINE_FAIL", "verdict": "FAIL", "exit_code": 1}
PASS = {"status": "OFFLINE_OK", "verdict": "PASS", "exit_code": 0}


def _summary(report: dict) -> dict:
    return {
        "status": report["status"],
        "verdict": report["verdict"],
        "exit_code": report["exit_code"],
        "registry_link": report["checks"]["registry_link"],
        "errors": [error["code"] for error in report["errors"]],
    }


# The one parser reads ASCII digits only: a digit of another script is refused, though str.isdigit
# and a regular expression's \d both accept it.
@pytest.mark.parametrize(
    "value",
    [
        "\u0662\u0660\u0662\u0666-05-10T00:00:00Z",  # Arabic-Indic digits in the year
        "2026-05-1\u0660T00:00:00Z",
        "2026-05-10T00:00:0\uff10Z",  # a fullwidth zero
    ],
    ids=["arabic-indic-year", "arabic-indic-day", "fullwidth-second"],
)
def test_an_instant_written_with_digits_of_another_script_is_refused(value: str) -> None:
    assert parse_calendar_instant(value) is None
    assert parse_calendar_instant("2026-05-10T00:00:00Z") is not None


def test_the_contract_names_every_instant_of_the_three_documents_a_verifier_loads() -> None:
    """The calendar rule is keyed to the schemas' instant pattern: it must reach every instant."""

    def instants(node, path):
        if isinstance(node, dict):
            if node.get("pattern") == INSTANT_PATTERN:
                yield path
            for key, value in node.items():
                yield from instants(value, f"{path}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                yield from instants(value, f"{path}/{index}")

    found = {
        name: sorted(p.rsplit("/", 1)[-1] for p in instants(SCHEMA_CONTRACTS[name], "")) for name in SCHEMA_CONTRACTS
    }
    assert {name: fields for name, fields in found.items() if fields} == {
        "registry_entry": ["anchored_at", "effective_at", "issued_at"],
        "trust_registry": ["effective_at", "effective_from", "expires_at", "expires_at", "issued_at", "revoked_at"],
        "verification_receipt": ["verified_at"],
    }


def test_a_receipt_instant_that_is_not_a_date_breaks_the_receipt_contract(tmp_path: Path) -> None:
    got, expected = {}, {}
    for label, value in {**NOT_INSTANTS, "leap-day": LEAP_DAY}.items():
        bundle = Bundle().edit("verification_receipt.json", lambda r, v=value: r.update(verified_at=v)).seal()
        root = bundle.write(tmp_path / label / "bundle")
        integrity_report = verify_path(root).to_dict()
        link_report = verify_path(
            root, registry_entry_path=bundle.link_entry(tmp_path / label / "entry.json")
        ).to_dict()
        got[label] = {"integrity": _summary(integrity_report), "link": _summary(link_report)}
        if label == "leap-day":
            expected[label] = {
                "integrity": {**PASS, "registry_link": None, "errors": []},
                "link": {**PASS, "registry_link": True, "errors": []},
            }
        else:
            refused = ["verification_receipt_contract_violation"]
            expected[label] = {
                "integrity": {**FAIL, "registry_link": None, "errors": refused},
                "link": {**FAIL, "registry_link": False, "errors": refused},
            }
        assert contract_errors("verification_receipt", bundle.json("verification_receipt.json")) == (
            [] if label == "leap-day" else ["verification_receipt.verified_at:calendar"]
        )
    assert got == expected


def test_a_registry_entry_instant_that_is_not_a_date_breaks_the_entry_contract(tmp_path: Path) -> None:
    key = IssuerKey()
    got, expected = {}, {}
    refused = {
        **FAIL,
        "registry_link": False,
        "trust_registry": None,
        "registry_signature": "UNSUPPORTED",
        "authorization_status": None,
        "signature_status": None,
    }
    for label, value in NOT_INSTANTS.items():
        for field in ("issued_at", "effective_at", "anchored_at"):
            entry, registry = authorization_material(key, entry=lambda e, f=field, v=value: e.update({f: v}))
            link_report = verify_path(
                Path(__file__).resolve().parent / "fixtures" / "link_valid_bundle",
                registry_entry_path=_write(tmp_path / label / field / "entry.json", entry),
            ).to_dict()
            got[f"{field}.{label}"] = {
                "link": _summary(link_report),
                "authorization": outcome(run_authorization(tmp_path / label / field, entry, registry)),
            }
            expected[f"{field}.{label}"] = {
                "link": {**FAIL, "registry_link": False, "errors": ["registry_entry_contract_violation"]},
                "authorization": refused,
            }
    assert got == expected


def test_a_trust_registry_instant_that_is_not_a_date_makes_the_registry_invalid(tmp_path: Path) -> None:
    key = IssuerKey()
    got, expected = {}, {}
    invalid = {
        **FAIL,
        "registry_link": True,
        "trust_registry": False,
        "registry_signature": "UNSUPPORTED",
        "authorization_status": "INVALID_TRUST_REGISTRY",
        "signature_status": None,
    }
    for label, value in NOT_INSTANTS.items():
        changes = {
            "issued_at": lambda t, v=value: t.update(issued_at=v),
            "effective_at": lambda t, v=value: t.update(effective_at=v),
            "expires_at": lambda t, v=value: t.update(expires_at=v),
            "entries[0].effective_from": lambda t, v=value: t["entries"][0].update(effective_from=v),
            "entries[0].expires_at": lambda t, v=value: t["entries"][0].update(expires_at=v),
            # revoked, so that revoked_at is required and only its calendar is in question
            "entries[0].revoked_at": lambda t, v=value: t["entries"][0].update(status="revoked", revoked_at=v),
        }
        for where, change in changes.items():
            entry, registry = authorization_material(key, trust=change)
            got[f"{where}.{label}"] = outcome(run_authorization(tmp_path / label / where, entry, registry))
            expected[f"{where}.{label}"] = invalid
    entry, registry = authorization_material(
        key, trust=lambda t: t["entries"][0].update(status="revoked", revoked_at=LEAP_DAY)
    )
    got["entries[0].revoked_at.leap-day"] = outcome(run_authorization(tmp_path / "leap-day", entry, registry))
    expected["entries[0].revoked_at.leap-day"] = {**invalid, "authorization_status": "ISSUER_KEY_REVOKED"}
    assert got == expected


DOCUMENT = {"object_type": "trust_root_document", "schema_version": "v1"}


@pytest.mark.parametrize("field", ["not_before", "not_after"])
def test_a_trust_root_instant_that_is_not_a_date_is_a_trust_root_error(field: str) -> None:
    root = {
        "key_id": "root-1",
        "key_type": "secp256k1",
        "public_key_hex": "04" + "11" * 64,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }
    for value in NOT_INSTANTS.values():
        with pytest.raises(TrustRootError, match=field):
            parse_trust_roots({**DOCUMENT, "roots": [dict(root, **{field: value})]})
    assert (
        len(
            parse_trust_roots(
                {**DOCUMENT, "roots": [dict(root, not_before="2028-01-01T00:00:00Z", not_after=LEAP_DAY)]}
            )
        )
        == 1
    )


def _write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path
