"""The verification receipt: its closed contract at every level, and its bond to the bundle.

verification_receipt.json is validated against verification_receipt.schema.json at every
level, not only compared field by field with the registry entry at the link check. Without that:
  * at the structure and integrity checks a receipt that is not JSON, carries an unknown member or has no
    object_type would verify PASS, because nothing would read it;
  * at the link and authorization checks the same receipts would verify PASS as long as the compared fields agreed,
    and a string policy_version "1" could be coerced into the integer the entry's MAJOR is
    compared with;
  * unless the receipt's bundle_id must be this bundle's, and its p1_sha256 this bundle's P1,
    an issuer could sign a receipt about something else and collect PASS;
  * a receipt or registry entry that is present and not a JSON object must fail the link,
    not leave registry_link null, "not evaluated", for a document the run refused.
Every bundle here is sealed around its one defect and every link entry is bound to the
receipt it is compared with, so only the rule under test can refuse it. Receipts that verify,
and links that are null or false either way, run in the same test as a row the contract
refuses, so every test fails without it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_builder import FIXTURES, Bundle, jcs, sha

from loquitur.verify import cli
from loquitur.verify.runner import verify_path


def _run(tmp_path: Path, bundle: Bundle, entry: Path | None = None, **kwargs) -> dict:
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root, registry_entry_path=entry, **kwargs).to_dict()
    argv = [str(root), "--json"] + (["--registry-entry", str(entry)] if entry else [])
    if "trust_registry_path" not in kwargs:
        assert cli.main(argv) == report["exit_code"]
    return report


def _receipt_edited(mutate) -> Bundle:
    return Bundle().seal().edit("verification_receipt.json", mutate)


def _receipt_raw(raw: bytes) -> Bundle:
    bundle = Bundle().seal()
    bundle.members["verification_receipt.json"] = raw
    return bundle


_SCHEMA_INVALID = {
    "unknown-member": lambda r: r.update(unauthenticated_interpretation="x"),
    "missing-object-type": lambda r: r.pop("object_type"),
    "wrong-object-type": lambda r: r.update(object_type="arbitrary"),
    "policy-version-string": lambda r: r.update(policy_version="1"),
    "policy-version-zero": lambda r: r.update(policy_version=0),
    # Not well formed under the version gate's grammar (a leading zero), so the contract refuses it.
    "schema-version-v09": lambda r: r.update(schema_version="v09"),
    "verified-at-not-an-instant": lambda r: r.update(verified_at="not-an-instant"),
    "verified-at-newline": lambda r: r.update(verified_at=r["verified_at"] + "\n"),
    "reason-codes-empty": lambda r: r.update(reason_codes=[]),
    "reason-codes-duplicate": lambda r: r.update(reason_codes=["INTEGRITY_OK", "INTEGRITY_OK"]),
    "reason-codes-unknown": lambda r: r.update(reason_codes=["NOT_A_CODE"]),
    "reason-code-padded": lambda r: r.update(reason_codes=[" INTEGRITY_OK "]),
    # Not well formed under the version gate's grammar, so the contract refuses it; a
    # well-formed later version is the gate's (test_a_later_receipt_version_is_unsupported).
    "vocabulary-version-wrong": lambda r: r.update(reason_code_vocabulary_version="loquitur.reasons.v1"),
    "p1-sha256-not-hex": lambda r: r.update(p1_sha256="z" * 64),
    "missing-verification-mode": lambda r: r.pop("verification_mode"),
}
_UNREADABLE = {
    "not-json": b"not valid JSON",
    "array": b"[]",
    "number": b"1",
    "invalid-utf8": b'{"object_type":"verification_\xffreceipt"}',
    "nested-65": b'{"x":' + b"[" * 64 + b"]" * 64 + b"}",
}


# ---------------------------------------------------------------- structure, validated whenever present


@pytest.mark.parametrize("label", sorted(_SCHEMA_INVALID))
def test_a_schema_invalid_receipt_fails_without_a_registry_entry(tmp_path: Path, label: str) -> None:
    report = _run(tmp_path, _receipt_edited(_SCHEMA_INVALID[label]))
    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0] == {"code": "verification_receipt_contract_violation"}
    assert report["outcome"]["category"] == "malformed_input_failure"
    assert any(note.startswith("verification_receipt_contract_violation:") for note in report["notes"])
    assert report["checks"]["registry_link"] is None


@pytest.mark.parametrize("label", sorted(_UNREADABLE))
def test_an_unreadable_receipt_fails_without_a_registry_entry(tmp_path: Path, label: str) -> None:
    report = _run(tmp_path, _receipt_raw(_UNREADABLE[label]))
    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0]["code"] == "verification_receipt_contract_violation"
    assert report["checks"]["registry_link"] is None


@pytest.mark.parametrize(
    ("member", "value", "gate"),
    [
        ("schema_version", "v3", "verification_receipt"),
        ("reason_code_vocabulary_version", "loquitur.reason_codes.v2", "reason_code_vocabulary"),
    ],
)
def test_a_later_receipt_version_is_unsupported(tmp_path: Path, member: str, value: str, gate: str) -> None:
    # document-contracts.md section 1a, gates 3 and 4: read before the contract, with or
    # without a registry entry, and no evidence outcome follows.
    alone = _run(tmp_path / "alone", _receipt_edited(lambda r: r.update({member: value})))
    bundle = _receipt_edited(lambda r: r.update({member: value}))
    linked = _run(tmp_path / "linked", bundle, bundle.link_entry(tmp_path / "entry.json"))
    for report in (alone, linked):
        assert (report["status"], report["verdict"], report["exit_code"]) == ("UNSUPPORTED_VERSION", None, 4)
        assert [{k: e[k] for k in ("code", "object", "version")} for e in report["errors"]] == [
            {"code": "unsupported_version", "object": gate, "version": value}
        ]


def test_the_violations_are_named_by_path_and_keyword(tmp_path: Path) -> None:
    report = _run(tmp_path / "invalid", _receipt_edited(_SCHEMA_INVALID["policy-version-string"]))
    assert "verification_receipt_contract_violation:verification_receipt.policy_version:type" in report["notes"]
    # A valid receipt without an entry still verifies, and so does one naming another bundle:
    # the cross-object rule is a link rule.
    assert _run(tmp_path / "valid", Bundle().seal())["status"] == "OFFLINE_OK"
    other = _run(tmp_path / "other-bundle", _receipt_edited(lambda r: r.update(bundle_id="unrelated-bundle")))
    assert other["status"] == "OFFLINE_OK"


# ---------------------------------------------------------------- link, contract, cross-object, exact fields


def _link_run(tmp_path: Path, mutate) -> dict:
    bundle = _receipt_edited(mutate)
    return _run(tmp_path, bundle, bundle.link_entry(tmp_path / "entry.json"))


@pytest.mark.parametrize("label", sorted(_SCHEMA_INVALID))
def test_a_schema_invalid_receipt_fails_the_registry_link(tmp_path: Path, label: str) -> None:
    report = _link_run(tmp_path, _SCHEMA_INVALID[label])
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["registry_link"] is False
    assert report["errors"][0]["code"] == "verification_receipt_contract_violation"
    contract = next(c for c in report["registry_link"]["checks"] if c["name"] == "verification_receipt_contract")
    assert contract["ok"] is False
    assert "registry_link_verification_failed" not in report["notes"]


def test_an_unreadable_receipt_is_a_false_registry_link_and_only_an_absent_one_is_not_evaluated(
    tmp_path: Path,
) -> None:
    got, want = {}, {}
    for label, raw in _UNREADABLE.items():
        bundle = Bundle().seal()
        entry = bundle.link_entry(tmp_path / label / "entry.json")
        bundle.members["verification_receipt.json"] = raw
        report = _run(tmp_path / label, bundle, entry)
        got[label] = (report["status"], report["checks"]["registry_link"])
        want[label] = ("OFFLINE_FAIL", False)
    absent = Bundle().seal()
    entry = absent.link_entry(tmp_path / "absent" / "entry.json")
    del absent.members["verification_receipt.json"]
    report = _run(tmp_path / "absent", absent, entry)
    got["absent"] = (report["status"], report["checks"]["registry_link"])
    # No receipt is not evidence against the bundle: the link is not established (REVIEW).
    want["absent"] = ("OFFLINE_REVIEW", None)
    assert got == want


def test_a_receipt_about_another_bundle_fails_the_registry_link(tmp_path: Path) -> None:
    report = _link_run(tmp_path, lambda r: r.update(bundle_id="unrelated-bundle"))
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["registry_link"] is False
    check = next(c for c in report["registry_link"]["checks"] if c["name"] == "receipt_bundle_id")
    assert check == {
        "name": "receipt_bundle_id",
        "expected": "link_valid_bundle",
        "actual": "unrelated-bundle",
        "ok": False,
        "note": None,
    }


@pytest.mark.parametrize("value", ["LINK_VALID_BUNDLE", " link_valid_bundle"], ids=["case", "padded"])
def test_the_receipt_bundle_id_is_compared_exactly(tmp_path: Path, value: str) -> None:
    report = _link_run(tmp_path, lambda r: r.update(bundle_id=value))
    assert report["checks"]["registry_link"] is False


def test_a_receipt_naming_another_p1_fails_the_registry_link(tmp_path: Path) -> None:
    report = _link_run(tmp_path / "another", lambda r: r.update(p1_sha256="sha256:" + "a" * 64))
    assert report["status"] == "OFFLINE_FAIL"
    check = next(c for c in report["registry_link"]["checks"] if c["name"] == "receipt_p1_sha256")
    assert check["ok"] is False
    # Naming this P1 verifies, and so does naming none, with every optional member null.
    p1_digest = "sha256:" + sha(jcs(Bundle().json("p1.json")))
    assert _link_run(tmp_path / "this", lambda r: r.update(p1_sha256=p1_digest))["status"] == "OFFLINE_OK"
    nullable = (
        "anchor_provider",
        "anchor_type",
        "asset_id",
        "network",
        "p1_sha256",
        "policy_pack_sha256",
        "primary_anchor",
    )
    all_null = _link_run(tmp_path / "all-null", lambda r: r.update(dict.fromkeys(nullable)))
    assert (all_null["status"], all_null["checks"]["registry_link"]) == ("OFFLINE_OK", True)


def test_a_receipt_naming_a_p1_that_did_not_verify_fails_the_registry_link(tmp_path: Path) -> None:
    p1_digest = "sha256:" + sha(jcs(Bundle().json("p1.json")))
    bundle = _receipt_edited(lambda r: r.update(p1_sha256=p1_digest))
    entry = bundle.link_entry(tmp_path / "entry.json")
    bundle.members["p1.sha256"] = b"0" * 64
    report = _run(tmp_path, bundle, entry)
    check = next(c for c in report["registry_link"]["checks"] if c["name"] == "receipt_p1_sha256")
    assert check["ok"] is False


def test_a_padded_policy_id_does_not_match(tmp_path: Path) -> None:
    report = _link_run(tmp_path, lambda r: r.update(policy_id=" loquitur.policy.property.demo"))
    assert report["status"] == "OFFLINE_FAIL"
    policy = next(c for c in report["registry_link"]["checks"] if c["name"] == "policy_id")
    assert policy["ok"] is False


def test_an_integer_valued_policy_version_matches_the_entry_major(tmp_path: Path) -> None:
    raw = Bundle().seal()
    receipt = raw.json("verification_receipt.json")
    raw.members["verification_receipt.json"] = jcs(receipt).replace(b'"policy_version":1', b'"policy_version":1.0')
    entry = raw.link_entry(tmp_path / "entry.json")
    entry_obj = json.loads(entry.read_text(encoding="utf-8"))
    entry_obj["receipt_hash"] = "sha256:" + sha(jcs(receipt))
    entry.write_text(json.dumps(entry_obj), encoding="utf-8")
    assert _run(tmp_path, raw, entry)["status"] == "OFFLINE_OK"


def test_a_prefixed_registry_hash_must_be_lowercase(tmp_path: Path) -> None:
    bundle = Bundle().seal()
    entry = bundle.link_entry(tmp_path / "entry.json")
    entry_obj = json.loads(entry.read_text(encoding="utf-8"))
    entry_obj["manifest_hash"] = entry_obj["manifest_hash"].upper().replace("SHA256:", "sha256:")
    entry.write_text(json.dumps(entry_obj), encoding="utf-8")
    report = _run(tmp_path, bundle, entry)
    manifest_hash = next(c for c in report["registry_link"]["checks"] if c["name"] == "manifest_hash")
    assert manifest_hash["ok"] is not True
    assert report["checks"]["registry_link"] is False


# ---------------------------------------------------------------- a supplied entry that is not an entry


@pytest.mark.parametrize(
    "raw", [b"null", b"[]", b'"entry"', b"not valid JSON"], ids=["null", "array", "string", "not-json"]
)
def test_a_supplied_entry_that_is_not_an_object_is_a_false_registry_link(tmp_path: Path, raw: bytes) -> None:
    entry = tmp_path / "entry.json"
    entry.write_bytes(raw)
    report = _run(tmp_path, Bundle().seal(), entry)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["registry_link"] is False
    assert report["errors"][0]["code"] == "registry_link_verification_failed"


def test_a_null_entry_with_a_trust_registry_is_a_false_link_and_no_trust_evaluation(tmp_path: Path) -> None:
    entry = tmp_path / "entry.json"
    entry.write_bytes(b"null")
    report = _run(
        tmp_path, Bundle().seal(), entry, trust_registry_path=FIXTURES / "authorization_valid_trust_registry.json"
    )
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["registry_link"] is False
    assert report["checks"]["trust_registry"] is None


# ---------------------------------------------------------------- authorization, the receipt fails before trust


cryptography = pytest.importorskip("cryptography", reason="signing an authorization entry needs cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils  # noqa: E402

_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _sign(key, message: bytes) -> str:
    r, s = asym_utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, "big") + min(s, _ORDER - s).to_bytes(32, "big")).hex()


def _public(key) -> str:
    return (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    )


@pytest.mark.parametrize("label", ["unknown-member", "policy-version-string"])
def test_a_schema_invalid_receipt_fails_at_authorization_before_trust_is_evaluated(tmp_path: Path, label: str) -> None:
    from loquitur.verify.signing_envelope import signing_message_bytes
    from loquitur.verify.trust_root import parse_trust_roots, trust_registry_signing_bytes

    issuer, root_key = ec.generate_private_key(ec.SECP256K1()), ec.generate_private_key(ec.SECP256K1())
    bundle = _receipt_edited(_SCHEMA_INVALID[label])
    entry = json.loads((FIXTURES / "authorization_valid_registry_entry.json").read_text(encoding="utf-8"))
    entry["manifest_hash"] = "sha256:" + bundle.manifest_digest()
    entry["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))
    entry["signature"]["signature"] = _sign(issuer, signing_message_bytes(entry))
    trust = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    trust["entries"][0]["public_key_hex"] = _public(issuer)
    trust.pop("signature", None)
    trust["signature"] = {
        "algorithm": "secp256k1_ecdsa_sha256",
        "key_id": "root-1",
        "signature": _sign(root_key, trust_registry_signing_bytes(trust)),
    }
    entry_path, trust_path = tmp_path / "entry.json", tmp_path / "trust.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    roots = parse_trust_roots(
        {
            "object_type": "trust_root_document",
            "schema_version": "v1",
            "roots": [
                {
                    "key_id": "root-1",
                    "key_type": "secp256k1",
                    "public_key_hex": _public(root_key),
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z",
                }
            ],
        }
    )

    report = _run(tmp_path, bundle, entry_path, trust_registry_path=trust_path, trust_roots=roots)

    assert report["status"] == "OFFLINE_FAIL"
    assert report["errors"][0]["code"] == "verification_receipt_contract_violation"
    assert report["checks"]["registry_link"] is False
    assert report["checks"]["trust_registry"] is None
    assert report["checks_requested"] == ["structure", "integrity", "link", "authorization"]
    assert report["checks_established"] == []
