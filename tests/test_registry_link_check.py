from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from loquitur.verify.canonical import canonical_json_sha256
from loquitur.verify.cli import main
from loquitur.verify.registry_link import verify_registry_link
from loquitur.verify.runner import EXIT_OFFLINE_FAIL, EXIT_OFFLINE_OK, EXIT_OFFLINE_REVIEW, verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE_DIR = FIXTURES / "link_valid_bundle"
BUNDLE_ZIP = FIXTURES / "link_valid_bundle.zip"
VALID_ENTRY = FIXTURES / "link_valid_registry_entry.json"


def _check(payload: dict, name: str) -> dict:
    checks = payload["registry_link"]["checks"]
    return next(item for item in checks if item["name"] == name)


# Reason codes whose highest severity derives each verdict: an entry's verdict must be the
# verdict of its grounds (VG-1 to VG-4), so a committed FAIL, WARN or REVIEW cites codes that
# ground it, and the receipt cites the same codes.
GROUNDS = {
    "PASS": ["INTEGRITY_OK"],
    "WARN": ["INTEGRITY_OK", "MARK_STALE"],
    "REVIEW": ["INTEGRITY_OK", "NEEDS_REVIEW"],
    "FAIL": ["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"],
}


def _bundle_committing(tmp_path: Path, receipt_status: str, entry_verdict: str) -> tuple[Path, Path]:
    """A bundle and an entry that agree perfectly, on something other than PASS."""
    root = tmp_path / "committed" / "link_valid_bundle"
    shutil.copytree(BUNDLE_DIR, root)
    receipt_path = root / "verification_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = receipt_status
    receipt["reason_codes"] = GROUNDS[entry_verdict]
    receipt_path.write_text(json.dumps(receipt, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    entry["verdict"] = entry_verdict
    entry["reason_codes"] = GROUNDS[entry_verdict]
    entry["receipt_hash"] = "sha256:" + canonical_json_sha256(receipt)
    entry_path = tmp_path / "entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")
    return root, entry_path


def test_a_registry_entry_committing_fail_cannot_produce_exit_zero(tmp_path: Path) -> None:
    """The link check asks whether the two documents AGREE. Here they agree on FAIL.

    What they agree about decides the outcome: a public commitment that this evidence was
    examined and rejected must not return OFFLINE_OK / PASS / exit 0, or a CI gate keyed on
    the exit code, the use the README recommends, would admit rejected evidence.
    """
    root, entry_path = _bundle_committing(tmp_path, "fail", "FAIL")
    report = verify_path(root, registry_entry_path=entry_path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert report.verdict == "FAIL"
    assert report.exit_code == EXIT_OFFLINE_FAIL
    assert payload["outcome"]["category"] == "registry_verdict_not_pass"
    assert payload["outcome"]["reason"] == "registry_entry_verdict_fail"
    assert payload["registry_link"]["registry_entry_verdict"] == "FAIL"
    # The link itself is consistent throughout: nothing is broken, the registry has simply
    # said no.
    assert payload["registry_link"]["status"] == "OFFLINE_OK"


@pytest.mark.parametrize("receipt_status,entry_verdict", [("warning", "WARN"), ("review", "REVIEW")])
def test_a_registry_entry_committing_warn_or_review_cannot_produce_exit_zero(
    tmp_path: Path, receipt_status: str, entry_verdict: str
) -> None:
    root, entry_path = _bundle_committing(tmp_path, receipt_status, entry_verdict)
    report = verify_path(root, registry_entry_path=entry_path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_REVIEW"
    assert report.exit_code == EXIT_OFFLINE_REVIEW
    assert payload["outcome"]["reason"] == "registry_entry_verdict_requires_review"
    assert payload["registry_link"]["registry_entry_verdict"] == entry_verdict


def test_link_check_refuses_a_registry_entry_that_violates_the_closed_contract(tmp_path: Path) -> None:
    """The link check contract-checks the entry as the authorization check does, not only that it is a dict.

    The link check is the check a counterparty reaches when they hold no trust registry, so it is the
    level most readers will ever run. This entry declares a different object_type, carries
    an impossible issued_at, a signature that is not a signature, and a field no schema
    declares, and every hash in it still matches, so only the contract refuses it.
    """
    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    entry["object_type"] = "not_a_registry_entry"
    entry["issued_at"] = "2026-02-30T99:99:99Z"
    entry["signature"] = "NOT-A-SIGNATURE"
    entry["NOT_IN_SCHEMA_side_channel"] = "x" * 200
    entry_path = tmp_path / "entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    report = verify_path(BUNDLE_DIR, registry_entry_path=entry_path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert report.exit_code == EXIT_OFFLINE_FAIL
    assert payload["outcome"]["category"] == "malformed_input_failure"
    assert payload["errors"][0]["code"] == "registry_entry_contract_violation"
    assert "registry_entry_contract_violation:registry_entry.object_type:const" in payload["notes"]
    assert "registry_entry_contract_violation:registry_entry.issued_at:pattern" in payload["notes"]
    assert (
        "registry_entry_contract_violation:registry_entry.NOT_IN_SCHEMA_side_channel:additionalProperties"
        in payload["notes"]
    )


def test_the_contract_check_does_not_reject_a_conformant_unsigned_entry() -> None:
    """The contract check must not become a second, stricter schema.

    `signature: null` is conformant, an unsigned entry is a legitimate link shape, and a
    verifier that refused it would fail closed on valid evidence. That is as broken as
    failing open, and harder to notice, because nobody reports a verdict they expected.
    """
    assert json.loads(VALID_ENTRY.read_text(encoding="utf-8"))["signature"] is None

    report = verify_path(BUNDLE_DIR, registry_entry_path=VALID_ENTRY)

    assert report.status == "OFFLINE_OK"
    assert report.verdict == "PASS"
    assert report.to_dict()["registry_link"]["registry_entry_verdict"] == "PASS"


def test_verify_path_without_registry_entry_preserves_structure_and_integrity_behavior() -> None:
    report = verify_path(BUNDLE_DIR)
    payload = report.to_dict()

    assert report.status == "OFFLINE_OK"
    assert report.verdict == "PASS"
    assert payload["registry_link"] is None
    assert payload["checks_requested"] == ["structure", "integrity"]
    assert payload["registry"]["status"] == "REGISTRY_ENTRY_NOT_PROVIDED"


def test_valid_registry_link_passes_for_directory_bundle() -> None:
    report = verify_path(BUNDLE_DIR, registry_entry_path=VALID_ENTRY)
    payload = report.to_dict()

    assert report.status == "OFFLINE_OK"
    assert report.verdict == "PASS"
    assert report.exit_code == EXIT_OFFLINE_OK
    assert payload["checks_requested"] == ["structure", "integrity", "link"]
    assert payload["checks_established"] == ["structure", "integrity", "link"]
    assert payload["outcome"]["category"] == "success_registry_link_verified"
    assert payload["registry"]["status"] == "REGISTRY_ENTRY_LINK_VERIFIED"
    assert payload["registry"]["signature_supported"] is False
    assert payload["registry_link"]["status"] == "OFFLINE_OK"
    assert payload["registry_link"]["signature_verified"] is False
    assert payload["registry_link"]["trust_registry_verified"] is False
    assert payload["registry_link"]["registry_inclusion_verified"] is False
    assert payload["registry_link"]["anchor_finality_verified"] is False
    assert payload["checks"]["registry_link"] is True
    for name in [
        "manifest_hash",
        "receipt_manifest_sha256",
        "receipt_hash",
        "policy_id",
        "policy_version",
        "reason_code_catalog_version",
        "reason_codes",
        "asset_type",
        "status_verdict",
    ]:
        assert _check(payload, name)["ok"] is True


def test_valid_registry_link_passes_for_zip_bundle() -> None:
    report = verify_path(BUNDLE_ZIP, registry_entry_path=VALID_ENTRY)

    assert report.status == "OFFLINE_OK"
    assert report.to_dict()["input"]["type"] == "zip"
    assert report.to_dict()["registry_link"]["ok"] is True


@pytest.mark.parametrize(
    "entry_name,failed_check",
    [
        ("link_manifest_mismatch_registry_entry.json", "manifest_hash"),
        ("link_receipt_hash_mismatch_registry_entry.json", "receipt_hash"),
        ("link_policy_mismatch_registry_entry.json", "policy_id"),
        (None, "reason_codes"),
    ],
)
def test_registry_link_mismatches_fail_closed(tmp_path: Path, entry_name: str | None, failed_check: str) -> None:
    if entry_name is None:
        # Two info-severity codes where the receipt cites one: grounds that derive the entry's
        # PASS, and a multiset that differs from the receipt's. The corpus fixture for this
        # mismatch, link_reason_codes_mismatch_registry_entry.json, cites FRESHNESS_WARNING under
        # a PASS, which fails the entry's contract before the link is judged (see below).
        entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
        entry["reason_codes"] = ["INTEGRITY_OK", "REQUIRED_CLAIMS_PRESENT"]
        entry_path = tmp_path / "reason_codes_mismatch_entry.json"
        entry_path.write_text(json.dumps(entry), encoding="utf-8")
    else:
        entry_path = FIXTURES / entry_name
    report = verify_path(BUNDLE_DIR, registry_entry_path=entry_path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert report.verdict == "FAIL"
    assert report.exit_code == EXIT_OFFLINE_FAIL
    assert payload["outcome"]["reason"] == "registry_link_verification_failed"
    assert payload["registry"]["status"] == "REGISTRY_ENTRY_LINK_FAILED"
    assert payload["checks"]["registry_link"] is False
    assert _check(payload, failed_check)["ok"] is False


def test_the_corpus_reason_codes_mismatch_entry_fails_its_grounds_before_its_link() -> None:
    """PASS citing FRESHNESS_WARNING (severity warn): the verdict is not the verdict of its grounds.

    The link is still computed, and its reason_codes check is still false; the refusal is named
    as the entry's contract violation.
    """
    report = verify_path(BUNDLE_DIR, registry_entry_path=FIXTURES / "link_reason_codes_mismatch_registry_entry.json")
    payload = report.to_dict()
    assert (report.status, report.exit_code, payload["checks"]["registry_link"]) == ("OFFLINE_FAIL", 1, False)
    assert payload["outcome"]["reason"] == "registry_entry_contract_violation"
    assert "registry_entry_contract_violation:registry_entry.verdict:verdict_contradicts_grounds" in payload["notes"]
    assert _check(payload, "reason_codes")["ok"] is False


def test_missing_verification_receipt_is_not_established(tmp_path: Path) -> None:
    # This fixture has no verification_receipt.json. With a registry entry the link cannot be
    # evaluated, which is not evidence against the bundle: the link check is not established,
    # never silently OK (report-contract.md section 3.3, verification_receipt_not_provided).
    report = verify_path(FIXTURES / "valid_bundle", registry_entry_path=VALID_ENTRY)
    payload = report.to_dict()

    assert (report.status, payload["errors"]) == ("OFFLINE_REVIEW", [])
    assert payload["review_reasons"] == ["verification_receipt_not_provided"]
    assert payload["checks_established"] == ["structure", "integrity"]
    assert payload["checks"]["registry_link"] is not True


def test_malformed_registry_entry_fails_safely() -> None:
    report = verify_path(BUNDLE_DIR, registry_entry_path=FIXTURES / "link_malformed_registry_entry.json")
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert payload["errors"][0]["code"] == "registry_link_verification_failed"
    assert "invalid_json" in payload["errors"][0]["message"]


def test_registry_link_helper_is_local_and_does_not_verify_trust_or_finality() -> None:
    base_report = verify_path(BUNDLE_DIR)
    result = verify_registry_link(BUNDLE_DIR, registry_entry_path=VALID_ENTRY, manifest_result=base_report.manifest)

    assert result.link_holds is True
    assert result.status == "OFFLINE_OK"
    assert "registry_link_signature_trust_inclusion_anchor_not_verified" in result.notes
    assert "registry_receipt_id_metadata_not_matched_by_receipt_schema" in result.notes


def test_cli_registry_entry_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(BUNDLE_ZIP), "--registry-entry", str(VALID_ENTRY), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_OFFLINE_OK
    assert payload["registry_link"]["status"] == "OFFLINE_OK"
    assert payload["checks_requested"] == ["structure", "integrity", "link"]


def test_cli_registry_entry_pretty_output(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(BUNDLE_DIR), "--registry-entry", str(VALID_ENTRY), "--pretty"])
    out = capsys.readouterr().out

    assert exit_code == EXIT_OFFLINE_OK
    assert "registry_link: OFFLINE_OK / PASS" in out
    assert "registry_signature" in out


def test_cli_help_documents_registry_entry_without_overclaim(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    out = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--registry-entry" in out
    assert "link check" in out
    assert "compares the entry with the bundle's receipt and manifest" in " ".join(out.split())
    assert "does not verify" in out
    assert "issuer signatures" in out


@pytest.mark.parametrize(
    "rejected_status",
    ["ok", "passed", "success", "  SUCCESS  ", "PASS", "warn", "needs_review", "failed", "error"],
)
def test_receipt_status_outside_the_closed_vocabulary_is_never_mapped(rejected_status: str) -> None:
    """An unrecognized status is a rejection, not a downgrade.

    ``_STATUS_TO_VERDICT`` carries the four values of the enum and nothing else: a synonym
    such as ``passed``, ``ok`` or ``success`` mapped to PASS would let a receipt declaring
    ``status: "ok"``, a value the specification says to reject, produce verdict PASS and
    exit 0 against an otherwise valid bundle. The lookup applies no ``.strip().lower()``,
    so ``"  SUCCESS  "`` is not a member either.

    The rule is the "Registry verdict" section of
    loquitur-protocol/docs/specification/verification-vocabularies.md, and loquitur-schemas'
    README states the same MUST and names this module as the bridge between the two
    vocabularies.
    """

    from loquitur.verify.registry_link import _map_receipt_status_to_verdict

    assert _map_receipt_status_to_verdict(rejected_status) is None


def test_the_four_closed_statuses_map() -> None:
    """The counterweight: each of the four statuses maps to its verdict, so the rejection above
    does not reach the mapping that must exist."""

    from loquitur.verify.registry_link import _map_receipt_status_to_verdict

    assert _map_receipt_status_to_verdict("pass") == "PASS"
    assert _map_receipt_status_to_verdict("warning") == "WARN"
    assert _map_receipt_status_to_verdict("review") == "REVIEW"
    assert _map_receipt_status_to_verdict("fail") == "FAIL"


def test_contract_violating_registry_entry_fails_closed_at_link(tmp_path: Path) -> None:
    """The link check must refuse the entries authorization refuses.

    ``read_registry_entry`` checks only that the bytes parse into a dict, so
    ``verify_registry_link`` applies the generated contract itself: the closed
    ``registry_entry`` schema is enforced whether or not ``--trust-registry`` is also
    supplied. An entry with many violations (``object_type: "not_a_registry_entry"``,
    an unbounded extra field against ``additionalProperties: false``, a deleted
    ``subject_ref_hash``) must not be reported as REGISTRY_ENTRY_LINK_VERIFIED. A report
    that establishes the link check asserts that the entry conforms to its schema, so it has to
    compute that.
    """

    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    entry["object_type"] = "not_a_registry_entry"
    entry["schema_version"] = "v99"
    entry["registry_entry_id"] = "hello"
    entry["receipt_id"] = "x"
    entry["issuer_id"] = "not-an-issuer-at-all"
    entry["privacy_classification"] = "secret"
    entry["workflow"] = "made_up_workflow"
    entry["signature"] = "not even an object"
    entry["evil_side_channel"] = "x" * 4096
    del entry["subject_ref_hash"]
    del entry["disclosure_profile"]
    entry_path = tmp_path / "contract_violating_registry_entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    report = verify_path(BUNDLE_DIR, registry_entry_path=entry_path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert report.exit_code == EXIT_OFFLINE_FAIL
    assert payload["registry"]["status"] == "REGISTRY_ENTRY_LINK_FAILED"
    violations = _check(payload, "registry_entry_contract")
    assert violations["ok"] is False
    assert "registry_entry.object_type:const" in violations["actual"]
    assert "registry_entry.evil_side_channel:additionalProperties" in violations["actual"]
    assert "registry_entry.subject_ref_hash:required" in violations["actual"]


def test_duplicate_reason_codes_in_the_entry_fail_closed_at_link(tmp_path: Path) -> None:
    """``reason_codes`` is ``uniqueItems`` in the schema, and the comparison keeps a duplicate visible.

    Deduplicating with ``dict.fromkeys`` before comparing would let an entry carrying
    ["INTEGRITY_OK", "INTEGRITY_OK"] match a clean receipt on a hard check. The contract
    rejects the duplicate, and the normalization keeps the evidence of it for the
    comparison.
    """

    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    entry["reason_codes"] = ["INTEGRITY_OK", "INTEGRITY_OK"]
    entry_path = tmp_path / "duplicate_reason_codes_registry_entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    report = verify_path(BUNDLE_DIR, registry_entry_path=entry_path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert _check(payload, "registry_entry_contract")["ok"] is False
    assert _check(payload, "reason_codes")["ok"] is False


@pytest.mark.parametrize(
    "receipt_status,entry_verdict,expected_status,expected_exit",
    [
        ("pass", "PASS", "OFFLINE_OK", EXIT_OFFLINE_OK),
        ("fail", "FAIL", "OFFLINE_FAIL", EXIT_OFFLINE_FAIL),
        ("review", "REVIEW", "OFFLINE_REVIEW", EXIT_OFFLINE_REVIEW),
        ("warning", "WARN", "OFFLINE_REVIEW", EXIT_OFFLINE_REVIEW),
    ],
)
def test_the_entrys_own_committed_verdict_caps_the_report(
    tmp_path: Path, receipt_status: str, entry_verdict: str, expected_status: str, expected_exit: int
) -> None:
    """Every other link check scores AGREEMENT, and two documents agreeing on FAIL agree.

    A receipt with ``status: "fail"`` and an entry with ``verdict: "FAIL"``, a public
    commitment stating that this evidence was verified and rejected, must not produce
    OFFLINE_OK / PASS / exit 0. The committed verdict is an input to the outcome, not only
    to a consistency comparison.
    """

    bundle = tmp_path / "link_valid_bundle"
    shutil.copytree(BUNDLE_DIR, bundle)
    receipt_path = bundle / "verification_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = receipt_status
    receipt["reason_codes"] = GROUNDS[entry_verdict]
    receipt_path.write_text(json.dumps(receipt, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    entry["verdict"] = entry_verdict
    entry["reason_codes"] = GROUNDS[entry_verdict]
    entry["receipt_hash"] = "sha256:" + canonical_json_sha256(receipt)
    entry_path = tmp_path / "committed_verdict_registry_entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    report = verify_path(bundle, registry_entry_path=entry_path)
    payload = report.to_dict()

    # The link itself is intact in all four cases: the two documents agree.
    assert _check(payload, "status_verdict")["ok"] is True
    assert _check(payload, "registry_entry_contract")["ok"] is True
    assert _check(payload, "registry_entry_verdict")["actual"] == entry_verdict
    assert report.status == expected_status
    assert report.exit_code == expected_exit


@pytest.mark.parametrize(
    ("field", "value", "keyword"),
    [
        ("secret_side_channel", "smuggled payload", "additionalProperties"),
        ("issuer_id", "x", "pattern"),
        ("object_type", "not_a_registry_entry", "const"),
        ("privacy_classification", "SECRET", "enum"),
        ("verdict", "BANANA", "enum"),
    ],
)
def test_an_entry_the_contract_rejects_does_not_pass_at_link(
    tmp_path: Path, field: str, value: str, keyword: str
) -> None:
    """The link check enforces the closed value contract.

    Were ``contract_errors`` called only from ``trust_registry.py``, a counterparty who
    supplied ``--registry-entry`` and nothing else, the documented way to verify with no
    trust material, would collect OFFLINE_OK, PASS and exit 0 for a document carrying
    ``object_type: "not_a_registry_entry"``, a malformed identifier, or an unbounded extra
    field, while the identical bytes return INVALID_REGISTRY_ENTRY one level up. This
    exercises the link side, so the two checks cannot disagree about one file.
    """

    from loquitur.verify.contract_validation import contract_errors

    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    entry[field] = value
    # The premise, asserted rather than assumed: the package's own contract rejects this
    # document, and for the stated reason.
    assert any(error.endswith(f":{keyword}") for error in contract_errors("registry_entry", entry))

    path = tmp_path / "entry.json"
    path.write_text(json.dumps(entry), encoding="utf-8")
    report = verify_path(BUNDLE_DIR, registry_entry_path=path)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert report.verdict == "FAIL"
    assert report.exit_code == EXIT_OFFLINE_FAIL
    assert payload["checks"]["registry_link"] is False
    assert _check(payload, "registry_entry_contract")["ok"] is False


def test_the_shipped_valid_entry_still_conforms_and_still_passes() -> None:
    """The counterweight. A verifier that refuses everything is not a fixed verifier."""

    from loquitur.verify.contract_validation import contract_errors

    assert contract_errors("registry_entry", json.loads(VALID_ENTRY.read_text(encoding="utf-8"))) == []
    report = verify_path(BUNDLE_DIR, registry_entry_path=VALID_ENTRY)
    assert report.status == "OFFLINE_OK"
    assert _check(report.to_dict(), "registry_entry_contract")["ok"] is True


@pytest.mark.parametrize("verdict", ["FAIL", "WARN", "REVIEW"])
def test_an_entry_that_breaks_its_contract_commits_no_verdict(tmp_path: Path, verdict: str) -> None:
    """Only an entry that satisfies its contract commits a verdict (registry-link.md section 6).

    Reading the committed verdict from any entry that is a JSON object would give an entry
    refused for its contract registry_entry_verdict_fail as well, or a request for review, over
    a verdict it has not validly committed. Here the verdict contradicts the grounds the entry
    cites, which breaks the contract.
    """
    root, entry_path = _bundle_committing(
        tmp_path, {"FAIL": "fail", "WARN": "warning", "REVIEW": "review"}[verdict], verdict
    )
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    entry["reason_codes"] = ["INTEGRITY_OK"]
    entry_path.write_text(json.dumps(entry), encoding="utf-8")
    report = verify_path(root, registry_entry_path=entry_path).to_dict()
    assert (
        report["status"],
        [error["code"] for error in report["errors"]],
        report["checks"]["registry_link"],
        "registry_entry_verdict_requires_review" in report["notes"],
    ) == ("OFFLINE_FAIL", ["registry_entry_contract_violation"], False, False)
