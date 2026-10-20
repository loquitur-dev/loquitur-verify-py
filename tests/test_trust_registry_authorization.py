from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from loquitur.verify.cli import main
from loquitur.verify.runner import (
    EXIT_OFFLINE_FAIL,
    EXIT_OFFLINE_REVIEW,
    EXIT_USAGE_ERROR,
    OUTCOME_ISSUER_AUTHORIZATION_FAILURE,
    OUTCOME_PROOF_INTEGRITY_FAILURE,
    verify_path,
)
from loquitur.verify.trust_registry import verify_registry_entry_trust

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE_DIR = FIXTURES / "link_valid_bundle"
BUNDLE_ZIP = FIXTURES / "link_valid_bundle.zip"
VALID_ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
VALID_TRUST = FIXTURES / "authorization_valid_trust_registry.json"
# The operator's evaluation time, inside every window of the fixture trust registry.
AT = "2026-05-10T00:00:00Z"

# Pinned exact bytes of the message signed under the LOQUITUR domain prefix (LCP-0002). These change
# whenever the signed message changes, which is the point of pinning them: a rename that
# silently left signatures verifying would mean the domain separation was not load-bearing.
EXPECTED_AUTHORIZATION_SIGNING_PAYLOAD_HASH = "sha256:8d6c5ee930385a51e57ba21ca6066925d704e5cccc9e378737537e5a5b21311e"
EXPECTED_AUTHORIZATION_DEMO_SIGNATURE = "438f2e18592da25c9cb2407f0de44cfa9e2e90f2a849c70c15640a8ca674e2ab0474a295fc9b109ba8715a6ecf04e4f3bb40c535dcc3ef722e12db4f4c10fac4"


def _trust(payload: dict) -> dict:
    trust = payload["trust_registry"]
    assert trust is not None
    return trust


def test_valid_authorization_trust_registry_reviews_without_a_pinned_root_for_directory_bundle() -> None:
    """Every authorization check below still passes. The run still does not return PASS.

    With PINNED_TRUST_ROOTS empty nothing separates this fixture from a trust registry an
    attacker created end to end, so OFFLINE_OK would be a fail-open. The fixture's own
    registry is signed "demo-trust-registry-signature-placeholder-non-production".
    Everything the tool genuinely verified is asserted here, and the headline is a refusal.
    tests/test_trust_root_flag.py holds the other half: pin the right root and the same
    shape returns OFFLINE_OK.
    """
    report = verify_path(
        BUNDLE_DIR, registry_entry_path=VALID_ENTRY, trust_registry_path=VALID_TRUST, evaluation_time=AT
    )
    payload = report.to_dict()
    trust = _trust(payload)

    assert report.status == "OFFLINE_REVIEW"
    assert report.verdict == "REVIEW"
    assert report.exit_code == EXIT_OFFLINE_REVIEW
    assert payload["checks_requested"] == ["structure", "integrity", "link", "authorization"]
    assert payload["checks_established"] == ["structure", "integrity", "link"]
    assert payload["review_reasons"] == ["trust_registry_root_not_pinned"]
    assert payload["outcome"]["category"] == "warning_or_review_state"
    assert payload["outcome"]["reason"] == "trust_registry_root_not_pinned"
    assert payload["registry_link"]["status"] == "OFFLINE_OK"
    assert payload["registry"]["status"] == "TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED"
    assert payload["checks"]["registry_link"] is True
    assert payload["checks"]["trust_registry"] is True
    # The component restates authorization and root authentication together: no root is pinned,
    # so it reviews too (trust-root.md section 2), while checks.trust_registry says authorization
    # itself held. The component has no ok, which would read as its outcome.
    assert trust["status"] == "OFFLINE_REVIEW"
    assert trust["verdict"] == "REVIEW"
    assert "ok" not in trust
    assert "trust_status" not in trust
    assert trust["signature_verified"] is True
    assert trust["trust_registry_verified"] is False
    assert trust["trust_registry_root_signature_verified"] is False
    assert trust["registry_inclusion_verified"] is False
    assert trust["anchor_finality_verified"] is False
    assert trust["authorization_status"] == "AUTHORIZED_ACTIVE_KEY"
    assert trust["signature_status"] == "VALID_SIGNATURE"
    assert trust["signing_payload_hash"] == EXPECTED_AUTHORIZATION_SIGNING_PAYLOAD_HASH
    assert trust["signing_payload_id"] == "registry_entry_signing_payload_v2"
    assert trust["signing_payload_version"] == 2
    assert (
        json.loads(VALID_ENTRY.read_text(encoding="utf-8"))["signature"]["signature"]
        == EXPECTED_AUTHORIZATION_DEMO_SIGNATURE
    )
    assert trust["evaluation_time"] == "2026-05-10T00:00:00Z"


def test_the_trust_registry_section_has_no_ok_beside_its_verdict() -> None:
    """trust_registry.ok read True for a REVIEW: authorization alone, beside the verdict it is not.

    Whether authorization held is checks.trust_registry, which both reference verifiers write.
    """
    payload = verify_path(
        BUNDLE_DIR, registry_entry_path=VALID_ENTRY, trust_registry_path=VALID_TRUST, evaluation_time=AT
    ).to_dict()
    trust = _trust(payload)

    assert (trust["verdict"], payload["checks"]["trust_registry"]) == ("REVIEW", True)
    assert "ok" not in trust


def test_valid_authorization_trust_registry_reviews_without_a_pinned_root_for_zip_bundle() -> None:
    report = verify_path(
        BUNDLE_ZIP, registry_entry_path=VALID_ENTRY, trust_registry_path=VALID_TRUST, evaluation_time=AT
    )

    assert report.status == "OFFLINE_REVIEW"
    assert report.to_dict()["input"]["type"] == "zip"
    # The authorization component passed every check it makes, and still says so. The downgrade is
    # about the registry's provenance, not about anything the component examined.
    assert report.to_dict()["checks"]["trust_registry"] is True


@pytest.mark.parametrize(
    "entry_name,expected_authorization_status,expected_signature",
    [
        ("authorization_unknown_issuer_registry_entry.json", "ISSUER_NOT_FOUND", None),
        ("authorization_unknown_key_registry_entry.json", "ISSUER_KEY_NOT_FOUND", None),
        ("authorization_signature_mismatch_registry_entry.json", "AUTHORIZED_ACTIVE_KEY", "SIGNATURE_INVALID"),
    ],
)
def test_authorization_registry_entry_failures_fail_closed(
    entry_name: str, expected_authorization_status: str, expected_signature: str | None
) -> None:
    report = verify_path(
        BUNDLE_DIR, registry_entry_path=FIXTURES / entry_name, trust_registry_path=VALID_TRUST, evaluation_time=AT
    )
    payload = report.to_dict()
    trust = _trust(payload)

    assert report.status == "OFFLINE_FAIL"
    assert report.verdict == "FAIL"
    assert report.exit_code == EXIT_OFFLINE_FAIL
    assert payload["outcome"]["reason"] == "trust_registry_verification_failed"
    assert payload["checks"]["trust_registry"] is False
    assert trust["authorization_status"] == expected_authorization_status
    assert trust["signature_status"] == expected_signature


@pytest.mark.parametrize(
    "trust_name,expected_authorization_status",
    [
        ("authorization_revoked_trust_registry.json", "ISSUER_KEY_REVOKED"),
        ("authorization_suspended_trust_registry.json", "ISSUER_KEY_SUSPENDED"),
        ("authorization_disallowed_asset_type_trust_registry.json", "ISSUER_KEY_SCOPE_MISMATCH"),
        ("authorization_malformed_trust_registry.json", "INVALID_TRUST_REGISTRY"),
    ],
)
def test_authorization_trust_registry_failures_fail_closed(trust_name: str, expected_authorization_status: str) -> None:
    # Revocation and suspension fail at every instant, with or without an evaluation time.
    report = verify_path(BUNDLE_DIR, registry_entry_path=VALID_ENTRY, trust_registry_path=FIXTURES / trust_name)
    timed = verify_path(
        BUNDLE_DIR, registry_entry_path=VALID_ENTRY, trust_registry_path=FIXTURES / trust_name, evaluation_time=AT
    )
    assert timed.to_dict()["trust_registry"]["authorization_status"] == expected_authorization_status
    assert timed.status == "OFFLINE_FAIL"
    payload = report.to_dict()
    trust = _trust(payload)

    assert report.status == "OFFLINE_FAIL"
    assert payload["outcome"]["reason"] == "trust_registry_verification_failed"
    assert trust["authorization_status"] == expected_authorization_status
    assert payload["checks"]["trust_registry"] is False


@pytest.mark.parametrize(
    "links,category",
    [
        pytest.param({}, OUTCOME_ISSUER_AUTHORIZATION_FAILURE, id="links-not-evaluated"),
        pytest.param({"manifest_link_ok": False}, OUTCOME_PROOF_INTEGRITY_FAILURE, id="a-link-broken"),
    ],
)
def test_the_category_of_a_fail_with_no_error_reads_a_link_not_evaluated_as_not_broken(
    links: dict[str, bool], category: str
) -> None:
    # outcome.category of an OFFLINE_FAIL that carries no error comes from the layers: the
    # issuer's authorization when every integrity layer holds, the proof's integrity otherwise.
    # An envelope whose links were not evaluated (links_ok None) has not failed, so the FAIL of a
    # revoked key over it stays the issuer's; a broken link makes it the proof's. The report is
    # the revoked run's, with no error and the envelope's links changed as each case says.
    revoked = verify_path(
        BUNDLE_DIR,
        registry_entry_path=VALID_ENTRY,
        trust_registry_path=FIXTURES / "authorization_revoked_trust_registry.json",
        evaluation_time=AT,
    )
    assert revoked.status == "OFFLINE_FAIL" and revoked.envelope is not None
    envelope = dataclasses.replace(
        revoked.envelope, **{"bundle_id_ok": None, "manifest_link_ok": None, "p1_link_ok": None, **links}
    )
    payload = dataclasses.replace(revoked, envelope=envelope, errors=()).to_dict()
    assert payload["checks"]["envelope_links"] is envelope.links_ok
    assert payload["errors"] == []
    assert payload["outcome"]["category"] == category


@pytest.mark.parametrize(
    "trust_name,expected_authorization_status",
    [
        ("authorization_expired_trust_registry.json", "ISSUER_KEY_EXPIRED"),
        ("authorization_not_yet_effective_trust_registry.json", "ISSUER_KEY_NOT_YET_EFFECTIVE"),
    ],
)
def test_a_key_outside_its_window_at_the_evaluation_time_is_review(
    trust_name: str, expected_authorization_status: str
) -> None:
    # trust-registry-authorization.md section 6 rows 11-12: no attested signing time exists,
    # so a key window that does not hold the operator's time is not evidence against the entry.
    report = verify_path(
        BUNDLE_DIR, registry_entry_path=VALID_ENTRY, trust_registry_path=FIXTURES / trust_name, evaluation_time=AT
    ).to_dict()
    assert (report["status"], report["errors"]) == ("OFFLINE_REVIEW", [])
    assert report["review_reasons"][0] == "issuer_key_outside_validity_window"
    assert report["trust_registry"]["authorization_status"] == expected_authorization_status
    # Without the time the window rows are skipped: authorization is not established.
    untimed = verify_path(BUNDLE_DIR, registry_entry_path=VALID_ENTRY, trust_registry_path=FIXTURES / trust_name)
    assert untimed.status == "OFFLINE_REVIEW"
    assert untimed.review_reasons[0] == "evaluation_time_not_provided"


def test_trust_registry_without_registry_entry_fails_closed() -> None:
    report = verify_path(BUNDLE_DIR, trust_registry_path=VALID_TRUST)
    payload = report.to_dict()

    assert report.status == "OFFLINE_FAIL"
    assert payload["registry_link"] is None
    assert payload["trust_registry"] is None
    assert payload["errors"][0]["code"] == "trust_registry_requires_registry_entry"


def test_default_and_link_behaviors_remain_unchanged_without_trust_registry() -> None:
    default = verify_path(BUNDLE_DIR).to_dict()
    link_report = verify_path(BUNDLE_DIR, registry_entry_path=FIXTURES / "link_valid_registry_entry.json").to_dict()

    assert default["checks_requested"] == ["structure", "integrity"]
    assert default["trust_registry"] is None
    assert link_report["checks_requested"] == ["structure", "integrity", "link"]
    assert link_report["trust_registry"] is None


def test_trust_registry_helper_is_local_and_does_not_verify_transparency_anchoring_or_root_signature() -> None:
    entry = json.loads(VALID_ENTRY.read_text(encoding="utf-8"))
    result = verify_registry_entry_trust(entry, trust_registry_path=VALID_TRUST, evaluation_time=AT)

    assert result.authorization_holds is True
    assert result.signature_valid is True
    assert result.signing_payload_hash == EXPECTED_AUTHORIZATION_SIGNING_PAYLOAD_HASH
    assert result.signing_payload_id == "registry_entry_signing_payload_v2"
    assert result.signing_payload_version == 2
    # Authorization held, but no root vouches for the registry: never verified, never PASS.
    assert result.trust_registry_verified is False
    assert (result.verdict, result.offline_status) == ("REVIEW", "OFFLINE_REVIEW")
    assert "registry_inclusion_anchor_finality_not_verified" in result.notes

    # Root authentication is computed, not asserted. With no root pinned the observable
    # boolean must stay False: a mechanism that passed when nothing was pinned would turn a
    # truthful "not verified" into a false "verified". The report also says *why*, so a
    # counterparty can tell a gap in the deployment from a gap in the tool.
    assert result.root_signature_verified is False
    assert result.root_signature_status == "NO_PINNED_TRUST_ROOT"
    assert result.root_key_id is None
    assert "trust_registry_root_signature_not_verified:no_pinned_trust_root" in result.notes

    # And the instant that judged the issuer's key is the operator's, as supplied: the entry's
    # own dates are never a time (trust-registry-authorization.md section 2).
    assert result.evaluation_time == AT
    assert not hasattr(result, "evaluation_time_source")


def test_cli_trust_registry_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [str(BUNDLE_ZIP), "--registry-entry", str(VALID_ENTRY), "--trust-registry", str(VALID_TRUST), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)

    # The authorization check ran and every check it makes passed; the CLI still exits 2, because no root was
    # pinned and the registry's own authenticity was therefore never established.
    assert exit_code == EXIT_OFFLINE_REVIEW
    assert payload["checks_requested"] == ["structure", "integrity", "link", "authorization"]
    assert payload["trust_registry"]["status"] == "OFFLINE_REVIEW"


def test_cli_trust_registry_pretty_output(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [str(BUNDLE_DIR), "--registry-entry", str(VALID_ENTRY), "--trust-registry", str(VALID_TRUST), "--pretty"]
    )
    out = capsys.readouterr().out

    assert exit_code == EXIT_OFFLINE_REVIEW
    assert "OFFLINE_REVIEW / REVIEW" in out
    assert "registry: TRUST_REGISTRY_ROOT_NOT_AUTHENTICATED" in out
    # Both component lines still report what those components concluded. The headline and
    # the `registry:` line are what changed, and they are what a reader quotes.
    assert "registry_link: OFFLINE_OK / PASS" in out
    assert "trust_registry: OFFLINE_REVIEW / REVIEW" in out


def test_cli_trust_registry_requires_registry_entry(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([str(BUNDLE_DIR), "--trust-registry", str(VALID_TRUST), "--json"])

    err = capsys.readouterr().err
    assert exc_info.value.code == EXIT_USAGE_ERROR
    assert "--trust-registry requires --registry-entry" in err


def test_cli_help_documents_trust_registry_without_overclaim(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    out = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--trust-registry" in out
    assert "authorization check" in out
    assert "local trust_registry" in out
    assert "authorization is not established" in out
    assert "anchors" in out
    assert "valuation correctness" in out


def test_the_fixture_readme_states_the_signing_payload_hash_the_fixture_has() -> None:
    """tests/fixtures/README.md gives the hash for a reader to check by hand; it must be this one."""
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    stated = readme.split("The expected signing payload hash of `authorization_valid_registry_entry.json` is:", 1)[1]
    assert stated.split("```text\n", 1)[1].split("\n", 1)[0] == EXPECTED_AUTHORIZATION_SIGNING_PAYLOAD_HASH
