"""An intact bundle with an unauthorized issuer must not be narrated as damaged.

``infer_active_reason_codes`` reads ``registry_link`` and ``trust_registry`` as well as
manifest, P1 and envelope. Reading only the integrity layers, its fallback would attribute
INTEGRITY_OFFLINE_FAIL to any FAIL that produced no integrity code: a byte-perfect bundle
whose issuer key had been REVOKED would get the compliance text "cannot confirm that this
bundle is internally consistent ... Require the issuer to regenerate and resubmit":
false on both counts, hiding a probable key compromise behind the wrong remediation.

WHY THESE TESTS ARE SHAPED THIS WAY. A substring ban does not hold. Exact phrases,
checked on one fixture, are defeated three ways: by continuing the sentence so the
sentinel survives while the meaning reverses ("...would not change the outcome ON ITS
OWN, SO PAIR IT WITH A FRESH SUBMISSION"), by using a synonym, and by editing any of the
fixtures the ban does not cover. All three would be invisible to the whole suite after a
routine ``tools/build_golden.py`` run, which is the documented remediation for a golden
failure, and therefore the action that would launder the regression.

So the assertions here are about the STRUCTURE the renderer chose, not about words:
which closing template key it resolved, and that the authorization templates are
disjoint from the generic FAIL family. A rephrasing cannot satisfy those. The remaining
literal checks are applied across every authorization fixture rather than one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from narrative_bundles import BUNDLE_CHANGES, changed_bundle

from loquitur.verify.narrative import (
    AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS,
    AUTHORIZATION_CODE_BY_SIGNATURE_STATUS,
    AUTHORIZATION_REASON_CODES,
    SIGNATURE_FAILURE_CODE,
    _closing_template_key,
    infer_active_reason_codes,
    render_verdict_narrative,
)
from loquitur.verify.runner import (
    OUTCOME_ISSUER_AUTHORIZATION_FAILURE,
    OUTCOME_PROOF_INTEGRITY_FAILURE,
    STATUS_OFFLINE_FAIL,
    verify_path,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Every authorization fixture, not just the revoked one: a ban on a single fixture leaves the
# verbatim banned phrase free to appear in any of the other seven.
AUTHORIZATION_CASES = [
    (
        "authorization_valid_registry_entry.json",
        "authorization_revoked_trust_registry.json",
        "AUTHORIZATION_ISSUER_KEY_REVOKED",
    ),
    (
        "authorization_valid_registry_entry.json",
        "authorization_suspended_trust_registry.json",
        "AUTHORIZATION_ISSUER_KEY_SUSPENDED",
    ),
    (
        "authorization_valid_registry_entry.json",
        "authorization_expired_trust_registry.json",
        "AUTHORIZATION_ISSUER_KEY_EXPIRED",
    ),
    (
        "authorization_valid_registry_entry.json",
        "authorization_not_yet_effective_trust_registry.json",
        "AUTHORIZATION_ISSUER_KEY_NOT_YET_EFFECTIVE",
    ),
    (
        "authorization_valid_registry_entry.json",
        "authorization_disallowed_asset_type_trust_registry.json",
        "AUTHORIZATION_SCOPE_MISMATCH",
    ),
    (
        "authorization_unknown_issuer_registry_entry.json",
        "authorization_valid_trust_registry.json",
        "AUTHORIZATION_ISSUER_NOT_RECOGNISED",
    ),
    (
        "authorization_signature_mismatch_registry_entry.json",
        "authorization_valid_trust_registry.json",
        SIGNATURE_FAILURE_CODE,
    ),
]

# Instructions that must never reach a reader whose evidence is intact. Kept as a coarse
# net only; the load-bearing guard is the structural one below.
RE_ISSUE_INSTRUCTIONS = (
    "regenerate and resubmit",
    "produce a corrected version",
    "address the failing condition and resubmit",
)


# The operator's evaluation time: inside the valid fixture registry's windows, outside the
# expired and the not-yet-effective fixture keys' windows.
EVALUATION_TIME = "2026-05-10T00:00:00Z"


def _report(entry: str, trust: str):
    return verify_path(
        FIXTURES / "link_valid_bundle",
        registry_entry_path=FIXTURES / entry,
        trust_registry_path=FIXTURES / trust,
        evaluation_time=EVALUATION_TIME,
    )


_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@pytest.fixture(scope="module")
def authenticated_authorization_report(tmp_path_factory):
    """An authorization report that genuinely reaches PASS, root and all.

    ``authorization_valid_trust_registry.json`` carries no root public key, so no run over it as
    shipped can reach PASS: ``trust_registry_root_not_pinned`` caps it at REVIEW, which is
    the honest outcome for a registry whose own root was never authenticated. Reading that
    REVIEW as acceptance would check the one outcome a reader affirmatively relies on
    against a report that was not accepted. So a root is made here, the fixture re-signed
    with it and pinned, which is what an operator does out of band.
    """
    pytest.importorskip("cryptography", reason="pinning a root needs cryptography")

    import json

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    from loquitur.verify.trust_root import TrustRootKey, trust_registry_signing_bytes

    key = ec.generate_private_key(ec.SECP256K1())
    payload = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    payload.pop("signature", None)
    r, s = asym_utils.decode_dss_signature(key.sign(trust_registry_signing_bytes(payload), ec.ECDSA(hashes.SHA256())))
    if s > _SECP256K1_ORDER // 2:  # low-S, as the protocol requires
        s = _SECP256K1_ORDER - s
    payload["signature"] = {
        "algorithm": "secp256k1_ecdsa_sha256",
        "key_id": "narrative-root-1",
        "signature": (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex(),
    }
    registry_path = tmp_path_factory.mktemp("narrative-root") / "authentic_trust_registry.json"
    registry_path.write_text(json.dumps(payload), encoding="utf-8")

    root = TrustRootKey(
        key_id="narrative-root-1",
        key_type="secp256k1",
        public_key_hex=key.public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        .hex(),
        not_before="2020-01-01T00:00:00Z",
        not_after="2030-01-01T00:00:00Z",
        status="active",
    )
    return verify_path(
        FIXTURES / "link_valid_bundle",
        registry_entry_path=FIXTURES / "authorization_valid_registry_entry.json",
        trust_registry_path=registry_path,
        trust_roots=(root,),
        evaluation_time=EVALUATION_TIME,
    )


def _revoked_report():
    return _report("authorization_valid_registry_entry.json", "authorization_revoked_trust_registry.json")


# --- the authorization failure itself -----------------------------------------------


def test_a_revoked_key_is_reported_as_an_authorization_failure() -> None:
    report = _revoked_report()
    assert report.trust_registry.authorization_status == "ISSUER_KEY_REVOKED"
    assert "AUTHORIZATION_ISSUER_KEY_REVOKED" in infer_active_reason_codes(report)


def test_the_outcome_category_distinguishes_authority_from_integrity() -> None:
    """A machine-readable field a consumer can branch on, not only prose."""
    outcome = _revoked_report().to_dict()["outcome"]
    assert outcome["category"] == OUTCOME_ISSUER_AUTHORIZATION_FAILURE
    assert outcome["category"] != OUTCOME_PROOF_INTEGRITY_FAILURE


def test_an_integrity_failure_is_still_narrated_as_one() -> None:
    """Guards the opposite error: not everything may become an authorization failure."""
    report = verify_path(FIXTURES / "tampered_manifest_bundle.zip")
    assert report.to_dict()["outcome"]["category"] == OUTCOME_PROOF_INTEGRITY_FAILURE
    assert "INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH" in infer_active_reason_codes(report)


# --- the structural guard the substring ban could not provide -----------------------


def test_an_authorization_failure_resolves_the_authorization_closing() -> None:
    """Asserts the template the renderer CHOSE, which no rewording can satisfy.

    A substring ban checks what the text says; this checks which paragraph the renderer
    decided to emit. Reinstating a re-issue instruction requires either editing the
    authorization closing, caught by the disjointness test below, or routing an
    authorization failure to the generic family, caught here.
    """
    codes = ("AUTHORIZATION_ISSUER_KEY_REVOKED",)
    assert _closing_template_key(STATUS_OFFLINE_FAIL, len(codes), codes) == "FAIL_AUTHORIZATION"


def test_a_signature_failure_resolves_its_own_closing() -> None:
    """A failed signature is not an authority problem: the signed statement is the problem.

    Routed to the generic FAIL closing it would read "require the issuer to address the
    failing condition and resubmit", the integrity closer's words, in the one scenario
    where preserving the artifact matters most.
    """
    codes = (SIGNATURE_FAILURE_CODE,)
    assert _closing_template_key(STATUS_OFFLINE_FAIL, len(codes), codes) == "FAIL_SIGNATURE"


def test_a_mixed_integrity_and_authority_failure_keeps_the_generic_closing() -> None:
    """A bundle that fails both really is defective, and the generic text is right there."""
    codes = ("INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH", "AUTHORIZATION_ISSUER_KEY_REVOKED")
    assert _closing_template_key(STATUS_OFFLINE_FAIL, len(codes), codes) in {"FAIL_SINGLE", "FAIL_MULTI"}


def test_the_authorization_closings_are_disjoint_from_the_generic_family() -> None:
    """The other half of the structural guard.

    Without this, the authorization closing could simply be edited to say what the
    generic one says, and every routing assertion above would still pass.
    """
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    templates = catalog.composition_templates
    for audience in ("technical", "compliance", "executive"):
        closing = templates[audience]["common"]["closing"]
        generic = {closing["FAIL_SINGLE"], closing["FAIL_MULTI"]}
        for key in ("FAIL_AUTHORIZATION", "FAIL_SIGNATURE"):
            assert closing[key] not in generic, (
                f"{audience}.{key} has been made identical to a generic FAIL closing, which "
                "restores the instruction the authorization path exists to avoid"
            )


# --- literal checks, applied across every fixture rather than one -------------------


@pytest.mark.parametrize("entry,trust,code", AUTHORIZATION_CASES, ids=[c[2] for c in AUTHORIZATION_CASES])
@pytest.mark.parametrize("audience", ["technical", "compliance", "executive"])
def test_no_authorization_outcome_tells_the_reader_to_re_issue(
    entry: str, trust: str, code: str, audience: str
) -> None:
    for path in (FIXTURES / entry, FIXTURES / trust):
        if not path.is_file():
            pytest.skip(f"fixture {path.name} not present")
    rendered = render_verdict_narrative(_report(entry, trust), audiences=(audience,)).to_dict()[audience]
    assert rendered
    for instruction in RE_ISSUE_INSTRUCTIONS:
        assert instruction not in rendered, (
            f"{code} / {audience} instructs the reader to {instruction!r} on evidence that "
            "verified; the remediation belongs to whoever owns the authority problem"
        )


def test_the_compliance_narrative_states_the_evidence_is_intact() -> None:
    rendered = render_verdict_narrative(_revoked_report(), audiences=("compliance",)).to_dict()["compliance"]
    assert "has not been altered" in rendered
    assert "revoked" in rendered
    assert "compromised" in rendered, "the reader must be told why a key gets revoked"


# --- the mapping ---------------------------------------------------------------------


@pytest.mark.parametrize("entry,trust,code", AUTHORIZATION_CASES, ids=[c[2] for c in AUTHORIZATION_CASES])
def test_each_authorization_outcome_gets_its_own_code(entry: str, trust: str, code: str) -> None:
    """Distinct authority failures must not collapse into one explanation.

    Expiry and not-yet-effective are different events: a record dated before its signer
    held authority is a back-dating indicator, while a lapsed key is usually a missed
    renewal. Merged, the two scenarios would render byte-identically and neither would
    have test value.
    """
    for path in (FIXTURES / entry, FIXTURES / trust):
        if not path.is_file():
            pytest.skip(f"fixture {path.name} not present")
    assert code in infer_active_reason_codes(_report(entry, trust))


def test_expired_and_not_yet_effective_do_not_share_a_code() -> None:
    expired = AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS["ISSUER_KEY_EXPIRED"]
    not_yet = AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS["ISSUER_KEY_NOT_YET_EFFECTIVE"]
    assert expired != not_yet


def test_the_accept_case_states_that_authority_was_checked(authenticated_authorization_report) -> None:
    """Silence on acceptance reads as "authorization was not evaluated".

    A PASS carrying full trust material must not render byte-identically to a plain
    integrity pass with no trust registry at all: acceptance is the only outcome on
    which a reader affirmatively relies.
    """
    report = authenticated_authorization_report
    assert report.verdict == "PASS"
    assert "AUTHORIZATION_VERIFIED" in infer_active_reason_codes(report)
    rendered = render_verdict_narrative(report, audiences=("compliance",)).to_dict()["compliance"]
    assert "authority verified" in rendered.lower()


def test_a_pass_without_trust_material_claims_no_authority() -> None:
    """The opposite error: an integrity-only pass must not imply authority was checked."""
    report = verify_path(FIXTURES / "valid_bundle.zip")
    assert report.verdict == "PASS"
    assert "AUTHORIZATION_VERIFIED" not in infer_active_reason_codes(report)


def test_signature_statuses_are_mapped_too_not_only_authorization() -> None:
    """An unsupported issuer key_type sets authorization_status to AUTHORIZED_ACTIVE_KEY
    and reports the failure under signature_status, so an inference keyed on
    authorization alone would narrate algorithm confusion as damaged evidence.
    """
    assert (
        AUTHORIZATION_CODE_BY_SIGNATURE_STATUS["UNSUPPORTED_SIGNATURE_ALGORITHM"]
        == "AUTHORIZATION_SIGNING_METHOD_UNSUPPORTED"
    )


def test_the_signature_code_is_excluded_from_the_authority_closing_set() -> None:
    assert SIGNATURE_FAILURE_CODE not in AUTHORIZATION_REASON_CODES
    assert "AUTHORIZATION_VERIFIED" not in AUTHORIZATION_REASON_CODES


def test_every_mapped_code_exists_in_the_catalog() -> None:
    """A mapped code with no catalog entry renders as a runtime error, not a paragraph."""
    from loquitur.schemas import load_reason_codes_catalog

    catalog = load_reason_codes_catalog()
    mapped = set(AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS.values()) | set(
        AUTHORIZATION_CODE_BY_SIGNATURE_STATUS.values()
    )
    assert mapped, "no codes mapped; the assertion would be vacuous"
    missing = sorted(code for code in mapped if code not in catalog.entries)
    assert not missing, f"mapped reason codes absent from the catalog: {missing}"


def test_every_reachable_authorization_status_is_mapped() -> None:
    """An unmapped status falls through to the generic integrity text: the failure this module guards against.

    INVALID_REGISTRY_ENTRY and INVALID_TRUST_REGISTRY are excluded deliberately: the
    runner categorizes malformed input separately, before authority is considered.
    """
    from loquitur.verify import trust_registry as tr

    malformed = {tr.AUTH_STATUS_INVALID_REGISTRY_ENTRY, tr.AUTH_STATUS_INVALID_TRUST_REGISTRY}
    reachable = {
        value for name, value in vars(tr).items() if name.startswith("AUTH_STATUS_") and isinstance(value, str)
    } - malformed
    unmapped = sorted(reachable - set(AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS))
    assert not unmapped, f"authorization statuses with no reason code: {unmapped}"


@pytest.mark.parametrize(
    "trust", ["authorization_expired_trust_registry.json", "authorization_not_yet_effective_trust_registry.json"]
)
def test_a_window_outside_the_evaluation_time_is_narrated_as_a_review_never_a_failure(trust: str) -> None:
    """report-contract.md section 3.3 and the catalog narratives worded by the evaluation time.

    The key window's codes keep catalog severity fail, but the run is OFFLINE_REVIEW with the
    review reason issuer_key_outside_validity_window. The narrative follows the run: its lead and
    closing are the REVIEW ones in every audience, and it never says the record is rejected.
    """
    report = _report("authorization_valid_registry_entry.json", trust)
    assert (report.status, report.review_reasons) == ("OFFLINE_REVIEW", ("issuer_key_outside_validity_window",))
    rendered = render_verdict_narrative(report, audiences=("technical", "compliance", "executive")).to_dict()
    assert rendered["technical"].startswith("Offline verification produced a REVIEW verdict.")
    assert "FAIL verdict" not in rendered["technical"]
    assert "rejected" not in rendered["executive"].lower()
    assert rendered["compliance"].startswith("The bundle requires review.")


# --- a record whose integrity does not hold is never called undamaged ------------------
#
# Every authorization code's wording starts from an intact record ("The record is undamaged",
# "Bundle integrity verified"). Cited beside a bundle whose integrity check was not
# established, it would contradict the grounds next to it. The guard is structural: which
# codes the renderer cites, read against the report's own checks_established.


def _scope_mismatch_report(bundle: Path):
    return verify_path(
        bundle,
        registry_entry_path=FIXTURES / "authorization_valid_registry_entry.json",
        trust_registry_path=FIXTURES / "authorization_disallowed_asset_type_trust_registry.json",
        evaluation_time=EVALUATION_TIME,
    )


def _assert_integrity_grounds_only(report) -> None:
    assert report.status == STATUS_OFFLINE_FAIL
    # The trust registry was still evaluated: the guard is the renderer's, not the run's.
    assert report.trust_registry is not None
    assert "integrity" not in report.checks_established
    codes = infer_active_reason_codes(report)
    assert codes
    authorization_codes = set(AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS.values()) | set(
        AUTHORIZATION_CODE_BY_SIGNATURE_STATUS.values()
    )
    assert not authorization_codes & set(codes), codes
    assert any(code.startswith("INTEGRITY_") for code in codes), codes


@pytest.mark.parametrize("change", sorted(BUNDLE_CHANGES))
def test_no_authorization_code_is_cited_where_integrity_does_not_hold(change: str) -> None:
    with changed_bundle(FIXTURES / "link_valid_bundle", change) as bundle:
        report = _scope_mismatch_report(bundle)
    _assert_integrity_grounds_only(report)


def test_an_unsafe_member_is_not_narrated_as_an_undamaged_record(tmp_path: Path) -> None:
    import shutil

    root = tmp_path / "link_valid_bundle"
    shutil.copytree(FIXTURES / "link_valid_bundle", root)
    try:
        (root / "extra.json").symlink_to(root / "p1.json")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"this host cannot make a symbolic link: {exc}")
    report = _scope_mismatch_report(root)
    assert [error["code"] for error in report.errors] == ["unsafe_bundle_member"]
    _assert_integrity_grounds_only(report)


def test_the_scope_finding_is_cited_where_integrity_holds() -> None:
    """The counterpart: the same signer beside an intact bundle is narrated by its scope."""
    report = _scope_mismatch_report(FIXTURES / "link_valid_bundle")
    assert "integrity" in report.checks_established
    assert infer_active_reason_codes(report) == ("AUTHORIZATION_SCOPE_MISMATCH",)
