"""This verifier's own informative members, held to the normative members of the same report.

report-contract.md section 2 makes every member outside its table informative: a conformance
comparison does not read it. It does not license a false value, and a member only this verifier
carries (section 7) has no second implementation to disagree with it. So each rule below states
what such a member says in terms of the normative members of the same run, and every declared run
of the pinned conformance corpus is held to the rules.

The corpus is the archive CONFORMANCE_CONSUMER.json pins, read from the loquitur-protocol
checkout beside this one. The module skips, saying why, when that checkout is absent, and fails
when LOQUITUR_REQUIRE_SIBLINGS is set.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest
from test_corpus_roots import declared_runs, run_once

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT.parent / "loquitur-protocol"
REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"

# The four window rows of trust-registry-authorization.md section 9 and the check of
# trust_registry.checks each one is decided by.
WINDOW_CHECKS = {
    "TRUST_REGISTRY_NOT_YET_EFFECTIVE": "trust_registry_effective",
    "TRUST_REGISTRY_EXPIRED": "trust_registry_expires",
    "ISSUER_KEY_NOT_YET_EFFECTIVE": "issuer_key_effective",
    "ISSUER_KEY_EXPIRED": "issuer_key_expires",
}


def _pinned_archive() -> Path:
    pin = json.loads((ROOT / "CONFORMANCE_CONSUMER.json").read_text(encoding="utf-8"))["canonical_artifact"]
    archive = PROTOCOL / "conformance" / pin["name"]
    if not archive.is_file():
        reason = f"the pinned corpus {pin['name']} is not beside this checkout ({PROTOCOL} is absent)"
        if os.environ.get(REQUIRE_SIBLINGS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            pytest.fail(f"{REQUIRE_SIBLINGS_ENV} is set but {reason}")
        pytest.skip(reason)
    data = archive.read_bytes()
    assert hashlib.sha256(data).hexdigest() == pin["sha256"], f"{archive} is not the pinned corpus"
    return archive


@pytest.fixture(scope="module")
def corpus_reports(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    """The report of every declared run of the pinned corpus that writes one, by run name."""
    archive = _pinned_archive()
    target = tmp_path_factory.mktemp("pinned-corpus")
    with zipfile.ZipFile(archive) as opened:
        opened.extractall(target)
    (root,) = [path for path in target.iterdir() if path.is_dir()]
    reports = {}
    for name, run in declared_runs(root).items():
        report, _ = run_once(root / "vectors", run)
        if report is not None:
            reports[name] = report
    assert len(reports) > 900, f"only {len(reports)} runs wrote a report; the rules would measure little"
    return reports


def informative_member_findings(report: dict[str, Any]) -> list[str]:
    """Every informative member of ``report`` that says something its normative members deny."""
    found: list[str] = []
    requested = report.get("checks_requested") or []
    registry = report.get("registry") or {}
    notes = report.get("notes") or []
    trust = report.get("trust_registry")
    link = report.get("registry_link")
    # The registry block says which checks the run was asked for; checks_requested says it too.
    if registry.get("trust_registry_supported") != (trust is not None):
        found.append(f"registry.trust_registry_supported is {registry.get('trust_registry_supported')!r}")
    if registry.get("link_verification_supported") != ("link" in requested):
        found.append(f"registry.link_verification_supported is {registry.get('link_verification_supported')!r}")
    if "registry_entry_not_provided" in notes and "link" in requested:
        found.append("notes say no registry entry was provided beside a requested link check")
    skipped = "trust_registry_skipped_registry_link_failed" in notes
    link_failed = "authorization" in requested and link is not None and link.get("ok") is False
    if skipped != link_failed:
        found.append(f"the skipped-trust-registry note is {'present' if skipped else 'absent'} for this link outcome")
    if trust is not None:
        valid_root = trust.get("trust_registry_root_signature_status") == "ROOT_SIGNATURE_VALID"
        if trust.get("trust_registry_root_signature_verified") is not valid_root:
            found.append("trust_registry.trust_registry_root_signature_verified contradicts the root status")
        checks = {check.get("name"): check for check in trust.get("checks") or []}
        status = checks.get("issuer_key_status")
        if status is not None and status.get("ok") is not (status.get("actual") == status.get("expected")):
            found.append("trust_registry.checks issuer_key_status contradicts its own values")
        window = WINDOW_CHECKS.get(trust.get("authorization_status") or "")
        if window is not None and (checks.get(window) or {}).get("ok") is not False:
            found.append(f"trust_registry.checks {window} holds beside {trust.get('authorization_status')}")
    return found


def test_every_informative_member_agrees_with_its_run(corpus_reports: dict[str, dict[str, Any]]) -> None:
    found = [
        f"{name}: {finding}"
        for name, report in sorted(corpus_reports.items())
        for finding in informative_member_findings(report)
    ]
    assert not found, f"{len(found)} informative members contradict their runs:\n" + "\n".join(found[:40])


def test_the_window_rows_and_a_verified_root_are_reached(corpus_reports: dict[str, dict[str, Any]]) -> None:
    """Not vacuous: the corpus reaches every rule's condition, so a rule cannot hold for want of a run."""
    statuses = {(report.get("trust_registry") or {}).get("authorization_status") for report in corpus_reports.values()}
    assert set(WINDOW_CHECKS) <= statuses, sorted(set(WINDOW_CHECKS) - statuses)
    roots = {
        (report.get("trust_registry") or {}).get("trust_registry_root_signature_status")
        for report in corpus_reports.values()
    }
    assert {"ROOT_SIGNATURE_VALID", "ROOT_SIGNATURE_NOT_EVALUATED"} <= roots
    notes = [note for report in corpus_reports.values() for note in report.get("notes") or []]
    assert "trust_registry_skipped_registry_link_failed" in notes and "registry_entry_not_provided" in notes


@pytest.mark.parametrize(
    ("member", "value"),
    [
        (("registry", "trust_registry_supported"), False),
        (("registry", "link_verification_supported"), False),
        (("trust_registry", "trust_registry_root_signature_verified"), True),
    ],
)
def test_a_contradicting_member_is_found(member: tuple[str, str], value: object) -> None:
    """Not vacuous: one member set against its run is a finding."""
    report = {
        "checks_requested": ["structure", "integrity", "link", "authorization"],
        "registry": {"trust_registry_supported": True, "link_verification_supported": True},
        "notes": [],
        "registry_link": {"ok": True},
        "trust_registry": {
            "authorization_status": "AUTHORIZED_ACTIVE_KEY",
            "trust_registry_root_signature_status": "NO_PINNED_TRUST_ROOT",
            "trust_registry_root_signature_verified": False,
            "checks": [],
        },
    }
    assert informative_member_findings(report) == []
    section, name = member
    report[section][name] = value
    assert len(informative_member_findings(report)) == 1
