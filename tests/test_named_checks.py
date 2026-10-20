"""The named checks a report requests and establishes (verification-checks.md, report-contract.md).

The checks are `structure`, `integrity`, `link` and `authorization`, in that dependency order.
`checks_requested` is what the caller supplied: always the first two, `link` when a registry
entry was supplied (whatever became of it), `authorization` when a trust registry was. Only the
requested checks that hold, each with every check before it, are `checks_established`. A run is
OFFLINE_OK exactly when every requested check is established, and a run whose status is not an
evidence outcome establishes nothing. No level number, and none of the removed members, is in a
report.
"""

from __future__ import annotations

import re
from pathlib import Path

from authorization_kit import EVALUATION_TIME, IssuerKey, authorization_material, write_json
from bundle_builder import Bundle

from loquitur.verify.runner import verify_path

BASE = ["structure", "integrity"]
LINK = [*BASE, "link"]
ALL = [*LINK, "authorization"]
REMOVED = {"implemented_levels", "verification_level", "verification_scope", "trust_status", "attested_time"}


def _run(path: Path, **kwargs: object) -> dict:
    return verify_path(path, **kwargs).to_dict()


def _checks(report: dict) -> tuple:
    return report["status"], report["checks_requested"], report["checks_established"]


def _authorization_run(tmp_path: Path, *, trust=None, **kwargs: object) -> dict:
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    key = IssuerKey()
    bound = {"manifest_hash": "sha256:" + bundle.manifest_digest()}
    from bundle_builder import jcs, sha

    bound["receipt_hash"] = "sha256:" + sha(jcs(bundle.json("verification_receipt.json")))
    entry, registry = authorization_material(key, entry=lambda e: e.update(bound), trust=trust)
    return _run(
        root,
        registry_entry_path=write_json(tmp_path / "entry.json", entry),
        trust_registry_path=write_json(tmp_path / "trust.json", registry),
        **kwargs,
    )


def test_a_bundle_alone_requests_and_establishes_structure_and_integrity(tmp_path: Path) -> None:
    report = _run(Bundle().seal().write(tmp_path / "bundle"))
    assert _checks(report) == ("OFFLINE_OK", BASE, BASE)
    assert report["checks_evaluated"] == BASE


def test_an_entry_that_links_establishes_link(tmp_path: Path) -> None:
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    report = _run(root, registry_entry_path=bundle.link_entry(tmp_path / "entry.json"))
    assert _checks(report) == ("OFFLINE_OK", LINK, LINK)


def test_authorization_is_established_only_at_an_evaluation_time(tmp_path: Path) -> None:
    timed = _authorization_run(tmp_path / "timed", evaluation_time=EVALUATION_TIME)
    untimed = _authorization_run(tmp_path / "untimed")
    # Without a root the run is in review either way; the time decides only whether
    # evaluation_time_not_provided is among the reasons.
    assert _checks(timed) == ("OFFLINE_REVIEW", ALL, LINK)
    assert timed["review_reasons"] == ["trust_registry_root_not_pinned"]
    assert timed["evaluation_time"] == EVALUATION_TIME
    assert _checks(untimed) == ("OFFLINE_REVIEW", ALL, LINK)
    assert untimed["review_reasons"] == ["evaluation_time_not_provided", "trust_registry_root_not_pinned"]
    assert untimed["evaluation_time"] is None


def test_a_supplied_entry_requests_link_whatever_became_of_it(tmp_path: Path) -> None:
    bundle = Bundle().seal()
    root = bundle.write(tmp_path / "bundle")
    entry = bundle.link_entry(tmp_path / "entry.json")
    receiptless = Bundle()
    del receiptless.members["verification_receipt.json"]
    receiptless_root = receiptless.seal().write(tmp_path / "receiptless")
    runs = {
        "an entry path naming nothing": _run(root, registry_entry_path=tmp_path / "absent.json"),
        "an entry path naming a directory": _run(root, registry_entry_path=tmp_path),
        "a bundle without a receipt": _run(receiptless_root, registry_entry_path=entry),
        "an input that does not exist": _run(tmp_path / "nothing-here", registry_entry_path=entry),
    }
    assert {label: report["checks_requested"] for label, report in runs.items()} == dict.fromkeys(runs, LINK)
    assert {label: (report["status"], report["checks_established"]) for label, report in runs.items()} == {
        # Nothing found at the entry's path refuses the run as a whole (report-contract.md 5.3).
        "an entry path naming nothing": ("HOST_FAILURE", []),
        "an entry path naming a directory": ("OFFLINE_FAIL", BASE),
        # An entry without a receipt is not evidence against the bundle: link is not established.
        "a bundle without a receipt": ("OFFLINE_REVIEW", BASE),
        "an input that does not exist": ("HOST_FAILURE", []),
    }
    assert runs["a bundle without a receipt"]["review_reasons"] == ["verification_receipt_not_provided"]


def test_established_checks_are_a_prefix_of_the_requested_ones(tmp_path: Path) -> None:
    tampered = Bundle().seal()
    tampered.members["canonical_input.json"] = b'{"tampered":true}'
    failing = _run(tampered.write(tmp_path / "tampered"))
    revoked = _authorization_run(
        tmp_path / "revoked",
        trust=lambda t: t["entries"][0].update(status="revoked", revoked_at="2026-05-01T00:00:00Z"),
        evaluation_time=EVALUATION_TIME,
    )
    assert _checks(failing) == ("OFFLINE_FAIL", BASE, ["structure"])
    assert _checks(revoked) == ("OFFLINE_FAIL", ALL, LINK)
    for report in (failing, revoked):
        established = report["checks_established"]
        assert report["checks_requested"][: len(established)] == established
        assert report["review_reasons"] == []


def test_no_report_carries_a_removed_member(tmp_path: Path) -> None:
    reports = [
        _run(Bundle().seal().write(tmp_path / "bundle")),
        _authorization_run(tmp_path / "authorization", evaluation_time=EVALUATION_TIME),
        _run(tmp_path / "nothing-here"),
    ]
    for report in reports:
        assert not REMOVED & set(report), sorted(REMOVED & set(report))
        assert not REMOVED & set(report["outcome"]), sorted(REMOVED & set(report["outcome"]))
        assert not re.search(r"\bL[0-5]\b", str(report)) and "OFFLINE_STANDALONE" not in str(report)
