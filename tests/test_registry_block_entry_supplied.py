"""The report's registry block says an entry was supplied whenever the operator supplied one.

checks_requested reads the operator's arguments, and the registry block must agree with it:
an entry the run never compared with the bundle (here, a bundle without a receipt, which
leaves the link check not established) was still supplied and is not reported as
REGISTRY_ENTRY_NOT_PROVIDED.
"""

from __future__ import annotations

from pathlib import Path

from loquitur.verify.runner import verify_path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_an_entry_beside_a_bundle_without_a_receipt_is_reported_as_supplied() -> None:
    report = verify_path(
        FIXTURES / "valid_bundle", registry_entry_path=FIXTURES / "link_valid_registry_entry.json"
    ).to_dict()
    assert report["status"] == "OFFLINE_REVIEW"
    assert report["checks_requested"] == ["structure", "integrity", "link"]
    assert report["registry"]["entry_present"] is True
    assert report["registry"]["status"] == "REGISTRY_ENTRY_LINK_NOT_EVALUATED"
    assert report["registry"]["link_verification_supported"] is True


def test_no_entry_is_reported_as_not_provided() -> None:
    report = verify_path(FIXTURES / "valid_bundle").to_dict()
    assert report["registry"]["entry_present"] is False
    assert report["registry"]["status"] == "REGISTRY_ENTRY_NOT_PROVIDED"


def test_a_compared_entry_keeps_the_link_status() -> None:
    report = verify_path(
        FIXTURES / "link_valid_bundle", registry_entry_path=FIXTURES / "link_valid_registry_entry.json"
    ).to_dict()
    assert report["registry"]["entry_present"] is True
    assert report["registry"]["status"] == "REGISTRY_ENTRY_LINK_VERIFIED"
