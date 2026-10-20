"""A layer's read row and its verification row are each judged on their own.

Each layer reads the members it finds whatever else refuses it, and a host failure on one is the
layer's ``*_read_failed`` row (bundle-objects.md section 6). report-contract.md section 5.3 judges
every row on its own: a layer refused for what one member holds still reports the host failing to
read another, and a host failure on one member does not hide a refusal of what another holds. One
row is never reported in place of the other.

The envelope layer reads the envelope and its sidecar whenever either is present, also when it
lacks the other; envelope.json, with or without envelope_env1.json beside it, is never read
(bundle-objects.md section 4). envelope_links is false when the manifest layer is refused and the bundle carries both
the envelope and its sidecar, and null when it lacks either: no link was evaluated.

The host failure is injected where the verifier opens the member, so it holds on every host.
"""

from __future__ import annotations

import contextlib
import errno
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from bundle_builder import Bundle

from loquitur.verify.host_path import host_path
from loquitur.verify.runner import verify_path


@contextlib.contextmanager
def _refusing_read_of(monkeypatch: pytest.MonkeyPatch, target: Path) -> Iterator[list[str]]:
    """Opening ``target`` fails with EACCES; it can still be listed and inspected."""
    real_open = open
    host_target = Path(host_path(target))
    seen: list[str] = []

    def refusing_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and Path(os.fspath(file)) == host_target:
            seen.append(os.fspath(file))
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(file))
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", refusing_open)
        patch.setattr("io.open", refusing_open)
        yield seen


def _run(root: Path, unread: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    with _refusing_read_of(monkeypatch, root / unread) as seen:
        report = verify_path(root).to_dict()
    assert seen, f"the host was never asked to read {unread}"
    return report


def _codes(report: dict[str, Any]) -> list[str]:
    return [error["code"] for error in report["errors"]]


def _not_strict(bundle: Bundle, name: str) -> Bundle:
    bundle.members[name] = b'{"s": '
    return bundle


def _p1_breaking_its_contract() -> Bundle:
    return Bundle().edit("p1.json", lambda p1: p1.update({"unexpected": 1})).seal()


def _both_envelope_names() -> Bundle:
    bundle = Bundle().seal()
    bundle.members["envelope.json"] = bundle.members["envelope_env1.json"]
    return bundle


def _envelope_without_sidecar() -> Bundle:
    bundle = Bundle().seal()
    del bundle.members["envelope.sha256"]
    return bundle


def _sidecar_without_envelope() -> Bundle:
    bundle = Bundle().seal()
    del bundle.members["envelope_env1.json"]
    return bundle


# name: (bundle, the member the host fails to read, the errors, the outcome.reason)
_CASES = {
    "manifest not strict JSON, its sidecar unread": (
        lambda: _not_strict(Bundle().seal(), "manifest.json"),
        "manifest.sha256",
        ["manifest_verification_failed", "manifest_read_failed"],
        "manifest_verification_failed",
    ),
    "manifest unread, no sidecar": (
        lambda: _remove(Bundle().seal(), "manifest.sha256"),
        "manifest.json",
        ["manifest_verification_failed", "manifest_read_failed"],
        "manifest_verification_failed",
    ),
    "P1 breaking its contract, the canonical input unread": (
        _p1_breaking_its_contract,
        "canonical_input.json",
        ["manifest_read_failed", "p1_verification_failed", "p1_read_failed"],
        "manifest_read_failed",
    ),
    "P1 breaking its contract, its sidecar unread": (
        _p1_breaking_its_contract,
        "p1.sha256",
        ["manifest_read_failed", "p1_verification_failed", "p1_read_failed"],
        "manifest_read_failed",
    ),
    "P1 unread, the canonical input not strict JSON": (
        lambda: _not_strict(Bundle(), "canonical_input.json").seal(),
        "p1.json",
        ["manifest_read_failed", "p1_verification_failed", "p1_read_failed"],
        "manifest_read_failed",
    ),
    "envelope not strict JSON, its sidecar unread": (
        lambda: _not_strict(Bundle().seal(), "envelope_env1.json"),
        "envelope.sha256",
        ["envelope_verification_failed", "envelope_read_failed"],
        "envelope_verification_failed",
    ),
    # Half an envelope is a property of the names present, whatever the host reads.
    "envelope without its sidecar, unread": (
        _envelope_without_sidecar,
        "envelope_env1.json",
        ["envelope_incomplete", "envelope_read_failed"],
        "envelope_incomplete",
    ),
    "sidecar without its envelope, unread": (
        _sidecar_without_envelope,
        "envelope.sha256",
        ["envelope_incomplete", "envelope_read_failed"],
        "envelope_incomplete",
    ),
}


def _remove(bundle: Bundle, name: str) -> Bundle:
    del bundle.members[name]
    return bundle


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_read_row_and_the_verification_row_are_each_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    make, unread, errors, reason = _CASES[case]
    root = make().write(tmp_path / "bundle")
    report = _run(root, unread, monkeypatch)
    assert _codes(report) == errors
    assert report["outcome"]["reason"] == reason
    assert report["status"] == "OFFLINE_FAIL"


def test_each_case_is_refused_for_its_content_alone_when_every_member_is_read(tmp_path: Path) -> None:
    """Non-vacuity of the cases above: with every member readable, the run carries the
    verification row and no read row, so the read row above comes from the host failure alone."""
    for case, (make, _unread, errors, _reason) in sorted(_CASES.items()):
        root = make().write(tmp_path / case.replace(",", "").replace(" ", "_"))
        codes = _codes(verify_path(root).to_dict())
        assert not [code for code in codes if code.endswith("_read_failed")], case
        assert [code for code in codes if code.endswith("_verification_failed")] == [
            code for code in errors if code.endswith("_verification_failed")
        ], case


def test_envelope_json_beside_envelope_env1_json_is_never_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _both_envelope_names().write(tmp_path / "bundle")
    with _refusing_read_of(monkeypatch, root / "envelope.json") as seen:
        report = verify_path(root).to_dict()
    # envelope.json is an ordinary member name: undeclared beside the envelope, it is an extra
    # member, listed and never opened.
    assert not seen
    assert (_codes(report), report["review_reasons"]) == ([], ["bundle_extra_files"])


def _envelope_only_as_envelope_json() -> Bundle:
    bundle = Bundle().seal()
    bundle.members["envelope.json"] = bundle.members.pop("envelope_env1.json")
    return bundle


def test_envelope_json_without_envelope_env1_json_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No earlier envelope name is defined: without envelope_env1.json, envelope.json is still
    an ordinary member, so the host failing to read it is no envelope read row."""
    control = verify_path(_envelope_only_as_envelope_json().write(tmp_path / "control")).to_dict()
    root = _envelope_only_as_envelope_json().write(tmp_path / "bundle")
    with _refusing_read_of(monkeypatch, root / "envelope.json") as seen:
        report = verify_path(root).to_dict()
    assert not seen
    assert "envelope_incomplete" in _codes(control)
    assert _codes(report) == _codes(control)
    assert "envelope_read_failed" not in _codes(report)


def test_a_member_the_host_fails_to_read_keeps_the_flags_of_what_was_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unread_envelope = _run(_envelope_without_sidecar().write(tmp_path / "a"), "envelope_env1.json", monkeypatch)
    unread_sidecar = _run(_sidecar_without_envelope().write(tmp_path / "b"), "envelope.sha256", monkeypatch)
    for report, present in ((unread_envelope, True), (unread_sidecar, False)):
        checks = report["checks"]
        assert (checks["envelope_present"], checks["envelope_sha256"], checks["envelope_links"]) == (
            present,
            False,
            False,
        )


@pytest.mark.parametrize(
    ("envelope", "links"),
    [("both", False), ("envelope only", None), ("sidecar only", None), ("neither", None)],
)
def test_envelope_links_beside_a_refused_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, envelope: str, links: bool | None
) -> None:
    bundle = Bundle().seal()
    if envelope in ("sidecar only", "neither"):
        del bundle.members["envelope_env1.json"]
    if envelope in ("envelope only", "neither"):
        del bundle.members["envelope.sha256"]
    root = bundle.write(tmp_path / "bundle")
    report = _run(root, "manifest.sha256", monkeypatch)
    assert _codes(report)[0] == "manifest_read_failed"
    assert report["checks"]["envelope_links"] is links
