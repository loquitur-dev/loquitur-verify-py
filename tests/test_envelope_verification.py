from __future__ import annotations

import json
from pathlib import Path

import pytest
from bundle_builder import Bundle
from import_guards import assert_no_new_forbidden_modules_loaded, snapshot_forbidden_modules

from loquitur.verify import cli
from loquitur.verify.canonical import canonical_json_sha256, file_sha256
from loquitur.verify.envelope import (
    REGISTRY_ENTRY_NOT_PROVIDED,
    verify_envelope,
)
from loquitur.verify.manifest import verify_manifest
from loquitur.verify.p1 import canonical_input_hash, canonical_p1_sha256, verify_p1
from loquitur.verify.runner import verify_path


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")


def _write_bundle(root: Path) -> tuple[dict[str, object], str, str]:
    root.mkdir(parents=True, exist_ok=True)
    canonical_input = {"asset_id": "asset-1", "external_mark": 100, "currency": "EUR"}
    ih = "sha256:" + canonical_input_hash(canonical_input, ("asset_id", "external_mark", "currency"))
    p1 = {"s": "p1", "v": 1, "ik": ["asset_id", "external_mark", "currency"], "ih": ih}
    _write_json(root / "canonical_input.json", canonical_input)
    _write_json(root / "p1.json", p1)
    p1_sha, _size = canonical_p1_sha256(p1)
    (root / "p1.sha256").write_text(p1_sha, encoding="utf-8")
    manifest = {
        "bundle_id": root.name,
        "schema_version": "loquitur.bundle.v1",
        "nonce": "5e" * 32,
        "files": {
            "canonical_input.json": "sha256:" + file_sha256(root / "canonical_input.json"),
            "p1.json": "sha256:" + file_sha256(root / "p1.json"),
            "p1.sha256": "sha256:" + file_sha256(root / "p1.sha256"),
        },
    }
    _write_json(root / "manifest.json", manifest)
    manifest_sha = canonical_json_sha256(manifest)
    (root / "manifest.sha256").write_text(manifest_sha, encoding="utf-8")
    return p1, p1_sha, manifest_sha


def _write_envelope(root: Path, *, p1_sha: str, manifest_sha: str, bundle_id: str | None = None) -> dict[str, object]:
    env = {
        "s": "env1",
        "v": 1,
        "ts": 1776988860,
        "network": "testnet",
        "p1_txid": "TX-P1",
        "p1_sha256": "sha256:" + p1_sha,
        "bundle_id": bundle_id or root.name,
        "bundle_manifest_sha256": "sha256:" + manifest_sha,
        "uri": f"/bundles/{root.name}/download",
        "asset_id": "asset-1",
        "asset_type": "property",
    }
    _write_json(root / "envelope_env1.json", env)
    (root / "envelope.sha256").write_text(canonical_json_sha256(env), encoding="utf-8")
    return env


def test_verify_envelope_accepts_env1_and_links_manifest_and_p1(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _p1, p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha=p1_sha, manifest_sha=manifest_sha)

    result = verify_envelope(root, manifest_result=verify_manifest(root), p1_result=verify_p1(root))

    assert result.status == "OFFLINE_OK"
    assert result.verdict == "PASS"
    assert result.envelope_path_name == "envelope_env1.json"
    assert result.envelope_sha256_ok is True
    assert result.bundle_id_ok is True
    assert result.manifest_link_ok is True
    assert result.p1_link_ok is True
    assert result.links_ok is True
    assert result.registry_status == REGISTRY_ENTRY_NOT_PROVIDED
    assert result.registry_signature_supported is False


def test_envelope_json_is_not_an_envelope_name(tmp_path: Path) -> None:
    # bundle-objects.md: the only envelope name is envelope_env1.json. The former second name is
    # an ordinary member, so a bundle that carries it and the sidecar has half an envelope.
    root = tmp_path / "bundle-a"
    _p1, p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha=p1_sha, manifest_sha=manifest_sha)
    (root / "envelope.json").write_text((root / "envelope_env1.json").read_text(encoding="utf-8"), encoding="utf-8")
    (root / "envelope_env1.json").unlink()

    result = verify_envelope(root, manifest_result=verify_manifest(root), p1_result=verify_p1(root))

    assert result.envelope_path_name is None
    assert result.envelope_files_complete is False
    assert result.ok is False


def test_verify_envelope_detects_tampered_envelope_sha(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _p1, p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha=p1_sha, manifest_sha=manifest_sha)
    envelope = json.loads((root / "envelope_env1.json").read_text(encoding="utf-8"))
    envelope["asset_id"] = "asset-tampered"
    _write_json(root / "envelope_env1.json", envelope)

    result = verify_envelope(root, manifest_result=verify_manifest(root), p1_result=verify_p1(root))

    assert result.status == "OFFLINE_FAIL"
    assert result.envelope_sha256_ok is False
    assert "envelope_sha_mismatch" in result.notes


def test_verify_envelope_detects_manifest_link_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _p1, p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha=p1_sha, manifest_sha="0" * 64)

    result = verify_envelope(root, manifest_result=verify_manifest(root), p1_result=verify_p1(root))

    assert result.status == "OFFLINE_FAIL"
    assert result.manifest_link_ok is False
    assert "envelope_manifest_link_mismatch" in result.notes


def test_verify_envelope_detects_p1_link_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _p1, _p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha="1" * 64, manifest_sha=manifest_sha)

    result = verify_envelope(root, manifest_result=verify_manifest(root), p1_result=verify_p1(root))

    assert result.status == "OFFLINE_FAIL"
    assert result.p1_link_ok is False
    assert "envelope_p1_link_mismatch" in result.notes


def test_verify_envelope_classifies_missing_registry_entry_clearly(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _p1, p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha=p1_sha, manifest_sha=manifest_sha)

    result = verify_envelope(root)

    assert result.registry_entry_present is False
    assert result.registry_status == REGISTRY_ENTRY_NOT_PROVIDED
    assert result.registry_signature_supported is False
    assert "registry_entry_not_provided" in result.notes


def test_verify_envelope_takes_no_registry_entry(tmp_path: Path) -> None:
    # The envelope layer never reads an entry; the runner never passed one, and a parameter
    # for it let the report's registry block say an entry was not provided when one was.
    root = tmp_path / "bundle-a"
    _p1, p1_sha, manifest_sha = _write_bundle(root)
    _write_envelope(root, p1_sha=p1_sha, manifest_sha=manifest_sha)

    with pytest.raises(TypeError):
        verify_envelope(root, registry_entry={"receipt_id": "draft"})  # type: ignore[call-arg]
    result = verify_envelope(root)
    assert result.registry_entry_present is False
    assert result.registry_status == REGISTRY_ENTRY_NOT_PROVIDED
    assert "registry_signature_verification_unsupported" not in result.notes


def test_verify_envelope_missing_envelope_returns_review_not_fake_ok(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _write_bundle(root)

    result = verify_envelope(root)

    assert result.status == "OFFLINE_REVIEW"
    assert result.verdict == "REVIEW"
    assert result.envelope_present is False
    assert result.envelope_sha256_ok is None
    assert "envelope_not_provided" in result.notes


def test_verify_envelope_incomplete_files_fail(tmp_path: Path) -> None:
    root = tmp_path / "bundle-a"
    _write_bundle(root)
    _write_json(root / "envelope_env1.json", {"s": "env1"})

    result = verify_envelope(root)

    assert result.status == "OFFLINE_FAIL"
    assert result.envelope_files_complete is False
    assert result.envelope_sha256_ok is False
    assert "envelope_files_incomplete" in result.notes


# ---------------------------------------------------------------- links read exactly as written
#
# Each case below changes one envelope member and reseals envelope.sha256, so the envelope
# digest still holds and only the link rule can refuse it.


def _envelope_case(tmp_path: Path, mutate, *, manifest_mutate=None) -> dict:
    bundle = Bundle()
    if manifest_mutate is not None:
        bundle.edit("manifest.json", manifest_mutate)
    bundle.seal().edit("envelope_env1.json", mutate).reseal_envelope_sidecar()
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


@pytest.mark.parametrize("value", ["", "   ", "\t"], ids=["empty", "spaces", "tab"])
def test_an_empty_envelope_bundle_id_is_a_failed_link_not_an_absent_one(tmp_path: Path, value: str) -> None:
    report = _envelope_case(tmp_path, lambda v: v.update(bundle_id=value))
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["envelope_sha256"] is True
    assert report["checks"]["envelope_links"] is False
    assert report["envelope"]["bundle_id_ok"] is False


def test_a_padded_envelope_bundle_id_is_not_trimmed_into_a_match(tmp_path: Path) -> None:
    # The bundle_id is compared exactly: padding on one side is a mismatch, as a changed letter
    # case is, and the same padded value on both sides is a match.
    padded = _envelope_case(tmp_path / "padded", lambda v: v.update(bundle_id=" link_valid_bundle "))
    case_changed = _envelope_case(tmp_path / "case", lambda v: v.update(bundle_id="LINK_VALID_BUNDLE"))
    both = Bundle().edit("manifest.json", lambda m: m.update(bundle_id=" padded-id ")).seal()
    got = {
        "padded": (padded["status"], "envelope_bundle_id_mismatch" in padded["notes"]),
        "case-changed": (case_changed["status"], "envelope_bundle_id_mismatch" in case_changed["notes"]),
        "same-padding-both-sides": verify_path(both.write(tmp_path / "both" / "bundle")).status,
    }
    assert got == {
        "padded": ("OFFLINE_FAIL", True),
        "case-changed": ("OFFLINE_FAIL", True),
        "same-padding-both-sides": "OFFLINE_OK",
    }


@pytest.mark.parametrize(("envelope_value", "manifest_value"), [(7, "7"), (True, "True")], ids=["number", "boolean"])
def test_a_bundle_id_that_is_not_a_string_is_a_malformed_link(
    tmp_path: Path, envelope_value: object, manifest_value: str
) -> None:
    report = _envelope_case(
        tmp_path,
        lambda v: v.update(bundle_id=envelope_value),
        manifest_mutate=lambda m: m.update(bundle_id=manifest_value),
    )
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["envelope_links"] is False
    assert "envelope_bundle_id_malformed" in report["notes"]


@pytest.mark.parametrize("member", ["p1_sha256", "bundle_manifest_sha256"])
def test_an_envelope_digest_link_is_read_as_written(tmp_path: Path, member: str) -> None:
    # The link is the whole self-describing string (canonicalization-and-hashing.md section 2):
    # a bare digest and a relabeled one run with the spellings a folding reader would match.
    link = "manifest" if member == "bundle_manifest_sha256" else "p1"
    spellings = {
        "uppercase": str.upper,
        "padded": lambda d: " " + d + " ",
        "bare": lambda d: d.removeprefix("sha256:"),
        "doubly-prefixed": lambda d: "sha256:" + d,
        "uppercase-label": lambda d: "SHA256:" + d.removeprefix("sha256:"),
        "newline": lambda d: d + "\n",
    }
    got = {}
    for label, spell in spellings.items():
        report = _envelope_case(tmp_path / label, lambda v, s=spell: v.update({member: s(v[member])}))
        got[label] = (
            report["status"],
            report["checks"]["envelope_sha256"],
            report["checks"]["envelope_links"],
            f"envelope_{link}_link_malformed" in report["notes"],
        )
    assert got == dict.fromkeys(spellings, ("OFFLINE_FAIL", True, False, True))


@pytest.mark.parametrize("spell", [str.upper, lambda d: d + "\n"], ids=["uppercase", "newline"])
def test_the_envelope_sidecar_is_read_as_written(tmp_path: Path, spell) -> None:
    bundle = Bundle().seal()
    bundle.members["envelope.sha256"] = spell(bundle.members["envelope.sha256"].decode()).encode()
    report = verify_path(bundle.write(tmp_path / "bundle")).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["envelope_sha256"] is False


@pytest.mark.parametrize(
    "spell", [str.upper, lambda d: "sha256:" + d, lambda d: d + "\n"], ids=["uppercase", "prefixed", "newline"]
)
def test_a_sidecar_not_bare_beside_a_malformed_envelope_is_a_failed_comparison(tmp_path: Path, spell) -> None:
    # bundle-objects.md section 6: null means the comparison's input is absent, false that it was
    # made and did not hold. The sidecar is present here, so the value is false, as it is beside a
    # well-formed envelope and as the TypeScript verifier reports.
    bundle = Bundle().seal()
    envelope = json.loads(bundle.members["envelope_env1.json"])
    envelope["unexpected"] = True
    bundle.members["envelope_env1.json"] = json.dumps(envelope, separators=(",", ":")).encode()
    bundle.members["envelope.sha256"] = spell(canonical_json_sha256(envelope)).encode()
    report = verify_path(bundle.write(tmp_path / "bundle")).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["envelope_sha256"] is False


# ---------------------------------------------------------------- selection and presence


def _envelope_members(tmp_path: Path, *, env1: bytes | None, legacy: bytes | None) -> dict:
    bundle = Bundle().seal()
    valid = bundle.members.pop("envelope_env1.json")
    for name, data in (("envelope_env1.json", env1), ("envelope.json", legacy)):
        if data is not None:
            bundle.members[name] = valid if data == b"valid" else data
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


@pytest.mark.parametrize("legacy", [b"valid", b"not valid JSON"], ids=["identical", "other-bytes"])
def test_envelope_json_beside_the_envelope_is_an_undeclared_member(tmp_path: Path, legacy: bytes) -> None:
    # The former second envelope name is an ordinary member name: beside a valid envelope it is
    # an undeclared member (bundle_extra_files), whatever it holds, and never read as JSON.
    report = _envelope_members(tmp_path / "both", env1=b"valid", legacy=legacy)
    assert (report["status"], report["errors"], report["review_reasons"]) == (
        "OFFLINE_REVIEW",
        [],
        ["bundle_extra_files"],
    )
    assert [report["checks"][k] for k in ("envelope_present", "envelope_sha256", "envelope_links")] == [
        True,
        True,
        True,
    ]
    # Alone beside the sidecar it is not an envelope: the bundle carries half of one.
    alone = _envelope_members(tmp_path / "alone", env1=None, legacy=b"valid")
    assert (alone["status"], [error["code"] for error in alone["errors"]]) == ("OFFLINE_FAIL", ["envelope_incomplete"])
    assert alone["envelope"] is None or alone["envelope"]["envelope_path_name"] is None


@pytest.mark.parametrize("legacy", [None, b"valid"], ids=["alone", "beside-a-valid-legacy-envelope"])
@pytest.mark.parametrize("env1", [b"not valid JSON", b"[]", b"{\xff}"], ids=["not-json", "not-an-object", "not-utf8"])
def test_an_unreadable_envelope_is_present_and_fails(tmp_path: Path, env1: bytes, legacy: bytes | None) -> None:
    report = _envelope_members(tmp_path, env1=env1, legacy=legacy)
    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["envelope_present"] is True
    assert report["checks"]["envelope_sha256"] is False
    assert report["checks"]["envelope_links"] is False
    assert report["checks"]["registry_signature"] == "UNSUPPORTED"


def test_envelope_core_imports_no_backend_stack() -> None:
    before = snapshot_forbidden_modules()

    import loquitur.verify.envelope  # noqa: F401

    assert_no_new_forbidden_modules_loaded(before)
