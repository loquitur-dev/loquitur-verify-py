from __future__ import annotations

from pathlib import Path

import pytest
from bundle_builder import Bundle
from import_guards import assert_no_new_forbidden_modules_loaded, snapshot_forbidden_modules

from loquitur.verify.canonical import canonical_json_sha256, file_sha256
from loquitur.verify.manifest import (
    ManifestMissingError,
    ManifestShaMissingError,
    UnsafeManifestPathError,
    manifest_files_map,
    read_manifest,
    safe_manifest_child,
    verify_manifest,
)
from loquitur.verify.runner import verify_path


def _write_bundle(root: Path, manifest: dict[str, object], files: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / "manifest.json").write_text(__import__("json").dumps(manifest), encoding="utf-8")
    (root / "manifest.sha256").write_text(canonical_json_sha256(manifest), encoding="utf-8")


def _manifest_for(root: Path, *, files: dict[str, bytes] | None = None) -> dict[str, object]:
    if files:
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    return {
        "bundle_id": "bundle-a",
        "schema_version": "loquitur.bundle.v1",
        "nonce": "3a" * 32,
        "files": {name: "sha256:" + file_sha256(root / name) for name in sorted(files or {})},
    }


def test_verify_manifest_accepts_valid_bundle(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    files = {"p1.json": b'{"ok":true}', "docs/readme.txt": b"hello"}
    manifest = _manifest_for(root, files=files)
    _write_bundle(root, manifest, {})

    result = verify_manifest(root)

    assert result.ok is True
    assert result.manifest_sha256_ok is True
    assert result.files_ok is True
    assert [check.name for check in result.file_checks] == ["docs/readme.txt", "p1.json"]
    assert all(check.ok for check in result.file_checks)


def test_verify_manifest_detects_tampered_manifest_sha(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    files = {"p1.json": b'{"ok":true}'}
    manifest = _manifest_for(root, files=files)
    _write_bundle(root, manifest, {})
    (root / "manifest.json").write_text('{"bundle_id":"bundle-a","files":{}}', encoding="utf-8")

    result = verify_manifest(root)

    assert result.ok is False
    assert result.manifest_sha256_ok is False


def test_verify_manifest_detects_tampered_declared_file(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    files = {"p1.json": b'{"ok":true}'}
    manifest = _manifest_for(root, files=files)
    _write_bundle(root, manifest, {})
    (root / "p1.json").write_bytes(b'{"ok":false}')

    result = verify_manifest(root)

    assert result.ok is False
    assert result.manifest_sha256_ok is True
    assert result.file_checks[0].ok is False
    assert result.file_checks[0].error == "sha256_mismatch"


def test_verify_manifest_detects_missing_declared_file(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    files = {"p1.json": b'{"ok":true}'}
    manifest = _manifest_for(root, files=files)
    _write_bundle(root, manifest, {})
    (root / "p1.json").unlink()

    result = verify_manifest(root)

    assert result.ok is False
    assert result.file_checks[0].ok is False
    assert result.file_checks[0].error == "file_missing"


def test_verify_manifest_records_unsafe_declared_file_path(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    manifest = {
        "bundle_id": "bundle-a",
        "schema_version": "loquitur.bundle.v1",
        "nonce": "3a" * 32,
        "files": {"../outside.txt": "sha256:" + "0" * 64},
    }
    _write_bundle(root, manifest, {})

    result = verify_manifest(root)

    assert result.ok is False
    assert result.file_checks[0].error == "unsafe_manifest_path"


@pytest.mark.parametrize("unsafe_name", ["../x", "/x", "C:/x", r"C:\\x", "nested/../../x"])
def test_safe_manifest_child_rejects_unsafe_paths(tmp_path: Path, unsafe_name: str) -> None:
    with pytest.raises(UnsafeManifestPathError):
        safe_manifest_child(tmp_path, unsafe_name)


def test_manifest_files_map_reads_the_object_form_and_not_the_list_form() -> None:
    digest_a = "a" * 64
    digest_b = "b" * 64

    assert manifest_files_map({"files": {"a.txt": digest_a}}) == {"a.txt": digest_a}
    # The list form is refused by the contract and declares nothing, so nothing is hashed for it.
    assert manifest_files_map({"files": [{"name": "b.txt", "sha256": digest_b}]}) == {}


ONE_MEMBER = "canonical_input.json"


@pytest.mark.parametrize("wrong", [False, True], ids=["digest-matches", "digest-wrong"])
def test_a_manifest_declaring_one_member_is_checked_through_verify_path(tmp_path: Path, wrong: bool) -> None:
    # No manifest of the corpus declares exactly one member, so the member check over a files map
    # of one entry is held here, through verify_path. The bundle's p1 members are left undeclared,
    # which makes a run whose one digest matches REVIEW (bundle_extra_files), not PASS; the member
    # check itself holds, and fails when that one digest is wrong.
    bundle = Bundle().edit("manifest.json", lambda m: m.update(files={ONE_MEMBER: m["files"][ONE_MEMBER]})).seal()
    if wrong:
        bundle.edit("manifest.json", lambda m: m["files"].update({ONE_MEMBER: "sha256:" + "0" * 64})).seal(files=False)
    report = verify_path(bundle.write(tmp_path / "bundle")).to_dict()
    [check] = report["manifest"]["file_checks"]
    assert (check["name"], check["ok"]) == (ONE_MEMBER, not wrong)
    assert report["checks"]["manifest_files"] is not wrong
    assert report["manifest"]["extra_files"] == ["p1.json", "p1.sha256"]
    if wrong:
        assert report["status"] == "OFFLINE_FAIL"
    else:
        assert (report["status"], report["review_reasons"]) == ("OFFLINE_REVIEW", ["bundle_extra_files"])


def test_read_manifest_reports_missing_required_files(tmp_path: Path) -> None:
    with pytest.raises(ManifestMissingError):
        read_manifest(tmp_path)

    (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
    from loquitur.verify.manifest import read_stored_manifest_sha256

    with pytest.raises(ManifestShaMissingError):
        read_stored_manifest_sha256(tmp_path)


def test_manifest_core_imports_no_backend_stack() -> None:
    before = snapshot_forbidden_modules()

    import loquitur.verify.manifest  # noqa: F401

    assert_no_new_forbidden_modules_loaded(before)


def test_a_present_sidecar_that_is_not_text_is_a_mismatch_not_a_refused_manifest(tmp_path: Path) -> None:
    """A sidecar present and not UTF-8, or over the 20 MiB member bound, is not the digest.

    Raising, as an absent sidecar does, would refuse the manifest outright: no manifest
    result, the error manifest_verification_failed, and no manifest digest for the registry
    link, which would then fail although the entry commits to exactly that manifest. A sidecar
    of 65 characters, a p1.sha256 or envelope.sha256 that is not UTF-8, and loquitur-verify-ts
    over the same bytes all report a mismatch and nothing else.
    """
    from bundle_builder import Bundle

    from loquitur.verify.members import MAX_MEMBER_BYTES
    from loquitur.verify.runner import verify_path

    got = {}
    for label, sidecar in {
        "not-utf-8": bytes([0xFF]) * 64,
        "over-the-bound": b"0" * (MAX_MEMBER_BYTES + 1),
        "sixty-five-characters": b"0" * 65,
    }.items():
        sealed = Bundle().seal()
        sealed.members["manifest.sha256"] = sidecar
        root = sealed.write(tmp_path / label / "bundle")
        result = verify_manifest(root)
        report = verify_path(root, registry_entry_path=sealed.link_entry(tmp_path / label / "entry.json")).to_dict()
        got[label] = (
            result.manifest_sha256_ok,
            report["status"],
            [error["code"] for error in report["errors"]],
            report["checks"]["registry_link"],
        )
    assert got == {label: (False, "OFFLINE_FAIL", [], True) for label in got}
