"""A manifest.files entry whose digest is not a string fails the file check.

bundle-objects.md section 2 types every declared digest as 64 lowercase hexadecimal characters.
A digest that is a number, a boolean, null, a list or an object is not one: the manifest fails
its contract (manifest_invalid_file_digest), and the member it names fails the file check, so
checks.manifest_files is false. The name is still declared, so the member is not an undeclared
file. loquitur-verify-ts holds the same rows in test/manifest-non-string-digest.test.ts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bundle_builder import Bundle

from loquitur.verify import cli
from loquitur.verify.runner import verify_path

NON_STRING_DIGESTS = {
    "number": 7,
    "boolean": True,
    "null": None,
    "list": ["a" * 64],
    "object": {"sha256": "a" * 64},
}


def _declared_name(bundle: Bundle) -> str:
    return sorted(bundle.json("manifest.json")["files"])[0]


def _report(tmp_path: Path, bundle: Bundle) -> dict:
    root = bundle.write(tmp_path / "bundle")
    report = verify_path(root).to_dict()
    assert cli.main([str(root), "--json"]) == report["exit_code"]
    return report


def test_the_sealed_fixture_passes_the_file_check(tmp_path: Path) -> None:
    report = _report(tmp_path, Bundle().seal())
    assert report["checks"]["manifest_files"] is True


@pytest.mark.parametrize("kind", sorted(NON_STRING_DIGESTS))
def test_a_digest_that_is_not_a_string_fails_the_file_check(tmp_path: Path, kind: str) -> None:
    bundle = Bundle().seal()
    name = _declared_name(bundle)
    bundle.edit("manifest.json", lambda manifest: manifest["files"].__setitem__(name, NON_STRING_DIGESTS[kind]))
    bundle.seal(files=False)

    report = _report(tmp_path, bundle)

    assert report["status"] == "OFFLINE_FAIL"
    assert report["checks"]["manifest_files"] is False
    manifest = report["manifest"]
    assert f"manifest_invalid_file_digest:{name}" in manifest["shape_errors"]
    assert name not in manifest["extra_files"]
    [check] = [check for check in manifest["file_checks"] if check["name"] == name]
    assert check == {
        "name": name,
        "expected_sha256": None,
        "actual_sha256": None,
        "ok": False,
        "error": "invalid_file_digest",
    }
