"""The package is licensed under `MIT OR Apache-2.0`, and ships both license texts.

The license expression in `pyproject.toml` is what the package metadata declares, and the files
`license-files` names are the texts and the notice it carries. That every one of them is in the
built wheel and sdist is checked on the built files, by tools/local_wheel_gate.py --check-dist.

LICENSE-APACHE and LICENSE-MIT are pinned here by digest, and compared byte for byte with the
copies of loquitur-protocol, loquitur-schemas and loquitur-verify-ts where those are checked out
beside this repository, so a copy changed in one repository alone fails here.

One file is an exception: the Wycheproof test-vector file is third-party material under the
Apache License, Version 2.0 only, and NOTICE says so.
"""

from __future__ import annotations

import hashlib

import pytest
from repository import ROOT, WYCHEPROOF_FILE, flat, pyproject, require_repository_file
from siblings import absent

APACHE_SHA256 = "b67e145e47c0c9b190b0bc542481e05c5f9d001d78fda0dd5c41fb8b12d4c192"
MIT_SHA256 = "cd1a09a7a2e280075e41892deb81c8b552bd8e817597f9d0e357ba9a5546e83a"
LICENSE_TEXTS = ("LICENSE-APACHE", "LICENSE-MIT")
SIBLINGS = ("loquitur-protocol", "loquitur-schemas", "loquitur-verify-ts")


def test_metadata_declares_the_dual_license() -> None:
    project = pyproject()["project"]
    assert project["license"] == "MIT OR Apache-2.0"
    assert project["license-files"] == ["LICENSE-APACHE", "LICENSE-MIT", "NOTICE"]
    assert not any(classifier.startswith("License ::") for classifier in project["classifiers"])


@pytest.mark.parametrize(("name", "digest"), [("LICENSE-APACHE", APACHE_SHA256), ("LICENSE-MIT", MIT_SHA256)])
def test_each_license_text_is_the_pinned_one(name: str, digest: str) -> None:
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("sibling", SIBLINGS)
def test_each_license_text_is_the_one_the_other_repositories_carry(sibling: str) -> None:
    other = ROOT.parent / sibling
    if not other.is_dir():
        absent(f"{sibling} is not checked out beside this repository")
    differ = [name for name in LICENSE_TEXTS if (other / name).read_bytes() != (ROOT / name).read_bytes()]
    assert not differ, f"{sibling} carries other bytes in {differ}"


def test_the_root_has_no_single_license_file() -> None:
    assert not (ROOT / "LICENSE").exists()


def test_notice_and_readme_state_the_same_license() -> None:
    notice = flat("NOTICE")
    readme = flat("README.md")
    for text in (notice, readme):
        assert "MIT OR Apache-2.0" in text
        assert "LICENSE-APACHE" in text
        assert "LICENSE-MIT" in text
    assert "at your option" in readme


def test_notice_keeps_the_wycheproof_file_apache_only() -> None:
    notice = flat("NOTICE")
    assert WYCHEPROOF_FILE in notice
    assert "That file is licensed under the Apache License, Version 2.0 only" in notice
    assert "the MIT License option does not apply to it" in notice
    assert "The source distribution of this package does not include it" in notice
    require_repository_file(WYCHEPROOF_FILE, "it is under the Apache License 2.0 only (NOTICE)")


def test_the_source_distribution_leaves_the_apache_only_file_out() -> None:
    """The distributions declare `MIT OR Apache-2.0`, which must cover every file they hold
    (PEP 639); the Apache-2.0-only file is therefore not one of them. The wheel never held it, and
    tools/local_wheel_gate.py --check-dist refuses an sdist that does."""
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    assert f"exclude {WYCHEPROOF_FILE}" in manifest
    assert manifest.index(f"exclude {WYCHEPROOF_FILE}") > manifest.index("graft tests")
