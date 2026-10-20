from __future__ import annotations

import json
from pathlib import Path

import pytest
from import_guards import assert_no_new_forbidden_modules_loaded, snapshot_forbidden_modules

from loquitur.verify.canonical import canonical_json_sha256
from loquitur.verify.p1 import (
    P1CanonicalizationError,
    P1MissingError,
    P1TypeError,
    canonical_input_hash,
    canonical_p1_sha256,
    verify_p1,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")


def _write_valid_p1_bundle(root: Path) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    canonical_input = {"asset_id": "asset-1", "external_mark": 100, "currency": "EUR"}
    ih = "sha256:" + canonical_input_hash(canonical_input, ("asset_id", "external_mark", "currency"))
    p1 = {"s": "p1", "v": 1, "ik": ["asset_id", "external_mark", "currency"], "ih": ih}
    _write_json(root / "canonical_input.json", canonical_input)
    _write_json(root / "p1.json", p1)
    p1_sha, _size = canonical_p1_sha256(p1)
    (root / "p1.sha256").write_text(p1_sha, encoding="utf-8")
    return p1


def test_verify_p1_accepts_valid_canonical_input(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_valid_p1_bundle(root)

    result = verify_p1(root)

    assert result.status == "OFFLINE_OK"
    assert result.verdict == "PASS"
    assert result.p1_sha256_ok is True
    assert result.input_hash_ok is True
    assert result.canonical_input_present is True


def test_verify_p1_detects_tampered_canonical_input(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_valid_p1_bundle(root)
    canonical_input = json.loads((root / "canonical_input.json").read_text(encoding="utf-8"))
    canonical_input["external_mark"] = 999
    _write_json(root / "canonical_input.json", canonical_input)

    result = verify_p1(root)

    assert result.status == "OFFLINE_FAIL"
    assert result.verdict == "FAIL"
    assert result.input_hash_ok is False
    assert "input_hash_mismatch" in result.notes


def test_verify_p1_missing_canonical_input_returns_review_not_ok(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_valid_p1_bundle(root)
    (root / "canonical_input.json").unlink()

    result = verify_p1(root)

    assert result.status == "OFFLINE_REVIEW"
    assert result.verdict == "REVIEW"
    assert result.input_hash_ok is None
    assert result.canonical_input_present is False
    assert "canonical_input_not_provided" in result.notes


def test_verify_p1_detects_p1_sha_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_valid_p1_bundle(root)
    (root / "p1.sha256").write_text("0" * 64, encoding="utf-8")

    result = verify_p1(root)

    assert result.status == "OFFLINE_FAIL"
    assert result.p1_sha256_ok is False
    assert "p1_sha_mismatch" in result.notes


def test_verify_p1_requires_p1_json(tmp_path: Path) -> None:
    with pytest.raises(P1MissingError):
        verify_p1(tmp_path)


def test_verify_p1_requires_p1_marker(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    root.mkdir()
    _write_json(root / "p1.json", {"s": "not-p1"})
    (root / "p1.sha256").write_text(canonical_json_sha256({"s": "not-p1"}), encoding="utf-8")

    with pytest.raises(P1CanonicalizationError):
        verify_p1(root)


def test_verify_p1_rejects_non_object_canonical_input(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_valid_p1_bundle(root)
    _write_json(root / "canonical_input.json", ["not", "object"])

    with pytest.raises(P1TypeError):
        verify_p1(root)


def test_p1_core_imports_no_backend_stack() -> None:
    before = snapshot_forbidden_modules()

    import loquitur.verify.p1  # noqa: F401

    assert_no_new_forbidden_modules_loaded(before)
