from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from loquitur.verify.canonical import canonical_json_sha256, file_sha256
from loquitur.verify.cli import main
from loquitur.verify.p1 import canonical_input_hash, canonical_p1_sha256
from loquitur.verify.runner import (
    EXIT_OFFLINE_FAIL,
    EXIT_OFFLINE_OK,
    EXIT_OFFLINE_REVIEW,
    EXIT_USAGE_ERROR,
    verify_path,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")


def _write_valid_bundle(root: Path, *, envelope: bool = True) -> None:
    root.mkdir(parents=True, exist_ok=True)
    canonical_input = {"asset_id": "asset-1", "external_mark": 100, "currency": "EUR"}
    input_keys = ("asset_id", "external_mark", "currency")
    ih = "sha256:" + canonical_input_hash(canonical_input, input_keys)
    p1 = {"s": "p1", "v": 1, "ik": list(input_keys), "ih": ih}
    _write_json(root / "canonical_input.json", canonical_input)
    _write_json(root / "p1.json", p1)
    p1_sha, _size = canonical_p1_sha256(p1)
    (root / "p1.sha256").write_text(p1_sha, encoding="utf-8")
    manifest = {
        "bundle_id": root.name,
        "schema_version": "loquitur.bundle.v1",
        "nonce": "c1" * 32,
        "files": {
            "canonical_input.json": "sha256:" + file_sha256(root / "canonical_input.json"),
            "p1.json": "sha256:" + file_sha256(root / "p1.json"),
            "p1.sha256": "sha256:" + file_sha256(root / "p1.sha256"),
        },
    }
    _write_json(root / "manifest.json", manifest)
    manifest_sha = canonical_json_sha256(manifest)
    (root / "manifest.sha256").write_text(manifest_sha, encoding="utf-8")
    if envelope:
        env = {
            "s": "env1",
            "v": 1,
            "bundle_id": root.name,
            "bundle_manifest_sha256": "sha256:" + manifest_sha,
            "p1_sha256": "sha256:" + p1_sha,
            "registry_entry": None,
        }
        _write_json(root / "envelope_env1.json", env)
        (root / "envelope.sha256").write_text(canonical_json_sha256(env), encoding="utf-8")


def _zip_dir(source_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir.parent).as_posix())


def test_runner_returns_offline_ok_for_valid_directory_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)

    report = verify_path(bundle)

    assert report.status == "OFFLINE_OK"
    assert report.verdict == "PASS"
    assert report.exit_code == EXIT_OFFLINE_OK
    payload = report.to_dict()
    assert payload["checks"]["manifest_sha256"] is True
    assert payload["checks"]["manifest_files"] is True
    assert payload["checks"]["p1_input_hash"] is True
    assert payload["checks"]["envelope_links"] is True
    assert payload["registry"]["status"] == "REGISTRY_ENTRY_NOT_PROVIDED"


def test_runner_returns_offline_ok_for_valid_zip_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)
    archive = tmp_path / "bundle.zip"
    _zip_dir(bundle, archive)

    report = verify_path(archive)

    assert report.status == "OFFLINE_OK"
    assert report.input_type == "zip"
    assert report.exit_code == EXIT_OFFLINE_OK


def test_cli_json_output_contract_and_exit_zero_for_ok_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)

    exit_code = main([str(bundle), "--json"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OFFLINE_OK
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["tool"] == "loquitur-verify"
    assert payload["checks_requested"] == payload["checks_established"] == ["structure", "integrity"]
    assert (payload["review_reasons"], payload["evaluation_time"]) == ([], None)
    assert payload["status"] == "OFFLINE_OK"
    assert payload["verdict"] == "PASS"
    assert payload["checks"]["registry_signature"] == "UNSUPPORTED"


def test_cli_pretty_output_contract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)

    exit_code = main([str(bundle), "--pretty"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OFFLINE_OK
    assert captured.err == ""
    assert "Loquitur offline verification: OFFLINE_OK / PASS" in captured.out
    assert "registry: REGISTRY_ENTRY_NOT_PROVIDED" in captured.out


def test_cli_review_exit_code_for_missing_canonical_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle, envelope=False)
    (bundle / "canonical_input.json").unlink()
    # Keep manifest hash internally consistent for this branch: the REVIEW must
    # come from missing canonical input semantics, not manifest failure.
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"].pop("canonical_input.json")
    _write_json(bundle / "manifest.json", manifest)
    (bundle / "manifest.sha256").write_text(canonical_json_sha256(manifest), encoding="utf-8")

    exit_code = main([str(bundle), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OFFLINE_REVIEW
    assert payload["status"] == "OFFLINE_REVIEW"
    assert payload["verdict"] == "REVIEW"
    assert "canonical_input_not_provided" in payload["notes"]


def test_cli_accept_review_accepts_only_the_reasons_it_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # report-contract.md section 4: exit 0 only when every review reason of the run is named;
    # the report is unchanged either way.
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle, envelope=False)

    accepted = main([str(bundle), "--json", "--accept-review", "envelope_not_provided"])
    accepted_payload = json.loads(capsys.readouterr().out)
    other = main([str(bundle), "--json", "--accept-review", "bundle_extra_files"])
    other_payload = json.loads(capsys.readouterr().out)

    assert accepted_payload == other_payload
    assert (accepted_payload["status"], accepted_payload["exit_code"]) == ("OFFLINE_REVIEW", EXIT_OFFLINE_REVIEW)
    assert accepted_payload["review_reasons"] == ["envelope_not_provided"]
    assert (accepted, other) == (EXIT_OFFLINE_OK, EXIT_OFFLINE_REVIEW)


def test_cli_accept_review_needs_every_reason_of_the_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Two review reasons: accepting one of them leaves the run at exit 2, accepting both gives 0.
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle, envelope=False)
    (bundle / "canonical_input.json").unlink()
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"].pop("canonical_input.json")
    _write_json(bundle / "manifest.json", manifest)
    (bundle / "manifest.sha256").write_text(canonical_json_sha256(manifest), encoding="utf-8")

    one = main([str(bundle), "--json", "--accept-review", "envelope_not_provided"])
    payload = json.loads(capsys.readouterr().out)
    both = main([str(bundle), "--json", "--accept-review", "envelope_not_provided,canonical_input_not_provided"])
    capsys.readouterr()

    assert payload["review_reasons"] == ["canonical_input_not_provided", "envelope_not_provided"]
    assert (one, both) == (EXIT_OFFLINE_REVIEW, EXIT_OFFLINE_OK)


def test_cli_fail_exit_code_for_tampered_bundle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)
    canonical_input = json.loads((bundle / "canonical_input.json").read_text(encoding="utf-8"))
    canonical_input["external_mark"] = 999
    _write_json(bundle / "canonical_input.json", canonical_input)

    exit_code = main([str(bundle), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OFFLINE_FAIL
    assert payload["status"] == "OFFLINE_FAIL"
    assert payload["verdict"] == "FAIL"


def test_cli_usage_errors_use_ex_usage_not_review_code(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([])

    captured = capsys.readouterr()
    assert exc_info.value.code == EXIT_USAGE_ERROR
    assert captured.out == ""
    assert "the following arguments are required: bundle" in captured.err


def test_cli_refuses_an_empty_evaluation_time(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """An unset CI variable must not read as a run without an evaluation time.

    An empty value that skipped the option would leave authorization not established, a REVIEW
    the operator did not ask for and could mistake for the run with the time. No report at all
    is the only answer that cannot be mistaken for the one the operator asked for.
    """
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)

    with pytest.raises(SystemExit) as exc_info:
        main([str(bundle), "--evaluation-time", "", "--json"])

    captured = capsys.readouterr()
    assert exc_info.value.code == EXIT_USAGE_ERROR
    assert captured.out == ""
    assert "--evaluation-time was given an empty value" in captured.err


@pytest.mark.parametrize("flag", ["--attested-time", "--tsa-token", "--review-zero"])
def test_cli_removed_options_are_unknown(tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str) -> None:
    # report-contract.md section 4.1: options this version does not define, removed with the
    # issuer's clock, the time-stamp token and the blanket REVIEW opt-in.
    bundle = tmp_path / "bundle-a"
    _write_valid_bundle(bundle)
    arguments = [str(bundle), flag] if flag == "--review-zero" else [str(bundle), flag, "2026-05-10T00:00:00Z"]

    with pytest.raises(SystemExit) as exc_info:
        main([*arguments, "--json"])

    captured = capsys.readouterr()
    assert exc_info.value.code == EXIT_USAGE_ERROR
    assert captured.out == ""
    assert "unrecognized arguments" in captured.err
