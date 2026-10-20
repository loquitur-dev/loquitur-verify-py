"""The verification report, held to loquitur-protocol docs/specification/report-contract.md.

The report contract states which members of a report are normative and their exact values: the
status, verdict and exit code (section 3), the process exit codes (section 4), the rules that
derive ``outcome.reason`` (section 5.2), the error codes in their order of emission (section 5.3),
and the eleven informative per-check results (section 6). Each table is read from the sibling
checkout (spec_tables.py) and every row is produced by a run: a bundle built for it, the CLI, or,
for a condition only the host can cause (a read that fails, a directory that cannot be listed),
the component raising what the host would make it raise.

The rules of section 5.2 are held by a model of their conditions: every run, built for one rule or
for several that hold together, must report the first rule the table lists among those it meets,
and every two neighboring rules lead some run or cannot hold together. The set of error codes
this package can emit, read from its source, must be exactly the table's.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import EVALUATION_TIME, IssuerKey, authorization_material, run_authorization, write_json
from bundle_builder import Bundle, jcs, sha
from spec_tables import code, codes, document, table

import loquitur.verify.runner as runner
from loquitur.verify.archive import ArchiveLoadError
from loquitur.verify.cli import main
from loquitur.verify.host_path import host_path
from loquitur.verify.members import BundleInventory, BundleInventoryError
from loquitur.verify.runner import OfflineVerificationReport, exit_code_for_status, verify_path
from loquitur.verify.trust_root import DOCUMENT_READ_FAILED, parse_trust_roots, trust_registry_signing_bytes

SPEC = "report-contract.md"
SOURCE = Path(runner.__file__).parent
# The null device, as a path names it (section 5.3): on Windows a path is read in the file
# namespace, where os.devnull ("nul") is an ordinary name and the device is "\\.\nul".
NULL_DEVICE = "\\\\.\\nul" if sys.platform == "win32" else os.devnull


# ---- bundles and runs --------------------------------------------------------------------------


def _dir(path: Path, change: Callable[[Bundle], Any] | None = None, *, seal: dict[str, bool] | None = None) -> Path:
    bundle = Bundle()
    if change is not None:
        change(bundle)
    bundle.seal(**(seal or {}))
    return bundle.write(path / "bundle")


def _undeclare_canonical_input(bundle: Bundle) -> None:
    bundle.edit("manifest.json", lambda m: m["files"].pop("canonical_input.json"))
    del bundle.members["canonical_input.json"]


def _drop_envelope(bundle: Bundle) -> None:
    del bundle.members["envelope_env1.json"]
    del bundle.members["envelope.sha256"]


def _report(path: Path, **kwargs: Any) -> dict[str, Any]:
    return verify_path(path, **kwargs).to_dict()


def _after_sealing(path: Path, change: Callable[[Bundle], Any], before: Callable[[Bundle], Any] | None = None) -> Path:
    bundle = Bundle()
    if before is not None:
        before(bundle)
    bundle.seal()
    change(bundle)
    return bundle.write(path / "bundle")


def _link_run(path: Path, *, entry: dict[str, Any] | None = None, receipt: Callable | None = None, change=None) -> dict:
    bundle = Bundle()
    if receipt is not None:
        bundle.edit("verification_receipt.json", receipt)
    if change is not None:
        change(bundle)
    bundle.seal()
    root = bundle.write(path / "bundle")
    return _report(root, registry_entry_path=bundle.link_entry(path / "entry.json", **(entry or {})))


def _grounded_warn(path: Path, change=None) -> dict[str, Any]:
    codes_ = ["INTEGRITY_OK", "FRESHNESS_WARNING"]
    return _link_run(
        path,
        entry={"verdict": "WARN", "reason_codes": codes_},
        receipt=lambda r: r.update(status="warning", reason_codes=codes_),
        change=change,
    )


def _signed_by_root(key: IssuerKey, root: IssuerKey) -> tuple[dict, dict, tuple]:
    entry, registry = authorization_material(key)
    registry["signature"]["key_id"] = "root-1"
    registry["signature"]["signature"] = root.sign_digest(
        hashlib.sha256(trust_registry_signing_bytes(registry)).digest()
    )
    roots = parse_trust_roots(
        {
            "object_type": "trust_root_document",
            "schema_version": "v1",
            "roots": [
                {
                    "key_id": "root-1",
                    "key_type": "secp256k1",
                    "public_key_hex": root.public_key_hex,
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2027-01-01T00:00:00Z",
                }
            ],
        }
    )
    return entry, registry, roots


def _zip_with_peer(path: Path, change: Callable[[Bundle], Any] | None = None) -> Path:
    source = _dir(path / "src", change)
    archive = path / "container.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for member in sorted(source.rglob("*")):
            if member.is_file():
                handle.write(member, "bundle/" + member.relative_to(source).as_posix())
        handle.writestr("beside-the-bundle.txt", b"delivered, never committed")
    return archive


def _synthetic(status: str) -> dict[str, Any]:
    return OfflineVerificationReport(
        status=status, verdict="X", input_path="x", input_type=None, bundle_root_name=None
    ).to_dict()


def _key() -> IssuerKey:
    return IssuerKey()


# ---- section 3 ----------------------------------------------------------------------------------


def test_status_verdict_and_exit_code_move_together(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["`status`", "`verdict`", "`exit_code`", "class", "meaning"])

    def verdict_cell(cell: str) -> str | None:
        return None if code(cell) == "null" else code(cell)

    specified = {code(row["`status`"]): (verdict_cell(row["`verdict`"]), int(code(row["`exit_code`"]))) for row in rows}
    classes = {code(row["`status`"]): row["class"] for row in rows}
    assert set(specified) == {
        "OFFLINE_OK",
        "OFFLINE_FAIL",
        "OFFLINE_REVIEW",
        "INTERNAL_ERROR",
        "UNSUPPORTED_VERSION",
        "HOST_FAILURE",
    }
    # A status carries a verdict exactly when its class is evidence.
    assert {status: verdict is not None for status, (verdict, _) in specified.items()} == {
        status: cls == "evidence" for status, cls in classes.items()
    }
    for status, (verdict, exit_code) in specified.items():
        assert exit_code_for_status(status) == exit_code, status
        assert runner._verdict_for_status(status) == verdict, status
    runs = {
        "UNSUPPORTED_VERSION": _report(
            _dir(
                tmp_path / "unsupported",
                lambda b: b.edit("manifest.json", lambda m: m.update(schema_version="loquitur.bundle.v2")),
            )
        ),
        "HOST_FAILURE": _report(tmp_path / "nothing-here"),
        "OFFLINE_OK": _report(_dir(tmp_path / "ok")),
        "OFFLINE_FAIL": _report(
            _after_sealing(tmp_path / "fail", lambda b: b.members.update({"manifest.sha256": b"0" * 64}))
        ),
        "OFFLINE_REVIEW": _report(_dir(tmp_path / "review", _undeclare_canonical_input)),
    }
    for status, report in runs.items():
        assert (report["status"], report["verdict"], report["exit_code"]) == (status, *specified[status])
    internal = runner.internal_error_report("x", RuntimeError("boom")).to_dict()
    assert (internal["status"], internal["verdict"], internal["exit_code"]) == (
        "INTERNAL_ERROR",
        *specified["INTERNAL_ERROR"],
    )
    assert [error["code"] for error in internal["errors"]] == ["internal_error"]


# ---- section 4 ----------------------------------------------------------------------------------


def _cli(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code_ = main(argv)
        except SystemExit as exc:  # argparse errors exit through the parser
            code_ = int(exc.code)
    return code_, out.getvalue()


def test_the_process_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = table(document(SPEC), ["process exit", "meaning", "report"])
    assert [codes(row["process exit"]) for row in rows] == [["0", "1", "2"], ["3"], ["4"], ["5"], ["64"]]
    bundle = _dir(tmp_path / "b")
    key = _key()
    entry, registry = authorization_material(key)
    entry_path, registry_path = write_json(tmp_path / "e.json", entry), write_json(tmp_path / "t.json", registry)
    bad_root = tmp_path / "root.json"
    bad_root.write_text(json.dumps({"roots": []}), encoding="utf-8")
    usage = {
        "no-bundle": [],
        "trust-registry-without-entry": [str(bundle), "--trust-registry", str(registry_path)],
        "instant-without-trust-registry": [str(bundle), "--evaluation-time", "2026-05-10T00:00:00Z"],
        "removed-token-option": [
            str(bundle),
            "--registry-entry",
            str(entry_path),
            "--trust-registry",
            str(registry_path),
            "--evaluation-time",
            "2026-05-10T00:00:00Z",
            "--tsa-token",
            str(bad_root),
        ],
        "empty-instant": [
            str(bundle),
            "--registry-entry",
            str(entry_path),
            "--trust-registry",
            str(registry_path),
            "--evaluation-time",
            "",
        ],
        "not-a-calendar-instant": [
            str(bundle),
            "--registry-entry",
            str(entry_path),
            "--trust-registry",
            str(registry_path),
            "--evaluation-time",
            "2026-02-30T00:00:00Z",
        ],
        "roots-without-trust-registry": [str(bundle), "--trust-root", str(bad_root)],
        "malformed-roots": [
            str(bundle),
            "--registry-entry",
            str(entry_path),
            "--trust-registry",
            str(registry_path),
            "--trust-root",
            str(bad_root),
        ],
    }
    got = {label: _cli(argv) for label, argv in usage.items()}
    assert got == {label: (64, "") for label in usage}

    authorization_files = [
        str(bundle),
        "--json",
        "--registry-entry",
        str(entry_path),
        "--trust-registry",
        str(registry_path),
    ]
    exit_default, out_default = _cli(authorization_files)
    assert json.loads(out_default)["review_reasons"] == [
        "evaluation_time_not_provided",
        "trust_registry_root_not_pinned",
    ]
    exit_other, out_other = _cli([*authorization_files, "--accept-review", "trust_registry_root_not_pinned"])
    exit_zero, out_zero = _cli(
        [*authorization_files, "--accept-review", "evaluation_time_not_provided,trust_registry_root_not_pinned"]
    )
    assert exit_default == 2 and json.loads(out_default)["exit_code"] == 2
    assert exit_other == 2 and json.loads(out_other)["exit_code"] == 2
    assert (
        exit_zero == 0 and json.loads(out_zero)["status"] == "OFFLINE_REVIEW" and json.loads(out_zero)["exit_code"] == 2
    )
    # Exit 4 and exit 5, each with its report, and never changed by --accept-review.
    unsupported = _dir(
        tmp_path / "v2", lambda b: b.edit("manifest.json", lambda m: m.update(schema_version="loquitur.bundle.v2"))
    )
    every_reason = "evaluation_time_not_provided,verification_receipt_not_provided"
    for argv, expected in (
        ([str(unsupported), "--json"], (4, "UNSUPPORTED_VERSION")),
        ([str(tmp_path / "absent"), "--json"], (5, "HOST_FAILURE")),
        ([str(tmp_path / "absent"), "--json", "--accept-review", every_reason], (5, "HOST_FAILURE")),
    ):
        exit_, out = _cli(argv)
        report_ = json.loads(out)
        assert (exit_, report_["status"], report_["exit_code"], report_["verdict"]) == (
            *expected[:1],
            expected[1],
            expected[0],
            None,
        )

    def fault(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("a defect of the tool")

    monkeypatch.setattr("loquitur.verify.cli.verify_path", fault)
    exit_fault, out_fault = _cli([str(bundle), "--json"])
    report = json.loads(out_fault)
    assert (exit_fault, report["status"], report["verdict"], report["exit_code"]) == (3, "INTERNAL_ERROR", None, 3)
    assert [error["code"] for error in report["errors"]] == ["internal_error"]


# ---- section 5.2 --------------------------------------------------------------------------------
#
# Each rule of the table is a condition on the run. A model of those conditions, written from the
# table and read off the report's other members and the run's inputs, says which rules a run
# meets; the run must report the value of the first rule the table lists among them. Every run is
# declared with the rules it was built to meet, which must be among those the model finds. A rule
# moved in the table therefore changes what some run must report, and every two neighboring rules
# lead some run or are listed with the reason they cannot hold together.


@dataclass(frozen=True)
class ReasonRun:
    report: dict[str, Any]
    built_for: frozenset[str]
    entry: bool = False  # a registry entry was supplied
    committed: str | None = None  # the verdict an entry that satisfies its contract commits
    roots: bool = False  # trust roots were supplied
    # The review reasons an OFFLINE_REVIEW run was built to hold, in the order of section 3.3.
    reasons: tuple[str, ...] = ()
    # False for a report made without reading a bundle, standing for a run whose layers report nothing:
    # its per-check results are defaults, not observations, and meet no layer's condition.
    bundle_read: bool = True


def _reason_rows() -> dict[str, str]:
    rows = table(document(SPEC), ["#", "the run", "`outcome.reason`"])
    return {row["#"]: row["`outcome.reason`"] for row in rows}


def _window_statuses() -> set[str]:
    """The authorization statuses whose effect is REVIEW: section 3.3, the rows of the two windows."""
    rows = table(document(SPEC), ["#", "review reason", "holds when"])
    reasons = {code(row["review reason"]): row["holds when"] for row in rows}
    found = {
        status
        for reason in ("trust_registry_not_current", "issuer_key_outside_validity_window")
        for status in codes(reasons[reason])
    }
    assert len(found) == 4, found
    return found


def _trust_failed(report: dict[str, Any]) -> bool:
    """The trust registry was evaluated and stopped at a row whose effect is a failure."""
    trust = report["trust_registry"]
    if trust is None or report["checks"]["trust_registry"] is not False:
        return False
    stopped_at_window = trust["signature_status"] is None and trust["authorization_status"] in _window_statuses()
    return not stopped_at_window


def _rules_met(run: ReasonRun) -> set[str]:
    """The rules of section 5.2 whose condition the run meets."""
    report = run.report
    status, checks = report["status"], report["checks"]
    trust_evaluated = report["trust_registry"] is not None
    review = status == "OFFLINE_REVIEW"
    failed = status == "OFFLINE_FAIL"
    read = run.bundle_read
    manifest, p1, envelope = report["manifest"], report["p1"], report["envelope"]
    conditions = {
        "1": bool(report["errors"]),
        "2": status == "OFFLINE_OK" and trust_evaluated,
        "3": status == "OFFLINE_OK" and run.entry,
        "4": status == "OFFLINE_OK",
        # A trust registry that stopped at a REVIEW row (a window outside the evaluation time) did
        # not fail; nor did a link that is not established because the bundle carries no receipt.
        "5": _trust_failed(report),
        "6": run.entry and checks["registry_link"] is False,
        "7": review,
        # A manifest refused at load fails its layer as surely as one whose sidecar does not match.
        "8": failed and read and (not manifest["ok"] if manifest is not None else checks["manifest_sha256"] is False),
        "9": failed and read and p1 is not None and p1["status"] == "OFFLINE_FAIL",
        "10": failed and read and envelope is not None and envelope["status"] == "OFFLINE_FAIL",
        "11": True,
    }
    return {rule for rule, holds in conditions.items() if holds}


def _expected_reason(run: ReasonRun, rows: dict[str, str]) -> str:
    listed = list(rows)
    rule = min(_rules_met(run), key=listed.index)
    if rule == "1":
        assert rows["1"] == "the `code` of its first error"
        return run.report["errors"][0]["code"]
    if rule == "7":
        assert rows["7"] == "the first entry of `review_reasons`"
        # The run's declared reasons, not the report's: the report must hold what it was built for.
        assert run.reasons, "a run built for rule 7 declares its review reasons"
        return run.reasons[0]
    return code(rows[rule])


def _authorization_over(
    path: Path,
    key: IssuerKey,
    *,
    before: Callable[[Bundle], Any] | None = None,
    after: Callable[[Bundle], Any] | None = None,
    trust: Callable[[dict[str, Any]], Any] | None = None,
    entry: Callable[[dict[str, Any]], Any] | None = None,
    receipt: Callable[[dict[str, Any]], Any] | None = None,
    container: bool = False,
) -> dict[str, Any]:
    """An authorization run over the fixture bundle changed as given, the entry bound to it and signed again.

    ``container`` delivers the bundle inside a ZIP archive with a file beside its root.
    """
    bundle = Bundle()
    if receipt is not None:
        bundle.edit("verification_receipt.json", receipt)
    if before is not None:
        before(bundle)
    bundle.seal()
    bound = {
        "manifest_hash": "sha256:" + bundle.manifest_digest(),
        "receipt_hash": "sha256:" + sha(jcs(bundle.json("verification_receipt.json"))),
    }
    if after is not None:
        after(bundle)
    document_, registry = authorization_material(
        key, entry=lambda e: (e.update(bound), entry(e) if entry is not None else None), trust=trust
    )
    root = bundle.write(path / "bundle")
    if container:
        archive = path / "container.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for member in sorted(root.rglob("*")):
                if member.is_file():
                    handle.write(member, "bundle/" + member.relative_to(root).as_posix())
            handle.writestr("beside-the-bundle.txt", b"delivered, never committed")
        root = archive
    return _report(
        root,
        registry_entry_path=write_json(path / "e.json", document_),
        trust_registry_path=write_json(path / "t.json", registry),
        evaluation_time=EVALUATION_TIME,
    )


WARN_CODES = ["INTEGRITY_OK", "FRESHNESS_WARNING"]
FAIL_CODES = ["INTEGRITY_OK", "INTEGRITY_OFFLINE_FAIL"]


def _warned(entry: dict[str, Any]) -> None:
    entry.update(verdict="WARN", reason_codes=list(WARN_CODES))


def _warning_receipt(receipt: dict[str, Any]) -> None:
    receipt.update(status="warning", reason_codes=list(WARN_CODES))


def _reason_runs(tmp_path: Path) -> dict[str, ReasonRun]:
    """Runs built for each rule alone, and for rules that hold together."""
    key, root = _key(), _key()
    signed_entry, signed_registry, roots = _signed_by_root(key, root)
    revoked = lambda t: t["entries"][0].update(status="revoked", revoked_at="2026-05-01T00:00:00Z")  # noqa: E731
    revoked_entry, revoked_registry = authorization_material(key, trust=revoked)
    plain_entry, plain_registry = authorization_material(key)
    wrong_manifest_sidecar = lambda b: b.members.update({"manifest.sha256": b"0" * 64})  # noqa: E731
    wrong_p1 = lambda b: b.members.update({"p1.sha256": b"0" * 64})  # noqa: E731
    undeclared = lambda b: b.members.update({"undeclared.txt": b"x"})  # noqa: E731

    expired_key = lambda t: t["entries"][0].update(expires_at="2026-05-05T00:00:00Z")  # noqa: E731
    expired_entry, expired_registry = authorization_material(key, trust=expired_key)

    link_fails = Bundle()
    link_fails.edit("verification_receipt.json", lambda r: r.update(policy_id="loquitur.policy.other"))
    link_fails.seal()
    link_entry = link_fails.link_entry(tmp_path / "6+8" / "entry.json")
    wrong_manifest_sidecar(link_fails)

    no_receipt = Bundle()
    no_receipt.seal()
    no_receipt_entry = no_receipt.link_entry(tmp_path / "7-no-receipt" / "entry.json")
    del no_receipt.members["verification_receipt.json"]
    no_receipt.edit("manifest.json", lambda m: m["files"].pop("verification_receipt.json", None))
    no_receipt.seal()

    def run(label: str, built_for: str, report: dict[str, Any], *reasons: str, **context: Any) -> tuple[str, ReasonRun]:
        return label, ReasonRun(report=report, built_for=frozenset(built_for.split("+")), reasons=reasons, **context)

    not_pinned = "trust_registry_root_not_pinned"
    runs = [
        run("1", "1", _report(_after_sealing(tmp_path / "1", lambda b: b.members.update({"manifest.json": b"{"})))),
        run(
            "2+3+4",
            "2+3+4",
            run_authorization(tmp_path / "2", signed_entry, signed_registry, trust_roots=roots),
            entry=True,
            committed="PASS",
            roots=True,
        ),
        run("3+4", "3+4", _link_run(tmp_path / "3"), entry=True, committed="PASS"),
        run("4", "4", _report(_dir(tmp_path / "4"))),
        run("5", "5", run_authorization(tmp_path / "5", revoked_entry, revoked_registry), entry=True, committed="PASS"),
        run(
            "6",
            "6",
            _link_run(tmp_path / "6", receipt=lambda r: r.update(policy_id="loquitur.policy.other")),
            entry=True,
            committed="PASS",
        ),
        # Rule 7, one run per review reason a run can hold alone, and runs holding several.
        run(
            "7-entry-warn",
            "7",
            _grounded_warn(tmp_path / "7"),
            "registry_entry_verdict_requires_review",
            entry=True,
            committed="WARN",
        ),
        run(
            "7-no-receipt",
            "7",
            _report(no_receipt.write(tmp_path / "7-no-receipt" / "bundle"), registry_entry_path=no_receipt_entry),
            "verification_receipt_not_provided",
            entry=True,
            committed="PASS",
        ),
        run(
            "7-no-evaluation-time",
            "7",
            run_authorization(tmp_path / "7-no-time", plain_entry, plain_registry, evaluation_time=None),
            "evaluation_time_not_provided",
            not_pinned,
            entry=True,
            committed="PASS",
        ),
        run(
            "7-key-window",
            "7",
            run_authorization(tmp_path / "7-key-window", expired_entry, expired_registry),
            "issuer_key_outside_validity_window",
            entry=True,
            committed="PASS",
        ),
        run(
            "7-root-not-pinned",
            "7",
            run_authorization(tmp_path / "8", plain_entry, plain_registry),
            not_pinned,
            entry=True,
            committed="PASS",
        ),
        run("7-container-extra", "7", _report(_zip_with_peer(tmp_path / "9")), "container_extra_files"),
        run("7-bundle-extra", "7", _report(_dir(tmp_path / "10", undeclared)), "bundle_extra_files"),
        run(
            "7-canonical-input",
            "7",
            _report(_dir(tmp_path / "11", _undeclare_canonical_input)),
            "canonical_input_not_provided",
        ),
        run("7-envelope", "7", _report(_dir(tmp_path / "12", _drop_envelope)), "envelope_not_provided"),
        run("8", "8", _report(_after_sealing(tmp_path / "14", wrong_manifest_sidecar))),
        # The P1 sidecar is wrong and the manifest declares the wrong bytes: P1 fails, and so does the
        # envelope's link to it.
        run("9+10", "9+10", _report(_dir(tmp_path / "15", wrong_p1, seal={"p1": False}))),
        run(
            "10+11",
            "10+11",
            _report(_after_sealing(tmp_path / "16", lambda b: b.members.update({"envelope.sha256": b"0" * 64}))),
        ),
        run("11", "11", _synthetic("OFFLINE_FAIL"), bundle_read=False),
        # Rules that hold together.
        run(
            "1+5",
            "1+5",
            _authorization_over(
                tmp_path / "1+5",
                key,
                receipt=lambda r: r.update(status="fail", reason_codes=list(FAIL_CODES)),
                entry=lambda e: e.update(verdict="FAIL", reason_codes=list(FAIL_CODES)),
                trust=revoked,
            ),
            entry=True,
            committed="FAIL",
        ),
        run(
            "1+6",
            "1+6",
            _link_run(tmp_path / "1+6", receipt=lambda r: r.update(smuggled=1)),
            entry=True,
            committed="PASS",
        ),
        run(
            "1+8",
            "1+8",
            _report(_after_sealing(tmp_path / "1+14", lambda b: b.members.update({"manifest.json": b"{"}))),
        ),
        run(
            "5+8",
            "5+8",
            _authorization_over(tmp_path / "5+14", key, after=wrong_manifest_sidecar, trust=revoked),
            entry=True,
            committed="PASS",
        ),
        run(
            "6+8",
            "6+8",
            _report(link_fails.write(tmp_path / "6+8" / "bundle"), registry_entry_path=link_entry),
            entry=True,
            committed="PASS",
        ),
        run(
            "7-warn-not-pinned",
            "7",
            _authorization_over(tmp_path / "7+8", key, receipt=_warning_receipt, entry=_warned),
            "registry_entry_verdict_requires_review",
            not_pinned,
            entry=True,
            committed="WARN",
        ),
        run(
            "7-warn-bundle-extra",
            "7",
            _grounded_warn(tmp_path / "7+10", change=undeclared),
            "registry_entry_verdict_requires_review",
            "bundle_extra_files",
            entry=True,
            committed="WARN",
        ),
        run(
            "7-not-pinned-container",
            "7",
            _authorization_over(tmp_path / "8+9", key, container=True),
            not_pinned,
            "container_extra_files",
            entry=True,
            committed="PASS",
        ),
        run(
            "7-not-pinned-bundle-extra",
            "7",
            _authorization_over(tmp_path / "8+10", key, before=undeclared),
            not_pinned,
            "bundle_extra_files",
            entry=True,
            committed="PASS",
        ),
        run(
            "7-not-pinned-canonical-input",
            "7",
            _authorization_over(tmp_path / "8+11", key, before=_undeclare_canonical_input),
            not_pinned,
            "canonical_input_not_provided",
            entry=True,
            committed="PASS",
        ),
        run(
            "7-container-bundle-extra",
            "7",
            _report(_zip_with_peer(tmp_path / "9+10", undeclared)),
            "container_extra_files",
            "bundle_extra_files",
        ),
        run(
            "7-bundle-extra-canonical-input",
            "7",
            _report(_dir(tmp_path / "10+11", lambda b: (_undeclare_canonical_input(b), undeclared(b)))),
            "bundle_extra_files",
            "canonical_input_not_provided",
        ),
        run(
            "7-canonical-input-envelope",
            "7",
            _report(_dir(tmp_path / "11+12", lambda b: (_undeclare_canonical_input(b), _drop_envelope(b)))),
            "canonical_input_not_provided",
            "envelope_not_provided",
        ),
        run(
            "8+9",
            "8+9",
            _report(
                _after_sealing(
                    tmp_path / "14+15",
                    lambda b: b.members.update({"p1.sha256": b"0" * 64, "manifest.sha256": b"0" * 64}),
                )
            ),
        ),
    ]
    labelled: dict[str, ReasonRun] = {}
    for label, item in runs:
        assert label not in labelled, label
        labelled[label] = item
    return labelled


@pytest.fixture(scope="module")
def reason_runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, ReasonRun]:
    return _reason_runs(tmp_path_factory.mktemp("reasons"))


def test_every_run_reports_the_first_rule_it_meets(reason_runs: dict[str, ReasonRun]) -> None:
    """Section 5.2: the value of the first rule, in the table's order, whose condition the run meets."""
    rows = _reason_rows()
    assert set(rows) == {str(rule) for rule in range(1, 12)}
    # Every rule has a run built for it alone or among others, and every run meets what it was built for.
    assert set().union(*(run.built_for for run in reason_runs.values())) == set(rows)
    unmet = {label: sorted(run.built_for - _rules_met(run), key=int) for label, run in reason_runs.items()}
    assert not {label: rules for label, rules in unmet.items() if rules}, unmet
    got = {label: run.report["outcome"]["reason"] for label, run in reason_runs.items()}
    expected = {label: _expected_reason(run, rows) for label, run in reason_runs.items()}
    assert got == expected
    # Every OFFLINE_REVIEW run holds exactly the review reasons it was built for (section 3.3), and
    # every other run holds none.
    held = {label: tuple(run.report["review_reasons"]) for label, run in reason_runs.items()}
    assert held == {label: run.reasons for label, run in reason_runs.items()}
    reasons = {code(cell) for number, cell in rows.items() if number not in {"1", "7"}}
    assert len(reasons) == len(rows) - 2


# Neighboring rules whose conditions cannot hold together, so that no run can show which comes first.
EXCLUSIVE_RULES = {
    frozenset({"1", "2"}): "a run that carries an error is OFFLINE_FAIL (section 3)",
    frozenset({"4", "5"}): "a trust registry that does not hold makes the run OFFLINE_FAIL",
    frozenset({"5", "6"}): "the trust registry is evaluated only beside a link that holds",
    frozenset({"6", "7"}): "a link that does not hold makes the run OFFLINE_FAIL, and rule 7 needs OFFLINE_REVIEW",
    frozenset({"7", "8"}): "rule 7 needs OFFLINE_REVIEW, and rule 8 a failed manifest, which fails the run",
}


def test_every_two_neighbouring_rules_lead_a_run(reason_runs: dict[str, ReasonRun]) -> None:
    """Two neighboring rules are the first two a run meets, or cannot hold together.

    Swapping those two rules in the table changes what that run must report, and swapping any two
    rules exchanges at least one such neighboring pair.
    """
    listed = list(_reason_rows())
    decided = set()
    for run in reason_runs.values():
        leading = sorted(_rules_met(run), key=listed.index)[:2]
        if len(leading) == 2:
            decided.add(frozenset(leading))
    neighbours = {frozenset(pair) for pair in zip(listed, listed[1:], strict=False)}
    undecided = sorted((sorted(pair, key=int) for pair in neighbours - decided - set(EXCLUSIVE_RULES)), key=str)
    assert not undecided, f"neighbouring rules no run decides and no reason excludes: {undecided}"
    assert set(EXCLUSIVE_RULES) <= neighbours, "an exclusion names rules that are not neighbours"


def test_rules_9_and_10_name_only_a_layer_that_failed(tmp_path: Path) -> None:
    """Section 5.2: a layer that is only OFFLINE_REVIEW is not what failed the run.

    A run whose canonical input is absent and undeclared has a P1 layer in review. When its envelope
    fails, rule 9 does not name it: rule 10 does, because the envelope is the layer that failed.
    """
    text = " ".join(document(SPEC).split())
    assert "Each names a layer whose outcome is `OFFLINE_FAIL`, and never a layer that is only `OFFLINE_REVIEW`" in text
    rows = _reason_rows()
    runs = {
        "p1-in-review-envelope-fails": _report(
            _after_sealing(
                tmp_path / "a",
                lambda b: b.members.update({"envelope.sha256": b"0" * 64}),
                before=_undeclare_canonical_input,
            )
        ),
        "p1-fails-envelope-absent": _report(
            _dir(
                tmp_path / "b",
                lambda b: (b.members.update({"p1.sha256": b"0" * 64}), _drop_envelope(b)),
                seal={"p1": False},
            )
        ),
    }
    layers = {
        label: (report["status"], report["errors"], report["p1"]["status"], report["envelope"]["status"])
        for label, report in runs.items()
    }
    assert layers == {
        "p1-in-review-envelope-fails": ("OFFLINE_FAIL", [], "OFFLINE_REVIEW", "OFFLINE_FAIL"),
        "p1-fails-envelope-absent": ("OFFLINE_FAIL", [], "OFFLINE_FAIL", "OFFLINE_REVIEW"),
    }
    assert {label: report["outcome"]["reason"] for label, report in runs.items()} == {
        "p1-in-review-envelope-fails": code(rows["10"]),
        "p1-fails-envelope-absent": code(rows["9"]),
    }


# ---- section 5.3 --------------------------------------------------------------------------------


def _error_rows() -> list[str]:
    return [code(row["code"]) for row in table(document(SPEC), ["code", "class", "condition"])]


def _raise(exception: BaseException) -> Callable[..., Any]:
    def raising(*_args: Any, **_kwargs: Any) -> Any:
        raise exception

    return raising


def _zip(path: Path, members: dict[str, bytes], compression: int = zipfile.ZIP_STORED) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=compression) as handle:
        for name, data in members.items():
            handle.writestr(name, data)
    return path


def _receipt_unreadable(
    path: Path, monkeypatch: pytest.MonkeyPatch, run: Callable[[], dict[str, Any]]
) -> dict[str, Any]:
    """``run`` with the host refusing to read verification_receipt.json, and every other member read."""
    import loquitur.verify.registry_link as registry_link

    real = registry_link.read_member_bytes

    def refusing(bundle_root: Path, name: str, **kwargs: Any) -> bytes:
        if name == "verification_receipt.json":
            raise PermissionError(f"the host refuses {name}")
        return real(bundle_root, name, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(registry_link, "read_member_bytes", refusing)
        return run()


def test_a_host_failure_to_read_the_receipt_is_a_link_read_failure_at_every_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Section 5.3: the receipt is a document the link reads, whether or not a link is requested.

    A receipt the host cannot read is not a receipt that breaks its contract: reporting
    `verification_receipt_contract_violation`, and at the link check `registry_link_verification_failed` as
    well, would be two findings about a document nothing has established anything about. It is
    `registry_link_read_failed` at the structure, link and authorization checks, emitted once and alone: with a trust registry too
    it is not `trust_registry_requires_valid_registry_entry`, which names a fact about the entry or
    the receipt, and the run is `HOST_FAILURE`, exit 5. A host failure to read the registry entry's
    own file is the same error.
    """
    key = _key()
    entry, registry = authorization_material(key)
    root = _dir(tmp_path / "structure")
    at_structure = _receipt_unreadable(tmp_path, monkeypatch, lambda: _report(root))
    at_link = _receipt_unreadable(tmp_path, monkeypatch, lambda: _link_run(tmp_path / "link"))
    at_authorization = _receipt_unreadable(
        tmp_path,
        monkeypatch,
        lambda: _report(
            _dir(tmp_path / "authorization"),
            registry_entry_path=write_json(tmp_path / "authorization-entry.json", entry),
            trust_registry_path=write_json(tmp_path / "authorization-trust.json", registry),
        ),
    )
    got = {
        "structure": (
            [error["code"] for error in at_structure["errors"]],
            at_structure["outcome"]["reason"],
            at_structure["checks"]["registry_link"],
        ),
        "link": (
            [error["code"] for error in at_link["errors"]],
            at_link["outcome"]["reason"],
            at_link["checks"]["registry_link"],
        ),
        "authorization": (
            [error["code"] for error in at_authorization["errors"]],
            at_authorization["outcome"]["reason"],
            at_authorization["checks"]["registry_link"],
            at_authorization["trust_registry"],
        ),
    }
    # The informative `registry_link` check is null: the link reached no conclusion, as
    # loquitur-verify-ts reports it.
    assert got == {
        "structure": (["registry_link_read_failed"], "registry_link_read_failed", None),
        "link": (["registry_link_read_failed"], "registry_link_read_failed", None),
        "authorization": (["registry_link_read_failed"], "registry_link_read_failed", None, None),
    }
    for report in (at_structure, at_link, at_authorization):
        assert not [note for note in report["notes"] if note.startswith("verification_receipt_contract_violation")]
        assert (report["status"], report["verdict"], report["exit_code"]) == ("HOST_FAILURE", None, 5)

    entry_path = write_json(tmp_path / "entry-unreadable.json", entry)
    import loquitur.verify.registry_link as registry_link

    real_read_bytes = registry_link.read_file_bytes

    def refusing(path: Any) -> bytes:
        if Path(path) == Path(host_path(entry_path)):
            raise PermissionError("the host refuses the entry")
        return real_read_bytes(path)

    with monkeypatch.context() as patch:
        # Documents are read through read_file_bytes, which opens them with every share mode.
        patch.setattr(registry_link, "read_file_bytes", refusing)
        entry_unreadable = _report(_dir(tmp_path / "entry"), registry_entry_path=entry_path)
    assert [error["code"] for error in entry_unreadable["errors"]] == ["registry_link_read_failed"]
    assert entry_unreadable["status"] == "HOST_FAILURE"


def test_a_document_the_host_cannot_read_masks_no_other_condition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Section 5.3: a condition that holds is not masked by another that also holds.

    `registry_link_read_failed` is not one of the rows that refuse the input as a whole, so it
    hides nothing. A link layer whose read failure aborted the whole block would discard every
    error the link contributes: a supplied document that is not a registry entry at all, and an
    entry that satisfies its contract and commits FAIL, would be reported as a read failure
    alone. The codes come out in the table's order, not in the order the code reaches them,
    because `outcome.reason` is the first code (section 5.2, rule 1).

    Each row here is judged on inputs the unreadable document does not decide:
    `registry_link_verification_failed` holds on the entry alone, `registry_entry_verdict_fail`
    on an entry that satisfies its contract. The trust registry's row holds only on a fact about
    the entry or the receipt (the entry's path names no regular file, or a receipt that cannot be
    canonicalized), never on a read failure. A run whose only error is the read failure is
    `HOST_FAILURE`; one that also carries a content error is `OFFLINE_FAIL` (section 3.1).
    loquitur-verify-ts reports the same lists.
    """
    rows = _error_rows()
    text = " ".join(document(SPEC).split())
    assert "The rows from `input_not_found` to `filesystem_error` refuse the input as a whole" in text
    assert "A condition that holds is not masked by another that also holds, earlier in the table or not" in text
    key = _key()
    entry, registry = authorization_material(key)
    trust = write_json(tmp_path / "trust.json", registry)

    def with_entry(name: str, text: str) -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    def at_link(path: Path, entry_path: Path) -> dict[str, Any]:
        return _report(_dir(path), registry_entry_path=entry_path)

    def directory(name: str) -> Path:
        return _a_directory(tmp_path / name)

    def verdict_fail(path: Path) -> dict[str, Any]:
        codes_ = ["INTEGRITY_OK", "INTEGRITY_OFFLINE_FAIL"]
        return _link_run(
            path,
            entry={"verdict": "FAIL", "reason_codes": codes_},
            receipt=lambda r: r.update(status="fail", reason_codes=codes_),
        )

    runs = {
        # The entry is not a registry entry at all, and the receipt cannot be read.
        "entry-not-an-object": lambda: at_link(tmp_path / "a", with_entry("a-entry.json", "[1, 2]")),
        # The entry's path names a directory, no regular file: the same refusal, found before the
        # receipt.
        "entry-path-names-no-file": lambda: at_link(tmp_path / "b", directory("b-entry")),
        # An entry that satisfies its contract and commits FAIL: its row holds whatever the
        # receipt turns out to be, because the link was not refused.
        "entry-commits-fail": lambda: verdict_fail(tmp_path / "c"),
        # The entry is fine: the read failure is the only condition that holds.
        "entry-valid": lambda: _link_run(tmp_path / "d"),
        # At authorization the trust registry's own row does not hold: the entry's path names a file, and the
        # receipt was never read.
        "authorization-entry-not-an-object": lambda: _report(
            _dir(tmp_path / "e"),
            registry_entry_path=with_entry("e-entry.json", "[1, 2]"),
            trust_registry_path=trust,
        ),
        "authorization-entry-valid": lambda: _report(
            _dir(tmp_path / "f"),
            registry_entry_path=write_json(tmp_path / "f-entry.json", entry),
            trust_registry_path=trust,
        ),
    }
    runs["authorization-entry-path-names-no-file"] = lambda: _report(
        _dir(tmp_path / "h"), registry_entry_path=directory("h-entry"), trust_registry_path=trust
    )
    reports = {label: _receipt_unreadable(tmp_path, monkeypatch, run) for label, run in runs.items()}
    got = {label: [error["code"] for error in report["errors"]] for label, report in reports.items()}
    statuses = {label: report["status"] for label, report in reports.items()}
    assert statuses == {
        label: "HOST_FAILURE" if codes_ == ["registry_link_read_failed"] else "OFFLINE_FAIL"
        for label, codes_ in got.items()
    }
    assert got == {
        "entry-not-an-object": ["registry_link_verification_failed", "registry_link_read_failed"],
        "entry-path-names-no-file": ["registry_link_verification_failed", "registry_link_read_failed"],
        "entry-commits-fail": ["registry_entry_verdict_fail", "registry_link_read_failed"],
        "entry-valid": ["registry_link_read_failed"],
        "authorization-entry-not-an-object": ["registry_link_verification_failed", "registry_link_read_failed"],
        "authorization-entry-valid": ["registry_link_read_failed"],
        "authorization-entry-path-names-no-file": [
            "registry_link_verification_failed",
            "registry_link_read_failed",
            "trust_registry_requires_valid_registry_entry",
        ],
    }
    for label, codes_ in got.items():
        assert codes_ == sorted(codes_, key=rows.index), (label, codes_)

    # The entry's own file, refused by the host, while the bundle carries no receipt: a bundle
    # without a receipt is no refusal (it leaves the link not established), so the read failure on
    # the entry is the only error, and the run is HOST_FAILURE.
    no_receipt = _dir(tmp_path / "g", lambda b: b.members.pop("verification_receipt.json"))
    entry_path = write_json(tmp_path / "g-entry.json", entry)
    import loquitur.verify.registry_link as registry_link

    real_read_bytes = registry_link.read_file_bytes

    def refusing(path: Any) -> bytes:
        if Path(path) == Path(host_path(entry_path)):
            raise PermissionError("the host refuses the entry")
        return real_read_bytes(path)

    with monkeypatch.context() as patch:
        patch.setattr(registry_link, "read_file_bytes", refusing)
        both = _report(no_receipt, registry_entry_path=entry_path)
    assert [error["code"] for error in both["errors"]] == ["registry_link_read_failed"]
    # The link reached no conclusion, and says so rather than reporting false.
    assert both["checks"]["registry_link"] is None
    assert (both["outcome"]["reason"], both["status"]) == ("registry_link_read_failed", "HOST_FAILURE")


def test_the_error_codes_this_package_orders_by_are_the_table() -> None:
    """The order of emission is a property of the report, not of the code path that finds it.

    ``runner.ERROR_CODES`` is the table, cell for cell, and the report is projected onto it.
    """
    assert list(runner.ERROR_CODES) == _error_rows()
    scrambled = [{"code": "registry_link_read_failed"}, {"code": "registry_link_verification_failed"}]
    assert [error["code"] for error in runner._in_table_order(scrambled)] == [
        "registry_link_verification_failed",
        "registry_link_read_failed",
    ]
    # No code twice, and the first of a repeated code is the one kept.
    kept = runner._in_table_order([{"code": "p1_read_failed", "type": "first"}, {"code": "p1_read_failed"}])
    assert kept == ({"code": "p1_read_failed", "type": "first"},)


def _error_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Callable[[Path], dict[str, Any]]]:
    key = _key()
    plain_entry, plain_registry = authorization_material(key)
    other_root = _key()

    def host(target: str, exception: BaseException, run: Callable[[Path], dict[str, Any]]) -> Callable:
        def patched(path: Path) -> dict[str, Any]:
            with monkeypatch.context() as patch:
                patch.setattr(target, _raise(exception))
                return run(path)

        return patched

    def links(path: Path) -> dict[str, Any]:
        real = runner.bundle_inventory
        with monkeypatch.context() as patch:
            patch.setattr(
                runner, "bundle_inventory", lambda root: BundleInventory(files=real(root).files, links=("x",))
            )
            return _report(_dir(path))

    def unsupported(path: Path) -> dict[str, Any]:
        # The null device exists on every host and is neither a directory nor a regular file.
        return _report(Path(NULL_DEVICE))

    def trust_without_link(path: Path) -> dict[str, Any]:
        root = _dir(path)
        return _report(
            root,
            registry_entry_path=_a_directory(path / "entry-directory"),
            trust_registry_path=write_json(path / "t.json", plain_registry),
        )

    def root_not_authenticated(path: Path) -> dict[str, Any]:
        roots = parse_trust_roots(
            {
                "object_type": "trust_root_document",
                "schema_version": "v1",
                "roots": [
                    {
                        "key_id": "root-1",
                        "key_type": "secp256k1",
                        "public_key_hex": other_root.public_key_hex,
                        "not_before": "2026-01-01T00:00:00Z",
                        "not_after": "2027-01-01T00:00:00Z",
                    }
                ],
            }
        )
        return run_authorization(path, plain_entry, plain_registry, trust_roots=roots)

    def verdict_fail(path: Path) -> dict[str, Any]:
        codes_ = ["INTEGRITY_OK", "INTEGRITY_OFFLINE_FAIL"]
        return _link_run(
            path,
            entry={"verdict": "FAIL", "reason_codes": codes_},
            receipt=lambda r: r.update(status="fail", reason_codes=codes_),
        )

    def entry_text(text: str) -> Callable[[Path], dict[str, Any]]:
        def run(path: Path) -> dict[str, Any]:
            root = _dir(path)
            entry = path / "entry.json"
            entry.write_text(text, encoding="utf-8")
            return _report(root, registry_entry_path=entry)

        return run

    return {
        "input_not_found": lambda p: _report(p / "nothing-here"),
        "invalid_zip": lambda p: _report(_write(p / "not.zip", b"not a zip")),
        "archive_unsafe_member": lambda p: _report(_zip(p / "unsafe.zip", {"../escaped.txt": b"x"})),
        "archive_safety_limit": lambda p: _report(_zip(p / "bzip.zip", {"manifest.json": b"{}"}, zipfile.ZIP_BZIP2)),
        "bundle_root_invalid": lambda p: _report(_mkdir(p / "empty")),
        "archive_load_failed": host(
            "loquitur.verify.runner.extracted_zip",
            ArchiveLoadError("zip_member_missing:x"),
            lambda p: _report(_zip(p / "ok.zip", {"manifest.json": b"{}"})),
        ),
        "unsupported_input": unsupported,
        "filesystem_error": host(
            "loquitur.verify.runner.os.listdir", PermissionError("denied"), lambda p: _report(_mkdir(p / "d"))
        ),
        "bundle_inventory_failed": host(
            "loquitur.verify.runner.bundle_inventory", BundleInventoryError("not listable"), lambda p: _report(_dir(p))
        ),
        "bundle_member_name_invalid": lambda p: _report(
            _dir(
                p,
                lambda b: (
                    b.members.update({" padded.txt": b"x"}),
                    b.edit("manifest.json", lambda m: m["files"].update({" padded.txt": ""})),
                ),
            )
        ),
        "unsafe_bundle_member": links,
        "manifest_verification_failed": lambda p: _report(
            _after_sealing(p, lambda b: b.members.update({"manifest.json": b"{"}))
        ),
        "manifest_read_failed": host(
            "loquitur.verify.runner.verify_manifest", PermissionError("denied"), lambda p: _report(_dir(p))
        ),
        "p1_verification_failed": lambda p: _report(
            _dir(p, lambda b: b.edit("p1.json", lambda x: x.update(smuggled=1)))
        ),
        "p1_read_failed": host(
            "loquitur.verify.runner.verify_p1", PermissionError("denied"), lambda p: _report(_dir(p))
        ),
        "envelope_verification_failed": lambda p: _report(
            _after_sealing(p, lambda b: b.members.update({"envelope_env1.json": b"{"}))
        ),
        "envelope_incomplete": lambda p: _report(_after_sealing(p, lambda b: b.members.pop("envelope.sha256"))),
        "envelope_read_failed": host(
            "loquitur.verify.runner.verify_envelope", PermissionError("denied"), lambda p: _report(_dir(p))
        ),
        "verification_receipt_contract_violation": lambda p: _report(
            _dir(p, lambda b: b.edit("verification_receipt.json", lambda r: r.update(smuggled=1)))
        ),
        "registry_link_verification_failed": entry_text("null"),
        "registry_entry_contract_violation": lambda p: _link_run(p, entry={"smuggled": 1}),
        "registry_entry_verdict_fail": verdict_fail,
        "registry_link_read_failed": lambda p: _receipt_unreadable(p, monkeypatch, lambda: _link_run(p)),
        "trust_registry_requires_registry_entry": lambda p: _report(
            _dir(p), trust_registry_path=write_json(p / "t.json", plain_registry)
        ),
        "trust_registry_requires_valid_registry_entry": trust_without_link,
        "trust_registry_read_failed": host(
            "loquitur.verify.runner.verify_registry_entry_trust",
            PermissionError("denied"),
            lambda p: run_authorization(p, plain_entry, plain_registry),
        ),
        "trust_root_read_failed": lambda p: run_authorization(
            p, plain_entry, plain_registry, trust_roots=DOCUMENT_READ_FAILED
        ),
        "trust_registry_root_not_authenticated": root_not_authenticated,
        "unsupported_version": lambda p: _report(
            _dir(p, lambda b: b.edit("manifest.json", lambda m: m.update(schema_version="loquitur.bundle.v2")))
        ),
        "internal_error": lambda p: runner.internal_error_report("x", RuntimeError("boom")).to_dict(),
    }


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


INPUT_REFUSALS = (
    "input_not_found",
    "invalid_zip",
    "archive_unsafe_member",
    "archive_safety_limit",
    "bundle_root_invalid",
    "archive_load_failed",
    "unsupported_input",
    "filesystem_error",
)


def test_every_error_code_and_its_condition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _error_rows()
    classes = {code(row["code"]): row["class"] for row in table(document(SPEC), ["code", "class", "condition"])}
    assert set(classes.values()) == {"content", "host", "not evidence"}
    runs = _error_runs(tmp_path, monkeypatch)
    assert rows == list(runs), "the error table and this test's runs must name the same codes in the same order"
    for code_, run in runs.items():
        report = run(tmp_path / code_)
        emitted = [error["code"] for error in report["errors"]]
        assert code_ in emitted, (code_, emitted)
        assert len(emitted) == len(set(emitted)), (code_, emitted)
        assert emitted == sorted(emitted, key=rows.index), (code_, emitted)
        if code_ in INPUT_REFUSALS or code_ in {"internal_error", "unsupported_version"}:
            assert emitted == [code_], (code_, emitted)
        # The status follows the row's class (section 3.1): content fails, host is HOST_FAILURE
        # when nothing else fails, and the two rows that are not evidence have their own status.
        expected_status = {
            "content": "OFFLINE_FAIL",
            "host": "HOST_FAILURE" if emitted == [code_] else "OFFLINE_FAIL",
            "not evidence": {"internal_error": "INTERNAL_ERROR", "unsupported_version": "UNSUPPORTED_VERSION"}.get(
                code_
            ),
        }[classes[code_]]
        assert report["status"] == expected_status, (code_, report["status"])
    # The rows that refuse the input as a whole are the table's first eight.
    assert tuple(rows[: len(INPUT_REFUSALS)]) == INPUT_REFUSALS


def test_a_verifier_with_archive_intake_refuses_a_regular_file_as_invalid_zip(tmp_path: Path) -> None:
    """Section 5.3: which of the first two rows holds is decided by the verifier's intake.

    This verifier reads ZIP archives, so a regular file that is not a readable one is
    ``invalid_zip``. The ``unsupported_input`` row covers an input of a kind the verifier does
    not read, which for this verifier is no regular file at all: a readable archive is read as
    the archive it is, and neither row holds for it.
    """
    text = document(SPEC)
    conditions = {code(row["code"]): row["condition"] for row in table(text, ["code", "class", "condition"])}
    assert "Archive intake is optional: a verifier **MAY** read directory bundles only" in " ".join(text.split())
    assert conditions["invalid_zip"].startswith("the verifier reads ZIP archives and"), conditions["invalid_zip"]
    assert (
        "is of a kind the verifier does not read (a verifier without archive intake given a regular file)"
        in (conditions["unsupported_input"])
    ), conditions["unsupported_input"]

    report = _report(_write(tmp_path / "not.zip", b"not a zip"))
    assert [
        report["status"],
        report["verdict"],
        report["exit_code"],
        report["outcome"]["reason"],
        [error["code"] for error in report["errors"]],
    ] == ["OFFLINE_FAIL", "FAIL", 1, "invalid_zip", ["invalid_zip"]]

    # A regular file this verifier does read: refused by neither of the two rows, and judged as
    # the archive it is.
    readable = _report(_zip(tmp_path / "empty.zip", {"note.txt": b"x"}))
    assert [error["code"] for error in readable["errors"]] == ["bundle_root_invalid"]


def _unreadable_entry_without_receipt(path: Path, registry: dict[str, Any]) -> dict[str, Any]:
    bundle = Bundle()
    del bundle.members["verification_receipt.json"]
    bundle.seal()
    root = bundle.write(path / "bundle")
    entry = path / "entry.json"
    entry.write_text("{not json", encoding="utf-8")
    return _report(root, registry_entry_path=entry, trust_registry_path=write_json(path / "t.json", registry))


def _a_directory(path: Path) -> Path:
    """A directory at ``path``: something found that is not a regular file (report-contract.md 5.3)."""
    path.mkdir(parents=True)
    return path


def _absent_entry_without_receipt(path: Path, registry: dict[str, Any]) -> dict[str, Any]:
    bundle = Bundle()
    del bundle.members["verification_receipt.json"]
    bundle.seal()
    root = bundle.write(path / "bundle")
    return _report(
        root,
        registry_entry_path=_a_directory(path / "entry-directory"),
        trust_registry_path=write_json(path / "t.json", registry),
    )


def test_errors_are_emitted_in_the_order_of_the_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _error_rows()
    key = _key()
    _entry, registry = authorization_material(key)

    def links_and_bad_manifest(path: Path) -> dict[str, Any]:
        real = runner.bundle_inventory
        root = _after_sealing(path, lambda b: b.members.update({"manifest.json": b"{"}))
        with monkeypatch.context() as patch:
            patch.setattr(runner, "bundle_inventory", lambda r: BundleInventory(files=real(r).files, links=("x",)))
            return _report(root)

    runs = {
        "links-then-manifest": links_and_bad_manifest(tmp_path / "a"),
        "manifest-then-p1": _report(
            _after_sealing(
                tmp_path / "b", lambda b: (b.members.pop("manifest.sha256"), b.members.update({"p1.json": b"{"}))
            )
        ),
        "p1-then-envelope": _report(
            _after_sealing(
                tmp_path / "c",
                lambda b: b.members.update({"p1.json": b"{", "envelope_env1.json": b"{"}),
            )
        ),
        "envelope-then-receipt": _report(
            _after_sealing(
                tmp_path / "d",
                lambda b: b.members.update({"envelope_env1.json": b"{"}),
                before=lambda b: b.edit("verification_receipt.json", lambda r: r.update(smuggled=1)),
            )
        ),
        "receipt-then-entry": _link_run(tmp_path / "e", entry={"smuggled": 1}, receipt=lambda r: r.update(smuggled=1)),
        "link-then-trust": _report(
            _dir(tmp_path / "f"),
            registry_entry_path=_a_directory(tmp_path / "f-entry"),
            trust_registry_path=write_json(tmp_path / "f" / "t.json", registry),
        ),
        # Section 5.3: each condition is judged on the inputs on its own. An entry path that names
        # a directory, no regular file, beside a bundle without a receipt: the link's row and the
        # trust registry's row both hold on the entry, not the first refusal alone.
        "absent-entry-without-receipt": _absent_entry_without_receipt(tmp_path / "h", registry),
        "receipt-then-trust-without-entry": _report(
            _dir(tmp_path / "g", lambda b: b.edit("verification_receipt.json", lambda r: r.update(smuggled=1))),
            trust_registry_path=write_json(tmp_path / "g" / "t.json", registry),
        ),
    }
    got = {label: [error["code"] for error in report["errors"]] for label, report in runs.items()}
    assert all(len(codes_) == 2 for codes_ in got.values()), got
    assert got["absent-entry-without-receipt"] == [
        "registry_link_verification_failed",
        "trust_registry_requires_valid_registry_entry",
    ]
    # An entry that is not strict JSON is refused for the entry alone: the trust registry's row
    # names the entry's path or the receipt, neither of which holds here.
    unreadable = _unreadable_entry_without_receipt(tmp_path / "i", registry)
    assert [error["code"] for error in unreadable["errors"]] == ["registry_link_verification_failed"]
    assert got == {label: sorted(codes_, key=rows.index) for label, codes_ in got.items()}


def test_the_error_vocabulary_is_what_this_package_can_emit() -> None:
    emitted: set[str] = set()
    for module in ("runner.py", "cli.py"):
        text = (SOURCE / module).read_text(encoding="utf-8")
        emitted |= set(re.findall(r'_error\(\s*"([a-z0-9_]+)"', text))
        emitted |= set(re.findall(r'"code":\s*"([a-z0-9_]+)"', text))
    archive_codes = re.search(
        r"def _archive_error_code\(.*?\n(?=def )", (SOURCE / "runner.py").read_text(encoding="utf-8"), re.S
    )
    assert archive_codes
    emitted |= set(re.findall(r'return "([a-z0-9_]+)"', archive_codes.group(0)))
    assert set(_error_rows()) == emitted
    rows = _reason_rows()
    reasons = {code(cell) for number, cell in rows.items() if number not in {"1", "7"}}
    assert len(reasons) == len(rows) - 2


# ---- sections 2, 5.4 and 6 ----------------------------------------------------------------------


def test_the_members_a_report_carries(tmp_path: Path) -> None:
    text = document(SPEC)
    section = text.split("## 6. The informative per-check results", 1)[1].split("\n## ", 1)[0]
    eleven = codes(section.split("results:", 1)[1].split(".", 1)[0])
    assert len(eleven) == 11
    report = _report(_dir(tmp_path / "structure"))
    assert list(report["checks"]) == eleven
    assert report["trust_registry"] is None
    members = [code(row["member"]) for row in table(text, ["member", "domain", "class"])]
    key = _key()
    entry, registry = authorization_material(key)
    authorization_files = run_authorization(tmp_path / "authorization", entry, registry)
    for member in members:
        value: Any = authorization_files
        for part in member.split("."):
            assert isinstance(value, dict) and part in value, member
            value = value[part]
