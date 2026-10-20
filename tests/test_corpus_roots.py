"""The declared runs of every corpus root named by LOQUITUR_CORPUS_ROOTS, reproduced by this verifier.

LOQUITUR_CORPUS_ROOTS names corpus roots separated by the host's path separator (`;` on Windows,
`:` elsewhere): an extraction of the pinned conformance archive, or any tree laid out as one, with
`vectors/verify.json` and optionally `vectors/additional-negatives/expected.json` and
`vectors/bundles/manifest.json`. Each declared run is verified as `tools/conformance_adapter.py`
verifies it, and the members `conformance-testing.md` section 6 item 1 compares are compared: the
status, verdict, exit code, reason, error codes, the checks requested and established, the review
reasons, the evaluation time, the trust-registry statuses and the object and version a version gate
names, or, for a run declared refused, the refusal and its exit code; a run declared per intake is
reproduced by either declaration. The module skips, saying why, when the variable is unset.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time
from loquitur.verify.runner import EXIT_USAGE_ERROR, unsupported_version_report, verify_path
from loquitur.verify.trust_root import (
    PINNED_TRUST_ROOTS,
    TrustRootDocumentUnsupportedVersion,
    read_trust_root_document,
)
from loquitur.verify.vocabulary import KINDS, VocabularyError, resolve_vocabularies

ROOTS_ENV = "LOQUITUR_CORPUS_ROOTS"
COMPARED = (
    "status",
    "verdict",
    "exit_code",
    "reason",
    "errors",
    "checks_requested",
    "checks_established",
    "review_reasons",
    "evaluation_time",
    "unsupported_version",
)


def _roots() -> list[Path]:
    value = os.environ.get(ROOTS_ENV, "").strip()
    return [Path(part) for part in value.split(os.pathsep) if part.strip()]


def declared_runs(root: Path) -> dict[str, dict]:
    """Every declared run under ``root``, by name."""
    vectors = root / "vectors"
    runs: dict[str, dict] = {}
    sources = [
        ("verify.json", None),
        ("additional-negatives/expected.json", "cases"),
        ("bundles/manifest.json", "cases"),
    ]
    for relative, member in sources:
        path = vectors / relative
        if not path.is_file():
            if relative == "verify.json":
                raise FileNotFoundError(f"{path} is not a corpus declaration file")
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        items = document.items() if member is None else ((case["id"], case) for case in document[member])
        for name, run in items:
            if name in runs:
                raise ValueError(f"{root}: the run {name} is declared twice")
            runs[name] = run
    return runs


def surface(report: dict) -> dict:
    outcome = report.get("outcome") or {}
    return {
        "status": report.get("status"),
        "verdict": report.get("verdict"),
        "exit_code": report.get("exit_code"),
        "reason": outcome.get("reason"),
        "errors": [error.get("code") for error in report.get("errors") or []],
        "trust_registry": report.get("trust_registry"),
        "checks_requested": report.get("checks_requested"),
        "checks_established": report.get("checks_established"),
        "review_reasons": report.get("review_reasons"),
        "evaluation_time": report.get("evaluation_time"),
        "unsupported_version": next(
            (
                {"object": error.get("object"), "version": error.get("version")}
                for error in report.get("errors") or []
                if error.get("code") == "unsupported_version"
            ),
            None,
        ),
    }


def differences(expected: dict, actual: dict) -> list[str]:
    found = [
        f"{member} is {actual[member]!r}, declared {expected[member]!r}"
        for member in COMPARED
        if member in expected and actual[member] != expected[member]
    ]
    for member, value in (expected.get("trust_registry") or {}).items():
        if (actual["trust_registry"] or {}).get(member) != value:
            found.append(
                f"trust_registry.{member} is {(actual['trust_registry'] or {}).get(member)!r}, declared {value!r}"
            )
    return found


def run_once(vectors: Path, run: dict) -> tuple[dict | None, int]:
    """The report and exit code of one run, verified as the conformance adapter verifies it."""
    target = vectors / "bundles" / run["bundle"] if "bundle" in run else vectors / run["input"]
    document = {
        key: str(vectors / run[key]) if run.get(key) else None
        for key in ("registry_entry", "trust_registry", "trust_root")
    }
    # The run declares the operator's evaluation time as the command line takes it
    # (conformance-testing.md section 4.1).
    if run.get("evaluation_time") is not None and document["trust_registry"] is None:
        return None, EXIT_USAGE_ERROR
    evaluation_time = None
    if run.get("evaluation_time") is not None:
        try:
            evaluation_time = operator_evaluation_time(run["evaluation_time"])
        except EvaluationTimeError:
            return None, EXIT_USAGE_ERROR
    # conformance-testing.md section 4.1: the vocabulary a run names for a kind, else the corpus's
    # baseline for it; a corpus that carries no vocabularies leaves the verifier's own.
    named = run.get("vocabularies") or {}
    baseline = vectors / "vocabularies" / "baseline"
    supplied = {
        kind: str(vectors / named[kind]) if named.get(kind) else str(baseline / f"{kind}.json")
        for kind in KINDS
        if named.get(kind) or (baseline / f"{kind}.json").is_file()
    }
    try:
        vocabularies = resolve_vocabularies(supplied)
    except VocabularyError:
        return None, EXIT_USAGE_ERROR
    trust_roots = PINNED_TRUST_ROOTS
    if document["trust_root"] is not None:
        if document["trust_registry"] is None:
            return None, EXIT_USAGE_ERROR
        try:
            trust_roots = read_trust_root_document(document["trust_root"])
        except TrustRootDocumentUnsupportedVersion as exc:
            report = unsupported_version_report(
                str(target),
                "trust_root_document",
                exc.version,
                registry_entry_supplied=document["registry_entry"] is not None,
                trust_registry_supplied=True,
                evaluation_time=evaluation_time,
            )
            return report.to_dict(), 0
        except (OSError, ValueError):
            return None, EXIT_USAGE_ERROR
    report = verify_path(
        str(target),
        registry_entry_path=document["registry_entry"],
        trust_registry_path=document["trust_registry"],
        evaluation_time=evaluation_time,
        trust_roots=trust_roots,
        vocabularies=vocabularies,
    )
    return report.to_dict(), 0


def disagreements(root: Path) -> tuple[int, list[str]]:
    vectors = root / "vectors"
    runs = declared_runs(root)
    found: list[str] = []
    for name, run in runs.items():
        report, code = run_once(vectors, run)
        expected = run.get("expected")
        if expected is not None and expected.get("report", False) is None:
            if report is not None or code != expected["exit_code"]:
                found.append(f"{name}: declared a refusal with exit {expected['exit_code']}")
            continue
        if report is None:
            found.append(f"{name}: refused with exit {code}, declared a report")
            continue
        actual = surface(report)
        if expected is not None:
            found += [f"{name}: {difference}" for difference in differences(expected, actual)]
        elif not any(not differences(declared, actual) for declared in run["expected_by_intake"].values()):
            found.append(f"{name}: matches no declared intake")
    return len(runs), found


@pytest.mark.skipif(not _roots(), reason=f"{ROOTS_ENV} names no corpus root")
@pytest.mark.parametrize("root", _roots(), ids=lambda root: root.name or str(root))
def test_every_declared_run_of_each_corpus_root_is_reproduced(root: Path) -> None:
    count, found = disagreements(root)
    assert not found, f"{len(found)} of {count} runs under {root} disagree:\n" + "\n".join(found)


def test_a_changed_declaration_is_a_disagreement(tmp_path: Path) -> None:
    """Not vacuous: one run whose declared exit code is changed is reported."""
    vectors = tmp_path / "vectors"
    bundle = vectors / "bundles" / "empty_bundle"
    bundle.mkdir(parents=True)
    count, found = 0, []
    for declared in (None, 99):
        report, code = run_once(vectors, {"bundle": "empty_bundle"})
        expected = {key: value for key, value in surface(report).items() if key in COMPARED}
        if declared is not None:
            expected["exit_code"] = declared
        (vectors / "verify.json").write_text(
            json.dumps({"r": {"bundle": "empty_bundle", "expected": expected}}), encoding="utf-8"
        )
        count, found = disagreements(tmp_path)
        assert count == 1
        assert bool(found) == (declared is not None), found
