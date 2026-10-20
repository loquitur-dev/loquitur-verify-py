"""Randomised fail-closed fuzzing of the offline bundle verifier.

The verifier is the component an integrator points at untrusted evidence, so its two
non-negotiable properties are:

  1. it never crashes on hostile input (no unhandled exception escapes ``verify_path``);
  2. it never returns PASS for a bundle whose hash-covered material was altered.

Existing suites cover *known* adversarial shapes (tampered fixtures, malformed
manifests, Wycheproof edge cases). This module covers the shapes nobody enumerated:
randomised structural and byte-level mutations of a known-good bundle.

The corpus is seeded, so any failure reproduces exactly. Scale with
LOQUITUR_FUZZ_ITERATIONS before a release.
"""

from __future__ import annotations

import json
import os
import random
import shutil
from pathlib import Path

import pytest

from loquitur.verify.runner import EXIT_OFFLINE_OK, VERDICT_PASS, verify_path

FIXTURES = Path(__file__).parent / "fixtures"
SOURCE_BUNDLE = FIXTURES / "valid_bundle"
SEED = 20260722
ITERATIONS = int(os.environ.get("LOQUITUR_FUZZ_ITERATIONS", "40"))

# Files whose bytes are covered by the manifest/hash chain: any change to them must
# be detected. Mutating these may never yield PASS.
HASH_COVERED = (
    "canonical_input.json",
    "manifest.json",
    "p1.json",
    "envelope_env1.json",
    "manifest.sha256",
    "p1.sha256",
    "envelope.sha256",
)


def _semantic_content(path: Path) -> bytes:
    """Content normalized the way the verifier reads it.

    Hex digest sidecars are case-insensitive and surrounded by optional whitespace,
    so a mutation that only changes case is a *semantic no-op* and the verifier is
    right to still accept the bundle. Comparing raw bytes would make this fuzzer
    report false findings.
    """
    raw = path.read_bytes()
    if path.name.endswith(".sha256"):
        try:
            return raw.decode("utf-8").strip().lower().encode("utf-8")
        except UnicodeDecodeError:
            return raw
    return raw


def _fresh_bundle(tmp_path: Path, tag: str) -> Path:
    target = tmp_path / f"bundle_{tag}"
    shutil.copytree(SOURCE_BUNDLE, target)
    return target


def _baseline_is_pass(tmp_path: Path) -> None:
    report = verify_path(_fresh_bundle(tmp_path, "baseline"))
    assert report.verdict == VERDICT_PASS and report.exit_code == EXIT_OFFLINE_OK, (
        "fuzz baseline must start from a genuinely passing bundle, "
        f"got verdict={report.verdict} exit={report.exit_code}"
    )


def _mutate_bytes(path: Path, rng: random.Random) -> None:
    data = bytearray(path.read_bytes())
    if not data:
        data.extend(b"x")
    index = rng.randrange(len(data))
    data[index] ^= 1 << rng.randrange(8)
    path.write_bytes(bytes(data))


def _truncate(path: Path, rng: random.Random) -> None:
    data = path.read_bytes()
    path.write_bytes(data[: rng.randrange(0, max(1, len(data)))])


def _corrupt_json_value(path: Path, rng: random.Random) -> None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        return _mutate_bytes(path, rng)
    if not isinstance(doc, dict) or not doc:
        return _mutate_bytes(path, rng)
    key = rng.choice(sorted(doc))
    value = doc[key]
    if isinstance(value, str):
        doc[key] = value + "x"
    elif isinstance(value, bool) or value is None:
        doc[key] = not bool(value)
    elif isinstance(value, (int, float)):
        doc[key] = value + 1
    else:
        doc[key] = "mutated"
    path.write_text(json.dumps(doc), encoding="utf-8")


MUTATIONS = (
    ("flip_bit", _mutate_bytes),
    ("truncate", _truncate),
    ("corrupt_json_value", _corrupt_json_value),
)


@pytest.mark.parametrize("mutation_name", [name for name, _ in MUTATIONS])
def test_mutating_hash_covered_material_never_passes(tmp_path: Path, mutation_name: str) -> None:
    mutate = dict(MUTATIONS)[mutation_name]
    _baseline_is_pass(tmp_path)
    rng = random.Random(f"{SEED}-{mutation_name}")
    for i in range(ITERATIONS):
        bundle = _fresh_bundle(tmp_path, f"{mutation_name}_{i}")
        target = bundle / rng.choice(HASH_COVERED)
        if not target.exists():
            continue
        before = _semantic_content(target)
        mutate(target, rng)
        if _semantic_content(target) == before:
            continue  # semantic no-op (for example hex case): nothing is claimed about it
        report = verify_path(bundle)
        assert not (report.verdict == VERDICT_PASS and report.exit_code == EXIT_OFFLINE_OK), (
            f"FALSE PASS after {mutation_name} on {target.name} (iteration {i}): "
            f"verdict={report.verdict} exit={report.exit_code}"
        )


def test_deleting_any_required_file_never_passes(tmp_path: Path) -> None:
    _baseline_is_pass(tmp_path)
    for name in sorted(p.name for p in SOURCE_BUNDLE.iterdir() if p.is_file()):
        bundle = _fresh_bundle(tmp_path, f"del_{name.replace('.', '_')}")
        (bundle / name).unlink()
        report = verify_path(bundle)
        assert not (report.verdict == VERDICT_PASS and report.exit_code == EXIT_OFFLINE_OK), (
            f"FALSE PASS after deleting {name}: verdict={report.verdict}"
        )


def test_hostile_inputs_never_raise(tmp_path: Path) -> None:
    """Property 1: no unhandled exception escapes, whatever the bundle looks like."""
    rng = random.Random(SEED + 99)
    hostile: list[tuple[str, Path]] = []

    empty = tmp_path / "empty_dir"
    empty.mkdir()
    hostile.append(("empty_dir", empty))

    missing = tmp_path / "does_not_exist"
    hostile.append(("missing_path", missing))

    not_a_bundle = tmp_path / "not_a_bundle"
    not_a_bundle.mkdir()
    (not_a_bundle / "random.txt").write_text("nothing to see", encoding="utf-8")
    hostile.append(("unrelated_files", not_a_bundle))

    deep = tmp_path / "deep_nesting"
    shutil.copytree(SOURCE_BUNDLE, deep)
    depth = 2000
    deep_json = '{"n":' * depth + '{"x":1}' + "}" * depth
    (deep / "canonical_input.json").write_text(deep_json, encoding="utf-8")
    hostile.append(("deep_nesting", deep))

    for name in ("garbage_json", "empty_files", "huge_strings", "unicode"):
        bundle = _fresh_bundle(tmp_path, name)
        for member in bundle.iterdir():
            if not member.is_file():
                continue
            if name == "garbage_json":
                member.write_bytes(bytes(rng.randrange(256) for _ in range(64)))
            elif name == "empty_files":
                member.write_bytes(b"")
            elif name == "huge_strings":
                member.write_text(json.dumps({"k": "\U0001f600\ufffe\ufeff\u202e\u0000"}), encoding="utf-8")
            else:
                # astral plane, noncharacter, BOM, RTL override, NUL
                member.write_text(json.dumps({"k": "\U0001f600\ufffe\ufeff\u202e\u0000"}), encoding="utf-8")
        hostile.append((name, bundle))

    for label, path in hostile:
        try:
            report = verify_path(path)
        except Exception as exc:  # noqa: BLE001 - the property under test
            raise AssertionError(f"verify_path raised on hostile input [{label}]: {exc!r}") from exc
        assert report.verdict != VERDICT_PASS or report.exit_code != EXIT_OFFLINE_OK, (
            f"FALSE PASS on hostile input [{label}]"
        )
