from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import readme_includes
from siblings import absent

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
FIXTURES = ROOT / "tests" / "fixtures"
FENCE = re.compile(r"^```(?P<lang>[a-z]*)\n(?P<body>.*?)^```$", re.M | re.S)


def test_readme_documents_quickstart_trust_model_and_limitations() -> None:
    readme = Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text(encoding="utf-8")

    required_phrases = [
        "5-minute quickstart from source",
        "OFFLINE_OK",
        "OFFLINE_REVIEW",
        "OFFLINE_FAIL",
        "REGISTRY_ENTRY_NOT_PROVIDED",
        "issuer signatures",
        "trust registry",
        "chain anchors",
        "Expected abbreviated result",
        "Loquitur offline verification: OFFLINE_OK / PASS",
    ]
    for phrase in required_phrases:
        assert phrase in text
    # The scope sections state what the package does and does not verify as it stands: a heading
    # qualified by "today" or "yet" would read as a promise about a later release.
    lines = text.splitlines()
    for heading in ("## Status", "## What it verifies", "## What it does not verify", "## Trust model"):
        assert heading in lines, f"the README has no line {heading!r}"
    # The README describes who integrates the package, and names no partner: none exists, and the
    # public text of this repository claims none.
    assert "partner" not in text.lower()


def test_the_maintainer_testing_document_runs_the_coverage_and_wheel_gates() -> None:
    # The full checks are maintainer material: CONTRIBUTING.md links docs/maintainers/, and the
    # README keeps the quickstart a reader runs.
    text = (ROOT / "docs" / "maintainers" / "testing.md").read_text(encoding="utf-8")
    for phrase in (
        "python -m pip install -e ../loquitur-schemas",
        "python -m coverage report --fail-under=85",
        "python tools/local_wheel_gate.py",
        "LOQUITUR_REQUIRE_SIBLINGS=1",
    ):
        assert phrase in text, phrase
    assert "docs/maintainers/" in (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


# The docs site includes README sections by these markers rather than by heading, so a heading can
# be reworded without breaking a page. Each id is part of the contract with the site: removing or
# renaming one breaks the page that includes it, which is why the set is fixed here. A region
# opens on the line after its section heading and leaves the heading out: the page that includes
# it supplies its own.
INCLUDE_IDS = (
    "status",
    "installation",
    "quickstart",
    "windows-quickstart",
    "what-it-verifies",
    "does-not-verify",
    "link-check",
    "authorization-check",
    "trust-model",
    "cli-contract",
    "python-api",
)
# The names every package README gives the same content, so a page that composes the packages
# reads one name in each.
SHARED_IDS = ("status", "installation", "quickstart", "what-it-verifies", "does-not-verify", "scope-and-limits")


def _anchor(heading: str) -> str:
    """The anchor GitHub gives a heading: lower case, punctuation other than hyphens dropped, spaces as hyphens."""
    return re.sub(r"[^a-z0-9 -]", "", heading.lstrip("#").strip().lower()).replace(" ", "-")


# The form of every block is tests/readme_includes.py's, and tests/test_readme_include_markers.py
# holds README.md to each of its rules; loquitur-schemas carries both files byte for byte. The tests
# below are this README's own: its set of names, how a name is chosen, and the absolute links into
# this README.


def test_the_blocks_are_the_ones_the_site_includes() -> None:
    names = [block.name for block in readme_includes.blocks()]
    assert sorted(names) == sorted(INCLUDE_IDS), names


def test_each_block_is_a_shared_name_or_its_headings_anchor() -> None:
    lines = README.read_text(encoding="utf-8").splitlines()
    for block in readme_includes.blocks(lines):
        heading = lines[block.start - 3]
        assert block.name in SHARED_IDS or block.name == _anchor(heading), (
            f"README.md:{block.start}: {block.name!r} is neither a shared name nor the anchor of {heading!r}"
        )


def test_an_absolute_link_into_this_readme_names_one_of_its_anchors() -> None:
    lines = README.read_text(encoding="utf-8").splitlines()
    anchors = {_anchor(line) for line in lines if line.startswith("#")}
    own = "https://github.com/loquitur-dev/loquitur-verify-py/blob/main/README.md#"
    included = "\n".join(line for block in readme_includes.blocks(lines) for line in block.body)
    cited = re.findall(re.escape(own) + r"([^)\s]+)\)", included)
    assert cited and set(cited) <= anchors, (cited, sorted(anchors))


@pytest.mark.parametrize("name", ["readme_includes.py", "test_readme_include_markers.py"])
def test_the_include_checker_and_its_tests_are_the_ones_loquitur_schemas_carries(name: str) -> None:
    other = ROOT.parent / "loquitur-schemas" / "tests" / name
    if not other.is_file():
        absent(f"{other} is not checked out beside this repository")
    assert other.read_bytes() == (ROOT / "tests" / name).read_bytes(), f"{other} differs from tests/{name}"


def test_readme_uses_existing_golden_fixture_names() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "README.md").read_text(encoding="utf-8")

    for fixture_name in [
        "valid_bundle.zip",
        "tampered_manifest_bundle.zip",
        "tampered_canonical_input_bundle.zip",
        "missing_canonical_input_bundle.zip",
    ]:
        assert fixture_name in text
        assert (root / "tests" / "fixtures" / fixture_name).is_file()


def test_readme_installs_from_a_checkout_and_not_from_a_place_that_does_not_serve_it() -> None:
    # The README installs the package from a local checkout, the one install that works for every
    # reader whatever an index or a host serves: it sends no reader to a git URL and states no
    # version a package index would hold.
    text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "pip install git+" not in text
    assert "reached PyPI" not in text
    assert "python -m pip install ./loquitur-verify-py" in text


# Every `loquitur-verify` command the README shows is run below, and a command followed by an
# "Expected result" block must produce exactly what the block says, the OFFLINE_OK of the authorization
# section included, which needs the root-signed trust registry and the trust-root document.
# The commands are read out of the README rather than restated here, so a README that drifts
# from the verifier fails this test.


def _documented_runs() -> list[tuple[list[str], list[str] | None]]:
    """(argv after `loquitur-verify`, expected lines or None), in README order."""
    text = README.read_text(encoding="utf-8")
    blocks = list(FENCE.finditer(text))
    runs: list[tuple[list[str], list[str] | None]] = []
    for index, block in enumerate(blocks):
        if block["lang"] not in {"bash", "powershell"}:
            continue
        lines = block["body"].replace("\\\n", " ").splitlines()
        # A line with a <placeholder> is a usage template, not a command.
        commands = [line.strip() for line in lines if line.strip().startswith("loquitur-verify") and "<" not in line]
        if not commands:
            continue
        expected: list[str] | None = None
        following = blocks[index + 1] if index + 1 < len(blocks) else None
        if following is not None and following["lang"] == "text":
            if re.fullmatch(r"\s*Expected (abbreviated )?result:\s*", text[block.end() : following.start()]):
                expected = [line for line in following["body"].splitlines() if line.strip()]
        for position, command in enumerate(commands):
            if block["lang"] == "powershell":
                command = command.replace("\\", "/")
            # The expected block follows the code block, so it belongs to the block's last command.
            runs.append((shlex.split(command)[1:], expected if position == len(commands) - 1 else None))
    return runs


RUNS = _documented_runs()


def _member(report: dict, path: str) -> object:
    value: object = report
    for part in path.split("."):
        assert isinstance(value, dict) and part in value, f"the report has no member {path}"
        value = value[part]
    return value


def test_the_readme_documents_every_authorization_outcome_with_its_result() -> None:
    """The three authorization runs are present, each followed by the result it must produce."""

    def documented(present: str | None, absent: str | None, status: str) -> bool:
        return any(
            expected is not None
            and "--trust-registry" in argv
            and (present is None or present in argv)
            and (absent is None or absent not in argv)
            and f"status: {status}" in expected
            for argv, expected in RUNS
        )

    assert documented(None, "--trust-root", "OFFLINE_REVIEW"), (
        "no authorization run without --trust-root documents OFFLINE_REVIEW"
    )
    assert documented("--trust-root", None, "OFFLINE_OK"), "no authorization run with --trust-root documents OFFLINE_OK"
    # A window that does not hold the operator's evaluation time reviews rather than fails, even
    # with the root pinned (trust-registry-authorization.md section 6).
    assert documented("--trust-root", None, "OFFLINE_REVIEW"), (
        "no authorization run with --trust-root documents the window outside the evaluation time"
    )
    # Every authorization run of the README passes the operator's evaluation time, as the quickstart must.
    authorization_runs = [argv for argv, expected in RUNS if expected is not None and "--trust-registry" in argv]
    assert authorization_runs and all("--evaluation-time" in argv for argv in authorization_runs), authorization_runs
    assert sum(expected is not None for _, expected in RUNS) == 10, "not every documented result was found"


@pytest.mark.parametrize(("argv", "expected"), RUNS, ids=[" ".join(argv) for argv, _ in RUNS])
def test_every_documented_command_produces_its_documented_result(argv: list[str], expected: list[str] | None) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "loquitur.verify.cli", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if expected is None:
        assert result.returncode == 0, result.stderr
        return
    if "--json" not in argv:
        # An abbreviated human-readable result: each documented line is a line of the output.
        for line in expected:
            assert line in result.stdout.splitlines(), f"{line!r} is not a line of the output:\n{result.stdout}"
        return
    report = json.loads(result.stdout)
    for line in expected:
        key, separator, value = line.partition(": ")
        assert separator, f"{line!r} is not of the form 'name: value'"
        if key == "exit code":
            assert result.returncode == int(value), f"exit {result.returncode}, documented {value}"
        else:
            assert _member(report, key) == value, f"{key} is {_member(report, key)!r}, documented {value!r}"


def test_the_quickstart_trust_registry_is_the_authorization_fixture_signed_by_the_quickstart_root() -> None:
    """Only the signature differs, and the root the trust-root document names made it.

    When authorization_valid_trust_registry.json changes, this fails until
    tools/sign_quickstart_trust_fixtures.py is run again.
    """
    from loquitur.verify.trust_root import parse_trust_roots, verify_trust_registry_root_signature

    source = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    signed = json.loads((FIXTURES / "authorization_quickstart_trust_registry.json").read_text(encoding="utf-8"))
    document = json.loads((FIXTURES / "authorization_quickstart_trust_root.json").read_text(encoding="utf-8"))
    source.pop("signature")
    signature = signed.pop("signature")
    assert signed == source
    assert [root["key_id"] for root in document["roots"]] == [signature["key_id"]]
    verification = verify_trust_registry_root_signature(
        {**signed, "signature": signature},
        evaluated_at="2026-05-10T00:00:00Z",
        roots=parse_trust_roots(document),
    )
    assert verification.status == "ROOT_SIGNATURE_VALID"


def test_the_readme_python_example_prints_what_the_readme_says() -> None:
    """The Python API example runs from the repository root and prints the lines stated after it."""
    text = README.read_text(encoding="utf-8")
    examples = [block for block in FENCE.finditer(text) if block["lang"] == "python"]
    assert len(examples) == 1, "the README has no Python example, or more than one"
    stated = re.search(r"It prints `([^`]+)`, then `([^`]+)`\.", text[examples[0].end() :])
    assert stated is not None, "the README does not state what the Python example prints"
    result = subprocess.run(
        [sys.executable, "-c", examples[0]["body"]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == list(stated.groups())
