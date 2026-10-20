"""The verdict path contains no network access and no AI: enforced, and shown to be able to fail.

tools/check_verdict_path_isolation.py is the gate; its docstring says what each of its three
checks reads and what none of them covers, and tests/import_guards.py holds the rule it
applies as an allow-list. These tests run it on this package and require it to pass, and then
plant what it exists to find in a scratch copy of the package: forms of import that get
`socket` and `urllib.request` past a guard that reads text, a package outside
the runtime dependency closure under a name nobody enumerated, an import hidden in a function
body, a connection attempt the code swallows, a module site customization had preloaded, and
require each to be named. A gate that has only ever been seen passing has not been shown to
check anything.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _tool():
    spec = importlib.util.spec_from_file_location(
        "_check_verdict_path_isolation", REPO / "tools/check_verdict_path_isolation.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = _tool()
GUARDS = TOOL.GUARDS


def _scratch_copy(tmp_path: Path) -> tuple[Path, Path]:
    source_root = tmp_path / "src"
    shutil.copytree(
        REPO / "src/loquitur", source_root / "loquitur", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info")
    )
    return source_root, source_root / "loquitur" / "verify"


def _plant(module: Path, text: str) -> None:
    module.write_text(module.read_text(encoding="utf-8") + "\n" + text + "\n", encoding="utf-8")


def test_this_package_passes_all_three_checks(capsys: pytest.CaptureFixture[str]) -> None:
    assert TOOL.main([]) == 0, capsys.readouterr().out
    assert "verdict path isolation OK" in capsys.readouterr().out


def test_the_allow_list_is_the_rule_the_module_states() -> None:
    """Standard library outside the network modules, the namespace, the closure; nothing else."""

    for name in (
        "socket",
        "_socket",
        "ssl",
        "http.client",
        "urllib.request",
        "asyncio",
        "asyncio.streams",
        "ftplib",
        "smtplib",
        "xmlrpc.client",
        "multiprocessing.connection",
    ):
        assert GUARDS.disallowed_reason(name) == "network", name
    # Names outside the closure are refused whether or not a distribution of that name exists
    # or is installed: pytest is installed wherever this suite runs and is not on the verdict path.
    for name in ("some_model_sdk", "a_web_client", "an_unpublished_namespace.module", "pytest", "_pytest.config"):
        reason = GUARDS.disallowed_reason(name)
        assert reason is not None and reason.startswith("outside the runtime dependency closure ["), (name, reason)
        assert GUARDS.is_forbidden_on_the_verdict_path(name)
    for name in (
        "urllib.parse",
        "json",
        "hashlib",
        "zipfile",
        "rfc8785",
        "loquitur.schemas",
        "loquitur.verify.cli",
        "__main__",
    ):
        assert GUARDS.disallowed_reason(name) is None, name
        assert not GUARDS.is_forbidden_on_the_verdict_path(name)


def test_the_base_closure_requires_only_what_cryptography_asks_for_on_every_supported_python() -> None:
    """An environment holding the package alone has no typing-extensions on Python 3.11 and later.

    cryptography requires typing-extensions only below Python 3.11, so a fresh install of this
    package (the CI job that runs it alone) does not carry it. A base closure that required it
    failed the closure check in exactly that environment, while every workspace environment,
    which has it for other reasons, passed. It is admitted where present and never required.
    """
    assert "typing-extensions" not in TOOL.REVIEWED_RUNTIME_CLOSURE["base"]
    assert "typing-extensions" in TOOL.REVIEWED_RUNTIME_CLOSURE["base_where_asked"]
    without = frozenset(GUARDS.runtime_dependency_closure()) - {"typing-extensions"}
    assert TOOL.REVIEWED_RUNTIME_CLOSURE["base"] <= without


def test_the_closure_is_read_from_pyproject_and_is_the_reviewed_one(tmp_path: Path) -> None:
    assert TOOL.closure_violations() == []
    closure = set(GUARDS.runtime_dependency_closure())
    assert "rfc8785" in closure
    assert TOOL.REVIEWED_RUNTIME_CLOSURE["base"] <= closure
    assert closure <= frozenset().union(*TOOL.REVIEWED_RUNTIME_CLOSURE.values())
    # `dev` is tooling, not a runtime extra: its distributions never enter the closure.
    assert "pytest" not in closure

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'probe'\nversion = '0'\ndependencies = ['rfc8785>=0.1', 'Not_Installed.Distribution>=1']\n"
        "[project.optional-dependencies]\nnarrative = ['loquitur-schemas[extra-one]; extra == \"narrative\"']\n"
        "dev = ['pytest']\n",
        encoding="utf-8",
    )
    assert GUARDS.declared_runtime_requirements(pyproject) == [
        "rfc8785>=0.1",
        "Not_Installed.Distribution>=1",
        'loquitur-schemas[extra-one]; extra == "narrative"',
    ]
    assert GUARDS.missing_base_dependencies(pyproject) == ["not-installed-distribution"]
    probe_closure = GUARDS.runtime_dependency_closure(pyproject)
    assert "rfc8785" in probe_closure and "not-installed-distribution" not in probe_closure
    assert "pytest" not in probe_closure


def test_a_distribution_outside_the_reviewed_closure_fails_the_static_check(monkeypatch: pytest.MonkeyPatch) -> None:
    widened = dict(GUARDS.runtime_dependency_closure())
    widened["some-transitive-distribution"] = frozenset({"some_transitive_module"})
    monkeypatch.setattr(GUARDS, "runtime_dependency_closure", lambda pyproject=None: widened)
    assert TOOL.closure_violations() == [
        "closure: some-transitive-distribution is in the runtime dependency closure and not in the reviewed one"
    ]
    monkeypatch.setattr(GUARDS, "missing_base_dependencies", lambda pyproject=None: ["rfc8785"])
    assert any("rfc8785 is not installed" in violation for violation in TOOL.closure_violations())


@pytest.mark.parametrize(
    ("planted", "named"),
    [
        ("import socket", "socket (network)"),
        ("import urllib.request", "urllib.request (network)"),
        ("from urllib.request import urlopen", "urllib.request (network)"),
        ("from urllib import request", "urllib.request (network)"),
        ("import http.client as client", "http.client (network)"),
        ("from asyncio import open_connection", "asyncio (network)"),
        ("import some_model_sdk", "some_model_sdk (outside the runtime dependency closure"),
        ("from a_model_client import Client", "a_model_client (outside the runtime dependency closure"),
        (
            "from an_unpublished_namespace import thing",
            "an_unpublished_namespace (outside the runtime dependency closure",
        ),
        ("import pytest", "pytest (outside the runtime dependency closure"),
        ("def later():\n    import ssl\n    return ssl", "ssl (network)"),
        ("import importlib\nimportlib.import_module('a_tokenizer')", "a_tokenizer (outside"),
        ("__import__('a_tokenizer')", "a_tokenizer (outside"),
        ("name = 'soc' + 'ket'\n__import__(name)", "not a literal"),
        ("exec('import socket')", "exec"),
    ],
)
def test_the_static_check_names_a_planted_import(tmp_path: Path, planted: str, named: str) -> None:
    _source_root, package = _scratch_copy(tmp_path)
    clean, modules = TOOL.static_violations(package)
    assert clean == [] and modules >= 17

    _plant(package / "archive.py", planted)
    violations, _ = TOOL.static_violations(package)
    assert any(named in violation and "archive.py" in violation for violation in violations), violations


def test_the_static_check_reads_imports_not_words(tmp_path: Path) -> None:
    _source_root, package = _scratch_copy(tmp_path)
    _plant(package / "archive.py", "# import socket\nNOTE = 'from some_model_sdk import Client'\nimport urllib.parse")
    assert TOOL.static_violations(package)[0] == []


def test_the_static_check_fails_on_nothing_to_read(tmp_path: Path) -> None:
    violations, modules = TOOL.static_violations(tmp_path)
    assert modules == 0 and violations


@pytest.mark.parametrize(
    ("planted", "named"),
    [
        ("import socket  # planted", "loaded socket (network)"),
        ("import pytest  # planted", "loaded pytest (outside the runtime dependency closure"),
    ],
)
def test_the_runtime_check_names_a_module_an_import_loads(tmp_path: Path, planted: str, named: str) -> None:
    source_root, package = _scratch_copy(tmp_path)
    assert TOOL.runtime_violations(package, source_root) == []

    _plant(package / "runner.py", planted)
    violations = TOOL.runtime_violations(package, source_root)
    assert any(named in violation for violation in violations), violations


def test_the_runtime_check_sees_a_module_site_customisation_had_preloaded(tmp_path: Path) -> None:
    """A refused module already in the cache at start-up is evicted, so its import is visible.

    `sitecustomize` on the child's path imports `a_startup_module` before anything else runs,
    the way an editable-install finder or a build tool's shim is imported by a `.pth` file.
    Without the eviction the planted import in runner.py would find the module in the cache
    and the check would have nothing to report.
    """

    source_root, package = _scratch_copy(tmp_path)
    (source_root / "a_startup_module.py").write_text("LOADED = True\n", encoding="utf-8")
    (source_root / "sitecustomize.py").write_text("import a_startup_module  # noqa: F401\n", encoding="utf-8")
    assert TOOL.runtime_violations(package, source_root) == []

    _plant(package / "runner.py", "import a_startup_module  # planted")
    violations = TOOL.runtime_violations(package, source_root)
    assert any("loaded a_startup_module (outside" in violation for violation in violations), violations


def test_the_offline_run_records_a_connection_attempt_the_code_swallows(tmp_path: Path) -> None:
    source_root, package = _scratch_copy(tmp_path)
    cli = package / "cli.py"
    text = cli.read_text(encoding="utf-8")
    anchor = "    parser = build_parser()\n"
    assert anchor in text
    # 192.0.2.1 is TEST-NET-1: nothing answers there, and the refusal fires before any packet.
    planted = (
        "    try:\n"
        "        __import__('socket').create_connection(('192.0.2.1', 9), timeout=0.01)\n"
        "    except OSError:\n"
        "        pass\n"
    )
    cli.write_text(text.replace(anchor, anchor + planted, 1), encoding="utf-8")

    violations, runs = TOOL.offline_violations(package, source_root)
    assert runs > 0
    assert any("network attempt recorded" in violation for violation in violations), violations
    # The swallowed refusal left every run with an outcome: only the recorded attempt fails it.
    assert not any("no outcome" in violation for violation in violations), violations


def test_the_offline_run_and_the_static_check_must_read_the_same_code(tmp_path: Path) -> None:
    _source_root, package = _scratch_copy(tmp_path)
    # No --source-root: the child imports the installed package, not this copy.
    violations, _ = TOOL.offline_violations(package, None)
    assert any("not the package the static check read" in violation for violation in violations), violations


def _pinned_bundle_names() -> set[str]:
    """The bundle directories of the archive loquitur-protocol pins, read from its listing."""
    import json
    import zipfile

    lock = json.loads(TOOL.CONFORMANCE_LOCK.read_text(encoding="utf-8"))
    with zipfile.ZipFile(TOOL.PROTOCOL / lock["artifact"]) as archive:
        names = archive.namelist()
    return {
        name[len(TOOL.CORPUS_BUNDLES) :].split("/", 1)[0]
        for name in names
        if name.startswith(TOOL.CORPUS_BUNDLES)
        and name[len(TOOL.CORPUS_BUNDLES) :].split("/", 1)[0].endswith("_bundle")
    }


def test_the_offline_run_covers_every_bundle_of_the_pinned_corpus(tmp_path: Path) -> None:
    if not TOOL.CONFORMANCE_LOCK.is_file():
        from siblings import absent

        absent(f"loquitur-protocol is not checked out beside this repository: {TOOL.CONFORMANCE_LOCK} is missing")
    cases, problems = TOOL.offline_cases(tmp_path)
    assert problems == []
    corpus = {Path(case[0]).name for case in cases if Path(case[0]).is_relative_to(tmp_path)}
    expected = _pinned_bundle_names()
    assert len(expected) >= 10, expected
    assert corpus == expected


def test_the_offline_run_refuses_a_corpus_that_is_not_the_pinned_one(tmp_path: Path, monkeypatch) -> None:
    import json

    lock = tmp_path / "CONFORMANCE_LOCK.json"
    lock.write_text(json.dumps({"artifact": "conformance/absent.zip", "sha256": "0" * 64}), encoding="utf-8")
    monkeypatch.setattr(TOOL, "CONFORMANCE_LOCK", lock)
    monkeypatch.setattr(TOOL, "PROTOCOL", tmp_path)
    (tmp_path / "conformance").mkdir()
    (tmp_path / "conformance/absent.zip").write_bytes(b"not the pinned archive")
    for scratch in ("scratch-a", "scratch-b", "scratch-c"):
        (tmp_path / scratch).mkdir()
    _, problems = TOOL.offline_cases(tmp_path / "scratch-a")
    assert problems == [f"offline: {tmp_path / 'conformance/absent.zip'} is not the archive CONFORMANCE_LOCK.json pins"]

    monkeypatch.setattr(TOOL, "CONFORMANCE_LOCK", tmp_path / "missing" / "CONFORMANCE_LOCK.json")
    monkeypatch.setenv(TOOL.REQUIRE_SIBLINGS_ENV, "1")
    _, problems = TOOL.offline_cases(tmp_path / "scratch-b")
    assert problems == [
        f"offline: {TOOL.REQUIRE_SIBLINGS_ENV}=1 but {tmp_path / 'missing' / 'CONFORMANCE_LOCK.json'} is absent"
    ]
    monkeypatch.delenv(TOOL.REQUIRE_SIBLINGS_ENV)
    cases, problems = TOOL.offline_cases(tmp_path / "scratch-c")
    assert problems == [] and not any("scratch-c" in case[0] for case in cases)
