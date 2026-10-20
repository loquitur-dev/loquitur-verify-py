"""Enforce that the verdict path contains no network access and no AI.

The package says so of itself, and this tool enforces it. tests/import_guards.py holds the
rule as an allow-list: a module may be imported
when it is standard library outside the network modules, the `loquitur` namespace, or a
top-level module of a distribution in the runtime dependency closure pyproject.toml declares
(rfc8785 and cryptography for the base install; loquitur-schemas and what it requires under
the `narrative` extra). Everything else is refused by that one rule, so the tool needs no list of
the packages it refuses and carries none.

Three checks, each of which fails closed (an input it cannot read, a module list it
cannot find, a run that ended in no outcome of the outcome table, is a failure, never a pass):

  static   Every `.py` file of the loquitur.verify package is parsed with `ast`, and every
           `import`, `from ... import`, `__import__(...)` and `importlib.import_module(...)`
           is resolved to a module name and held to the allow-list. Reading the syntax tree
           rather than grepping text means a name in a comment or a string is not an import
           and an import is not missed for its spelling; reading every module rather than
           importing one means an import buried in a function that a given run never calls
           is still found. An import whose target is not a string literal cannot be checked
           and is reported as such, as are `exec` and `eval`. The runtime dependency closure
           the allow-list was computed from must be the reviewed one (REVIEWED_RUNTIME_CLOSURE):
           a distribution that arrives through a new transitive requirement is a change to
           this file, not a silent widening of what the verifier may load.
  runtime  A fresh interpreter evicts from its module cache whatever site customization
           loaded at start-up that the allow-list refuses (an editable-install finder, a
           build tool's shim), so that an import of it would be visible, then imports
           loquitur.verify, its runner and its CLI and reports every refused module that
           appeared.
  offline  A fresh interpreter replaces socket creation, name resolution and connection
           helpers with functions that record the attempt and raise, installs an audit hook
           that records every socket and URL-opening event the interpreter raises, and then
           runs the CLI over the package's own fixture bundles under each of the four checks, with
           --trust-root, and over the bundles of the conformance corpus that
           loquitur-protocol pins, when that repository is checked out beside this one: the
           archive its CONFORMANCE_LOCK.json names, checked against the pinned digest and
           extracted into a scratch directory. Every run must produce a verdict (exit 0, 1 or 2
           with a JSON report); a crash is not evidence of anything. Any recorded attempt
           fails the check.

The three checks look at the same code: runtime and offline both report the file their
`loquitur.verify` was imported from, and the tool fails if it is not inside the package
directory the static check read.

What this does not cover, so that nothing claims it does: the modules of the dependency
closure itself (`rfc8785`, `cryptography` and, for narrative rendering only, `loquitur-schemas`) are covered
by the runtime and offline checks, which see what those packages load, and not by the
static one; and it forbids modules, not every conceivable channel: a verifier that spawned
a program to reach the network would need a different check.

Usage:
  python tools/check_verdict_path_isolation.py                # all three, installed package
  python tools/check_verdict_path_isolation.py --source-root DIR
      # DIR contains loquitur/verify; used for all three checks (non-vacuity demonstrations)
Exit status: 0 when all three pass, 1 on any violation.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"
FIXTURES = TESTS / "fixtures"
# The corpus is the archive loquitur-protocol pins, read from a loquitur-protocol checkout
# beside this one; its bundles are the archive members under CORPUS_BUNDLES.
PROTOCOL = REPO.parent / "loquitur-protocol"
CONFORMANCE_LOCK = PROTOCOL / "CONFORMANCE_LOCK.json"
CORPUS_BUNDLES = "loquitur-conformance/vectors/bundles/"
REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"


def _load_import_guards():
    spec = importlib.util.spec_from_file_location("_verdict_path_import_guards", TESTS / "import_guards.py")
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {TESTS / 'import_guards.py'}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARDS = _load_import_guards()

# The runtime dependency closure as reviewed: the base install is rfc8785 and cryptography, with
# what cryptography requires (`cffi` and `pycparser`), which the README promises; cryptography
# asks for `typing-extensions` only on interpreters older than this package supports, so it is
# admitted where an environment has it and never required; and the `narrative` extra may add
# loquitur-schemas and what it requires. A distribution outside these sets in the computed
# closure fails the static check, so a new transitive requirement widens the allow-list only
# through an edit here.
REVIEWED_RUNTIME_CLOSURE = {
    "base": frozenset({"rfc8785", "cryptography", "cffi", "pycparser"}),
    "base_where_asked": frozenset({"typing-extensions"}),
    "narrative": frozenset({"loquitur-schemas"}),
}


# --------------------------------------------------------------------------- static


def package_dir(source_root: Path | None) -> Path:
    if source_root is not None:
        return (source_root / "loquitur" / "verify").resolve()
    # Asked of a fresh interpreter, not of this one: under pytest, pyproject's
    # `pythonpath = ["src"]` puts the checkout first in this process only, while the
    # runtime and offline children import whatever is installed. The static check must
    # read the package those children run.
    locate = (
        "import importlib.util; spec = importlib.util.find_spec('loquitur.verify'); "
        "print(next(iter(spec.submodule_search_locations)) if spec and spec.submodule_search_locations else '')"
    )
    result = subprocess.run(
        [sys.executable, "-c", locate],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**_child_env(None), "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    location = result.stdout.strip()
    if result.returncode != 0 or not location:
        raise SystemExit("loquitur.verify is not importable here; install the package or pass --source-root")
    return Path(location).resolve()


def _module_name(package: Path, path: Path) -> tuple[str, bool]:
    parts = ["loquitur", "verify", *path.relative_to(package).with_suffix("").parts]
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


def _imported_names(tree: ast.AST, module: str, is_package: bool) -> list[tuple[int, str | None, str]]:
    """Return (line, imported module or None when it cannot be determined, how) triples."""

    found: list[tuple[int, str | None, str]] = []
    anchor = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name, "import") for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = anchor
                for _ in range(node.level - 1):
                    base = base.rpartition(".")[0]
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            found.append((node.lineno, target, "from-import"))
            # `from urllib import request` imports urllib.request.
            found.extend((node.lineno, f"{target}.{alias.name}", "from-import") for alias in node.names)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name in {"__import__", "import_module"}:
                argument = node.args[0] if node.args else None
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    found.append((node.lineno, argument.value, name))
                else:
                    found.append((node.lineno, None, name))
            elif isinstance(func, ast.Name) and name in {"exec", "eval"}:
                found.append((node.lineno, None, name))
    return found


def closure_violations() -> list[str]:
    """The computed runtime closure must be readable and must be the reviewed one."""

    violations = [
        f"closure: the declared base dependency {name} is not installed, so the allow-list cannot be read"
        for name in GUARDS.missing_base_dependencies()
    ]
    closure = frozenset(GUARDS.runtime_dependency_closure())
    reviewed = frozenset().union(*REVIEWED_RUNTIME_CLOSURE.values())
    if not REVIEWED_RUNTIME_CLOSURE["base"] <= closure:
        violations.append(f"closure: the base closure {sorted(REVIEWED_RUNTIME_CLOSURE['base'])} is not installed")
    for name in sorted(closure - reviewed):
        violations.append(f"closure: {name} is in the runtime dependency closure and not in the reviewed one")
    return violations


def static_violations(package: Path) -> tuple[list[str], int]:
    violations: list[str] = closure_violations()
    files = sorted(package.rglob("*.py"))
    if not files:
        return [*violations, f"{package}: no Python modules found; nothing was checked"], 0
    for path in files:
        rel = path.relative_to(package.parents[1]).as_posix()
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, ValueError, OSError) as exc:
            violations.append(f"{rel}: cannot be parsed, so cannot be checked ({exc})")
            continue
        module, is_package = _module_name(package, path)
        for line, target, how in _imported_names(tree, module, is_package):
            if target is None:
                violations.append(f"{rel}:{line}: {how} with a target that is not a literal cannot be checked")
            elif (reason := GUARDS.disallowed_reason(target)) is not None:
                violations.append(f"{rel}:{line}: {how} of {target} ({reason})")
    return violations, len(files)


# --------------------------------------------------------------------------- runtime


def _child_env(source_root: Path | None) -> dict[str, str]:
    env = dict(os.environ)
    if source_root is not None:
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(source_root), env.get("PYTHONPATH", "")]))
    env.pop("PYTHONSTARTUP", None)
    return env


def _run_child(code: str, source_root: Path | None, payload: object) -> dict:
    with tempfile.TemporaryDirectory() as scratch:
        request = Path(scratch) / "request.json"
        request.write_text(json.dumps(payload), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-c", code, str(TESTS / "import_guards.py"), str(request)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**_child_env(source_root), "PYTHONIOENCODING": "utf-8"},
            check=False,
            timeout=600,
        )
    lines = [line for line in result.stdout.splitlines() if line.startswith("VERDICT-PATH-ISOLATION ")]
    if result.returncode != 0 or len(lines) != 1:
        return {"error": f"child exited {result.returncode}: {result.stdout[-2000:]} {result.stderr[-2000:]}"}
    return json.loads(lines[0].split(" ", 1)[1])


RUNTIME_CHILD = r"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("_guards", sys.argv[1])
guards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guards)
evicted = sorted(guards.evict_preloaded_forbidden_modules())
import loquitur.verify, loquitur.verify.runner, loquitur.verify.cli
loaded = {name: guards.disallowed_reason(name) for name in sorted(guards.snapshot_forbidden_modules())}
print("VERDICT-PATH-ISOLATION " + json.dumps({"file": loquitur.verify.__file__, "evicted": evicted, "loaded": loaded}))
"""


def runtime_violations(package: Path, source_root: Path | None) -> list[str]:
    report = _run_child(RUNTIME_CHILD, source_root, {})
    if "error" in report:
        return [f"runtime: {report['error']}"]
    violations = [
        f"runtime: importing the verifier loaded {name} ({reason})" for name, reason in report["loaded"].items()
    ]
    if not Path(report["file"]).resolve().is_relative_to(package):
        violations.append(f"runtime: imported {report['file']}, not the package the static check read ({package})")
    return violations


# --------------------------------------------------------------------------- offline run


OFFLINE_CHILD = r"""
import contextlib, io, json, sys

attempts = []
_NETWORK_EVENTS = ("socket.", "urllib.Request", "http.client.", "ftplib.", "smtplib.", "poplib.",
                   "imaplib.", "nntplib.", "telnetlib.", "webbrowser.")

def _audit(event, args):
    if event.startswith(_NETWORK_EVENTS):
        attempts.append(event)

sys.addaudithook(_audit)

import socket, _socket

def _refuse(what):
    def refused(*args, **kwargs):
        attempts.append(what)
        raise OSError(f"network access refused by the verdict-path isolation check: {what}")
    return refused

class _RefusedSocket(_socket.socket):
    def __init__(self, *args, **kwargs):
        attempts.append("socket.socket()")
        raise OSError("network access refused by the verdict-path isolation check: socket.socket()")

socket.socket = _RefusedSocket
_socket.socket = _RefusedSocket
for _name in ("create_connection", "create_server", "getaddrinfo", "gethostbyname", "gethostbyname_ex",
              "gethostbyaddr", "socketpair", "fromfd"):
    if hasattr(socket, _name):
        setattr(socket, _name, _refuse(f"socket.{_name}()"))

import loquitur.verify
from loquitur.verify.cli import main

with open(sys.argv[2], encoding="utf-8") as handle:
    cases = json.load(handle)
results = []
for argv in cases:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = exc.code
    try:
        status = json.loads(out.getvalue()).get("status")
    except ValueError:
        status = None
    results.append({"argv": argv, "exit": code, "status": status})
report = {"file": loquitur.verify.__file__, "attempts": attempts, "results": results}
print("VERDICT-PATH-ISOLATION " + json.dumps(report))
"""


def _require_siblings() -> bool:
    return os.environ.get(REQUIRE_SIBLINGS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


# The outcomes a run may end in (report-contract.md section 3.1), by process exit: the three
# evidence outcomes, and the two that are not evidence and still carry a report, an unsupported
# version and a host failure. Exit 3 (a fault of the tool) and 64 (no report) are never an outcome
# of a fixture or a corpus bundle.
OUTCOMES = {0: "OFFLINE_OK", 1: "OFFLINE_FAIL", 2: "OFFLINE_REVIEW", 4: "UNSUPPORTED_VERSION", 5: "HOST_FAILURE"}
# An instant inside every window of the fixture trust registry.
EVALUATION_TIME = "2026-05-10T00:00:00Z"


def offline_cases(scratch: Path) -> tuple[list[list[str]], list[str]]:
    """The CLI invocations to run, and any problem assembling them (a violation)."""

    problems: list[str] = []
    cases: list[list[str]] = []
    bundles = sorted(
        path for path in FIXTURES.iterdir() if path.name.endswith("_bundle") or path.name.endswith("_bundle.zip")
    )
    if not bundles:
        problems.append(f"offline: no fixture bundles under {FIXTURES}")
    cases.extend([str(path), "--json"] for path in bundles)

    link_bundle = FIXTURES / "link_valid_bundle"
    entries = sorted(
        [*FIXTURES.glob("link_*_registry_entry.json"), *FIXTURES.glob("authorization_*_registry_entry.json")]
    )
    registries = sorted(FIXTURES.glob("authorization_*_trust_registry.json"))
    cases.extend([str(link_bundle), "--registry-entry", str(entry), "--json"] for entry in entries)
    valid_entry = FIXTURES / "authorization_valid_registry_entry.json"
    # Each trust registry with and without the operator's evaluation time: the window rows are
    # evaluated only with one (trust-registry-authorization.md section 2).
    cases.extend(
        [str(link_bundle), "--registry-entry", str(valid_entry), "--trust-registry", str(registry), "--json"] + timed
        for registry in registries
        for timed in ([], ["--evaluation-time", EVALUATION_TIME])
    )
    valid_trust = FIXTURES / "authorization_valid_trust_registry.json"
    if valid_entry.is_file() and valid_trust.is_file():
        public_key = json.loads(valid_trust.read_text(encoding="utf-8"))["entries"][0]["public_key_hex"]
        roots = scratch / "trust-roots.json"
        roots.write_text(
            json.dumps(
                {
                    "object_type": "trust_root_document",
                    "schema_version": "v1",
                    "roots": [
                        {
                            "key_id": "isolation-check-root",
                            "key_type": "secp256k1",
                            "public_key_hex": public_key,
                            "not_before": "2000-01-01T00:00:00Z",
                            "not_after": "2100-01-01T00:00:00Z",
                            "status": "active",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        # The fixture registry carries no root signature, so this is a FAIL, reached
        # through the root-authentication code, which is the point of running it.
        cases.append(
            [str(link_bundle), "--registry-entry", str(valid_entry), "--trust-registry", str(valid_trust)]
            + ["--trust-root", str(roots), "--json", "--evaluation-time", EVALUATION_TIME]
        )
    else:
        problems.append("offline: the authorization fixtures are missing")

    if CONFORMANCE_LOCK.is_file():
        corpus, corpus_problems = _pinned_corpus_bundles(scratch)
        problems.extend(corpus_problems)
        cases.extend([str(path), "--json"] for path in corpus)
    elif _require_siblings():
        problems.append(f"offline: {REQUIRE_SIBLINGS_ENV}=1 but {CONFORMANCE_LOCK} is absent")
    return cases, problems


def _pinned_corpus_bundles(scratch: Path) -> tuple[list[Path], list[str]]:
    """The bundle directories of the archive CONFORMANCE_LOCK.json pins, extracted into ``scratch``."""

    lock = json.loads(CONFORMANCE_LOCK.read_text(encoding="utf-8"))
    archive = PROTOCOL / lock["artifact"]
    try:
        data = archive.read_bytes()
    except OSError as exc:
        return [], [f"offline: the pinned corpus {archive} cannot be read: {exc}"]
    if hashlib.sha256(data).hexdigest() != lock["sha256"]:
        return [], [f"offline: {archive} is not the archive CONFORMANCE_LOCK.json pins"]
    target = scratch / "corpus"
    with zipfile.ZipFile(archive) as handle:
        # The archive is pinned by digest, and only the bundle members are written.
        members = [name for name in handle.namelist() if name.startswith(CORPUS_BUNDLES)]
        handle.extractall(target, members=members)
    root = target / CORPUS_BUNDLES
    found = root.iterdir() if root.is_dir() else ()
    corpus = sorted(path for path in found if path.is_dir() and path.name.endswith("_bundle"))
    return corpus, ([] if corpus else [f"offline: the pinned corpus {archive} holds no bundles"])


def offline_violations(package: Path, source_root: Path | None) -> tuple[list[str], int]:
    with tempfile.TemporaryDirectory() as scratch:
        cases, violations = offline_cases(Path(scratch))
        report = _run_child(OFFLINE_CHILD, source_root, cases)
    if "error" in report:
        return [*violations, f"offline: {report['error']}"], 0
    violations.extend(f"offline: network attempt recorded: {attempt}" for attempt in report["attempts"])
    for result in report["results"]:
        if OUTCOMES.get(result["exit"]) != result["status"]:
            violations.append(f"offline: no outcome (exit {result['exit']}) for {' '.join(result['argv'])}")
    if len(report["results"]) != len(cases) or not cases:
        violations.append(f"offline: ran {len(report['results'])} of {len(cases)} cases")
    if not Path(report["file"]).resolve().is_relative_to(package):
        violations.append(f"offline: imported {report['file']}, not the package the static check read ({package})")
    return violations, len(report["results"])


# --------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-root", type=Path, help="directory containing loquitur/verify to check instead")
    args = parser.parse_args(argv)
    source_root = args.source_root.resolve() if args.source_root is not None else None

    package = package_dir(source_root)
    static, modules = static_violations(package)
    runtime = runtime_violations(package, source_root)
    offline, runs = offline_violations(package, source_root)
    violations = static + runtime + offline
    for violation in violations:
        print(f"FORBIDDEN {violation}")
    if violations:
        print(f"verdict path isolation FAILED: {len(violations)} violation(s) in {package}")
        return 1
    closure = ", ".join(sorted(GUARDS.runtime_dependency_closure()))
    print(
        f"verdict path isolation OK: {modules} modules parsed importing only the standard library outside its "
        f"network modules, this namespace and the runtime dependency closure [{closure}]; a fresh import loaded "
        f"nothing else; {runs} CLI runs with sockets refused attempted no network access"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
