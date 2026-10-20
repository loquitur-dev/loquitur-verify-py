#!/usr/bin/env python3
"""Local release gate for the extracted loquitur-verify package.

This script intentionally stays outside the package runtime. It builds a wheel,
installs it into a temporary virtual environment, and runs the installed console
script over the golden fixtures: the integrity check on the valid bundle, then the link
check and the authorization check on the link bundle with a registry entry and a trust
registry supplied locally. It is meant for local and CI checks and must not be imported by
the verifier runtime.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from collections.abc import Mapping
from pathlib import Path

# The environment variable that turns a sibling-dependent skip into a failure. It is the
# workspace's way of saying "every repository is checked out here, so an absent one is a
# defect", and it must not reach the extracted source distribution, which is deliberately
# alone: see `extracted_suite_environment`.
SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS"


def extracted_suite_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment the extracted sdist's own suite runs in.

    This gate measures one configuration: a fresh virtual environment holding the sdist
    and pytest, with no sibling repository beside the extracted tree. Several test modules
    need a sibling and skip there, and `LOQUITUR_REQUIRE_SIBLINGS` turns exactly those
    skips into failures. The variable therefore decides what the gate measures, and inheriting
    it means the gate measures the operator instead of the artifact.

    It is removed rather than trusted to be absent: an environment that sets it would turn
    the same artifact red, with collection errors, for a reason that has nothing to do with
    the source distribution.
    """
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if key != SIBLINGS_ENV}


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    expect_code: int = 0,
    expect_reason: str = "",
) -> None:
    """Run a command and require an exact exit code.

    `expect_code` exists because one smoke in this gate is required to exit non-zero:
    the authorization fixture has no pinned trust root, so a correct verifier must return 2. That
    check has to go through this helper rather than call subprocess directly: the gate
    tests stub `_run`, and a direct call escapes the stub and shells out for real.
    """
    completed = subprocess.run(args, cwd=cwd, env=env, check=expect_code == 0)
    if completed.returncode != expect_code:
        reason = f" ({expect_reason})" if expect_reason else ""
        raise SystemExit(f"expected exit {expect_code}{reason} from {args[0]} and got {completed.returncode}")


def _has_pyproject_build_main() -> bool:
    # `python -m build` is optional for this local gate because the project can
    # fall back to the configured PEP 517 backend. Probe without emitting a
    # traceback when the package is absent or partially installed.
    try:
        import importlib.util

        if importlib.util.find_spec("build") is None:
            return False
        return importlib.util.find_spec("build.__main__") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _build_with_pyproject_build(verify_root: Path, dist_dir: Path) -> bool:
    # Prefer the standard frontend with build isolation. On Windows, the
    # interpreter-visible setuptools/wheel versions may lag behind
    # pyproject.toml build-system requirements even when editable installs work.
    # Isolation lets the frontend provision the pinned setuptools instead of
    # falling through to an older local backend.
    if not _has_pyproject_build_main():
        return False
    try:
        _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)], cwd=verify_root)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _build_with_pip_wheel(verify_root: Path, dist_dir: Path) -> bool:
    # Secondary fallback: pip's wheel command also performs PEP 517 build
    # isolation by default. This is safer than directly importing
    # setuptools.build_meta from an environment that may not satisfy
    # build-system.requires.
    try:
        _run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--wheel-dir", str(dist_dir)], cwd=verify_root)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _build_with_setuptools_backend(verify_root: Path, dist_dir: Path) -> None:
    script = f"import setuptools.build_meta as backend; print(backend.build_wheel({str(dist_dir)!r}))"
    _run([sys.executable, "-c", script], cwd=verify_root)


def purge_build_tree(verify_root: Path) -> None:
    """Delete build/ and src/*.egg-info before building.

    setuptools' build_py copies src/ into build/lib and never removes anything
    from build/lib; bdist_wheel then zips whatever that directory contains. A
    module deleted from src/, or one that was never in src/ and never in git,
    therefore survives there and is packaged. Every wheel-only path in this file
    (`python -m build --wheel`, `pip wheel .`, the backend call) reads build/lib,
    so without the purge the gate could certify a wheel that the source tree cannot
    explain. Only the sdist-first `python -m build` is immune, because MANIFEST.in
    prunes build/.

    Best-effort on purpose: a virus scanner or an indexer can hold a file here for
    a second, and refusing to build over a transient lock would fail closed on a
    legitimate release. The check that must not be best-effort is
    ``assert_wheel_matches_source`` below, which inspects the artifact itself and
    therefore catches the consequence whether or not this purge succeeded.
    """
    for path in [verify_root / "build", *verify_root.glob("src/*.egg-info")]:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def _source_package_files(verify_root: Path) -> dict[str, bytes]:
    src_root = verify_root / "src"
    return {
        path.relative_to(src_root).as_posix(): path.read_bytes()
        for path in sorted((src_root / "loquitur").rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }


def assert_wheel_matches_source(wheel: Path, verify_root: Path) -> None:
    """Require the wheel's package members to be exactly the source tree's.

    `twine check` renders the long description and nothing else: it passes a
    wheel carrying an out-of-tree module and it passes a wheel built from stale
    bytes, which could miss a whole command-line option while every other gate
    stays green. This is the check that can see it. It rejects three things and
    accepts nothing else: a member that is not in src/, a src/ file missing from
    the wheel, and a member whose bytes differ from the file it claims to be.
    """
    import zipfile

    expected = _source_package_files(verify_root)
    with zipfile.ZipFile(wheel) as archive:
        shipped = {name: archive.read(name) for name in archive.namelist() if name.startswith("loquitur/")}
    not_in_source = sorted(set(shipped) - set(expected))
    missing_from_wheel = sorted(set(expected) - set(shipped))
    bytes_differ = sorted(name for name in set(shipped) & set(expected) if shipped[name] != expected[name])
    if not_in_source or missing_from_wheel or bytes_differ:
        raise RuntimeError(
            f"{wheel.name} does not match src/: "
            f"not in src/={not_in_source}; missing from wheel={missing_from_wheel}; bytes differ={bytes_differ}"
        )


# The sdist alone, with no optional extra, runs this many tests. The narrative modules
# need loquitur-schemas and skip without it, which is the same honest outcome a reviewer
# gets. The floor exists so the check cannot pass on a suite that collects nothing.
MINIMUM_SDIST_TESTS = 250
# The repository file MANIFEST.in keeps out of the source distribution: it is under the Apache
# License, Version 2.0 only (NOTICE).
APACHE_ONLY_FILE = "tests/vectors/ecdsa_secp256k1_sha256_p1363_test.json"


def _short_extraction_root() -> str | None:
    """Where to extract the sdist, or None for the platform default.

    Windows only, and only when it works. The longest member path plus a deep temporary
    directory can exceed the classic 260-character limit, and extraction then fails with an
    unhelpful "could not create"; extracting under the drive root buys the margin back.

    On POSIX `Path("/tmp").anchor` is "/", the filesystem root, where a runner cannot
    create a directory. A workaround for one platform must not become a requirement on the
    others, so this returns None everywhere else, and also when the drive root turns out
    not to be writable.
    """
    if sys.platform != "win32":
        return None
    anchor = Path(tempfile.gettempdir()).anchor
    if not anchor:
        return None
    try:
        probe = Path(tempfile.mkdtemp(prefix="lqv-probe-", dir=anchor))
    except OSError:
        return None
    probe.rmdir()
    return anchor


def extract_sdist(sdist: Path, destination: Path) -> None:
    """Extract ``sdist`` into ``destination``, refusing a member that would land outside it.

    An absolute or ``..`` member name is refused by name first. The extraction then uses
    tarfile's ``data`` filter wherever the running Python provides it (3.11.4 and later),
    which also refuses links that point outside the destination, device files and
    absolute link targets; without an explicit filter, Python 3.12 and later warn that the
    default changes, and the warning would appear in every run of this gate.
    """
    import tarfile

    with tarfile.open(sdist) as archive:
        for info in archive.getmembers():
            if info.name.startswith("/") or ".." in Path(info.name).parts:
                raise SystemExit(f"unsafe sdist member path: {info.name}")
        if hasattr(tarfile, "data_filter"):
            archive.extractall(destination, filter="data")
        else:  # pragma: no cover - Python 3.11 before 3.11.4
            archive.extractall(destination)


def check_sdist_is_self_verifying(verify_root: Path, dist_dir: Path) -> None:
    """Extract the sdist and run its own test suite, with nothing but pytest.

    MANIFEST.in ships `tests/`, `tools/` and `docs/` on purpose: this package's whole
    thesis is that a claim should be checkable by the recipient rather than taken on
    trust, and a reviewer who downloads the source distribution can run the proofs
    without cloning anything, without network and without trusting a git host. That is a
    promise, and a promise nothing checks is a wish.

    Two ways it breaks are easy to miss: grafting `tests` without `docs` leaves tests
    reading files that were not shipped, so the suite is red the moment anyone extracts it,
    which is worse than shipping no tests at all; and `recursive-exclude __pycache__ *` does not
    match nested directories, so .pyc files compiled on one machine go into the archive.
    A package index keeps what it is given, forever.

    Bytecode is refused outright rather than merely counted: it is never correct here, and
    a threshold would only invite someone to tune it.
    """
    import tarfile
    import tempfile

    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(sdists) != 1:
        raise SystemExit(f"expected exactly one sdist in {dist_dir}, found {[p.name for p in sdists]}")
    sdist = sdists[0]

    with tarfile.open(sdist) as archive:
        members = archive.getnames()
    compiled = [name for name in members if name.endswith(".pyc") or "__pycache__" in name]
    if compiled:
        raise SystemExit(
            f"the sdist carries {len(compiled)} compiled or cached files, which are machine- and "
            f"interpreter-specific and cannot be corrected after upload: {compiled[:5]}"
        )
    # NOTICE: the one Apache-2.0-only file of the repository is left out (MANIFEST.in), so the
    # License-Expression MIT OR Apache-2.0 covers every file the sdist holds (PEP 639).
    apache_only = [name for name in members if name.endswith("/" + APACHE_ONLY_FILE)]
    if apache_only:
        raise SystemExit(
            f"the sdist carries {apache_only[0]}, which is under the Apache License 2.0 only (NOTICE); "
            "its License-Expression MIT OR Apache-2.0 would not cover it"
        )
    for required in ("tests", "docs", "tools"):
        if not any(f"/{required}/" in name for name in members):
            raise SystemExit(
                f"the sdist ships no {required}/ directory; MANIFEST.in promises a source "
                f"distribution a reviewer can run, and this one cannot be run as shipped"
            )

    with tempfile.TemporaryDirectory(prefix="lqv-", dir=_short_extraction_root()) as raw:
        destination = Path(raw)
        extract_sdist(sdist, destination)
        extracted = destination / sdist.name[: -len(".tar.gz")]

        # A clean environment with the sdist installed into it, which is what a reviewer
        # does. Running the outer interpreter instead would measure whatever happens to be
        # installed on the release machine (whether loquitur-schemas is importable there,
        # for one), and a gate whose result depends on the operator's site-packages
        # measures the operator.
        environment = destination / "env"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        _run([str(python), "-m", "pip", "install", "--quiet", str(sdist), "pytest"])
        result = subprocess.run(
            [str(python), "-m", "pytest", "-q"],
            cwd=extracted,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            env={**extracted_suite_environment(), "PYTHONIOENCODING": "utf-8"},
        )
        if result.returncode != 0:
            raise SystemExit(
                "the extracted sdist does not pass its own test suite; a source distribution that "
                "ships red tests is worse evidence than one that ships none:\n"
                + result.stdout[-3000:]
                + result.stderr[-2000:]
            )
        summary = result.stdout.strip().splitlines()[-1]
        # Anti-vacuity. A suite that collects nothing exits 0 too, and "no tests ran" would
        # satisfy every assertion above while proving nothing at all.
        passed = int(summary.split(" passed")[0].split()[-1]) if " passed" in summary else 0
        if passed < MINIMUM_SDIST_TESTS:
            raise SystemExit(
                f"the extracted sdist ran only {passed} tests, below the {MINIMUM_SDIST_TESTS} floor; "
                f"a source distribution that ships a suite which does not run is not evidence"
            )
        print(f"sdist_self_verifying_ok {summary}")


def check_dist(verify_root: Path, dist_dir: Path, version: str) -> None:
    """Validate the artifacts that `twine upload dist/*` would actually send.

    dist/ is gitignored, so an artifact from an earlier build survives there
    unseen and `twine upload dist/*` uploads every file it finds. PyPI accepts a
    filename once, forever. Requiring exactly one wheel and one sdist, both at
    the version in pyproject.toml, is what stops a leftover from being published
    alongside the intended one.
    """
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    expected_wheel = f"loquitur_verify-{version}-py3-none-any.whl"
    expected_sdist = f"loquitur_verify-{version}.tar.gz"
    if [w.name for w in wheels] != [expected_wheel] or [s.name for s in sdists] != [expected_sdist]:
        raise RuntimeError(
            f"{dist_dir} must hold exactly {expected_wheel} and {expected_sdist}; "
            f"found wheels={[w.name for w in wheels]} sdists={[s.name for s in sdists]}. "
            "Remove build/, dist/ and src/*.egg-info and rebuild."
        )
    assert_wheel_matches_source(wheels[0], verify_root)
    assert_license_files_shipped(wheels[0], sdists[0], verify_root, version)


def assert_license_files_shipped(wheel: Path, sdist: Path, verify_root: Path, version: str) -> None:
    """Require every `license-files` entry of pyproject.toml in the wheel and the sdist, byte for byte.

    The metadata declares `MIT OR Apache-2.0`. A distribution that left out one of the two texts,
    or NOTICE, which keeps one test-vector file under Apache-2.0 only, would declare a license
    whose terms it does not carry; assert_wheel_matches_source reads the package members only.
    """
    import tarfile
    import tomllib
    import zipfile

    names = tomllib.loads((verify_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["license-files"]
    expected = {name: (verify_root / name).read_bytes() for name in names}
    with zipfile.ZipFile(wheel) as archive:
        listed = set(archive.namelist())
        in_wheel = {
            name: archive.read(member)
            for name in names
            if (member := f"loquitur_verify-{version}.dist-info/licenses/{name}") in listed
        }
    in_sdist: dict[str, bytes] = {}
    with tarfile.open(sdist) as archive:
        for name in names:
            try:
                member = archive.extractfile(f"loquitur_verify-{version}/{name}")
            except KeyError:
                continue
            if member is not None:
                in_sdist[name] = member.read()
    wrong = [
        f"{artifact.name}: {name}"
        for artifact, shipped in ((wheel, in_wheel), (sdist, in_sdist))
        for name in names
        if shipped.get(name) != expected[name]
    ]
    if wrong:
        raise RuntimeError(f"license files missing from the artifacts or different from the source: {wrong}")


def build_wheel(verify_root: Path, dist_dir: Path, *, backend_only: bool = False) -> Path:
    purge_build_tree(verify_root)
    if dist_dir.exists():
        try:
            shutil.rmtree(dist_dir)
        except PermissionError as exc:
            raise RuntimeError(
                f"could not remove existing dist directory {dist_dir}. "
                "Close any process holding files there, or pass --dist-dir pointing to a writable temporary directory."
            ) from exc
    dist_dir.mkdir(parents=True)
    if backend_only:
        _build_with_setuptools_backend(verify_root, dist_dir)
    elif not _build_with_pyproject_build(verify_root, dist_dir):
        if not _build_with_pip_wheel(verify_root, dist_dir):
            _build_with_setuptools_backend(verify_root, dist_dir)
    wheels = sorted(dist_dir.glob("loquitur_verify-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one loquitur_verify wheel in {dist_dir}, found {wheels}")
    return wheels[0]


REPRODUCIBLE_EPOCH = "1700000000"


def check_reproducible(root: Path) -> str:
    """Build the wheel twice and require byte-identical output.

    Institutional supply-chain review expects a published artifact hash to be
    independently reproducible. Wheel archives embed modification timestamps, so
    reproducibility requires SOURCE_DATE_EPOCH to be fixed at build time; this
    verifies that it is sufficient rather than assuming it.
    """
    import hashlib
    import os

    purge_build_tree(root)
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = REPRODUCIBLE_EPOCH
    env["PYTHONHASHSEED"] = "0"
    digests: list[str] = []
    for index in range(2):
        with tempfile.TemporaryDirectory(prefix=f"repro-{index}-") as tmp:
            dist = Path(tmp)
            subprocess.run(
                [sys.executable, "-m", "pip", "wheel", str(root), "--no-deps", "-w", str(dist)],
                env={**env, "PYTHONIOENCODING": "utf-8"},
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            wheels = sorted(dist.glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError(f"expected exactly one wheel, found {wheels}")
            digests.append(hashlib.sha256(wheels[0].read_bytes()).hexdigest())
    if digests[0] != digests[1]:
        raise RuntimeError(
            f"wheel build is NOT reproducible with SOURCE_DATE_EPOCH={REPRODUCIBLE_EPOCH}: {digests[0]} != {digests[1]}"
        )
    return digests[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build/install/smoke-test the loquitur-verify wheel.")
    parser.add_argument("--verify-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dist-dir", type=Path, default=None)
    parser.add_argument(
        "--system-site-packages",
        action="store_true",
        help="Create the temporary venv with system site packages. Useful in offline "
        "environments where rfc8785 is already installed.",
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Install the built wheel with --no-deps. Use only when dependencies are already available in the venv.",
    )
    parser.add_argument(
        "--backend-only",
        action="store_true",
        help="Build with the configured setuptools backend directly; useful for offline RC checks.",
    )
    parser.add_argument(
        "--check-reproducible",
        action="store_true",
        help="Verify the wheel builds byte-identically twice with SOURCE_DATE_EPOCH fixed.",
    )
    parser.add_argument(
        "--check-dist",
        type=Path,
        default=None,
        help="Validate artifacts already in this directory instead of building. Run this last, "
        "immediately before `twine upload`, on the exact files that will be uploaded.",
    )
    args = parser.parse_args(argv)

    verify_root = args.verify_root.resolve()

    if args.check_dist is not None:
        import tomllib

        version = tomllib.loads((verify_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        check_dist(verify_root, args.check_dist.resolve(), version)
        print(f"dist_matches_source_ok version={version}")
        check_sdist_is_self_verifying(verify_root, args.check_dist.resolve())
        return 0

    if args.check_reproducible:
        digest = check_reproducible(verify_root)
        print(f"wheel_reproducible_ok sha256={digest}")
        return 0

    with tempfile.TemporaryDirectory(prefix="loquitur-verify-wheel-gate-") as tmp:
        work_dir = Path(tmp)
        dist_dir = args.dist_dir.resolve() if args.dist_dir else work_dir / "dist"
        if args.backend_only:
            wheel = build_wheel(verify_root, dist_dir, backend_only=True)
        else:
            wheel = build_wheel(verify_root, dist_dir)

        # Before installing it: the wheel the gate is about to certify must be the
        # source tree, exactly. Smoke checks answer "does this wheel pass the
        # fixtures"; they cannot answer "is this wheel the code that was reviewed".
        assert_wheel_matches_source(wheel, verify_root)

        venv_dir = work_dir / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=args.system_site_packages).create(venv_dir)
        if sys.platform == "win32":
            python = venv_dir / "Scripts" / "python.exe"
            cli = venv_dir / "Scripts" / "loquitur-verify.exe"
        else:
            python = venv_dir / "bin" / "python"
            cli = venv_dir / "bin" / "loquitur-verify"

        install_cmd = [str(python), "-m", "pip", "install"]
        if args.no_deps:
            install_cmd.append("--no-deps")
        install_cmd.append(str(wheel))
        _run(install_cmd)

        fixtures = verify_root / "tests" / "fixtures"

        # The structure and integrity checks: the installed verifier verifies a bundle's integrity.
        integrity_bundle = fixtures / "valid_bundle.zip"
        _run([str(cli), str(integrity_bundle), "--json"])

        # The link check: the installed verifier verifies the link to a registry entry supplied locally.
        link_bundle = fixtures / "link_valid_bundle.zip"
        link_entry = fixtures / "link_valid_registry_entry.json"
        _run([str(cli), str(link_bundle), "--registry-entry", str(link_entry), "--json"])

        # The authorization check: the installed verifier verifies the issuer signature and the
        # authorization of the issuer and its key against a trust registry supplied locally. This
        # remains local verification only; it does not verify trust-registry root
        # authenticity, registry inclusion, checkpoint consistency, or anchor finality.
        authorization_entry = fixtures / "authorization_valid_registry_entry.json"
        authorization_trust = fixtures / "authorization_valid_trust_registry.json"
        # `_run` uses check=True, and this invocation exits 2, not 0. That is the correct
        # verdict and not a defect in the wheel: an authorization run whose trust registry was never
        # authenticated against a pinned root returns REVIEW, and PINNED_TRUST_ROOTS ships
        # empty. Left as a plain `_run`, this gate, which docs/maintainers/build-checks.md
        # requires and tests/test_release_checks_0_1_0.py pins by name, would fail on
        # every good build.
        #
        # Exit 2 is accepted here and only here, with the reason named. Exit 0 is refused
        # just as loudly as a failure would be: it would mean the verifier certifies a
        # registry whose root was never authenticated.
        _run(
            [
                str(cli),
                str(link_bundle),
                "--registry-entry",
                str(authorization_entry),
                "--trust-registry",
                str(authorization_trust),
                "--json",
            ],
            expect_code=2,
            expect_reason="REVIEW: trust-registry root not pinned",
        )

    print(f"wheel_gate_ok {wheel} checks=structure,integrity,link,authorization")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
