from __future__ import annotations

import importlib.util
import io
import tarfile
import warnings
from pathlib import Path

import pytest
from repository import tool


def _load_gate_module():
    return tool("local_wheel_gate")


def test_pyproject_build_probe_handles_missing_build_without_traceback(monkeypatch) -> None:
    gate = _load_gate_module()

    def fake_find_spec(name: str):
        if name == "build":
            return None
        raise AssertionError(f"unexpected probe for {name}")

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    assert gate._has_pyproject_build_main() is False


def test_pyproject_build_probe_handles_partial_build_install_without_traceback(monkeypatch) -> None:
    gate = _load_gate_module()

    class DummySpec:
        pass

    def fake_find_spec(name: str):
        if name == "build":
            return DummySpec()
        if name == "build.__main__":
            raise ModuleNotFoundError("No module named 'build.__main__'")
        raise AssertionError(f"unexpected probe for {name}")

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    assert gate._has_pyproject_build_main() is False


def test_main_uses_temporary_dist_dir_by_default(monkeypatch, tmp_path) -> None:
    gate = _load_gate_module()
    verify_root = tmp_path / "verify"
    verify_root.mkdir()
    captured: dict[str, Path] = {}

    def fake_build_wheel(root: Path, dist_dir: Path) -> Path:
        captured["root"] = root
        captured["dist_dir"] = dist_dir
        dist_dir.mkdir(parents=True, exist_ok=True)
        wheel = dist_dir / "loquitur_verify-0.1.0-py3-none-any.whl"
        wheel.write_text("fake", encoding="utf-8")
        return wheel

    class DummyEnvBuilder:
        def __init__(self, **_: object) -> None:
            pass

        def create(self, _: Path) -> None:
            pass

    calls: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> None:
        calls.append(args)

    monkeypatch.setattr(gate, "build_wheel", fake_build_wheel)
    # fake_build_wheel writes the four bytes "fake", not a zip. The source-match
    # check has its own tests below; this one is about where dist/ lands.
    monkeypatch.setattr(gate, "assert_wheel_matches_source", lambda wheel, root: None)
    monkeypatch.setattr(gate.venv, "EnvBuilder", DummyEnvBuilder)
    monkeypatch.setattr(gate, "_run", fake_run)

    assert gate.main(["--verify-root", str(verify_root)]) == 0
    assert captured["root"] == verify_root.resolve()
    assert captured["dist_dir"] != verify_root.resolve() / "dist"
    assert verify_root.resolve() not in captured["dist_dir"].parents
    assert calls, "expected install and CLI smoke commands to be invoked"


def test_build_wheel_reports_locked_dist_dir(monkeypatch, tmp_path) -> None:
    import pytest

    gate = _load_gate_module()
    verify_root = tmp_path / "verify"
    dist_dir = verify_root / "dist"
    dist_dir.mkdir(parents=True)

    def raise_permission_error(_: Path) -> None:
        raise PermissionError("locked")

    monkeypatch.setattr(gate.shutil, "rmtree", raise_permission_error)

    with pytest.raises(RuntimeError, match="could not remove existing dist directory"):
        gate.build_wheel(verify_root, dist_dir)


def test_pyproject_build_uses_isolation_by_default(monkeypatch, tmp_path) -> None:
    gate = _load_gate_module()
    calls: list[list[str]] = []

    monkeypatch.setattr(gate, "_has_pyproject_build_main", lambda: True)

    def fake_run(args: list[str], **_: object) -> None:
        calls.append(args)

    monkeypatch.setattr(gate, "_run", fake_run)

    assert gate._build_with_pyproject_build(tmp_path, tmp_path / "dist") is True
    assert calls
    assert "--no-isolation" not in calls[0]
    assert calls[0][:4] == [gate.sys.executable, "-m", "build", "--wheel"]


def test_build_wheel_falls_back_to_pip_wheel_before_raw_setuptools(monkeypatch, tmp_path) -> None:
    gate = _load_gate_module()
    verify_root = tmp_path / "verify"
    dist_dir = tmp_path / "dist"
    verify_root.mkdir()

    calls: list[str] = []

    monkeypatch.setattr(gate, "_build_with_pyproject_build", lambda root, dist: False)

    def fake_pip_wheel(root: Path, dist: Path) -> bool:
        calls.append("pip")
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "loquitur_verify-0.1.0-py3-none-any.whl").write_text("fake", encoding="utf-8")
        return True

    def fake_setuptools(root: Path, dist: Path) -> None:
        calls.append("setuptools")

    monkeypatch.setattr(gate, "_build_with_pip_wheel", fake_pip_wheel)
    monkeypatch.setattr(gate, "_build_with_setuptools_backend", fake_setuptools)

    wheel = gate.build_wheel(verify_root, dist_dir)

    assert wheel.name == "loquitur_verify-0.1.0-py3-none-any.whl"
    assert calls == ["pip"]


LICENSE_TEXTS = {"LICENSE-MIT": b"MIT text\n", "NOTICE": b"notice\n"}


def _fake_tree(
    tmp_path, wheel_members: dict[str, bytes], licenses: dict[str, bytes] = LICENSE_TEXTS
) -> tuple[Path, Path]:
    """A minimal verify root plus a wheel, so the source-match check has both sides.

    The root declares LICENSE_TEXTS as its license files; the wheel carries `licenses`.
    """
    import zipfile

    verify_root = tmp_path / "verify"
    package = verify_root / "src" / "loquitur" / "verify"
    package.mkdir(parents=True)
    (package / "cli.py").write_bytes(b"print('cli')\n")
    (package / "py.typed").write_bytes(b"")
    (verify_root / "pyproject.toml").write_text(
        '[project]\nlicense-files = ["LICENSE-MIT", "NOTICE"]\n', encoding="utf-8"
    )
    for name, text in LICENSE_TEXTS.items():
        (verify_root / name).write_bytes(text)
    wheel = tmp_path / "loquitur_verify-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in wheel_members.items():
            archive.writestr(name, payload)
        archive.writestr("loquitur_verify-0.1.0.dist-info/METADATA", "Name: loquitur-verify\n")
        for name, text in licenses.items():
            archive.writestr(f"loquitur_verify-0.1.0.dist-info/licenses/{name}", text)
    return verify_root, wheel


def _fake_sdist(dist_dir: Path, licenses: dict[str, bytes] = LICENSE_TEXTS) -> Path:
    """An sdist holding `licenses` at its root."""
    sdist = dist_dir / "loquitur_verify-0.1.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, text in licenses.items():
            info = tarfile.TarInfo(f"loquitur_verify-0.1.0/{name}")
            info.size = len(text)
            archive.addfile(info, io.BytesIO(text))
    return sdist


VALID_MEMBERS = {"loquitur/verify/cli.py": b"print('cli')\n", "loquitur/verify/py.typed": b""}


def test_wheel_matching_source_is_accepted(tmp_path) -> None:
    gate = _load_gate_module()
    verify_root, wheel = _fake_tree(tmp_path, VALID_MEMBERS)

    gate.assert_wheel_matches_source(wheel, verify_root)


def test_wheel_carrying_a_module_absent_from_src_is_rejected(tmp_path) -> None:
    # The uncleaned build/lib leak: setuptools zips build/lib, which keeps files
    # that src/ does not have, or never had. `twine check` passes such a wheel.
    import pytest

    gate = _load_gate_module()
    members = dict(VALID_MEMBERS, **{"loquitur/verify/_leftover.py": b"DSN = 'private'\n"})
    verify_root, wheel = _fake_tree(tmp_path, members)

    with pytest.raises(RuntimeError, match=r"not in src/=\['loquitur/verify/_leftover\.py'\]"):
        gate.assert_wheel_matches_source(wheel, verify_root)


def test_wheel_built_from_stale_bytes_is_rejected(tmp_path) -> None:
    # Same module name, older bytes: a wheel that would miss a command-line option.
    import pytest

    gate = _load_gate_module()
    members = dict(VALID_MEMBERS, **{"loquitur/verify/cli.py": b"print('old cli')\n"})
    verify_root, wheel = _fake_tree(tmp_path, members)

    with pytest.raises(RuntimeError, match=r"bytes differ=\['loquitur/verify/cli\.py'\]"):
        gate.assert_wheel_matches_source(wheel, verify_root)


def test_wheel_missing_a_source_module_is_rejected(tmp_path) -> None:
    import pytest

    gate = _load_gate_module()
    verify_root, wheel = _fake_tree(tmp_path, {"loquitur/verify/cli.py": b"print('cli')\n"})

    with pytest.raises(RuntimeError, match=r"missing from wheel=\['loquitur/verify/py\.typed'\]"):
        gate.assert_wheel_matches_source(wheel, verify_root)


def test_check_dist_rejects_a_leftover_artifact_from_an_earlier_version(tmp_path) -> None:
    # `twine upload dist/*` uploads every file it finds, and PyPI takes a filename
    # once, forever. dist/ is gitignored, so a leftover is invisible to review.
    import pytest

    gate = _load_gate_module()
    verify_root, wheel = _fake_tree(tmp_path, VALID_MEMBERS)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    wheel.replace(dist_dir / wheel.name)
    (dist_dir / "loquitur_verify-0.1.0.tar.gz").write_bytes(b"sdist")
    (dist_dir / "loquitur_verify-0.0.9-py3-none-any.whl").write_bytes(b"stale")

    with pytest.raises(RuntimeError, match="must hold exactly"):
        gate.check_dist(verify_root, dist_dir, "0.1.0")


def test_check_dist_accepts_exactly_the_current_pair(tmp_path) -> None:
    gate = _load_gate_module()
    verify_root, wheel = _fake_tree(tmp_path, VALID_MEMBERS)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    wheel.replace(dist_dir / wheel.name)
    _fake_sdist(dist_dir)

    gate.check_dist(verify_root, dist_dir, "0.1.0")


@pytest.mark.parametrize(
    ("in_wheel", "in_sdist", "refused"),
    [
        ({"LICENSE-MIT": b"MIT text\n"}, LICENSE_TEXTS, "loquitur_verify-0.1.0-py3-none-any.whl: NOTICE"),
        (LICENSE_TEXTS, {"NOTICE": b"notice\n"}, "loquitur_verify-0.1.0.tar.gz: LICENSE-MIT"),
        (LICENSE_TEXTS, {**LICENSE_TEXTS, "NOTICE": b"another notice\n"}, "loquitur_verify-0.1.0.tar.gz: NOTICE"),
    ],
    ids=["wheel without NOTICE", "sdist without a license text", "sdist with another NOTICE"],
)
def test_check_dist_refuses_artifacts_without_the_license_files(
    in_wheel: dict[str, bytes], in_sdist: dict[str, bytes], refused: str, tmp_path
) -> None:
    # The package members can match src/ exactly while a license text is missing from the
    # distribution that declares the license.
    gate = _load_gate_module()
    verify_root, wheel = _fake_tree(tmp_path, VALID_MEMBERS, licenses=in_wheel)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    wheel.replace(dist_dir / wheel.name)
    _fake_sdist(dist_dir, in_sdist)

    with pytest.raises(RuntimeError, match="license files missing") as refusal:
        gate.check_dist(verify_root, dist_dir, "0.1.0")
    assert str(refusal.value).endswith(f"[{refused!r}]")


def _sdist(tmp_path: Path, *members: tarfile.TarInfo, payload: bytes = b"print('ok')\n") -> Path:
    sdist = tmp_path / "loquitur_verify-0.1.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo("loquitur_verify-0.1.0/tools/example.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        for member in members:
            archive.addfile(member)
    return sdist


def test_extract_sdist_writes_the_members_without_a_warning(tmp_path) -> None:
    # The gate's output is read by whoever releases: on Python 3.12 and later an extraction
    # with no explicit filter prints a DeprecationWarning into every --check-dist run.
    gate = _load_gate_module()
    destination = tmp_path / "out"
    destination.mkdir()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        gate.extract_sdist(_sdist(tmp_path), destination)
    assert (destination / "loquitur_verify-0.1.0" / "tools" / "example.py").read_bytes() == b"print('ok')\n"


def test_extract_sdist_refuses_a_link_that_leaves_the_destination(tmp_path) -> None:
    gate = _load_gate_module()
    link = tarfile.TarInfo("loquitur_verify-0.1.0/escape")
    link.type = tarfile.SYMTYPE
    link.linkname = "../../outside"
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(tarfile.FilterError):
        gate.extract_sdist(_sdist(tmp_path, link), destination)


def test_check_sdist_refuses_the_apache_only_file(tmp_path) -> None:
    """NOTICE: the Wycheproof vector file is under the Apache License 2.0 only, so an sdist whose
    License-Expression is MIT OR Apache-2.0 must not carry it. Refused before anything is run."""
    gate = _load_gate_module()
    vectors = tarfile.TarInfo(f"loquitur_verify-0.1.0/{gate.APACHE_ONLY_FILE}")
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    _sdist(dist_dir, vectors)
    with pytest.raises(SystemExit, match="Apache License 2.0 only"):
        gate.check_sdist_is_self_verifying(tmp_path, dist_dir)
