"""The release workflow, held to the rules docs/maintainers/releasing.md states.

`.github/workflows/release.yml` runs only on a pushed vX.Y.Z tag or by hand, pins every action by
a full commit SHA, grants each job only the permissions it declares, attests what it builds, and
creates the GitHub release as a draft. It publishes nothing: no job uploads to a package index and
no step publishes the draft. A change that loosens one of these rules fails here, and the test is
changed with it on purpose or not at all. The checks that stop a release are not only read here but
run, with bash as the runner runs them, so a check that does not stop the run fails too.

The source distribution does not ship `.github/`, so in an extracted sdist the tests that read the
workflows skip and say why; in a checkout a missing workflow fails.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from repository import CI, RELEASE, ROOT, tool
from repository import workflow as _load

RELEASING = ROOT / "docs" / "maintainers" / "releasing.md"

TAG_PATTERN = "v[0-9]+.[0-9]+.[0-9]+"
LOCAL_CI = "./.github/workflows/ci.yml"
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
PIN_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s+(\S+)(.*)$")

# The steps of the verify job that stop a release.
TAG_REFUSAL = "A tag is released by pushing it, not by a dry run"
TAG_CHECK = "The tag is annotated, signed, on the commit checked out and on the default branch"
VERSION_CHECK = "The version is X.Y.Z, the tag's, and in the package metadata and CHANGELOG.md"

# The one action that makes both attestations, the provenance and the SBOM.
ATTEST = "actions/attest"

# The dry-run notice of the attest job, the same step in the four repositories: the last step of
# the job, after both attestations, under the opposite of their condition.
DRY_RUN_NOTICE = {
    "name": "Say that this dry run attested nothing",
    "if": "github.event_name != 'push' && github.event.repository.private",
    "run": 'echo "::notice::private repository, so this dry run built, summed and described the files and attested none"',
}

# The two reads of GitHub's API in the tag check. Each answer is kept in a variable, so that a
# failed call stops the run with its own error, and only then split at the tabs: bash checks the
# status of a command substitution and not that of a process substitution, so
# `read < <(gh api ...)` would take a failed call for an empty answer.
API_READ = re.compile(r"""^ *if ! (\w+)="\$\(gh api "([^"]+)" --jq '\[([^\]]+)\] \| @tsv'\)"; then$""", re.M)
API_READS = [
    ("ref", "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG", ".object.type, .object.sha"),
    (
        "tag",
        "repos/$GITHUB_REPOSITORY/git/tags/$tag_sha",
        ".object.type, .object.sha, .verification.verified, .verification.reason",
    ),
]
SPLITS = [
    "IFS=$'\\t' read -r ref_type tag_sha <<< \"$ref\"",
    "IFS=$'\\t' read -r target_type target_sha verified reason <<< \"$tag\"",
]

# Every job's permissions, exactly. The attest job signs with an OIDC token and writes
# attestations; the release job creates the draft release. Every other job only reads, the build
# job among them, which runs third-party code.
PERMISSIONS = {
    "verify": {"contents": "read"},
    "ci": {"contents": "read"},
    "build": {"contents": "read"},
    "attest": {"id-token": "write", "attestations": "write"},
    "release": {"contents": "write"},
}

# What would publish: an upload to a package index, a step that publishes the draft or changes a
# release after it is created, or a stored secret, which would be a long-lived token.
PUBLISHING = (
    "twine upload",
    "gh-action-pypi-publish",
    "npm publish",
    "uv publish",
    "flit publish",
    "poetry publish",
    "gh release edit",
    "gh release upload",
    "--draft=false",
    "secrets.",
)


def _triggers(document: dict[str, Any]) -> Any:
    # YAML 1.1 reads the bare key `on` as the boolean true.
    return document["on"] if "on" in document else document[True]


def _steps(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(name, step) for name, job in document["jobs"].items() for step in job.get("steps", [])]


def _step(job: str, name: str) -> dict[str, Any]:
    """The step of a release job with this name; there is exactly one."""
    found = [step for step in _load(RELEASE)["jobs"][job]["steps"] if step.get("name") == name]
    assert len(found) == 1, (job, name, len(found))
    return found[0]


def _bash() -> str:
    found = shutil.which("bash")
    if found is None or (sys.platform == "win32" and Path(found).parent.name.lower() in {"windowsapps", "system32"}):
        pytest.skip("no POSIX bash on this host to run the workflow's steps with")
    return found


def _run(step: dict[str, Any], where: Path, env: dict[str, str], stubs: str = "") -> subprocess.CompletedProcess[str]:
    """A step's script run as the runner runs a bash step, after `stubs`, in `where` (and its working-directory).

    The tools bash runs (find, sort, sha256sum) are the ones beside it, which on Windows are not
    the first of those names on the PATH.
    """
    bash = _bash()
    script = where / "step.sh"
    script.write_text(f"{stubs}\n{step['run']}", encoding="utf-8", newline="\n")
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", script.as_posix()],
        cwd=where / step.get("working-directory", "."),
        env={**os.environ, "PATH": str(Path(bash).parent) + os.pathsep + os.environ.get("PATH", ""), **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_release_runs_only_on_a_version_tag_or_by_hand() -> None:
    triggers = _triggers(_load(RELEASE))
    assert triggers == {"push": {"tags": [TAG_PATTERN]}, "workflow_dispatch": None}, triggers


def test_ci_keeps_its_triggers_and_can_be_called_by_the_release() -> None:
    triggers = _triggers(_load(CI))
    assert triggers == {"push": {"branches": ["main"]}, "pull_request": None, "workflow_call": None}, triggers


@pytest.mark.parametrize("workflow", [RELEASE, CI], ids=lambda path: path.name)
def test_every_action_is_pinned_by_a_full_commit_sha(workflow: Path) -> None:
    document = _load(workflow)
    uses = [step["uses"] for _, step in _steps(document) if "uses" in step]
    assert uses, f"{workflow.name} uses no action; nothing was checked"
    unpinned = [ref for ref in uses if not PINNED.match(ref)]
    assert not unpinned, f"{workflow.name}: not pinned by a 40-hex commit SHA: {unpinned}"
    # A job that calls a workflow names one in this repository, which runs at the caller's commit.
    called = [job["uses"] for job in document["jobs"].values() if "uses" in job]
    assert all(ref == LOCAL_CI for ref in called), called
    # Every pin says which tag it is, so an update can be read.
    for line in workflow.read_text(encoding="utf-8").splitlines():
        match = PIN_LINE.match(line)
        if match and not match.group(1).startswith("./"):
            assert re.fullmatch(r"\s+# v\d+\.\d+\.\d+", match.group(2)), line


def test_one_action_is_pinned_to_one_commit_across_the_workflows() -> None:
    pins: dict[str, set[str]] = {}
    for workflow in (RELEASE, CI):
        for _, step in _steps(_load(workflow)):
            if "uses" in step:
                action, sha = step["uses"].split("@")
                pins.setdefault(action, set()).add(sha)
    split = {action: shas for action, shas in pins.items() if len(shas) > 1}
    assert not split, split


def test_permissions_are_declared_per_job_and_only_the_needed_ones_write() -> None:
    document = _load(RELEASE)
    assert document["permissions"] == {}, "the workflow grants nothing by default"
    declared = {name: job.get("permissions") for name, job in document["jobs"].items()}
    assert declared == PERMISSIONS, declared
    text = RELEASE.read_text(encoding="utf-8")
    assert "write-all" not in text and "read-all" not in text


def test_the_attest_job_attests_every_file_and_the_sbom() -> None:
    # Both attestations are one action, `actions/attest`: a step that gives it an `sbom-path`
    # attests that SBOM, and a step that gives none attests the provenance.
    document = _load(RELEASE)
    attesting = [(name, step) for name, step in _steps(document) if step.get("uses", "").split("@")[0] == ATTEST]
    assert {name for name, _ in attesting} == {"attest"}, attesting
    assert len(attesting) == 2, attesting
    [provenance] = [step for _, step in attesting if "sbom-path" not in step["with"]]
    [sbom] = [step for _, step in attesting if "sbom-path" in step["with"]]
    assert set(provenance["with"]) == {"subject-path"}
    assert provenance["with"]["subject-path"].split() == [
        "dist/*.tar.gz",
        "dist/*.whl",
        "dist/*.cdx.json",
        "dist/SHA256SUMS",
    ]
    assert sbom["with"]["subject-path"].split() == ["dist/*.tar.gz", "dist/*.whl"]
    assert sbom["with"]["sbom-path"] == "dist/loquitur_verify-${{ needs.verify.outputs.version }}.cdx.json"
    assert set(sbom["with"]) == {"subject-path", "sbom-path"}
    # A tag push always attests; only a dry run in a private repository may skip.
    for step in (provenance, sbom):
        assert step["if"] == "github.event_name == 'push' || !github.event.repository.private"
    # The provenance, then the SBOM; a dry run that attests nothing says so, in the job's last step,
    # under the opposite condition.
    attest = document["jobs"]["attest"]["steps"]
    assert attest[-3:-1] == [provenance, sbom]
    assert attest[-1] == DRY_RUN_NOTICE


def test_the_attest_job_runs_no_code_of_its_own_and_checks_the_files_first() -> None:
    # The attest job holds the token that signs, so it checks out nothing, installs nothing and
    # runs only the pinned actions and its own shell lines, after checking the file set and the sums.
    document = _load(RELEASE)
    attest = document["jobs"]["attest"]
    assert attest["needs"] == ["verify", "build"]
    actions = [step["uses"].split("@")[0] for step in attest["steps"] if "uses" in step]
    assert actions == ["actions/download-artifact", ATTEST, ATTEST], actions
    assert attest["steps"][0]["with"]["name"] == "release-files"
    runs = "\n".join(step.get("run", "") for step in attest["steps"])
    fetching = re.findall(r"\b(?:pip3?|python3?|uv|npm|npx|curl|wget|git|gh)\b", runs)
    assert not fetching, fetching
    checks = [step for step in attest["steps"] if "run" in step]
    first_attestation = next(
        i for i, step in enumerate(attest["steps"]) if step.get("uses", "").split("@")[0] == ATTEST
    )
    assert attest["steps"].index(checks[0]) < first_attestation
    assert attest["steps"][0]["with"]["path"] == "dist"
    assert checks[0]["working-directory"] == "dist"
    for phrase in ("find . -mindepth 1", "SHA256SUMS", "sha256sum --strict -c SHA256SUMS"):
        assert phrase in checks[0]["run"], phrase


BUILD = "Build the sdist and the wheel"
FILES_CHECK = "The files are exactly the ones the build wrote, and match SHA256SUMS"
SDIST, WHEEL, SBOM = (
    "loquitur_verify-0.1.0.tar.gz",
    "loquitur_verify-0.1.0-py3-none-any.whl",
    "loquitur_verify-0.1.0.cdx.json",
)
# `python` as the build step calls it: `-m build` writes an sdist and a wheel, anything else does nothing.
BUILD_STUBS = f"""
python() {{
  if [ "$1 $2" = "-m build" ]; then
    mkdir -p dist
    printf sdist > dist/{SDIST}
    printf wheel > dist/{WHEEL}
    if [ -n "${{STUB_SECOND_WHEEL:-}}" ]; then printf other > dist/loquitur_verify-0.1.0-py3-none-other.whl; fi
  fi
}}
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_the_build_step_takes_the_digests_of_what_it_built_before_anything_else_runs() -> None:
    build = _load(RELEASE)["jobs"]["build"]
    assert build["outputs"] == {
        "sdist-sha256": "${{ steps.build.outputs.sdist-sha256 }}",
        "wheel-sha256": "${{ steps.build.outputs.wheel-sha256 }}",
    }
    names = [step.get("name", step.get("uses", "").split("@")[0]) for step in build["steps"]]
    # Only the checkout and the setup of the build tools run before the step that builds and takes the digests.
    assert names.index(BUILD) == 3, names
    assert _step("build", BUILD)["id"] == "build"
    assert _step("build", "A second build of the wheel gives the same bytes")["env"] == {
        "BUILT": "${{ steps.build.outputs.wheel-sha256 }}"
    }
    attest = _step("attest", FILES_CHECK)["env"]
    assert attest["SDIST_SHA256"] == "${{ needs.build.outputs.sdist-sha256 }}"
    assert attest["WHEEL_SHA256"] == "${{ needs.build.outputs.wheel-sha256 }}"


@pytest.mark.parametrize("second_wheel", [False, True])
def test_the_build_step_records_the_digest_of_one_sdist_and_one_wheel(second_wheel: bool, tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.write_text("", encoding="utf-8")
    env = {"GITHUB_OUTPUT": output.as_posix(), "STUB_SECOND_WHEEL": "1" if second_wheel else ""}
    run = _run(_step("build", BUILD), tmp_path, env, BUILD_STUBS)
    if second_wheel:
        assert run.returncode != 0 and "not one of each" in run.stdout, (run.stdout, run.stderr)
        assert output.read_text(encoding="utf-8") == ""
        return
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert output.read_text(encoding="utf-8").splitlines() == [
        f"sdist-sha256={_sha256(b'sdist')}",
        f"wheel-sha256={_sha256(b'wheel')}",
    ]


def _artifact(where: Path, wheel: bytes) -> dict[str, str]:
    """dist/ as the build job uploads it, with a wheel holding `wheel`; the environment of the check."""
    dist = where / "dist"
    dist.mkdir()
    files = {SDIST: b"sdist", WHEEL: wheel, SBOM: b"{}"}
    for name, data in files.items():
        (dist / name).write_bytes(data)
    sums = "".join(f"{_sha256(data)}  {name}\n" for name, data in sorted(files.items()))
    (dist / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    return {"VERSION": "0.1.0", "SDIST_SHA256": _sha256(b"sdist"), "WHEEL_SHA256": _sha256(b"wheel")}


def test_the_attest_job_takes_the_files_the_build_step_wrote(tmp_path: Path) -> None:
    run = _run(_step("attest", FILES_CHECK), tmp_path, _artifact(tmp_path, b"wheel"))
    assert run.returncode == 0, (run.stdout, run.stderr)


@pytest.mark.parametrize("case", ["rewritten after the build", "no digest recorded"])
def test_the_attest_job_refuses_a_wheel_other_than_the_one_built(case: str, tmp_path: Path) -> None:
    # Code that ran in the build job after the build can rewrite the wheel and write SHA256SUMS
    # over the new bytes; the digest the build step recorded names the wheel it built.
    env = _artifact(tmp_path, b"wheel" if case == "no digest recorded" else b"rewritten")
    if case == "no digest recorded":
        env["WHEEL_SHA256"] = ""
    run = _run(_step("attest", FILES_CHECK), tmp_path, env)
    assert run.returncode != 0, (case, run.stdout, run.stderr)
    assert "::error::the sdist or the wheel is not the file the build step wrote" in run.stdout


def test_the_build_job_builds_sums_and_describes_the_files_as_the_checklist_does() -> None:
    document = _load(RELEASE)
    build = document["jobs"]["build"]
    assert build["needs"] == ["ci", "verify"]
    runs = "\n".join(step.get("run", "") for step in build["steps"])
    environment = {key: value for step in build["steps"] for key, value in step.get("env", {}).items()}
    assert environment["SOURCE_DATE_EPOCH"] == tool("local_wheel_gate").REPRODUCIBLE_EPOCH
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["VERSION"] == "${{ needs.verify.outputs.version }}"
    for phrase in (
        "python -m pip install pip==26.2.1 build==1.6.1",
        # The build tree is purged by the gate's own function, not by a second list of paths.
        "from local_wheel_gate import purge_build_tree; purge_build_tree(Path.cwd())",
        "rm -rf dist\n",
        "python -m build",
        "python tools/local_wheel_gate.py --check-reproducible",
        "python tools/local_wheel_gate.py --check-dist dist",
        'python -m venv "$RUNNER_TEMP/sbom-tool"',
        '"$RUNNER_TEMP/sbom-tool/bin/python" -m pip install pip==26.2.1 cyclonedx-bom==7.5.0 cyclonedx-python-lib==11.12.0',
        '"$RUNNER_TEMP/sbom-tool/bin/cyclonedx-py" environment',
        '-o "dist/loquitur_verify-$VERSION.cdx.json"',
        "sha256sum -- *.tar.gz *.whl *.cdx.json > SHA256SUMS",
    ):
        assert phrase in runs, phrase
    assert "egg-info" not in runs
    # The SBOM tool runs from its own environment, never from the interpreter that built the files.
    assert not re.search(r"^\s*(?:python -m pip|pip) install[^\n]*cyclonedx", runs, re.M), runs
    # The sums are written beside the files, and the artifact is dist/ as the build left it.
    sums = next(step for step in build["steps"] if "SHA256SUMS" in step.get("run", ""))
    assert sums["working-directory"] == "dist"
    upload = next(step for step in build["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"] == {"name": "release-files", "path": "dist/", "if-no-files-found": "error"}


def test_the_version_is_read_once_and_every_later_job_takes_it_from_verify() -> None:
    document = _load(RELEASE)
    jobs = document["jobs"]
    assert jobs["verify"]["outputs"] == {"version": "${{ steps.version.outputs.version }}"}
    # The full CI waits for verify, so a refused tag stops the run before the matrix starts.
    assert jobs["ci"]["needs"] == "verify"
    text = RELEASE.read_text(encoding="utf-8")
    assert "tomllib" not in text
    # The build job's outputs are the digests it took, never a version of its own.
    assert set(re.findall(r"needs\.build\.outputs\.([\w-]+)", text)) == {"sdist-sha256", "wheel-sha256"}
    for name in ("build", "attest", "release"):
        assert "verify" in jobs[name]["needs"], name
        assert "${{ needs.verify.outputs.version }}" in str(jobs[name]), name
    assert "release/" not in text


def test_nothing_is_published_and_the_release_is_a_draft_of_the_pushed_tag() -> None:
    document = _load(RELEASE)
    text = RELEASE.read_text(encoding="utf-8")
    for phrase in PUBLISHING:
        assert phrase not in text, phrase
    release = document["jobs"]["release"]
    assert release["if"] == "github.event_name == 'push'"
    assert release["needs"] == ["verify", "attest"]
    creates = [step["run"] for step in release["steps"] if "gh release create" in step.get("run", "")]
    assert len(creates) == 1, creates
    command = " ".join(creates[0].replace("\\\n", " ").split())
    assert "--draft --verify-tag" in command, command
    assert command.endswith('--notes-file "$RUNNER_TEMP/release-notes.md" dist/*'), command
    # The notes are the changelog section, read by the rule the verify job checks it with.
    runs = [step.get("run", "") for step in release["steps"]]
    assert 'python tools/release_checks.py notes "$VERSION" > "$RUNNER_TEMP/release-notes.md"' in runs
    # The only job that runs on a dry run and could reach a release is the one above.
    others = [name for name, job in document["jobs"].items() if name != "release" and "gh release" in str(job)]
    assert not others, others


# The only calls to GitHub the workflow's own lines make: the two reads of the tag in verify, and
# the creation of the draft in release. A list of publishing commands cannot be complete (`gh api
# -X PATCH .../releases/...`, curl to the same address), so the rule is the other way round: every
# call is one of these, no call to the API sends a method or a field, and only the two steps that
# make them hold a token.
GH_CALLS = {
    ("verify", 'gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG"'),
    ("verify", 'gh api "repos/$GITHUB_REPOSITORY/git/tags/$tag_sha"'),
    ("release", 'gh release create "$TAG"'),
}
TOKEN_STEPS = {("verify", TAG_CHECK), ("release", "Create the draft release")}
API_WRITES = re.compile(r"\s(?:-X|--method|-f|-F|--field|--raw-field|--input)(?:\s|=)")
OTHER_CLIENTS = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|urllib|requests|httpx)\b|https?://")


def test_the_workflow_calls_github_only_to_read_the_tag_and_create_the_draft() -> None:
    document = _load(RELEASE)
    calls = set()
    for job, step in _steps(document):
        run = step.get("run", "").replace("\\\n", " ")
        assert not OTHER_CLIENTS.search(run), (job, step.get("name"), OTHER_CLIENTS.search(run))
        for line in run.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for call in re.finditer(r"\bgh\s+(?:api\s+\S+|\S+\s+\S+\s+\S+)", line):
                calls.add((job, call.group()))
            if re.search(r"\bgh\s+api\b", line):
                assert not API_WRITES.search(line), (job, line)
    assert calls == GH_CALLS, calls
    holders = {
        (job, step.get("name"))
        for job, step in _steps(document)
        if any("github.token" in str(value) or "GITHUB_TOKEN" in str(value) for value in step.get("env", {}).values())
        or "token" in step.get("with", {})
    }
    assert holders == TOKEN_STEPS, holders
    # No job holds a token at its own level, where every step would inherit it.
    assert not [name for name, job in document["jobs"].items() if "github.token" in str(job.get("env", {}))]
    # The release job may write the repository's contents, so it runs no action but the two that
    # bring in the tree and the files, and the one that sets up its Python.
    release = [step["uses"].split("@")[0] for step in document["jobs"]["release"]["steps"] if "uses" in step]
    assert set(release) <= {"actions/checkout", "actions/download-artifact", "actions/setup-python"}, release


def test_the_verify_job_checks_the_tag_and_the_version() -> None:
    # What the version check refuses is tests/test_release_checks_tool.py's; here, that the job
    # runs it, with the tag on a push, and asks GitHub about the tag in the protocol's form.
    document = _load(RELEASE)
    assert document["jobs"]["ci"]["uses"] == LOCAL_CI
    runs = "\n".join(step.get("run", "") for step in document["jobs"]["verify"]["steps"])
    for phrase in (
        "--jq '[.object.type, .object.sha] | @tsv'",
        "--jq '[.object.type, .object.sha, .verification.verified, .verification.reason] | @tsv'",
        'if [ "$ref_type" != "tag" ]; then',
        'if [ "$target_type" != "commit" ] || [ "$target_sha" != "$GITHUB_SHA" ]; then',
        'if [ "$verified" != "true" ]; then',
        'git merge-base --is-ancestor "$GITHUB_SHA" "refs/remotes/origin/$DEFAULT_BRANCH"',
        'python tools/release_checks.py check --tag "$TAG"',
        "python tools/release_checks.py check\n",
        'echo "version=$(python tools/release_checks.py version)" >> "$GITHUB_OUTPUT"',
    ):
        assert phrase in runs, phrase


def test_every_job_that_runs_python_sets_up_the_python_it_runs() -> None:
    # The runner image's own interpreter changes when the image does, and is outside every pin:
    # a job whose lines run Python sets up the one it runs, before the first line that runs it.
    for name, job in _load(RELEASE)["jobs"].items():
        steps = job.get("steps", [])
        runs_python = [i for i, step in enumerate(steps) if re.search(r"\bpython3?\b", step.get("run", ""))]
        if not runs_python:
            continue
        setups = [i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/setup-python@")]
        assert setups and setups[0] < runs_python[0], name
        assert all(not re.search(r"\bpython3\b", step.get("run", "")) for step in steps), name


@pytest.mark.parametrize("workflow", [RELEASE, CI], ids=lambda path: path.name)
def test_no_run_script_holds_an_expression(workflow: Path) -> None:
    # An expression in a script is pasted into its text before the shell reads it, so a value an
    # event carries (a branch name, a ref) would run as shell code. Values reach a script through
    # `env:`, where the shell reads them as data.
    runs = [(job, step) for job, step in _steps(_load(workflow)) if "run" in step]
    assert runs, f"{workflow.name} has no run script; nothing was checked"
    pasted = [(job, step.get("name")) for job, step in runs if "${{" in step["run"]]
    assert not pasted, pasted


def test_ci_waits_only_on_its_own_runs_never_on_the_release_that_calls_it() -> None:
    # Called by the release workflow, github.workflow and github.ref are the caller's: the `ci-`
    # prefix and the event keep the group from being one the caller could hold.
    assert _load(CI)["concurrency"] == {
        "group": "ci-${{ github.workflow }}-${{ github.ref }}-${{ github.event_name }}",
        "cancel-in-progress": True,
    }
    assert "concurrency" not in _load(RELEASE)


@pytest.mark.parametrize("workflow", [RELEASE, CI], ids=lambda path: path.name)
def test_no_job_or_step_lets_the_run_go_on_after_it_fails(workflow: Path) -> None:
    for name, job in _load(workflow)["jobs"].items():
        assert "continue-on-error" not in job, name
        for step in job.get("steps", []):
            assert "continue-on-error" not in step, (name, step.get("name", step.get("uses")))


def test_the_verify_job_runs_each_check_when_it_applies() -> None:
    # A condition that cannot hold would skip a check as surely as removing it: each step's
    # condition is the one stated here. The refusal of a dry run on a tag comes first, before
    # anything is checked out.
    steps = _load(RELEASE)["jobs"]["verify"]["steps"]
    conditions = [(step.get("name", step.get("uses", "").split("@")[0]), step.get("if")) for step in steps]
    assert conditions == [
        (TAG_REFUSAL, "github.event_name != 'push' && github.ref_type == 'tag'"),
        ("actions/checkout", None),
        ("actions/setup-python", None),
        (TAG_CHECK, "github.event_name == 'push'"),
        (VERSION_CHECK, None),
    ], conditions
    # The default-branch check reads the branches of the clone, so the clone holds them.
    assert steps[1]["with"]["fetch-depth"] == 0
    assert _step("verify", TAG_CHECK)["env"]["DEFAULT_BRANCH"] == "${{ github.event.repository.default_branch }}"


def test_a_dry_run_started_on_a_tag_is_refused(tmp_path: Path) -> None:
    run = _run(_step("verify", TAG_REFUSAL), tmp_path, {"TAG": "v0.1.0"})
    assert run.returncode != 0, run.stdout
    assert run.stdout.startswith("::error::"), run.stdout


# `gh` and `git` as GitHub and the clone answer them, from the STUB_ variables.
TAG_STUBS = """
gh() {
  if [ "${STUB_GH_FAILS:-}" = 1 ]; then echo "HTTP 404" >&2; return 1; fi
  case "$*" in
    *"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG "*) printf '%s\\t%s\\n' "$STUB_REF_TYPE" "$STUB_TAG_OBJECT" ;;
    *"repos/$GITHUB_REPOSITORY/git/tags/$STUB_TAG_OBJECT "*)
      printf '%s\\t%s\\t%s\\t%s\\n' "$STUB_TARGET_TYPE" "$STUB_TARGET" "$STUB_VERIFIED" "$STUB_REASON" ;;
    *) echo "unexpected: gh $*" >&2; return 2 ;;
  esac
}
git() {
  if [ "$1 $2 $3 $4" = "merge-base --is-ancestor $GITHUB_SHA refs/remotes/origin/$DEFAULT_BRANCH" ]; then
    return "$STUB_NOT_ON_DEFAULT"
  fi
  echo "unexpected: git $*" >&2
  return 2
}
"""
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
RELEASABLE_TAG = {
    "TAG": "v0.1.0",
    "GITHUB_REPOSITORY": "loquitur-dev/loquitur-verify-py",
    "GITHUB_SHA": COMMIT,
    "DEFAULT_BRANCH": "main",
    "STUB_REF_TYPE": "tag",
    "STUB_TAG_OBJECT": TAG_OBJECT,
    "STUB_TARGET_TYPE": "commit",
    "STUB_TARGET": COMMIT,
    "STUB_VERIFIED": "true",
    "STUB_REASON": "valid",
    "STUB_NOT_ON_DEFAULT": "0",
}


def test_the_tag_check_keeps_each_api_answer_before_it_reads_it() -> None:
    run = _step("verify", TAG_CHECK)["run"]
    assert API_READ.findall(run) == API_READS
    code = [line for line in run.splitlines() if not line.lstrip().startswith("#")]
    assert sum(line.count("gh api") for line in code) == 2 and not [line for line in code if "< <(" in line]
    for split in SPLITS:
        assert split in run, split


def test_the_tag_check_passes_a_releasable_tag(tmp_path: Path) -> None:
    run = _run(_step("verify", TAG_CHECK), tmp_path, RELEASABLE_TAG, TAG_STUBS)
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert "::error::" not in run.stdout


@pytest.mark.parametrize(
    ("case", "answer", "refusal"),
    [
        ("a lightweight tag", {"STUB_REF_TYPE": "commit", "STUB_TAG_OBJECT": COMMIT}, "tag v0.1.0 is lightweight"),
        ("a ref with no tag object", {"STUB_REF_TYPE": "", "STUB_TAG_OBJECT": ""}, "names no tag object"),
        ("a tag of another commit", {"STUB_TARGET": "c" * 40}, "not the commit this run builds"),
        ("a tag of a tag", {"STUB_TARGET_TYPE": "tag"}, "not the commit this run builds"),
        ("an unsigned tag", {"STUB_VERIFIED": "false", "STUB_REASON": "unsigned"}, "no signature GitHub verifies"),
        (
            "a signature GitHub does not verify",
            {"STUB_VERIFIED": "false", "STUB_REASON": "unknown_key"},
            "no signature GitHub verifies (unknown_key)",
        ),
        ("a commit off the default branch", {"STUB_NOT_ON_DEFAULT": "1"}, "not on main"),
        ("no answer from the API", {"STUB_GH_FAILS": "1"}, "no answer for the ref of tag v0.1.0"),
    ],
)
def test_the_tag_check_stops_the_run_on_a_tag_it_refuses(
    case: str, answer: dict[str, str], refusal: str, tmp_path: Path
) -> None:
    run = _run(_step("verify", TAG_CHECK), tmp_path, {**RELEASABLE_TAG, **answer}, TAG_STUBS)
    assert run.returncode != 0, (case, run.stdout)
    assert run.stdout.startswith("::error::") and refusal in run.stdout, (case, run.stdout)
    assert "annotated, signed and verified" not in run.stdout, (case, run.stdout)


@pytest.mark.parametrize(
    ("event", "tag", "passes"),
    [("push", "v0.1.0", True), ("push", "v0.1.1", False), ("workflow_dispatch", "main", True)],
)
def test_the_version_check_stops_the_run_on_a_version_it_refuses(
    event: str, tag: str, passes: bool, tmp_path: Path
) -> None:
    tree = tmp_path / "tree"
    (tree / "tools").mkdir(parents=True)
    (tree / "src/loquitur/verify").mkdir(parents=True)
    shutil.copyfile(ROOT / "tools" / "release_checks.py", tree / "tools" / "release_checks.py")
    (tree / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
    (tree / "src/loquitur/verify/_version.py").write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    (tree / "CHANGELOG.md").write_text("# Changelog\n\n## [0.1.0]\n\n- first\n", encoding="utf-8")
    output = tmp_path / "output"
    output.write_text("", encoding="utf-8")
    stubs = f'python() {{ "{Path(sys.executable).as_posix()}" "$@"; }}'
    env = {"EVENT": event, "TAG": tag, "GITHUB_OUTPUT": output.as_posix()}
    run = _run(_step("verify", VERSION_CHECK), tree, env, stubs)
    assert (run.returncode == 0) == passes, (run.stdout, run.stderr)
    assert (output.read_text(encoding="utf-8") == "version=0.1.0\n") == passes


def test_every_attestation_check_the_releasing_document_gives_names_the_workflow_the_tag_and_the_runner() -> None:
    # The wheel is reproducible, so a dry run on a branch attests the same bytes as the release: a
    # check that does not name the tag would accept that run's attestations, the SBOM's included.
    text = RELEASING.read_text(encoding="utf-8").replace("\\\n", " ")
    commands = [" ".join(line.split()) for line in text.splitlines() if line.startswith("gh attestation verify ")]
    assert len(commands) == 3, commands
    for command in commands:
        for flag in (
            "--repo loquitur-dev/loquitur-verify-py",
            "--signer-workflow loquitur-dev/loquitur-verify-py/.github/workflows/release.yml",
            "--source-ref refs/tags/vX.Y.Z",
            "--deny-self-hosted-runners",
        ):
            assert flag in command, (flag, command)
    assert sum("--predicate-type https://cyclonedx.org/bom" in command for command in commands) == 1


def test_the_releasing_document_asks_for_a_public_dry_run_before_the_first_tag() -> None:
    # A private repository's dry runs attest nothing and never reach the release job.
    lines = RELEASING.read_text(encoding="utf-8").splitlines()
    assert "## Before the first release tag" in lines
    section = " ".join(" ".join(lines[lines.index("## Before the first release tag") :]).split("## ")[1].split())
    for phrase in ("public and before the first tag is pushed", "dry run", "--source-ref refs/heads/main", "re-runs"):
        assert phrase in section, phrase


def test_the_releasing_document_says_how_a_release_is_checked_and_what_is_not_claimed() -> None:
    text = " ".join(RELEASING.read_text(encoding="utf-8").split())
    for phrase in (
        "sha256sum -c SHA256SUMS",
        "gh attestation verify",
        "--repo loquitur-dev/loquitur-verify-py",
        "--predicate-type https://cyclonedx.org/bom",
        "git tag -s",
        "never moved or deleted",
        "--draft",
        "What is not claimed",
        "where a file was built, not that it is correct",
        "trusted publish",
    ):
        assert phrase in text, phrase


# `git` as GitHub answers the sibling probe: STUB_PROBE holds one `status|message` answer per
# attempt, separated by `;`, the last one repeated, and the file `attempts` counts the calls;
# `sleep` returns at once. Bash builtins only, so no tool beside bash is needed.
PROBE_STUBS = """
git() {
  local count=0 answers line
  if [ -f attempts ]; then read -r count < attempts; fi
  echo $((count + 1)) > attempts
  IFS=';' read -ra answers <<< "$STUB_PROBE"
  line="${answers[count < ${#answers[@]} ? count : ${#answers[@]} - 1]}"
  echo "${line#*|}" >&2
  return "${line%%|*}"
}
sleep() { :; }
"""
PROBE_READABLE = "0|"
PROBE_PRIVATE = "128|fatal: could not read Username for 'https://github.com': terminal prompts disabled"
PROBE_ABSENT = "128|remote: Repository not found.\nfatal: repository 'https://github.com/o/r.git/' not found"
PROBE_UNREACHABLE = {
    "no-name-resolution": "128|fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host: github.com",
    "server-error": "128|fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 503",
    "rate-limited": "128|fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 403",
}


def _probe() -> dict[str, Any]:
    [probe] = [step for step in _load(CI)["jobs"]["siblings"]["steps"] if step.get("id") == "probe"]
    return probe


def _probed_siblings() -> list[str]:
    found = re.search(r"^ *for repo in ([a-z -]+); do$", _probe()["run"], re.M)
    assert found, "the probe names no sibling"
    return found[1].split()


def _run_probe(answers: str, ref_type: str, where: Path) -> tuple[subprocess.CompletedProcess[str], str, int]:
    """The probe step, run with git answering ``answers``: the run, its outputs and the attempts made."""
    output = where / "output"
    output.write_text("", encoding="utf-8")
    env = {"OWNER": "owner", "REF_TYPE": ref_type, "STUB_PROBE": answers, "GITHUB_OUTPUT": str(output)}
    # Without its working-directory, which names the runner's temporary directory.
    run = _run({"run": _probe()["run"]}, where, env, PROBE_STUBS)
    attempts = where / "attempts"
    count = int(attempts.read_text(encoding="utf-8")) if attempts.is_file() else 0
    return run, output.read_text(encoding="utf-8"), count


def test_the_probe_passes_the_ref_type_through_env() -> None:
    assert _probe()["env"]["REF_TYPE"] == "${{ github.ref_type }}"


@pytest.mark.parametrize("ref_type", ["branch", "tag"])
def test_the_probe_checks_out_every_readable_sibling(ref_type: str, tmp_path: Path) -> None:
    run, output, attempts = _run_probe(PROBE_READABLE, ref_type, tmp_path)
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert f"published={' '.join(_probed_siblings())}" in output.splitlines()
    assert attempts == len(_probed_siblings())


@pytest.mark.parametrize("answer", [PROBE_PRIVATE, PROBE_ABSENT, "2|"], ids=["private", "absent", "no-head"])
@pytest.mark.parametrize("ref_type", ["branch", "tag"])
def test_a_sibling_that_is_not_found_is_skipped_at_once_even_on_a_tag(
    ref_type: str, answer: str, tmp_path: Path
) -> None:
    run, output, attempts = _run_probe(answer, ref_type, tmp_path)
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert "published=" in output.splitlines() and "::" not in run.stdout
    assert attempts == len(_probed_siblings())


@pytest.mark.parametrize("answer", sorted(PROBE_UNREACHABLE.values()), ids=sorted(PROBE_UNREACHABLE))
def test_a_probe_failure_that_is_not_a_not_found_fails_a_run_on_a_tag(answer: str, tmp_path: Path) -> None:
    run, output, attempts = _run_probe(answer, "tag", tmp_path)
    assert run.returncode == 1, (run.stdout, run.stderr)
    assert f"::error::{_probed_siblings()[0]} could not be probed" in run.stdout
    assert attempts == 4 and output == ""


@pytest.mark.parametrize("answer", sorted(PROBE_UNREACHABLE.values()), ids=sorted(PROBE_UNREACHABLE))
def test_a_probe_failure_on_a_branch_warns_and_skips_the_sibling(answer: str, tmp_path: Path) -> None:
    run, output, attempts = _run_probe(answer, "branch", tmp_path)
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert run.stdout.count("::warning::") == len(_probed_siblings())
    assert "published=" in output.splitlines() and attempts == 4 * len(_probed_siblings())


def test_a_transient_probe_failure_is_asked_again(tmp_path: Path) -> None:
    run, output, attempts = _run_probe(PROBE_UNREACHABLE["server-error"] + ";" + PROBE_READABLE, "tag", tmp_path)
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert f"published={' '.join(_probed_siblings())}" in output.splitlines()
    assert attempts == len(_probed_siblings()) + 1
