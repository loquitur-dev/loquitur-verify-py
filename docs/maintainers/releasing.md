# Releasing

A release of `loquitur-verify` is built by
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) from a version tag. The
workflow creates the GitHub release as a draft; the maintainer checks the draft and publishes it by
hand. Nothing in this repository publishes a release, and nothing uploads to a package index.
`tests/test_release_workflow.py` holds the workflow to what this page says.

## Tag rules

- A release tag is `vX.Y.Z`, three numbers with no leading zeros, and nothing else: no
  pre-release or build suffix. The workflow runs on no other tag and refuses one that is not of
  this form.
- It is annotated and signed with the maintainer's key:
  `git tag -s vX.Y.Z -m "loquitur-verify X.Y.Z"`. The key is registered as a signing key of the
  maintainer's GitHub account, so GitHub marks the tag verified; the workflow refuses a lightweight
  tag, an unsigned one, and one GitHub does not mark verified.
- It points at a commit of the default branch, whose `pyproject.toml` and
  `src/loquitur/verify/_version.py` declare `X.Y.Z`, and whose `CHANGELOG.md` has a section
  headed by the line `## [X.Y.Z]` or `## [X.Y.Z] - YYYY-MM-DD`, with text under it: the section
  is the release notes.
- A pushed release tag is never moved or deleted. A mistake is fixed by a new version.

## What the workflow does

On a pushed tag:

1. `verify` asks GitHub whether the tag is annotated, points at the commit the run checked out and
   carries a signature GitHub verifies, checks in the clone that the commit is on the default
   branch, and checks with `tools/release_checks.py` that the tag, the package metadata and the
   changelog name the same version. The later jobs take the version from it.
2. `ci`, after `verify`, runs every job of
   [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) on the tagged commit, the wheel
   gate and the source distribution's self-test among them. Its `siblings` job checks out the
   sibling repositories at the head of their default branch, not at a matching tag, so the run of
   a tag depends on their state when it runs: a `siblings` job that fails on a tag is fixed in the
   sibling and the job re-run, and the tag is not moved.
3. `build`, after both, builds the sdist and the wheel with the pinned `build`, with the fixed
   `SOURCE_DATE_EPOCH` and `PYTHONHASHSEED` of [`build-checks.md`](build-checks.md), and
   records their digests as outputs of the build step before anything else runs in the job. It
   then checks that `tools/local_wheel_gate.py --check-reproducible` rebuilds the wheel to the
   recorded digest, and that `tools/local_wheel_gate.py --check-dist dist` finds the files match
   `src/` and the extracted sdist passes its own tests. It installs the wheel into an empty
   environment and writes a CycloneDX SBOM of that environment with the pinned `cyclonedx-py`,
   itself installed with its pinned library in an environment of its own. It writes `SHA256SUMS`
   over the sdist, the wheel and the SBOM, and keeps the four files, all in `dist/`, as the run's
   `release-files` artifact. It may only read the repository: the build, the sdist's self-tests
   and the SBOM tool run third-party code, and none of it can sign or write to the repository.
4. `attest`, after `build`, checks out nothing and installs nothing. It downloads the four files,
   checks that they are exactly the sdist, the wheel, the SBOM and `SHA256SUMS` of that version,
   that `sha256sum --strict -c SHA256SUMS` passes, and that the sdist and the wheel have the
   digests the build step recorded, so a file rewritten by code that ran after the build is
   refused even when `SHA256SUMS` was written over it. It then attests the provenance of all four
   files and the SBOM of the sdist and the wheel with GitHub artifact attestations. An
   attestation is signed with a short-lived certificate issued for this workflow run; no signing
   key is stored anywhere.
5. `release`, after `attest`, checks the files against `SHA256SUMS` and runs
   `gh release create vX.Y.Z --draft --verify-tag` with the files attached and the changelog
   section as its notes, read by the rule `verify` checks it with.

Every action is pinned by a full commit SHA, with its tag in a comment. The workflow grants no
permission by default; `attest` alone may request an OIDC token and write attestations, and
`release` alone may write the repository's contents, which is what creating a release needs.
Every other job may only read the repository.

A dry run is started by hand (`workflow_dispatch`) on a branch; `verify` refuses one started on a
tag, since a tag is released by pushing it. It runs the version check of `verify`, `ci`, `build`
and `attest`, and keeps the files as an artifact of the run; it creates no release.
GitHub offers artifact attestations on public repositories, and on private ones only with GitHub
Enterprise Cloud, so a dry run in a private repository skips the two attestation steps and says
so. A tag push never skips them. A dry run's attestations name the branch it ran on, so the
commands below, which name the tag, do not accept them for a release.

## Before the first release tag

A dry run in a private repository reaches neither the attestation steps nor the `release` job, so
without a dry run in the public repository the first tag push would be the first run of both.
With the repository public and before the first tag is pushed, the maintainer runs a dry run on
the default branch and checks that it attested the files, with the commands below on the files of
its `release-files` artifact and `--source-ref refs/heads/main` in place of the tag. The `release`
job runs only on a tag. If it fails after `attest` has passed, the maintainer re-runs that job
from the same run, which takes the same files; the tag is not moved, and the version is not
spent.

## Before publishing the draft

The maintainer downloads the draft's files and checks them as a third party would, below. Then
the draft is published. With immutable releases turned on for the repository, a published
release's files and tag can no longer be changed, which is why the release is checked while it
is still a draft.

## How a third party checks a release

With the [GitHub CLI](https://cli.github.com/), for the release `vX.Y.Z`:

```bash
gh release download vX.Y.Z --repo loquitur-dev/loquitur-verify-py --dir loquitur-verify-X.Y.Z
cd loquitur-verify-X.Y.Z
sha256sum -c SHA256SUMS
gh attestation verify loquitur_verify-X.Y.Z-py3-none-any.whl --repo loquitur-dev/loquitur-verify-py \
  --signer-workflow loquitur-dev/loquitur-verify-py/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
gh attestation verify loquitur_verify-X.Y.Z.tar.gz --repo loquitur-dev/loquitur-verify-py \
  --signer-workflow loquitur-dev/loquitur-verify-py/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
gh attestation verify loquitur_verify-X.Y.Z-py3-none-any.whl --repo loquitur-dev/loquitur-verify-py \
  --signer-workflow loquitur-dev/loquitur-verify-py/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners --predicate-type https://cyclonedx.org/bom
```

Every command names the workflow, the tag and a GitHub-hosted runner: a file of the same bytes
built and attested by a dry run on a branch, the SBOM attestation included, is not accepted as
the release's. The same `gh attestation verify` line checks the SBOM file and `SHA256SUMS`
themselves. The tag's signature can be checked in a clone with `git tag -v vX.Y.Z` against the
maintainer's public signing key.

The wheel can also be rebuilt from the tag and compared, as
[`build-checks.md`](build-checks.md) describes.

The workflows run on a pinned runner image (`ubuntu-24.04`), not on the moving `ubuntu-latest`
label, so that the CI does not change when GitHub moves the label; the pin is moved deliberately,
with a run on the new image.

## What is not claimed

- An attestation shows where a file was built, not that it is correct: which repository,
  workflow, commit and tag produced it on a GitHub-hosted runner. It says nothing about whether the
  code is free of defects.
- `SHA256SUMS` sits beside the files it sums. It detects a damaged download, not a substituted
  one; the attestations are what tie the files to this workflow.
- No reproducible-build claim is made beyond what the workflow shows: a second build of the wheel
  on the same runner gives the same bytes. Nothing is claimed for a build on another machine, and
  nothing for the sdist, whose two builds differ.
- The SBOM lists the environment the build job installed the wheel into, with the dependency
  versions pip resolved during that run. An install elsewhere may resolve other versions within
  the ranges `pyproject.toml` declares. The SBOM is an inventory, not a statement about
  vulnerabilities.

## Settings outside this repository

These belong to the GitHub account and the repository settings, so no file here can show them.
The procedure above expects them:

- a FIDO2 security key or passkey as the account's second factor;
- no long-lived personal access token used for releases: the workflow uses only the run's own
  `GITHUB_TOKEN` and the OIDC token of the attestation steps;
- immutable releases turned on for the repository;
- a tag ruleset on `v*` that blocks updating and deleting a tag.

## A package index, later

The package is not published to a package index, and the workflow has no job that publishes it;
`tests/test_release_workflow.py` fails if one is added. Uploading a version to PyPI is permanent:
a file name can never be used again, even after a deletion. So the first uploads stay the
maintainer's manual act, made after the published release has been checked.

When an upload from the workflow is wanted, it is added with trusted publishing, which needs no
stored token:

1. On PyPI, register a trusted publisher for the project with the owner `loquitur-dev`, the
   repository `loquitur-verify-py`, the workflow `release.yml` and an environment, for example
   `pypi`.
2. In the repository settings, create that environment with the maintainer as required reviewer,
   so that every upload waits for an approval.
3. Add a job that `needs: release`, runs in that environment with `id-token: write` and no other
   permission, downloads the release files, and runs `pypa/gh-action-pypi-publish` pinned by
   commit SHA on the sdist and the wheel.
4. Change `tests/test_release_workflow.py` in the same commit, so that the new rule is stated on
   purpose.
