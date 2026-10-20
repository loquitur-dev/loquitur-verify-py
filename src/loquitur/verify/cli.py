"""Command-line entry point for the public Loquitur verifier package.

This module defines the command-line output contract and exit-code taxonomy for offline
bundle verification. The command line calls no online registry.

It does verify issuer signatures, trust registries and the status of an issuer key as the
supplied trust registry states it (revoked, suspended, outside its window): that is what
``--trust-registry`` and ``--trust-root`` are for, and the help text of those options says so.
Revocation is not checked beyond what the registry states.
It does not validate chain anchors or prove registry inclusion: both need something that
happened elsewhere, so neither can be decided offline.

The ``--narrative`` option adds the verdict narrative to the output. It accepts one or more
audience values (``technical``, ``compliance``, ``executive``), comma-separated. Without it,
the output carries no narrative section.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any, NoReturn, TextIO

from loquitur.verify._version import __version__
from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time
from loquitur.verify.manifest import STATUS_OFFLINE_REVIEW
from loquitur.verify.runner import (
    EXIT_USAGE_ERROR,
    REVIEW_REASONS,
    exit_code_for_status,
    internal_error_report,
    unsupported_version_report,
    verify_path,
)
from loquitur.verify.trust_root import (
    DOCUMENT_READ_FAILED,
    PINNED_TRUST_ROOTS,
    TrustRootDocumentUnsupportedVersion,
    TrustRootKey,
    read_trust_root_document,
)
from loquitur.verify.vocabulary import HeldVocabulary, VocabularyError, read_vocabulary

# The options that supply a registered vocabulary document, one per kind
# (verification-vocabularies.md section 8, report-contract.md section 4.1).
VOCABULARY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("asset_type", "--asset-type-vocabulary"),
    ("workflow", "--workflow-vocabulary"),
    ("anchoring_method", "--anchoring-method-vocabulary"),
)

VALID_NARRATIVE_AUDIENCES: tuple[str, ...] = ("technical", "compliance", "executive")


class LoquiturArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # pragma: no cover - exercised through CLI tests
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE_ERROR, f"{self.prog}: error: {message}\n")


def _parse_narrative_audiences(value: str) -> tuple[str, ...]:
    """Parse the ``--narrative`` argument into a validated audience tuple.

    Accepts a comma-separated list of one or more audience values from
    ``VALID_NARRATIVE_AUDIENCES``. Whitespace around commas is tolerated.
    Duplicates are deduplicated while preserving first-occurrence order.

    Raises ``argparse.ArgumentTypeError`` for empty input or any unknown
    audience, with a clear message listing the accepted values.
    """
    if not value or not value.strip():
        raise argparse.ArgumentTypeError(
            f"--narrative requires at least one audience; valid values are: {', '.join(VALID_NARRATIVE_AUDIENCES)}"
        )
    raw_parts = [part.strip() for part in value.split(",")]
    audiences: list[str] = []
    seen: set[str] = set()
    for part in raw_parts:
        if not part:
            continue
        if part not in VALID_NARRATIVE_AUDIENCES:
            raise argparse.ArgumentTypeError(
                f"unknown narrative audience: {part!r}; valid values are: {', '.join(VALID_NARRATIVE_AUDIENCES)}"
            )
        if part not in seen:
            seen.add(part)
            audiences.append(part)
    if not audiences:
        raise argparse.ArgumentTypeError(
            f"--narrative requires at least one audience; valid values are: {', '.join(VALID_NARRATIVE_AUDIENCES)}"
        )
    return tuple(audiences)


def _parse_accept_review(value: str) -> tuple[str, ...]:
    """The review reasons ``--accept-review`` accepts (report-contract.md section 4).

    A comma-separated list of names of section 3.3: no unknown name, no empty element and no
    reason twice; any of them is a usage error, exit 64.
    """
    parts = value.split(",")
    for part in parts:
        if part == "":
            raise argparse.ArgumentTypeError("--accept-review holds an empty element")
        if part not in REVIEW_REASONS:
            raise argparse.ArgumentTypeError(f"--accept-review names {part!r}, which is not a review reason")
    if len(set(parts)) != len(parts):
        raise argparse.ArgumentTypeError("--accept-review names the same review reason twice")
    return tuple(parts)


class _Once(argparse.Action):
    """An option given at most once, never with an empty value (report-contract.md section 4.1).

    argparse keeps the last of a repeated option, so a malformed earlier value would be silently
    replaced by a later one, and it reads ``--opt ""`` as a value. Both are usage errors, exit 64.
    """

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, f"_seen_{self.dest}", False):
            parser.error(f"{option_string} was given more than once")
        setattr(namespace, f"_seen_{self.dest}", True)
        if self.nargs == 0:
            setattr(namespace, self.dest, True)
            return
        if isinstance(values, str) and values == "":
            parser.error(f"{option_string} was given an empty value; supply one or omit the option")
        setattr(namespace, self.dest, values)


class _OnceFlag(_Once):
    """A flag without a value, given at most once."""

    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: object) -> None:
        kwargs.pop("nargs", None)
        super().__init__(option_strings, dest, nargs=0, default=False, **kwargs)  # type: ignore[arg-type]


def build_parser() -> argparse.ArgumentParser:
    # allow_abbrev=False: an option given by a prefix of its name (--reg) is unknown, exit 64.
    parser = LoquiturArgumentParser(
        prog="loquitur-verify",
        description="Verify a Loquitur evidence bundle offline.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "bundle",
        nargs="?",
        help="Path to a Loquitur bundle directory or ZIP archive.",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json",
        action=_OnceFlag,
        help="Write a machine-readable JSON verification report to stdout.",
    )
    output.add_argument(
        "--pretty",
        action=_OnceFlag,
        help="Write a compact human-readable verification summary to stdout. This is the default.",
    )
    parser.add_argument(
        "--registry-entry",
        metavar="PATH",
        action=_Once,
        help=(
            "Path to a local public registry_entry JSON file: requests the link check, which "
            "compares the entry with the bundle's receipt and manifest. A deterministic local "
            "check; it does not verify issuer signatures, inclusion proofs, anchors or finality."
        ),
    )
    parser.add_argument(
        "--trust-registry",
        metavar="PATH",
        action=_Once,
        help=(
            "Path to a local trust_registry JSON file: requests the authorization check, the "
            "issuer signature of the --registry-entry and the authorization of its issuer key. "
            "Requires --registry-entry. Local only; "
            "it does not verify inclusion proofs, anchors, finality, legal identity, compliance "
            "or valuation correctness."
        ),
    )
    parser.add_argument(
        "--trust-root",
        metavar="PATH",
        action=_Once,
        help=(
            "Path to a trust-root JSON document, obtained out of band, carrying the public "
            "keys entitled to sign a trust registry. Without it nothing vouches for the trust "
            "registry, and authorization is not established. The document must be a separate "
            "file; reading roots from the registry they authenticate would be circular."
        ),
    )
    parser.add_argument(
        "--evaluation-time",
        metavar="INSTANT",
        action=_Once,
        help=(
            "Your evaluation time, a UTC instant of the form YYYY-MM-DDTHH:MM:SSZ: the time "
            "the trust registry, the issuer key and the trust root are judged at. The issuer's "
            "own dates are never used as a time; without it authorization is not established "
            "(review reason evaluation_time_not_provided)."
        ),
    )
    parser.add_argument(
        "--accept-review",
        metavar="REASONS",
        action=_Once,
        type=_parse_accept_review,
        default=None,
        help=(
            "Comma-separated review reasons to accept: exit 0 instead of 2 when every review "
            "reason of the run is in the list. The report is unchanged, and exits 1, 3, 4, 5 "
            "and 64 are never changed."
        ),
    )
    for kind, option in VOCABULARY_OPTIONS:
        parser.add_argument(
            option,
            metavar="PATH",
            action=_Once,
            dest=f"{kind}_vocabulary",
            help=(
                f"Path to a registered vocabulary document of the kind {kind}, to judge the run's "
                f"{kind.replace('_', ' ')} values against in place of the version built into this "
                "verifier. A value it does not register is the review reason vocabulary_value_unknown. "
                "A document that is malformed or registers another kind is refused with exit 64."
            ),
        )
    parser.add_argument(
        "--narrative",
        action=_Once,
        type=_parse_narrative_audiences,
        default=None,
        metavar="AUDIENCES",
        help=(
            "Include verdict narrative output for one or more audiences "
            "(comma-separated). Valid values: technical, compliance, executive. "
            "Example: --narrative=technical,compliance. Requires loquitur-schemas "
            "to be installed; without it the narrative section is included but "
            "fields are null."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"loquitur-verify {__version__}",
    )
    return parser


def _payload_for_report(report: object, audiences: tuple[str, ...] | None) -> dict[str, Any]:
    """Return the JSON-serializable payload, optionally including narrative.

    If ``audiences`` is ``None``, returns the payload without narrative
    (``to_dict()`` output, no ``narrative`` key). If ``audiences`` is a
    non-empty tuple, returns the extended shape with ``narrative`` populated
    for the requested audiences.
    """
    payload: dict[str, Any]
    if audiences is None:
        payload = report.to_dict()  # type: ignore[attr-defined]
    else:
        # Imported here, so a run without --narrative never loads the narrative module.
        from loquitur.verify.narrative import report_dict_with_narrative

        payload = report_dict_with_narrative(report, audiences=audiences)  # type: ignore[arg-type]
    return payload


def _write_json_report(
    report: object,
    *,
    stdout: TextIO,
    audiences: tuple[str, ...] | None = None,
) -> None:
    payload = _payload_for_report(report, audiences)
    stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    stdout.write("\n")


def _escaped(value: object) -> str:
    """``value`` as text with every character that is not printable written as an escape.

    The summary interpolates the input path, member names, notes and error messages, all of
    which the bundle or the caller controls. A newline, a carriage return or an escape sequence
    written raw could forge a verdict line on a terminal, so C0 and C1 controls, DEL and the
    other non-printable characters are written as backslash escapes.
    """
    text = str(value)
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def _write_pretty_report(
    report: object,
    *,
    stdout: TextIO,
    audiences: tuple[str, ...] | None = None,
) -> None:
    payload = _payload_for_report(report, audiences)
    checks = payload["checks"]
    registry = payload["registry"]
    stdout.write(f"Loquitur offline verification: {payload['status']} / {payload['verdict']}\n")
    stdout.write(f"checks requested: {', '.join(payload['checks_requested'])}\n")
    stdout.write(f"checks established: {', '.join(payload['checks_established']) or '(none)'}\n")
    if payload["review_reasons"]:
        stdout.write(f"review reasons: {', '.join(payload['review_reasons'])}\n")
    stdout.write(f"input: {_escaped(payload['input']['path'])} ({payload['input']['type'] or 'unknown'})\n")
    if payload["input"].get("bundle_root_name"):
        stdout.write(f"bundle_root: {_escaped(payload['input']['bundle_root_name'])}\n")
    stdout.write("checks:\n")
    for name in (
        "manifest_sha256",
        "manifest_files",
        "p1_sha256",
        "canonical_input_present",
        "p1_input_hash",
        "envelope_present",
        "envelope_sha256",
        "envelope_links",
        "registry_signature",
        "registry_link",
        "trust_registry",
    ):
        stdout.write(f"  - {name}: {_escaped(checks.get(name))}\n")
    stdout.write(f"registry: {registry['status']} (signature_supported={registry['signature_supported']})\n")
    registry_link = payload.get("registry_link")
    if registry_link is not None:
        stdout.write(f"registry_link: {registry_link['status']} / {registry_link['verdict']}\n")
    trust_registry = payload.get("trust_registry")
    if trust_registry is not None:
        stdout.write(f"trust_registry: {trust_registry['status']} / {trust_registry['verdict']}\n")
    if payload["notes"]:
        stdout.write("notes:\n")
        for note in payload["notes"]:
            stdout.write(f"  - {_escaped(note)}\n")
    if payload["errors"]:
        stdout.write("errors:\n")
        for error in payload["errors"]:
            message = error.get("message")
            suffix = f": {_escaped(message)}" if message else ""
            stdout.write(f"  - {_escaped(error.get('code'))}{suffix}\n")
    if audiences is not None:
        narrative = payload.get("narrative") or {}
        refused = narrative.get("refused")
        # Render audiences in the canonical order they were requested.
        for audience in audiences:
            content = narrative.get(audience)
            stdout.write(f"\nnarrative.{audience}:\n")
            if refused is not None:
                stdout.write(f"  (refused: {_escaped(refused)})\n")
                continue
            if content is None:
                stdout.write("  (unavailable: install loquitur-schemas to enable verdict narrative)\n")
                continue
            for line in content.splitlines() or [""]:
                stdout.write(f"  {_escaped(line)}\n" if line else "\n")


def _silence_broken_stdout() -> None:
    """Detach stdout after a consumer (for example ``head``) closed the pipe early.

    The exit-code taxonomy is the CLI contract; truncated textual output must
    not surface a raw traceback or alter the exit code. Redirecting the
    underlying descriptor to ``os.devnull`` keeps the interpreter's final
    stdout flush from re-raising ``BrokenPipeError`` at shutdown.
    """
    try:
        stdout_fd = sys.stdout.fileno()
    except (OSError, ValueError, AttributeError):
        return
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
    except OSError:  # pragma: no cover - devnull unavailable
        return
    try:
        os.dup2(devnull, stdout_fd)
    except OSError:  # pragma: no cover - best-effort detach
        pass
    finally:
        os.close(devnull)


def _escape_unencodable_stdout() -> None:
    """Write a character stdout cannot encode as an escape instead of raising.

    The summary prints the bundle path as given, and the narrative prints the text of the
    reason-code catalog. Where stdout is a file or a pipe, its encoding is the host's locale
    encoding, which need not represent either: a strict encoder would then raise mid-report, and the traceback
    would exit 1, the code of ``OFFLINE_FAIL``, for evidence that verified. The verdict and its
    exit code do not depend on how the summary is spelled, so a character outside the encoding
    is written as a backslash escape. The encoding itself is left as the host chose it.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(errors="backslashreplace")
    except (OSError, ValueError):  # pragma: no cover - a stream that cannot be reconfigured
        pass


def main(argv: Sequence[str] | None = None) -> int:
    _escape_unencodable_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.bundle:
        parser.error("the following arguments are required: bundle")

    if args.trust_registry and not args.registry_entry:
        parser.error("--trust-registry requires --registry-entry")
    evaluation_time: str | None = None
    if args.evaluation_time is not None:
        if not args.trust_registry:
            parser.error("--evaluation-time requires --trust-registry; it is the time authorization is judged at")
        try:
            evaluation_time = operator_evaluation_time(args.evaluation_time)
        except EvaluationTimeError as exc:
            print(f"loquitur-verify: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    # A registered vocabulary is configuration, not evidence: each supplied one is read and
    # checked before any evidence, and refused with exit 64 (verification-vocabularies.md section 8).
    vocabularies: dict[str, HeldVocabulary] = {}
    for kind, option in VOCABULARY_OPTIONS:
        path = getattr(args, f"{kind}_vocabulary")
        if path is None:
            continue
        try:
            vocabularies[kind] = read_vocabulary(kind, path)
        except VocabularyError as exc:
            print(f"loquitur-verify: {option} was refused: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    trust_roots: Sequence[TrustRootKey] | object = PINNED_TRUST_ROOTS
    host_fault: RecursionError | None = None
    roots_unsupported: str | None = None
    if args.trust_root is not None:
        if args.trust_registry is None:
            print(
                "loquitur-verify: --trust-root requires --trust-registry; there is nothing to authenticate without one",
                file=sys.stderr,
            )
            return EXIT_USAGE_ERROR
        try:
            # The strict loader, as for every other document the verifier reads: a
            # trust-root file with a duplicate member, a 1e400 or a lone surrogate is refused
            # here rather than parsed by whichever rule json.loads happens to apply. A path that
            # names no regular file is refused before anything is read from it.
            trust_roots = read_trust_root_document(args.trust_root)
        except TrustRootDocumentUnsupportedVersion as exc:
            # Gate 1: a well-formed later version is not malformed; the run is
            # UNSUPPORTED_VERSION, exit 4, with a report (report-contract.md section 5.5).
            roots_unsupported = exc.version
        except OSError:
            # The path names a regular file the host failed to inspect or read: not a refusal of
            # the invocation but a host failure, which the report carries as
            # trust_root_read_failed, HOST_FAILURE, exit 5 (report-contract.md sections 4 and 5.3).
            # Root authentication is not evaluated; no root is taken as pinned or as absent.
            trust_roots = DOCUMENT_READ_FAILED
        except ValueError as exc:
            # A path that names no regular file, or a document that breaks trust-root.md section 3.
            # Refusing beats proceeding with the module default, which is empty: an operator
            # who supplied roots and silently got none would believe a check ran that did not.
            print(f"loquitur-verify: --trust-root could not be read: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR
        except RecursionError as exc:
            # The loader refuses a document deeper than 64 levels before its decoder runs, so
            # this is a host whose recursion limit cannot hold a document the protocol admits:
            # a fault of the tool, reported as one, as the same fault inside verify_path is.
            host_fault = exc

    if host_fault is not None:
        report = internal_error_report(args.bundle, host_fault)
    elif roots_unsupported is not None:
        report = unsupported_version_report(
            args.bundle,
            "trust_root_document",
            roots_unsupported,
            registry_entry_supplied=args.registry_entry is not None,
            trust_registry_supplied=args.trust_registry is not None,
            evaluation_time=evaluation_time,
        )
    else:
        try:
            report = verify_path(
                args.bundle,
                registry_entry_path=args.registry_entry,
                trust_registry_path=args.trust_registry,
                evaluation_time=evaluation_time,
                trust_roots=trust_roots,
                vocabularies=vocabularies,
            )
        except Exception as exc:  # pragma: no cover - defensive CLI contract boundary
            report = internal_error_report(args.bundle, exc)

    audiences: tuple[str, ...] | None = args.narrative
    stdout = sys.stdout
    if stdout is not None:
        try:
            if args.json:
                _write_json_report(report, stdout=stdout, audiences=audiences)
            else:
                _write_pretty_report(report, stdout=stdout, audiences=audiences)
            stdout.flush()
        except (OSError, ValueError):
            # The verdict was already computed; a consumer that stopped reading (``head``,
            # ``less`` quitting early), a pipe closed on Windows (EINVAL, not BrokenPipeError) or
            # a closed stream must not turn into a traceback or change the exit code.
            _silence_broken_stdout()

    # --accept-review: exit 0 for an OFFLINE_REVIEW run whose every review reason is accepted;
    # the report is unchanged, and no other exit is ever changed (report-contract.md section 4).
    accepted: tuple[str, ...] | None = args.accept_review
    if (
        accepted is not None
        and report.status == STATUS_OFFLINE_REVIEW
        and report.review_reasons
        and all(reason in accepted for reason in report.review_reasons)
    ):
        return 0
    return exit_code_for_status(report.status)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
