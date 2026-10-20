from __future__ import annotations

import argparse
import json
import sys

from loquitur.verify.canonical import JsonLoadError, loads_json_bytes
from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time
from loquitur.verify.host_path import host_path
from loquitur.verify.members import read_file_bytes
from loquitur.verify.runner import EXIT_USAGE_ERROR, unsupported_version_report, verify_path
from loquitur.verify.trust_root import (
    DOCUMENT_READ_FAILED,
    PINNED_TRUST_ROOTS,
    TrustRootDocumentUnsupportedVersion,
    read_trust_root_document,
)
from loquitur.verify.verdict_grounds import summary_violated_rules
from loquitur.verify.vocabulary import VocabularyError, read_vocabulary

# The registered vocabulary documents a run names, by kind (conformance-testing.md section 4.1),
# taken as the command line takes them.
VOCABULARY_OPTIONS = (
    ("asset_type", "--asset-type-vocabulary"),
    ("workflow", "--workflow-vocabulary"),
    ("anchoring_method", "--anchoring-method-vocabulary"),
)


def _check_summary(path: str) -> int:
    """A summary run (conformance-testing.md section 4.1): the rules the document violates.

    The document is read as strictly as every other document the verifier reads. One line of
    JSON goes to stdout, {"violated_rules": [...]}, and the exit code is 0 whatever it holds: the
    answer is the list. A document that cannot be read or parsed is refused with exit 64.
    """
    try:
        document = loads_json_bytes(read_file_bytes(host_path(path)))
    except (OSError, JsonLoadError) as exc:
        print(f"conformance adapter: --summary could not be read: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    print(json.dumps({"violated_rules": summary_violated_rules(document)}, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    # Every path is a string, handed to the verifier as it is written (report-contract.md
    # section 5.3), as the command line hands it. A Path rewrites the string before the host
    # reads it: Path("") is Path("."), the working directory, where the empty path names
    # nothing; a trailing separator is dropped; and on Windows a path that begins with the
    # device prefix and a second separator is read below the drive's root. The three document
    # paths are strings too, or the adapter would read documents the command line does not.
    # A summary run names a verification summary and nothing else (conformance-testing.md
    # section 4.1); every other run names a bundle.
    parser.add_argument("--summary", default=None)
    parser.add_argument("--bundle", default=None)
    # Optional so the adapter can exercise bundle-only runs too: the cross-repo gate
    # compares verdicts across the whole corpus, not only runs with every check requested.
    parser.add_argument("--registry-entry", default=None)
    parser.add_argument("--trust-registry", default=None)
    # The two inputs an operator supplies out of band. Without them no run in the corpus
    # could reach a pinned trust root or the operator's evaluation time, and the whole
    # trust-root surface of trust-root.md would be unreachable from a vector.
    parser.add_argument("--trust-root", default=None)
    parser.add_argument("--evaluation-time", default=None)
    for kind, option in VOCABULARY_OPTIONS:
        parser.add_argument(option, dest=f"{kind}_vocabulary", default=None)
    args = parser.parse_args()
    if args.summary is not None:
        others = (args.bundle, args.registry_entry, args.trust_registry, args.trust_root, args.evaluation_time)
        if any(value is not None for value in others):
            print("conformance adapter: --summary names a summary and nothing else", file=sys.stderr)
            return EXIT_USAGE_ERROR
        return _check_summary(args.summary)
    if args.bundle is None:
        parser.error("the following arguments are required: --bundle")

    # Both are refused before the bundle is read, and a refusal writes no report: the run
    # produced no verdict, and an empty report would be read as one. This is the CLI's
    # contract for the same two inputs, reproduced here so a vector measures the shipped
    # behavior rather than the adapter's convenience.
    if args.evaluation_time is not None and args.trust_registry is None:
        print("conformance adapter: --evaluation-time requires --trust-registry", file=sys.stderr)
        return EXIT_USAGE_ERROR
    evaluation_time = None
    if args.evaluation_time is not None:
        try:
            evaluation_time = operator_evaluation_time(args.evaluation_time)
        except EvaluationTimeError as exc:
            print(f"conformance adapter: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    # A refused vocabulary is refused before any evidence, with no report (verification-vocabularies.md
    # section 8), as the command line refuses it.
    vocabularies = {}
    for kind, option in VOCABULARY_OPTIONS:
        path = getattr(args, f"{kind}_vocabulary")
        if path is None:
            continue
        try:
            vocabularies[kind] = read_vocabulary(kind, path)
        except VocabularyError as exc:
            print(f"conformance adapter: {option} was refused: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    trust_roots = PINNED_TRUST_ROOTS
    if args.trust_root is not None:
        if args.trust_registry is None:
            print("conformance adapter: --trust-root requires --trust-registry", file=sys.stderr)
            return EXIT_USAGE_ERROR
        try:
            # Read as the command line reads it: a path that names no regular file is refused
            # before anything is read, so a device or a pipe named here is never waited on.
            trust_roots = read_trust_root_document(args.trust_root)
        except TrustRootDocumentUnsupportedVersion as exc:
            # Gate 1, as the command line reports it: a well-formed later version is not
            # malformed, and the run is UNSUPPORTED_VERSION with a report (report-contract.md
            # section 5.5).
            report = unsupported_version_report(
                args.bundle,
                "trust_root_document",
                exc.version,
                registry_entry_supplied=args.registry_entry is not None,
                trust_registry_supplied=True,
                evaluation_time=evaluation_time,
            )
            print(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")))
            return 0
        except OSError:
            # A regular file the host failed to read is a host failure the report carries
            # (trust_root_read_failed, report-contract.md section 5.3), as the command line
            # reports it, not a refusal.
            trust_roots = DOCUMENT_READ_FAILED
        except ValueError as exc:
            print(f"conformance adapter: --trust-root could not be read: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    report = verify_path(
        args.bundle,
        registry_entry_path=args.registry_entry,
        trust_registry_path=args.trust_registry,
        evaluation_time=evaluation_time,
        trust_roots=trust_roots,
        vocabularies=vocabularies,
    )
    print(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
