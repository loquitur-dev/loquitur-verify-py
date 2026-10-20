"""Registered vocabularies: which asset types, workflows and anchoring methods this verifier knows.

The schemas hold `asset_type`, `workflow` and `anchor.method` to an identifier and nothing more
(verification-vocabularies.md §5 and §7). Whether a well-formed value is one the verifier knows is
decided against a registered vocabulary document, one per kind: the version built into this
package (`registered_vocabularies.py`, generated from loquitur-protocol), or one the operator
supplies (§8). The input never supplies one.

A supplied document is refused, before any evidence is read, when it is not strict JSON, is not
an object, breaks the document contract of §6 (the generated table of
`registered-vocabularies/schema.json` and the two rules that schema cannot state) or registers
another kind than the one it was supplied for. A vocabulary is configuration, not evidence: there
is no version gate, and a later `schema_version` is refused like any other malformed value.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from .canonical import JsonLoadError, loads_json_bytes
from .contract_validation import contract_errors
from .errors import LoquiturVerifyError
from .host_path import host_path
from .manifest import is_blank
from .members import path_names_regular_file, read_file_bytes
from .registered_vocabularies import REGISTERED_VOCABULARIES

KINDS: tuple[str, ...] = ("asset_type", "workflow", "anchoring_method")
SOURCE_EMBEDDED = "embedded"
SOURCE_OPERATOR = "operator"
KNOWN = "known"
UNKNOWN = "unknown"
INVALID = "invalid"

# verification-vocabularies.md §7: the grammar of every governed member, applied with fullmatch.
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_]{0,63}")
_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")


class VocabularyError(ValueError, LoquiturVerifyError):
    """A registered vocabulary document is refused (verification-vocabularies.md §8)."""


@dataclass(frozen=True)
class HeldVocabulary:
    """One registered vocabulary document the verifier holds for a run."""

    kind: str
    version: str
    values: frozenset[str]
    sha256: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "sha256": "sha256:" + self.sha256, "version": self.version}


def _version(text: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(text)
    if match is None:  # pragma: no cover - the contract has already held the pattern
        raise VocabularyError(f"not a vocabulary version: {text!r}")
    return int(match[1]), int(match[2]), int(match[3])


def document_problems(document: Any) -> list[str]:
    """Every way ``document`` breaks verification-vocabularies.md §6, contract first."""
    problems = contract_errors("registered_vocabulary", document)
    if problems:
        return problems
    version = _version(document["version"])
    for name, entry in document["values"].items():
        if _version(entry["since"]) > version:
            problems.append(f"values.{name}.since:later_than_version")
        if ("asset_types" in entry) != (document["kind"] == "workflow"):
            problems.append(f"values.{name}.asset_types:present_exactly_for_a_workflow")
        for member in ("title", "profile"):
            text = entry.get(member)
            if isinstance(text, str) and is_blank(text):
                problems.append(f"values.{name}.{member}:empty")
    return problems


def parse_vocabulary(kind: str, data: bytes, *, source: str) -> HeldVocabulary:
    """The vocabulary of ``kind`` held in ``data``, or VocabularyError."""
    if kind not in KINDS:
        raise VocabularyError(f"not a kind of registered vocabulary: {kind!r}")
    try:
        document = loads_json_bytes(data, name=f"{kind} vocabulary")
    except JsonLoadError as exc:
        raise VocabularyError(str(exc)) from exc
    problems = document_problems(document)
    if problems:
        raise VocabularyError(f"the {kind} vocabulary breaks its contract: {problems[0]}")
    if document["kind"] != kind:
        raise VocabularyError(f"the document registers the kind {document['kind']}, not {kind}")
    return HeldVocabulary(
        kind=kind,
        version=document["version"],
        values=frozenset(document["values"]),
        sha256=hashlib.sha256(data).hexdigest(),
        source=source,
    )


@cache
def embedded_vocabulary(kind: str) -> HeldVocabulary:
    """The version of ``kind`` built into this package."""
    return parse_vocabulary(kind, REGISTERED_VOCABULARIES[kind], source=SOURCE_EMBEDDED)


def read_vocabulary(kind: str, path: str | os.PathLike[str]) -> HeldVocabulary:
    """The vocabulary of ``kind`` in the document at ``path``, supplied by the operator.

    A path that names no regular file, a host that fails to read it, and a document refused under
    §8 all raise VocabularyError: a command line refuses each with exit 64.
    """
    host = host_path(path)
    if not path_names_regular_file(host):
        raise VocabularyError(f"{os.fspath(path)!r} names no regular file")
    try:
        data = read_file_bytes(Path(host))
    except OSError as exc:
        raise VocabularyError(f"{os.fspath(path)!r} could not be read") from exc
    return parse_vocabulary(kind, data, source=SOURCE_OPERATOR)


def resolve_vocabularies(
    supplied: Mapping[str, str | os.PathLike[str] | HeldVocabulary] | None,
) -> dict[str, HeldVocabulary]:
    """One vocabulary per kind: the one supplied for it, otherwise the embedded one. No merge."""
    supplied = dict(supplied or {})
    unknown = sorted(set(supplied) - set(KINDS))
    if unknown:
        raise VocabularyError(f"not a kind of registered vocabulary: {unknown[0]!r}")
    held: dict[str, HeldVocabulary] = {}
    for kind in KINDS:
        given = supplied.get(kind)
        if given is None:
            held[kind] = embedded_vocabulary(kind)
        elif isinstance(given, HeldVocabulary):
            if given.kind != kind:
                raise VocabularyError(f"the {given.kind} vocabulary was supplied for {kind}")
            held[kind] = given
        else:
            held[kind] = read_vocabulary(kind, given)
    return held


def value_status(value: object, vocabulary: HeldVocabulary) -> str:
    """``known``, ``unknown`` or ``invalid`` (verification-vocabularies.md §7)."""
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        return INVALID
    return KNOWN if value in vocabulary.values else UNKNOWN
