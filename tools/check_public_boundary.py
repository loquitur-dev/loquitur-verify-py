#!/usr/bin/env python3
"""Public-boundary gate for a Loquitur repository.

It checks that nothing discloses private material, that no private-perimeter route or host is named and, where
configured, that no claim goes beyond the specification.

    python tools/<this file> [--root ROOT]
    python tools/<this file> --pack DIRECTORY   # writes DIRECTORY.zip, the packing described below

This file is one tool, byte for byte the same in loquitur-protocol (as
tools/check_public_spec_boundary.py) and in loquitur-schemas, loquitur-verify-py and
loquitur-verify-ts (as tools/check_public_boundary.py); each repository's test suite compares its
copy with the others whenever the siblings are checked out. What differs between the repositories
is data, in tools/public_boundary.json: which needle lists apply, which root paths are forbidden,
and the reviewed digests.

What it reads: every file git tracks, because tracked files are what a publication copies; outside
a git checkout, every file under the root less the tool caches.

How a file is cleared. The checker reads every tracked file as UTF-8 text and searches it. A file
that is not such text is cleared by its provenance, or by a person's review. The routes are one
table, CLEARANCE_ROUTES below, tried in its order, and the first that answers decides; each names
where it applies, a tracked file or a member of the pinned corpus archive:

1. packed (a tracked file that is not text): a tracked `NAME.zip`, when it is byte for byte the
   packing of the tracked files under `NAME/`, which are checked as every tracked file is. The
   packing is the one `--pack` writes: stored entries named `NAME/...` in byte order of their
   names, dated 1980-01-01, with no extra field and no comment;
2. corpus (a tracked file that is not text): the pinned corpus archive, when it is byte for byte
   the canonical build of its members, which are then checked member by member by the routes
   below;
3. crafted (a member): a member that tools/crafted_members.py, where the repository carries it,
   builds byte for byte from the archive's other members;
4. spliced (a member that is not text): a member that tool lists as text with one run of bytes
   put at one offset, when the member holds that run there, in which case the text without the
   run is read and searched as every member is;
5. zero-filled (a file or member that is not text): one that holds NUL bytes only, which holds
   nothing to read;
6. reviewed (a file or member): one whose SHA-256 is recorded, with a reason, in
   tools/public_boundary.json; it must be the bytes recorded.

A file or member no route clears is searched when it is text and reported when it is not.

No container is ever opened or decoded to clear it: provenance is proved by building the same
bytes from what was read, and a file that is not text, whatever it holds, is reported unless its
provenance is proved or a person reviewed its digest. Text that carries an encoded block (a line
starting `begin` or `begin-base64` followed by whitespace) is reported as not cleared on the same
terms. A reviewed digest that names an absent file, a file whose bytes changed, or a file whose
provenance is proved, is reported.

Also: GOVERNANCE.md must say that one person, not a team, maintains the repository.

And no tracked text file holds a literal code point that prints as nothing: a control, format or
line or paragraph separator other than tab, line feed and carriage return, a space other than
U+0020, a Default_Ignorable_Code_Point (variation selectors and the Hangul and Khmer fillers among
them), U+2800, or one of the 66 noncharacters. Such a code point is written as an escape. The
predicate is the one tests/test_invisible_characters.py in loquitur-protocol holds. Members of the
corpus archive are data and carry such code points on purpose, so they are not read for it.

And every test the prose of a tracked file cites must be one a reader can find. Prose is a text
file's whole text for Markdown and plain text, the JSON strings that hold a space, and the comments
and docstrings of code and configuration. A citation is a path under the `tests` directory, a path
under the `test` directory whose name ends `.test.ts`, or a name that starts with `test` and an
underscore; a path resolves when a tracked path starts with it (a last segment in capitals, such as
NAME, stands for any name), and a name when a tracked Python file defines it or is named after it.
One that does not resolve here must sit in a paragraph (a JSON string, a run of comment lines) that
names a published repository holding it: loquitur-protocol, loquitur-schemas, loquitur-verify-py or
loquitur-verify-ts. When that repository is checked out beside this one, the citation must resolve
there. A CHANGELOG records past states and is not read for citations; the title of a TypeScript test
is a name, not a citation a reader looks up, and is not read either; nor are the members of the
corpus archive, which are data.

Every needle below is assembled from fragments: this file is scanned like every other, so a needle
spelled out here would make the tool its own finding.

What the needle search is. It is a literal substring check over the needles below. It does not find
a needle spelled another way or assembled at run time from fragments, as this file assembles its
own, a needle split across string literals that are joined when the code runs, a local path, or a
name it has no row for. It is one control, not a guarantee.

Exit codes: 0 cleared, 1 a finding.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import io
import json
import re
import struct
import subprocess
import sys
import tokenize
import unicodedata
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = "tools/public_boundary.json"
CONFIG_SCHEMA = "loquitur.public_boundary.v1"
CRAFTED = "tools/crafted_members.py"
CACHE_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "node_modules",
}

GOVERNANCE = "GOVERNANCE.md"
MAINTAINED_BY_A_TEAM = re.compile(r"maintained by [^.\n]*\bteams?\b", re.IGNORECASE)
MAINTAINED_BY_ONE_PERSON = "one person"

# Material that must not be in any published file: secret material and credentials.
DISCLOSURE_SUBSTRINGS = [
    "".join(parts)
    for parts in (
        ("BEGIN PR", "IVATE KEY"),
        ("PRIVATE ", "KEY-----"),
        ("api", "_key"),
        ("api", "key"),
        ("authori", "zation:"),
        ("bea", "rer "),
        ("coo", "kie:"),
        ("sec", "ret="),
        ("pass", "word="),
    )
]

# A server-side surface: route classes and private hosts that no published surface has. Each is a
# class rather than a list of members, so that naming the members does not write them into a
# published file.
PRIVATE_PERIMETER_SUBSTRINGS = [
    "".join(parts)
    for parts in (
        ("/v1/in", "ternal/"),
        ("/ad", "min/"),
        ("/o", "ps/"),
        ("http:", "//10."),
        ("http://", "192.168."),
        ("http://1", "27.0.0.1"),
        ("http://l", "ocalhost:"),
    )
]

# What the specification's own prose may claim. Applied only where the configuration asks for it:
# in a package repository the tests that prove a forbidden field is refused have to spell it.
CLAIM_DISCIPLINE_SUBSTRINGS = [
    "".join(parts)
    for parts in (
        ("BEGIN PR", "IVATE KEY"),
        ("PRIVATE ", "KEY-----"),
        ("api", "_key"),
        ("api", "key"),
        ("authori", "zation:"),
        ("bea", "rer "),
        ("coo", "kie:"),
        ("sec", "ret="),
        ("pass", "word="),
        ("raw_req", "uest_id"),
        ("canonica", 'l_input":'),
        ("valuatio", "n_amount"),
        ("nav_a", "mount"),
        ("cap_", "rate"),
        ("rent", "_roll"),
        ("bundle_do", "wnload_url"),
        ("stora", "ge_uri"),
        ("eviden", "ce_uri"),
        ("productio", "n registry"),
        ("live f", "inality"),
        ("so", "c2"),
        ("certified", " valuation"),
        ("truste", "d asset"),
        ("accurate ", "valuation"),
    )
]

NEEDLE_LISTS = {
    "disclosure": DISCLOSURE_SUBSTRINGS,
    "private_perimeter": PRIVATE_PERIMETER_SUBSTRINGS,
    "claim_discipline": CLAIM_DISCIPLINE_SUBSTRINGS,
}

# Matched with case: the JSON key a canonical-input payload carries is lower case, and folded it
# would also match a published reason code whose identifier ends in the same word.
CASE_SENSITIVE_NEEDLES = frozenset({"".join(("canonica", 'l_input":'))})

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# What prints as nothing, the readable controls aside (tab, line feed, carriage return): the
# categories below, every space but U+0020, Default_Ignorable_Code_Point (Unicode
# DerivedCoreProperties.txt, written out because unicodedata does not expose it) plus U+2800, and
# the 66 noncharacters.
_READABLE_CONTROLS = frozenset((9, 10, 13))
_INVISIBLE_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))
_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_ENCODED_BLOCK = re.compile(r"(?m)^begin(?:-base64)?[ \t]")

# The packing of a directory: stored entries, made by a Unix host with mode 0644, dated
# 1980-01-01, no data descriptor, no extra field, no comment.
_ZIP_LOCAL = struct.Struct("<IHHHHHIIIHH")
_ZIP_CENTRAL = struct.Struct("<IHHHHHHIIIHHHHHII")
_ZIP_END = struct.Struct("<IHHHHIIH")
_ZIP_VERSION = 20
_ZIP_MADE_BY = 0x0300 | _ZIP_VERSION
_ZIP_DOS_DATE = 0x0021
_ZIP_EXTERNAL = 0o100644 << 16


def team_claim(text: str) -> str | None:
    """The sentence in which a repository says a team maintains it, if it says so; a sentence
    that answers "not a team" is the refusal, not the claim."""
    for found in MAINTAINED_BY_A_TEAM.finditer(text):
        if " not " not in found.group(0).lower():
            return found.group(0)
    return None


def governance_failures(root: Path) -> list[str]:
    """Every way GOVERNANCE.md fails to say, truthfully, who maintains this repository."""
    path = root / GOVERNANCE
    if not path.is_file():
        return [f"{GOVERNANCE} is missing, so nothing says who maintains this repository"]
    text = path.read_text(encoding="utf-8")
    failures = []
    claim = team_claim(text)
    if claim is not None:
        failures.append(f"{GOVERNANCE} claims a team: {claim!r}")
    if MAINTAINED_BY_ONE_PERSON not in text:
        failures.append(f"{GOVERNANCE} does not say who maintains this repository ({MAINTAINED_BY_ONE_PERSON!r})")
    return failures


# Citations of a test in prose: a path under tests/ and a name that starts with test and an
# underscore. A repository a citation may name, when it is not held here, is a published one.
_TEST_PATH = re.compile(r"(?<![\w./-])(?:tests/[\w./-]*[\w/]|test/[\w.-]+\.test\.ts(?!\w))")
_TEST_NAME = re.compile(r"(?<![\w./-])test_\w+")
_DEFINED_TEST = re.compile(r"^\s*(?:async\s+)?def (test_\w+)", re.MULTILINE)
PUBLISHED_REPOSITORIES = ("loquitur-protocol", "loquitur-schemas", "loquitur-verify-py", "loquitur-verify-ts")
_REPOSITORY = re.compile(r"\b(" + "|".join(re.escape(name) for name in PUBLISHED_REPOSITORIES) + r")(?![\w-])")
_WHOLE_TEXT = (".md", ".txt", ".rst")
_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_PLACEHOLDER = re.compile(r"/[A-Z][A-Z0-9_]*$")
_HASH_COMMENTED = (".yml", ".yaml", ".toml", ".cfg", ".ini", ".sh", ".ps1", ".in")
_SLASH_COMMENTED = (".ts", ".mts", ".cts", ".js", ".mjs", ".cjs")
# A changelog records past states, so it is not read for citations; named by its stem, since the
# file it names is not one this tool reads.
_PAST_STATES = "CHANGELOG"


def _python_prose(text: str) -> list[str]:
    """The comments, each run of adjacent comment lines one paragraph, and the docstrings."""
    paragraphs: list[str] = []
    try:
        tree = ast.parse(text)
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (SyntaxError, tokenize.TokenError, ValueError):
        return []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            docstring = ast.get_docstring(node, clean=False)
            if docstring:
                paragraphs.append(docstring)
    run: list[str] = []
    last = -2
    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue
        if token.start[0] != last + 1 and run:
            paragraphs.append("\n".join(run))
            run = []
        run.append(token.string)
        last = token.start[0]
    if run:
        paragraphs.append("\n".join(run))
    return paragraphs


def _comment_runs(text: str, pattern: re.Pattern[str]) -> list[str]:
    """Each run of adjacent lines that carry a comment, as one paragraph of their comments."""
    paragraphs: list[str] = []
    run: list[str] = []
    for line in text.splitlines():
        found = pattern.search(line)
        if found:
            run.append(found.group(0))
        elif run:
            paragraphs.append("\n".join(run))
            run = []
    if run:
        paragraphs.append("\n".join(run))
    return paragraphs


def prose(rel: str, text: str) -> list[str]:
    """The paragraphs of prose in the tracked file ``rel``, whose text is ``text``."""
    name = rel.rsplit("/", 1)[-1]
    if name.split(".", 1)[0] == _PAST_STATES:
        return []
    if name.endswith(".json"):
        return [found for found in _JSON_STRING.findall(text) if any(c.isspace() for c in found)]
    if name.endswith(_WHOLE_TEXT):
        return re.split(r"\n[ \t]*\n", text)
    if name.endswith(".py"):
        return _python_prose(text)
    if name.endswith(_HASH_COMMENTED):
        return _comment_runs(text, re.compile(r"(?:^|\s)#.*"))
    if name.endswith(_SLASH_COMMENTED):
        blocks = re.findall(r"/\*.*?\*/", text, flags=re.DOTALL)
        return blocks + _comment_runs(re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL), re.compile(r"(?<![:\w])//.*"))
    return []


class TestIndex:
    """The test paths and test names a repository holds."""

    def __init__(self, root: Path, files: list[str]) -> None:
        self.paths = files
        self.names: set[str] = set()
        for rel in files:
            for part in rel.split("/"):
                self.names.add(part.split(".", 1)[0])
            if rel.endswith(".py"):
                try:
                    self.names.update(_DEFINED_TEST.findall((root / rel).read_text(encoding="utf-8")))
                except (OSError, UnicodeDecodeError):
                    continue

    def holds(self, citation: str) -> bool:
        if citation.startswith(("tests/", "test/")):
            stem = _PLACEHOLDER.sub("/", citation)
            return any(path.startswith(stem) for path in self.paths)
        if citation.endswith("_"):
            return any(name.startswith(citation) for name in self.names)
        return citation in self.names


def citation_failures(root: Path, files: list[str], texts: dict[str, str]) -> list[str]:
    """Every test the prose of ``texts`` (tracked path to text) cites that a reader cannot find."""
    here = TestIndex(root, files)
    siblings: dict[str, TestIndex | None] = {}
    failures = []
    for rel, text in texts.items():
        for paragraph in prose(rel, text):
            citations = _TEST_PATH.findall(paragraph) + _TEST_NAME.findall(paragraph)
            for citation in dict.fromkeys(citations):
                if here.holds(citation):
                    continue
                named = [name for name in dict.fromkeys(_REPOSITORY.findall(paragraph)) if name != root.name]
                held = False
                for name in named:
                    if name not in siblings:
                        sibling = root.parent / name
                        siblings[name] = TestIndex(sibling, tracked_files(sibling)) if sibling.is_dir() else None
                    if siblings[name] is None or siblings[name].holds(citation):
                        held = True
                        break
                if not held:
                    failures.append(
                        f"{rel} cites {citation}, which neither this repository"
                        " nor a published repository it names holds"
                    )
    return failures


def invisible(code: int) -> bool:
    """Whether the code point ``code`` prints as nothing and so must be written as an escape."""
    if code in _READABLE_CONTROLS:
        return False
    category = unicodedata.category(chr(code))
    return (
        category in _INVISIBLE_CATEGORIES
        or (category == "Zs" and code != 0x20)
        or any(low <= code <= high for low, high in _DEFAULT_IGNORABLE)
        or 0xFDD0 <= code <= 0xFDEF
        or code & 0xFFFE == 0xFFFE
    )


def invisible_failures(label: str, text: str) -> list[str]:
    """One finding per literal invisible code point of ``text``; ``label`` names the file."""
    return [
        f"invisible character U+{ord(character):04X} at {label}:{number}:{column}; write it as an escape"
        for number, line in enumerate(text.split(chr(10)), start=1)
        for column, character in enumerate(line, start=1)
        if invisible(ord(character))
    ]


def text_of(blob: bytes) -> str | None:
    """``blob`` as text: UTF-8 with no control character but tab, line feed and carriage return."""
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if _CONTROL.search(text) else text


def packing(prefix: str, files: dict[str, bytes]) -> bytes:
    """The packing of ``files`` (path inside the directory to bytes) as entries named
    ``prefix/path``, in byte order of the entry names."""
    body = bytearray()
    central = bytearray()
    names = sorted(((f"{prefix}/{rel}", data) for rel, data in files.items()), key=lambda item: item[0].encode("utf-8"))
    for name, data in names:
        raw = name.encode("utf-8")
        crc = zlib.crc32(data)
        offset = len(body)
        body += _ZIP_LOCAL.pack(
            0x04034B50, _ZIP_VERSION, 0, 0, 0, _ZIP_DOS_DATE, crc, len(data), len(data), len(raw), 0
        )
        body += raw + data
        central += _ZIP_CENTRAL.pack(
            0x02014B50,
            _ZIP_MADE_BY,
            _ZIP_VERSION,
            0,
            0,
            0,
            _ZIP_DOS_DATE,
            crc,
            len(data),
            len(data),
            len(raw),
            0,
            0,
            0,
            0,
            _ZIP_EXTERNAL,
            offset,
        )
        central += raw
    end = _ZIP_END.pack(0x06054B50, 0, 0, len(names), len(names), len(central), len(body), 0)
    return bytes(body + central + end)


def packed_from(root: Path, rel: str, blob: bytes, files: list[str]) -> bool:
    """Whether ``rel`` is ``NAME.zip`` and ``blob`` is the packing of the tracked files under ``NAME/``."""
    if not rel.endswith(".zip"):
        return False
    directory = rel[: -len(".zip")]
    inside = {name[len(directory) + 1 :]: name for name in files if name.startswith(directory + "/")}
    if not inside:
        return False
    prefix = directory.rsplit("/", 1)[-1]
    return packing(prefix, {short: (root / name).read_bytes() for short, name in inside.items()}) == blob


def find_needles(text: str, needles: list[str]) -> list[str]:
    """The needles ``text`` carries; every needle but the case-sensitive ones is matched folded."""
    folded = text.lower()
    return [
        needle
        for needle in needles
        if (needle in text if needle in CASE_SENSITIVE_NEEDLES else needle.lower() in folded)
    ]


def tracked_files(root: Path) -> list[str]:
    """The paths git tracks under ``root``; outside a checkout, every file less the tool caches."""
    try:
        listing = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        if (root / ".git").exists():
            return sorted(name.decode("utf-8") for name in listing.split(b"\0") if name)
    except (OSError, subprocess.CalledProcessError):
        pass
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not CACHE_PARTS & set(path.relative_to(root).parts)
    )


def load_config(root: Path) -> dict:
    config = json.loads((root / CONFIG).read_text(encoding="utf-8"))
    expected = {
        "archive_member_lists",
        "corpus_lock",
        "forbidden_roots",
        "needle_lists",
        "reviewed",
        "schema_version",
    }
    if set(config) != expected or config["schema_version"] != CONFIG_SCHEMA:
        raise ValueError(f"{CONFIG} holds exactly {sorted(expected)} with schema_version {CONFIG_SCHEMA}")
    for name in config["needle_lists"] + config["archive_member_lists"]:
        if name not in NEEDLE_LISTS:
            raise ValueError(f"{CONFIG} names an unknown needle list {name!r}")
    return config


def _needles(names: list[str]) -> list[str]:
    return list(dict.fromkeys(needle for name in names for needle in NEEDLE_LISTS[name]))


class Clearing:
    """The reviewed digests, which of them a run used, what provenance cleared, and the facts the
    clearance routes read (``context``); ``cleared_by`` records which route decided each path."""

    def __init__(self, reviewed: list[dict]) -> None:
        self.reviewed: dict[str, dict] = {}
        self.used: set[str] = set()
        self.proved: set[str] = set()
        self.failures: list[str] = []
        self.cleared_by: dict[str, str] = {}
        self.context: dict[str, object] = {}
        for entry in reviewed:
            if set(entry) != {"path", "reason", "sha256"} or not str(entry.get("reason", "")).strip():
                self.failures.append(f"{CONFIG}: a reviewed entry needs exactly path, sha256 and a reason: {entry!r}")
            elif entry["path"] in self.reviewed:
                self.failures.append(f"{CONFIG}: {entry['path']} is reviewed twice")
            else:
                self.reviewed[entry["path"]] = entry

    def clear(self, domain: str, label: str, blob: bytes, needles: list[str]) -> list[str]:
        """The findings over ``blob``, a tracked file or a member as ``domain`` says: the first route
        of CLEARANCE_ROUTES that applies there and answers decides, and otherwise ``blob`` is searched
        as text or reported as not text; ``label`` names it."""
        text = text_of(blob)
        for name, domains, route in CLEARANCE_ROUTES:
            if domain not in domains:
                continue
            answer = route(self, label, blob, text)
            if answer is not None:
                self.cleared_by[label] = name
                return answer
        if text is None:
            self.cleared_by[label] = "not-cleared"
            return [
                f"not text and no reviewed digest, so not cleared: {label} (sha256 {hashlib.sha256(blob).hexdigest()})"
            ]
        self.cleared_by[label] = "searched"
        return self.search(label, text, needles)

    @staticmethod
    def search(label: str, text: str, needles: list[str]) -> list[str]:
        """The needles and the encoded block ``text`` carries; ``label`` names it."""
        failures = [f"forbidden substring {needle!r} in {label}" for needle in find_needles(text, needles)]
        if _ENCODED_BLOCK.search(text):
            failures.append(f"an encoded block is not read, so not cleared: {label}")
        return failures

    def unused(self) -> list[str]:
        return [
            f"{CONFIG} reviews {path}, which its provenance clears; remove the review"
            if path in self.proved
            else f"{CONFIG} reviews {path}, which this run did not meet"
            for path in sorted(set(self.reviewed) - self.used)
        ]


def _corpus_builder(root: Path):
    spec = importlib.util.spec_from_file_location("corpus_archive", root / "tools/corpus_archive.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crafted(root: Path):
    """The crafted-members module the repository carries, or ``None``."""
    path = root / CRAFTED
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("crafted_members", path)
    module = importlib.util.module_from_spec(spec)
    # Registered while it runs: its dataclass looks its own module up by name.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def member_failures(root: Path, members: dict[str, bytes], needles: list[str], clearing: Clearing) -> list[str]:
    """Every finding over the members of the pinned corpus archive."""
    crafted = _crafted(root)
    clearing.context["crafted"] = crafted
    clearing.context["built"] = crafted.built(members) if crafted is not None else {}
    clearing.context["member_needles"] = needles
    failures: list[str] = []
    for name, content in sorted(members.items()):
        failures += clearing.clear("member", name, content, needles)
    return failures


def corpus_members(root: Path, config: dict, rel: str, blob: bytes) -> dict[str, bytes] | None:
    """The members of ``blob`` when it is the pinned corpus archive and its canonical build."""
    if not config["corpus_lock"]:
        return None
    lock = json.loads((root / config["corpus_lock"]).read_text(encoding="utf-8"))
    if rel != lock.get("artifact") or hashlib.sha256(blob).hexdigest() != lock.get("sha256"):
        return None
    builder = _corpus_builder(root)
    try:
        return builder.members_of(blob)
    except builder.CanonicalArchiveError:
        return None


def _packed(clearing: Clearing, label: str, blob: bytes, text: str | None) -> list[str] | None:
    """A tracked NAME.zip that is the packing of the tracked files under NAME/."""
    if text is not None or not packed_from(clearing.context["root"], label, blob, clearing.context["files"]):
        return None
    clearing.proved.add(label)
    return []


def _corpus(clearing: Clearing, label: str, blob: bytes, text: str | None) -> list[str] | None:
    """The pinned corpus archive, built canonically from its members: the members' findings."""
    if text is not None:
        return None
    members = corpus_members(clearing.context["root"], clearing.context["config"], label, blob)
    if members is None:
        return None
    return member_failures(clearing.context["root"], members, clearing.context["archive_needles"], clearing)


def _rebuilt(clearing: Clearing, label: str, blob: bytes, text: str | None) -> list[str] | None:
    """A member the crafted-members tool builds byte for byte from the other members."""
    built = clearing.context.get("built") or {}
    if label not in built or built[label] != blob:
        return None
    clearing.proved.add(label)
    return []


def _spliced(clearing: Clearing, label: str, blob: bytes, text: str | None) -> list[str] | None:
    """A member that is text with one listed run of bytes spliced in: the text without the run."""
    crafted = clearing.context.get("crafted")
    if crafted is None or text is not None:
        return None
    unspliced = crafted.spliced(label, blob)
    rest = text_of(unspliced) if unspliced is not None else None
    if rest is None:
        return None
    clearing.proved.add(label)
    return clearing.search(label, rest, clearing.context["member_needles"])


def _zero_filled(clearing: Clearing, label: str, blob: bytes, text: str | None) -> list[str] | None:
    """Bytes that are NUL only, which hold nothing to read."""
    if text is not None or not blob or blob.strip(b"\0"):
        return None
    clearing.proved.add(label)
    return []


def _reviewed(clearing: Clearing, label: str, blob: bytes, text: str | None) -> list[str] | None:
    """Bytes a person reviewed, by the digest recorded with a reason in the configuration."""
    if label not in clearing.reviewed:
        return None
    clearing.used.add(label)
    digest = hashlib.sha256(blob).hexdigest()
    if clearing.reviewed[label]["sha256"] != digest:
        return [f"{label} is not the bytes its review recorded (sha256 {digest}); review it again"]
    return []


# The clearance routes, in the order they are tried, each with where it applies: "file" for a tracked
# file, "member" for a member of the pinned corpus archive. A route answers None when it does not
# clear the bytes, and otherwise the findings over what it cleared, [] when that is all of it.
CLEARANCE_ROUTES = (
    ("packed", ("file",), _packed),
    ("corpus", ("file",), _corpus),
    ("crafted", ("member",), _rebuilt),
    ("spliced", ("member",), _spliced),
    ("zero-filled", ("file", "member"), _zero_filled),
    ("reviewed", ("file", "member"), _reviewed),
)


def check(root: Path) -> list[str]:
    """Every finding over the repository at ``root``; an empty list when it is cleared."""
    try:
        config = load_config(root)
    except (OSError, ValueError) as exc:
        return [f"{CONFIG} cannot be read ({exc})"]
    failures: list[str] = governance_failures(root)
    for pattern in config["forbidden_roots"]:
        for found in sorted(root.glob(pattern)):
            failures.append(f"forbidden root path present: {found.name}")
    clearing = Clearing(config["reviewed"])
    failures += clearing.failures
    own = _needles(config["needle_lists"])
    members_needles = _needles(config["archive_member_lists"])
    files = tracked_files(root)
    if not files:
        return [f"no files found under {root}; nothing was scanned"]
    clearing.context.update(root=root, config=config, files=files, archive_needles=members_needles)
    texts: dict[str, str] = {}
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        blob = path.read_bytes()
        text = text_of(blob)
        binary = text is None
        if not binary:
            texts[rel] = text
            failures += invisible_failures(rel, text)
        failures += clearing.clear("file", rel, blob, own)
    failures += clearing.unused()
    failures += citation_failures(root, files, texts)
    return list(dict.fromkeys(failures))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--pack", type=Path, metavar="DIRECTORY", help="write DIRECTORY.zip, its packing, and exit")
    args = parser.parse_args(argv)
    if args.pack is not None:
        directory = args.pack.resolve()
        files = {
            path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob("*")
            if path.is_file() and not CACHE_PARTS & set(path.relative_to(directory).parts)
        }
        directory.with_name(directory.name + ".zip").write_bytes(packing(directory.name, files))
        return 0
    failures = check(args.root.resolve())
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("public_boundary_ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
