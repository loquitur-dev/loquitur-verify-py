"""What the human-readable output may say: claim words only in phrases a check establishes.

The words "valid", "validated", "verified", "authentic", "authenticated", "trusted", "genuine",
"certified" and "guaranteed" (any case) are the ones a reader takes as a statement about the
evidence. Each may appear in what a person reads only inside a phrase listed below, and each
listed phrase says, in a comment, which check establishes it or why it claims nothing (a
negation, a statement about an option's values). A new occurrence outside the lists fails, so a
sentence that claims more than its check cannot reach a reader unreviewed.

Three sources are read:

* the package: every string constant of src/loquitur/verify/*.py that is not a docstring and
  holds a space (prose, not a reason code or member name), which covers the command line's help
  and stderr messages and every error message the readable report prints;
* the command line as run: the help text, a usage error, and the readable text report over the
  fixture bundles, registry entries and trust registries;
* the narrative sentences: the wording of the reason-code catalog of loquitur-schemas, which
  narrative.py renders and does not own (its composition templates and every entry). Without
  loquitur-schemas this part skips, and fails where LOQUITUR_REQUIRE_SIBLINGS is set.

Identifiers are not prose: ``\\b`` does not separate a word from an underscore, so
``VALID_SIGNATURE`` or ``trust_registry_root_signature_verified`` never match. This is the
maintainer's own review of the wording, carried out with the help of AI tools, which is internal
verification and not an audit.
"""

from __future__ import annotations

import ast
import contextlib
import io
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

import pytest
from siblings import absent

from loquitur.verify.cli import main

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "loquitur" / "verify"
FIXTURES = ROOT / "tests" / "fixtures"
EVALUATION_TIME = "2026-05-10T00:00:00Z"

CLAIM_WORDS = re.compile(
    r"\b(valid|validated|verified|authentic|authenticated|trusted|genuine|certified|guaranteed)\b", re.IGNORECASE
)

# Phrases of the package's own strings and of the command line's output.
PACKAGE_PHRASES = {
    # --narrative help text: the values the option accepts. A statement about the command line,
    # not about the evidence.
    "Valid values: technical, compliance, executive",
    # stderr when --narrative names no audience or an unknown one: the values the option accepts.
    "valid values are:",
    # canonical.py refusals, printed as an error message: the lone-surrogate check found a
    # string that is no sequence of Unicode scalar values. A negation, about the input's text.
    "is not valid Unicode",
    # trust_root.py, the detail of a root check with no pinned root: a negation, saying the
    # registry is refused rather than reported as verified.
    "rather than reporting an unverified registry as verified",
}

# Phrases of the reason-code catalog (loquitur-schemas), as narrative.py renders them.
CATALOG_PHRASES = {
    # Technical detail of every authorization code. narrative.py cites an authorization code
    # only when the report establishes the integrity check (infer_active_reason_codes, the
    # _CHECK_INTEGRITY gate), and only after the registry entry's contract held.
    "Bundle integrity verified and the registry entry is well formed",
    "Bundle integrity verified and the entry is well formed",
    "Bundle integrity verified:",
    "Bundle-level integrity verified:",
    # AUTHORIZATION_SCOPE_MISMATCH: cited when the trust registry lists the key as active and
    # inside its window and only the scope fails; same integrity gate.
    "Bundle integrity verified, the registry entry is well formed, and the issuer key is active and within its validity window",
    "holding a valid key is not sufficient",
    "the issuer holds a valid, active key",
    # Same code. "Trusted" here means listed as active in the trust registry supplied for the
    # run. Without a pinned trust root that registry is itself taken as given; the wording
    # belongs to loquitur-schemas, not to this package, and is a candidate for rewording there.
    # AUTHORIZATION_VERIFIED: cited only on an OFFLINE_OK run whose authorization status is
    # AUTHORIZED_ACTIVE_KEY (the affirmative-code gate), so the signature and the key's
    # authorization in the supplied material both held. Scoped to "the supplied trust material".
    "The issuer's authority verified against the supplied trust material",
    # The same code's technical detail: a qualification, saying what is NOT verified.
    "the trust registry's own root signature is not verified, so that material is trusted as given",
    # Closings for an authorization-only failure and a signature failure. FAIL_AUTHORIZATION
    # is chosen only when every active code is an authorization code, which narrative.py
    # cites only when the integrity check is established; FAIL_SIGNATURE likewise follows
    # the signature code, cited under the same gate.
    "manifest, P1, envelope and canonical-input replay all verified",
    "The bundle's own contents verified;",
    "The bundle's contents verified;",
    # Verdict leads: rendered only for a PASS (OFFLINE_OK and PASS) or a WARN verdict, and
    # scoped to the layers the run covered.
    "The verification record is valid and may be relied upon for the layers it covers",
    "The verification record is valid and may be relied upon, with recorded warnings",
    # Leads of the registry_entry context: the entry records that verdict; "confirms" is the
    # entry's statement, read for a PASS or WARN verdict.
    "The public registry entry confirms a valid verification record",
    # MARK_STALE: hedged ("may be"), and the sentence says what is wrong.
    "The receipt may be technically valid but its evidentiary basis is dated",
    # Negations: each says what could not be established.
    "could be verified independently",
    "cannot be fully verified",
    "cannot be verified against any commitment",
    "cannot be trusted in its current form",
    "cannot be trusted as authentic",
    "cannot be trusted as authoritative",
    "could not confirm this record is genuine",
    "recorded as not-verified rather than failed",
    "The receipt-to-input link is not validated",
    "not part of the policy-validated scope",
    "cannot be accepted as verified until the value is recognized",
}


def _normalised(text: str) -> str:
    """Runs of whitespace as one space, so a phrase matches across a wrapped help line."""
    return " ".join(text.split())


def uncovered(texts: Iterable[str], phrases: set[str]) -> tuple[list[str], set[str]]:
    """Claim words outside every listed phrase (with context), and the listed phrases found."""
    found: list[str] = []
    used: set[str] = set()
    for raw in texts:
        text = _normalised(raw)
        covered: list[tuple[int, int]] = []
        for phrase in phrases:
            for match in re.finditer(re.escape(phrase), text):
                covered.append(match.span())
                used.add(phrase)
        for word in CLAIM_WORDS.finditer(text):
            if not any(start <= word.start() and word.end() <= end for start, end in covered):
                found.append(text[max(0, word.start() - 60) : word.end() + 40])
    return found, used


def _docstring_nodes(tree: ast.AST) -> set[int]:
    nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                nodes.add(id(first.value))
    return nodes


def package_prose() -> Iterator[str]:
    """Every string constant of the package that is prose: not a docstring, and holding a space."""
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                if " " in node.value:
                    yield node.value
            elif isinstance(node, ast.JoinedStr):
                # The constant parts of an f-string, joined, so a phrase split by a placeholder
                # is still read as one text; the parts are also yielded above, one by one.
                yield "".join(part.value for part in node.values if isinstance(part, ast.Constant))


def _cli(*args: str) -> str:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            main(list(args))
        except SystemExit:
            pass
    return out.getvalue() + "\n" + err.getvalue()


def cli_output() -> Iterator[str]:
    """The help text, a usage error, and the readable text report over the fixtures."""
    yield _cli("--help")
    yield _cli(str(FIXTURES / "link_valid_bundle"), "--narrative", "nobody")
    bundle = str(FIXTURES / "link_valid_bundle")
    for path in sorted(FIXTURES.iterdir()):
        if path.name.endswith(("_bundle", "_bundle.zip")):
            yield _cli(str(path))
    entry = str(FIXTURES / "authorization_valid_registry_entry.json")
    trust = str(FIXTURES / "authorization_valid_trust_registry.json")
    for path in sorted(FIXTURES.glob("*_registry_entry.json")):
        yield _cli(bundle, "--registry-entry", str(path))
        yield _cli(
            bundle, "--registry-entry", str(path), "--trust-registry", trust, "--evaluation-time", EVALUATION_TIME
        )
    for path in sorted(FIXTURES.glob("*_trust_registry.json")):
        yield _cli(
            bundle, "--registry-entry", entry, "--trust-registry", str(path), "--evaluation-time", EVALUATION_TIME
        )
        yield _cli(
            bundle,
            "--registry-entry",
            entry,
            "--trust-registry",
            str(path),
            "--evaluation-time",
            EVALUATION_TIME,
            "--trust-root",
            str(FIXTURES / "authorization_quickstart_trust_root.json"),
        )


def catalog_texts() -> Iterator[str]:
    try:
        from loquitur.schemas import load_reason_codes_catalog
    except ImportError as exc:
        absent(f"the narrative wording is the catalog of loquitur-schemas, which is not importable: {exc}")
    catalog = load_reason_codes_catalog()

    def strings(value: object) -> Iterator[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Mapping):
            for item in value.values():
                yield from strings(item)

    yield from strings(catalog.composition_templates)
    for entry in catalog.entries.values():
        for narrative in (entry.technical, entry.compliance, entry.executive):
            yield from strings(vars(narrative))


def test_the_package_strings_use_claim_words_only_in_listed_phrases() -> None:
    found, used = uncovered(package_prose(), PACKAGE_PHRASES)
    assert not found, f"claim words outside the listed phrases: {found}"
    # Every phrase but the help text's is a string of the package; the help text is checked below.
    assert used >= PACKAGE_PHRASES - {"Valid values: technical, compliance, executive"}, PACKAGE_PHRASES - used


def test_the_command_line_output_uses_claim_words_only_in_listed_phrases() -> None:
    found, used = uncovered(cli_output(), PACKAGE_PHRASES)
    assert not found, f"claim words outside the listed phrases: {found}"
    assert {"Valid values: technical, compliance, executive", "valid values are:"} <= used


def test_the_narrative_sentences_use_claim_words_only_in_listed_phrases() -> None:
    found, used = uncovered(catalog_texts(), CATALOG_PHRASES)
    assert not found, f"claim words outside the listed phrases: {found}"
    assert used == CATALOG_PHRASES, f"listed phrases the catalog no longer holds: {sorted(CATALOG_PHRASES - used)}"


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("The record is verified.", True),
        ("A GENUINE record", True),
        ("Trusted by the operator", True),
        ("ROOT_SIGNATURE_VALID and trust_registry_root_signature_verified", False),
        ("cannot be trusted in its current form", False),
        ("an invalid digest; unverified", False),
    ],
)
def test_the_scan_flags_claim_words_and_not_identifiers(text: str, flagged: bool) -> None:
    found, _ = uncovered([text], CATALOG_PHRASES)
    assert bool(found) is flagged, found
