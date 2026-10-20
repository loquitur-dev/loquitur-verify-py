"""The trust-root document is validated as a whole when it is read, held to trust-root.md §3.

A malformed root is not a row of the evaluation order of §5, where a root the trust registry
does not name would never be examined and a named one would lose to the rows before it. This
verifier refuses the document when it reads it, every element whatever its key_id, before any
row of §5, as section 3 says, and report-contract.md §4 states what a library interface does
with such roots.

Both tables of §3 are read from the sibling loquitur-protocol checkout (spec_tables.py) and run
three ways: through the command line (exit 64, no report), through the library with the
document (parse_trust_roots refuses it), and through the library with roots already built
(verify_path raises before it reads the bundle, verify_registry_entry_trust before it reads the
trust registry or looks at the entry). The runs use the quickstart fixtures, whose
trust registry the public quickstart root signed; no private key is involved.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import re
from pathlib import Path
from typing import Any

from spec_tables import code, codes, document, table

from loquitur.verify import verify_registry_entry_trust
from loquitur.verify.cli import EXIT_USAGE_ERROR, main
from loquitur.verify.runner import EXIT_UNSUPPORTED_VERSION, verify_path
from loquitur.verify.trust_root import (
    STATUS_AMBIGUOUS_ROOT_KEY,
    STATUS_MALFORMED_SIGNATURE,
    STATUS_MALFORMED_TRUST_REGISTRY,
    STATUS_NO_PINNED_ROOT,
    STATUS_ROOT_EXPIRED,
    STATUS_ROOT_NOT_YET_VALID,
    STATUS_ROOT_REVOKED,
    STATUS_SIGNATURE_INVALID,
    STATUS_UNKNOWN_ROOT_KEY,
    STATUS_UNSUPPORTED_ALGORITHM,
    STATUS_VALID,
    TrustRootError,
    TrustRootKey,
    parse_trust_roots,
    verify_trust_registry_root_signature,
)

SPEC = "trust-root.md"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUNDLE = FIXTURES / "link_valid_bundle.zip"
ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
SIGNED_REGISTRY = json.loads((FIXTURES / "authorization_quickstart_trust_registry.json").read_text(encoding="utf-8"))
QUICKSTART_ROOTS = json.loads((FIXTURES / "authorization_quickstart_trust_root.json").read_text(encoding="utf-8"))
NAMED = QUICKSTART_ROOTS["roots"][0]
# The instant the quickstart run is judged at: the entry's effective_at (README, authorization section).
EVALUATED_AT = json.loads(ENTRY.read_text(encoding="utf-8"))["effective_at"]
MEMBERS = {"key_id", "key_type", "public_key_hex", "not_before", "not_after", "status"}
# The two members every trust-root document carries before its roots (section 3), written H in
# the document table.
HEAD = {"object_type": "trust_root_document", "schema_version": "v1"}


def _flat(text: str) -> str:
    return " ".join(text.split())


def _cli(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        exit_code = main(argv)
    return exit_code, out.getvalue()


def _negated(public_key_hex: str) -> str:
    """The compressed SEC1 encoding of the point -P, for the uncompressed encoding of P.

    -P has P's x and the other y, so it is a secp256k1 point that P does not share: it differs
    from P's key by no more than the parity of y.
    """
    assert re.fullmatch(r"04[0-9a-f]{128}", public_key_hex), public_key_hex
    x, y = public_key_hex[2:66], int(public_key_hex[66:], 16)
    return ("03" if y % 2 == 0 else "02") + x


def _cell_values(cell: str, members: list[str], target: dict[str, Any]) -> list[Any]:
    """The values a row's value cell gives its members, in the order the member cell names them."""
    if cell == "`N`'s `key_id` in upper case":
        assert members == ["key_id"]
        return [NAMED["key_id"].upper()]
    if cell == '`"ed25519"`, and a key of its own that shares no point with `N`\'s':
        assert members == ["key_type", "public_key_hex"]
        return ["ed25519", _negated(NAMED["public_key_hex"])]
    if cell == '`"ed25519"`, `root-9` still carrying `N`\'s key':
        assert members == ["key_type"] and target["key_id"] == "root-9"
        assert target["public_key_hex"] == NAMED["public_key_hex"]
        return ["ed25519"]
    assert len(members) == 1, (cell, members)
    return [json.loads(code(cell))]


def _trust_registry(variant: str) -> dict[str, Any]:
    """The quickstart trust registry, as the table's column describes it."""
    registry = copy.deepcopy(SIGNED_REGISTRY)
    if variant == "signed by `N`":
        return registry
    if variant == "signature not lowercase hex":
        registry["signature"]["signature"] = registry["signature"]["signature"].upper()
    elif variant == "names a key no root has":
        registry["signature"]["key_id"] = "root-7"
    elif variant == "altered after signing":
        registry["entries"][0]["notes"] += " Altered."
    else:
        raise AssertionError(f"the trust registry column has a value this test does not know: {variant!r}")
    return registry


def _roots_document(row: dict[str, str]) -> dict[str, Any]:
    """{"roots":[N]}, with the row's change applied to N or to an added root-9."""
    named = copy.deepcopy(NAMED)
    elements: list[Any] = [named]
    if row["root"] == "—":
        assert row["member"] == row["value"] == "—", row
        return {**HEAD, "roots": elements}
    if row["root"] == "`N`":
        target = named
    else:
        assert code(row["root"]) == "root-9", row
        target = dict(named, key_id="root-9")
        elements.append(target)
    if row["member"] == "—":
        elements[elements.index(target)] = json.loads(code(row["value"]))
    elif row["value"] == "absent":
        del target[code(row["member"])]
    else:
        # A member cell names one member, or several as a list of code spans.
        members = codes(row["member"])
        assert row["member"] == ", ".join(f"`{member}`" for member in members), row
        target.update(zip(members, _cell_values(row["value"], members, target), strict=True))
    return {**HEAD, "roots": elements}


def _built_roots(document_: dict[str, Any]) -> tuple[TrustRootKey, ...] | None:
    """The roots as a library caller builds them, when every element can be built at all."""
    elements = document_["roots"]
    if not all(isinstance(element, dict) and set(element) <= MEMBERS for element in elements):
        return None
    if not all(
        {"key_id", "key_type", "public_key_hex", "not_before", "not_after"} <= set(element) for element in elements
    ):
        return None
    return tuple(TrustRootKey(**element) for element in elements)


def test_section_3_states_the_rule_and_section_5_has_no_malformed_row() -> None:
    text = document(SPEC)
    flat = _flat(text)
    for sentence in (
        "A verifier **MUST** validate the trust-root document against this section when it reads it, "
        "before it evaluates any row of §5: the document itself, and every element of its array, whatever "
        "the element's `key_id` and whether or not the trust registry names it.",
        "A document that breaks this section anywhere is malformed, and a malformed document is refused as "
        "a whole. It is never evaluated in part, and no status of §5 reports it",
        "A command line refuses a malformed document with exit `64` and no report",
        "refuses a set that has any root breaking this section with an error of the host language, before "
        "it evaluates any row of §5 or reads any evidence, and returns no report.",
        "The roots were validated as a whole when they were read (§3): a malformed set was refused then, "
        "and the rows below are evaluated only against a well-formed one.",
    ):
        assert sentence in flat, sentence
    contract = _flat(document("report-contract.md"))
    assert "Given trust roots that break `trust-root.md` §3, any one of them, it returns no report" in contract

    # §5: rows numbered 1, 2, ... then the otherwise row, and every row a status of this verifier.
    rows = table(text, ["#", "condition", "status", "effect"])
    assert [row["#"] for row in rows] == [str(n) for n in range(1, len(rows))] + ["—"]
    statuses = [code(row["status"]) for row in rows]
    assert set(statuses) == {
        STATUS_NO_PINNED_ROOT,
        STATUS_MALFORMED_TRUST_REGISTRY,
        STATUS_MALFORMED_SIGNATURE,
        STATUS_UNSUPPORTED_ALGORITHM,
        STATUS_UNKNOWN_ROOT_KEY,
        STATUS_AMBIGUOUS_ROOT_KEY,
        STATUS_ROOT_REVOKED,
        STATUS_ROOT_NOT_YET_VALID,
        STATUS_ROOT_EXPIRED,
        STATUS_SIGNATURE_INVALID,
        STATUS_VALID,
    }
    # The cross-references to renumbered rows follow the table.
    number = {status: row["#"] for status, row in zip(statuses, rows, strict=True) if row["#"] != "—"}
    revoked, not_yet, expired = (
        number[STATUS_ROOT_REVOKED],
        number[STATUS_ROOT_NOT_YET_VALID],
        number[STATUS_ROOT_EXPIRED],
    )
    assert f"**Revocation is checked before the validity window ({revoked} before {not_yet} and {expired}).**" in flat
    assert f"reaches `ROOT_SIGNATURE_INVALID` (§5, row {number[STATUS_SIGNATURE_INVALID]})" in flat
    assert f"`trust-root.md` §5, rows {revoked} to {expired}" in _flat(document("threat-model.md"))


def test_the_document_table(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["document", "document is"])
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps(SIGNED_REGISTRY), encoding="utf-8")
    got, expected = {}, {}
    for index, row in enumerate(rows):
        written = code(row["document"])
        head = json.dumps(HEAD, separators=(",", ":"))[1:-1]
        payload = json.loads(written.replace("{H", "{" + head).replace("R", json.dumps(NAMED)))
        # The library, given the document: a malformed one raises before any evidence is read, and
        # one of a well-formed later version is reported as an unsupported version (report-contract.md
        # section 5.5). parse_trust_roots alone refuses both, since it builds only a v1 set.
        try:
            library_report = verify_path(
                BUNDLE,
                registry_entry_path=ENTRY,
                trust_registry_path=registry,
                trust_roots=payload,
                evaluation_time=EVALUATED_AT,
            )
            library = "an unsupported version" if library_report.status == "UNSUPPORTED_VERSION" else "well-formed"
        except TrustRootError:
            library = "malformed"
        try:
            parse_trust_roots(payload)
            assert library == "well-formed", written
        except TrustRootError:
            assert library != "well-formed", written
        path = tmp_path / f"document-{index}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        exit_code, stdout = _cli(
            [str(BUNDLE), "--registry-entry", str(ENTRY), "--trust-registry", str(registry)]
            + ["--trust-root", str(path), "--json"]
        )
        if (exit_code, stdout) == (EXIT_USAGE_ERROR, ""):
            command_line = "malformed"
        elif exit_code == EXIT_UNSUPPORTED_VERSION:
            report = json.loads(stdout)
            assert [{k: error[k] for k in ("code", "object", "version")} for error in report["errors"]] == [
                {"code": "unsupported_version", "object": "trust_root_document", "version": payload["schema_version"]}
            ]
            command_line = "an unsupported version"
        else:
            command_line = "well-formed"
        got[written] = (library, command_line)
        expected[written] = (row["document is"], row["document is"])
    assert got == expected
    assert {value for value, _ in expected.values()} == {"well-formed", "malformed", "an unsupported version"}


def test_the_element_table(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["case", "root", "member", "value", "trust registry", "outcome"])
    got, expected, built_refusals = {}, {}, 0
    for row in rows:
        case = code(row["case"])
        roots_document = _roots_document(row)
        registry = _trust_registry(row["trust registry"])
        directory = tmp_path / case
        directory.mkdir()
        (directory / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        (directory / "roots.json").write_text(json.dumps(roots_document), encoding="utf-8")

        # The command line.
        exit_code, stdout = _cli(
            [str(BUNDLE), "--registry-entry", str(ENTRY), "--trust-registry", str(directory / "registry.json")]
            + ["--trust-root", str(directory / "roots.json"), "--json", "--evaluation-time", EVALUATED_AT]
        )
        if exit_code == EXIT_USAGE_ERROR and stdout == "":
            outcomes = ["refused"]
        else:
            report = json.loads(stdout)
            status = report["trust_registry"]["trust_registry_root_signature_status"]
            assert exit_code == (0 if status == STATUS_VALID else 1), (
                case,
                exit_code,
                status,
                report["review_reasons"],
            )
            outcomes = [status]

        # The library, given the document.
        try:
            parsed = parse_trust_roots(roots_document)
        except TrustRootError:
            outcomes.append("refused")
        else:
            report = verify_path(
                BUNDLE,
                registry_entry_path=ENTRY,
                trust_registry_path=directory / "registry.json",
                trust_roots=parsed,
                evaluation_time=EVALUATED_AT,
            ).to_dict()
            outcomes.append(report["trust_registry"]["trust_registry_root_signature_status"])

        # The library, given roots already built: refused before the bundle is read, so a
        # bundle path that does not exist is never reached; and refused by the §5 function
        # before any of its rows.
        built = _built_roots(roots_document)
        if built is not None:
            missing = directory / "no-such-bundle"
            try:
                result = verify_path(
                    missing,
                    registry_entry_path=ENTRY,
                    trust_registry_path=directory / "registry.json",
                    trust_roots=built,
                ).to_dict()
                outcomes.append(f"report {result['status']}")
            except TrustRootError:
                outcomes.append("refused")
            try:
                verification = verify_trust_registry_root_signature(registry, evaluated_at=EVALUATED_AT, roots=built)
                outcomes.append(verification.status)
            except TrustRootError:
                outcomes.append("refused")
                built_refusals += 1
            # The authorization entry point, exported by the package: an empty entry and a trust registry
            # path that does not exist, so a well-formed set reports the missing registry, and a
            # malformed one is refused before either is looked at.
            try:
                trust = verify_registry_entry_trust(
                    {}, trust_registry_path=directory / "no-such-registry.json", trust_roots=built
                )
                outcomes.append(f"result {trust.authorization_status}")
            except TrustRootError:
                outcomes.append("refused")

        outcome = row["outcome"] if row["outcome"] == "refused" else code(row["outcome"])
        got[case] = outcomes
        if built is None:
            expected[case] = [outcome, outcome]
        elif outcome == "refused":
            expected[case] = [outcome] * 5
        else:
            # A bundle path where nothing is found is a host-class refusal of the input.
            expected[case] = [outcome, outcome, "report HOST_FAILURE", outcome, "result INVALID_TRUST_REGISTRY"]
    assert got == expected
    outcomes = {row["outcome"] for row in rows}
    assert "refused" in outcomes and len(outcomes) > 1
    assert built_refusals, "no refused row ran through roots built by a library caller"
    # A refused row sits beside an earlier row of §5 that would otherwise hold (5 and 6).
    assert re.search(r"not lowercase hex \| refused", document(SPEC))
    assert re.search(r"names a key no root has \| refused", document(SPEC))
