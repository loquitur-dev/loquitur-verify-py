"""Every row of threat-model.md sections 7 and 11 is a run of this verifier.

Section 7 tabulates the hostile inputs the verifier refuses and the error each one reports;
section 11 records the runs behind the document's claims, each with the input it was given
and what it produced. A table written from runs on one machine and driven by nothing
afterwards goes stale: a cell drifts, a row describes a run nobody repeats, and a run this
verifier makes is missing from the record. This module makes the two tables the record
of what the suite runs. Every row has a run here, keyed by the row's first column, and the
two sets are held equal in both directions: a row without a run fails the suite, and a run
without a row fails it too. Each run's report is compared exactly with what the row's cell
observes, at the place the mapping names (an error, a note, a check value, an authorization status,
an exit code), and a cell the verifier cannot reproduce is corrected in the document, never
approximated here. In section 11 a cell observes its backticked values, its exit codes and the
phrases a run decides ("all", "no report", "no traceback"); the words between them may only join
them, and the only other words a cell may hold are an explanation after its last value, in
parentheses or as a contrast introduced by ", not". A cell with any other word is compared whole,
and so fails: a negation or a qualifier cannot change what a cell says while the run stays green.

Section 7's lead-in also scopes the table, because archive intake is optional: it tells a
verifier that reads directory bundles only which rows it never meets. That scope is prose about
the rows, so it parses whether it is true or not, and a scope wider than the archive rows exempts
a reader from rows that do bind it. It is held here against the runs rather than against the
reading: the rows the lead-in exempts and the rows this suite materializes as an archive are one
set, in both directions.

Section 7's rows are all one gate on this host, including the two POSIX entries: a ZIP
entry's type is what its central-directory external attributes record (bundle-objects.md
section 5, rule ``type``), which zipfile writes on any host, so the symbolic-link and FIFO
rows need no POSIX filesystem. Section 11's rows use the fixtures, keys minted at test time
for the rows that sign, and the command line for the rows that name a flag.

Reads the document through spec_tables.py: skips without the sibling checkout, fails under
LOQUITUR_REQUIRE_SIBLINGS.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from authorization_kit import EVALUATION_TIME, IssuerKey, authorization_material, write_json
from bundle_builder import Bundle, jcs, nested_text
from repository import ROOT, WYCHEPROOF_FILE, in_source_distribution
from spec_tables import document, sections, table
from test_spec_archive_intake import BZIP2, DEFLATED, Entry, write_zip

import loquitur.verify.cli as cli_module
from loquitur.verify.cli import main
from loquitur.verify.trust_root import trust_registry_signing_bytes

SPEC = "threat-model.md"
HOSTILE = "7. The verifier as target — observed outcomes"
OBSERVATIONS = "11. How the claims here were verified"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ENTRY = FIXTURES / "authorization_valid_registry_entry.json"
TRUST = FIXTURES / "authorization_valid_trust_registry.json"
MIB = 1024 * 1024
ELLIPSIS = "…:"


# ---- running the verifier -----------------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    """One command-line run: its exit code, its JSON report (None when it printed none), its stderr."""

    exit: int
    report: dict[str, Any] | None
    stderr: str
    argv: tuple[str, ...] = ()

    def input_is_an_archive(self) -> bool:
        """The input this run was given is a regular file, so an archive rather than a directory."""
        return Path(self.argv[0]).is_file()

    def errors(self) -> list[str]:
        """Each error as ``code`` and, when it carries a message, ``code:message``."""
        found: list[str] = []
        for error in (self.report or {}).get("errors", []):
            found.append(error["code"])
            if error.get("message"):
                found.append(f"{error['code']}:{error['message']}")
        return found

    def notes(self) -> list[str]:
        return list((self.report or {}).get("notes", []))

    def manifest_shape_errors(self) -> list[str]:
        return list(((self.report or {}).get("manifest") or {}).get("shape_errors", []))

    def manifest_file_errors(self) -> list[str]:
        checks = ((self.report or {}).get("manifest") or {}).get("file_checks", [])
        return [check["error"] for check in checks if check.get("error")]

    def check(self, name: str) -> Any:
        assert self.report is not None
        return self.report["checks"][name]

    def trust(self, name: str) -> Any:
        assert self.report is not None
        return (self.report.get("trust_registry") or {})[name]

    def link_check(self, name: str) -> bool:
        assert self.report is not None
        return next(check["ok"] for check in self.report["registry_link"]["checks"] if check["name"] == name)

    def head(self) -> tuple[str, int]:
        """``status`` and exit, the observation most of section 11 starts with."""
        assert self.report is not None
        return self.report["status"], self.report["exit_code"]


def run_cli(argv: list[str]) -> Run:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            exit_code = main([*argv, "--json"])
        except SystemExit as exc:  # argparse usage errors
            exit_code = int(exc.code)
    try:
        report = json.loads(out.getvalue())
    except ValueError:
        report = None
    return Run(exit_code, report, err.getvalue(), tuple(argv))


def _bundle_entries() -> list[Entry]:
    bundle = Bundle().seal()
    return [Entry(name, data, DEFLATED) for name, data in sorted(bundle.members.items())]


# ---- section 7: the hostile inputs, keyed by the row's first column -------------------------------

# Where in the report the row's "Reported" cell is found.
ERROR, NOTE, MANIFEST_SHAPE, MANIFEST_FILE = "error", "note", "manifest shape error", "manifest file error"


def _zip(tmp: Path, name: str, extra: list[Entry]) -> Run:
    return run_cli([str(write_zip(tmp / f"{name}.zip", _bundle_entries() + extra))])


def _sealed_dir(tmp: Path, name: str, mutate: Callable[[Bundle], Any], *, seal: bool = True) -> Run:
    bundle = Bundle()
    mutate(bundle)
    if seal:
        bundle.seal()
    return run_cli([str(bundle.write(tmp / name))])


def _raw_member(bundle: Bundle, name: str, raw: bytes) -> None:
    bundle.members[name] = raw


def _append_raw_member(bundle: Bundle, name: str, tail: str) -> None:
    """The member's canonical text with ``tail`` spliced in before the closing brace."""
    text = jcs(bundle.json(name)).decode("utf-8")
    bundle.members[name] = (text[:-1] + tail + "}").encode("utf-8")


def _both_links_removed(tmp: Path) -> Run:
    bundle = Bundle().seal()
    envelope = bundle.json("envelope_env1.json")
    del envelope["bundle_manifest_sha256"]
    del envelope["p1_sha256"]
    bundle.set_json("envelope_env1.json", envelope).reseal_envelope_sidecar()
    return run_cli([str(bundle.write(tmp / "envelope-no-links"))])


def _two_roots(tmp: Path) -> Run:
    base = _bundle_entries()
    entries = [Entry(f"a/{e.name}", e.data, DEFLATED) for e in base] + [
        Entry(f"b/{e.name}", e.data, DEFLATED) for e in base
    ]
    return run_cli([str(write_zip(tmp / "two-roots.zip", entries))])


def _not_a_zip(tmp: Path) -> Run:
    path = tmp / "not-a-zip.zip"
    path.write_bytes(b"this is not a zip archive")
    return run_cli([str(path)])


HOSTILE_RUNS: dict[str, tuple[str, Callable[[Path], Run]]] = {
    "`../escaped.txt` member": (ERROR, lambda tmp: _zip(tmp, "traversal", [Entry("../escaped.txt")])),
    "`/etc/pwned` member": (ERROR, lambda tmp: _zip(tmp, "absolute", [Entry("/etc/pwned")])),
    "`sub\\x.json` member": (ERROR, lambda tmp: _zip(tmp, "backslash", [Entry("sub/x.json", raw_name=b"sub\\x.json")])),
    "POSIX symlink member": (ERROR, lambda tmp: _zip(tmp, "symlink", [Entry("x.bin", mode=stat.S_IFLNK | 0o777)])),
    "POSIX FIFO member": (ERROR, lambda tmp: _zip(tmp, "fifo", [Entry("x.bin", mode=stat.S_IFIFO | 0o644)])),
    "`p1.json::$DATA` (NTFS ADS alias)": (ERROR, lambda tmp: _zip(tmp, "ads", [Entry("p1.json::$DATA")])),
    "`p1.json.` (NTFS trailing-dot alias)": (ERROR, lambda tmp: _zip(tmp, "trailing-dot", [Entry("p1.json.")])),
    "`P1.JSON` beside `p1.json`": (ERROR, lambda tmp: _zip(tmp, "case-duplicate", [Entry("P1.JSON")])),
    "a file `a` and a member `a/b`": (ERROR, lambda tmp: _zip(tmp, "implied-directory", [Entry("a"), Entry("a/b")])),
    "8 MiB of zeros, deflated": (
        ERROR,
        lambda tmp: _zip(tmp, "8mib-zeros", [Entry("zeros.bin", b"\0" * (8 * MIB), DEFLATED)]),
    ),
    "500 000 zero bytes, deflated": (
        ERROR,
        lambda tmp: _zip(tmp, "500k-zeros", [Entry("zeros.bin", b"\0" * 500_000, DEFLATED)]),
    ),
    "4 × 15 MiB members": (
        ERROR,
        lambda tmp: _zip(
            tmp, "4x15mib", [Entry(f"big{i}.bin", file_size=15 * MIB, compress_size=15 * MIB) for i in range(4)]
        ),
    ),
    "600 members": (ERROR, lambda tmp: _zip(tmp, "600-members", [Entry(f"f{i}.txt") for i in range(600)])),
    "bzip2 compression": (ERROR, lambda tmp: _zip(tmp, "bzip2", [Entry("x.bin", b"x" * 64, method=BZIP2)])),
    "an encrypted member": (ERROR, lambda tmp: _zip(tmp, "encrypted", [Entry("x.bin", flags=1)])),
    "two bundle roots": (ERROR, _two_roots),
    "not a ZIP": (ERROR, _not_a_zip),
    "duplicate JSON member name in `p1.json`": (
        ERROR,
        lambda tmp: _sealed_dir(
            tmp,
            "duplicate-key",
            lambda b: _append_raw_member(b, "p1.json", ',"ih":' + json.dumps(b.json("p1.json")["ih"])),
            seal=False,
        ),
    ),
    "20 000-level nested JSON": (
        ERROR,
        lambda tmp: _sealed_dir(
            tmp, "nested", lambda b: _raw_member(b, "canonical_input.json", nested_text(20000).encode()), seal=False
        ),
    ),
    "`NaN` in canonical input": (
        ERROR,
        lambda tmp: _sealed_dir(
            tmp, "nan", lambda b: _append_raw_member(b, "canonical_input.json", ',"nan":NaN'), seal=False
        ),
    ),
    "invalid UTF-8 in `p1.json`": (
        ERROR,
        lambda tmp: _sealed_dir(
            tmp, "invalid-utf8", lambda b: _raw_member(b, "p1.json", b'{"ih":"\xff\xfe"}'), seal=False
        ),
    ),
    "extra field in `p1.json`": (
        ERROR,
        lambda tmp: _sealed_dir(tmp, "p1-extra", lambda b: b.edit("p1.json", lambda p1: p1.__setitem__("smuggled", 1))),
    ),
    "extra field in `manifest.json`": (
        MANIFEST_SHAPE,
        lambda tmp: _sealed_dir(
            tmp, "manifest-extra", lambda b: b.edit("manifest.json", lambda m: m.__setitem__("smuggled", 1))
        ),
    ),
    "extra field in `envelope_env1.json`": (
        NOTE,
        lambda tmp: _sealed_dir(
            tmp, "envelope-extra", lambda b: b.edit("envelope_env1.json", lambda e: e.__setitem__("smuggled", 1))
        ),
    ),
    "envelope with both digest links removed": (NOTE, _both_links_removed),
    "manifest declaring `../../outside.txt`": (
        MANIFEST_FILE,
        lambda tmp: _sealed_dir(
            tmp,
            "manifest-outside",
            lambda b: b.edit("manifest.json", lambda m: m["files"].__setitem__("../../outside.txt", "0" * 64)),
        ),
    ),
}


def _reported(run: Run, where: str) -> list[str]:
    return {
        ERROR: run.errors(),
        NOTE: run.notes(),
        MANIFEST_SHAPE: run.manifest_shape_errors(),
        MANIFEST_FILE: run.manifest_file_errors(),
    }[where]


# ---- section 11: the observations, keyed by the row's "Claim" column ------------------------------


def _root_signed(registry: dict[str, Any], root: IssuerKey, key_id: str) -> dict[str, Any]:
    """``registry`` carrying a root signature by ``root`` under ``key_id``."""
    unsigned = {k: v for k, v in registry.items() if k != "signature"}
    signature = root.sign_digest(hashlib.sha256(trust_registry_signing_bytes(unsigned)).digest())
    return {**unsigned, "signature": {"algorithm": "secp256k1_ecdsa_sha256", "key_id": key_id, "signature": signature}}


def _roots_document(key: IssuerKey, key_id: str) -> dict[str, Any]:
    return {
        "object_type": "trust_root_document",
        "schema_version": "v1",
        "roots": [
            {
                "key_id": key_id,
                "key_type": "secp256k1",
                "public_key_hex": key.public_key_hex,
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
                "status": "active",
            }
        ],
    }


class Material:
    """The inputs the section-11 runs share, built once per module."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.entry = json.loads(ENTRY.read_text(encoding="utf-8"))
        self.registry = json.loads(TRUST.read_text(encoding="utf-8"))
        self.root, self.other = IssuerKey(), IssuerKey()
        self.roots = write_json(tmp / "roots.json", _roots_document(self.root, "root-1"))
        self.unrelated_roots = write_json(tmp / "unrelated-roots.json", _roots_document(self.other, "unrelated"))
        self.registry_signed_by_root = write_json(
            tmp / "registry-root-signed.json", _root_signed(self.registry, self.root, "root-1")
        )
        self.registry_signed_by_other = write_json(
            tmp / "registry-other-signed.json", _root_signed(self.registry, self.other, "root-1")
        )
        # The fully self-minted chain: an issuer key, a root key, a registry naming the issuer's
        # key and root-signed, an entry the issuer signed.
        issuer = IssuerKey()
        minted_entry, minted_registry = authorization_material(issuer)
        self.minted_entry = write_json(tmp / "minted-entry.json", minted_entry)
        self.minted_registry = write_json(
            tmp / "minted-registry.json", _root_signed(minted_registry, self.root, "root-1")
        )
        # The re-sealed altered bundle: canonical input changed inside the projection, every local
        # digest recomputed.
        altered = Bundle()
        canonical_input = altered.json("canonical_input.json")
        canonical_input["external_mark"] = "altered"
        altered.set_json("canonical_input.json", canonical_input).reproject().seal()
        self.resealed = altered.write(tmp / "resealed")

    def hostile_dir(self) -> Path:
        path = self.tmp / "hostile"
        path.mkdir(exist_ok=True)
        return path

    def authorization_files(
        self, registry: Path | str, *args: str, entry: Path | str = ENTRY, evaluation_time: str | None = EVALUATION_TIME
    ) -> Run:
        """An authorization run over the link fixture bundle, at ``evaluation_time`` unless it is None."""
        when = [] if evaluation_time is None else ["--evaluation-time", evaluation_time]
        return run_cli(
            [
                str(FIXTURES / "link_valid_bundle"),
                "--registry-entry",
                str(entry),
                "--trust-registry",
                str(registry),
                *when,
                *args,
            ]
        )

    def fixture_registry(self, name: str) -> Run:
        return self.authorization_files(FIXTURES / f"authorization_{name}_trust_registry.json")

    def fixture_entry(self, name: str) -> Run:
        return self.authorization_files(TRUST, entry=FIXTURES / f"authorization_{name}_registry_entry.json")

    def undeclared_member(self) -> Run:
        bundle = Bundle(FIXTURES / "valid_bundle")
        bundle.members["smuggled.txt"] = b"x"
        return run_cli([str(bundle.write(self.tmp / "undeclared"))])

    def unprojected_key_altered(self) -> Run:
        bundle = Bundle()
        canonical_input = bundle.json("canonical_input.json")
        assert "asset_id" not in bundle.json("p1.json")["ik"]
        canonical_input["asset_id"] = "altered-outside-the-projection"
        bundle.set_json("canonical_input.json", canonical_input)
        return run_cli([str(bundle.write(self.tmp / "unprojected"))])

    def duplicate_key_active_first(self) -> Run:
        registry = copy.deepcopy(self.registry)
        revoked = copy.deepcopy(registry["entries"][0])
        revoked["status"] = "revoked"
        revoked["revoked_at"] = "2026-05-11T00:00:00Z"
        registry["entries"].append(revoked)
        return self.authorization_files(write_json(self.tmp / "duplicate-key.json", registry))

    def one_key_under_two_issuers(self) -> Run:
        """The trust entry's key listed again under another issuer, both entries active."""
        issuer = IssuerKey()

        def other_issuer(registry: dict[str, Any]) -> None:
            other = copy.deepcopy(registry["entries"][0])
            other.update(issuer_id="issuer_other_demo")
            registry["entries"].append(other)

        entry, registry = authorization_material(issuer, trust=other_issuer)
        return self.authorization_files(
            write_json(self.tmp / "one-key-two-issuers-registry.json", registry),
            entry=write_json(self.tmp / "one-key-two-issuers-entry.json", entry),
        )

    def one_key_under_two_labels_entry_names_the_revoked(self) -> Run:
        """The key listed again under another label of the issuer, the entry naming the revoked label."""
        issuer = IssuerKey()

        def revoked_label(registry: dict[str, Any]) -> None:
            other = copy.deepcopy(registry["entries"][0])
            other.update(issuer_key_id="demo-key-9")
            registry["entries"][0].update(status="revoked", revoked_at="2026-05-01T00:00:00Z")
            registry["entries"].append(other)

        entry, registry = authorization_material(issuer, trust=revoked_label)
        return self.authorization_files(
            write_json(self.tmp / "one-key-two-labels-registry.json", registry),
            entry=write_json(self.tmp / "one-key-two-labels-entry.json", entry),
        )

    def one_root_key_under_two_key_ids(self) -> Run:
        """The pinned root's key listed again under another key_id, revoked there."""
        document = _roots_document(self.root, "root-1")
        document["roots"].append(dict(document["roots"][0], key_id="root-9", status="revoked"))
        roots = write_json(self.tmp / "one-root-key-two-key-ids.json", document)
        return self.authorization_files(self.registry_signed_by_root, "--trust-root", str(roots))

    def internal_error(self) -> Run:
        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("an unexpected failure inside the verifier")

        with mock.patch.object(cli_module, "verify_path", boom):
            return run_cli([str(FIXTURES / "valid_bundle")])

    def back_dated_entry(self, *args: str) -> Run:
        """The fixture entry claiming ``effective_at`` one second before the expired key's window ends."""
        expired = json.loads((FIXTURES / "authorization_expired_trust_registry.json").read_text(encoding="utf-8"))
        entry = dict(self.entry, effective_at=expired["entries"][0]["expires_at"])
        return self.authorization_files(
            FIXTURES / "authorization_expired_trust_registry.json",
            *args,
            entry=write_json(self.tmp / "back-dated.json", entry),
        )

    def committed_verdict(self, verdict: str, reason_codes: list[str], status: str) -> Run:
        """A link run over a bundle whose receipt and entry agree on ``verdict`` and its grounds."""
        bundle = Bundle()
        receipt = bundle.json("verification_receipt.json")
        receipt["status"] = status
        receipt["reason_codes"] = reason_codes
        bundle.set_json("verification_receipt.json", receipt).seal()
        root = bundle.write(self.tmp / f"verdict-{verdict}")
        entry = bundle.link_entry(
            self.tmp / f"verdict-{verdict}-entry.json", verdict=verdict, reason_codes=reason_codes
        )
        return run_cli([str(root), "--registry-entry", str(entry)])

    def fabricated_anchor(self) -> Run:
        issuer = IssuerKey()
        entry, registry = authorization_material(issuer)
        entry["anchor"] = {
            "method": "blockchain_transaction",
            "system": "eip155:1",
            "anchor_reference": "tx-fabricated",
        }
        entry["anchored_at"] = "2026-05-10T12:00:00Z"
        return self.authorization_files(
            write_json(self.tmp / "anchored-registry.json", registry),
            entry=write_json(self.tmp / "anchored-entry.json", entry),
        )

    def payload_unnamed(self) -> Run:
        issuer = IssuerKey()
        entry, registry = authorization_material(issuer)
        del entry["signature"]["payload_id"]
        del entry["signature"]["payload_version"]
        return self.authorization_files(
            write_json(self.tmp / "unnamed-payload-registry.json", registry),
            entry=write_json(self.tmp / "unnamed-payload-entry.json", entry),
        )

    def tsa_token(self) -> Run:
        token = self.tmp / "token.tsr"
        token.write_bytes(b"\x30\x03\x02\x01\x00")
        return self.authorization_files(TRUST, "--tsa-token", str(token))

    def later_root_document(self) -> Run:
        """A trust-root document of a schema version this verifier does not know."""
        document = dict(_roots_document(self.root, "root-1"), schema_version="v2")
        later = write_json(self.tmp / "roots-v2.json", document)
        return self.authorization_files(self.registry_signed_by_root, "--trust-root", str(later))

    def nothing_at_the_input(self) -> Run:
        return run_cli([str(self.tmp / "no-such-bundle")])

    def entry_signed_over_the_root_message(self) -> Run:
        """The issuer key signs the entry under the trust-root construction instead of its own.

        threat-model.md section 14: the two prefixes differ, so the signature verifies as neither.
        """
        issuer = IssuerKey()
        entry, registry = authorization_material(issuer)
        unsigned = {k: v for k, v in entry.items() if k not in ("signature", "anchor", "anchored_at")}
        entry["signature"]["signature"] = issuer.sign_digest(
            hashlib.sha256(trust_registry_signing_bytes(unsigned)).digest()
        )
        return self.authorization_files(
            write_json(self.tmp / "cross-role-registry.json", registry),
            entry=write_json(self.tmp / "cross-role-entry.json", entry),
        )

    def rollback(self, copy_name: str) -> Run:
        """threat-model.md section 16: two copies of one trust registry, both signed by the pinned root.

        The older copy authorizes the key; the newer one, issued later, revokes it after the entry
        was signed. Each copy's window holds the evaluation time, so each is judged on its own.
        """
        issuer = IssuerKey()
        entry, older = authorization_material(issuer)
        newer = copy.deepcopy(older)
        newer["issued_at"] = "2026-05-12T00:00:00Z"
        newer["registry_version"] = "0.1.1-demo"
        newer["entries"][0].update(
            status="revoked", revoked_at="2026-05-11T00:00:00Z", revocation_reason="key_compromise"
        )
        registry = {"older": older, "newer": newer}[copy_name]
        return self.authorization_files(
            write_json(self.tmp / f"rollback-{copy_name}.json", _root_signed(registry, self.root, "root-1")),
            "--trust-root",
            str(self.roots),
            entry=write_json(self.tmp / f"rollback-entry-{copy_name}.json", entry),
            evaluation_time="2026-05-20T00:00:00Z",
        )

    def full_width_key_id(self) -> Run:
        """threat-model.md section 18: a key id that differs from the trust entry's only by a full-width digit."""
        issuer = IssuerKey()

        def full_width(entry: dict[str, Any]) -> None:
            entry["issuer_key_id"] = entry["signature"]["key_id"] = "demo-key-\uff11"

        def ascii_digit(registry: dict[str, Any]) -> None:
            registry["entries"][0]["issuer_key_id"] = "demo-key-1"

        entry, registry = authorization_material(issuer, entry=full_width, trust=ascii_digit)
        return self.authorization_files(
            write_json(self.tmp / "full-width-registry.json", registry),
            entry=write_json(self.tmp / "full-width-entry.json", entry),
        )


def _fixture_bundle(name: str) -> Callable[[Material], Run]:
    return lambda m: run_cli([str(FIXTURES / name)])


def _head_and(*parts: Callable[[Run], Any]) -> Callable[[Run], tuple[Any, ...]]:
    return lambda run: (*run.head(), *(part(run) for part in parts))


def _each(render: Callable[[Run], tuple[Any, ...]]) -> Callable[[Any], tuple[str, ...]]:
    """The observation of several runs: the one they share, or every distinct one, so a difference fails."""
    return lambda runs: tuple(
        token for observed in sorted({tuple(map(str, render(run))) for run in runs}) for token in observed
    )


def _all(render: Callable[[Run], tuple[Any, ...]]) -> Callable[[Any], tuple[str, ...]]:
    """Several runs observed as `all`: the observation they share, and whether any printed a traceback."""
    return lambda runs: (
        "all",
        *_each(render)(runs),
        "a traceback" if any("Traceback" in run.stderr for run in runs) else "no traceback",
    )


def _wycheproof(m: Material) -> str:
    """The corpus run of test_wycheproof_secp256k1.py, which also holds the count the row states.

    Imported when the row runs, not when this module loads: that module is collected after
    this one, and a test module imported before pytest collects it is collected unrewritten.
    """
    from test_wycheproof_secp256k1 import test_wycheproof_p1363_corpus_locks_the_secp256k1_verifier as run_corpus

    if not (ROOT / WYCHEPROOF_FILE).is_file() and in_source_distribution():
        return NOT_SHIPPED
    run_corpus()
    return "all pass"


# The observation of a run whose input the source distribution does not ship (MANIFEST.in).
NOT_SHIPPED = "not shipped in the source distribution"


# Each claim: the run, and what the run reports, as the values the cell observes, in its order.
OBSERVATION_RUNS: dict[str, tuple[Callable[[Material], Any], Callable[[Any], tuple[Any, ...]]]] = {
    "Baseline PASS": (
        _fixture_bundle("valid_bundle"),
        lambda r: (r.report["status"], r.report["verdict"], r.exit),
    ),
    "Tampered manifest": (
        _fixture_bundle("tampered_manifest_bundle"),
        _head_and(lambda r: f"manifest_sha256: {r.check('manifest_sha256')}"),
    ),
    "Tampered canonical input": (
        _fixture_bundle("tampered_canonical_input_bundle"),
        _head_and(lambda r: f"p1_input_hash: {r.check('p1_input_hash')}"),
    ),
    "Missing canonical input": (
        _fixture_bundle("missing_canonical_input_bundle"),
        _head_and(lambda r: r.report["outcome"]["reason"]),
    ),
    "Undeclared member": (lambda m: m.undeclared_member(), _head_and(lambda r: r.report["outcome"]["reason"])),
    "Link check": (
        lambda m: run_cli(
            [str(FIXTURES / "link_valid_bundle"), "--registry-entry", str(FIXTURES / "link_valid_registry_entry.json")]
        ),
        _head_and(lambda r: r.report["registry"]["status"]),
    ),
    "Re-sealed altered bundle, structure and integrity": (
        lambda m: run_cli([str(m.resealed)]),
        _head_and(
            lambda r: "checks_established", lambda r: json.dumps(r.report["checks_established"], separators=(",", ":"))
        ),
    ),
    "…same bundle, + registry entry": (
        lambda m: run_cli([str(m.resealed), "--registry-entry", str(FIXTURES / "link_valid_registry_entry.json")]),
        _head_and(lambda r: f"link.manifest_hash: ok={json.dumps(r.link_check('manifest_hash'))}"),
    ),
    "Unprojected key altered": (
        lambda m: m.unprojected_key_altered(),
        lambda r: (f"p1_input_hash: {r.check('p1_input_hash')}", f"manifest_files: {r.check('manifest_files')}"),
    ),
    "Authorization, no pinned root": (
        lambda m: m.authorization_files(TRUST),
        _head_and(lambda r: r.trust("trust_registry_root_signature_status")),
    ),
    "Authorization, no evaluation time": (
        lambda m: m.authorization_files(TRUST, evaluation_time=None),
        _head_and(lambda r: "review_reasons", lambda r: json.dumps(r.report["review_reasons"], separators=(",", ":"))),
    ),
    "Authorization, root pinned and valid": (
        lambda m: m.authorization_files(m.registry_signed_by_root, "--trust-root", str(m.roots)),
        _head_and(lambda r: r.trust("trust_registry_root_signature_status")),
    ),
    "Authorization, root pinned, registry signed by another key": (
        lambda m: m.authorization_files(m.registry_signed_by_other, "--trust-root", str(m.roots)),
        _head_and(lambda r: r.trust("trust_registry_root_signature_status"), lambda r: r.report["outcome"]["category"]),
    ),
    "Fully self-minted chain, default": (
        lambda m: m.authorization_files(m.minted_registry, entry=m.minted_entry),
        _head_and(lambda r: r.report["outcome"]["reason"]),
    ),
    "…with an unrelated root pinned": (
        lambda m: m.authorization_files(
            m.minted_registry, "--trust-root", str(m.unrelated_roots), entry=m.minted_entry
        ),
        _head_and(lambda r: r.trust("trust_registry_root_signature_status")),
    ),
    "…accepting another review reason": (
        lambda m: m.authorization_files(
            m.minted_registry, "--accept-review", "registry_entry_verdict_requires_review", entry=m.minted_entry
        ),
        lambda r: (r.exit,),
    ),
    "…accepting the unpinned root": (
        lambda m: m.authorization_files(
            m.minted_registry, "--accept-review", "trust_registry_root_not_pinned", entry=m.minted_entry
        ),
        lambda r: (r.exit,),
    ),
    "Revoked key": (lambda m: m.fixture_registry("revoked"), _head_and(lambda r: r.trust("authorization_status"))),
    "…with no evaluation time": (
        lambda m: m.authorization_files(FIXTURES / "authorization_revoked_trust_registry.json", evaluation_time=None),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Suspended key": (lambda m: m.fixture_registry("suspended"), _head_and(lambda r: r.trust("authorization_status"))),
    "Key not yet effective": (
        lambda m: m.fixture_registry("not_yet_effective"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Scope mismatch": (
        lambda m: m.fixture_registry("disallowed_asset_type"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Malformed trust registry": (
        lambda m: m.fixture_registry("malformed"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Unknown issuer": (
        lambda m: m.fixture_entry("unknown_issuer"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Unknown key": (lambda m: m.fixture_entry("unknown_key"), _head_and(lambda r: r.trust("authorization_status"))),
    "Signature mismatch": (
        lambda m: m.fixture_entry("signature_mismatch"),
        _head_and(lambda r: r.trust("authorization_status"), lambda r: r.trust("signature_status")),
    ),
    "Duplicate `(issuer_id, key_id)`, active listed first": (
        lambda m: m.duplicate_key_active_first(),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "One key under two issuers, both entries active": (
        lambda m: m.one_key_under_two_issuers(),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "One key under two labels, the entry naming the revoked label": (
        lambda m: m.one_key_under_two_labels_entry_names_the_revoked(),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "One root key under two `key_id` values, the other revoked": (
        lambda m: m.one_root_key_under_two_key_ids(),
        _head_and(lambda r: r.trust("trust_registry_root_signature_status")),
    ),
    "secp256k1 verifier": (_wycheproof, lambda rendered: (rendered,)),
    "Internal-error path": (
        lambda m: m.internal_error(),
        lambda r: (r.report["status"], json.dumps(r.report["verdict"]), r.exit),
    ),
    "Expired key, entry as issued": (
        lambda m: m.fixture_registry("expired"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "…entry back-dated by 1 second": (
        lambda m: m.back_dated_entry(),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Committed verdict `FAIL`": (
        lambda m: m.committed_verdict("FAIL", ["INTEGRITY_OFFLINE_FAIL"], "fail"),
        _head_and(lambda r: r.report["outcome"]["category"]),
    ),
    "Committed verdict `WARN`/`REVIEW`": (
        lambda m: (
            m.committed_verdict("WARN", ["FRESHNESS_WARNING"], "warning"),
            m.committed_verdict("REVIEW", ["NEEDS_REVIEW"], "review"),
        ),
        _each(_head_and(lambda r: r.report["outcome"]["reason"])),
    ),
    "Committed verdict `BANANA`": (
        lambda m: m.committed_verdict("BANANA", ["INTEGRITY_OK"], "pass"),
        lambda r: (r.report["outcome"]["reason"],),
    ),
    "Fabricated anchor": (
        lambda m: m.fabricated_anchor(),
        lambda r: (
            f"signature_status: {r.trust('signature_status')}",
            f"anchor_finality_verified: {json.dumps(r.trust('anchor_finality_verified'))}",
        ),
    ),
    "Signature naming no payload": (
        lambda m: m.payload_unnamed(),
        _head_and(lambda r: r.report["outcome"]["reason"]),
    ),
    "`--tsa-token`": (
        lambda m: m.tsa_token(),
        lambda r: (r.exit, "no report" if r.report is None else "a report"),
    ),
    "Empty `--evaluation-time`": (
        lambda m: m.authorization_files(TRUST, "--evaluation-time", "", evaluation_time=None),
        lambda r: (r.exit,),
    ),
    "Trust-root document of a later version": (
        lambda m: m.later_root_document(),
        # Each error's code, then each of its other members and its value, in the report's order.
        lambda r: (
            *r.head(),
            *(
                value
                for error in r.report["errors"]
                for value in (
                    error["code"],
                    *(item for member in error.items() if member[0] not in ("code", "message") for item in member),
                )
            ),
        ),
    ),
    "Nothing at the input path": (
        lambda m: m.nothing_at_the_input(),
        _head_and(lambda r: ", ".join(e["code"] for e in r.report["errors"])),
    ),
    "`--trust-registry` without `--registry-entry`": (
        lambda m: run_cli([str(FIXTURES / "link_valid_bundle"), "--trust-registry", str(TRUST)]),
        lambda r: (r.exit,),
    ),
    "Entry signed over the root construction's message": (
        lambda m: m.entry_signed_over_the_root_message(),
        _head_and(lambda r: r.trust("signature_status")),
    ),
    "Rollback of trust material: newer copy, key revoked": (
        lambda m: m.rollback("newer"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "…older copy by the same root, key active": (
        lambda m: m.rollback("older"),
        _head_and(lambda r: r.trust("trust_registry_root_signature_status")),
    ),
    "Revoked key, entry signed before the revocation": (
        lambda m: m.rollback("newer"),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Full-width digit in `issuer_key_id`": (
        lambda m: m.full_width_key_id(),
        _head_and(lambda r: r.trust("authorization_status")),
    ),
    "Hostile archives and JSON": (
        lambda m: [HOSTILE_RUNS[key][1](m.hostile_dir()) for key in HOSTILE_RUNS],
        _all(lambda r: ((r.report or {}).get("status"), r.exit)),
    ),
}


# ---- the tables ---------------------------------------------------------------------------------


# Section 7's columns. The second gives a run's errors, each `code:message`; for a run with no
# error it gives the outcome reason and then the informative note or per-file result naming the cause.
HOSTILE_HEADER = ["Hostile input", "Reported (code, then informative message)", "Rule"]
CODE_SPANS = r"`[^`]+`(?:, `[^`]+`)*"
NO_ERROR = re.compile(r"no error, reason `([^`]+)`; informative (?:per-file result )?(" + CODE_SPANS + ")")


def _hostile_rows() -> dict[str, tuple[str | None, list[str]]]:
    """Section 7's rows: hostile input -> the outcome reason of a run with no error, or None, and
    the reported items, ``…:`` expanded from the row above.

    A cell names one item, or several separated by commas, each in code spans, after
    "no error, reason `R`; informative" for a run that reports no error. Any other cell fails.
    """
    rows = table(sections(document(SPEC))[HOSTILE], HOSTILE_HEADER)
    expanded: dict[str, tuple[str | None, list[str]]] = {}
    previous = ""
    for row in rows:
        cell, reason = row[HOSTILE_HEADER[1]], None
        no_error = NO_ERROR.fullmatch(cell)
        if no_error:
            reason, cell = no_error.groups()
        assert re.fullmatch(CODE_SPANS, cell), f"section 7 cell {row[HOSTILE_HEADER[1]]!r} is not code spans"
        items = [item.strip().strip("`") for item in cell.split(",")]
        for index, item in enumerate(items):
            if item.startswith(ELLIPSIS):
                # The error of the row above with its last segment replaced: `…:absolute_path` after
                # `archive_unsafe_member:unsafe_zip_member:traversal`.
                items[index] = previous.rpartition(":")[0] + ":" + item[len(ELLIPSIS) :]
            previous = items[index]
        expanded[row["Hostile input"]] = (reason, items)
    return expanded


# The lead-in of section 7 exempts a verifier without archive intake from some of the rows and
# from no others. It names the exempt rows two ways: by the rule their Rule column cites, and by
# the row's own name. Both are read here and held against what the runs below actually build.
ARCHIVE_RULE = "`bundle-objects.md` §5"
SCOPES_BY_RULE = "every row whose Rule column cites `bundle-objects.md` §5"


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _lead_in() -> str:
    """Section 7's prose before its table, whitespace flattened so a rewrap changes nothing."""
    return _flat(sections(document(SPEC))[HOSTILE].split("| Hostile input |", 1)[0])


def _rule_cells() -> dict[str, str]:
    """Section 7's rows: hostile input -> the rule the row cites."""
    rows = table(sections(document(SPEC))[HOSTILE], HOSTILE_HEADER)
    return {row["Hostile input"]: row["Rule"] for row in rows}


def _rows_the_document_exempts() -> set[str]:
    """The rows section 7's lead-in scopes to a verifier that reads archives."""
    lead_in = _lead_in()
    assert SCOPES_BY_RULE in lead_in, f"section 7 does not scope its rows by the rule they cite: {lead_in!r}"
    return {row for row, rule in _rule_cells().items() if ARCHIVE_RULE in rule or f"the `{row}` row" in lead_in}


# What a section 11 cell observes: a backticked value, an exit code written `exit N` or `/ N`, or
# a phrase whose truth a run decides.
OBSERVED = re.compile(r"`([^`]*)`|\bexit (\d+)\b|/ (\d+)\b|\b(all pass|all|no report|no traceback)\b")
# What may stand between the values: punctuation that joins them, the word naming a value, and the
# words that name an error's members ("the error `c` with `object` `o` and `version` `v`").
JOINING = re.compile(r"(?:[\s/,+]|\bverdict\b|\bthe error\b|\bwith\b|\band\b)*")
# What may follow the last value: nothing, or an explanation in parentheses or after ", not".
EXPLAINING = re.compile(r"|\s+\([^()`]*\)|,\s+not\s[^`]*")
BOLD_NOT = re.compile(r",\s+\*\*not\*\*\s(.*)\Z", re.DOTALL)


def _without_bold_not(cell: str) -> str:
    """The cell without a trailing ", **not** ..." explanation, when that is all it holds.

    A bold "not" after the last value names what the run does not report, one value at most
    ("**not** `X`") or words ("**not** the active duplicate"). A tail that states a second value, or an
    exit code, is a claim of the cell and stays, so it is compared with the run.
    """
    found = BOLD_NOT.search(cell)
    if found is None or OBSERVED.search(re.sub(r"`[^`]*`", "", found.group(1), count=1)):
        return cell
    return cell[: found.start()]


def observation(cell: str) -> tuple[str, ...]:
    """The values a section 11 cell observes, in order.

    The words after the last value may explain the observation rather than state it ("**not** the
    active duplicate", "(the entry's dates are not a time)") and are not compared. Any other word
    ("a report", "not" before a value, "some") is part of what the cell says, so the cell is then
    compared whole, and fails against the values a run renders.
    """
    text = _without_bold_not(cell).replace("**", "")
    matches = list(OBSERVED.finditer(text))
    if not matches:
        return (text,)
    between = OBSERVED.sub(" ", text[: matches[-1].end()])
    after = text[matches[-1].end() :]
    if not JOINING.fullmatch(between) or not EXPLAINING.fullmatch(after):
        return (text,)
    return tuple(next(group for group in match.groups() if group is not None) for match in matches)


def _observation_rows() -> dict[str, tuple[str, ...]]:
    """Section 11's rows: claim -> what the Result cell observes."""
    rows = table(sections(document(SPEC))[OBSERVATIONS], ["Claim", "How it was observed", "Result"])
    return {row["Claim"]: observation(row["Result"]) for row in rows}


@pytest.fixture(scope="module")
def material(tmp_path_factory: pytest.TempPathFactory) -> Material:
    return Material(tmp_path_factory.mktemp("threat-model"))


@pytest.fixture(scope="module")
def runs(material: Material) -> dict[str, Any]:
    """Every run, made once: the aggregate row and the per-row tests read the same reports."""
    return {claim: build(material) for claim, (build, _) in OBSERVATION_RUNS.items()}


# ---- section 7 ----------------------------------------------------------------------------------


def test_section_7_has_a_run_for_every_row_and_a_row_for_every_run() -> None:
    rows = _hostile_rows()
    assert set(rows) == set(HOSTILE_RUNS), {
        "rows without a run": sorted(set(rows) - set(HOSTILE_RUNS)),
        "runs without a row": sorted(set(HOSTILE_RUNS) - set(rows)),
    }


def test_section_7_exempts_a_directory_only_verifier_from_its_archive_rows_and_no_others(
    tmp_path: Path,
) -> None:
    """The lead-in's scope is held against how the rows are built, not against how they read.

    Archive intake is optional (``report-contract.md`` §5.3), so a lead-in that scopes this table
    tells a verifier without it which rows it is free of. A scope wider than the archive rows
    exempts that reader from rows that do bind it, which is how a correct table teaches the wrong
    thing; a scope narrower than them binds a reader to rows it can never meet. Neither is visible
    in the prose, because both parse. The two sets are therefore held equal: the rows the lead-in
    exempts, read from the document, and the rows whose input this suite materializes as an
    archive, read from the run itself.
    """
    exempt = _rows_the_document_exempts()
    archives, directories = set(), set()
    for index, row in enumerate(HOSTILE_RUNS):
        where = tmp_path / f"row{index}"
        where.mkdir()
        run = HOSTILE_RUNS[row][1](where)
        (archives if run.input_is_an_archive() else directories).add(row)
    assert exempt == archives, {
        "exempted but a directory bundle, so binding on every verifier": sorted(exempt - archives),
        "an archive but not exempted": sorted(archives - exempt),
    }
    # Anti-vacuity: the table has rows of both kinds, so neither half of the comparison is empty
    # and a lead-in exempting everything or nothing fails rather than matching a degenerate set.
    assert archives and directories, {"archives": sorted(archives), "directories": sorted(directories)}
    assert archives | directories == set(HOSTILE_RUNS)


@pytest.mark.parametrize("hostile_input", list(HOSTILE_RUNS), ids=lambda key: key.replace("`", ""))
def test_each_hostile_input_of_section_7_is_refused_as_the_row_states(hostile_input: str, tmp_path: Path) -> None:
    rows = _hostile_rows()
    assert hostile_input in rows, f"section 7 has no row {hostile_input!r}"
    where, build = HOSTILE_RUNS[hostile_input]
    run = build(tmp_path)
    assert run.report is not None and "Traceback" not in run.stderr, (run.exit, run.stderr[-500:])
    assert (run.report["status"], run.report["verdict"], run.exit) == ("OFFLINE_FAIL", "FAIL", 1)
    reason, items = rows[hostile_input]
    if reason is not None:
        assert (run.report["errors"], run.report["outcome"]["reason"]) == ([], reason), hostile_input
    reported = _reported(run, where)
    missing = [item for item in items if item not in reported]
    assert not missing, f"{hostile_input}: the {where}s are {reported}, the row states {items!r}"


# ---- section 11 ---------------------------------------------------------------------------------


def test_section_11_has_a_run_for_every_row_and_a_row_for_every_run() -> None:
    rows = _observation_rows()
    assert set(rows) == set(OBSERVATION_RUNS), {
        "rows without a run": sorted(set(rows) - set(OBSERVATION_RUNS)),
        "runs without a row": sorted(set(OBSERVATION_RUNS) - set(rows)),
    }


@pytest.mark.parametrize(
    ("cell", "observed"),
    [
        ("`OFFLINE_OK` / `PASS` / 0", ("OFFLINE_OK", "PASS", "0")),
        (
            "`OFFLINE_FAIL` / 1, `TRUST_REGISTRY_AMBIGUOUS_KEY`, **not** the active duplicate",
            ("OFFLINE_FAIL", "1", "TRUST_REGISTRY_AMBIGUOUS_KEY"),
        ),
        (
            "`OFFLINE_REVIEW` / 2, `ISSUER_KEY_EXPIRED` (the entry's dates are not a time)",
            ("OFFLINE_REVIEW", "2", "ISSUER_KEY_EXPIRED"),
        ),
        ("`INTERNAL_ERROR` / verdict `null` / exit 3", ("INTERNAL_ERROR", "null", "3")),
        (
            "`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, **not** `ROOT_SIGNATURE_VALID`",
            ("OFFLINE_FAIL", "1", "AMBIGUOUS_ROOT_KEY"),
        ),
        ("exit **2**", ("2",)),
        (
            "`UNSUPPORTED_VERSION` / 4, the error `unsupported_version` with `object` `trust_root_document`",
            ("UNSUPPORTED_VERSION", "4", "unsupported_version", "object", "trust_root_document"),
        ),
        ("exit 64, no report", ("64", "no report")),
        ("all `OFFLINE_FAIL` / 1, no traceback", ("all", "OFFLINE_FAIL", "1", "no traceback")),
        ("all pass", ("all pass",)),
        # A word that is part of what the cell says, not an explanation after it: compared whole.
        ("exit 64, a report", ("exit 64, a report",)),
        (
            "`OFFLINE_FAIL` / 1, not `TRUST_REGISTRY_AMBIGUOUS_KEY`",
            ("`OFFLINE_FAIL` / 1, not `TRUST_REGISTRY_AMBIGUOUS_KEY`",),
        ),
        ("some `OFFLINE_FAIL` / 1, a traceback", ("some `OFFLINE_FAIL` / 1, a traceback",)),
        (
            "`OFFLINE_OK` / 0, no `REGISTRY_ENTRY_LINK_VERIFIED`",
            ("`OFFLINE_OK` / 0, no `REGISTRY_ENTRY_LINK_VERIFIED`",),
        ),
        # A bold "not" explains one value or words; a tail that states another code or an exit is
        # a claim of the cell, so the cell is compared whole.
        (
            "`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, **not** `ROOT_SIGNATURE_VALID`, `ROOT_KEY_REVOKED`",
            ("`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, not `ROOT_SIGNATURE_VALID`, `ROOT_KEY_REVOKED`",),
        ),
        (
            "`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, **not** the active duplicate, exit 3",
            ("`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, not the active duplicate, exit 3",),
        ),
        (
            "`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, **not** `ROOT_SIGNATURE_VALID` / 0",
            ("`OFFLINE_FAIL` / 1, `AMBIGUOUS_ROOT_KEY`, not `ROOT_SIGNATURE_VALID` / 0",),
        ),
    ],
)
def test_a_cell_observes_its_values_and_says_nothing_else(cell: str, observed: tuple[str, ...]) -> None:
    assert observation(cell) == observed


@pytest.mark.parametrize("claim", list(OBSERVATION_RUNS), ids=lambda key: key.replace("`", ""))
def test_each_observation_of_section_11_is_what_the_run_reports(claim: str, runs: dict[str, Any]) -> None:
    rows = _observation_rows()
    assert claim in rows, f"section 11 has no row {claim!r}"
    if runs[claim] == NOT_SHIPPED:
        pytest.skip(f"the source distribution does not ship the input of {claim!r} (MANIFEST.in)")
    _, render = OBSERVATION_RUNS[claim]
    assert tuple(map(str, render(runs[claim]))) == rows[claim]


def test_every_section_11_run_that_prints_a_report_prints_no_traceback(runs: dict[str, Any]) -> None:
    for claim, result in runs.items():
        for run in result if isinstance(result, (list, tuple)) else [result]:
            if isinstance(run, Run):
                assert "Traceback" not in run.stderr, (claim, run.stderr[-500:])
                assert (run.report is None) == (run.exit == 64), (claim, run.exit, run.report is None)
