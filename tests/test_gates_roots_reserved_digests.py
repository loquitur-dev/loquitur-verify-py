"""Rows of the specification that no other test runs.

- Version gates 5, 6 and 8 (document-contracts.md, "Version gate"): a registry entry, its
  reason-code vocabulary pin and a trust registry of a well-formed but unknown version stop the
  run at UNSUPPORTED_VERSION (exit 4), naming the object and the identifier; a malformed
  identifier stays a refusal of the object's contract.
- trust-root.md section 5: root key_id matching is exact code-unit equality (rows 6-7: a
  letter-case or NFC/NFD variant is an unknown root), both window bounds belong to the window
  (rows 9-10), and a root key_type outside the allowlist is UNSUPPORTED_SIGNATURE_ALGORITHM
  (row 11); a trust-root document that names its roots ``trust_roots`` is malformed (exit 64).
- bundle-objects.md reserved names: a member at attestations/, document_index.json or
  claims_openings.json is the review reason bundle_reserved_member, declared or not, and never
  bundle_extra_files.
- Self-describing digests: a bare digest in manifest.files, p1.ih or the receipt's
  manifest_sha256 is refused.

Every signature is made here with an ephemeral key whose private half never leaves the process.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from authorization_kit import BUNDLE, EVALUATION_TIME, SECP256K1_ORDER, IssuerKey, authorization_material, write_json
from bundle_builder import Bundle
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from loquitur.verify.runner import verify_path
from loquitur.verify.trust_root import TrustRootKey, trust_registry_signing_bytes

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _summary(report: Any) -> dict[str, Any]:
    d = report.to_dict()
    trust = d.get("trust_registry") or {}
    return {
        "status": d["status"],
        "exit_code": d["exit_code"],
        "review_reasons": d["review_reasons"],
        "errors": [{k: e[k] for k in ("code", "object", "version") if k in e} for e in d["errors"]],
        "root": trust.get("trust_registry_root_signature_status"),
    }


def _authorization_run(
    tmp_path: Path, entry: dict[str, Any], registry: dict[str, Any], **kwargs: Any
) -> dict[str, Any]:
    kwargs.setdefault("evaluation_time", EVALUATION_TIME)
    return _summary(
        verify_path(
            BUNDLE,
            registry_entry_path=write_json(tmp_path / "entry.json", entry),
            trust_registry_path=write_json(tmp_path / "trust_registry.json", registry),
            **kwargs,
        )
    )


# ---------------------------------------------------------------- version gates 5, 6, 8
def _gate(obj: str, version: str) -> dict[str, Any]:
    return {
        "status": "UNSUPPORTED_VERSION",
        "exit_code": 4,
        "review_reasons": [],
        "errors": [{"code": "unsupported_version", "object": obj, "version": version}],
        "root": None,
    }


GATES = [
    ("gate-5-entry", {"entry": lambda e: e.update(schema_version="v2")}, _gate("registry_entry", "v2")),
    (
        "gate-6-entry-vocabulary",
        {"entry": lambda e: e.update(reason_code_catalog_version="loquitur.reason_codes.v2")},
        _gate("reason_code_vocabulary", "loquitur.reason_codes.v2"),
    ),
    ("gate-8-trust-registry", {"trust": lambda t: t.update(schema_version="v2")}, _gate("trust_registry", "v2")),
]


@pytest.mark.parametrize(("change", "expected"), [row[1:] for row in GATES], ids=[row[0] for row in GATES])
def test_a_later_version_stops_the_run_at_the_gate(tmp_path: Path, change: dict, expected: dict) -> None:
    entry, registry = authorization_material(IssuerKey(), **change)
    assert _authorization_run(tmp_path, entry, registry) == expected


def test_a_malformed_entry_version_is_a_contract_refusal_not_a_gate(tmp_path: Path) -> None:
    entry, registry = authorization_material(IssuerKey(), entry=lambda e: e.update(schema_version="2"))
    got = _authorization_run(tmp_path, entry, registry)
    assert (got["status"], got["exit_code"]) == ("OFFLINE_FAIL", 1)
    assert got["errors"] == [{"code": "registry_entry_contract_violation"}]


def test_a_malformed_trust_registry_version_is_a_refusal_not_a_gate(tmp_path: Path) -> None:
    entry, registry = authorization_material(IssuerKey(), trust=lambda t: t.update(schema_version="V2"))
    got = _authorization_run(tmp_path, entry, registry)
    assert (got["status"], got["exit_code"]) == ("OFFLINE_FAIL", 1)
    assert all(e["code"] != "unsupported_version" for e in got["errors"])


# ---------------------------------------------------------------- trust-root rows 6, 9, 10, 11
class _Root:
    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256K1())
        self.public_key_hex = (
            self._key.public_key()
            .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            .hex()
        )

    def sign(self, registry: dict[str, Any], key_id: str) -> None:
        registry.pop("signature", None)
        der = self._key.sign(trust_registry_signing_bytes(registry), ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        registry["signature"] = {
            "algorithm": "secp256k1_ecdsa_sha256",
            "key_id": key_id,
            "signature": format(r, "064x") + format(min(s, SECP256K1_ORDER - s), "064x"),
        }


def _root_run(
    tmp_path: Path,
    *,
    signed: str = "root-a",
    pinned: str = "root-a",
    not_before: str = "2026-01-01T00:00:00Z",
    not_after: str = "2027-01-01T00:00:00Z",
    key_type: str = "secp256k1",
) -> dict[str, Any]:
    root = _Root()
    entry, registry = authorization_material(IssuerKey())
    root.sign(registry, signed)
    pin = TrustRootKey(pinned, root.public_key_hex, not_before, not_after, key_type=key_type)
    return _authorization_run(tmp_path, entry, registry, trust_roots=[pin])


OK = {"status": "OFFLINE_OK", "exit_code": 0, "review_reasons": [], "errors": [], "root": "ROOT_SIGNATURE_VALID"}


def _refused(root_status: str) -> dict[str, Any]:
    return {
        "status": "OFFLINE_FAIL",
        "exit_code": 1,
        "review_reasons": [],
        "errors": [{"code": "trust_registry_root_not_authenticated"}],
        "root": root_status,
    }


def _window(root_status: str) -> dict[str, Any]:
    return {
        "status": "OFFLINE_REVIEW",
        "exit_code": 2,
        "review_reasons": ["trust_root_outside_validity_window"],
        "errors": [],
        "root": root_status,
    }


NFC = unicodedata.normalize("NFC", "root-é")
NFD = unicodedata.normalize("NFD", "root-é")
ROOT_ROWS = [
    ("control", {}, OK),
    ("row-6-letter-case", {"signed": "root-a", "pinned": "ROOT-A"}, _refused("UNKNOWN_ROOT_KEY")),
    ("row-6-nfc-signed-nfd-pinned", {"signed": NFC, "pinned": NFD}, _refused("UNKNOWN_ROOT_KEY")),
    ("row-6-nfd-signed-nfc-pinned", {"signed": NFD, "pinned": NFC}, _refused("UNKNOWN_ROOT_KEY")),
    ("row-6-same-nfd", {"signed": NFD, "pinned": NFD}, OK),
    ("row-9-not-before-equal", {"not_before": EVALUATION_TIME}, OK),
    ("row-9-not-before-one-second-later", {"not_before": "2026-05-10T00:00:01Z"}, _window("ROOT_KEY_NOT_YET_VALID")),
    ("row-10-not-after-equal", {"not_after": EVALUATION_TIME}, OK),
    ("row-10-not-after-one-second-earlier", {"not_after": "2026-05-09T23:59:59Z"}, _window("ROOT_KEY_EXPIRED")),
    ("row-11-key-type-outside-allowlist", {"key_type": "ed25519"}, _refused("UNSUPPORTED_SIGNATURE_ALGORITHM")),
]


@pytest.mark.parametrize(("change", "expected"), [row[1:] for row in ROOT_ROWS], ids=[row[0] for row in ROOT_ROWS])
def test_root_authentication_rows(tmp_path: Path, change: dict, expected: dict) -> None:
    assert NFC != NFD
    assert _root_run(tmp_path, **change) == expected


def test_a_trust_root_document_under_the_old_name_is_a_usage_error(tmp_path: Path) -> None:
    document = json.loads((FIXTURES / "authorization_quickstart_trust_root.json").read_text(encoding="utf-8"))
    document["trust_roots"] = document.pop("roots")
    root_path = write_json(tmp_path / "root.json", document)
    entry, registry = authorization_material(IssuerKey())
    args = [
        sys.executable,
        "-m",
        "loquitur.verify.cli",
        str(BUNDLE),
        "--registry-entry",
        str(write_json(tmp_path / "entry.json", entry)),
        "--trust-registry",
        str(write_json(tmp_path / "trust_registry.json", registry)),
        "--evaluation-time",
        EVALUATION_TIME,
        "--json",
    ]
    malformed = subprocess.run([*args, "--trust-root", str(root_path)], capture_output=True, text=True, check=False)
    assert malformed.returncode == 64
    assert malformed.stdout == ""
    # The same document under its own name is read: the run reaches a report.
    document["roots"] = document.pop("trust_roots")
    write_json(root_path, document)
    wellformed = subprocess.run([*args, "--trust-root", str(root_path)], capture_output=True, text=True, check=False)
    assert wellformed.returncode in (0, 1, 2)
    assert json.loads(wellformed.stdout)["status"].startswith("OFFLINE_")


# ---------------------------------------------------------------- reserved names
RESERVED = ("attestations/x.json", "document_index.json", "claims_openings.json")


def _with_member(name: str, *, declared: bool) -> Bundle:
    bundle = Bundle(FIXTURES / "valid_bundle")
    bundle.members[name] = b"{}"
    if declared:
        bundle.edit("manifest.json", lambda m: m["files"].update({name: ""}))
        bundle.seal()
    return bundle


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
@pytest.mark.parametrize("name", RESERVED)
def test_a_member_at_a_reserved_name_is_a_reserved_member(tmp_path: Path, name: str, declared: bool) -> None:
    got = _summary(verify_path(_with_member(name, declared=declared).write(tmp_path / "bundle")))
    assert (got["status"], got["exit_code"], got["review_reasons"]) == ("OFFLINE_REVIEW", 2, ["bundle_reserved_member"])


def test_an_undeclared_member_elsewhere_is_an_extra_file(tmp_path: Path) -> None:
    got = _summary(verify_path(_with_member("extra.json", declared=False).write(tmp_path / "bundle")))
    assert got["review_reasons"] == ["bundle_extra_files"]


# ---------------------------------------------------------------- bare digests
def _bare(value: str) -> str:
    assert value.startswith("sha256:")
    return value.split(":", 1)[1]


def _bare_files() -> Bundle:
    bundle = Bundle().seal()
    manifest = bundle.json("manifest.json")
    first = sorted(manifest["files"])[0]
    manifest["files"][first] = _bare(manifest["files"][first])
    bundle.set_json("manifest.json", manifest)
    return bundle.seal(files=False)


def _bare_ih() -> Bundle:
    return Bundle().edit("p1.json", lambda p: p.update(ih=_bare(p["ih"]))).seal()


def _bare_receipt() -> Bundle:
    bundle = Bundle().seal()
    return bundle.edit("verification_receipt.json", lambda r: r.update(manifest_sha256=_bare(r["manifest_sha256"])))


@pytest.mark.parametrize(
    ("build", "check", "error"),
    [
        (_bare_files, "manifest_files", None),
        (_bare_ih, "p1_input_hash", "p1_verification_failed"),
        (_bare_receipt, None, "verification_receipt_contract_violation"),
    ],
    ids=["manifest-files", "p1-ih", "receipt-manifest-sha256"],
)
def test_a_bare_digest_is_refused(tmp_path: Path, build, check: str | None, error: str | None) -> None:
    report = verify_path(build().write(tmp_path / "bundle")).to_dict()
    assert (report["status"], report["exit_code"]) == ("OFFLINE_FAIL", 1)
    if check is not None:
        assert report["checks"][check] is False
    if error is not None:
        assert [e["code"] for e in report["errors"]] == [error]


def test_the_sealed_control_bundle_verifies(tmp_path: Path) -> None:
    report = verify_path(Bundle().seal().write(tmp_path / "bundle")).to_dict()
    assert report["status"] == "OFFLINE_OK"
