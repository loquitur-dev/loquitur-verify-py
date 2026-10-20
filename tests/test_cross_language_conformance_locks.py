"""Cross-language conformance locks for the critical authorization controls.

The protocol's central claim, "anyone can independently re-verify, and every
implementation agrees", is only as strong as the weakest implementation. Each test
here holds a control on which two implementations could disagree, or a verifier could
prove something weaker than it claims.

The paired TypeScript assertions live in loquitur-verify-ts
(test/cross-language-conformance.test.ts); the two files must be kept in step.

Controls locked here:
- expiry: an expired trust registry or issuer key is not authorized;
- uniqueness: a duplicated issuer/key pair is refused, so the verdict never depends
  on ARRAY ORDER (a REVOKED key authorized by putting an active duplicate first);
- key type: a declared key_type is enforced (no algorithm confusion);
- digest self-consistency is not accepted as protocol conformance;
- a validly signed but schema-invalid entry is not authorized (no side channel).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from siblings import import_sibling

# importorskip, not a plain import: this module needs loquitur-schemas as the reference
# implementation, and loquitur-verify is deliberately standalone: a base install does not have it.
# A plain import here would raise at COLLECTION time, which aborts the whole session with
# exit 2 rather than skipping this one file. It skips through siblings.import_sibling, which
# fails instead where LOQUITUR_REQUIRE_SIBLINGS says loquitur-schemas must be there.
_schemas_canonical = import_sibling(
    "loquitur.schemas.canonical",
    "cross-language locks need loquitur-schemas as the reference implementation",
)
_schemas_signing = import_sibling(
    "loquitur.schemas.registry_signing",
    "cross-language locks need loquitur-schemas as the reference implementation",
)

canonical_json_bytes = _schemas_canonical.canonical_json_bytes
SIGNING_PAYLOAD_EXCLUDED_FIELDS = _schemas_signing.SIGNING_PAYLOAD_EXCLUDED_FIELDS

from authorization_kit import IssuerKey

from loquitur.verify.trust_registry import verify_registry_entry_trust

FIXTURES = Path(__file__).parent / "fixtures"


def _entry() -> dict:
    return json.loads((FIXTURES / "authorization_valid_registry_entry.json").read_text(encoding="utf-8"))


def _trust() -> dict:
    return json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))


def _authorize(entry: dict, trust: dict):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(trust, handle)
        path = handle.name
    # The operator's evaluation time: the issuer's own dates are never one.
    return verify_registry_entry_trust(entry, trust_registry_path=path, evaluation_time="2026-05-10T00:00:00Z")


# ------------------------------------------------------------------ expiry


def test_expired_issuer_key_is_not_authorized():
    trust = _trust()
    # After the key's effective_from (2026-04-29) and before the entry's instant (2026-05-10):
    # a key that expires before it takes effect is a malformed trust registry, not an expired key.
    trust["entries"][0]["expires_at"] = "2026-05-01T00:00:00Z"
    result = _authorize(_entry(), trust)
    assert result.authorization_holds is False
    # The named control is key-level expiry. A bare boolean stays green
    # if any other refusal takes over while expiry silently stops being enforced.
    assert result.authorization_status == "ISSUER_KEY_EXPIRED"


def test_expired_trust_registry_is_not_authorized():
    trust = _trust()
    trust["expires_at"] = "2026-05-01T00:00:00Z"  # after issued_at and effective_at, before the instant
    result = _authorize(_entry(), trust)
    assert result.authorization_holds is False
    # Registry-level expiry is a control distinct from the key-level one above;
    # only the status distinguishes which of the two actually fired.
    assert result.authorization_status == "TRUST_REGISTRY_EXPIRED"


def test_valid_time_window_still_authorizes():
    assert _authorize(_entry(), _trust()).authorization_holds is True


# ------------------------------------------------------------------ uniqueness


@pytest.mark.parametrize("active_first", [True, False])
def test_duplicate_issuer_key_is_rejected_regardless_of_order(active_first: bool):
    # A revoked key must not become authorized just because an `active` duplicate
    # happens to be earlier in the array. Revocation is the primary control after a
    # key compromise; it cannot be defeatable by list ordering.
    trust = _trust()
    active = copy.deepcopy(trust["entries"][0])
    active["status"] = "active"
    revoked = copy.deepcopy(trust["entries"][0])
    revoked["status"] = "revoked"
    revoked["revoked_at"] = "2026-05-01T00:00:00Z"
    trust["entries"] = [active, revoked] if active_first else [revoked, active]
    result = _authorize(_entry(), trust)
    assert result.authorization_holds is False
    # Uniqueness is about AMBIGUITY, not about the revoked duplicate winning. Without
    # the status this cannot tell "both orders refused as ambiguous" from "both
    # orders happened to pick the revoked entry", which is a different property.
    assert result.authorization_status == "TRUST_REGISTRY_AMBIGUOUS_KEY"


# ------------------------------------------------------------------ key type


@pytest.mark.parametrize("key_type", ["ed25519", "", None])
def test_non_secp256k1_key_type_is_not_authorized(key_type):
    # The only algorithm this stack verifies is secp256k1_ecdsa_sha256. A trust entry
    # advertising anything else must never be authorized, or the declared algorithm and
    # the verified one diverge.
    trust = _trust()
    if key_type is None:
        trust["entries"][0].pop("key_type", None)
    else:
        trust["entries"][0]["key_type"] = key_type
    result = _authorize(_entry(), trust)
    assert result.authorization_holds is False
    # The key-type control names algorithm confusion. A well-formed key type the verifier does
    # not support is answered at the signature step from its own allowlist
    # (trust-registry-authorization.md section 6 row 16); a malformed or absent one breaks the
    # trust registry's contract.
    expected = (
        ("AUTHORIZED_ACTIVE_KEY", "UNSUPPORTED_SIGNATURE_ALGORITHM")
        if key_type == "ed25519"
        else ("INVALID_TRUST_REGISTRY", None)
    )
    assert (result.authorization_status, result.signature_status) == expected


# ------------------------------------------------------------------
def test_validly_signed_but_schema_invalid_entry_is_rejected():
    # A malicious issuer signs DIRECTLY (bypassing any signing tool that validates)
    # an entry carrying a forbidden extra public field. The signature is genuinely valid
    # over it. The verifier must still refuse: registry_entry is a CLOSED contract, and
    # a "verified" entry must not be able to carry an unbounded side channel.
    # The signing key is made here, for the run, and signs through the test-only kit: the
    # property under test is the CONTRACT, not which key signs, so make one here and point the
    # trust registry at it.
    key = IssuerKey()
    key_id = "demo-key-2"
    trust = _trust()
    trust["entries"][0]["public_key_hex"] = key.public_key_hex
    entry = _entry()
    entry.pop("signature", None)
    entry["secret_side_channel"] = "smuggled"

    payload = {k: v for k, v in entry.items() if k not in SIGNING_PAYLOAD_EXCLUDED_FIELDS}
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    entry["signature"] = {
        "algorithm": "secp256k1_ecdsa_sha256",
        "key_id": key_id,
        "signature": key.sign_digest(digest),
    }

    result = _authorize(entry, trust)
    assert result.authorization_holds is False, "a schema-invalid entry must never be AUTHORIZED"
    # Name the refusal. A bare `ok is False` is also satisfied by an unknown-key or
    # bad-signature refusal, which is exactly what a mis-wired ephemeral key would produce:
    # the contract check could stop running altogether and this test would stay green.
    assert result.authorization_status == "INVALID_REGISTRY_ENTRY"


# ------------------------------------------------------------------
def _write_bundle(root: Path, *, mode: str) -> None:
    """Build a bundle whose digests are all internally consistent by construction.

    That is the whole point: because each digest is computed over whatever the object
    contains, a MALFORMED object is trivially self-consistent. Digest self-consistency
    is not protocol conformance.
    """

    def sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def ref(data: bytes) -> str:
        # A digest inside a JSON document is self-describing; a sidecar file stays bare.
        return "sha256:" + sha(data)

    canonical_input = {"asset_id": "x", "asset_type": "property", "external_mark": 1, "policy_id": "p"}
    ci_bytes = canonical_json_bytes(canonical_input)
    (root / "canonical_input.json").write_bytes(ci_bytes)

    p1 = {"ih": ref(ci_bytes), "ik": sorted(canonical_input), "s": "p1", "v": 1}
    if mode == "p1_malformed":
        p1 = {"ih": ref(ci_bytes), "ik": sorted(canonical_input), "s": "p1", "garbage": "smuggled"}
    if mode == "p1_ik_malformed":
        # ih over the whole input: a non-list ik selects no subset to hash.
        p1 = {"ih": ref(ci_bytes), "ik": "asset_id", "s": "p1", "v": 1}
    if mode == "p1_ih_uppercase":
        # The input hash in upper case: a P1 outside its contract, not only a failed input hash.
        p1 = {"ih": "sha256:" + sha(ci_bytes).upper(), "ik": sorted(canonical_input), "s": "p1", "v": 1}
    p1_bytes = canonical_json_bytes(p1)
    (root / "p1.json").write_bytes(p1_bytes)
    (root / "p1.sha256").write_text(sha(p1_bytes), encoding="utf-8")

    files = {
        "canonical_input.json": ref(ci_bytes),
        "p1.json": ref(p1_bytes),
        "p1.sha256": ref(sha(p1_bytes).encode()),
    }
    if mode == "p1_missing":
        (root / "p1.json").unlink()
    head = {"schema_version": "loquitur.bundle.v1", "nonce": "ab" * 32}
    manifest = {"bundle_id": "b", **head, "files": files}
    if mode == "manifest_malformed":
        manifest = {"files": files}
    if mode == "manifest_type":
        # 7 in the manifest and 7 in the envelope: str() coercion would make the link hold.
        manifest = {"bundle_id": 7, **head, "files": files}
    if mode == "manifest_digest_case":
        manifest = {"bundle_id": "b", **head, "files": {**files, "p1.json": "sha256:" + sha(p1_bytes).upper()}}
    if mode == "manifest_self_declared":
        manifest = {"bundle_id": "b", **head, "files": {**files, "manifest.json": "sha256:" + "0" * 64}}
    if mode == "manifest_files_list":
        manifest = {
            "bundle_id": "b",
            **head,
            "files": [{"name": k, "sha256": v} for k, v in files.items()],
        }
    manifest_bytes = canonical_json_bytes(manifest)
    (root / "manifest.json").write_bytes(manifest_bytes)
    (root / "manifest.sha256").write_text(sha(manifest_bytes), encoding="utf-8")

    envelope = {
        "s": "env1",
        "v": 1,
        "bundle_id": manifest.get("bundle_id", "b"),
        "bundle_manifest_sha256": ref(manifest_bytes),
        "p1_sha256": ref(p1_bytes),
        "registry_entry": None,
    }
    if mode == "envelope_bad_version":
        envelope = {"s": "env1", "v": 999, "unexpected": "smuggled"}
    if mode == "envelope_no_links":
        envelope = {"s": "env1", "v": 1}
    envelope_bytes = canonical_json_bytes(envelope)
    (root / "envelope_env1.json").write_bytes(envelope_bytes)
    (root / "envelope.sha256").write_text(sha(envelope_bytes), encoding="utf-8")


@pytest.mark.parametrize(
    ("mode", "expected_exit"),
    [
        ("good", 0),  # conformant bundle still passes
        ("manifest_malformed", 1),  # no bundle_id / schema_version
        ("p1_malformed", 1),  # no version, smuggled field
        ("envelope_bad_version", 1),  # v=999, unexpected field
        # 1, not 2: the envelope contract requires bundle_id, bundle_manifest_sha256 and p1_sha256, so
        # {"s":"env1","v":1} is not an envelope missing some optional detail: it is not an
        # env1 document, and the report says so by name in
        # envelope_missing_field:{bundle_id,bundle_manifest_sha256,p1_sha256}. REVIEW asks a
        # human to adjudicate something no human can adjudicate: there is nothing here to
        # weigh. The conformant "good" case above still exits 0, so this rejects no valid
        # bundle.
        ("envelope_no_links", 1),
        # The manifest contract, each bundle self-consistent by construction; paired with the
        # same modes in loquitur-verify-ts test/cross-language-conformance.test.ts.
        ("manifest_type", 1),  # bundle_id 7, and 7 in the envelope
        ("manifest_digest_case", 1),  # an uppercase digest in manifest.files
        ("manifest_self_declared", 1),  # files names manifest.json
        ("manifest_files_list", 1),  # files in the legacy list form
        ("p1_ik_malformed", 1),  # ik "asset_id": no whole-input fallback for a present ik
        ("p1_ih_uppercase", 1),  # ih in upper case: the P1 contract, so no P1 link either
        ("p1_missing", 1),  # p1.json absent, its sidecar and the envelope link still present
    ],
)
def test_self_consistent_but_malformed_bundles_do_not_pass(tmp_path: Path, mode: str, expected_exit: int):
    _write_bundle(tmp_path, mode=mode)
    # The child interpreter does not inherit pytest's `pythonpath = ["src"]`: that setting
    # mutates this process's sys.path and nothing else. On a tree that is not pip-installed
    # the subprocess would die with ModuleNotFoundError and return 1, precisely the code
    # three of these five parametrizations expect, so they would pass without the verifier
    # ever running, and keep passing if it were deleted. Two defences, because an exit code
    # alone cannot distinguish a refusal from a failure to start: hand the child the source
    # tree explicitly, and require the report it printed to parse and to carry the verdict
    # the exit code claims.
    src = str(Path(__file__).resolve().parents[1] / "src")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [src, os.environ.get("PYTHONPATH", "")]))}
    result = subprocess.run(
        [sys.executable, "-m", "loquitur.verify.cli", str(tmp_path), "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env={**env, "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == expected_exit, result.stdout + result.stderr
    report = json.loads(result.stdout)  # an interpreter that never started prints nothing parseable
    assert report["verdict"] == {0: "PASS", 1: "FAIL", 2: "REVIEW"}[expected_exit], result.stdout
    if mode in {"p1_malformed", "p1_ik_malformed", "p1_ih_uppercase", "p1_missing", "manifest_malformed"}:
        # A link to a P1 or a manifest that did not verify does not hold, in either verifier:
        # the sidecar beside it is not a verified digest.
        assert report["checks"]["envelope_links"] is False, result.stdout
    if mode == "manifest_files_list":
        # The list form declares nothing, so its entries are not hashed and manifest_files is
        # false, in either verifier.
        assert report["checks"]["manifest_files"] is False, result.stdout
    if mode == "p1_ih_uppercase":
        # A P1 refused for its contract has no verified digest: for an uppercase ih p1_sha256 is
        # false, in either verifier.
        assert report["checks"]["p1_sha256"] is False, result.stdout
    if mode.startswith("envelope_"):
        # Refused for its shape, yet still matching the digest the builder stored beside it.
        # loquitur-verify-ts asserts the same two checks on the same bundles.
        assert report["checks"]["envelope_sha256"] is True, result.stdout
        assert report["checks"]["envelope_links"] is False, result.stdout
