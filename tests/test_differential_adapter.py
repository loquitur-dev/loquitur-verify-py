"""The test-only differential adapter (tools/differential_adapter.py): its answers, and where it ships.

The adapter is run as a subprocess, as a harness runs it, over a handful of requests of every
operation, a request of an unknown operation and lines that are no request. Every expected answer
is written here from the specification or computed with ``rfc8785`` and the prefixes the
specification states, not with the adapter's own code. This is the maintainer's own testing, carried out with the help of AI tools, which is internal
verification and not an audit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import rfc8785
from repository import tool

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tools" / "differential_adapter.py"
ENTRY_PREFIX = b"LOQUITUR\x00REGISTRY_ENTRY\x00SIGNATURE\x00V2\x00"
ROOT_PREFIX = b"LOQUITUR\x00TRUST_REGISTRY\x00ROOT_SIGNATURE\x00V1\x00"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _run(lines: list[bytes]) -> list[dict[str, Any]]:
    result = subprocess.run(
        [sys.executable, str(ADAPTER)],
        input=b"".join(line + b"\n" for line in lines),
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stderr == b""
    out = result.stdout.splitlines()
    assert len(out) == len(lines), result.stdout
    for raw in out:
        # Compact, sorted keys, ASCII only, as the protocol fixes the bytes.
        parsed = json.loads(raw)
        assert raw == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("ascii")
    return [json.loads(raw) for raw in out]


def _request(identifier: str, op: str, **members: Any) -> bytes:
    return json.dumps({"id": identifier, "op": op, **members}).encode("utf-8")


def test_the_adapter_answers_every_operation() -> None:
    entry = {"b": 1, "a": "x", "signature": {"s": "1"}, "anchor": None, "anchored_at": "t"}
    registry = {"z": [1, 2], "anchor": "kept", "signature": {"s": "2"}}
    entry_envelope = {
        "domain": "org.loquitur.protocol.registry-entry-signature",
        "envelope_schema": "loquitur.signing_envelope.v2",
        "envelope_version": 2,
        "payload": {"a": "x", "b": 1},
        "payload_id": "registry_entry_signing_payload_v2",
        "payload_schema": "loquitur.registry_entry.v1",
        "signature_algorithm": "secp256k1_ecdsa_sha256",
    }
    root_envelope = {
        "domain": "org.loquitur.protocol.trust-registry-root-signature",
        "envelope_schema": "loquitur.trust_registry_root_signing_envelope.v1",
        "envelope_version": 1,
        "payload": {"anchor": "kept", "z": [1, 2]},
        "payload_schema": "loquitur.trust_registry.v1",
        "signature_algorithm": "secp256k1_ecdsa_sha256",
    }
    cases: list[tuple[bytes, dict[str, Any]]] = [
        # load: rules the loader enforces on the bytes.
        (_request("l1", "load", input_b64=_b64(b'{"a": [1, 2.5, "\\u00e9"]}')), {"accepted": True}),
        (_request("l2", "load", input_b64=_b64(b'\xef\xbb\xbf{"a":1}')), {"accepted": False}),
        (_request("l3", "load", input_b64=_b64(b'{"a":1,"\\u0061":2}')), {"accepted": False}),
        (_request("l4", "load", input_b64=_b64(b'{"a":"\\ud800"}')), {"accepted": False}),
        (_request("l5", "load", input_b64=_b64(b"[9007199254740992]")), {"accepted": False}),
        (_request("l6", "load", input_b64=_b64(b'"\xff"')), {"accepted": False}),
        (_request("l7", "load", input_b64=_b64(b"[" * 65 + b"]" * 65)), {"accepted": False}),
        (_request("l8", "load", input_b64=_b64(b"[" * 64 + b"]" * 64)), {"accepted": True}),
        # jcs
        (
            _request("j1", "jcs", input_b64=_b64(b'{"b": 1.0, "a": [1e2, "\\u00e9"]}')),
            {"accepted": True, "output_b64": _b64(rfc8785.dumps({"a": [100, "\u00e9"], "b": 1}))},
        ),
        (_request("j2", "jcs", input_b64=_b64(b"NaN")), {"accepted": False, "output_b64": None}),
        (_request("j3", "jcs", input_b64=_b64(b"2.0000000000000001")), {"accepted": False, "output_b64": None}),
        # signing_message
        (
            _request("s1", "signing_message", kind="registry_entry", input_b64=_b64(json.dumps(entry).encode())),
            {"accepted": True, "output_b64": _b64(ENTRY_PREFIX + rfc8785.dumps(entry_envelope))},
        ),
        (
            _request("s2", "signing_message", kind="trust_registry", input_b64=_b64(json.dumps(registry).encode())),
            {"accepted": True, "output_b64": _b64(ROOT_PREFIX + rfc8785.dumps(root_envelope))},
        ),
        (
            _request("s3", "signing_message", kind="registry_entry", input_b64=_b64(b"[1]")),
            {"accepted": False, "output_b64": None},
        ),
        (
            _request("s4", "signing_message", kind="trust_registry", input_b64=_b64(b'{"a":1,"a":2}')),
            {"accepted": False, "output_b64": None},
        ),
        # instant
        (_request("i1", "instant", value="2024-02-29T23:59:59Z"), {"accepted": True}),
        (_request("i2", "instant", value="2023-02-29T00:00:00Z"), {"accepted": False}),
        (_request("i3", "instant", value="2024-01-01T00:00:60Z"), {"accepted": False}),
        (_request("i4", "instant", value="2024-01-01T00:00:00+00:00"), {"accepted": False}),
        (_request("i5", "instant", value=20240101), {"accepted": False}),
        # member_name
        (
            _request("m1", "member_name", value="MANIFEST.JSON"),
            {"portable": True, "folded": "manifest.json", "self_declaration": True},
        ),
        (
            _request("m2", "member_name", value="MAN\u0130FEST.JSON"),
            {"portable": False, "folded": "man\u0130fest.json", "self_declaration": False},
        ),
        (
            _request("m3", "member_name", value="sub/CON.txt"),
            {"portable": False, "folded": "sub/con.txt", "self_declaration": False},
        ),
        (
            _request("m4", "member_name", value="\u212a.json"),
            {"portable": False, "folded": "\u212a.json", "self_declaration": False},
        ),
        (
            _request("m5", "member_name", value="Data/Input.json"),
            {"portable": True, "folded": "data/input.json", "self_declaration": False},
        ),
    ]
    responses = _run([line for line, _ in cases])
    for (line, expected), response in zip(cases, responses, strict=True):
        identifier = json.loads(line)["id"]
        assert response == {"id": identifier, **expected}, (line, response)


def test_the_adapter_answers_bad_lines_and_carries_on() -> None:
    lines = [
        _request("u1", "transmogrify"),
        b'{"op": "load"}',
        b'{"id": 7, "op": "load"}',
        b"[1, 2]",
        b"not json",
        b"\xff\xfe",
        b"",
        _request("e1", "load", input_b64="***"),
        _request("e2", "load"),
        _request("e3", "signing_message", kind="other", input_b64=_b64(b"{}")),
        _request("ok", "load", input_b64=_b64(b"{}")),
    ]
    responses = _run(lines)
    bad = {"id": None, "error": "bad_request"}
    assert responses[0] == {"id": "u1", "error": "unknown_op"}
    assert responses[1:7] == [bad] * 6
    assert responses[7] == {"id": "e1", "error": "Error"}  # binascii.Error
    assert responses[8] == {"id": "e2", "error": "KeyError"}
    assert responses[9] == {"id": "e3", "error": "ValueError"}
    assert responses[10] == {"id": "ok", "accepted": True}


def test_no_input_no_output() -> None:
    assert _run([]) == []


def test_the_adapter_ships_in_the_sdist_and_never_in_the_wheel() -> None:
    """The wheel holds the package under src/ and nothing else; tools/ is grafted into the sdist only."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    find = pyproject["tool"]["setuptools"]["packages"]["find"]
    assert find["where"] == ["src"]
    assert all(pattern.startswith("loquitur") for pattern in find["include"])
    assert not (ROOT / "tools" / "__init__.py").exists()
    assert not list((ROOT / "src").rglob("differential_adapter*"))
    # The local wheel gate accepts a wheel only when its members are exactly the files under
    # src/loquitur; the adapter is not one of them.
    gate = tool("local_wheel_gate")
    assert not [name for name in gate._source_package_files(ROOT) if "differential_adapter" in name]
    assert "graft tools" in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()


# ---------- the public-API operations ----------
#
# A chain made for the run: an issuer key signs the fixture entry, a root key signs the trust
# registry, and a trust-root document pins the root. Every expected answer is the row of
# trust-registry-authorization.md section 6 or trust-root.md section 5 the case stops at, and the
# verdict trust-root.md sections 2 and 6 give it, written here, not read from the adapter.

ROOT_WINDOW = ("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")


def _doc(value: Any) -> str:
    return _b64(json.dumps(value).encode("utf-8"))


def _root_signed(registry: dict[str, Any], root: Any, key_id: str = "root-a") -> dict[str, Any]:
    unsigned = {k: v for k, v in registry.items() if k != "signature"}
    message = ROOT_PREFIX + rfc8785.dumps(
        {
            "domain": "org.loquitur.protocol.trust-registry-root-signature",
            "envelope_schema": "loquitur.trust_registry_root_signing_envelope.v1",
            "envelope_version": 1,
            "payload": unsigned,
            "payload_schema": "loquitur.trust_registry.v1",
            "signature_algorithm": "secp256k1_ecdsa_sha256",
        }
    )
    signature = root.sign_digest(hashlib.sha256(message).digest())
    return {**unsigned, "signature": {"algorithm": "secp256k1_ecdsa_sha256", "key_id": key_id, "signature": signature}}


def _roots(public_key_hex: str, status: str = "active", key_id: str = "root-a") -> dict[str, Any]:
    return {
        "object_type": "trust_root_document",
        "schema_version": "v1",
        "roots": [
            {
                "key_id": key_id,
                "key_type": "secp256k1",
                "not_after": ROOT_WINDOW[1],
                "not_before": ROOT_WINDOW[0],
                "public_key_hex": public_key_hex,
                "status": status,
            }
        ],
    }


def _entry_digest(entry: dict[str, Any]) -> bytes:
    envelope = {
        "domain": "org.loquitur.protocol.registry-entry-signature",
        "envelope_schema": "loquitur.signing_envelope.v2",
        "envelope_version": 2,
        "payload": {k: v for k, v in entry.items() if k not in ("signature", "anchor", "anchored_at")},
        "payload_id": "registry_entry_signing_payload_v2",
        "payload_schema": "loquitur.registry_entry.v1",
        "signature_algorithm": "secp256k1_ecdsa_sha256",
    }
    return hashlib.sha256(ENTRY_PREFIX + rfc8785.dumps(envelope)).digest()


def _trust(root_status: str, verdict: str) -> dict[str, Any]:
    return {
        "authorization_status": "AUTHORIZED_ACTIVE_KEY",
        "signature_status": "VALID_SIGNATURE",
        "root_signature_status": root_status,
        "verdict": verdict,
    }


def test_the_adapter_answers_every_public_api_operation() -> None:
    from authorization_kit import BUNDLE, EVALUATION_TIME, IssuerKey, authorization_material

    issuer, root = IssuerKey(), IssuerKey()
    entry, registry = authorization_material(issuer)
    signed = _root_signed(registry, root)
    altered = json.loads(json.dumps(signed))
    altered["entries"][0]["allowed_asset_types"].append("equity")
    roots = _roots(root.public_key_hex)
    chain = {"trust_registry_b64": _doc(signed), "trust_roots_b64": _doc(roots), "evaluation_time": EVALUATION_TIME}
    revoked = {**chain, "trust_roots_b64": _doc(_roots(root.public_key_hex, "revoked"))}
    later = {**chain, "trust_roots_b64": _doc({**roots, "schema_version": "v2"})}
    key = {"public_key_hex": issuer.public_key_hex, "key_id": entry["issuer_key_id"], "key_type": "secp256k1"}
    unsigned = {k: v for k, v in entry.items() if k != "signature"}
    verified = {
        "status": "OFFLINE_OK",
        "verdict": "PASS",
        "exit_code": 0,
        "reason": "local_integrity_registry_link_and_trust_checks_passed",
        "errors": [],
        "checks_requested": ["structure", "integrity", "link", "authorization"],
        "checks_established": ["structure", "integrity", "link", "authorization"],
        "review_reasons": [],
        "evaluation_time": EVALUATION_TIME,
        "trust_registry": {
            "authorization_status": "AUTHORIZED_ACTIVE_KEY",
            "signature_status": "VALID_SIGNATURE",
            "trust_registry_root_signature_status": "ROOT_SIGNATURE_VALID",
        },
        "checks": {"registry_link": True, "trust_registry": True, "registry_signature": "VALID_SIGNATURE"},
    }
    not_an_entry = {
        "authorization_status": "INVALID_REGISTRY_ENTRY",
        "signature_status": None,
        "root_signature_status": "ROOT_SIGNATURE_NOT_EVALUATED",
        "verdict": "FAIL",
    }
    cases: list[tuple[bytes, dict[str, Any]]] = [
        # trust_registry: the statuses, and the verdict that folds in the root and the time.
        (_request("t1", "trust_registry", entry_b64=_doc(entry), **chain), _trust("ROOT_SIGNATURE_VALID", "PASS")),
        (
            _request("t2", "trust_registry", entry_b64=_doc(entry), trust_registry_b64=_doc(signed)),
            _trust("NO_PINNED_TRUST_ROOT", "REVIEW"),
        ),
        (
            _request("t3", "trust_registry", entry_b64=_doc(entry), **{**chain, "trust_registry_b64": _doc(altered)}),
            _trust("ROOT_SIGNATURE_INVALID", "FAIL"),
        ),
        (_request("t4", "trust_registry", entry_b64=_doc(entry), **revoked), _trust("ROOT_KEY_REVOKED", "FAIL")),
        (
            _request(
                "t5",
                "trust_registry",
                entry_b64=_doc(entry),
                trust_registry_b64=_doc(signed),
                trust_roots_b64=_doc(roots),
            ),
            _trust("ROOT_SIGNATURE_VALID", "REVIEW"),
        ),
        (_request("t6", "trust_registry", entry_b64=_doc([entry]), **chain), not_an_entry),
        (_request("t7", "trust_registry", entry_b64=_b64(b'{"a":1,"a":2}'), **chain), {"entry_strict": False}),
        (
            _request("t8", "trust_registry", entry_b64=_doc(entry), **{**chain, "evaluation_time": "2026-05-10"}),
            {"refused": "evaluation_time"},
        ),
        (_request("t9", "trust_registry", entry_b64=_doc(entry), **later), {"refused": "trust_roots_version"}),
        (
            _request(
                "t10", "trust_registry", entry_b64=_doc(entry), **{**chain, "trust_roots_b64": _doc({"roots": []})}
            ),
            {"refused": "trust_roots"},
        ),
        # root_signature: trust-root.md section 5
        (_request("r1", "root_signature", **chain), {"status": "ROOT_SIGNATURE_VALID"}),
        (
            _request(
                "r2", "root_signature", **{**chain, "trust_registry_b64": _doc(_root_signed(registry, root, "root-b"))}
            ),
            {"status": "UNKNOWN_ROOT_KEY"},
        ),
        (
            _request("r3", "root_signature", **{**chain, "evaluation_time": "2027-01-01T00:00:01Z"}),
            {"status": "ROOT_KEY_EXPIRED"},
        ),
        (_request("r4", "root_signature", trust_registry_b64=_doc(signed)), {"status": "NO_PINNED_TRUST_ROOT"}),
        (
            _request("r5", "root_signature", **{**chain, "trust_registry_b64": _b64(b"\xef\xbb\xbf{}")}),
            {"registry_strict": False},
        ),
        # trust_roots: trust-root.md section 3, and the version gate
        (_request("o1", "trust_roots", input_b64=_doc(roots)), {"accepted": True, "unsupported_version": None}),
        (
            _request("o2", "trust_roots", input_b64=_doc({**roots, "schema_version": "v2"})),
            {"accepted": False, "unsupported_version": "v2"},
        ),
        # signature: rows 14 to 20
        (_request("g1", "signature", entry_b64=_doc(entry), **key), {"status": "VALID_SIGNATURE"}),
        (
            _request("g2", "signature", entry_b64=_doc(entry), **{**key, "key_id": "other"}),
            {"status": "SIGNATURE_KEY_MISMATCH"},
        ),
        (
            _request("g3", "signature", entry_b64=_doc(entry), **{**key, "key_type": "ed25519"}),
            {"status": "UNSUPPORTED_SIGNATURE_ALGORITHM"},
        ),
        (
            _request("g4", "signature", entry_b64=_doc({**entry, "policy_version": "9.9.9"}), **key),
            {"status": "SIGNATURE_INVALID"},
        ),
        (_request("g5", "signature", entry_b64=_doc(unsigned), **key), {"status": "MALFORMED_SIGNATURE"}),
        (_request("g6", "signature", entry_b64=_doc([entry]), **key), {"entry_object": False}),
        # ecdsa
        (
            _request(
                "e1",
                "ecdsa",
                digest_hex=_entry_digest(entry).hex(),
                signature_hex=entry["signature"]["signature"],
                public_key_hex=issuer.public_key_hex,
            ),
            {"valid": True},
        ),
        (
            _request(
                "e2",
                "ecdsa",
                digest_hex=bytes(32).hex(),
                signature_hex=entry["signature"]["signature"],
                public_key_hex=issuer.public_key_hex,
            ),
            {"valid": False},
        ),
        # summary_rules: verdict-grounds.md sections 3 and 5
        (
            _request("u1", "summary_rules", input_b64=_b64(b'{"status":"pass","reason_codes":[1,1.0]}')),
            {"accepted": True, "rules": ["VG-1"]},
        ),
        (_request("u2", "summary_rules", input_b64=_b64(b"[]")), {"accepted": True, "rules": ["VG-1"]}),
        (_request("u3", "summary_rules", input_b64=_b64(b'{"a":1,"a":1}')), {"accepted": False, "rules": None}),
        # parse: the two contracts
        (_request("p1", "parse", kind="registry_entry", input_b64=_doc(entry)), {"accepted": True, "valid": True}),
        (
            _request("p2", "parse", kind="trust_registry", input_b64=_doc({**signed, "extra": 1})),
            {"accepted": True, "valid": False},
        ),
        (_request("p3", "parse", kind="trust_registry", input_b64=_doc([signed])), {"accepted": True, "valid": False}),
        # capability: the allowlist of pairs
        (
            _request("c1", "capability", algorithm="secp256k1_ecdsa_sha256", key_type="ed25519"),
            {"algorithm_supported": True, "key_type_supported": False, "pair_supported": False},
        ),
        # verify: the whole run, its normative members and three per-check results
        (_request("v1", "verify", bundle=str(BUNDLE), entry_b64=_doc(entry), **chain), verified),
        (
            _request("v2", "verify", bundle=str(BUNDLE), entry_b64=_doc(entry), **{**chain, "evaluation_time": 5}),
            {"refused": "evaluation_time"},
        ),
    ]
    responses = _run([line for line, _ in cases])
    for (line, expected), response in zip(cases, responses, strict=True):
        identifier = json.loads(line)["id"]
        assert response == {"id": identifier, **expected}, (line[:200], response)
