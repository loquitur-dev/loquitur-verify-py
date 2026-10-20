"""Test-only adapter for a seeded differential harness: one JSON request per line in, one JSON response per line out.

Not part of the published package: tools/ ships in the source distribution only, never in the
wheel (tests/test_differential_adapter.py checks both). A harness that drives this verifier and
loquitur-verify-ts over the same generated inputs compares the answers; the two verifiers were
written separately against the specification, by the same maintainer.

Transport: requests on stdin, UTF-8, one per line; exactly one response line per request on
stdout, in order, flushed after each line, and exit 0 at the end of input. A response is compact
JSON with sorted keys and non-ASCII characters escaped. Every request is
``{"id": <string>, "op": <string>, ...}`` and every response carries the same ``id``; bytes travel
as standard base64 in ``input_b64``.

  load            {input_b64}             -> {accepted}
  jcs             {input_b64}             -> {accepted, output_b64}
  signing_message {kind, input_b64}       -> {accepted, output_b64}
                  kind: registry_entry | trust_registry
  instant         {value}                 -> {accepted}
  member_name     {value}                 -> {portable, folded, self_declaration}

The public-API operations, one or more per pair of tools/public_api_parity.json. A document
travels as bytes in a ``*_b64`` member and is read as the verifier reads one from disk, with the
strict loader; a member marked ``?`` may be absent. The operator's inputs are refused first, in this
order, with ``{refused}`` and nothing else: ``evaluation_time`` (not a calendar instant), then
``trust_roots_version`` (a trust-root document of a later version) or ``trust_roots`` (one that is
not strict JSON or breaks trust-root.md section 3).

  trust_registry  {entry_b64, trust_registry_b64, trust_roots_b64?, evaluation_time?}
                  -> {authorization_status, signature_status, root_signature_status, verdict}
                     | {entry_strict: false} | {refused}
                     verify_registry_entry_trust; verdict is the result's own
  root_signature  {trust_registry_b64, trust_roots_b64?, evaluation_time?}
                  -> {status} | {registry_strict: false} | {refused}
  trust_roots     {input_b64}             -> {accepted, unsupported_version}
  signature       {entry_b64, public_key_hex, key_id, key_type}
                  -> {status} | {entry_strict: false} | {entry_object: false}
                     the signature step, trust-registry-authorization.md section 6 rows 14 to 20
  ecdsa           {digest_hex, signature_hex, public_key_hex} -> {valid}
  summary_rules   {input_b64}             -> {accepted, rules}
  parse           {kind, input_b64}       -> {accepted, valid}
                  kind: registry_entry | trust_registry; valid: the document meets its contract
  capability      {algorithm, key_type}   -> {algorithm_supported, key_type_supported, pair_supported}
  verify          {bundle, entry_b64?, trust_registry_b64?, trust_roots_b64?, evaluation_time?}
                  -> {status, verdict, exit_code, reason, errors, checks_requested,
                      checks_established, review_reasons, evaluation_time, trust_registry, checks}
                     | {refused}
                     verify_path over the bundle directory ``bundle``; trust_registry holds the
                     three statuses of report-contract.md section 5.4 or is null, and checks the
                     per-check results registry_link, trust_registry and registry_signature

Any other op answers ``{"error": "unknown_op"}``; a request that raises answers
``{"error": <exception class name>}`` and the next line is read; a line that is not a JSON
object with a string ``id`` answers ``{"id": null, "error": "bad_request"}``.

Every answer comes from the functions the verifier itself runs when it reads a document from
disk: the strict loader on the bytes (never on a pre-decoded string), the canonicalizer, the two
signing-message builders, the evaluation-time parser, the member-name rule, the exported
verify_registry_entry_trust, verify_path, and the functions those two call for the signature step,
root authentication, the trust-root parser, the summary rules, the two contracts and the capability
allowlist. Nothing here re-implements a rule; the one decision taken here is the order in which the
operator's inputs are refused, which is the order loquitur-verify-ts refuses them in.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

from loquitur.verify import verify_registry_entry_trust
from loquitur.verify.canonical import CanonicalizationError, JsonLoadError, canonical_json_bytes, loads_json_bytes
from loquitur.verify.contract_validation import contract_errors
from loquitur.verify.cryptographic_capabilities import (
    signature_algorithm_supported,
    signature_pair_supported,
    trust_key_type_supported,
)
from loquitur.verify.evaluation_time import EvaluationTimeError, operator_evaluation_time
from loquitur.verify.manifest import _self_referential
from loquitur.verify.members import fold_member_name, member_name_problem
from loquitur.verify.registry_link import registry_entry_contract_violations
from loquitur.verify.runner import verify_path
from loquitur.verify.secp256k1 import verify_digest
from loquitur.verify.signing_envelope import signing_message_bytes
from loquitur.verify.trust_registry import _trust_registry_shape_errors, _verify_signature
from loquitur.verify.trust_root import (
    TrustRootError,
    TrustRootKey,
    parse_trust_roots,
    trust_registry_signing_bytes,
    trust_root_document_unsupported_version,
    verify_trust_registry_root_signature,
)
from loquitur.verify.verdict_grounds import summary_violated_rules

_SIGNING_MESSAGES: dict[str, Callable[[dict[str, Any]], bytes]] = {
    "registry_entry": signing_message_bytes,
    "trust_registry": trust_registry_signing_bytes,
}


def _input_bytes(request: dict[str, Any]) -> bytes:
    encoded = request["input_b64"]
    if not isinstance(encoded, str):
        raise TypeError("input_b64 is not a string")
    return base64.b64decode(encoded, validate=True)


def _b64(data: bytes | None) -> str | None:
    return None if data is None else base64.b64encode(data).decode("ascii")


def _load(request: dict[str, Any]) -> dict[str, Any]:
    try:
        loads_json_bytes(_input_bytes(request))
    except JsonLoadError:
        return {"accepted": False}
    return {"accepted": True}


def _jcs(request: dict[str, Any]) -> dict[str, Any]:
    try:
        output = canonical_json_bytes(loads_json_bytes(_input_bytes(request)))
    except (JsonLoadError, CanonicalizationError):
        return {"accepted": False, "output_b64": None}
    return {"accepted": True, "output_b64": _b64(output)}


def _signing_message(request: dict[str, Any]) -> dict[str, Any]:
    kind = request["kind"]
    if not isinstance(kind, str) or kind not in _SIGNING_MESSAGES:
        raise ValueError("kind is neither registry_entry nor trust_registry")
    build = _SIGNING_MESSAGES[kind]
    data = _input_bytes(request)
    try:
        document = loads_json_bytes(data)
    except JsonLoadError:
        return {"accepted": False, "output_b64": None}
    if not isinstance(document, dict):
        return {"accepted": False, "output_b64": None}
    try:
        message = build(document)
    except CanonicalizationError:
        return {"accepted": False, "output_b64": None}
    return {"accepted": True, "output_b64": _b64(message)}


def _instant(request: dict[str, Any]) -> dict[str, Any]:
    try:
        operator_evaluation_time(request["value"])
    except EvaluationTimeError:
        return {"accepted": False}
    return {"accepted": True}


def _member_name(request: dict[str, Any]) -> dict[str, Any]:
    value = request["value"]
    if not isinstance(value, str):
        raise TypeError("value is not a string")
    return {
        "portable": member_name_problem(value) is None,
        "folded": fold_member_name(value),
        "self_declaration": _self_referential(value),
    }


_NOT_STRICT = object()


def _b64_member(request: dict[str, Any], member: str) -> str:
    encoded = request[member]
    if not isinstance(encoded, str):
        raise TypeError(f"{member} is not a string")
    return encoded


def _document(request: dict[str, Any], member: str) -> Any:
    """The strictly loaded document of ``member``, or _NOT_STRICT when the loader refuses its bytes."""
    try:
        return loads_json_bytes(base64.b64decode(_b64_member(request, member), validate=True))
    except JsonLoadError:
        return _NOT_STRICT


class _Refused(Exception):
    def __init__(self, what: str) -> None:
        super().__init__(what)
        self.what = what


def _operator_inputs(request: dict[str, Any]) -> tuple[str | None, tuple[TrustRootKey, ...] | None]:
    """The evaluation time and the roots, each refused as the verifier refuses it, in that order."""
    evaluation_time = None
    if "evaluation_time" in request:
        try:
            evaluation_time = operator_evaluation_time(request["evaluation_time"])
        except EvaluationTimeError as exc:
            raise _Refused("evaluation_time") from exc
    roots = None
    if "trust_roots_b64" in request:
        document = _document(request, "trust_roots_b64")
        if document is _NOT_STRICT:
            raise _Refused("trust_roots")
        if trust_root_document_unsupported_version(document) is not None:
            raise _Refused("trust_roots_version")
        try:
            roots = parse_trust_roots(document)
        except TrustRootError as exc:
            raise _Refused("trust_roots") from exc
    return evaluation_time, roots


def _refusable(operation: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def answer(request: dict[str, Any]) -> dict[str, Any]:
        try:
            return operation(request)
        except _Refused as refusal:
            return {"refused": refusal.what}

    return answer


def _write(directory: Path, name: str, request: dict[str, Any], member: str) -> Path:
    path = directory / name
    path.write_bytes(base64.b64decode(_b64_member(request, member), validate=True))
    return path


@_refusable
def _trust_registry(request: dict[str, Any]) -> dict[str, Any]:
    evaluation_time, roots = _operator_inputs(request)
    entry = _document(request, "entry_b64")
    if entry is _NOT_STRICT:
        return {"entry_strict": False}
    with tempfile.TemporaryDirectory() as directory:
        result = verify_registry_entry_trust(
            entry,
            trust_registry_path=_write(Path(directory), "trust_registry.json", request, "trust_registry_b64"),
            trust_roots=roots or (),
            evaluation_time=evaluation_time,
        )
    return {
        "authorization_status": result.authorization_status,
        "signature_status": result.signature_status,
        "root_signature_status": result.root_signature_status,
        "verdict": result.verdict,
    }


@_refusable
def _root_signature(request: dict[str, Any]) -> dict[str, Any]:
    evaluation_time, roots = _operator_inputs(request)
    registry = _document(request, "trust_registry_b64")
    if registry is _NOT_STRICT:
        return {"registry_strict": False}
    verification = verify_trust_registry_root_signature(registry, evaluated_at=evaluation_time, roots=roots or ())
    return {"status": verification.status}


def _trust_roots(request: dict[str, Any]) -> dict[str, Any]:
    document = _document(request, "input_b64")
    if document is _NOT_STRICT:
        return {"accepted": False, "unsupported_version": None}
    version = trust_root_document_unsupported_version(document)
    if version is not None:
        return {"accepted": False, "unsupported_version": version}
    try:
        parse_trust_roots(document)
    except TrustRootError:
        return {"accepted": False, "unsupported_version": None}
    return {"accepted": True, "unsupported_version": None}


def _signature(request: dict[str, Any]) -> dict[str, Any]:
    entry = _document(request, "entry_b64")
    if entry is _NOT_STRICT:
        return {"entry_strict": False}
    if not isinstance(entry, dict):
        return {"entry_object": False}
    public_key_hex = request["public_key_hex"]
    if not isinstance(public_key_hex, str):
        raise TypeError("public_key_hex is not a string")
    outcome = _verify_signature(entry, public_key_hex, expected_key_id=request["key_id"], key_type=request["key_type"])
    return {"status": outcome.status}


def _ecdsa(request: dict[str, Any]) -> dict[str, Any]:
    digest = bytes.fromhex(request["digest_hex"])
    return {"valid": verify_digest(digest, request["signature_hex"], request["public_key_hex"])}


def _summary_rules(request: dict[str, Any]) -> dict[str, Any]:
    summary = _document(request, "input_b64")
    if summary is _NOT_STRICT:
        return {"accepted": False, "rules": None}
    return {"accepted": True, "rules": summary_violated_rules(summary)}


def _parse(request: dict[str, Any]) -> dict[str, Any]:
    kind = request["kind"]
    if kind not in ("registry_entry", "trust_registry"):
        raise ValueError("kind is neither registry_entry nor trust_registry")
    document = _document(request, "input_b64")
    if document is _NOT_STRICT:
        return {"accepted": False, "valid": None}
    if kind == "registry_entry":
        errors = registry_entry_contract_violations(document)
    elif isinstance(document, dict):
        errors = _trust_registry_shape_errors(document)
    else:
        errors = contract_errors("trust_registry", document)
    return {"accepted": True, "valid": not errors}


def _capability(request: dict[str, Any]) -> dict[str, Any]:
    algorithm, key_type = request["algorithm"], request["key_type"]
    return {
        "algorithm_supported": signature_algorithm_supported(algorithm),
        "key_type_supported": trust_key_type_supported(key_type),
        "pair_supported": signature_pair_supported(algorithm, key_type),
    }


VERIFY_CHECKS = ("registry_link", "trust_registry", "registry_signature")


@_refusable
def _verify(request: dict[str, Any]) -> dict[str, Any]:
    evaluation_time, roots = _operator_inputs(request)
    bundle = request["bundle"]
    if not isinstance(bundle, str):
        raise TypeError("bundle is not a string")
    with tempfile.TemporaryDirectory() as directory:
        here = Path(directory)
        entry = _write(here, "registry_entry.json", request, "entry_b64") if "entry_b64" in request else None
        trust = (
            _write(here, "trust_registry.json", request, "trust_registry_b64")
            if "trust_registry_b64" in request
            else None
        )
        report = verify_path(
            bundle,
            registry_entry_path=entry,
            trust_registry_path=trust,
            trust_roots=() if roots is None else roots,
            evaluation_time=evaluation_time,
        ).to_dict()
    trust_registry = report.get("trust_registry")
    checks = report.get("checks") or {}
    return {
        "status": report["status"],
        "verdict": report["verdict"],
        "exit_code": report["exit_code"],
        "reason": report["outcome"]["reason"],
        "errors": [error.get("code") for error in report["errors"]],
        "checks_requested": report["checks_requested"],
        "checks_established": report["checks_established"],
        "review_reasons": report["review_reasons"],
        "evaluation_time": report["evaluation_time"],
        "trust_registry": None
        if trust_registry is None
        else {
            "authorization_status": trust_registry["authorization_status"],
            "signature_status": trust_registry["signature_status"],
            "trust_registry_root_signature_status": trust_registry["trust_registry_root_signature_status"],
        },
        "checks": {name: checks.get(name) for name in VERIFY_CHECKS},
    }


OPERATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "load": _load,
    "jcs": _jcs,
    "signing_message": _signing_message,
    "instant": _instant,
    "member_name": _member_name,
    "trust_registry": _trust_registry,
    "root_signature": _root_signature,
    "trust_roots": _trust_roots,
    "signature": _signature,
    "ecdsa": _ecdsa,
    "summary_rules": _summary_rules,
    "parse": _parse,
    "capability": _capability,
    "verify": _verify,
}


def respond(line: bytes) -> dict[str, Any]:
    """The response to one request line (without its line terminator)."""
    try:
        request = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {"id": None, "error": "bad_request"}
    if not isinstance(request, dict) or not isinstance(request.get("id"), str):
        return {"id": None, "error": "bad_request"}
    identifier = request["id"]
    operation = OPERATIONS.get(request.get("op")) if isinstance(request.get("op"), str) else None
    if operation is None:
        return {"id": identifier, "error": "unknown_op"}
    try:
        answer = operation(request)
    except Exception as exc:  # the protocol answers any failure with its class name, and goes on
        return {"id": identifier, "error": type(exc).__name__}
    return {"id": identifier, **answer}


def run(source: BinaryIO, sink: BinaryIO) -> None:
    for raw in source:
        line = raw[:-1] if raw.endswith(b"\n") else raw
        response = json.dumps(respond(line), sort_keys=True, separators=(",", ":"))
        sink.write(response.encode("ascii") + b"\n")
        sink.flush()


def main() -> int:
    run(sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
