"""Normative registry-entry signing envelope v2 for the standalone verifier."""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_json_bytes

SIGNATURE_ALGORITHM = "secp256k1_ecdsa_sha256"
SIGNING_PAYLOAD_ID = "registry_entry_signing_payload_v2"
SIGNING_PAYLOAD_VERSION = 2
SIGNING_ENVELOPE_DOMAIN = "org.loquitur.protocol.registry-entry-signature"
SIGNING_ENVELOPE_SCHEMA = "loquitur.signing_envelope.v2"
SIGNING_PAYLOAD_SCHEMA = "loquitur.registry_entry.v1"
SIGNING_DOMAIN_PREFIX = b"LOQUITUR\x00REGISTRY_ENTRY\x00SIGNATURE\x00V2\x00"
SIGNING_PAYLOAD_EXCLUDED_FIELDS = frozenset({"signature", "anchor", "anchored_at"})


def signing_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key not in SIGNING_PAYLOAD_EXCLUDED_FIELDS}


def signing_envelope(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": SIGNING_ENVELOPE_DOMAIN,
        "envelope_schema": SIGNING_ENVELOPE_SCHEMA,
        "envelope_version": SIGNING_PAYLOAD_VERSION,
        "payload": signing_payload(entry),
        "payload_id": SIGNING_PAYLOAD_ID,
        "payload_schema": SIGNING_PAYLOAD_SCHEMA,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }


def signing_message_bytes(entry: dict[str, Any]) -> bytes:
    return SIGNING_DOMAIN_PREFIX + canonical_json_bytes(signing_envelope(entry))


def signing_message_hash(entry: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(signing_message_bytes(entry)).hexdigest()
