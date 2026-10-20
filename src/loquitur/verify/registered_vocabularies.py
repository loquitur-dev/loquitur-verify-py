"""The registered vocabularies built into this verifier, byte for byte.

GENERATED FILE - do not edit by hand.
Regenerate with: python tools/generate_registered_vocabularies.py

Each value is the bytes of loquitur-protocol's `vocabularies/<kind>.json`, and
REGISTERED_VOCABULARY_SHA256 their SHA-256 (verification-vocabularies.md §8). `vocabulary.py`
reads them under the same rules as a document an operator supplies.
"""

from __future__ import annotations

REGISTERED_VOCABULARIES: dict[str, bytes] = {
    "asset_type": (
        b"{\n"
        b"  \"object_type\": \"registered_vocabulary\",\n"
        b"  \"schema_version\": \"v1\",\n"
        b"  \"kind\": \"asset_type\",\n"
        b"  \"version\": \"1.0.0\",\n"
        b"  \"values\": {\n"
        b"    \"fund_nav\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"Fund net asset value\",\n"
        b"      \"profile\": null\n"
        b"    },\n"
        b"    \"property\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"Real property\",\n"
        b"      \"profile\": null\n"
        b"    }\n"
        b"  }\n"
        b"}\n"
    ),
    "workflow": (
        b"{\n"
        b"  \"object_type\": \"registered_vocabulary\",\n"
        b"  \"schema_version\": \"v1\",\n"
        b"  \"kind\": \"workflow\",\n"
        b"  \"version\": \"1.0.0\",\n"
        b"  \"values\": {\n"
        b"    \"fund_nav_initial\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"Initial fund NAV evidence\",\n"
        b"      \"profile\": null,\n"
        b"      \"asset_types\": [\n"
        b"        \"fund_nav\"\n"
        b"      ]\n"
        b"    },\n"
        b"    \"fund_nav_update\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"Fund NAV update\",\n"
        b"      \"profile\": null,\n"
        b"      \"asset_types\": [\n"
        b"        \"fund_nav\"\n"
        b"      ]\n"
        b"    },\n"
        b"    \"property_pre_listing\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"Property pre-listing evidence\",\n"
        b"      \"profile\": null,\n"
        b"      \"asset_types\": [\n"
        b"        \"property\"\n"
        b"      ]\n"
        b"    },\n"
        b"    \"property_review\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"Property periodic review\",\n"
        b"      \"profile\": null,\n"
        b"      \"asset_types\": [\n"
        b"        \"property\"\n"
        b"      ]\n"
        b"    }\n"
        b"  }\n"
        b"}\n"
    ),
    "anchoring_method": (
        b"{\n"
        b"  \"object_type\": \"registered_vocabulary\",\n"
        b"  \"schema_version\": \"v1\",\n"
        b"  \"kind\": \"anchoring_method\",\n"
        b"  \"version\": \"1.0.0\",\n"
        b"  \"values\": {\n"
        b"    \"blockchain_transaction\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"A transaction recorded on a blockchain\",\n"
        b"      \"profile\": null\n"
        b"    },\n"
        b"    \"rfc3161_timestamp\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"An RFC 3161 time-stamp token\",\n"
        b"      \"profile\": null\n"
        b"    },\n"
        b"    \"transparency_log_checkpoint\": {\n"
        b"      \"since\": \"1.0.0\",\n"
        b"      \"status\": \"active\",\n"
        b"      \"title\": \"A checkpoint of a transparency log\",\n"
        b"      \"profile\": null\n"
        b"    }\n"
        b"  }\n"
        b"}\n"
    ),
}

REGISTERED_VOCABULARY_SHA256: dict[str, str] = {
    "asset_type": "c5ae2936e0ab1fab0cd5c13010f62e4b05bf8e8d8a5536d34e0a81a5e141ccc4",
    "workflow": "a979ad5b26ae56841e32de648addb952acd592f5d9824c62f9bb9ca9b146ae8b",
    "anchoring_method": "931dcba1c63359702634794f3d9c408b46e70645468f1cd53e0b9f12f213f860",
}
