"""The authorization registry-entry signature step: its order and its labels.

The step follows the model trust-root.md sets for a root signature (sections 3 and 5), so one
signature is judged one way wherever it appears:

1. no signature object: MALFORMED_SIGNATURE, as the first finding after authorization;
2. the signing payload (legacy v1 not allowed, or not v2), then the algorithm;
3. the form of the value, 128 lowercase hex characters: MALFORMED_SIGNATURE;
4. the key ids, compared with the authorized key id: SIGNATURE_KEY_MISMATCH;
5. SIGNATURE_INVALID for whatever is well formed and does not verify: a public key that is
   not a point on the curve, r or s out of range, a high s, a wrong signature.

Three rows are where two readings most easily part, and both verifiers report them alike: an
entry with a null or absent signature is MALFORMED_SIGNATURE after authorization, not
INVALID_REGISTRY_ENTRY before it (the schema allows both, and the entry links at the link check); a
trust-registry key off the curve is SIGNATURE_INVALID; and the value's form is checked before
the key ids, so a missing value is MALFORMED_SIGNATURE.

The rows over ``verify_path`` run with an issuer key generated for the test. The order rows
call the step itself, because the registry entry's contract refuses a malformed signature
value before a bundle verification reaches it.
"""

from __future__ import annotations

from pathlib import Path

from authorization_kit import (
    SECP256K1_ORDER,
    IssuerKey,
    authorization_material,
    fixture_entry,
    outcome,
    run_authorization,
)

import loquitur.verify.trust_registry as trust_registry

AUTHORIZED = {"registry_link": True, "authorization_status": "AUTHORIZED_ACTIVE_KEY"}
REVIEW = {"status": "OFFLINE_REVIEW", "verdict": "REVIEW", "exit_code": 2}
FAIL = {"status": "OFFLINE_FAIL", "verdict": "FAIL", "exit_code": 1}


def _signature_failed(label: str) -> dict:
    return {**FAIL, **AUTHORIZED, "trust_registry": False, "registry_signature": label, "signature_status": label}


# A signature naming no payload breaks the entry's contract (trust-registry-authorization.md section
# 6: this protocol defines no earlier signing payload), so the link refuses the entry and the trust
# registry is never evaluated.
ENTRY_REFUSED = {
    **FAIL,
    "registry_link": False,
    "trust_registry": None,
    "registry_signature": "UNSUPPORTED",
    "authorization_status": None,
    "signature_status": None,
}


def _with_value(value_of):
    def change(entry: dict) -> None:
        entry["signature"]["signature"] = value_of(entry["signature"]["signature"])

    return change


def test_signature_step_labels_through_verify_path(tmp_path: Path) -> None:
    key = IssuerKey()
    n = SECP256K1_ORDER
    after_signing = {
        "r-equal-to-n": _with_value(lambda s: format(n, "064x") + s[64:]),
        "r-above-n": _with_value(lambda s: format(n + 5, "064x") + s[64:]),
        "r-all-f": _with_value(lambda s: "f" * 64 + s[64:]),
        "r-zero": _with_value(lambda s: "0" * 64 + s[64:]),
        "s-zero": _with_value(lambda s: s[:64] + "0" * 64),
        "s-equal-to-n": _with_value(lambda s: s[:64] + format(n, "064x")),
        "s-high": _with_value(lambda s: s[:64] + format(n - int(s[64:], 16), "064x")),
    }
    rows: dict[str, tuple[dict, dict]] = {
        "control": (
            authorization_material(key),
            {
                **REVIEW,
                **AUTHORIZED,
                "trust_registry": True,
                "registry_signature": "VALID_SIGNATURE",
                "signature_status": "VALID_SIGNATURE",
            },
        ),
        "signature-null": (
            authorization_material(key, entry=lambda e: e.update(signature=None)),
            _signature_failed("MALFORMED_SIGNATURE"),
        ),
        "signature-absent": (
            authorization_material(key, entry=lambda e: e.pop("signature")),
            _signature_failed("MALFORMED_SIGNATURE"),
        ),
        "public-key-off-curve": (
            authorization_material(key, trust=lambda t: t["entries"][0].update(public_key_hex="04" + "11" * 64)),
            _signature_failed("SIGNATURE_INVALID"),
        ),
        "no-payload-named": (
            authorization_material(
                key, entry=lambda e: (e["signature"].pop("payload_id"), e["signature"].pop("payload_version"))
            ),
            ENTRY_REFUSED,
        ),
        "no-payload-named-and-key-id-mismatch": (
            authorization_material(
                key,
                entry=lambda e: (
                    e["signature"].pop("payload_id"),
                    e["signature"].pop("payload_version"),
                    e["signature"].update(key_id="other-key"),
                ),
            ),
            ENTRY_REFUSED,
        ),
        "signature-key-id-mismatch": (
            authorization_material(key, entry=lambda e: e["signature"].update(key_id="other-key")),
            _signature_failed("SIGNATURE_KEY_MISMATCH"),
        ),
    }
    for label, change in after_signing.items():
        entry, registry = authorization_material(key)
        change(entry)
        rows[label] = ((entry, registry), _signature_failed("SIGNATURE_INVALID"))
    got = {label: outcome(run_authorization(tmp_path / label, *material)) for label, (material, _) in rows.items()}
    assert got == {label: want for label, (_, want) in rows.items()}


def test_signature_step_order_and_vocabulary() -> None:
    key = IssuerKey()
    entry = key.sign_entry(fixture_entry())
    good_key = key.public_key_hex

    def step(change=None, public_key_hex: str = good_key, key_type: str = "secp256k1") -> str:
        document = fixture_entry()
        document["signature"] = dict(entry["signature"])
        if change is not None:
            change(document)
        return trust_registry._verify_signature(
            document, public_key_hex, expected_key_id="demo-key-2", key_type=key_type
        ).status

    def mismatch(e: dict) -> None:
        e["signature"]["key_id"] = "other-key"

    got = {
        "valid": step(),
        "value-missing": step(lambda e: e["signature"].pop("signature")),
        "value-missing-and-key-id-mismatch": step(lambda e: (e["signature"].pop("signature"), mismatch(e))),
        "value-uppercase-and-key-id-mismatch": step(
            lambda e: (e["signature"].update(signature=e["signature"]["signature"].upper()), mismatch(e))
        ),
        "value-not-a-string": step(lambda e: e["signature"].update(signature=7)),
        "algorithm-and-form-and-key-id": step(
            lambda e: (e["signature"].update(algorithm="ed25519", signature="z" * 128), mismatch(e))
        ),
        "payload-and-algorithm": step(lambda e: e["signature"].update(payload_version=3, algorithm="ed25519")),
        "no-payload-and-algorithm": step(
            lambda e: (
                e["signature"].pop("payload_id"),
                e["signature"].pop("payload_version"),
                e["signature"].update(algorithm="ed25519"),
            )
        ),
        "key-type-outside-the-allowlist": step(key_type="ed25519"),
        "key-type-and-form": step(lambda e: e["signature"].update(signature="z" * 128), key_type="ed25519"),
        "entry-issuer-key-id-mismatch": step(lambda e: e.update(issuer_key_id="other-key")),
        "public-key-off-curve": step(public_key_hex="04" + "11" * 64),
        "public-key-not-uncompressed-hex": step(public_key_hex="04" + "zz" * 64),
        "public-key-uppercase": step(public_key_hex="04" + good_key[2:].upper()),
    }
    assert got == {
        "valid": "VALID_SIGNATURE",
        "value-missing": "MALFORMED_SIGNATURE",
        "value-missing-and-key-id-mismatch": "MALFORMED_SIGNATURE",
        "value-uppercase-and-key-id-mismatch": "MALFORMED_SIGNATURE",
        "value-not-a-string": "MALFORMED_SIGNATURE",
        "algorithm-and-form-and-key-id": "UNSUPPORTED_SIGNATURE_ALGORITHM",
        "payload-and-algorithm": "UNSUPPORTED_SIGNING_PAYLOAD",
        # On its own the step reads a signature naming no payload as naming another one (row 15).
        "no-payload-and-algorithm": "UNSUPPORTED_SIGNING_PAYLOAD",
        "key-type-outside-the-allowlist": "UNSUPPORTED_SIGNATURE_ALGORITHM",
        "key-type-and-form": "UNSUPPORTED_SIGNATURE_ALGORITHM",
        "entry-issuer-key-id-mismatch": "SIGNATURE_KEY_MISMATCH",
        "public-key-off-curve": "SIGNATURE_INVALID",
        "public-key-not-uncompressed-hex": "SIGNATURE_INVALID",
        "public-key-uppercase": "SIGNATURE_INVALID",
    }
    vocabulary = {value for name, value in vars(trust_registry).items() if name.startswith("SIG_STATUS_")}
    assert vocabulary == {
        "VALID_SIGNATURE",
        "MALFORMED_SIGNATURE",
        "UNSUPPORTED_SIGNING_PAYLOAD",
        "UNSUPPORTED_SIGNATURE_ALGORITHM",
        "SIGNATURE_KEY_MISMATCH",
        "SIGNATURE_INVALID",
    }
