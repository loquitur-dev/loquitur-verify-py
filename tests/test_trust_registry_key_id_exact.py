"""Authorization key ids are compared exactly as written, as loquitur-verify-ts compares them.

Stripping the entry's ``issuer_key_id`` and the signature's ``key_id`` of surrounding
whitespace, and not the trust registry's own ``issuer_key_id``, would make two verifiers
disagree on the same bytes:

- an entry key id with a leading space would match the registry key without it;
- a registry key id with a trailing space or no-break space, used identically by the entry
  and its signature, would match nothing;
- a signature ``key_id`` that differs from the authorized key only by whitespace would be
  accepted.

Nothing is trimmed anywhere (hexadecimal and identifier values are compared as written), and
the whitespace set W decides only whether a value is empty. Every row below runs with a
freshly generated issuer key, so the signature holds and the key id is the only variable.
"""

from __future__ import annotations

from pathlib import Path

from authorization_kit import IssuerKey, authorization_material, outcome, run_authorization

AUTHORIZED = {
    "status": "OFFLINE_REVIEW",
    "verdict": "REVIEW",
    "exit_code": 2,
    "registry_link": True,
    "trust_registry": True,
    "registry_signature": "VALID_SIGNATURE",
    "authorization_status": "AUTHORIZED_ACTIVE_KEY",
    "signature_status": "VALID_SIGNATURE",
}
KEY_NOT_FOUND = {
    "status": "OFFLINE_FAIL",
    "verdict": "FAIL",
    "exit_code": 1,
    "registry_link": True,
    "trust_registry": False,
    "registry_signature": "UNSUPPORTED",
    "authorization_status": "ISSUER_KEY_NOT_FOUND",
    "signature_status": None,
}
KEY_MISMATCH = {
    "status": "OFFLINE_FAIL",
    "verdict": "FAIL",
    "exit_code": 1,
    "registry_link": True,
    "trust_registry": False,
    "registry_signature": "SIGNATURE_KEY_MISMATCH",
    "authorization_status": "AUTHORIZED_ACTIVE_KEY",
    "signature_status": "SIGNATURE_KEY_MISMATCH",
}
# A signature key_id made only of W is not a key id the signature step compares: the entry breaks
# its contract (registry-link.md section 2, the entry's free strings) and no registry is evaluated.
ENTRY_REFUSED = {
    "status": "OFFLINE_FAIL",
    "verdict": "FAIL",
    "exit_code": 1,
    "registry_link": False,
    "trust_registry": None,
    "registry_signature": "UNSUPPORTED",
    "authorization_status": None,
    "signature_status": None,
}

# (entry issuer_key_id, signature key_id, trust-registry issuer_key_id) -> outcome
ROWS = {
    "control": (("demo-key-2", "demo-key-2", "demo-key-2"), AUTHORIZED),
    "entry-leading-space": ((" demo-key-2", " demo-key-2", "demo-key-2"), KEY_NOT_FOUND),
    "entry-leading-space-signature-plain": ((" demo-key-2", "demo-key-2", "demo-key-2"), KEY_NOT_FOUND),
    "entry-trailing-tab": (("demo-key-2\t", "demo-key-2\t", "demo-key-2"), KEY_NOT_FOUND),
    "registry-trailing-space-used-identically": (("demo-key-2 ", "demo-key-2 ", "demo-key-2 "), AUTHORIZED),
    "registry-trailing-nbsp-used-identically": (
        ("demo-key-2\u00a0", "demo-key-2\u00a0", "demo-key-2\u00a0"),
        AUTHORIZED,
    ),
    "signature-trailing-space-only": (("demo-key-2", "demo-key-2 ", "demo-key-2"), KEY_MISMATCH),
    "signature-leading-ideographic-space-only": (("demo-key-2", "\u3000demo-key-2", "demo-key-2"), KEY_MISMATCH),
    "signature-key-id-only-whitespace": (("demo-key-2", "\u3000", "demo-key-2"), ENTRY_REFUSED),
}


def test_issuer_and_signature_key_ids_are_matched_as_written(tmp_path: Path) -> None:
    key = IssuerKey()
    got, expected = {}, {}
    for label, ((entry_key_id, signature_key_id, registry_key_id), want) in ROWS.items():

        def change_entry(entry, entry_key_id=entry_key_id, signature_key_id=signature_key_id):
            entry["issuer_key_id"] = entry_key_id
            entry["signature"]["key_id"] = signature_key_id

        def change_trust(registry, registry_key_id=registry_key_id):
            registry["entries"][0]["issuer_key_id"] = registry_key_id

        entry, registry = authorization_material(key, entry=change_entry, trust=change_trust)
        got[label] = outcome(run_authorization(tmp_path / label, entry, registry))
        expected[label] = want
    assert got == expected
