"""A trust registry whose revocation fields or validity windows contradict each other is malformed.

Key status does not decide alone; the fields beside it are read. A key marked ``active`` with
a ``revoked_at`` in the past, a ``revoked`` key with no ``revoked_at``, and a window that ends
before it begins (which would otherwise read as ``ISSUER_KEY_NOT_YET_EFFECTIVE`` or
``TRUST_REGISTRY_NOT_YET_EFFECTIVE``) are contradictory trust material. A registry carrying
contradictory trust material is refused rather than read one way or the other: it is
``INVALID_TRUST_REGISTRY``, in either verifier, when

- an entry's status is ``active`` and its ``revoked_at`` or ``revocation_reason`` is not null;
- an entry's status is ``suspended`` and its ``revoked_at`` or ``revocation_reason`` is not null:
  a suspension is reversible and a revocation is not;
- an entry's status is ``revoked`` and its ``revoked_at`` is null;
- an entry's ``effective_from`` is later than its ``expires_at``;
- the registry's ``effective_at`` is later than its ``expires_at``;
- the registry's ``issued_at`` is later than its ``expires_at``: a registry cannot be issued
  after it expires.

Any entry of the registry counts, not only the one the registry entry names. A registry issued
before it takes effect is an advance issue and stays valid; bounds that are equal are not
inverted; a revoked entry that carries ``revoked_at`` is revoked whatever the evaluation time.
"""

from __future__ import annotations

from pathlib import Path

from authorization_kit import IssuerKey, authorization_material, outcome, run_authorization

INSTANT = "2026-05-10T00:00:00Z"  # the fixture entry's effective_at, the evaluation time
MALFORMED = {
    "status": "OFFLINE_FAIL",
    "verdict": "FAIL",
    "exit_code": 1,
    "registry_link": True,
    "trust_registry": False,
    "registry_signature": "UNSUPPORTED",
    "authorization_status": "INVALID_TRUST_REGISTRY",
    "signature_status": None,
}
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


def _refused(status: str) -> dict:
    return {**MALFORMED, "authorization_status": status}


def _key(**fields):
    return lambda t: t["entries"][0].update(fields)


def _second_issuer(**fields):
    def change(t: dict) -> None:
        other = dict(t["entries"][0], issuer_id="issuer_other_demo", issuer_key_id="other-key-1")
        other.update(fields)
        t["entries"].append(other)

    return change


ROWS = {
    # refused: contradictory trust material
    "active-with-revoked_at-in-the-past": (_key(revoked_at="2026-05-01T00:00:00Z"), MALFORMED),
    "active-with-revoked_at-in-the-future": (_key(revoked_at="2026-06-01T00:00:00Z"), MALFORMED),
    "active-with-revocation_reason-only": (_key(revocation_reason="key_compromise"), MALFORMED),
    "revoked-with-revoked_at-null": (_key(status="revoked"), MALFORMED),
    "suspended-with-revoked_at": (_key(status="suspended", revoked_at="2026-05-01T00:00:00Z"), MALFORMED),
    "suspended-with-revocation_reason-only": (_key(status="suspended", revocation_reason="under_review"), MALFORMED),
    "other-issuer-entry-suspended-with-revoked_at": (
        _second_issuer(status="suspended", revoked_at="2026-05-01T00:00:00Z"),
        MALFORMED,
    ),
    "revoked-with-revocation_reason-and-revoked_at-null": (_key(status="revoked", revocation_reason="x"), MALFORMED),
    "key-effective_from-after-expires_at": (
        _key(effective_from="2026-05-20T00:00:00Z", expires_at="2026-05-01T00:00:00Z"),
        MALFORMED,
    ),
    "registry-effective_at-after-expires_at": (
        lambda t: t.update(effective_at="2026-05-20T00:00:00Z", expires_at="2026-05-01T00:00:00Z"),
        MALFORMED,
    ),
    "registry-issued_at-after-expires_at": (lambda t: t.update(issued_at="2026-12-01T00:00:00Z"), MALFORMED),
    "other-issuer-entry-active-with-revoked_at": (_second_issuer(revoked_at="2026-05-01T00:00:00Z"), MALFORMED),
    "other-issuer-entry-window-inverted": (
        _second_issuer(effective_from="2026-05-20T00:00:00Z", expires_at="2026-05-01T00:00:00Z"),
        MALFORMED,
    ),
    # accepted: coherent trust material
    "control": (None, AUTHORIZED),
    "revoked-with-revoked_at-in-the-past": (
        _key(status="revoked", revoked_at="2026-05-01T00:00:00Z"),
        _refused("ISSUER_KEY_REVOKED"),
    ),
    "revoked-with-revoked_at-after-the-instant": (
        _key(status="revoked", revoked_at="2026-06-01T00:00:00Z", revocation_reason="key_compromise"),
        _refused("ISSUER_KEY_REVOKED"),
    ),
    "suspended-with-revoked_at-null": (_key(status="suspended"), _refused("ISSUER_KEY_SUSPENDED")),
    "key-window-a-single-instant": (_key(effective_from=INSTANT, expires_at=INSTANT), AUTHORIZED),
    "registry-issued-before-it-takes-effect": (lambda t: t.update(issued_at="2026-04-01T00:00:00Z"), AUTHORIZED),
    "registry-issued_at-equal-to-expires_at": (lambda t: t.update(issued_at="2026-05-29T12:00:00Z"), AUTHORIZED),
    "registry-effective_at-equal-to-expires_at": (
        lambda t: t.update(effective_at=INSTANT, expires_at=INSTANT, issued_at=INSTANT),
        AUTHORIZED,
    ),
}


def test_contradictory_revocation_fields_and_windows_make_the_trust_registry_malformed(tmp_path: Path) -> None:
    key = IssuerKey()
    got, expected = {}, {}
    for label, (change, want) in ROWS.items():
        entry, registry = authorization_material(key, trust=change)
        got[label] = outcome(run_authorization(tmp_path / label, entry, registry))
        expected[label] = want
    assert got == expected
