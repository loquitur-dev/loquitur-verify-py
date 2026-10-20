"""Root authentication that was never reached is reported as not evaluated, on every authorization path.

The trust-registry report carries ``root_signature_status``. A run that stops at authorization
or at the signature reports ``ROOT_SIGNATURE_NOT_EVALUATED``, and so does a run that stops
earlier, on a malformed registry entry, a malformed or contradictory trust registry, or a trust
registry that could not be read: root authentication is not reached on any of those paths either,
and a null status with no note would not say why. Every such run says so in the same words: the
status and the ``trust_registry_root_signature_not_verified:root_signature_not_evaluated`` note.
"""

from __future__ import annotations

from pathlib import Path

from authorization_kit import IssuerKey, authorization_material, run_authorization, write_json

from loquitur.verify.trust_registry import verify_registry_entry_trust

NOT_EVALUATED = "ROOT_SIGNATURE_NOT_EVALUATED"
NOTE = "trust_registry_root_signature_not_verified:root_signature_not_evaluated"


def _summary(result) -> dict:
    return {
        "authorization_status": result.authorization_status,
        "root_signature_status": result.root_signature_status,
        "note": NOTE in result.notes,
    }


def test_every_authorization_path_that_stops_before_root_authentication_reports_it_not_evaluated(
    tmp_path: Path,
) -> None:
    key = IssuerKey()
    entry, registry = authorization_material(key)
    got, expected = {}, {}

    def invalid_entry(e: dict) -> None:
        e["object_type"] = "not_a_registry_entry"

    rows = {
        "entry-contract": (authorization_material(key, entry=invalid_entry), "INVALID_REGISTRY_ENTRY"),
        "trust-registry-contract": (
            authorization_material(key, trust=lambda t: t.pop("entries")),
            "INVALID_TRUST_REGISTRY",
        ),
        "trust-registry-coherence": (
            authorization_material(key, trust=lambda t: t["entries"][0].update(status="revoked")),
            "INVALID_TRUST_REGISTRY",
        ),
        "trust-registry-calendar": (
            authorization_material(key, trust=lambda t: t.update(issued_at="2026-02-30T12:00:00Z")),
            "INVALID_TRUST_REGISTRY",
        ),
        "authorization": (
            authorization_material(key, trust=lambda t: t["entries"][0].update(status="suspended")),
            "ISSUER_KEY_SUSPENDED",
        ),
    }
    for label, ((document, trust), auth) in rows.items():
        path = write_json(tmp_path / label / "trust.json", trust)
        got[label] = _summary(verify_registry_entry_trust(document, trust_registry_path=path))
        expected[label] = {"authorization_status": auth, "root_signature_status": NOT_EVALUATED, "note": True}

    for label, raw in (("trust-registry-not-json", b"{not json"), ("trust-registry-not-an-object", b"[]")):
        path = tmp_path / label / "trust.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        got[label] = _summary(verify_registry_entry_trust(entry, trust_registry_path=path))
        expected[label] = {
            "authorization_status": "INVALID_TRUST_REGISTRY",
            "root_signature_status": NOT_EVALUATED,
            "note": True,
        }

    # In the report of a bundle verification too.
    report = run_authorization(tmp_path / "report", entry, dict(registry, issued_at="2026-12-01T00:00:00Z"))
    got["report"] = report["trust_registry"]["trust_registry_root_signature_status"]
    expected["report"] = NOT_EVALUATED
    assert got == expected
