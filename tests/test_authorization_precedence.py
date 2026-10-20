"""When several authorization conditions hold, the reader must be told the worst.

The verifier returns one `authorization_status`, so the order in which it checks
determines what a reader is told. Evaluating the trust registry's own validity window
BEFORE the issuer key is looked up would tell a counterparty holding a stale copy of the
trust registry "trust registry is expired", and it would never learn that the key which
signed the record had been REVOKED: the containment control applied after a suspected
compromise.

Only an input where two conditions hold at once tells the two orders apart, so the tests
here construct such inputs.

Revocation is reported first because it is monotone in the direction that matters: a key
marked revoked in an old copy of the registry WAS revoked at that time. Reporting the
staleness instead loses information a reader needs, and gains nothing: the staleness is
still reported when the key is otherwise fine.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loquitur.verify.runner import verify_path
from loquitur.verify.trust_registry import verify_registry_entry_trust

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _registry(**overrides) -> dict:
    """The valid trust registry, mutated to make several conditions hold together."""
    registry = json.loads((FIXTURES / "authorization_valid_trust_registry.json").read_text(encoding="utf-8"))
    entry_overrides = overrides.pop("entry", {})
    registry.update(overrides)
    registry["entries"][0].update(entry_overrides)
    return registry


def _authorize(tmp_path: Path, registry: dict):
    path = tmp_path / "trust_registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    entry = json.loads((FIXTURES / "authorization_valid_registry_entry.json").read_text(encoding="utf-8"))
    # Judged at the operator's evaluation time: the registry windows (rows 9 and 10) are evaluated
    # only when one is supplied (trust-registry-authorization.md section 2).
    return verify_registry_entry_trust(entry, trust_registry_path=path, evaluation_time="2026-05-10T00:00:00Z")


def test_a_revoked_key_is_reported_even_when_the_registry_copy_is_stale(tmp_path: Path) -> None:
    """Both conditions true: the compromise signal wins over the stale copy."""
    result = _authorize(
        tmp_path,
        _registry(
            expires_at="2026-05-01T00:00:00Z",  # registry stale at the evaluation time
            entry={"status": "revoked", "revoked_at": "2026-05-01T00:00:00Z"},  # and the key was revoked
        ),
    )
    assert result.authorization_holds is False
    assert result.authorization_status == "ISSUER_KEY_REVOKED", (
        "a stale registry copy must not hide a revocation: the reader would treat a "
        "probable key compromise as a housekeeping problem with their own trust material"
    )


def test_a_suspended_key_is_also_reported_over_a_stale_registry(tmp_path: Path) -> None:
    result = _authorize(
        tmp_path,
        _registry(
            expires_at="2026-05-01T00:00:00Z",
            entry={"status": "suspended"},
        ),
    )
    assert result.authorization_status == "ISSUER_KEY_SUSPENDED"


def test_revocation_is_reported_over_suspension(tmp_path: Path) -> None:
    """Both are terminal; only one means a key is believed compromised.

    A registry carrying both is malformed, but the verifier must still pick, and picking
    the reversible hold over the compromise signal is the wrong way round.
    """
    result = _authorize(tmp_path, _registry(entry={"status": "revoked", "revoked_at": "2026-05-01T00:00:00Z"}))
    assert result.authorization_status == "ISSUER_KEY_REVOKED"


def test_a_stale_registry_is_still_reported_when_the_key_is_fine(tmp_path: Path) -> None:
    """The other direction: the registry's validity window is checked after the key's status,
    and is still checked when the key is fine.

    A deferred check that never ran would turn a genuine trust-material problem into a pass.
    """
    result = _authorize(tmp_path, _registry(expires_at="2026-05-01T00:00:00Z"))
    assert result.authorization_holds is False
    assert result.authorization_status == "TRUST_REGISTRY_EXPIRED"


def test_a_not_yet_effective_registry_is_still_reported(tmp_path: Path) -> None:
    # Later than the evaluation time (2026-05-10) and not later than expires_at: a registry
    # that takes effect after it expires is malformed, not merely not yet effective.
    result = _authorize(tmp_path, _registry(effective_at="2026-05-20T00:00:00Z"))
    assert result.authorization_status == "TRUST_REGISTRY_NOT_YET_EFFECTIVE"


def test_an_unaffected_valid_registry_still_authorizes(tmp_path: Path) -> None:
    """Anti-vacuity: the fixture mutation helper must produce something that passes."""
    result = _authorize(tmp_path, _registry())
    assert result.authorization_status == "AUTHORIZED_ACTIVE_KEY"


def test_the_narrative_names_the_revocation_not_the_staleness(tmp_path: Path) -> None:
    """The point of the ordering, expressed where a human reads it."""
    from loquitur.verify.narrative import infer_active_reason_codes

    registry = _registry(
        expires_at="2026-05-01T00:00:00Z", entry={"status": "revoked", "revoked_at": "2026-05-01T00:00:00Z"}
    )
    path = tmp_path / "trust_registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    report = verify_path(
        FIXTURES / "link_valid_bundle",
        registry_entry_path=FIXTURES / "authorization_valid_registry_entry.json",
        trust_registry_path=path,
    )
    codes = infer_active_reason_codes(report)
    assert "AUTHORIZATION_ISSUER_KEY_REVOKED" in codes
    assert "AUTHORIZATION_TRUST_MATERIAL_OUTSIDE_VALIDITY_WINDOW" not in codes


@pytest.mark.parametrize("status", ["revoked", "suspended"])
def test_terminal_key_status_beats_a_scope_mismatch(tmp_path: Path, status: str) -> None:
    """Scope is about what a key may do; status is about whether it may do anything."""
    result = _authorize(
        tmp_path,
        _registry(
            entry={
                "status": status,
                "revoked_at": "2026-05-01T00:00:00Z" if status == "revoked" else None,
                "allowed_asset_types": ["fund_nav"],
            },
        ),
    )
    assert result.authorization_status == f"ISSUER_KEY_{status.upper()}"
