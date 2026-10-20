"""Cross-repo canonicalization equivalence and signature interop tests.

``loquitur-schemas`` implements a restricted sorted-key minimal-JSON profile
for the registry-entry signing surface; ``loquitur-verify`` implements
RFC 8785 (JCS). For the registry-entry object family the two profiles must be
**byte-identical**, otherwise a signature produced on one side can fail
verification on the other. These tests pin that invariant explicitly instead
of leaving it implicit in shared fixtures, and additionally prove live
cross-implementation interop: an entry signed over the message
``loquitur-schemas`` builds, with a key made for the run (``cryptography``),
must verify under this package's verifier, through the public authorization API.

Skipped when ``loquitur-schemas`` is not installed: it is an optional
extra of this package, never a core dependency. Failed instead when
LOQUITUR_REQUIRE_SIBLINGS is set, where its absence is a broken workspace.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from authorization_kit import IssuerKey
from siblings import import_sibling

schemas = import_sibling("loquitur.schemas", "canonical equivalence needs loquitur-schemas")

from loquitur.schemas import (  # noqa: E402
    SIGNING_PAYLOAD_EXCLUDED_FIELDS as SCHEMAS_EXCLUDED_FIELDS,
)
from loquitur.schemas import (
    canonical_json_bytes as schemas_canonical_json_bytes,
)
from loquitur.schemas import (
    canonicalize_registry_entry_signing_payload,
)
from loquitur.schemas.registry_signing import (  # noqa: E402
    SIGNATURE_ALGORITHM as SCHEMAS_SIGNATURE_ALGORITHM,
)
from loquitur.schemas.registry_signing import (
    SIGNING_PAYLOAD_ID as SCHEMAS_SIGNING_PAYLOAD_ID,
)
from loquitur.schemas.registry_signing import (
    SIGNING_PAYLOAD_VERSION as SCHEMAS_SIGNING_PAYLOAD_VERSION,
)

from loquitur.verify.canonical import CanonicalizationError, canonical_json_bytes  # noqa: E402
from loquitur.verify.signing_envelope import (  # noqa: E402
    SIGNATURE_ALGORITHM,
    SIGNING_PAYLOAD_EXCLUDED_FIELDS,
    signing_message_bytes,
)
from loquitur.verify.trust_registry import (  # noqa: E402
    AUTH_STATUS_VALID,
    SIGNING_PAYLOAD_ID,
    verify_registry_entry_trust,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _reorder_keys_recursively(value):
    """Rebuild mappings with reversed key insertion order (lists preserved)."""
    if isinstance(value, dict):
        return {key: _reorder_keys_recursively(value[key]) for key in reversed(list(value.keys()))}
    if isinstance(value, list):
        return [_reorder_keys_recursively(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Constant parity: a rename or semantic change on either side must fail here.
# ---------------------------------------------------------------------------
def test_signing_surface_constants_match_across_packages() -> None:
    assert SIGNING_PAYLOAD_ID == SCHEMAS_SIGNING_PAYLOAD_ID
    assert SIGNATURE_ALGORITHM == SCHEMAS_SIGNATURE_ALGORITHM
    assert frozenset(SIGNING_PAYLOAD_EXCLUDED_FIELDS) == frozenset(SCHEMAS_EXCLUDED_FIELDS)


# ---------------------------------------------------------------------------
# Canonical byte equality on the registry-entry object family.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "fixture_name",
    ["link_valid_registry_entry.json", "authorization_valid_registry_entry.json"],
)
def test_signing_payload_bytes_are_identical_across_packages(fixture_name: str) -> None:
    entry = _load(fixture_name)
    assert canonicalize_registry_entry_signing_payload(entry) == signing_message_bytes(entry)


@pytest.mark.parametrize(
    "fixture_name",
    ["link_valid_registry_entry.json", "authorization_valid_registry_entry.json"],
)
def test_canonical_bytes_are_key_order_independent_and_equal(fixture_name: str) -> None:
    entry = _load(fixture_name)
    reordered = _reorder_keys_recursively(entry)
    expected = canonical_json_bytes(entry)
    assert canonical_json_bytes(reordered) == expected
    assert schemas_canonical_json_bytes(entry) == expected
    assert schemas_canonical_json_bytes(reordered) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"plain": "ascii", "nested": {"b": "x", "a": "y"}, "list": ["one", "two"]},
        {"unicode": "città — perché ✓ 日本語", "mixed": ["é", "ü", "ß"]},
        {"escapes": 'quote " backslash \\ newline \n tab \t', "control": "\u0001\u001f"},
        {"empty": "", "empty_obj": {}, "empty_list": [], "null": None, "bool": True},
        {"small_ints": [0, 1, -1, 9007199254740991, -9007199254740991]},
    ],
)
def test_canonical_profiles_agree_on_protocol_value_space(payload: dict) -> None:
    assert schemas_canonical_json_bytes(payload) == canonical_json_bytes(payload)


def test_js_unsafe_integers_fail_closed_in_both_packages() -> None:
    """Both packages share the RFC 8785 (JCS) profile and converge here.

    An integer beyond the JavaScript safe range is rejected identically by both: a
    profile that serialized it while the other failed closed would be a
    cross-implementation divergence. This test pins the convergence so the profiles
    cannot drift apart.
    """
    from loquitur.schemas.canonical import (  # noqa: E402
        RegistryCanonicalizationError as SchemasCanonicalizationError,
    )

    payload = {"n": 2**53}
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes(payload)
    with pytest.raises(SchemasCanonicalizationError):
        schemas_canonical_json_bytes(payload)


def _nested_list(depth: int) -> object:
    value: object = 0
    for _ in range(depth):
        value = [value]
    return value


def test_both_canonicalisers_refuse_the_same_unencodable_or_unbounded_input() -> None:
    """The two ``_prepare_for_jcs`` copies are a drift pair: what one refuses, the other refuses.

    A lone surrogate in a member name or a string value has no UTF-8 encoding, and a value
    nested past the interpreter's recursion limit cannot be walked. Each package must refuse
    such input with its own canonicalization error, never let UnicodeEncodeError or
    RecursionError escape, and never serialize it: an escape from loquitur-verify ends a
    verifier run in exit 3. This test holds the two copies to the same answer, so neither can
    drift from the other unnoticed.
    """
    from loquitur.schemas.canonical import (  # noqa: E402
        RegistryCanonicalizationError as SchemasCanonicalizationError,
    )

    rows = {
        "lone-surrogate-key": {"\udc00x": 1},
        "lone-surrogate-value": {"k": "x\ud800"},
        "lone-surrogate-nested-key": {"outer": [{"\ud800": True}]},
        "nesting-beyond-the-recursion-limit": {"deep": _nested_list(100_000)},
        # One level past input strictness rule 6: both refuse it by the protocol's bound, not
        # where the interpreter's recursion stops, which moves with the Python version.
        "nesting-one-level-past-rule-6": {"deep": _nested_list(64)},
    }
    outcomes: dict[str, tuple[str, str]] = {}
    for name, payload in rows.items():
        seen = []
        for canonicalise in (canonical_json_bytes, schemas_canonical_json_bytes):
            try:
                canonicalise(payload)
            except (CanonicalizationError, SchemasCanonicalizationError) as exc:
                seen.append(type(exc).__name__)
            except Exception as exc:  # noqa: BLE001 - the escape itself is what this row detects
                seen.append(f"escaped {type(exc).__name__}")
            else:
                seen.append("serialized")
        outcomes[name] = (seen[0], seen[1])
    expected = ("CanonicalizationError", "RegistryCanonicalizationError")
    assert outcomes == {name: expected for name in rows}


# ---------------------------------------------------------------------------
# Live interop: an entry signed over the message loquitur-schemas builds, with a
# key made for the run, is accepted by verify through the public authorization API.
# ---------------------------------------------------------------------------
def _signed_entry_and_trust_registry(tmp_path: Path) -> tuple[dict, Path]:
    key_id = "ephemeral-interop-key"
    key = IssuerKey()
    public_key_hex = key.public_key_hex

    entry = copy.deepcopy(_load("authorization_valid_registry_entry.json"))
    entry.pop("signature", None)
    entry["issuer_key_id"] = key_id
    message = canonicalize_registry_entry_signing_payload(entry)
    signed = dict(entry)
    signed["signature"] = {
        "algorithm": SCHEMAS_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "payload_id": SCHEMAS_SIGNING_PAYLOAD_ID,
        "payload_version": SCHEMAS_SIGNING_PAYLOAD_VERSION,
        "signature": key.sign_digest(hashlib.sha256(message).digest()),
    }

    trust_registry = copy.deepcopy(_load("authorization_valid_trust_registry.json"))
    trust_registry["entries"][0]["issuer_key_id"] = key_id
    trust_registry["entries"][0]["public_key_hex"] = public_key_hex
    trust_path = tmp_path / "ephemeral_trust_registry.json"
    trust_path.write_text(json.dumps(trust_registry), encoding="utf-8")
    return signed, trust_path


def test_an_entry_signed_over_the_schemas_message_verifies(tmp_path: Path) -> None:
    signed, trust_path = _signed_entry_and_trust_registry(tmp_path)
    result = verify_registry_entry_trust(signed, trust_registry_path=trust_path)
    assert result.error is None
    assert result.authorization_status == AUTH_STATUS_VALID
    assert result.authorization_holds


def test_tampered_field_after_signing_fails_verification(tmp_path: Path) -> None:
    signed, trust_path = _signed_entry_and_trust_registry(tmp_path)
    tampered = dict(signed)
    tampered["verdict"] = "FAIL" if signed.get("verdict") != "FAIL" else "PASS"
    result = verify_registry_entry_trust(tampered, trust_registry_path=trust_path)
    assert not result.authorization_holds
