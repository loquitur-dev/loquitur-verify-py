"""Properties of the two signing messages, over generated documents.

The registry-entry message is ``signing_envelope.signing_message_bytes`` and the trust-registry
root message ``trust_root.trust_registry_signing_bytes``, the functions the verifier hashes when
it checks a signature. The prefixes are written here from the specification text
(signing-envelope-v2.md section 1, trust-root.md section 4), not imported from the code under
test. These properties are the maintainer's own testing, not an audit.
"""

from __future__ import annotations

import copy
from typing import Any

import property_profile  # noqa: F401  (loads the fixed profile before any test is defined)
from hypothesis import assume, given
from hypothesis import strategies as st
from property_strategies import json_objects, json_values, texts

from loquitur.verify.canonical import canonical_json_bytes
from loquitur.verify.signing_envelope import signing_message_bytes
from loquitur.verify.trust_root import trust_registry_signing_bytes

ENTRY_PREFIX = b"LOQUITUR\x00REGISTRY_ENTRY\x00SIGNATURE\x00V2\x00"
ROOT_PREFIX = b"LOQUITUR\x00TRUST_REGISTRY\x00ROOT_SIGNATURE\x00V1\x00"

ENTRY_EXCLUDED = ("signature", "anchor", "anchored_at")

# Member names drawn at random, and names that differ from an excluded one by letter case,
# padding or one character: the exclusion is by exact name.
names = st.one_of(
    texts,
    st.sampled_from(
        [
            "Signature",
            "SIGNATURE",
            "Anchor",
            "anchored_At",
            " signature",
            "signature ",
            "anchor\u0000",
            "anchored",
            "sig",
        ]
    ),
)


def _differs(left: Any, right: Any) -> bool:
    """Two JSON values that are different values, as the canonical form tells (1 and 1.0 are one)."""
    return canonical_json_bytes(left) != canonical_json_bytes(right)


def test_the_two_prefixes_are_distinct_and_neither_begins_the_other() -> None:
    """Domain separation of the two messages: no prefix is, or begins, the other.

    A registry-entry message can therefore never be read as a trust-registry message, whatever
    follows either prefix (signing-envelope-v2.md section 2).
    """
    assert len(ENTRY_PREFIX) == 37
    assert ENTRY_PREFIX != ROOT_PREFIX
    assert not ENTRY_PREFIX.startswith(ROOT_PREFIX) and not ROOT_PREFIX.startswith(ENTRY_PREFIX)


@given(json_objects)
def test_each_message_starts_with_its_own_prefix(document: dict[str, Any]) -> None:
    """Built over any JSON object, each message begins with its prefix and the two never coincide."""
    entry = signing_message_bytes(document)
    root = trust_registry_signing_bytes(document)
    assert entry.startswith(ENTRY_PREFIX) and not entry.startswith(ROOT_PREFIX)
    assert root.startswith(ROOT_PREFIX) and not root.startswith(ENTRY_PREFIX)
    assert entry != root


@given(json_objects, st.sampled_from(ENTRY_EXCLUDED), st.one_of(st.none(), json_values))
def test_the_entry_message_ignores_signature_anchor_and_anchored_at(
    entry: dict[str, Any], excluded: str, replacement: Any
) -> None:
    """Adding, changing or removing ``signature``, ``anchor`` or ``anchored_at`` leaves the entry message as it is.

    ``None`` stands for removal. Shows that the signature does not cover the members the
    specification leaves out of the payload: an anchor can be recorded after signing.
    """
    before = signing_message_bytes(entry)
    changed = copy.deepcopy(entry)
    if replacement is None:
        changed.pop(excluded, None)
    else:
        changed[excluded] = replacement
    assert signing_message_bytes(changed) == before


@given(json_objects, names, json_values)
def test_the_entry_message_changes_with_every_other_member(entry: dict[str, Any], name: str, value: Any) -> None:
    """Adding, changing or removing any member other than the three changes the entry message."""
    assume(name not in ENTRY_EXCLUDED)
    before = signing_message_bytes(entry)
    if name in entry:
        removed = copy.deepcopy(entry)
        del removed[name]
        assert signing_message_bytes(removed) != before
        assume(_differs(entry[name], value))
    changed = copy.deepcopy(entry)
    changed[name] = value
    assert signing_message_bytes(changed) != before


@given(json_objects, json_values)
def test_the_root_message_ignores_signature(registry: dict[str, Any], replacement: Any) -> None:
    """Adding, changing or removing ``signature`` leaves the trust-registry root message as it is."""
    before = trust_registry_signing_bytes(registry)
    changed = copy.deepcopy(registry)
    changed["signature"] = replacement
    assert trust_registry_signing_bytes(changed) == before
    changed.pop("signature")
    assert trust_registry_signing_bytes(changed) == before


@given(json_objects, names, json_values)
def test_the_root_message_changes_with_every_member_but_signature(
    registry: dict[str, Any], name: str, value: Any
) -> None:
    """Adding, changing or removing any member but ``signature`` changes the root message.

    ``anchor`` and ``anchored_at`` are ordinary members here: only the entry message leaves them out.
    """
    assume(name != "signature")
    before = trust_registry_signing_bytes(registry)
    if name in registry:
        removed = copy.deepcopy(registry)
        del removed[name]
        assert trust_registry_signing_bytes(removed) != before
        assume(_differs(registry[name], value))
    changed = copy.deepcopy(registry)
    changed[name] = value
    assert trust_registry_signing_bytes(changed) != before


@given(json_objects, st.sampled_from(["anchor", "anchored_at"]), json_values)
def test_anchor_members_are_covered_by_the_root_message(registry: dict[str, Any], name: str, value: Any) -> None:
    """The two members the entry message leaves out are signed when they sit in a trust registry."""
    assume(name not in registry)
    changed = copy.deepcopy(registry)
    changed[name] = value
    assert trust_registry_signing_bytes(changed) != trust_registry_signing_bytes(registry)
