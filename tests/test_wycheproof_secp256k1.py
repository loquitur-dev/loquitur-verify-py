"""Wycheproof known-answer vectors for the secp256k1 verifier.

Locks ``secp256k1.verify_digest`` against the adversarially
crafted edge cases that random fuzzing does not reach: boundary/malformed
``r``/``s`` values, arithmetic special cases (Shamir multiplication edges,
special-case hashes, modular-inverse edges), edge-case public keys, point
duplication, and signature malleability.

Source: Wycheproof project (C2SP/wycheproof), file
``testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json`` (retrieved
2026-07-02). The P1363 file is the correct variant for this verifier: raw
``r || s`` compact signatures, exactly the format this implementation parses.
(The "bitcoin" variant uses DER-encoded signatures and is therefore
inapplicable here.)

Semantics mapping: this verifier REQUIRES low-S (malleability rejected), which
is stricter than plain ECDSA. Wycheproof P1363 marks mathematically-valid
high-S signatures as ``valid``; under this verifier's contract those MUST be
rejected. The expectation is therefore:

    expected ACCEPT  <=>  result == "valid" AND 0 < s <= n/2
    everything else  =>   expected REJECT

The vector file is integrity-pinned: the suite fails if the bundled JSON does
not match the recorded SHA-256, so the assurance baseline cannot drift
silently.
"""

from __future__ import annotations

import hashlib
import json
import re

from repository import WYCHEPROOF_FILE, require_repository_file
from spec_tables import document, sections, table

from loquitur.verify.secp256k1 import SECP256K1_N, verify_digest

_VECTORS_SHA256 = "7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2"

# Corpus floors: a truncated or substituted vector file must fail loudly.
_MIN_TOTAL = 250
_MIN_VALID_LOW_S = 90
_MIN_VALID_HIGH_S = 70
_MIN_INVALID = 80


def _load_vectors() -> dict:
    data = require_repository_file(WYCHEPROOF_FILE, "it is under the Apache License 2.0 only (NOTICE)").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == _VECTORS_SHA256, (
        f"Wycheproof vector file integrity mismatch: sha256={digest}, "
        f"expected {_VECTORS_SHA256}. Do not silently swap the assurance corpus."
    )
    return json.loads(data)


def _is_low_s(sig_hex: str) -> bool:
    if len(sig_hex) != 128:
        return False
    try:
        s = int(sig_hex[64:], 16)
    except ValueError:
        return False
    return 0 < s <= SECP256K1_N // 2


def test_wycheproof_p1363_corpus_locks_the_secp256k1_verifier() -> None:
    data = _load_vectors()
    totals = {"valid_low_s": 0, "valid_high_s": 0, "invalid": 0, "acceptable": 0}
    failures: list[tuple[int, str, str]] = []

    for group in data["testGroups"]:
        key = group.get("key") or group.get("publicKey")
        public_key_hex = key["uncompressed"]
        for case in group["tests"]:
            result = case["result"]
            sig_hex = case["sig"]
            digest = hashlib.sha256(bytes.fromhex(case["msg"])).digest()

            if result == "valid":
                if _is_low_s(sig_hex):
                    totals["valid_low_s"] += 1
                    expect_accept = True
                else:
                    totals["valid_high_s"] += 1
                    expect_accept = False  # stricter-than-ECDSA low-S contract
            elif result == "invalid":
                totals["invalid"] += 1
                expect_accept = False
            else:  # "acceptable": no deterministic expectation; counted only
                totals["acceptable"] += 1
                continue

            got = verify_digest(digest, sig_hex, public_key_hex)
            if got is not expect_accept:
                failures.append(
                    (
                        case["tcId"],
                        f"expected {'ACCEPT' if expect_accept else 'REJECT'}, got {got}",
                        case.get("comment", ""),
                    )
                )

    assert not failures, f"{len(failures)} Wycheproof mismatches (first 10): " + "; ".join(
        f"tcId={t} {w} [{c[:60]}]" for t, w, c in failures[:10]
    )
    total = sum(totals.values())
    assert total >= _MIN_TOTAL, f"corpus too small: {totals}"
    assert totals["valid_low_s"] >= _MIN_VALID_LOW_S, totals
    assert totals["valid_high_s"] >= _MIN_VALID_HIGH_S, totals
    assert totals["invalid"] >= _MIN_INVALID, totals


# ---------------------------------------------------------------- the count the threat model states

THREAT_MODEL_ROW = "secp256k1 verifier"
OBSERVATIONS = "11. How the claims here were verified"
CORPUS_CELL = re.compile(r"^(?P<count>[0-9]+) Wycheproof P1363 vectors$")


def _compared() -> int:
    """The vectors this module compares: every case with a deterministic expectation."""
    return sum(
        1
        for group in _load_vectors()["testGroups"]
        for case in group["tests"]
        if case["result"] in {"valid", "invalid"}
    )


def test_the_threat_models_count_of_this_corpus_is_the_corpus_this_module_runs() -> None:
    """`threat-model.md` §11 counts this corpus, and a count written by hand goes stale silently.

    The protocol document states how much was run; this is where the running happens, so this
    is where the number is held. A corpus swapped for a smaller one, or a row that claims more
    vectors than the file carries, fails here rather than standing as prose. The floors above
    keep the corpus from shrinking; this keeps the document from overstating it.
    """
    rows = table(sections(document("threat-model.md"))[OBSERVATIONS], ["Claim", "How it was observed", "Result"])
    found = [row for row in rows if row["Claim"] == THREAT_MODEL_ROW]
    assert len(found) == 1, f"§11 names {len(found)} rows {THREAT_MODEL_ROW!r}"
    match = CORPUS_CELL.fullmatch(found[0]["How it was observed"])
    assert match, f"§11 does not count this corpus: {found[0]['How it was observed']!r}"
    assert int(match.group("count")) == _compared(), found[0]
    assert found[0]["Result"] == "all pass", found[0]
