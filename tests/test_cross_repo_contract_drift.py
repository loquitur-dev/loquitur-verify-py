"""Cross-repo contract-drift guard.

The protocol's central promise is that every implementation agrees. That promise
survives the first release only if it survives every *later* change too. This test is
the mechanism: it extracts each shared contract constant from the CANONICAL source
(the JSON Schemas in loquitur-schemas) and asserts that the hand-mirrored copies in
loquitur-verify (which is deliberately standalone and cannot import schemas at
runtime) and in the TypeScript verifier, loquitur-verify-ts, have not drifted.

If someone adds a field to registry_entry.schema.json but forgets the verifier's
allowlist, or bumps a supported version in one place only, this test fails loudly in
CI, before the two verifiers silently disagree.

The test locates sibling repos relative to this file; it is skipped (not failed) when
a repo is absent, so the base matrix stays green in isolation, and failed when
LOQUITUR_REQUIRE_SIBLINGS is set, where an absent repo is a broken workspace.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from siblings import absent, needs

# ---------------------------------------------------------------- repo locations

_HERE = Path(__file__).resolve()
_VERIFY_ROOT = _HERE.parents[1]
_REPOS_ROOT = _VERIFY_ROOT.parent


def _first_existing(*candidates: Path) -> Path | None:
    for c in candidates:
        if c.exists():
            return c
    return None


_SCHEMAS_DATA = _first_existing(
    _REPOS_ROOT / "loquitur-schemas" / "src" / "loquitur" / "schemas" / "data",
    _VERIFY_ROOT.parent / "loquitur-schemas" / "src" / "loquitur" / "schemas" / "data",
)
_VERIFY_SRC = _VERIFY_ROOT / "src" / "loquitur" / "verify"
_TS_CORE = _first_existing(_REPOS_ROOT / "loquitur-verify-ts" / "src" / "verify-core.ts")
_TS_SIG = _first_existing(_REPOS_ROOT / "loquitur-verify-ts" / "src" / "signature.ts")
# The registry entry's closed field set lives in the parser (protocol-input.ts), which is the one
# place the TypeScript verifier holds it; verify-core.ts does not restate it.
_TS_INPUT = _first_existing(_REPOS_ROOT / "loquitur-verify-ts" / "src" / "protocol-input.ts")

_need_schemas = needs(_SCHEMAS_DATA is not None, "loquitur-schemas sibling not present")
_need_ts = needs(_TS_CORE is not None, "loquitur-verify-ts sibling not present")


# ---------------------------------------------------------------- extractors


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS_DATA / f"{name}.schema.json").read_text(encoding="utf-8"))


def _py_frozenset(path: Path, const: str) -> set[str]:
    txt = path.read_text(encoding="utf-8")
    # \s* around the brace: the formatter may put frozenset( and { on separate lines, and a
    # drift guard must assert on the SET OF NAMES, not on where the formatter placed them.
    m = re.search(rf"{const} = frozenset\(\s*\{{([^}}]+)\}}\s*\)", txt, re.S)
    assert m, f"{const} not found in {path.name}"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def _ts_set(const: str, path: Path | None = None) -> set[str]:
    source = _TS_CORE if path is None else path
    txt = source.read_text(encoding="utf-8")
    m = re.search(rf"{const} = new Set\(\[([^\]]+)\]", txt, re.S)
    assert m, f"{const} not found in {source.name}"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def _ts_const(path: Path, const: str) -> str:
    txt = path.read_text(encoding="utf-8")
    m = re.search(rf'{const}\s*=\s*"([^"]+)"', txt)
    assert m, f"{const} not found in {path.name}"
    return m.group(1)


def _ts_number(const: str) -> int:
    txt = _TS_CORE.read_text(encoding="utf-8")
    m = re.search(rf"{const}\s*=\s*(\d+)", txt)
    assert m, f"{const} not found in verify-core.ts"
    return int(m.group(1))


# ---------------------------------------------------------------- registry_entry fields


@_need_schemas
def test_registry_entry_contract_in_verify_is_the_closed_schema():
    """The authorization check reads the entry's member set from the generated contract alone."""
    from loquitur.verify.schema_contract import SCHEMA_CONTRACTS

    schema = _schema("registry_entry")
    contract = SCHEMA_CONTRACTS["registry_entry"]
    assert schema.get("additionalProperties") is False
    assert contract.get("additionalProperties") is False, "the generated registry_entry contract is not closed"
    assert set(contract["properties"]) == set(schema["properties"]), (
        "the generated registry_entry contract names other members than registry_entry.schema.json"
    )


@_need_schemas
@_need_ts
def test_registry_entry_allowlist_matches_schema_in_verify_ts():
    schema_fields = set(_schema("registry_entry")["properties"].keys())
    ts_fields = _ts_set("REGISTRY_FIELDS", _TS_INPUT)
    assert ts_fields == schema_fields, (
        f"loquitur-verify-ts's REGISTRY_FIELDS drifted from registry_entry.schema.json; "
        f"schema-only={sorted(schema_fields - ts_fields)} ts-only={sorted(ts_fields - schema_fields)}"
    )


# ---------------------------------------------------------------- shared allowlists (verify <-> verify-ts)


@_need_ts
@pytest.mark.parametrize(
    ("py_file", "const"),
    [
        ("envelope.py", "ENVELOPE_ALLOWED_FIELDS"),
        ("manifest.py", "MANIFEST_ALLOWED_FIELDS"),
        ("p1.py", "P1_ALLOWED_FIELDS"),
    ],
)
def test_shared_allowlists_match_between_verify_and_verify_ts(py_file: str, const: str):
    py = _py_frozenset(_VERIFY_SRC / py_file, const)
    ts = _ts_set(const)
    assert py == ts, (
        f"{const} drifted between verify and verify-ts: verify-only={sorted(py - ts)} ts-only={sorted(ts - py)}"
    )


# ---------------------------------------------------------------- signature algorithm


@_need_ts
def test_signature_algorithm_matches_everywhere():
    verify_txt = (_VERIFY_SRC / "signing_envelope.py").read_text(encoding="utf-8")
    m = re.search(r'SIGNATURE_ALGORITHM = "([^"]+)"', verify_txt)
    assert m, "SIGNATURE_ALGORITHM not found in verify signing envelope"
    verify_alg = m.group(1)
    ts_alg = _ts_const(_TS_SIG, "SIGNATURE_ALGORITHM")
    assert verify_alg == ts_alg == "secp256k1_ecdsa_sha256", (
        f"signature algorithm drift: verify={verify_alg!r} verify-ts={ts_alg!r}"
    )
    # and the schema must admit it: the entry names any well-formed algorithm identifier, and the
    # verifier's allowlist decides (canonicalization-and-hashing.md section 4).
    if _SCHEMAS_DATA is not None:
        patterns = _algorithm_patterns(_schema("registry_entry")["properties"]["signature"])
        assert len(patterns) == 1, patterns
        assert re.fullmatch(patterns[0].removeprefix("^").removesuffix("$"), verify_alg), (verify_alg, patterns)


def _algorithm_patterns(signature_schema: dict) -> list[str]:
    """The pattern the signature object's ``algorithm`` carries, in every branch that has one."""
    branches = signature_schema.get("oneOf", [signature_schema])
    return sorted(
        {
            branch["properties"]["algorithm"]["pattern"]
            for branch in branches
            if isinstance(branch, dict) and "algorithm" in branch.get("properties", {})
        }
    )


@_need_ts
def test_signing_envelope_v2_constants_match_python_and_typescript() -> None:
    from loquitur.verify.signing_envelope import (
        SIGNING_DOMAIN_PREFIX,
        SIGNING_ENVELOPE_DOMAIN,
        SIGNING_ENVELOPE_SCHEMA,
        SIGNING_PAYLOAD_ID,
        SIGNING_PAYLOAD_SCHEMA,
        SIGNING_PAYLOAD_VERSION,
    )

    assert _ts_const(_TS_SIG, "SIGNING_PAYLOAD_ID") == SIGNING_PAYLOAD_ID
    assert _ts_number_from_file(_TS_SIG, "SIGNING_PAYLOAD_VERSION") == SIGNING_PAYLOAD_VERSION
    assert _ts_const(_TS_SIG, "SIGNING_ENVELOPE_DOMAIN") == SIGNING_ENVELOPE_DOMAIN
    assert _ts_const(_TS_SIG, "SIGNING_ENVELOPE_SCHEMA") == SIGNING_ENVELOPE_SCHEMA
    assert _ts_const(_TS_SIG, "SIGNING_PAYLOAD_SCHEMA") == SIGNING_PAYLOAD_SCHEMA
    ts_text = _TS_SIG.read_text(encoding="utf-8")
    # loquitur-verify-ts derives the prefix from its NUL-delimited segments, so the segments
    # are what must agree: a wrong byte in a literal byte array is never a TypeScript compile
    # error, and reading it back one integer at a time would only confirm the typo faithfully.
    segments = re.search(r"SIGNING_DOMAIN_SEGMENTS = \[([^\]]+)\]", ts_text, re.S)
    assert segments, "SIGNING_DOMAIN_SEGMENTS not found in the loquitur-verify-ts signature module"
    names = re.findall(r'"([^"]+)"', segments.group(1))
    assert names, "no domain segments parsed; the comparison would be vacuous"
    ts_prefix = b"".join(name.encode("ascii") + b"\x00" for name in names)
    assert ts_prefix == SIGNING_DOMAIN_PREFIX


def _ts_number_from_file(path: Path, const: str) -> int:
    txt = path.read_text(encoding="utf-8")
    match = re.search(rf"{const}\s*=\s*(\d+)", txt)
    assert match, f"{const} not found in {path.name}"
    return int(match.group(1))


# ---------------------------------------------------------------- exit-code taxonomy


@_need_ts
def test_exit_code_taxonomy_matches_between_verify_and_verify_ts():
    # canonical source: verify/runner.py
    runner = (_VERIFY_SRC / "runner.py").read_text(encoding="utf-8")
    verify_codes = {name: int(val) for name, val in re.findall(r"(EXIT_[A-Z_]+)\s*=\s*(\d+)", runner)}
    # The six exit codes a report carries (report-contract.md section 3). The usage error, exit 64,
    # is a command line's refusal before any report exists; loquitur-verify-ts is a library with no
    # command line and declares no constant for it.
    for name in (
        "EXIT_OFFLINE_OK",
        "EXIT_OFFLINE_FAIL",
        "EXIT_OFFLINE_REVIEW",
        "EXIT_INTERNAL_ERROR",
        "EXIT_UNSUPPORTED_VERSION",
        "EXIT_HOST_FAILURE",
    ):
        assert name in verify_codes, f"{name} missing from verify runner"
        assert _ts_number(name) == verify_codes[name], (
            f"{name} differs: verify={verify_codes[name]} verify-ts={_ts_number(name)}"
        )


# ---------------------------------------------------------------- reason-code catalog integrity


@_need_schemas
def test_reason_code_catalog_matches_schema_enum():
    schema_codes = set(_schema("registry_entry")["properties"]["reason_codes"]["items"]["enum"])
    # Discover the catalog rather than hard-coding its version directory. The path is
    # derived from CATALOG_VERSION on the schemas side, so a version written here would be
    # a second, unlinked copy of a version number, wrong the moment the catalog's version
    # changes. A drift guard that itself drifts is worse
    # than no guard, because it fails for the wrong reason and gets edited to pass.
    catalog_versions = sorted((_SCHEMAS_DATA / "reason_codes_catalog").glob("v*/catalog.json"))
    if not catalog_versions:
        absent("reason-code catalog not present in the sibling schemas checkout")
    assert len(catalog_versions) == 1, (
        f"expected exactly one catalog version directory, found {[p.parent.name for p in catalog_versions]}; "
        "two would mean a consumer could resolve either one"
    )
    catalog = json.loads(catalog_versions[0].read_text(encoding="utf-8"))
    entries = catalog["entries"]
    catalog_codes = set(entries.keys()) if isinstance(entries, dict) else {e["code"] for e in entries}
    assert catalog_codes == schema_codes, (
        f"reason-code catalog drifted from registry_entry enum; "
        f"schema-only={sorted(schema_codes - catalog_codes)} catalog-only={sorted(catalog_codes - schema_codes)}"
    )
    # the receipt enum must match too (both surfaces share the vocabulary)
    receipt_codes = set(_schema("verification_receipt")["properties"]["reason_codes"]["items"]["enum"])
    assert receipt_codes == schema_codes, (
        f"verification_receipt reason_codes enum drifted from registry_entry; "
        f"entry-only={sorted(schema_codes - receipt_codes)} receipt-only={sorted(receipt_codes - schema_codes)}"
    )


# ---------------------------------------------------------------- asset_type / workflow / key_type


@_need_schemas
def test_asset_type_is_one_identifier_grammar_across_objects():
    # verification-vocabularies.md section 7: an asset type is an identifier, the value a
    # registered vocabulary holds; no schema enumerates the asset types.
    entry = _schema("registry_entry")["properties"]["asset_type"]
    receipt = _schema("verification_receipt")["properties"]["asset_type"]
    assert entry["pattern"] == receipt["pattern"] == "^[a-z0-9][a-z0-9_]{0,63}$", (entry, receipt)
    assert "enum" not in entry and "enum" not in receipt


@_need_schemas
def test_key_type_and_algorithm_patterns_agree_between_entry_and_trust_registry():
    """Algorithm and key type are identifiers of one grammar, closed by the verifier's allowlist.

    The entry's and the trust registry's signature algorithm, and the trust entry's key type, carry
    the same identifier pattern, and the verifier's own allowlist pair is of that form. No schema
    keeps a closed enum of algorithms, which would make the documents choose what a verifier
    supports.
    """
    from loquitur.verify.cryptographic_capabilities import SUPPORTED_SIGNATURE_PAIRS as ALLOWED_SIGNATURE_PAIRS

    entry_algo = _algorithm_patterns(_schema("registry_entry")["properties"]["signature"])
    tr_algo = _algorithm_patterns(_schema("trust_registry")["properties"]["signature"])
    key_type = _schema("trust_registry")["properties"]["entries"]["items"]["properties"]["key_type"]
    assert entry_algo == tr_algo == [key_type["pattern"]], (entry_algo, tr_algo, key_type)
    assert "enum" not in key_type
    identifier = key_type["pattern"].removeprefix("^").removesuffix("$")
    assert ("secp256k1_ecdsa_sha256", "secp256k1") in ALLOWED_SIGNATURE_PAIRS
    for algorithm, type_ in ALLOWED_SIGNATURE_PAIRS:
        assert re.fullmatch(identifier, algorithm) and re.fullmatch(identifier, type_), (algorithm, type_)


# ---------------------------------------------------------------- trust-root mirror

# loquitur-verify cannot import loquitur-schemas at runtime, so the bytes a root key signs
# over a trust registry are defined twice: once where the signer builds them
# (loquitur-schemas trust_root.py) and once where the verifier rebuilds them. Two copies of
# a signing rule is how a consensus split starts: if one side changes the domain prefix or
# an envelope identifier, a signer and a verifier disagree about the message while both
# report success. These assertions compare the two files as text, deliberately: importing
# one to check the other would only prove that whichever module got imported agrees with
# itself. Verification itself (trust-root.md sections 3 and 5) has one implementation, the
# verifier's, so nothing here compares two verifications.

_SCHEMAS_TRUST_ROOT = _first_existing(
    _REPOS_ROOT / "loquitur-schemas" / "src" / "loquitur" / "schemas" / "trust_root.py",
)
_VERIFY_TRUST_ROOT = _VERIFY_SRC / "trust_root.py"

_need_trust_root = needs(
    _SCHEMAS_TRUST_ROOT is not None and _VERIFY_TRUST_ROOT.exists(),
    "trust_root mirror not present in both repos (loquitur-schemas sibling absent)",
)


def _py_constants(path: Path, pattern: str) -> dict[str, str]:
    txt = path.read_text(encoding="utf-8")
    return dict(re.findall(pattern, txt))


@_need_trust_root
def test_trust_root_signing_domain_prefix_is_identical():
    """The prefix is inside the signed message. A divergence here is a silent fork."""
    pattern = r'(TRUST_ROOT_SIGNING_DOMAIN_PREFIX) = (b"[^"]+")'
    schemas = _py_constants(_SCHEMAS_TRUST_ROOT, pattern)
    verify = _py_constants(_VERIFY_TRUST_ROOT, pattern)
    assert schemas, "domain prefix not found in the schemas mirror"
    assert schemas == verify, f"trust-root domain prefix drift: schemas={schemas} verify={verify}"


@_need_trust_root
def test_trust_root_envelope_identifiers_are_identical():
    pattern = r'(TRUST_ROOT_DOMAIN|TRUST_ROOT_ENVELOPE_SCHEMA|TRUST_REGISTRY_PAYLOAD_SCHEMA) = "([^"]+)"'
    schemas = _py_constants(_SCHEMAS_TRUST_ROOT, pattern)
    verify = _py_constants(_VERIFY_TRUST_ROOT, pattern)
    assert len(schemas) == 3, f"expected 3 envelope identifiers, found {sorted(schemas)}"
    assert schemas == verify, f"envelope identifier drift: {schemas} vs {verify}"


@_need_trust_root
def test_signature_algorithm_agrees_where_each_side_actually_defines_it():
    """Neither trust_root.py declares this; both import it from their own signing_envelope.

    Comparing the trust_root files for it would silently pass by finding nothing on either
    side: the vacuous-check failure mode this suite exists to avoid. So the assertion
    follows the constant to where it is really defined.
    """
    pattern = r'(SIGNATURE_ALGORITHM) = "([^"]+)"'
    schemas = _py_constants(_SCHEMAS_TRUST_ROOT.parent / "signing_envelope.py", pattern)
    verify = _py_constants(_VERIFY_SRC / "signing_envelope.py", pattern)
    assert schemas == verify == {"SIGNATURE_ALGORITHM": "secp256k1_ecdsa_sha256"}, (
        f"signature algorithm drift: schemas={schemas} verify={verify}"
    )
    for path in (_SCHEMAS_TRUST_ROOT, _VERIFY_TRUST_ROOT):
        assert "SIGNATURE_ALGORITHM" in path.read_text(encoding="utf-8"), (
            f"{path.name} does not reference the algorithm constant at all"
        )


@_need_trust_root
def test_trust_root_excluded_fields_are_identical():
    """What the root signature covers must be the same on both sides."""
    schemas = _py_frozenset(_SCHEMAS_TRUST_ROOT, "TRUST_REGISTRY_SIGNING_EXCLUDED_FIELDS")
    verify = _py_frozenset(_VERIFY_TRUST_ROOT, "TRUST_REGISTRY_SIGNING_EXCLUDED_FIELDS")
    assert schemas == verify == {"signature"}, (
        f"signing exclusion drift: schemas={sorted(schemas)} verify={sorted(verify)}"
    )


# .../loquitur-schemas/src/loquitur/schemas/data -> parents[2] is `src`, the import root.
_SCHEMAS_SRC = None if _SCHEMAS_DATA is None else _SCHEMAS_DATA.parents[2]


# ------------------------------------------------ trust-root hex form, one table for both packages

# loquitur-schemas keeps the case table for the lowercase-hex rule of trust-root.md (row 5) and
# the uncompressed public key rule, beside the parsing helpers it runs the mutations against.
# Each case below goes through loquitur.verify's own trust_root and ECDSA helper; the
# signatures are made at test time with freshly generated keys, through this repository's
# test-only kit, over the message loquitur-schemas builds, which must be the message this
# package rebuilds.

_SCHEMAS_HEX_CASES = _first_existing(
    _REPOS_ROOT / "loquitur-schemas" / "tests" / "fixtures" / "trust_root_hex_cases.json"
)
_need_hex_cases = needs(
    _SCHEMAS_HEX_CASES is not None and _SCHEMAS_SRC is not None,
    "loquitur-schemas tests/fixtures/trust_root_hex_cases.json not present",
)
_HEX_CASES = json.loads(_SCHEMAS_HEX_CASES.read_text(encoding="utf-8")) if _SCHEMAS_HEX_CASES else {}
_HEX_NOW = "2026-09-16T00:00:00Z"


def _mutate_signature(sig: str, mutation: str) -> object:
    """The mutations trust_root_hex_cases.json defines, applied to ``sig``."""
    assert len(sig) == 128 and sig[0] == "0" and sig[64] == "0"
    return {
        "none": sig,
        "z128": "z" * 128,
        "upper": sig.upper(),
        "space_padded": " " + sig[1:64] + " " + sig[65:],
        "zero_x_prefixed": "0x" + sig[2:64] + "0x" + sig[66:],
        "underscored": sig[1] + "_" + sig[2:64] + sig[65] + "_" + sig[66:],
        "truncated_127": sig[:127],
        "extended_129": sig + "0",
        "empty": "",
        "non_string": 12345,
    }[mutation]


def _mutate_public_key(pub: str, mutation: str) -> str:
    return {
        "none": pub,
        "upper": "04" + pub[2:].upper(),
        "leading_space": " " + pub,
        "trailing_newline": pub + "\n",
    }[mutation]


@pytest.fixture(scope="module")
def _root_signed_registry():
    import hashlib

    from authorization_kit import IssuerKey
    from siblings import import_sibling

    from loquitur.verify.trust_root import trust_registry_signing_bytes

    schemas_trust_root = import_sibling("loquitur.schemas.trust_root", "the hex table needs loquitur-schemas")
    registry = json.loads(
        (_VERIFY_ROOT / "tests" / "fixtures" / "authorization_valid_trust_registry.json").read_text("utf-8")
    )
    registry.pop("signature", None)
    message = trust_registry_signing_bytes(registry)
    assert message == schemas_trust_root.trust_registry_signing_bytes(registry)
    digest = hashlib.sha256(message).digest()
    for _ in range(20000):
        key = IssuerKey()
        sig = key.sign_digest(digest)
        if sig[0] == "0" and sig[64] == "0":
            return registry, digest, sig, key.public_key_hex
    raise AssertionError("no signature with leading zero nibbles in 20000 keys")


def _verify_root(pub: str, key_id: str = "r1"):
    from loquitur.verify.trust_root import TrustRootKey

    return TrustRootKey(
        key_id=key_id,
        key_type="secp256k1",
        public_key_hex=pub,
        not_before="2020-01-01T00:00:00Z",
        not_after="2030-01-01T00:00:00Z",
    )


@_need_hex_cases
def test_verify_trust_root_runs_the_shared_hex_table(_root_signed_registry) -> None:
    import copy

    from loquitur.verify.secp256k1 import verify_digest
    from loquitur.verify.trust_root import TrustRootError, verify_trust_registry_root_signature

    registry, digest, sig, pub = _root_signed_registry
    mismatches: list[str] = []
    cases = _HEX_CASES["root_signature_cases"]
    assert len(cases) >= 12, "the shared table lost its root signature cases"
    for case in cases:
        form = _mutate_signature(sig, case["mutation"])
        document = copy.deepcopy(registry)
        document["signature"] = {"algorithm": "secp256k1_ecdsa_sha256", "key_id": "r1", "signature": form}
        roots = (_verify_root(pub, "r1" if case["pinned"] else "other"),)
        status = verify_trust_registry_root_signature(document, evaluated_at=_HEX_NOW, roots=roots).status
        if status != case["expected_status"]:
            mismatches.append(f"root signature {case['id']}: {status} != {case['expected_status']}")
        # The ECDSA helper under the same table: only the lowercase form verifies.
        verified = verify_digest(digest, form, pub)
        if verified is not (case["expected_status"] == "ROOT_SIGNATURE_VALID"):
            mismatches.append(f"ecdsa helper {case['id']}: verified={verified}")
    key_cases = _HEX_CASES["root_public_key_cases"]
    assert len(key_cases) >= 4, "the shared table lost its public key cases"
    document = copy.deepcopy(registry)
    document["signature"] = {"algorithm": "secp256k1_ecdsa_sha256", "key_id": "r1", "signature": sig}
    for case in key_cases:
        form = _mutate_public_key(pub, case["mutation"])
        root = _verify_root(form)
        try:
            root.assert_valid()
            accepted = verify_trust_registry_root_signature(document, evaluated_at=_HEX_NOW, roots=(root,)).ok
        except TrustRootError:
            accepted = False
        if accepted is not (case["expected"] == "accepted"):
            mismatches.append(f"root public key {case['id']}: accepted={accepted}")
        if verify_digest(digest, sig, form) is not (case["expected"] == "accepted"):
            mismatches.append(f"ecdsa helper public key {case['id']}")
    assert not mismatches, "loquitur.verify disagrees with the shared trust-root hex table:\n" + "\n".join(mismatches)
