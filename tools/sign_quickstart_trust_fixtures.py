"""Write the two fixtures that let the README quickstart reach every authorization outcome.

The quickstart documents three authorization runs over one registry entry: `OFFLINE_REVIEW` with no
trust root, `OFFLINE_OK` with `--trust-root`, and `OFFLINE_REVIEW` with an evaluation time
after the trust registry expires. The second needs a trust registry signed by a root and a
trust-root document naming that root's public key. `authorization_valid_trust_registry.json` carries a
placeholder signature that no root verifies, so no committed file could reach it.

This tool writes:

* `tests/fixtures/authorization_quickstart_trust_registry.json`: `authorization_valid_trust_registry.json` with its
  `signature` replaced by a root signature over the trust-root signing message
  (loquitur-protocol `docs/specification/trust-root.md` §4);
* `tests/fixtures/authorization_quickstart_trust_root.json`: a trust-root document (§3) naming the
  public key of that root.

The root key is generated in memory by this process, used once and discarded. It is never
written to disk and never printed, so nothing can sign with it again: the root has no
authority over anything, and the fixtures are a demonstration of the mechanism only. Running
the tool again makes a new key and new bytes for both files. Run it when
`authorization_valid_trust_registry.json` changes; `tests/test_readme_quickstart.py` fails until then.

Signing needs `cryptography`, a development dependency. Run from the repository root:

    python tools/sign_quickstart_trust_fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SOURCE = FIXTURES / "authorization_valid_trust_registry.json"
REGISTRY = FIXTURES / "authorization_quickstart_trust_registry.json"
TRUST_ROOT = FIXTURES / "authorization_quickstart_trust_root.json"

ROOT_KEY_ID = "quickstart-root-without-authority"
# The window covers the authorization fixtures' evaluation times (the registry is effective from
# 2026-04-29T12:00:00Z and expires at 2026-05-29T12:00:00Z) and nothing far beyond them.
NOT_BEFORE = "2026-04-01T00:00:00Z"
NOT_AFTER = "2026-07-01T00:00:00Z"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _render(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    from loquitur.verify.trust_root import trust_registry_signing_bytes

    registry = json.loads(SOURCE.read_text(encoding="utf-8"))
    registry.pop("signature", None)

    key = ec.generate_private_key(ec.SECP256K1())
    r, s = asym_utils.decode_dss_signature(key.sign(trust_registry_signing_bytes(registry), ec.ECDSA(hashes.SHA256())))
    s = min(s, SECP256K1_ORDER - s)  # low S, as the protocol requires
    public_key_hex = (
        key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    )
    del key

    registry["signature"] = {
        "algorithm": "secp256k1_ecdsa_sha256",
        "key_id": ROOT_KEY_ID,
        "signature": format(r, "064x") + format(s, "064x"),
    }
    trust_root = {
        "object_type": "trust_root_document",
        "schema_version": "v1",
        "roots": [
            {
                "key_id": ROOT_KEY_ID,
                "key_type": "secp256k1",
                "not_after": NOT_AFTER,
                "not_before": NOT_BEFORE,
                "public_key_hex": public_key_hex,
                "status": "active",
            }
        ],
    }
    REGISTRY.write_text(_render(registry), encoding="utf-8", newline="\n")
    TRUST_ROOT.write_text(_render(trust_root), encoding="utf-8", newline="\n")
    print(f"wrote {REGISTRY.relative_to(ROOT).as_posix()} and {TRUST_ROOT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
