# Loquitur verifier golden bundle fixtures

These fixtures are intentionally small, synthetic and non-confidential. They exercise the
public `loquitur-verify` package contract.
They are not production trust roots, issuer credentials, legal identity records or chain
finality evidence.

| Fixture | Expected status | Expected exit code | Purpose |
| --- | --- | ---: | --- |
| `valid_bundle/` and `valid_bundle.zip` | `OFFLINE_OK` | `0` | Minimal valid bundle with manifest, P1, canonical input and env1 envelope links. |
| `tampered_manifest_bundle/` and `.zip` | `OFFLINE_FAIL` | `1` | `manifest.json` was changed after `manifest.sha256` was written. |
| `tampered_canonical_input_bundle/` and `.zip` | `OFFLINE_FAIL` | `1` | `canonical_input.json` was changed while manifest/envelope were recomputed, isolating `p1.ih` mismatch. |
| `missing_canonical_input_bundle/` and `.zip` | `OFFLINE_REVIEW` | `2` | `canonical_input.json` is absent while manifest/envelope remain internally consistent. |
| `link_valid_bundle/` and `.zip` + `link_valid_registry_entry.json` | `OFFLINE_OK` | `0` | The local `link` check of a bundle against a registry entry, using manifest and receipt hashes. |
| `link_valid_bundle/` + `authorization_valid_registry_entry.json` + `authorization_valid_trust_registry.json` at `--evaluation-time 2026-05-10T00:00:00Z`, no `--trust-root` | `OFFLINE_REVIEW` | `2` | The local `authorization` check: issuer signature plus supplied trust-registry authorization. Signature and authorization pass; no root is pinned, so the registry's own authenticity is never established and the run reviews rather than passes. |
| `link_valid_bundle.zip` + `authorization_valid_registry_entry.json` + `authorization_quickstart_trust_registry.json` at `--evaluation-time 2026-05-20T00:00:00Z`, no `--trust-root` | `OFFLINE_REVIEW` | `2` | The README's first authorization run. The same result as the row above, over a trust registry a root signed. |
| the same, with `--trust-root authorization_quickstart_trust_root.json` | `OFFLINE_OK` | `0` | The README's second authorization run: the trust registry authenticates against the root the trust-root document names. `authorization_valid_trust_registry.json` carries a placeholder signature that no root verifies, and cannot reach this result. |
| the same, with `--evaluation-time 2026-05-29T12:00:01Z` | `OFFLINE_REVIEW` | `2` | The README's third authorization run: one second after the trust registry expires, `TRUST_REGISTRY_EXPIRED` with the review reason `trust_registry_not_current`, and root authentication is not reached. |
| `authorization_*_registry_entry.json` / `authorization_*_trust_registry.json` negative fixtures | `OFFLINE_FAIL` / `OFFLINE_REVIEW` | `1` / `2` | Coverage for tampered signatures, unknown issuer/key, revoked/suspended keys and scope mismatch (`OFFLINE_FAIL`), and for expired/not-yet-effective keys, whose window does not hold the evaluation time (`OFFLINE_REVIEW`). |

Each `NAME.zip` is the packing of the directory `NAME/` beside it, as
`python tools/check_public_boundary.py --pack tests/fixtures/NAME` writes it. The boundary
checker clears it by building the same bytes from the files it reads in `NAME/`; after a change
to `NAME/`, run that command again.

## The trust boundary of the link and authorization checks

The `link` check verifies only the local cryptographic link between a private bundle and a supplied
`registry_entry`. The `authorization` check also verifies the `registry_entry` issuer signature
against a supplied local `trust_registry` fixture and checks the authorization of the issuer and its
key, the key status, the scope and the validity windows against that supplied material.

The `authorization` check does **not** verify trust-registry root authenticity on its own: that
takes `--trust-root`, and without it a run that passes every other authorization condition returns
`OFFLINE_REVIEW` / exit `2`. It does not verify registry inclusion, checkpoint consistency, online
registry state, chain anchors or their finality, legal issuer identity, KMS or HSM custody, TUF
metadata or TSA evidence. The fixtures are synthetic demo material for offline verifier regression
tests only.

## Signing provenance for the authorization fixtures

`authorization_valid_registry_entry.json` is signed with the non-production demo secp256k1 key whose
public half `loquitur-schemas` carries as a test fixture. The private half was minted in
memory for the run that signed the fixtures and written nowhere, so no private demo key
exists in this package or in any other. None may be introduced, and this key must not be
represented as a production trust root.

`authorization_quickstart_trust_registry.json` is `authorization_valid_trust_registry.json` with its
`signature` replaced by a root signature, and `authorization_quickstart_trust_root.json` is the
trust-root document naming that root's public key. `tools/sign_quickstart_trust_fixtures.py`
generated the root key in memory, signed once and discarded it; the key was never written or
printed, and nothing can sign with it again. **This root has no authority over anything**: it
demonstrates `--trust-root` and must not be pinned for any other purpose. Running the tool again
writes both files with a new key. `tests/test_readme_quickstart.py` fails when
`authorization_valid_trust_registry.json` and its signed copy differ in anything but the signature.

The expected signing payload hash of `authorization_valid_registry_entry.json` is:

```text
sha256:8d6c5ee930385a51e57ba21ca6066925d704e5cccc9e378737537e5a5b21311e
```
