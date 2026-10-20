"""Closed cryptographic capability set for protocol release 0.1."""

CRYPTOGRAPHIC_CAPABILITY_PROFILE = "loquitur.crypto_capabilities.v0.1"
SUPPORTED_SIGNATURE_ALGORITHMS = ("secp256k1_ecdsa_sha256",)
SUPPORTED_TRUST_KEY_TYPES = ("secp256k1",)
RESERVED_UNSUPPORTED_ALGORITHMS = ("ed25519",)


def signature_algorithm_supported(value: object) -> bool:
    return isinstance(value, str) and value in SUPPORTED_SIGNATURE_ALGORITHMS


def trust_key_type_supported(value: object) -> bool:
    return isinstance(value, str) and value in SUPPORTED_TRUST_KEY_TYPES


# The verifier's closed allowlist of (signature algorithm, key type) pairs
# (CRYPTOGRAPHIC_CAPABILITIES.json; canonicalization-and-hashing.md, algorithm agility). The
# documents admit any well-formed identifier; this list, chosen by the verifier and never by the
# input, decides at the signature step, and a pair outside it is UNSUPPORTED_SIGNATURE_ALGORITHM.
SUPPORTED_SIGNATURE_PAIRS: tuple[tuple[str, str], ...] = (("secp256k1_ecdsa_sha256", "secp256k1"),)


def signature_pair_supported(algorithm: object, key_type: object) -> bool:
    return any(algorithm == a and key_type == k for a, k in SUPPORTED_SIGNATURE_PAIRS)
