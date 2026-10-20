from loquitur.verify.cryptographic_capabilities import (
    CRYPTOGRAPHIC_CAPABILITY_PROFILE,
    RESERVED_UNSUPPORTED_ALGORITHMS,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    SUPPORTED_TRUST_KEY_TYPES,
    signature_algorithm_supported,
    trust_key_type_supported,
)


def test_release_0_1_capability_matrix_is_closed() -> None:
    assert CRYPTOGRAPHIC_CAPABILITY_PROFILE == "loquitur.crypto_capabilities.v0.1"
    assert SUPPORTED_SIGNATURE_ALGORITHMS == ("secp256k1_ecdsa_sha256",)
    assert SUPPORTED_TRUST_KEY_TYPES == ("secp256k1",)
    assert RESERVED_UNSUPPORTED_ALGORITHMS == ("ed25519",)
    assert signature_algorithm_supported("secp256k1_ecdsa_sha256")
    assert trust_key_type_supported("secp256k1")
    assert not signature_algorithm_supported("ed25519")
    assert not trust_key_type_supported("ed25519")
