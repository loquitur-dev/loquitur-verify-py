# Test vectors

`ecdsa_secp256k1_sha256_p1363_test.json` is third-party material: a test-vector file of the
Wycheproof project (https://github.com/C2SP/wycheproof), file
`testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json`, retrieved on 2026-07-02 and kept
unmodified. The Wycheproof project distributes it under the Apache License, Version 2.0, whose
text is in this repository's `LICENSE-APACHE` file, and `NOTICE` credits it. It is licensed under
the Apache License, Version 2.0 only: the MIT License option of this repository does not apply to
it.
`tests/test_wycheproof_secp256k1.py` checks its SHA-256,
`7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2`, before it reads it. The
source distribution of the package does not include the file, so that every file it distributes
is under `MIT OR Apache-2.0`; there the tests that read it skip and say why.

The other files in this directory belong to this repository and are licensed as it is, under the
MIT License or the Apache License, Version 2.0, at your option.
