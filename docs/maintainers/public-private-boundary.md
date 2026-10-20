# Public/private boundary

`loquitur-verify` is an offline verifier package (preview). It verifies disclosed local material
supplied by the caller. It does not query any service or registry.

It must not be described as proving:

- registry inclusion;
- chain anchors or their finality;
- legal ownership;
- valuation correctness;
- regulatory compliance;
- KYC or AML status;
- SOC 2 or external audit status;
- real-world issuer identity beyond supplied local trust material.

The package may report local integrity outcomes, the `link` check of a registry entry supplied
locally, and the `authorization` check of the entry's signature and of the issuer key's
authorization against a trust registry supplied locally.
