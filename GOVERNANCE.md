# Governance

**Repository:** `loquitur-verify-py`  
**Role:** Standalone verifier package  
**Status:** preview governance note.

This repository is maintained by one person, the copyright holder `NOTICE` names; "the maintainer"
in its documents is that person, not a team. Governance must preserve repository ownership, release
boundaries, and the distinction between public commitment material and private evidence material.

## Change control

Changes that affect public semantics, release artifacts, schemas, generated surfaces, security
posture, or public documentation claims require explicit review.

The maintainer rejects changes that:

- blur this repository's ownership boundary;
- expose private evidence or material of an unpublished repository;
- create unsupported production, audit, compliance, finality, or valuation claims;
- silently change public contract behavior without tests and documentation.

## Repository split

Loquitur is maintained as multiple independent repositories. This repository should not absorb code
or documents owned by sibling repositories unless a dedicated migration decision explicitly changes
ownership and updates tests.
