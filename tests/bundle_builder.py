"""Build sealed test bundles in memory, independently of the code under test.

A regression test for a contract rule needs a bundle in which the rule is the ONLY thing
wrong: every other digest must match, or the test passes for the wrong reason (a vector
that leaves the envelope unsealed fails on the envelope instead of on the rule it was
written for). ``Bundle`` holds the members as bytes and ``seal`` recomputes
every digest the bundle commits to with ``rfc8785`` and ``hashlib`` directly, never with
``loquitur.verify``, so a defect in the verifier's own canonicalization cannot make a test
agree with it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785

FIXTURES = Path(__file__).resolve().parent / "fixtures"
LINK_BUNDLE = FIXTURES / "link_valid_bundle"


def jcs(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def nested_text(depth: int, leaf: str = "0") -> str:
    """JSON text of ``depth`` nested arrays around ``leaf``: a document of that depth."""
    return "[" * depth + leaf + "]" * depth


def with_raw_member(obj: dict[str, Any], key: str, raw_value: str) -> bytes:
    """Canonical bytes of ``obj`` with ``key`` appended as raw JSON text.

    The value is spliced in as text because the values under test (1e400, a lone
    surrogate escape, 9007199254740993) cannot be produced by a JSON serializer at all.
    """
    body = jcs({k: v for k, v in obj.items() if k != key}).decode("utf-8")
    separator = "," if body != "{}" else ""
    return (body[:-1] + separator + json.dumps(key) + ":" + raw_value + "}").encode("utf-8")


class Bundle:
    """A bundle as {posix member name: bytes}."""

    def __init__(self, source: Path = LINK_BUNDLE) -> None:
        self.members: dict[str, bytes] = {
            path.relative_to(source).as_posix(): path.read_bytes()
            for path in sorted(source.rglob("*"))
            if path.is_file()
        }

    def json(self, name: str) -> Any:
        return json.loads(self.members[name].decode("utf-8"))

    def set_json(self, name: str, value: Any) -> Bundle:
        self.members[name] = jcs(value)
        return self

    def edit(self, name: str, mutate) -> Bundle:
        value = self.json(name)
        mutate(value)
        return self.set_json(name, value)

    def reproject(self) -> Bundle:
        """Recompute p1.ih over the projection p1.ik names (or the whole input)."""
        p1 = self.json("p1.json")
        canonical_input = self.json("canonical_input.json")
        keys = p1["ik"] if "ik" in p1 else list(canonical_input)
        p1["ih"] = "sha256:" + sha(jcs({key: canonical_input.get(key) for key in keys}))
        return self.set_json("p1.json", p1)

    def seal(self, *, p1: bool = True, files: bool = True, manifest: bool = True, envelope: bool = True) -> Bundle:
        """Recompute the p1 sidecar, the file digests, the manifest sidecar and the envelope."""
        p1_digest = None
        if "p1.json" in self.members:
            try:
                p1_digest = sha(jcs(self.json("p1.json")))
            except (ValueError, TypeError):
                p1_digest = None
        if p1 and p1_digest is not None:
            self.members["p1.sha256"] = p1_digest.encode()
        manifest_obj = self.json("manifest.json")
        if files and isinstance(manifest_obj.get("files"), dict):
            for name in manifest_obj["files"]:
                if name in self.members:
                    manifest_obj["files"][name] = "sha256:" + sha(self.members[name])
            self.set_json("manifest.json", manifest_obj)
        manifest_digest = sha(jcs(manifest_obj))
        if manifest:
            self.members["manifest.sha256"] = manifest_digest.encode()
        if envelope and "envelope_env1.json" in self.members:
            env = self.json("envelope_env1.json")
            env["bundle_id"] = manifest_obj.get("bundle_id")
            env["bundle_manifest_sha256"] = "sha256:" + manifest_digest
            if p1_digest is not None:
                env["p1_sha256"] = "sha256:" + p1_digest
            self.set_json("envelope_env1.json", env)
            self.members["envelope.sha256"] = sha(jcs(env)).encode()
        if "verification_receipt.json" in self.members:
            try:
                receipt = self.json("verification_receipt.json")
            except ValueError:
                receipt = None
            if isinstance(receipt, dict):
                receipt["manifest_sha256"] = "sha256:" + manifest_digest
                self.set_json("verification_receipt.json", receipt)
        return self

    def reseal_envelope_sidecar(self) -> Bundle:
        self.members["envelope.sha256"] = sha(jcs(self.json("envelope_env1.json"))).encode()
        return self

    def write(self, root: Path) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        for name, data in self.members.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def manifest_digest(self) -> str:
        return sha(jcs(self.json("manifest.json")))

    def link_entry(self, path: Path, **overrides: Any) -> Path:
        """A link registry entry bound to this bundle's manifest and receipt digests."""
        entry = json.loads((FIXTURES / "link_valid_registry_entry.json").read_text(encoding="utf-8"))
        entry["manifest_hash"] = "sha256:" + self.manifest_digest()
        try:
            entry["receipt_hash"] = "sha256:" + sha(jcs(self.json("verification_receipt.json")))
        except (KeyError, ValueError):
            pass
        entry.update(overrides)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")
        return path
