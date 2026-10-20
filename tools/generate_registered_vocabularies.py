"""Generate the registered vocabularies this verifier embeds, from loquitur-protocol.

The verifier holds, for each kind of registered vocabulary, the version built into it unless the
operator supplies another (verification-vocabularies.md §8). The built-in versions are the bytes
of loquitur-protocol's `vocabularies/<kind>.json`, embedded byte for byte with their SHA-256 in
`src/loquitur/verify/registered_vocabularies.py`, so that the package reads no file at run time
and the report can name exactly what it held. `tests/test_registered_vocabularies_is_current.py`
regenerates the module against a sibling checkout and compares.

Run: python tools/generate_registered_vocabularies.py [--check]
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SOURCE = HERE.parent / "loquitur-protocol/vocabularies"
TARGET = HERE / "src/loquitur/verify/registered_vocabularies.py"
KINDS = ("asset_type", "workflow", "anchoring_method")

HEADER = '''"""The registered vocabularies built into this verifier, byte for byte.

GENERATED FILE - do not edit by hand.
Regenerate with: python tools/generate_registered_vocabularies.py

Each value is the bytes of loquitur-protocol's `vocabularies/<kind>.json`, and
REGISTERED_VOCABULARY_SHA256 their SHA-256 (verification-vocabularies.md §8). `vocabulary.py`
reads them under the same rules as a document an operator supplies.
"""

from __future__ import annotations
'''


def bytes_literal(data: bytes) -> str:
    """``data`` as a Python bytes literal in double quotes, the form the formatter keeps."""
    out = []
    for byte in data:
        if byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x22:
            out.append('\\"')
        elif byte == 0x0A:
            out.append("\\n")
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return 'b"' + "".join(out) + '"'


def render(source: Path = SOURCE) -> str:
    documents = {}
    for kind in KINDS:
        path = source / f"{kind}.json"
        if not path.is_file():
            raise SystemExit(
                f"registered vocabulary not found: {path}\n"
                "loquitur-protocol must be checked out alongside this repository to regenerate the module."
            )
        documents[kind] = path.read_bytes()
    lines = [HEADER, "REGISTERED_VOCABULARIES: dict[str, bytes] = {"]
    for kind, data in documents.items():
        lines.append(f'    "{kind}": (')
        for line in data.splitlines(keepends=True):
            lines.append(f"        {bytes_literal(line)}")
        lines.append("    ),")
    lines.append("}")
    lines.append("")
    lines.append("REGISTERED_VOCABULARY_SHA256: dict[str, str] = {")
    for kind, data in documents.items():
        lines.append(f'    "{kind}": "{hashlib.sha256(data).hexdigest()}",')
    lines.append("}")
    rendered = "\n".join(lines) + "\n"
    compile(rendered, str(TARGET), "exec")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit non-zero if the checked-in module is stale")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != rendered:
            print(
                "registered_vocabularies.py is stale; run python tools/generate_registered_vocabularies.py",
                file=sys.stderr,
            )
            return 1
        print("registered_vocabularies.py is current")
        return 0
    TARGET.write_text(rendered, encoding="utf-8", newline="")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
