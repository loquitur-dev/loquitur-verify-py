"""Named changes to a fixture bundle, for narratives over runs whose integrity does not hold.

A golden scenario or a test names one of these instead of shipping another fixture tree: the
change is applied to a fresh copy of the fixture bundle, which is removed afterwards.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path


def _remove(name: str) -> Callable[[Path], None]:
    def change(root: Path) -> None:
        (root / name).unlink()

    return change


def _directory_in_place_of(name: str) -> Callable[[Path], None]:
    def change(root: Path) -> None:
        (root / name).unlink()
        (root / name).mkdir()

    return change


BUNDLE_CHANGES: dict[str, Callable[[Path], None]] = {
    # A member the manifest declares is missing.
    "declared_member_removed": _remove("canonical_input.json"),
    # The envelope is there and its sidecar is not.
    "envelope_sidecar_removed": _remove("envelope.sha256"),
    # A directory carries the name p1.json, so the P1 layer is absent.
    "p1_replaced_by_directory": _directory_in_place_of("p1.json"),
}


@contextmanager
def changed_bundle(source: Path, change: str | None) -> Iterator[Path]:
    """Yield ``source`` itself, or a copy of it with the named change applied."""
    if change is None:
        yield source
        return
    with tempfile.TemporaryDirectory(prefix="loquitur-narrative-") as tmp:
        root = Path(tmp) / source.name
        shutil.copytree(source, root)
        BUNDLE_CHANGES[change](root)
        yield root
