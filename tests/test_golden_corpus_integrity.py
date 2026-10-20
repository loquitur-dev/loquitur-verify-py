"""The golden corpus is non-empty: checked without ``loquitur-schemas``.

test_golden_narratives.py is the wording gate, but tests/conftest.py skips it whenever
``loquitur.schemas`` is not importable, and that is exactly the condition under which a
regeneration would render nothing: an empty golden compares equal to an empty live
render, so the gate would pass while asserting nothing, and the only module that reads
those files would not be collected.

This module has no optional dependency and is therefore never skipped. It asserts only
that the corpus exists and carries text: it says nothing about what the text says, which
remains test_golden_narratives.py's job. Together: this one notices the corpus is gone,
that one notices the wording changed.
"""

from __future__ import annotations

from pathlib import Path

GOLDEN_DIR = Path(__file__).resolve().parent / "golden_narratives"
AUDIENCES: tuple[str, ...] = ("technical", "compliance", "executive")

# The shortest committed golden is 83 bytes (an executive PASS block, the most compact
# output the renderer produces). The floor is set well below it so ordinary wording
# changes never trip it, and well above a blanked file, which is one line terminator.
MIN_AUDIENCE_CHARS = 40

# The corpus measures ~40 KB across 51 files. The floor leaves room for scenarios to be
# reworded or a scenario to be retired, and still fails by a wide margin on a wipe.
MIN_CORPUS_BYTES = 20_000


def _scenario_dirs() -> list[Path]:
    return sorted(p for p in GOLDEN_DIR.iterdir() if p.is_dir() and p.name != "__pycache__")


def test_every_golden_audience_file_carries_text() -> None:
    """No golden file is empty or whitespace-only."""
    for scenario_dir in _scenario_dirs():
        for audience in AUDIENCES:
            path = scenario_dir / f"{audience}.txt"
            assert path.is_file(), f"missing golden: {path}"
            text = path.read_text(encoding="utf-8").strip()
            assert len(text) >= MIN_AUDIENCE_CHARS, (
                f"{scenario_dir.name}/{audience}.txt holds {len(text)} characters. "
                f"A blank or near-blank golden passes the byte-identity gate against a "
                f"blank live render. Regenerate with loquitur-schemas installed."
            )


def test_golden_corpus_total_size_floor() -> None:
    """The corpus as a whole has not been emptied."""
    total = sum(p.stat().st_size for p in GOLDEN_DIR.rglob("*.txt") if "__pycache__" not in p.parts)
    assert total >= MIN_CORPUS_BYTES, (
        f"golden corpus is {total} bytes, below the {MIN_CORPUS_BYTES} floor. "
        f"This is what a regeneration run without loquitur-schemas would leave behind."
    )
