"""The hand-written ZIP reader checked against a second implementation: the standard library's zipfile.

archive.py reads ZIP archives itself, so that the intake rules of bundle-objects.md section 5 are
applied to the records as written. This test is the second implementation it otherwise lacks. It
runs only here: zipfile is not imported by the verifier, and the import-isolation job keeps the
verdict path free of it.

The archives are seeded and deterministic: archives written with zipfile (stored and deflated
entries; none, one or several; under a wrapper directory or not; UTF-8 names; with and without
data descriptors), the ZIP fixtures of this suite, and byte mutations of both (a flipped byte, a
truncation, a changed CRC, size or offset field of a central-directory record, a dropped
central-directory record). Scale with LOQUITUR_FUZZ_ITERATIONS.

The oracle is one-sided, because archive.py is deliberately stricter than zipfile:

1. when archive.py accepts an archive, zipfile accepts it too (``testzip()`` finds no bad
   member), lists the same file entries in the same order and reads the same bytes for each;
2. when zipfile refuses an archive, archive.py refuses it with an ArchiveLoadError, never another
   exception;
3. when archive.py refuses an archive zipfile accepts, the refusal is one of its own intake rules;
   the test records the refusal and asserts nothing more.

What it cannot reach: ZIP64 records beyond what zipfile writes, and multi-disk archives, which
neither implementation reads.
"""

from __future__ import annotations

import io
import os
import random
import struct
import zipfile
import zlib
from collections import Counter
from pathlib import Path

import pytest

from loquitur.verify.archive import ArchiveLoadError, safe_extract_zip, validate_zip_members

SEED = 20261011
ITERATIONS = int(os.environ.get("LOQUITUR_FUZZ_ITERATIONS", "40"))
FIXTURES = sorted((Path(__file__).resolve().parent / "fixtures").glob("*.zip"))
_CENTRAL = b"PK\x01\x02"
# The only intake rules an unmutated archive from _written can break: a name outside the portable
# set (the rare wrapper it writes on purpose) and the compression-ratio bound (a repetitive member).
_WELL_FORMED_REFUSALS = ("unsafe_zip_member:character_outside_portable_set", "zip_suspicious_compression_ratio")
# OSError: zipfile seeks to a corrupted offset before it checks the record there.
_REFUSED_BY_ZIPFILE = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
    NotImplementedError,
    EOFError,
    ValueError,
    OSError,
)


class _Unseekable(io.RawIOBase):
    """A sink zipfile cannot seek back into, so it writes a data descriptor after each entry."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:  # type: ignore[override]
        self.buffer += data
        return len(data)


def _written(rng: random.Random) -> bytes:
    """A well-formed archive written by zipfile."""
    unseekable = rng.random() < 0.3
    sink: io.BytesIO | _Unseekable = _Unseekable() if unseekable else io.BytesIO()
    # A name outside the portable set is refused by archive.py alone (rule 3), so it is rare here.
    prefix = rng.choice(["", "bundle/", "wrapper/"]) if rng.random() < 0.9 else "wrapper-é/"
    names: set[str] = set()
    with zipfile.ZipFile(sink, "w") as archive:  # type: ignore[arg-type]
        for _ in range(rng.choice([0, 1, 1, 2, 3, 6])):
            name = prefix + rng.choice(["manifest.json", "p1.json", "data", "notes.txt", "sub/x.json", "a/b/c.bin"])
            if name in names:
                continue
            names.add(name)
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 2, 3, 4, 6))
            info.compress_type = rng.choice([zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
            info.external_attr = 0o644 << 16
            size = rng.choice([0, 1, 17, 300, 4096])
            data = bytes(rng.getrandbits(8) for _ in range(size)) if rng.random() < 0.5 else b"ab" * (size // 2)
            archive.writestr(info, data)
    return bytes(sink.buffer if isinstance(sink, _Unseekable) else sink.getvalue())


def _central_records(data: bytes) -> list[int]:
    offsets, start = [], 0
    while (found := data.find(_CENTRAL, start)) >= 0:
        offsets.append(found)
        start = found + 4
    return offsets


def _mutated(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    records = _central_records(data)
    kind = rng.choice(["flip", "truncate", "crc", "size", "offset", "drop"] if records else ["flip", "truncate"])
    if not buf:
        return bytes(buf)
    if kind == "flip":
        position = rng.randrange(len(buf))
        buf[position] ^= 1 << rng.randrange(8)
    elif kind == "truncate":
        del buf[rng.randrange(len(buf)) :]
    else:
        record = rng.choice(records)
        field = {"crc": 16, "size": rng.choice([20, 24]), "offset": 42}.get(kind)
        if field is not None and record + field + 4 <= len(buf):
            (value,) = struct.unpack_from("<I", buf, record + field)
            struct.pack_into("<I", buf, record + field, (value + rng.choice([1, 2, 255, 0x10000])) & 0xFFFFFFFF)
        elif kind == "drop":
            # Remove one central-directory record and fix the end record's counts and size.
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", buf, record + 28)
            length = 46 + name_len + extra_len + comment_len
            del buf[record : record + length]
            end = bytes(buf).rfind(b"PK\x05\x06")
            if end >= 0:
                disk_entries, total, size = struct.unpack_from("<HHI", buf, end + 8)
                struct.pack_into("<HHI", buf, end + 8, max(disk_entries - 1, 0), max(total - 1, 0), size - length)
    return bytes(buf)


def _ours(path: Path, destination: Path) -> list[tuple[str, bytes]] | ArchiveLoadError:
    try:
        names = validate_zip_members(path)
        extracted = safe_extract_zip(path, destination)
    except ArchiveLoadError as exc:
        return exc
    assert extracted == names
    return [(name, (destination / name).read_bytes()) for name in names]


def _theirs(path: Path) -> list[tuple[str, bytes]] | None:
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                return None
            return [(info.filename, archive.read(info)) for info in archive.infolist() if not info.is_dir()]
    except _REFUSED_BY_ZIPFILE:
        return None


def _cases() -> list[tuple[str, bytes]]:
    rng = random.Random(SEED)
    bases = [(f"written-{n}", _written(rng)) for n in range(max(ITERATIONS // 4, 8))]
    bases += [(f"fixture-{path.stem}", path.read_bytes()) for path in FIXTURES]
    cases = list(bases)
    for n in range(ITERATIONS):
        name, data = rng.choice(bases)
        cases.append((f"{name}-mutant-{n}", _mutated(data, rng)))
    return cases


def test_the_reader_and_zipfile_agree_one_sidedly(tmp_path: Path) -> None:
    refusals: Counter[str] = Counter()
    accepted = 0
    for index, (name, data) in enumerate(_cases()):
        path = tmp_path / f"{index}.zip"
        path.write_bytes(data)
        ours = _ours(path, tmp_path / f"{index}-out")
        theirs = _theirs(path)
        if isinstance(ours, ArchiveLoadError):
            # Rules 2 and 3: a refusal is always an ArchiveLoadError; when zipfile accepts, it is
            # one of archive.py's own stricter rules, recorded here.
            if theirs is not None:
                refusals[str(ours).split(":")[0] or type(ours).__name__] += 1
            # An unmutated archive zipfile wrote breaks only the rules its generator can break.
            if name.startswith("written-") and "-mutant-" not in name:
                assert str(ours).startswith(_WELL_FORMED_REFUSALS), f"{name}: refused as {ours}"
            continue
        accepted += 1
        # Rule 1: what archive.py accepts, zipfile accepts and reads identically.
        assert theirs is not None, f"{name}: archive.py accepted an archive zipfile refuses"
        assert [entry for entry, _ in ours] == [entry for entry, _ in theirs], f"{name}: entries differ"
        assert ours == theirs, f"{name}: member bytes differ"
    assert accepted >= len(FIXTURES), "too few archives were accepted for the comparison to say anything"
    print(f"accepted {accepted}; refused only by archive.py: {dict(refusals)}")


@pytest.mark.parametrize("fixture", FIXTURES, ids=[path.stem for path in FIXTURES])
def test_every_fixture_archive_reads_as_zipfile_reads_it(fixture: Path, tmp_path: Path) -> None:
    ours = _ours(fixture, tmp_path / "out")
    assert not isinstance(ours, ArchiveLoadError)
    assert ours == _theirs(fixture)
