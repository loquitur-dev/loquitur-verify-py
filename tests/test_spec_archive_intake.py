"""ZIP intake, held to loquitur-protocol docs/specification/bundle-objects.md §5.

§5 states the limits as one table and the rules as another, in the order an entry is judged:
name, type, method, member size, ratio, duplicate, count, total. Both tables are read from the
sibling checkout (spec_tables.py). Each limit is checked at its bound and one past it, each rule
by an entry that breaks it alone, and the order by every pair of rules with different errors:
one entry breaks both, and the rule listed first must decide the error. An archive is judged
entry by entry, so an earlier entry that breaks a later rule decides over a later entry that
breaks an earlier one.

The archives are written byte by byte here rather than with zipfile, because the entries the
rules refuse are ones zipfile will not write: a name with a backslash (zipfile rewrites it on
Windows), an encrypted entry, sizes the central directory records but the data does not carry.
A refusal happens before extraction, so a refused entry's data is never read.
"""

from __future__ import annotations

import itertools
import json
import re
import stat
import struct
import zlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from bundle_builder import Bundle
from spec_tables import code, document, table

from loquitur.verify import archive
from loquitur.verify.runner import verify_path

SPEC = "bundle-objects.md"
MIB = 1024 * 1024
STORED, DEFLATED, BZIP2 = 0, 8, 12


@dataclass(frozen=True)
class Entry:
    """One archive entry. ``file_size``/``compress_size`` override what the data gives."""

    name: str
    data: bytes = b"x"
    method: int = STORED
    flags: int = 0
    mode: int = 0
    file_size: int | None = None
    compress_size: int | None = None
    raw_name: bytes | None = None
    payload: bytes | None = None  # the data as written, in place of what ``data`` gives


def _payload(entry: Entry) -> bytes:
    if entry.payload is not None:
        return entry.payload
    if entry.method == DEFLATED:
        packer = zlib.compressobj(9, zlib.DEFLATED, -15)
        return packer.compress(entry.data) + packer.flush()
    return entry.data


def write_zip(path: Path, entries: list[Entry]) -> Path:
    """A ZIP whose central directory records exactly what each entry says."""
    body = bytearray()
    central = bytearray()
    for entry in entries:
        name = entry.raw_name if entry.raw_name is not None else entry.name.encode("utf-8")
        flags = entry.flags | (0x800 if entry.raw_name is None and not entry.name.isascii() else 0)
        payload = _payload(entry)
        crc = zlib.crc32(entry.data)
        size = len(entry.data) if entry.file_size is None else entry.file_size
        packed = len(payload) if entry.compress_size is None else entry.compress_size
        offset = len(body)
        body += struct.pack(
            "<4s5H3L2H", b"PK\x03\x04", 20, flags, entry.method, 0, 0x21, crc, packed, size, len(name), 0
        )
        body += name + payload
        central += struct.pack(
            "<4s6H3L5H2L",
            b"PK\x01\x02",
            (3 << 8) | 20,
            20,
            flags,
            entry.method,
            0,
            0x21,
            crc,
            packed,
            size,
            len(name),
            0,
            0,
            0,
            0,
            entry.mode << 16,
            offset,
        )
        central += name
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, len(entries), len(entries), len(central), len(body), 0)
    path.write_bytes(bytes(body + central + end))
    return path


def _bundle_entries() -> list[Entry]:
    bundle = Bundle()
    bundle.seal()
    return [Entry(name, data, DEFLATED) for name, data in sorted(bundle.members.items())]


def _run(tmp_path: Path, name: str, entries: list[Entry]) -> dict[str, Any]:
    return verify_path(write_zip(tmp_path / f"{name}.zip", entries)).to_dict()


def _refused_with(report: dict[str, Any]) -> str:
    assert report["status"] == "OFFLINE_FAIL", report["status"]
    assert len(report["errors"]) == 1, report["errors"]
    assert report["outcome"]["reason"] == report["errors"][0]["code"]
    return report["errors"][0]["code"]


# ---- the two tables ----------------------------------------------------------------------------


def _limits() -> dict[str, str]:
    return {row["limit"]: row["value"] for row in table(document(SPEC), ["limit", "value"])}


def _rules() -> list[tuple[str, str]]:
    rows = table(document(SPEC), ["rule", "an entry is refused when", "error"])
    return [(row["rule"], code(row["error"])) for row in rows]


def _mib(cell: str) -> int:
    match = re.fullmatch(r"(\d+) MiB", cell)
    assert match, cell
    return int(match.group(1)) * MIB


def _bounds() -> dict[str, int]:
    limits = _limits()
    assert set(limits) == {
        "file entries",
        "uncompressed bytes, per member",
        "uncompressed bytes, total",
        "compression ratio, per member",
    }
    ratio = re.fullmatch(r"(\d+):1", limits["compression ratio, per member"])
    assert ratio, limits["compression ratio, per member"]
    return {
        "count": int(limits["file entries"]),
        "member": _mib(limits["uncompressed bytes, per member"]),
        "total": _mib(limits["uncompressed bytes, total"]),
        "ratio": int(ratio.group(1)),
    }


def test_the_limits_are_the_ones_this_verifier_applies() -> None:
    bounds = _bounds()
    assert bounds == {
        "count": archive.MAX_ZIP_FILE_COUNT,
        "member": archive.MAX_ZIP_MEMBER_UNCOMPRESSED_BYTES,
        "total": archive.MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES,
        "ratio": archive.MAX_ZIP_COMPRESSION_RATIO,
    }
    flat = " ".join(document(SPEC).split())
    assert (
        f"a member breaks it when its uncompressed size is more than {bounds['ratio']} times its compressed size"
        in flat
    )
    assert "The compression ratio bounds every member, whatever its size" in flat


def _validates(tmp_path: Path, name: str, entries: list[Entry]) -> str | None:
    """None when every entry passes, else the error class ``verify_path`` maps the refusal to."""
    try:
        archive.validate_zip_members(write_zip(tmp_path / f"{name}.zip", entries))
    except archive.UnsafeZipMemberError:
        return "archive_unsafe_member"
    except archive.ArchiveSafetyLimitError:
        return "archive_safety_limit"
    return None


def test_each_limit_at_its_bound_and_one_past_it(tmp_path: Path) -> None:
    bounds = _bounds()
    ratio, member, total, count = bounds["ratio"], bounds["member"], bounds["total"], bounds["count"]
    at, past = {}, {}
    # The ratio, for a member of any size, and for one that records bytes from nothing.
    at["ratio"] = [Entry("r.bin", file_size=ratio * 7, compress_size=7)]
    past["ratio"] = [Entry("r.bin", file_size=ratio * 7 + 1, compress_size=7)]
    past["ratio from nothing"] = [Entry("r.bin", file_size=1, compress_size=0)]
    at["member"] = [Entry("m.bin", file_size=member, compress_size=member)]
    past["member"] = [Entry("m.bin", file_size=member + 1, compress_size=member + 1)]
    third = total // 3
    at["total"] = [
        Entry(f"t{i}.bin", file_size=s, compress_size=s) for i, s in enumerate((third, third, total - 2 * third))
    ]
    past["total"] = [
        Entry(f"t{i}.bin", file_size=s, compress_size=s) for i, s in enumerate((third, third, total - 2 * third + 1))
    ]
    at["count"] = [Entry(f"c{i}.txt") for i in range(count)]
    past["count"] = [Entry(f"c{i}.txt") for i in range(count + 1)]
    # A directory entry is not a member and not counted.
    at["count with a directory"] = [Entry("d/", b"")] + [Entry(f"d/c{i}.txt") for i in range(count)]
    got_at = {label: _validates(tmp_path, f"at-{i}", entries) for i, (label, entries) in enumerate(at.items())}
    got_past = {label: _validates(tmp_path, f"past-{i}", entries) for i, (label, entries) in enumerate(past.items())}
    assert got_at == {label: None for label in at}
    assert got_past == {label: "archive_safety_limit" for label in past}


# ---- each rule alone ---------------------------------------------------------------------------


def _backslash(entry: Entry) -> Entry:
    return replace(entry, raw_name=entry.name.replace("/", "\\").encode())


def _breaking(rule: str, bounds: dict[str, int]) -> tuple[list[Entry], Entry]:
    """Entries to put before the probe, and the probe entry, which breaks ``rule`` alone."""
    ratio, member, total, count = bounds["ratio"], bounds["member"], bounds["total"], bounds["count"]
    if rule == "name":
        return [], _backslash(Entry("sub/x.bin"))
    if rule == "type":
        return [], Entry("x.bin", mode=stat.S_IFLNK | 0o777)
    if rule == "method":
        return [], Entry("x.bin", b"x" * 64, method=BZIP2)
    if rule == "member size":
        return [], Entry("x.bin", file_size=member + 1, compress_size=member + 1)
    if rule == "ratio":
        return [], Entry("x.bin", file_size=ratio * 10 + 1, compress_size=10)
    if rule == "duplicate":
        return [Entry("dup.bin")], Entry("DUP.BIN")
    if rule == "count":
        return [Entry(f"f{i}.txt") for i in range(count)], Entry("x.bin")
    if rule == "total":
        # Up to 5 bytes below the total bound, in entries within the per-member bound.
        fill, sizes = total - 5, []
        while fill:
            sizes.append(min(fill, member))
            fill -= sizes[-1]
        before = [Entry(f"big{i}.bin", file_size=s, compress_size=s) for i, s in enumerate(sizes)]
        return before, Entry("x.bin", file_size=6, compress_size=6)
    raise AssertionError(f"no probe for the rule {rule!r}")


def test_each_rule_alone_gives_its_error(tmp_path: Path) -> None:
    rules = _rules()
    bounds = _bounds()
    base = _bundle_entries()
    # The bundle's own members count towards the file-entry and total bounds: leave room for them.
    used = sum(len(entry.data) for entry in base)
    bounds = {**bounds, "count": bounds["count"] - len(base), "total": bounds["total"] - used}
    clean = _run(tmp_path, "clean", base)
    assert clean["status"] == "OFFLINE_OK", clean["errors"]
    got, expected = {}, {}
    for rule, error in rules:
        before, probe = _breaking(rule, bounds)
        got[rule] = _refused_with(_run(tmp_path, f"rule-{rule}", base + before + [probe]))
        expected[rule] = error
    assert got == expected
    assert [rule for rule, _ in rules] == [
        "name", "type", "method", "member size", "ratio", "duplicate", "count", "total"
    ]  # fmt: skip


# ---- the order ---------------------------------------------------------------------------------


def _combine(first: str, second: str, bounds: dict[str, int]) -> tuple[list[Entry], Entry]:
    """Entries and one probe entry that breaks both rules at once."""
    before: list[Entry] = []
    probe = Entry("x.bin")
    for rule in (first, second):
        extra, alone = _breaking(rule, bounds)
        if rule != "duplicate":  # its pair is chosen below
            before += extra
        if rule == "name":
            probe = replace(probe, name="sub/x.bin", raw_name=b"sub\\x.bin")
        elif rule == "type":
            probe = replace(probe, mode=alone.mode)
        elif rule == "method":
            probe = replace(probe, method=BZIP2, data=b"x" * 64)
        elif rule in {"member size", "ratio", "total"}:
            probe = replace(probe, file_size=alone.file_size, compress_size=alone.compress_size)
    if "duplicate" in (first, second):
        # The probe folds to the name of an entry before it; an added entry only when there is none.
        if before:
            probe = replace(probe, name=before[0].name.upper())
        else:
            before = [Entry("X.BIN")]
    return before, probe


def test_within_an_entry_the_rule_listed_first_decides(tmp_path: Path) -> None:
    rules = _rules()
    order = [rule for rule, _ in rules]
    errors = dict(rules)
    bounds = _bounds()
    pairs = [(a, b) for a, b in itertools.combinations(order, 2) if errors[a] != errors[b]]
    assert len(pairs) == 15, pairs
    got, expected = {}, {}
    for a, b in pairs:
        before, probe = _combine(a, b, bounds)
        label = f"{a}+{b}"
        got[label] = _validates(tmp_path, label.replace(" ", "_"), before + [probe])
        expected[label] = errors[min(a, b, key=order.index)]
    assert got == expected


def test_an_earlier_entry_decides_over_a_later_one(tmp_path: Path) -> None:
    ratio = Entry("r.bin", file_size=1000, compress_size=1)
    name = _backslash(Entry("sub/x.bin"))
    assert _validates(tmp_path, "ratio-then-name", [ratio, name]) == "archive_safety_limit"
    assert _validates(tmp_path, "name-then-ratio", [name, ratio]) == "archive_unsafe_member"


# ---- names, types and folding ------------------------------------------------------------------


def test_names_are_held_to_the_portable_member_name_rule_and_nothing_is_rewritten(tmp_path: Path) -> None:
    rows = table(document(SPEC), ["member name", "a portable member name"])
    got, expected = {}, {}
    for row in rows:
        name = json.loads(code(row["member name"]))
        if name.endswith("/"):
            continue  # in an archive a final "/" makes a directory entry, read without it
        raw = name.encode("utf-8", "surrogatepass")
        # A name that is not ASCII is recorded as UTF-8, bit 11 set, as an archiver records it.
        entry = Entry("p.bin", raw_name=raw, flags=0 if name.isascii() else 0x800)
        got[name] = _validates(tmp_path, f"name-{len(got)}", [entry]) is None
        expected[name] = row["a portable member name"] == "yes"
    assert got == expected
    assert set(expected.values()) == {True, False}
    # A directory entry's name is read without its final "/", and only that one.
    assert _validates(tmp_path, "dir", [Entry("data/", b"")]) is None
    assert _validates(tmp_path, "dir2", [Entry("data//", b"")]) == "archive_unsafe_member"
    # The name as recorded: a NUL is not a place to stop reading it.
    assert _validates(tmp_path, "nul", [Entry("p.bin", raw_name=b"p.bin\x00.txt")]) == "archive_unsafe_member"


# Each clause of the rule, at its boundary and one past it: the name at the boundary passes the
# rule name, the one past it is refused by it.
_CLAUSES = {
    "every character of the set": ("AZaz09._-", "AZaz09._-+"),
    "a segment of one character": ("a/b", "a//b"),
    "a dot segment": ("a/.b", "a/./b"),
    "a parent segment": ("a/..b", "a/../b"),
    "a final dot": ("a.b", "a.b."),
    "a leading hyphen": ("a-b", "-ab"),
    "a device name with an extension": ("con1.txt", "con.txt"),
    "a device name in another case": ("COM0", "cOm9"),
    "a device name as a directory": ("lpt/x", "LPT1/x"),
    "a device name whole": ("auxx", "AUX"),
    "a device name before its first dot": ("x.con", "CON.x.y"),
    "the delete byte": ("z", "z\x7f"),
    "a byte from 0x80": ("x", "x\x80"),
    "a tilde": ("x_1", "x~1"),
    "a space": ("a_b", "a b"),
}


def test_each_clause_of_the_rule_at_its_boundary_and_one_past_it(tmp_path: Path) -> None:
    got = {}
    for i, (label, (at, past)) in enumerate(_CLAUSES.items()):
        got[label] = (
            _validates(tmp_path, f"clause-at-{i}", [Entry("p.bin", raw_name=at.encode("latin-1"))]),
            _validates(tmp_path, f"clause-past-{i}", [Entry("p.bin", raw_name=past.encode("latin-1"))]),
        )
    assert got == dict.fromkeys(_CLAUSES, (None, "archive_unsafe_member"))


def test_a_name_is_judged_as_bytes_whatever_bit_11_says(tmp_path: Path) -> None:
    """bundle-objects.md section 5: a byte that is not the ASCII code of a portable character breaks
    the rule name, whatever bit 11 says. A name read as UTF-8 under one flag and as code page 437
    under the other, and a control byte some charts draw as a graphic character, are both refused
    from their bytes, so no table decides them."""
    flat = " ".join(document(SPEC).split())
    assert "whatever bit 11 of the entry's general-purpose flags says" in flat
    cases = {
        "a UTF-8 name, bit 11 set": (b"caf\xc3\xa9.json", 0x800),
        "the UTF-8 bytes, bit 11 clear": (b"caf\xc3\xa9.json", 0),
        "bytes that are not UTF-8, bit 11 set": (b"\x81x.bin", 0x800),
        "bytes that are not UTF-8, bit 11 clear": (b"\x81x.bin", 0),
        "a control byte": (b"x\x01.json", 0),
        "the delete byte": (b"x\x7f.json", 0),
    }
    got = {
        label: _validates(tmp_path, f"bytes-{i}", [Entry("x.bin", raw_name=raw, flags=flags)])
        for i, (label, (raw, flags)) in enumerate(cases.items())
    }
    assert got == dict.fromkeys(cases, "archive_unsafe_member")
    portable = {"bit 11 set": 0x800, "bit 11 clear": 0}
    got = {
        label: _validates(tmp_path, f"ascii-{i}", [Entry("x.bin", raw_name=b"x.bin", flags=flags)])
        for i, (label, flags) in enumerate(portable.items())
    }
    assert got == dict.fromkeys(portable)
    undecodable = Entry("x.bin", raw_name=b"\x81x.bin", flags=0x800)
    assert _refused_with(_run(tmp_path, "not-portable", [*_bundle_entries(), undecodable])) == "archive_unsafe_member"
    order = {
        "an earlier entry breaks the rule method": (
            [Entry("m.bin", b"x" * 64, method=BZIP2), undecodable],
            "archive_safety_limit",
        ),
        "a later entry breaks the rule method": (
            [undecodable, Entry("m.bin", b"x" * 64, method=BZIP2)],
            "archive_unsafe_member",
        ),
    }
    got = {label: _validates(tmp_path, f"order-{i}", entries) for i, (label, (entries, _)) in enumerate(order.items())}
    assert got == {label: error for label, (_, error) in order.items()}
    with pytest.raises(archive.UnsafeZipMemberError):
        archive.read_zip_member_bytes(write_zip(tmp_path / "read.zip", [undecodable]), "x.bin")


def test_a_recorded_file_type_must_be_the_one_the_name_declares(tmp_path: Path) -> None:
    cases = {
        "regular file": (Entry("f.bin", mode=stat.S_IFREG | 0o644), None),
        "no type recorded": (Entry("f.bin", mode=0o644), None),
        "directory": (Entry("d/", b"", mode=stat.S_IFDIR | 0o755), None),
        "symbolic link": (Entry("f.bin", mode=stat.S_IFLNK | 0o777), "archive_unsafe_member"),
        "FIFO": (Entry("f.bin", mode=stat.S_IFIFO | 0o644), "archive_unsafe_member"),
        "directory type on a file name": (Entry("f.bin", mode=stat.S_IFDIR | 0o755), "archive_unsafe_member"),
        "file type on a directory name": (Entry("d/", b"", mode=stat.S_IFREG | 0o644), "archive_unsafe_member"),
    }
    got = {label: _validates(tmp_path, f"type-{i}", [entry]) for i, (label, (entry, _)) in enumerate(cases.items())}
    assert got == {label: error for label, (_, error) in cases.items()}


def test_an_encrypted_entry_and_the_two_methods(tmp_path: Path) -> None:
    assert _validates(tmp_path, "stored", [Entry("f.bin", method=STORED)]) is None
    assert _validates(tmp_path, "deflated", [Entry("f.bin", b"abc", method=DEFLATED)]) is None
    assert _validates(tmp_path, "encrypted", [Entry("f.bin", flags=0x1)]) == "archive_safety_limit"


def test_folded_names_and_implied_directories(tmp_path: Path) -> None:
    flat = " ".join(document(SPEC).split())
    assert "`a/b/c` implies `a` and `a/b`" in flat
    assert "with each of the letters `A` to `Z` read as its lower-case letter and nothing else changed" in flat
    cases = {
        "case variant": ([Entry("p1.json"), Entry("P1.JSON")], "archive_unsafe_member"),
        "two names that differ beyond case": ([Entry("p1.json"), Entry("p2.json")], None),
        "a file, then a name inside it": ([Entry("a"), Entry("a/b")], "archive_unsafe_member"),
        "a name, then a file it implies": ([Entry("a/b"), Entry("A")], "archive_unsafe_member"),
        "a directory entry twice": ([Entry("a/", b""), Entry("a/", b"")], "archive_unsafe_member"),
        "a directory entry, then a file of that name": ([Entry("a/", b""), Entry("a")], "archive_unsafe_member"),
        "a directory entry, then a name inside it": ([Entry("a/", b""), Entry("a/b")], None),
        "a name, then its directory entry": ([Entry("a/b"), Entry("a/", b"")], None),
    }
    got = {label: _validates(tmp_path, f"fold-{i}", entries) for i, (label, (entries, _)) in enumerate(cases.items())}
    assert got == {label: error for label, (_, error) in cases.items()}


# ---- the length of a name ----------------------------------------------------------------------

# Each name's bytes, as the rule counts them: at the bound, then one past it.
_AT_THE_BOUND = {
    "one segment": "s" * 250 + ".json",
    "short segments": "/".join(["d" * 49] * 5) + "/x.jso",
}
_PAST_THE_BOUND = {
    "one segment": "s" * 251 + ".json",
    "short segments": "/".join(["d" * 49] * 5) + "/x.json",
}


def test_a_name_is_bounded_at_255_bytes_and_extracts_under_any_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flat = " ".join(document(SPEC).split())
    assert "the whole name is at most 255 bytes" in flat
    assert archive.MAX_ZIP_MEMBER_NAME_BYTES == 255
    assert {len(name.encode()) for name in _AT_THE_BOUND.values()} == {255}
    assert {len(name.encode()) for name in _PAST_THE_BOUND.values()} == {256}
    # Left to the host, the verdict would be the host's: on a Windows host without long paths a
    # name at the bound extracts under a short temporary directory and fails, archive_load_failed,
    # under a longer one. Each name is judged here under a temporary directory 101 characters longer than
    # pytest's own.
    deep = tmp_path / ("t" * 100)
    deep.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(deep))
    got = {}
    for label, name in {
        **{f"at: {k}": v for k, v in _AT_THE_BOUND.items()},
        **{f"past: {k}": v for k, v in _PAST_THE_BOUND.items()},
    }.items():
        report = _run(tmp_path, f"length-{len(got)}", [*_bundle_entries(), Entry(name)])
        got[label] = (
            report["status"],
            [error["code"] for error in report["errors"]],
            "bundle_extra_files" in report["notes"],
        )
    review = ("OFFLINE_REVIEW", [], True)
    refused = ("OFFLINE_FAIL", ["archive_unsafe_member"], False)
    assert got == {
        **{f"at: {k}": review for k in _AT_THE_BOUND},
        **{f"past: {k}": refused for k in _PAST_THE_BOUND},
    }
    # A directory entry's name is counted without its final "/".
    assert _validates(tmp_path, "dir-at", [Entry("d" * 255 + "/", b"")]) is None
    assert _validates(tmp_path, "dir-past", [Entry("d" * 256 + "/", b"")]) == "archive_unsafe_member"


def _rewrite(path: Path, *, zip64: str | None = None, **record: Any) -> Path:
    """``path``, written by write_zip, rewritten byte by byte: each key of ``record`` sets one field of
    the LAST entry's central-directory record ("version", "extra", "local_name", "payload",
    "header_offset", and "local_extra", the extra field of its local header; "end_offset_delta" moves the end record's central-directory offset), and ``zip64`` adds the ZIP64 end records: "real" with the true counts in the
    end record, "ffff" with 0xFFFF and 0xFFFFFFFF there, "two_disks", "locator_off" with the
    locator's offset seven bytes off.
    """
    data = path.read_bytes()
    end = data.rindex(b"PK\x05\x06")
    _, _, _, count, _, size, offset, _ = struct.unpack("<4s4H2LH", data[end : end + 22])
    body, central = bytearray(data[:offset]), bytearray(data[offset : offset + size])
    last = central.rindex(b"PK\x01\x02")
    (local,) = struct.unpack("<L", central[last + 42 : last + 46])
    name_length = struct.unpack("<H", central[last + 28 : last + 30])[0]
    if "version" in record:
        central[last + 6 : last + 8] = struct.pack("<H", record["version"])
        body[local + 4 : local + 6] = struct.pack("<H", record["version"])
    if "local_name" in record:
        assert len(record["local_name"]) == name_length
        body[local + 30 : local + 30 + name_length] = record["local_name"]
    if "payload" in record:
        packed = struct.unpack("<L", central[last + 20 : last + 24])[0]
        assert len(record["payload"]) == packed
        body[local + 30 + name_length : local + 30 + name_length + packed] = record["payload"]
    if "header_offset" in record:
        central[last + 42 : last + 46] = struct.pack("<L", record["header_offset"])
    if "extra" in record:
        extra = record["extra"]
        central[last + 30 : last + 32] = struct.pack("<H", len(extra))
        central[last + 46 + name_length : last + 46 + name_length] = extra
    if "local_extra" in record:
        # The last entry's local header and data close the body, so nothing after it moves.
        extra = record["local_extra"]
        assert struct.unpack("<H", body[local + 28 : local + 30])[0] == 0
        body[local + 28 : local + 30] = struct.pack("<H", len(extra))
        body[local + 30 + name_length : local + 30 + name_length] = extra
    tail = b""
    if zip64:
        at = len(body) + len(central)
        disks = 2 if zip64 == "two_disks" else 1
        located = at + (7 if zip64 == "locator_off" else 0)
        tail = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, len(central), len(body))
        tail += struct.pack("<4sLQL", b"PK\x06\x07", 0, located, disks)
    if zip64 == "ffff":
        closing = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    else:
        closing = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, count, count, len(central), len(body), 0)
    path.write_bytes(bytes(body + central + tail + closing))
    return path


def _outcome(path: Path) -> str:
    report = verify_path(path).to_dict()
    return report["outcome"]["reason"] if report["status"] == "OFFLINE_FAIL" else report["status"]


def test_an_undecodable_name_is_found_in_a_zip64_archive(tmp_path: Path) -> None:
    """The ZIP64 end record and locator stand between the central directory and the end record.

    Looked for from the end record alone, the entry whose name is not the UTF-8 bit 11 says would
    not be found in a ZIP64 archive, and UnicodeDecodeError would escape the verifier,
    internal_error on the command line, whatever the end record held.
    """
    undecodable = Entry("x.bin", raw_name=b"\xed\xa0\x80x.bin", flags=0x800)
    method = Entry("m.bin", b"x" * 64, method=BZIP2)
    cases = {
        "real counts in the end record": ([undecodable], "real", "archive_unsafe_member"),
        "0xFFFF in the end record": ([undecodable], "ffff", "archive_unsafe_member"),
        "an earlier entry breaks the rule method": ([method, undecodable], "ffff", "archive_safety_limit"),
        "a later entry breaks the rule method": ([undecodable, method], "ffff", "archive_unsafe_member"),
    }
    got = {}
    for i, (label, (extra, zip64, _)) in enumerate(cases.items()):
        path = _rewrite(write_zip(tmp_path / f"zip64-{i}.zip", [*_bundle_entries(), *extra]), zip64=zip64)
        got[label] = _refused_with(verify_path(path).to_dict())
    assert got == {label: error for label, (_, _, error) in cases.items()}
    clean = _rewrite(write_zip(tmp_path / "zip64-clean.zip", _bundle_entries()), zip64="real")
    assert _outcome(clean) == "OFFLINE_OK"


def test_an_archive_zipfile_cannot_read_is_invalid_zip(tmp_path: Path) -> None:
    """Bytes that are not a readable ZIP archive are invalid_zip (report-contract.md section 5.3).

    bundle-objects.md section 5 says so of data that does not decompress to what its record states,
    found while extracting. zipfile raises more than BadZipFile on such bytes, zlib.error,
    EOFError, NotImplementedError, OSError on a negative seek, and each is invalid_zip, not an
    exception escaping the verifier, internal_error on the command line, nor filesystem_error, a
    failure of the host, on bytes the host has read. Under Python 3.11 and 3.12 zipfile also
    accepts ZIP64 end records that Python 3.13 refuses, so left to zipfile one archive would get
    two verdicts.
    """
    flat = " ".join(document(SPEC).split())
    assert "is not a readable ZIP archive, `invalid_zip`" in flat
    added = Entry("y.bin", b"abc" * 100, method=DEFLATED)
    packed = len(_payload(added))
    cases: dict[str, tuple[Entry, dict[str, Any]]] = {
        "data that is not a deflate stream": (added, {"payload": b"\xff" * packed}),
        "a deflate stream that ends early": (added, {"payload": _payload(added)[:3] + b"\x00" * (packed - 3)}),
        "a version needed to extract above 6.3": (Entry("v.bin"), {"version": 64}),
        "flag bit 5": (Entry("f.bin", flags=0x20), {}),
        "flag bit 6": (Entry("f.bin", flags=0x40), {}),
        "a local header name that is not UTF-8": (Entry("l.bin", flags=0x800), {"local_name": b"\xed\xa0\x80\x2e\x62"}),
        "a header offset past the archive": (Entry("o.bin"), {"header_offset": 0xFFFFFF00}),
        "a ZIP64 locator recording two disks": (Entry("z.bin"), {"zip64": "two_disks"}),
        "a ZIP64 locator seven bytes off": (Entry("z.bin"), {"zip64": "locator_off"}),
    }
    got = {}
    for i, (label, (entry, record)) in enumerate(cases.items()):
        path = _rewrite(write_zip(tmp_path / f"unreadable-{i}.zip", [*_bundle_entries(), entry]), **record)
        got[label] = _outcome(path)
    assert got == dict.fromkeys(cases, "invalid_zip")


def test_an_extra_field_that_can_carry_a_name_is_refused(tmp_path: Path) -> None:
    """bundle-objects.md section 5, "Extra fields": a central-directory record may hold only ZIP64
    extended information, NTFS times, an extended timestamp and Info-ZIP UNIX ownership.

    zipfile reads the Info-ZIP Unicode Path field (0x7075) as the entry's name from Python 3.12 and
    ignores it under 3.11, and Info-ZIP's unzip honors it too: an archive whose field names another
    spelling would be extracted under one name or the other depending on the reader. Every other field
    is refused with it, because a field this rule does not list may carry a name."""
    flat = " ".join(document(SPEC).split())
    assert "| 0x7875 | Info-ZIP UNIX owner and group |" in flat
    unicode_path = struct.pack("<HHBL", 0x7075, 5 + len(b"manifest.json"), 1, zlib.crc32(b"u.bin")) + b"manifest.json"
    refused = {
        "a Unicode Path field naming another spelling": unicode_path,
        "a Unicode Path field too short": struct.pack("<HH", 0x7075, 2) + b"\x01\x00",
        "a Unicode Path field that is not UTF-8": struct.pack("<HHBL", 0x7075, 7, 1, zlib.crc32(b"u.bin"))
        + b"\xff\xfe",
        "a Unicode Comment field": struct.pack("<HH", 0x6375, 5) + b"\x01abcd",
        "a field no table lists": struct.pack("<HH", 0xCAFE, 1) + b"\x00",
        "a listed field, then one no table lists": struct.pack("<HH", 0x5455, 5)
        + b"\x01"
        + bytes(4)
        + struct.pack("<HH", 0xCAFE, 0),
    }
    admitted = {
        "ZIP64 extended information": struct.pack("<HH", 0x0001, 8) + b"\x07" * 8,
        "NTFS times": struct.pack("<HH", 0x000A, 32) + bytes(4) + struct.pack("<HH", 1, 24) + bytes(24),
        "an extended timestamp": struct.pack("<HH", 0x5455, 5) + b"\x01" + bytes(4),
        "Info-ZIP UNIX owner and group": struct.pack("<HHBB", 0x7875, 11, 1, 4) + bytes(4) + b"\x04" + bytes(4),
        "an empty extra field": b"",
    }
    got = {}
    for i, (label, field) in enumerate({**refused, **admitted}.items()):
        path = _rewrite(write_zip(tmp_path / f"extra-{i}.zip", [*_bundle_entries(), Entry("u.bin")]), extra=field)
        got[label] = _outcome(path)
    assert got == {**dict.fromkeys(refused, "archive_unsafe_member"), **dict.fromkeys(admitted, "OFFLINE_REVIEW")}
    # The same fields in the local header alone: the header does not hold what the record judged,
    # and the archive is not a readable ZIP archive.
    got = {}
    for i, (label, field) in enumerate(
        {"a Unicode Path field": unicode_path, "an extended timestamp": admitted["an extended timestamp"]}.items()
    ):
        path = _rewrite(write_zip(tmp_path / f"local-{i}.zip", [*_bundle_entries(), Entry("u.bin")]), local_extra=field)
        got[label] = _outcome(path)
    assert got == {"a Unicode Path field": "invalid_zip", "an extended timestamp": "OFFLINE_REVIEW"}


def test_one_directory_spelled_two_ways_is_refused(tmp_path: Path) -> None:
    """A host that folds writes data/y.json under DATA, where the member is not found; one that
    does not makes two directories. Admitted, the same archive would be OFFLINE_FAIL on the first
    and OFFLINE_OK or OFFLINE_REVIEW on the second."""
    flat = " ".join(document(SPEC).split())
    assert "names or implies and the two are spelled differently" in flat
    cases = {
        "a directory entry, then a file under another spelling": (
            [Entry("DATA/", b""), Entry("data/y.json")],
            "archive_unsafe_member",
        ),
        "an implied directory, then another spelling": (
            [Entry("Sub/a.json"), Entry("sub/b.json")],
            "archive_unsafe_member",
        ),
        "a deeper directory in another case": ([Entry("a/b/x.json"), Entry("a/B/y.json")], "archive_unsafe_member"),
        "an outer directory in another case": ([Entry("a/b/x.json"), Entry("A/b/y.json")], "archive_unsafe_member"),
        "a directory entry under another spelling, after a file": (
            [Entry("d/x.json"), Entry("D/", b"")],
            "archive_unsafe_member",
        ),
        "one spelling throughout": ([Entry("d/", b""), Entry("d/x.json"), Entry("d/y.json")], None),
    }
    got = {
        label: _validates(tmp_path, f"respelled-{i}", entries) for i, (label, (entries, _)) in enumerate(cases.items())
    }
    assert got == {label: error for label, (_, error) in cases.items()}
    respelled = [*_bundle_entries(), Entry("DATA/", b""), Entry("data/y.json")]
    assert _refused_with(_run(tmp_path, "respelled-bundle", respelled)) == "archive_unsafe_member"


@pytest.mark.parametrize("prefix", ["", "bundle/"])
def test_an_archive_that_passes_every_rule_verifies(tmp_path: Path, prefix: str) -> None:
    entries = [replace(entry, name=prefix + entry.name) for entry in _bundle_entries()]
    if prefix:
        entries = [Entry(prefix, b"", mode=stat.S_IFDIR | 0o755)] + entries
    report = _run(tmp_path, f"pass-{bool(prefix)}", entries)
    assert (report["status"], report["errors"]) == ("OFFLINE_OK", [])


# ---- reading the archive (bundle-objects.md section 5, "Reading the archive") --------------------


def _end(data: bytes) -> int:
    return data.rindex(b"PK\x05\x06")


def _set_end(data: bytes, **fields: int) -> bytes:
    """``data`` with fields of its end record replaced: disk, directory_disk, on_disk, count."""
    end = _end(data)
    values = list(struct.unpack("<4s4H2LH", data[end : end + 22]))
    for key, index in {"disk": 1, "directory_disk": 2, "on_disk": 3, "count": 4}.items():
        if key in fields:
            values[index] = fields[key]
    return data[:end] + struct.pack("<4s4H2LH", *values) + data[end + 22 :]


def _two_entries_one_local_header(data: bytes) -> bytes:
    """``data`` with the last central record's local-header offset set to the first entry's, and
    its name made the first entry's, so both records read one local header and one data range."""
    end = _end(data)
    _, _, _, _, _, size, offset, _ = struct.unpack("<4s4H2LH", data[end : end + 22])
    central = bytearray(data[offset : offset + size])
    last = central.rindex(b"PK\x01\x02")
    central[last + 42 : last + 46] = struct.pack("<L", 0)
    return data[:offset] + bytes(central) + data[offset + size :]


def test_the_archive_is_read_as_section_5_states(tmp_path: Path) -> None:
    """Bytes section 5 does not read as a ZIP archive are invalid_zip, before any rule.

    Python's zipfile accepts each of these: bytes before the archive (it moves every offset by
    them), bytes after the end record, an end record naming another disk or miscounting the
    entries, an extra field running short, and two records naming one local header, which
    extracts one byte range twice. A verifier on another ZIP reader would refuse some and accept
    others, and reach another verdict on the same bytes.
    """
    flat = " ".join(document(SPEC).split())
    assert "**Reading the archive.**" in flat
    assert "only bits 0, 5 and 6 are" in flat
    assert "holds the ZIP64 extended information extra field more than once" in flat
    bundle = write_zip(tmp_path / "base.zip", [*_bundle_entries(), Entry("x.bin"), Entry("x2.bin")])
    data = bundle.read_bytes()
    entries = _bundle_entries()
    cases = {
        "bytes before the archive": b"\x00" * 100 + data,
        "bytes after the end record": data + b"\x00" * 64,
        "an end record naming disk 1": _set_end(data, disk=1, directory_disk=1),
        "an end record counting one entry fewer": _set_end(data, count=len(entries) + 1, on_disk=len(entries) + 1),
        "counts on this disk and in total that differ": _set_end(data, on_disk=len(entries) + 1),
        "two records naming one local header": _two_entries_one_local_header(data),
    }
    got = {}
    for i, (label, content) in enumerate(cases.items()):
        path = tmp_path / f"read-{i}.zip"
        path.write_bytes(content)
        got[label] = _outcome(path)
    short_extra = _rewrite(write_zip(tmp_path / "extra.zip", [*entries, Entry("e.bin")]), extra=b"\x01\x02\x03")
    got["an extra field area that no field fills"] = _outcome(short_extra)
    widened = write_zip(tmp_path / "wide.zip", [*entries, Entry("w.bin", file_size=0xFFFFFFFF, compress_size=1)])
    got["a size of 0xFFFFFFFF with no ZIP64 extra field"] = _outcome(widened)
    # The ZIP64 extended information field held twice: one reader takes the first, another the
    # last, so one entry has two sizes. Refused whether a value is read from it or not.
    zip64 = [struct.pack("<HHQ", 0x0001, 8, size) for size in (1, 2)]
    for i, (label, file_size) in enumerate(
        {"two ZIP64 fields, no value read": None, "two ZIP64 fields, the size read": 0xFFFFFFFF}.items()
    ):
        twice = write_zip(tmp_path / f"twice-{i}.zip", [*entries, Entry("t.bin", file_size=file_size)])
        got[label] = _outcome(_rewrite(twice, extra=b"".join(zip64)))
    assert got == dict.fromkeys(got, "invalid_zip")
    # What section 5 does not read: an end record comment, and a ZIP64 extra field where no field
    # holds 0xFFFFFFFF.
    commented = _end(data)
    with_comment = tmp_path / "comment.zip"
    with_comment.write_bytes(data[: commented + 20] + struct.pack("<H", 5) + b"hello")
    assert _outcome(with_comment) == "OFFLINE_REVIEW"
    # The record is the one at the last signature in the archive. A comment that holds three of
    # its four bytes is still only a comment; one that holds the whole signature, or a second
    # record whose own comment would run past the last byte, is refused, since a reader that
    # takes the last signature reads another central directory there.
    signature = b"PK\x05\x06"

    def comment(text: bytes) -> bytes:
        return data[: commented + 20] + struct.pack("<H", len(text)) + text

    partial = tmp_path / "partial.zip"
    partial.write_bytes(comment(signature[:3] + b"!"))
    assert _outcome(partial) == "OFFLINE_REVIEW"
    in_comment = {
        "the signature alone": signature,
        "a second record running past the last byte": data[commented : commented + 20] + struct.pack("<H", 7),
        "a second record ending at the last byte": data[commented : commented + 20] + struct.pack("<H", 0),
    }
    for i, text in enumerate(in_comment.values()):
        path = tmp_path / f"signature-{i}.zip"
        path.write_bytes(comment(text))
        assert _outcome(path) == "invalid_zip", text
    unread = _rewrite(
        write_zip(tmp_path / "unread.zip", [*entries, Entry("u.bin")]),
        extra=struct.pack("<HH", 0x0001, 8) + b"\x07" * 8,
    )
    assert _outcome(unread) == "OFFLINE_REVIEW"


def _insert(data: bytes, at: int, blob: bytes) -> bytes:
    """``data`` with ``blob`` inserted at offset ``at`` and every recorded offset at or after it
    moved by its length, so each local header and the central directory stand where the records
    say: the archive is exact but for the bytes no entry accounts for."""
    end = _end(data)
    _, _, _, _, count, _, directory, _ = struct.unpack("<4s4H2LH", data[end : end + 22])
    shift = len(blob)

    def moved(offset: int) -> int:
        return offset + shift if offset >= at else offset

    out = bytearray(data[:at] + blob + data[at:])
    struct.pack_into("<L", out, moved(end) + 16, moved(directory))
    position = directory
    for _ in range(count):
        name, extra, comment = struct.unpack_from("<3H", data, position + 28)
        (local,) = struct.unpack_from("<L", data, position + 42)
        struct.pack_into("<L", out, moved(position) + 42, moved(local))
        position += 46 + name + extra + comment
    return bytes(out)


def test_every_byte_before_the_central_directory_belongs_to_an_entry(tmp_path: Path) -> None:
    """Bytes no entry accounts for are invalid_zip, wherever they stand and whatever their offsets.

    Python's zipfile reads each of these archives, and with every offset counting the inserted
    bytes the central directory still ends where its end record starts: a self-extracting stub
    before the first entry, bytes between two entries, and bytes before the central directory.
    A data descriptor after an entry's data is the one thing that may stand there, and only when
    it repeats the CRC-32 and sizes the record states.
    """
    flat = " ".join(document(SPEC).split())
    assert "stands at the file's first byte" in flat
    assert "one data descriptor" in flat
    entries = [*_bundle_entries(), Entry("x.bin"), Entry("x2.bin")]
    data = write_zip(tmp_path / "base.zip", entries).read_bytes()
    assert _outcome(tmp_path / "base.zip") == "OFFLINE_REVIEW"
    directory = struct.unpack("<L", data[_end(data) + 16 : _end(data) + 20])[0]
    second = data.index(b"PK\x03\x04", 4)
    last = data.rindex(b"PK\x03\x04", 0, directory)
    (last_entry,) = [entry for entry in entries if entry.name == "x2.bin"]
    crc, size = zlib.crc32(last_entry.data), len(last_entry.data)
    descriptor = struct.pack("<3L", crc, size, size)
    stub = b"MZ" + bytes(62)
    cases = {
        "a stub before the first entry": (_insert(data, 0, stub), "invalid_zip"),
        "bytes between two entries": (_insert(data, second, bytes(16)), "invalid_zip"),
        "bytes before the central directory": (_insert(data, directory, bytes(16)), "invalid_zip"),
        "one byte before the central directory": (_insert(data, directory, b"\x00"), "invalid_zip"),
        "a descriptor that does not match": (
            _insert(data, directory, struct.pack("<3L", crc ^ 1, size, size)),
            "invalid_zip",
        ),
        "a descriptor followed by one more byte": (_insert(data, directory, descriptor + b"\x00"), "invalid_zip"),
        "a descriptor": (_insert(data, directory, descriptor), "OFFLINE_REVIEW"),
        "a descriptor with its signature": (_insert(data, directory, b"PK\x07\x08" + descriptor), "OFFLINE_REVIEW"),
        "a descriptor with 8-byte sizes": (
            _insert(data, directory, b"PK\x07\x08" + struct.pack("<L2Q", crc, size, size)),
            "OFFLINE_REVIEW",
        ),
        "a descriptor between two entries": (
            _insert(data, last, struct.pack("<3L", zlib.crc32(b"x"), 1, 1)),
            "OFFLINE_REVIEW",
        ),
    }
    got = {}
    for i, (label, (content, _)) in enumerate(cases.items()):
        path = tmp_path / f"gap-{i}.zip"
        path.write_bytes(content)
        got[label] = _outcome(path)
    assert got == {label: expected for label, (_, expected) in cases.items()}


def _set_crc(path: Path, name: bytes, crc: int) -> None:
    data = bytearray(path.read_bytes())
    end = _end(bytes(data))
    _, _, _, _, _, size, offset, _ = struct.unpack("<4s4H2LH", data[end : end + 22])
    position = offset
    while position < offset + size:
        name_length, extra_length, comment_length = struct.unpack("<3H", data[position + 28 : position + 34])
        if data[position + 46 : position + 46 + name_length] == name:
            data[position + 16 : position + 20] = struct.pack("<L", crc)
        position += 46 + name_length + extra_length + comment_length
    path.write_bytes(bytes(data))


def test_data_must_give_exactly_the_size_and_crc_its_record_states(tmp_path: Path) -> None:
    """zipfile cuts a member's data at the size its record states and checks the CRC-32 of what it
    returns. Left to zipfile, a stored member shorter or longer than stated, a deflate stream giving
    more or fewer bytes, or followed by more data, would verify; a declared manifest.json whose
    stream holds one more byte would be read as the bytes its record states, OFFLINE_OK, where
    section 5 has invalid_zip."""
    flat = " ".join(document(SPEC).split())
    assert "deflated data is one deflate stream that ends at the data's last byte" in flat
    entries = _bundle_entries()
    manifest = next(entry for entry in entries if entry.name == "manifest.json")
    others = [entry for entry in entries if entry.name != "manifest.json"]
    longer = manifest.data + b" "
    cases = {
        "a declared member whose stream gives one byte more": [
            *others,
            Entry("manifest.json", longer, DEFLATED, file_size=len(manifest.data)),
        ],
        "a declared member that records one byte more": [
            *others,
            Entry("manifest.json", manifest.data, DEFLATED, file_size=len(manifest.data) + 1),
        ],
        "a stored member shorter than recorded": [*entries, Entry("s.bin", b"0123456789", file_size=15)],
        "a stored member longer than recorded": [*entries, Entry("s.bin", b"0123456789", file_size=9)],
        "a deflated member shorter than recorded": [*entries, Entry("d.bin", b"ab" * 150, DEFLATED, file_size=400)],
    }
    got = {}
    for i, (label, case) in enumerate(cases.items()):
        written = write_zip(tmp_path / f"size-{i}.zip", case)
        if label == "a declared member whose stream gives one byte more":
            # The record states the CRC-32 of the bytes its size gives, not of the stream's.
            _set_crc(written, b"manifest.json", zlib.crc32(manifest.data))
        got[label] = _outcome(written)
    padded = [
        *entries,
        Entry("t.bin", b"abc" * 100, DEFLATED, payload=_payload(Entry("t.bin", b"abc" * 100, DEFLATED)) + bytes(2)),
    ]
    trailing = write_zip(tmp_path / "trailing.zip", padded)
    got["a stream followed by more data"] = _outcome(trailing)
    assert got == dict.fromkeys(got, "invalid_zip")


def test_an_empty_unicode_path_field_gives_no_warning(tmp_path: Path) -> None:
    """zipfile from Python 3.12 reads the Unicode Path field (0x7075) of every entry and warns on an
    empty name in one; with warnings as errors the command line would exit 3 under 3.13 and 2 under
    3.11. The field is refused from the record, on every Python, and nothing reads it."""
    import warnings

    path = _rewrite(
        write_zip(tmp_path / "empty-unicode-path.zip", [*_bundle_entries(), Entry("u.bin")]),
        extra=struct.pack("<HHBL", 0x7075, 5, 1, zlib.crc32(b"u.bin")),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _outcome(path) == "archive_unsafe_member"


def test_an_unreadable_archive_leaves_nothing_in_the_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The extraction opens a member's file only after zipfile has opened the member: a file left
    open for a member zipfile cannot open would keep the extraction, on Windows, from being
    removed from the temporary directory, one per run."""
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(archive.tempfile, "tempdir", str(temporary))
    entries = [*_bundle_entries(), Entry("l.bin", flags=0x800)]
    renamed = _rewrite(write_zip(tmp_path / "local-name.zip", entries), local_name=b"m.bin")
    garbage = _rewrite(
        write_zip(tmp_path / "garbage.zip", [*_bundle_entries(), Entry("g.bin", b"abc" * 100, DEFLATED)]),
        payload=b"\xff" * len(_payload(Entry("g.bin", b"abc" * 100, DEFLATED))),
    )
    assert [_outcome(renamed), _outcome(garbage)] == ["invalid_zip", "invalid_zip"]
    assert list(temporary.iterdir()) == []


@pytest.mark.parametrize("first", [True, False])
def test_a_tilde_is_outside_the_set_so_no_short_name_shape_extracts(tmp_path: Path, first: bool) -> None:
    """MANIFE~1.JSO is the short name a Windows file system generates for manifest.json. On a host
    that generates short names, extracting it after manifest.json would open manifest.json
    (archive_unsafe_member) and before it would write a second file (OFFLINE_REVIEW), and a host
    without short names would always write a second file. "~" is outside the portable set, so every
    such shape is refused by the rule name, whatever follows the tilde."""
    flat = " ".join(document(SPEC).split())
    assert "`~`, with which Windows writes the short name it generates for a long one" in flat
    alias = Entry("MANIFE~1.JSO", b"{}")
    entries = [alias, *_bundle_entries()] if first else [*_bundle_entries(), alias]
    assert _refused_with(_run(tmp_path, f"short-{first}", entries)) == "archive_unsafe_member"
    shapes = ["VERIFI~1.JSO", "sub/DATA~12/x.json", "a~0", "a~b.json", "x~.json", "~x.json", "a~\uff11.json"]
    got = {name: _validates(tmp_path, f"shape-{i}", [Entry(name)]) for i, name in enumerate(shapes)}
    assert got == dict.fromkeys(shapes, "archive_unsafe_member")
