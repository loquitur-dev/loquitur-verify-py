"""Safe ZIP archive loading for the public Loquitur verifier package.

This module intentionally stops at archive safety and bundle-root discovery.
It does not parse or validate manifest semantics, P1, canonical input, envelope,
or registry entries.

The loader applies conservative archive input-safety hardening. These checks are
local verifier safety gates only; they do not implement issuer trust, registry
inclusion/finality, chain anchor verification, valuation correctness, or
compliance verification.
"""

from __future__ import annotations

import os
import shutil
import stat
import struct
import tempfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from .errors import LoquiturVerifyError
from .host_path import host_path
from .members import (
    MAX_MEMBER_BYTES,
    MAX_MEMBER_NAME_BYTES,
    MemberNameConflicts,
    member_name_problem,
    open_for_reading,
)

# The intake rules of bundle-objects.md §5, in the order that section lists them.
MAX_ZIP_FILE_COUNT = 512
MAX_ZIP_MEMBER_UNCOMPRESSED_BYTES = MAX_MEMBER_BYTES
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 100
ZIP_STORED = 0
ZIP_DEFLATED = 8
ALLOWED_ZIP_COMPRESSION_METHODS = {ZIP_STORED, ZIP_DEFLATED}
# The portable member-name rule bounds a name at 255 bytes (bundle-objects.md section 2), a
# directory entry's counted without its final "/".
MAX_ZIP_MEMBER_NAME_BYTES = MAX_MEMBER_NAME_BYTES
# The extra fields a central-directory record or a local header may hold (bundle-objects.md
# section 5, "Extra fields"): ZIP64 extended information, NTFS times, extended timestamp and
# Info-ZIP UNIX owner and group. None of them carries a name; another field may, as the Info-ZIP
# Unicode Path field (0x7075) does, and a reader honoring it extracts the entry under that
# spelling. zipfile reads 0x7075 from Python 3.12 and not under 3.11.
ALLOWED_EXTRA_FIELDS = frozenset({0x0001, 0x000A, 0x5455, 0x7875})
_ENCRYPTED_FLAG = 0x1
_POSIX_TYPE_MASK = 0o170000


class ArchiveLoadError(LoquiturVerifyError):
    """Base class for expected archive loading failures."""


class InvalidZipError(ArchiveLoadError):
    """Raised when the input is not a readable ZIP archive."""


class UnsafeZipMemberError(ArchiveLoadError):
    """Raised when a ZIP member name or type is unsafe to extract."""


class ArchiveSafetyLimitError(ArchiveLoadError):
    """Raised when a ZIP archive exceeds local verifier safety limits."""


class BundleRootError(ArchiveLoadError):
    """Raised when the extracted archive does not contain one unambiguous bundle root."""


class ArchiveReadError(ArchiveLoadError):
    """Raised when the host fails to read the archive: a failure on the input itself.

    It is not a finding about the archive's bytes, which were never read, and the run reports
    filesystem_error (report-contract.md section 5.3): an archive the host held locked is not
    reported as not being a ZIP archive.
    """


class ArchiveExtractionError(ArchiveLoadError):
    """Raised when the host fails to write the extraction: neither the input nor its content.

    The archive was read and cannot be loaded for another reason, archive_load_failed: a full
    disk under the temporary directory is not an invalid archive.
    """


def _normalize_zip_member_name(member_name: str | None) -> str:
    """Return an entry's name, less the final "/" of a directory entry, or raise.

    ``member_name`` is the name as the archive records it, each byte read as the character of the
    same value (bundle-objects.md section 5): a byte outside the portable set is a character
    outside it, whatever bit 11 says, so no code page and no UTF-8 decoding decides a name. The
    name must be a portable member name (bundle-objects.md section 2). Nothing is rewritten.

    The one rule covers, with no special case of its own, a name not the UTF-8 bit 11 marked, a
    length counted in UTF-8, code points Unicode 14.0 does not assign, and the Windows
    short-name shape.
    """

    if not isinstance(member_name, str):
        raise UnsafeZipMemberError("unsafe_zip_member:empty")
    name = member_name[:-1] if member_name.endswith("/") else member_name
    problem = member_name_problem(name)
    if problem is not None:
        raise UnsafeZipMemberError(f"unsafe_zip_member:{problem}")
    return name


def _zip_member_mode(member: _Entry) -> int:
    """Return the POSIX mode bits encoded in a ZIP member, when present."""

    return (member.external_attr >> 16) & 0o177777


def _is_directory_entry(member: _Entry) -> bool:
    return member.orig_filename.endswith("/")


def _check_entry(member: _Entry) -> str:
    """Apply the per-entry rules of bundle-objects.md §5 and return the entry's name.

    The rules apply in this order: name, type, method, member size, ratio. These are archive
    and input safety checks only. A member that passes these gates
    is safe to extract into the verifier's temporary directory; it is not yet
    semantically trusted evidence or proof material.
    """

    name = _normalize_zip_member_name(member.orig_filename)
    if any(field not in ALLOWED_EXTRA_FIELDS for field in member.extra_fields):
        # A field that can carry another spelling of the name, as 0x7075 does (rule name).
        raise UnsafeZipMemberError("unsafe_zip_member:extra_field")
    directory = _is_directory_entry(member)
    file_type = _zip_member_mode(member) & _POSIX_TYPE_MASK
    if file_type and file_type != (stat.S_IFDIR if directory else stat.S_IFREG):
        # A link, a device, a FIFO or a socket, or a type the name contradicts: whatever a
        # host would make of it, it is not the regular file or directory the name declares.
        raise UnsafeZipMemberError("unsafe_zip_member:symlink" if stat.S_ISLNK(file_type) else "unsafe_zip_member:type")
    if member.flag_bits & _ENCRYPTED_FLAG:
        raise ArchiveSafetyLimitError("zip_encrypted_member")
    if member.compress_type not in ALLOWED_ZIP_COMPRESSION_METHODS:
        raise ArchiveSafetyLimitError("zip_unsupported_compression_method")
    if not directory:
        if member.file_size > MAX_ZIP_MEMBER_UNCOMPRESSED_BYTES:
            raise ArchiveSafetyLimitError("zip_member_too_large")
        # Every member, whatever its size: bundle-objects.md §5 states the bound as a ratio
        # and no size below which it stops applying. An entry that claims bytes from
        # nothing, a compressed size of 0, is above every ratio.
        if member.file_size > MAX_ZIP_COMPRESSION_RATIO * member.compress_size:
            raise ArchiveSafetyLimitError("zip_suspicious_compression_ratio")
    return name


def _validate_entries(entries: list[_Entry]) -> list[_Entry]:
    """Apply every rule of bundle-objects.md §5 to every entry, in central-directory order.

    The archive is refused at the first entry that breaks a rule, and within that entry at
    the first rule it breaks: name, type, method, member size, ratio, duplicate, count,
    total. Returns the entries, which are then safe to extract.
    """

    names = MemberNameConflicts()
    total_uncompressed = 0
    file_count = 0
    for member in entries:
        name = _check_entry(member)
        directory = _is_directory_entry(member)
        if names.add(name, directory=directory):
            # Two entries one host would write to one path, or a file where another entry
            # needs a directory: the second either replaces the first or fails to extract,
            # and which one depends on the host. Or one directory spelled two ways, "DATA/" and
            # "data/y.json": a host that folds writes y.json under DATA, where a read by the
            # name "data/y.json" does not find it, and a host that does not fold makes two
            # directories, so the same archive would verify differently depending on the host.
            raise UnsafeZipMemberError("unsafe_zip_member:duplicate_path")
        if directory:
            continue
        file_count += 1
        if file_count > MAX_ZIP_FILE_COUNT:
            raise ArchiveSafetyLimitError("zip_too_many_files")
        total_uncompressed += member.file_size
        if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
            raise ArchiveSafetyLimitError("zip_total_uncompressed_size_too_large")
    return entries


_END_OF_CENTRAL_DIRECTORY = b"PK\x05\x06"
_ZIP64_END_OF_CENTRAL_DIRECTORY = b"PK\x06\x06"
_ZIP64_END_LOCATOR = b"PK\x06\x07"
_CENTRAL_DIRECTORY_ENTRY = b"PK\x01\x02"
_LOCAL_HEADER = b"PK\x03\x04"
_DATA_DESCRIPTOR = b"PK\x07\x08"
_LONGEST_DATA_DESCRIPTOR = 24
_END_RECORD_BYTES = 22
_ZIP64_END_RECORD_BYTES = 56
_ZIP64_LOCATOR_BYTES = 20
_CENTRAL_RECORD_BYTES = 46
_LOCAL_HEADER_BYTES = 30
_MAX_COMMENT_BYTES = 0xFFFF
_ZIP64_EXTRA_FIELD = 0x0001
_MAX_VERSION_NEEDED = 63
_UNREAD_FLAGS = 0x20 | 0x40  # compressed patched data, strong encryption
_COPY_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class _Entry:
    """One central-directory record, as bundle-objects.md section 5 reads it.

    ``orig_filename`` is the name with each byte read as the character of the same value, so a
    byte outside the portable set of section 2 is a character outside it and the rule name refuses
    the entry, in central-directory order. ``extra_fields`` are the ids of its extra field.
    """

    orig_filename: str
    raw_name: bytes
    extra_fields: tuple[int, ...]
    flag_bits: int
    compress_type: int
    CRC: int
    compress_size: int
    file_size: int
    external_attr: int
    header_offset: int


def _invalid(detail: str) -> InvalidZipError:
    return InvalidZipError(f"invalid_zip:{detail}")


def _read_at(handle: IO[bytes], offset: int, length: int) -> bytes:
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise _invalid("truncated")
    return data


def _end_record(handle: IO[bytes], size: int) -> int:
    """The position of the end-of-central-directory record: the one that starts at the last
    occurrence of its signature in the archive, which must end at the archive's last byte.

    Readers search back from the end and take either the last signature they meet or the last
    record whose comment ends at the last byte. An archive in which the two differ, a signature
    standing inside the record's comment, lists one set of members to one reader and another to
    the next, so it is refused rather than read either way.
    """
    start = max(0, size - _END_RECORD_BYTES - _MAX_COMMENT_BYTES)
    tail = _read_at(handle, start, size - start)
    found = tail.rfind(_END_OF_CENTRAL_DIRECTORY)
    if found < 0 or found + _END_RECORD_BYTES > len(tail):
        raise _invalid("no_end_record")
    (comment,) = struct.unpack("<H", tail[found + 20 : found + 22])
    if found + _END_RECORD_BYTES + comment != len(tail):
        raise _invalid("no_end_record")
    return start + found


def _central_directory(handle: IO[bytes], size: int) -> tuple[int, int, int]:
    """The entry count, the central directory's offset, and the position where it must end."""
    end = _end_record(handle, size)
    _, disk, directory_disk, on_disk, count, length, offset, _ = struct.unpack(
        "<4s4H2LH", _read_at(handle, end, _END_RECORD_BYTES)
    )
    locator = end - _ZIP64_LOCATOR_BYTES
    if locator >= 0 and _read_at(handle, locator, 4) == _ZIP64_END_LOCATOR:
        # A ZIP64 archive: the ZIP64 end record stands directly before its locator, at the offset
        # the locator records, and holds the values; the end record's own are not read.
        _, record_disk, recorded, disks = struct.unpack("<4sLQL", _read_at(handle, locator, _ZIP64_LOCATOR_BYTES))
        record = locator - _ZIP64_END_RECORD_BYTES
        if record < 0 or recorded != record or record_disk != 0 or disks != 1:
            raise _invalid("zip64_locator")
        signature, record_size, _, _, disk, directory_disk, on_disk, count, length, offset = struct.unpack(
            "<4sQ2H2L4Q", _read_at(handle, record, _ZIP64_END_RECORD_BYTES)
        )
        if signature != _ZIP64_END_OF_CENTRAL_DIRECTORY or record_size != _ZIP64_END_RECORD_BYTES - 12:
            raise _invalid("zip64_end_record")
        end = record
    if disk != 0 or directory_disk != 0 or on_disk != count:
        raise _invalid("disk_number")
    if offset + length != end:
        # Bytes before an archive whose offsets do not count them, or between the central
        # directory and its end record.
        raise _invalid("central_directory_offset")
    return count, offset, end


def _extra_fields(extra: bytes) -> list[tuple[int, bytes]]:
    """The fields of an extra field, each a 2-byte id, a 2-byte size and that many bytes, which
    must fill it exactly; or InvalidZipError."""
    cursor = 0
    fields: list[tuple[int, bytes]] = []
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            raise _invalid("extra_field")
        field, length = struct.unpack("<2H", extra[cursor : cursor + 4])
        if cursor + 4 + length > len(extra):
            raise _invalid("extra_field")
        fields.append((field, extra[cursor + 4 : cursor + 4 + length]))
        cursor += 4 + length
    return fields


def _zip64_values(fields: list[tuple[int, bytes]], wanted: int) -> list[int]:
    """The first ``wanted`` values of the ZIP64 extended information extra field (0x0001).
    No other field is read for a value.

    An entry holds that field at most once: readers that meet it twice take the first or the last,
    and read two sizes or two offsets for one entry, so section 5 refuses the second whether or not
    a value is read from it.
    """
    bodies = [body for field, body in fields if field == _ZIP64_EXTRA_FIELD]
    if len(bodies) > 1:
        raise _invalid("zip64_extra_field")
    values: list[int] = []
    if bodies:
        length = len(bodies[0])
        values = [struct.unpack("<Q", bodies[0][at : at + 8])[0] for at in range(0, length - length % 8, 8)]
    if len(values) < wanted:
        raise _invalid("zip64_extra_field")
    return values[:wanted]


def _read_entries(handle: IO[bytes], size: int) -> tuple[list[_Entry], int]:
    """Read the central directory as bundle-objects.md section 5 states it, or raise InvalidZipError;
    return its entries and its offset.

    Python's zipfile is not used. It reads a different set of archives under each Python (a Unicode
    Path extra field from 3.12, ZIP64 end records checked from 3.13), refuses archives section 5
    gives no rule for, and accepts a member whose data holds more or fewer bytes than its record
    states.
    """
    count, offset, end = _central_directory(handle, size)
    directory = _read_at(handle, offset, end - offset)
    position = 0
    entries: list[_Entry] = []
    for _ in range(count):
        record = directory[position : position + _CENTRAL_RECORD_BYTES]
        if len(record) != _CENTRAL_RECORD_BYTES or record[:4] != _CENTRAL_DIRECTORY_ENTRY:
            raise _invalid("central_directory_record")
        (
            _,
            _,
            version_needed,
            flags,
            method,
            _,
            _,
            crc,
            compress_size,
            file_size,
            name_length,
            extra_length,
            comment_length,
            disk_start,
            _,
            external_attr,
            header_offset,
        ) = struct.unpack("<4s4H2H3L5H2L", record)
        name_start = position + _CENTRAL_RECORD_BYTES
        stop = name_start + name_length + extra_length + comment_length
        if stop > len(directory):
            raise _invalid("central_directory_record")
        raw_name = directory[name_start : name_start + name_length]
        extra = directory[name_start + name_length : name_start + name_length + extra_length]
        position = stop
        if version_needed & 0xFF > _MAX_VERSION_NEEDED or flags & _UNREAD_FLAGS:
            raise _invalid("unsupported_feature")
        widened = [value == 0xFFFFFFFF for value in (file_size, compress_size, header_offset)]
        fields = _extra_fields(extra)
        values = iter(_zip64_values(fields, sum(widened)))
        file_size, compress_size, header_offset = (
            next(values) if wide else value
            for wide, value in zip(widened, (file_size, compress_size, header_offset), strict=True)
        )
        if disk_start != 0:
            raise _invalid("disk_number")
        # Each byte is the character of its value: the rule name refuses any byte outside the
        # portable set, so neither bit 11 nor a code page decides what a name is.
        name = raw_name.decode("latin-1")
        entries.append(
            _Entry(
                name,
                raw_name,
                tuple(field for field, _ in fields),
                flags,
                method,
                crc,
                compress_size,
                file_size,
                external_attr,
                header_offset,
            )
        )
    if position != len(directory):
        raise _invalid("central_directory_size")
    return entries, offset


def _data_offsets(handle: IO[bytes], entries: list[_Entry], directory_offset: int) -> list[int]:
    """Where each entry's data starts, read once every entry has passed the rules; or InvalidZipError.

    Each entry's local header stands at the offset its record states, under the same name, with an
    extra field whose fields fill it exactly and are each one the rule name admits, and its data,
    of the compressed size the record states, ends before the central directory; no two entries'
    local headers and data overlap, so no byte range is read twice. A Unicode Path field in the
    local header alone is read by some extractors, so it is refused like one in the record.

    Every byte before the central directory belongs to an entry: the first local header stands at
    the archive's first byte, and each entry's data is followed directly by the next local header,
    or by the central directory, with at most a data descriptor between them. Bytes no entry
    accounts for are never read, so an archive carrying them, such as a self-extracting stub whose
    offsets count it, is refused rather than verified with bytes nobody checked.
    """
    offsets: list[int] = []
    regions: list[tuple[int, int, _Entry]] = []
    for member in entries:
        if member.header_offset + _LOCAL_HEADER_BYTES > directory_offset:
            raise _invalid("local_header")
        local = _read_at(handle, member.header_offset, _LOCAL_HEADER_BYTES)
        name_length, extra_length = struct.unpack("<2H", local[26:30])
        start = member.header_offset + _LOCAL_HEADER_BYTES + name_length + extra_length
        if (
            local[:4] != _LOCAL_HEADER
            or start + member.compress_size > directory_offset
            or _read_at(handle, member.header_offset + _LOCAL_HEADER_BYTES, name_length) != member.raw_name
        ):
            raise _invalid("local_header")
        local_extra = _read_at(handle, member.header_offset + _LOCAL_HEADER_BYTES + name_length, extra_length)
        if any(field not in ALLOWED_EXTRA_FIELDS for field, _ in _extra_fields(local_extra)):
            raise _invalid("local_header")
        offsets.append(start)
        regions.append((member.header_offset, start + member.compress_size, member))
    regions.sort(key=lambda region: (region[0], region[1]))
    if any(later[0] < earlier[1] for earlier, later in zip(regions, regions[1:], strict=False)):
        raise _invalid("overlapping_entries")
    position, previous = 0, None
    for begin, finish, member in regions:
        _between_entries(handle, position, begin, previous)
        position, previous = finish, member
    _between_entries(handle, position, directory_offset, previous)
    return offsets


def _data_descriptors(member: _Entry) -> set[bytes]:
    """The data descriptors that may follow an entry's data: its CRC-32, compressed size and
    uncompressed size as the record states them, as three 4-byte values or as a 4-byte and two
    8-byte values, each with or without the descriptor's signature before them."""
    forms: set[bytes] = set()
    for layout in ("<3L", "<L2Q"):
        try:
            body = struct.pack(layout, member.CRC, member.compress_size, member.file_size)
        except struct.error:  # a size that four bytes cannot hold has only the 8-byte form
            continue
        forms.update((body, _DATA_DESCRIPTOR + body))
    return forms


def _between_entries(handle: IO[bytes], start: int, stop: int, previous: _Entry | None) -> None:
    """Refuse the bytes from ``start`` to ``stop``, which stand after the data of ``previous`` (or
    at the archive's start), unless there are none or they are one data descriptor of ``previous``."""
    length = stop - start
    if length == 0:
        return
    if (
        previous is None
        or length > _LONGEST_DATA_DESCRIPTOR
        or _read_at(handle, start, length) not in _data_descriptors(previous)
    ):
        raise _invalid("unaccounted_bytes")


@contextmanager
def _open_archive(zip_path: Path) -> Iterator[tuple[IO[bytes], list[_Entry], int]]:
    """Open ``zip_path`` and read its entries. A failure to read the file is the host's,
    ArchiveReadError (filesystem_error); bytes section 5 cannot read are InvalidZipError."""
    try:
        handle = open_for_reading(zip_path)
    except OSError as exc:
        raise ArchiveReadError("zip_not_readable") from exc
    with handle:
        try:
            size = handle.seek(0, os.SEEK_END)
            entries, directory_offset = _read_entries(handle, size)
        except OSError as exc:
            raise ArchiveReadError("zip_not_readable") from exc
        yield handle, entries, directory_offset


def _member_chunks(handle: IO[bytes], member: _Entry, data_offset: int) -> Iterator[bytes]:
    """The bytes of a file entry, or InvalidZipError when its data does not give exactly them.

    Stored data must be as long as the uncompressed size the record states; deflated data must be
    one deflate stream that ends at its last byte and gives exactly that many bytes; and the bytes
    must match the record's CRC-32. Cutting the data at the stated size and checking the CRC of
    what remains, as zipfile does, would accept a member longer or shorter than its record states.
    """
    if member.compress_type == ZIP_STORED and member.compress_size != member.file_size:
        raise _invalid("data_size")
    inflater = zlib.decompressobj(-15) if member.compress_type == ZIP_DEFLATED else None
    remaining, produced, crc = member.compress_size, 0, 0
    try:
        handle.seek(data_offset)
        while remaining:
            data = handle.read(min(remaining, _COPY_CHUNK_BYTES))
            if not data:
                raise _invalid("truncated")
            remaining -= len(data)
            while data:
                if inflater is None:
                    chunk, data = data, b""
                else:
                    if inflater.eof:
                        raise _invalid("data_after_stream")
                    chunk = inflater.decompress(data, member.file_size - produced + 1)
                    data = inflater.unconsumed_tail
                produced += len(chunk)
                if produced > member.file_size:
                    raise _invalid("data_size")
                crc = zlib.crc32(chunk, crc)
                if chunk:
                    yield chunk
        if inflater is not None:
            if inflater.unused_data:
                raise _invalid("data_after_stream")
            if not inflater.eof:
                raise _invalid("data_size")
    except zlib.error as exc:
        raise _invalid("not_deflate") from exc
    if produced != member.file_size:
        raise _invalid("data_size")
    if crc != member.CRC:
        raise _invalid("crc")


def validate_zip_members(zip_path: Path) -> list[str]:
    """Validate every entry against bundle-objects.md §5 before extraction, and return the
    names of the file entries."""

    with _open_archive(zip_path) as (_, entries, _):
        return [
            _normalize_zip_member_name(member.orig_filename)
            for member in _validate_entries(entries)
            if not _is_directory_entry(member)
        ]


def is_zip_archive(path: Path) -> bool:
    """Whether ``path`` holds an end-of-central-directory record that bundle-objects.md §5 finds."""
    try:
        with open_for_reading(path) as handle:
            _end_record(handle, handle.seek(0, os.SEEK_END))
    except InvalidZipError:
        return False
    except OSError:
        return True  # the host's failure, reported as such when the archive is read
    return True


def _make_directory(path: Path) -> None:
    """Create ``path`` and its parents for the extraction; a host failure is ArchiveExtractionError."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except FileExistsError as exc:
        # Something that is not a directory already stands where an entry needs one.
        raise UnsafeZipMemberError("unsafe_zip_member:duplicate_path") from exc
    except OSError as exc:
        raise ArchiveExtractionError("archive_extraction_failed") from exc


def _copy_member(handle: IO[bytes], member: _Entry, data_offset: int, sink: IO[bytes]) -> None:
    """Copy one member out. A failed read is the host's on the input, a failed write the extraction's."""
    chunks = _member_chunks(handle, member, data_offset)
    while True:
        try:
            chunk = next(chunks)
        except StopIteration:
            break
        except OSError as exc:
            raise ArchiveReadError("zip_not_readable") from exc
        try:
            sink.write(chunk)
        except OSError as exc:
            raise ArchiveExtractionError("archive_extraction_failed") from exc
    try:
        sink.flush()
    except OSError as exc:
        raise ArchiveExtractionError("archive_extraction_failed") from exc


def safe_extract_zip(zip_path: Path, destination: Path) -> list[str]:
    """Safely extract a ZIP archive after validating every entry (bundle-objects.md §5).

    Returns the names of the file entries. The destination directory is
    created if missing. Extraction is rejected if any member would escape the
    destination directory.

    The destination is written in the file namespace on Windows (host_path), so no path is
    refused for its length: a name within the bound extracts under a short temporary
    directory and under a longer one on the same host alike.
    """

    destination = Path(host_path(destination))
    _make_directory(destination)
    destination_root = destination.resolve()
    normalized_members: list[str] = []

    with _open_archive(zip_path) as (handle, entries, directory_offset):
        # Every entry is validated before a single byte is written.
        _validate_entries(entries)
        try:
            data_offsets = _data_offsets(handle, entries, directory_offset)
        except OSError as exc:
            raise ArchiveReadError("zip_not_readable") from exc
        for member, data_offset in zip(entries, data_offsets, strict=True):
            normalized = _normalize_zip_member_name(member.orig_filename)
            target = (destination / normalized).resolve()
            try:
                target.relative_to(destination_root)
            except ValueError as exc:
                raise UnsafeZipMemberError("unsafe_zip_member:escaped_destination") from exc
            if _is_directory_entry(member):
                _make_directory(target)
                continue
            _make_directory(target.parent)
            # Exclusive create. "wb" would overwrite whatever is already there, so any
            # collision the name gate did not anticipate would become a silent
            # last-member-wins substitution instead of a refusal. Whatever the host's
            # own naming rules turn out to be, two members landing on one path is a
            # hard failure.
            try:
                sink = target.open("xb")
            except FileExistsError as exc:
                raise UnsafeZipMemberError("unsafe_zip_member:duplicate_path") from exc
            except OSError as exc:
                raise ArchiveExtractionError("archive_extraction_failed") from exc
            # Closed whatever the copy raises, and opened only after the member is: a target left
            # open on Windows keeps the extraction from being removed from the temporary directory.
            with sink:
                _copy_member(handle, member, data_offset, sink)
            normalized_members.append(normalized)

    return normalized_members


def read_zip_member_bytes(zip_path: Path, member_name: str, *, max_bytes: int | None = None) -> bytes:
    """Read one safe ZIP member without extracting the archive."""

    normalized_target = _normalize_zip_member_name(member_name)
    with _open_archive(zip_path) as (handle, entries, directory_offset):
        _validate_entries(entries)
        try:
            data_offsets = _data_offsets(handle, entries, directory_offset)
            for member, data_offset in zip(entries, data_offsets, strict=True):
                if _is_directory_entry(member):
                    continue
                if _normalize_zip_member_name(member.orig_filename) != normalized_target:
                    continue
                if max_bytes is not None and member.file_size > max_bytes:
                    raise ArchiveLoadError(f"zip_member_too_large:{normalized_target}")
                return b"".join(_member_chunks(handle, member, data_offset))
        except OSError as exc:
            raise ArchiveReadError("zip_not_readable") from exc
    raise ArchiveLoadError(f"zip_member_missing:{normalized_target}")


def _carries_marker(level: Path, marker: str) -> bool:
    """Whether ``level`` of an extraction holds a regular file named exactly ``marker``."""

    if marker not in os.listdir(level):
        return False
    return stat.S_ISREG(os.lstat(level / marker).st_mode)


def find_bundle_root(extracted: Path, *, marker_name: str = "manifest.json") -> Path:
    """Find the single bundle root in an extracted archive.

    This uses only a configurable marker filename. It does not parse manifest
    content or verify manifest semantics.
    """

    marker = _normalize_zip_member_name(marker_name)
    if "/" in marker:
        raise BundleRootError(f"invalid_bundle_root_marker:{marker_name}")

    # Matched exactly against the listing, as a directory input's marker is: Path.exists()
    # matches "MANIFEST.JSON" on a host that ignores case and not elsewhere. Only a file entry is
    # a member (bundle-objects.md sections 1 and 5): a directory entry named like the marker, or
    # a directory the extraction made for the paths below it, never marks a root.
    if _carries_marker(extracted, marker):
        return extracted

    candidates = [path for path in extracted.iterdir() if path.is_dir() and _carries_marker(path, marker)]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise BundleRootError("bundle_root_marker_missing")
    raise BundleRootError("ambiguous_bundle_root")


@contextmanager
def extracted_zip(zip_path: Path, *, keep_extracted: bool = False) -> Iterator[Path]:
    """Context manager yielding a safe temporary extraction directory."""

    try:
        # In the file namespace on Windows, as safe_extract_zip writes it, so every later read of
        # the extraction reaches a member whatever the length of its path.
        tmp = Path(host_path(tempfile.mkdtemp(prefix="loquitur-verify-")))
    except OSError as exc:
        raise ArchiveExtractionError("archive_extraction_failed") from exc
    try:
        safe_extract_zip(zip_path, tmp)
        yield tmp
    finally:
        if not keep_extracted:
            shutil.rmtree(tmp, ignore_errors=True)
