"""Reading the members of a directory bundle: no links, exact names, bounded size.

A directory bundle is attacker-supplied input, and three properties of reading it must come
from the verifier rather than from the host:

* **Links.** A host read resolves symbolic links and junctions. A declared member reached
  through a junction would be hashed from outside the bundle root; an inventory descending a
  junction would list the names of files outside the root in the report; a junction loop
  or a dangling junction would abort it with an OSError; an internal alias would verify one
  file under two names.
* **Names.** Windows matches names case-insensitively and drops a trailing dot, so a
  manifest declaring ``P1.JSON`` would verify against ``p1.json``, while the inventory, which
  compares exactly, reports ``p1.json`` as undeclared.
* **Size.** Declared members are bounded at 20 MiB, as ZIP members are.

This module is the one way the verifier reads a directory bundle. The inventory walks with
``os.scandir`` and never follows anything; a link anywhere is reported and fails the run.
A member name resolves segment by segment against the directory listing, and every
component is checked with lstat semantics, so a name the listing does not contain exactly,
or a path through a link, is not a member. A read refuses more than MAX_MEMBER_BYTES.

The check and the read are separate system calls, so a directory another process changes
during verification can still change between them; the read re-checks the file identity
it opened against the one it checked, which narrows that window without closing it.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import LoquiturVerifyError

# The per-member bound of bundle-objects.md §5, applied to directory bundles as to ZIP.
MAX_MEMBER_BYTES = 20 * 1024 * 1024

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_CHUNK_BYTES = 1024 * 1024


class BundleMemberError(OSError, LoquiturVerifyError):
    """A member of a directory bundle could not be read as a member."""


class UnsafeBundleMemberError(BundleMemberError):
    """A path component is a symbolic link, a junction or another reparse point."""


class MemberTooLargeError(BundleMemberError):
    """A member is larger than MAX_MEMBER_BYTES."""


class BundleInventoryError(BundleMemberError):
    """The bundle directory could not be enumerated."""


class BundleMemberNameError(BundleInventoryError):
    """A listing of the bundle holds a name that is not a portable member name, or two names that
    conflict (bundle-objects.md sections 1 and 2): content, bundle_member_name_invalid, not the
    host failing the inventory."""


# The errors of a path at which nothing is found: no entry, a path component that is not a
# directory, a link that resolves to nothing or to itself, or a path no entry can have because it
# is longer than the host lets a path or a name be. On Windows a link that resolves to nothing is
# ERROR_CANT_RESOLVE_FILENAME, and a name the file system cannot hold, a name longer than it
# allows included, is ERROR_INVALID_NAME, which no entry can carry. Every other OSError is the
# host failing an operation, and is never read as absence (report-contract.md section 5.3).
#
# On Windows the answer is read from the Windows error, never from the exception class: CPython
# raises FileNotFoundError for a missing UNC server or share (ERROR_BAD_NETPATH 53,
# ERROR_BAD_NET_NAME 67), which report-contract.md section 5.3 names a host failure, as it names
# invalid reparse data (4392). Nothing found is ERROR_FILE_NOT_FOUND 2, ERROR_PATH_NOT_FOUND 3,
# ERROR_INVALID_NAME 123, ERROR_FILENAME_EXCED_RANGE 206, ERROR_DIRECTORY 267 (a component that
# is not a directory) and ERROR_CANT_RESOLVE_FILENAME 1921.
_NOTHING_FOUND_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.ENAMETOOLONG})
_NOTHING_FOUND_WINERRORS = frozenset({2, 3, 123, 206, 267, 1921})

# On Windows, ERROR_INVALID_FUNCTION and ERROR_INVALID_PARAMETER, when the host inspects a path,
# are a device refusing a query it does not support or an access it does not accept: something is
# there, and it is neither a directory nor a regular file. os.stat asks a device for its type
# before anything else, so it rarely meets them; Node's stat meets them on the console and on a
# volume opened as a device. report-contract.md section 5.3 decides them: what refuses an
# inspection as an operation or a parameter it does not support is neither a directory nor a
# regular file.
_DEVICE_WINERRORS = frozenset({1, 87})

DIRECTORY = "directory"
REGULAR_FILE = "file"
OTHER = "other"


def finds_nothing(exc: OSError) -> bool:
    """True when ``exc`` says nothing is at the path, False when the host failed an operation."""
    winerror = getattr(exc, "winerror", None)
    if winerror is not None:
        return winerror in _NOTHING_FOUND_WINERRORS
    return isinstance(exc, (FileNotFoundError, NotADirectoryError)) or exc.errno in _NOTHING_FOUND_ERRNOS


_PIPE_NAMESPACE_ROOTS = ("\\\\.\\pipe\\", "\\\\?\\pipe\\")


def in_pipe_namespace(path: str | os.PathLike[str]) -> bool:
    r"""True on Windows for a path whose root is the named-pipe namespace, in any case and with
    either separator (``\\.\pipe\`` or ``\\?\pipe\``).

    A named pipe is neither a directory nor a regular file (report-contract.md section 5.3), and
    it is classified from its name without inspecting it: a pipe with no free instance makes
    the host's inspection fail as busy, and one the verifier may not open makes os.stat fall
    back to attributes that read as a regular file, which the verifier must not trust.
    """
    if sys.platform != "win32":
        return False
    text = os.fspath(path).replace("/", "\\").lower()
    return text.startswith(_PIPE_NAMESPACE_ROOTS)


def unc_root_folds(path: str | os.PathLike[str]) -> bool:
    r"""True on Windows for a share path whose server or share is ``.`` or ``..``.

    The server and the share of a root are names of the root, as written (report-contract.md
    section 5.3, step 1): neither is folded into anything, and a path whose root has one names
    nothing. Asked of the path as given and of its reading, so ``\\..\C:\d`` and
    ``\\?\UNC\..\C:\d`` are both caught before the host could read the second as ``C:\d``.
    ``\\.`` and ``\\?`` alone, and the ``\\.\`` and ``\\?\`` roots, are device roots, not
    shares.
    """
    if sys.platform != "win32":
        return False
    text = os.fspath(path).replace("/", "\\")
    if text in ("\\\\.", "\\\\?"):
        return False
    if text[:8].lower() == "\\\\?\\unc\\":
        rest = text[8:]
    elif text.startswith("\\\\") and not text.startswith(("\\\\?\\", "\\\\.\\")):
        rest = text[2:]
    else:
        return False
    names = rest.split("\\")
    server = names[0]
    share = names[1] if len(names) > 1 else None
    return server in (".", "..") or share in (".", "..")


# Every share mode, as libuv opens a file: a member another process holds open with delete
# access is read, not refused with the sharing violation that report-contract.md section 5.3
# makes a host failure.
_FILE_SHARE_ALL = 0x1 | 0x2 | 0x4


def open_for_reading(path: str | os.PathLike[str]) -> BinaryIO:
    """Open ``path`` for binary reading; on Windows with every share mode (read, write, delete).

    Through ``open`` with an opener, so the file object is the ordinary one. An OSError,
    carrying the Windows error, when the host refuses the open.
    """
    if sys.platform != "win32":
        return open(path, "rb")  # noqa: SIM115 - the caller closes it
    return open(path, "rb", opener=_open_shared)  # noqa: SIM115 - the caller closes it


# The Windows members of ctypes and msvcrt below carry a type: ignore that applies only where
# mypy checks for another platform, as CI does on Linux; on Windows it is unused.
def _open_shared(path: str, flags: int) -> int:  # pragma: no cover - Windows only
    """A descriptor for ``path`` opened for reading with FILE_SHARE_READ, _WRITE and _DELETE."""
    import ctypes  # noqa: PLC0415 - Windows only
    import msvcrt  # noqa: PLC0415 - Windows only
    from ctypes import wintypes  # noqa: PLC0415 - Windows only

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined, unused-ignore]
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    generic_read, open_existing, attribute_normal = 0x80000000, 3, 0x80
    handle = create(path, generic_read, _FILE_SHARE_ALL, None, open_existing, attribute_normal, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        code = ctypes.get_last_error()  # type: ignore[attr-defined, unused-ignore]
        raise OSError(None, ctypes.FormatError(code).strip(), path, code)  # type: ignore[attr-defined, unused-ignore]
    try:
        return msvcrt.open_osfhandle(  # type: ignore[attr-defined, no-any-return, unused-ignore]
            handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except OSError:
        kernel32.CloseHandle(wintypes.HANDLE(handle))
        raise


def read_file_bytes(path: str | os.PathLike[str]) -> bytes:
    """Every byte of the file at ``path``, opened as open_for_reading opens it."""
    with open_for_reading(path) as handle:
        return handle.read()


def inspect_path(path: str | os.PathLike[str]) -> str | None:
    """What ``path``, links followed, names: DIRECTORY, REGULAR_FILE, OTHER, or None for nothing.

    ``path`` is handed to the host as it is: a caller reading a path it was given passes
    ``host_path(path)``. An OSError when the host fails to inspect the path.

    A path holding a noncharacter finds nothing and is not handed to the host
    (report-contract.md section 5.3): a host may stop the process on such a path (Node.js on
    Windows does on one holding U+10FFFF). So does a path holding a surrogate code point, which is
    no sequence of Unicode scalar values: a host may read it as another name, with U+FFFD written
    in its place (Node.js does), and so read an entry other than the one given. A share path whose server
    or share is ``.`` or ``..`` finds nothing too, and is not handed to the host (unc_root_folds).
    """
    if has_noncharacter(os.fspath(path)) or has_surrogate(os.fspath(path)):
        return None
    if unc_root_folds(path):
        return None
    if in_pipe_namespace(path):
        return OTHER
    try:
        status = os.stat(path)
    except ValueError:
        # A path no entry can have: an embedded NUL, or on Windows one longer than any path.
        return None
    except OSError as exc:
        if finds_nothing(exc):
            return None
        if sys.platform == "win32" and getattr(exc, "winerror", None) in _DEVICE_WINERRORS:
            return OTHER
        raise
    if stat.S_ISDIR(status.st_mode):
        return DIRECTORY
    if stat.S_ISREG(status.st_mode):
        return REGULAR_FILE
    return OTHER


def path_names_regular_file(path: str | os.PathLike[str]) -> bool:
    """Whether ``path``, links followed, names a regular file.

    False when nothing is found there or what is found is not a regular file; an OSError when
    the host fails to inspect it. Not ``Path.exists`` or ``Path.is_file``: which host failures
    they read as a missing file depends on the Python version. ``path`` is handed to the host
    as it is, as for ``inspect_path``.
    """
    return inspect_path(path) == REGULAR_FILE


_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)

# The POSIX portable filename character set: the only characters a segment of a member name holds.
PORTABLE_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")

# A member name is at most this many bytes, its "/" separators included.
MAX_MEMBER_NAME_BYTES = 255


def _is_noncharacter(character: str) -> bool:
    code = ord(character)
    return 0xFDD0 <= code <= 0xFDEF or code & 0xFFFE == 0xFFFE


def has_noncharacter(name: str) -> bool:
    """True when ``name`` holds a noncharacter: U+FDD0 to U+FDEF, or a code point ending in FFFE or FFFF.

    Only host paths are asked this (report-contract.md section 5.3): no member name holds a
    character outside the portable set.
    """
    return any(_is_noncharacter(character) for character in name)


def has_surrogate(name: str) -> bool:
    """True when ``name`` holds a surrogate code point, U+D800 to U+DFFF, as a character of its own.

    Such a string is no sequence of Unicode scalar values, and a path holding one finds nothing
    (report-contract.md section 5.3). A Python string holds code points, so every surrogate in one
    stands alone: on Windows it reaches the host as a lone UTF-16 code unit, and on POSIX it is a
    byte the file system encoding could not decode.
    """
    return any(0xD800 <= ord(character) <= 0xDFFF for character in name)


def member_name_problem(name: str) -> str | None:
    """Why ``name`` is not a portable member name (bundle-objects.md section 2), or None when it is.

    A member name is a "/"-separated sequence of segments. Every segment is non-empty and holds
    only characters of the POSIX portable filename character set (A-Z, a-z, 0-9, ".", "_", "-");
    no segment is "." or "..", ends with ".", or begins with "-"; no segment is, ASCII letter case
    ignored, a Windows reserved device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9) alone or before
    its first "."; and the whole name is at most 255 bytes. Nothing is rewritten first.

    One rule decides a manifest key, an entry of a directory bundle and the name of an archive
    entry. It needs no grammar of refused characters and no special case (noncharacters, code
    points Unicode 14.0 does not assign, the Windows short-name shape, a length counted in
    UTF-8): each is a way a host reads, folds, extracts or opens a name as another name, and a
    name made only of the portable characters gives none of them a hold.

    The reason names the first clause the name breaks, for the report's notes; the reasons are
    informative.
    """
    if not isinstance(name, str) or not name:
        return "empty"
    if name.startswith("/"):
        return "absolute_path"
    if len(name.encode("utf-8", "surrogatepass")) > MAX_MEMBER_NAME_BYTES:
        return "name_too_long"
    if "\\" in name:
        return "backslash"
    if ":" in name:
        return "stream_or_drive_alias"
    if any(ord(character) < 0x20 for character in name):
        return "control_character"
    if any(character != "/" and character not in PORTABLE_CHARACTERS for character in name):
        return "character_outside_portable_set"
    for segment in name.split("/"):
        if segment == "":
            return "empty_segment"
        if segment in {".", ".."}:
            return "traversal" if segment == ".." else "dot_segment"
        if segment.endswith("."):
            return "trailing_dot_or_space"
        if segment.startswith("-"):
            return "leading_hyphen"
        if segment.split(".", 1)[0].upper() in _WINDOWS_DEVICE_NAMES:
            return "device_name"
    return None


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def fold_member_name(name: str) -> str:
    """``name`` with A to Z read as a to z and nothing else changed (bundle-objects.md section 2)."""
    return name.translate(_ASCII_LOWER)


def implied_directories(name: str) -> list[str]:
    """The directories a member name implies: "a/b/c" implies "a" and "a/b"."""
    segments = name.split("/")
    return ["/".join(segments[:count]) for count in range(1, len(segments))]


class MemberNameConflicts:
    """Names met one after another, and whether each conflicts with an earlier one (section 2).

    Two names conflict when, folded, they are equal; or one names a file and is equal to a
    directory the other implies; or a directory one names or implies is equal to a directory the
    other names or implies and the two are spelled differently.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._files: set[str] = set()
        self._implied: set[str] = set()
        self._spelled: dict[str, str] = {}

    def add(self, name: str, *, directory: bool = False) -> bool:
        """Record ``name``; True when it conflicts with a name recorded before it."""
        paths = [*implied_directories(name), name]
        key = fold_member_name(name)
        ancestors = [fold_member_name(parent) for parent in paths[:-1]]
        conflict = (
            key in self._seen
            or (not directory and key in self._implied)
            or any(parent in self._files for parent in ancestors)
            or any(self._spelled.get(fold_member_name(path), path) != path for path in paths)
        )
        self._seen.add(key)
        self._implied.update(ancestors)
        for path in paths:
            self._spelled.setdefault(fold_member_name(path), path)
        if not directory:
            self._files.add(key)
        return conflict


def conflicting_names(names: list[str]) -> set[str]:
    """Every name of ``names``, each naming a file, that conflicts with another of them (section 2)."""
    by_key: dict[str, list[str]] = {}
    implied_by: dict[str, list[str]] = {}
    spellings: dict[str, set[str]] = {}
    for name in names:
        by_key.setdefault(fold_member_name(name), []).append(name)
        for directory in implied_directories(name):
            key = fold_member_name(directory)
            implied_by.setdefault(key, []).append(name)
            spellings.setdefault(key, set()).add(directory)
    conflicting: set[str] = set()
    for key, group in by_key.items():
        if len(group) > 1:
            conflicting.update(group)
        if key in implied_by:
            conflicting.update(group)
            conflicting.update(implied_by[key])
    for key, spelled in spellings.items():
        if len(spelled) > 1:
            conflicting.update(implied_by[key])
    return conflicting


def is_link(status: os.stat_result) -> bool:
    """True for a symbolic link, and on Windows for any reparse point (junctions included)."""
    return stat.S_ISLNK(status.st_mode) or bool(getattr(status, "st_file_attributes", 0) & _REPARSE_POINT)


@dataclass(frozen=True)
class BundleInventory:
    """Every non-directory member, and every link, as sorted root-relative POSIX names."""

    files: tuple[str, ...]
    links: tuple[str, ...]


def bundle_inventory(bundle_root: Path) -> BundleInventory:
    """Enumerate the bundle without following anything.

    Each directory's listing is judged by its names before any entry in it is inspected
    (bundle-objects.md section 1): an entry whose path from the root is not a portable member
    name, or two entries whose names conflict under ASCII case folding, refuse the inventory, and
    such an entry is never inspected. No manifest can declare it, and whether it is a file, a
    directory or a link could only be learned by handing its name to the host. A name that is not a
    Unicode string (a lone surrogate on Windows, bytes that are not UTF-8 on POSIX) is outside the
    rule like any other.

    A link is recorded under its own name and never descended, so neither a name outside
    the root nor a loop can reach the result. Empty directories are not members.
    """
    files: list[str] = []
    links: list[str] = []
    pending: list[tuple[str, str]] = [("", os.fspath(bundle_root))]
    try:
        while pending:
            prefix, directory = pending.pop()
            with os.scandir(directory) as listing:
                entries = list(listing)
            folded: set[str] = set()
            for entry in entries:
                if member_name_problem(prefix + entry.name) is not None:
                    raise BundleMemberNameError("bundle_member_name_invalid:member_name_not_portable")
                key = fold_member_name(entry.name)
                if key in folded:
                    raise BundleMemberNameError("bundle_member_name_invalid:member_name_conflict")
                folded.add(key)
            for entry in entries:
                name = prefix + entry.name
                status = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or is_link(status):
                    links.append(name)
                elif stat.S_ISDIR(status.st_mode):
                    pending.append((name + "/", entry.path))
                else:
                    files.append(name)
    except BundleInventoryError:
        raise
    except (OSError, ValueError) as exc:
        # ValueError: a path under the root longer than the host lets any path be, which the
        # host refuses before it looks. The directory cannot be enumerated, as for a failure.
        raise BundleInventoryError(f"bundle_inventory_failed:{type(exc).__name__}") from exc
    return BundleInventory(files=tuple(sorted(files)), links=tuple(sorted(links)))


def member_path(bundle_root: Path, name: str) -> Path | None:
    """The path of the regular file ``name`` names exactly, or None.

    ``name`` is a "/"-separated root-relative name. Each segment must equal an entry of its
    directory's listing code unit for code unit; a component that is a link raises
    UnsafeBundleMemberError. None when a segment is absent, an intermediate component is not
    a directory, or the final component is not a regular file. A host that fails to list a
    directory on the way, or to inspect an entry, raises its OSError: the member is unread,
    not absent.
    """
    current = Path(bundle_root)
    segments = name.split("/")
    status: os.stat_result | None = None
    for index, segment in enumerate(segments):
        try:
            listing = os.listdir(current)
        except ValueError:
            return None  # a path longer than the host lets any path be: nothing is found there
        except OSError as exc:
            if finds_nothing(exc):
                return None
            raise
        if segment not in listing:
            return None
        current = current / segment
        try:
            status = os.lstat(current)
        except ValueError:
            return None
        except OSError as exc:
            if finds_nothing(exc):
                return None
            raise
        if is_link(status):
            raise UnsafeBundleMemberError(f"unsafe_bundle_member:link:{'/'.join(segments[: index + 1])}")
        if index < len(segments) - 1 and not stat.S_ISDIR(status.st_mode):
            return None
    if status is None or not stat.S_ISREG(status.st_mode):
        return None
    return current


def member_is_file(bundle_root: Path, name: str) -> bool:
    """Whether ``name`` is a regular-file member reached without a link.

    A link on the way is no regular member. A host that fails to list a directory on the way,
    or to inspect an entry, raises its OSError, which the layer asking reports as its
    ``*_read_failed`` error: report-contract.md section 5.3 has a manifest or a receipt the host
    could not inspect reported as unread, not as absent.
    """
    try:
        return member_path(bundle_root, name) is not None
    except UnsafeBundleMemberError:
        return False


def read_member_bytes(bundle_root: Path, name: str, *, max_bytes: int = MAX_MEMBER_BYTES) -> bytes:
    """The bytes of member ``name``, read without following a link and at most ``max_bytes``.

    Raises FileNotFoundError when there is no such member, UnsafeBundleMemberError for a
    link or a file that changed identity between the check and the open, and
    MemberTooLargeError above the bound.
    """
    path = member_path(bundle_root, name)
    if path is None:
        raise FileNotFoundError(f"bundle_member_missing:{name}")
    checked = os.lstat(path)
    if checked.st_size > max_bytes:
        raise MemberTooLargeError(f"member_too_large:{name}")
    with open_for_reading(path) as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            raise UnsafeBundleMemberError(f"unsafe_bundle_member:changed:{name}")
        # Chunked, not read(max_bytes + 1): that call allocates the whole bound up front for
        # every member, however small. The loop stops as soon as the bound is passed, so a
        # file that grew after the size check is refused without being read in full.
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = handle.read(min(_CHUNK_BYTES, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    if total > max_bytes:
        raise MemberTooLargeError(f"member_too_large:{name}")
    return b"".join(chunks)
