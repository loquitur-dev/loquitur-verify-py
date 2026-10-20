"""The string the host is asked for when the verifier reads a path (report-contract.md section 5.3).

A verifier reads each path it is given, the input and every supplied document, as it is written:
no layer of the host rewrites a name in it before the file system sees it. On POSIX nothing does,
and the path is handed over unchanged.

On Windows the Win32 path layer rewrites. It drops a trailing dot or space from a name, takes a
name such as ``NUL`` or ``CONIN$`` in any directory for a device, and refuses a path longer than
MAX_PATH. The verifier reads the path in the file namespace instead: made absolute and resolved
by name, then prefixed with ``\\\\?\\`` (``\\\\?\\UNC\\`` for a share), with ``\\\\?\\`` in place of
a ``\\\\.\\`` root, and read as it then is when it already begins with ``\\\\?\\``: steps 1 to 3
of report-contract.md section 5.3. Node's file system reads a path the same way, except for the
two prefixes it leaves to the Win32 layer, named below.

Through the Win32 layer, a directory named ``bundle.`` would verify as ``bundle``, ``NUL`` would
be the null device, and an input longer than MAX_PATH would not be found. A path whose root is
``\\\\.\\`` goes through it in Node: ``\\\\.\\C:\\d\\b `` is read as ``C:\\d\\b``, and
``\\\\.\\C:\\d\\b.`` finds nothing where ``b.`` exists, which is why that root is replaced.

``file_namespace`` is the resolution step by step, as Node's ``path.win32.resolve`` and
``path.win32.toNamespacedPath`` take it, and then the two prefixes Node leaves to the Win32 layer:
a ``\\\\.\\`` root, and a share whose server's name begins with ``.`` or ``?``. It is a pure
function of the path, the working directory and the working directories the host keeps for other
drives, so it is tested on every host.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

from loquitur.verify.members import unc_root_folds


def _is_separator(char: str) -> bool:
    return char == "\\" or char == "/"


def _is_drive_letter(char: str) -> bool:
    return "A" <= char <= "Z" or "a" <= char <= "z"


def _normalize(path: str, allow_above_root: bool) -> str:
    """Drop empty and ``.`` names and let each ``..`` drop the name before it, joined with ``\\``."""
    result = ""
    last_segment_length = 0
    last_slash = -1
    dots = 0
    char = ""
    index = 0
    while index <= len(path):
        if index < len(path):
            char = path[index]
        elif _is_separator(char):
            break
        else:
            char = "/"
        if _is_separator(char):
            if last_slash == index - 1 or dots == 1:
                pass
            elif dots == 2:
                if len(result) < 2 or last_segment_length != 2 or result[-1] != "." or result[-2] != ".":
                    if len(result) > 2:
                        cut = len(result) - last_segment_length - 1
                        if cut == -1:
                            result = ""
                            last_segment_length = 0
                        else:
                            result = result[:cut]
                            last_segment_length = len(result) - 1 - result.rfind("\\")
                        last_slash = index
                        dots = 0
                        index += 1
                        continue
                    if len(result) != 0:
                        result = ""
                        last_segment_length = 0
                        last_slash = index
                        dots = 0
                        index += 1
                        continue
                if allow_above_root:
                    result += "\\.." if len(result) > 0 else ".."
                    last_segment_length = 2
            else:
                name = path[last_slash + 1 : index]
                result = result + "\\" + name if len(result) > 0 else name
                last_segment_length = index - last_slash - 1
            last_slash = index
            dots = 0
        elif char == "." and dots != -1:
            dots += 1
        else:
            dots = -1
        index += 1
    return result


def _on_drive(directory: str | None, drive: str) -> bool:
    """``directory`` is an absolute directory on ``drive`` (``"D:"``), letter case aside."""
    return (
        isinstance(directory, str)
        and len(directory) > 2
        and directory[0:2].lower() == drive.lower()
        and _is_separator(directory[2])
    )


def _resolve(path: str, cwd: Callable[[], str], drive_cwd: Callable[[str], str | None]) -> str:
    """The absolute form of ``path``: its root, then its names resolved by name."""
    resolved_device = ""
    resolved_tail = ""
    resolved_absolute = False
    for step in (0, 1):
        if step == 0:
            current = path
            if len(current) == 0:
                continue
        elif len(resolved_device) == 0:
            current = cwd()
            if path in ("", ".") and len(current) > 0 and _is_separator(current[0]):
                return current
        else:
            # A drive-relative path (D:x) is taken against the working directory the host keeps for
            # that drive, else the process's own when it is on that drive, else the drive's root
            # (report-contract.md section 5.3, step 1). A working directory on a share is on no
            # drive: the path is then taken against the drive's root, not left relative.
            kept = drive_cwd(resolved_device)
            own = cwd()
            if _on_drive(kept, resolved_device):
                current = kept  # type: ignore[assignment]
            elif _on_drive(own, resolved_device):
                current = own
            else:
                current = resolved_device + "\\"
        length = len(current)
        root_end = 0
        device = ""
        is_absolute = False
        first = current[0]
        if length == 1:
            if _is_separator(first):
                root_end = 1
                is_absolute = True
        elif _is_separator(first):
            is_absolute = True
            if _is_separator(current[1]):
                j = 2
                last = j
                while j < length and not _is_separator(current[j]):
                    j += 1
                if j < length and j != last:
                    first_part = current[last:j]
                    last = j
                    while j < length and _is_separator(current[j]):
                        j += 1
                    if j < length and j != last:
                        last = j
                        while j < length and not _is_separator(current[j]):
                            j += 1
                        if j == length or j != last:
                            if first_part not in (".", "?"):
                                device = "\\\\" + first_part + "\\" + current[last:j]
                                root_end = j
                            else:
                                device = "\\\\" + first_part
                                root_end = 4
            else:
                root_end = 1
        elif _is_drive_letter(first) and current[1] == ":":
            device = current[0:2]
            root_end = 2
            if length > 2 and _is_separator(current[2]):
                is_absolute = True
                root_end = 3
        if len(device) > 0:
            if len(resolved_device) > 0:
                if device.lower() != resolved_device.lower():
                    continue
            else:
                resolved_device = device
        if resolved_absolute:
            if len(resolved_device) > 0:
                break
        else:
            resolved_tail = current[root_end:] + "\\" + resolved_tail
            resolved_absolute = is_absolute
            if is_absolute and len(resolved_device) > 0:
                break
    resolved_tail = _normalize(resolved_tail, not resolved_absolute)
    if resolved_absolute:
        return resolved_device + "\\" + resolved_tail
    return (resolved_device + resolved_tail) or "."


def file_namespace(
    path: str, cwd: str | Callable[[], str], drive_cwd: Callable[[str], str | None] = lambda drive: None
) -> str:
    """``path`` as a Windows host reads it in the file namespace, given the working directory ``cwd``.

    ``cwd`` is the working directory, or a function that answers it, asked only when the path is
    not absolute. ``drive_cwd`` answers the working directory the host keeps for another drive
    (``"D:"``), or None. The empty path stays empty, and names nothing.
    """
    if len(path) == 0:
        return path
    resolved = _resolve(path, cwd if callable(cwd) else (lambda: cwd), drive_cwd)
    if len(resolved) <= 2:
        return path
    if resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\.\\"):
        # The device prefix leaves the path to the Win32 layer, which still drops a trailing dot
        # from every name and a trailing space from the last; the file namespace prefix does not.
        return "\\\\?\\" + resolved[4:]
    if resolved[0] == "\\":
        if resolved[1] == "\\":
            # A share, the server's name beginning with "." or "?" included, which Node leaves
            # to the Win32 layer.
            return "\\\\?\\UNC\\" + resolved[2:]
    elif _is_drive_letter(resolved[0]) and resolved[1] == ":" and resolved[2] == "\\":
        return "\\\\?\\" + resolved
    return resolved


def _drive_cwd(drive: str) -> str | None:  # pragma: no cover - Windows only
    """The working directory Windows keeps for ``drive`` in the hidden variable ``=D:``, or None."""
    import ctypes

    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    # Windows only: the ignore applies where mypy checks for another platform, as CI does.
    length = ctypes.windll.kernel32.GetEnvironmentVariableW(  # type: ignore[attr-defined, unused-ignore]
        f"={drive}", buffer, size
    )
    if length == 0 or length >= size:
        return None
    return buffer.value


def host_path(path: str | os.PathLike[str]) -> str:
    """The string to hand the host for ``path``: the path as it is written, in the file namespace on Windows."""
    text = os.fspath(path)
    if sys.platform != "win32" or not isinstance(text, str):
        return text
    if unc_root_folds(text):
        # A root whose server or share is "." or ".." names nothing (section 5.3, step 1). The
        # path is kept as written, so the inspection that follows finds nothing in it, rather than
        # resolved: \\?\UNC\..\C:\d would resolve to C:\d.
        return text
    return file_namespace(text, os.getcwd, _drive_cwd)
