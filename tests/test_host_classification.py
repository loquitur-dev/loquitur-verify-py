"""Host answers classified as report-contract.md section 5.3 names them, by Windows error and by name.

- A missing UNC server or share (ERROR_BAD_NETPATH 53, ERROR_BAD_NET_NAME 67) and invalid
  reparse data (4392) are host failures. CPython raises FileNotFoundError for the first two, so
  the class of the exception is not the answer; the Windows error is.
- A path in the named-pipe namespace is neither a directory nor a regular file, classified from
  its name: a busy pipe and a pipe the verifier may not open are both unsupported_input.
- A member another process holds open with delete access is readable, as libuv opens it.
- A member carrying a reparse tag that is not a symbolic link or a junction is an unsafe member,
  as every reparse point is; a pipe that is busy or that the verifier may not open is
  unsupported_input as an input and names no regular file as a registry entry. These states are
  made real on the host; no archive or directory in the corpus can carry them.
- A share path whose server or share is '.' or '..' names nothing (input_not_found), and is not
  handed to the host, which would read the server '..' as a step above the root.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from bundle_builder import Bundle

from loquitur.verify.members import (
    OTHER,
    finds_nothing,
    in_pipe_namespace,
    inspect_path,
    read_file_bytes,
    unc_root_folds,
)
from loquitur.verify.runner import verify_path

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows host classification")


@windows_only
@pytest.mark.parametrize(
    ("winerror", "nothing"),
    [
        (2, True),  # ERROR_FILE_NOT_FOUND
        (3, True),  # ERROR_PATH_NOT_FOUND
        (123, True),  # ERROR_INVALID_NAME
        (206, True),  # ERROR_FILENAME_EXCED_RANGE
        (267, True),  # ERROR_DIRECTORY
        (1921, True),  # ERROR_CANT_RESOLVE_FILENAME
        (5, False),  # ERROR_ACCESS_DENIED
        (32, False),  # ERROR_SHARING_VIOLATION
        (53, False),  # ERROR_BAD_NETPATH
        (67, False),  # ERROR_BAD_NET_NAME
        (231, False),  # ERROR_PIPE_BUSY
        (4392, False),  # ERROR_INVALID_REPARSE_DATA
    ],
)
def test_the_windows_error_decides_between_nothing_found_and_a_host_failure(winerror: int, nothing: bool) -> None:
    exc = OSError(None, "host answer", "x", winerror)
    assert finds_nothing(exc) is nothing


@windows_only
def test_a_missing_share_raises_file_not_found_and_is_still_a_host_failure() -> None:
    exc = OSError(None, "The network name cannot be found", r"\\server\share", 67)
    assert isinstance(exc, FileNotFoundError)
    assert finds_nothing(exc) is False


@windows_only
@pytest.mark.parametrize(
    "path",
    [r"\\.\pipe\lsass", r"\\?\pipe\lsass", "//./PIPE/lsass", r"\\.\Pipe\loquitur-no-such-pipe"],
)
def test_a_path_in_the_pipe_namespace_is_neither_a_directory_nor_a_file(path: str) -> None:
    assert in_pipe_namespace(path) is True
    assert inspect_path(path) == OTHER


@windows_only
def test_a_named_pipe_input_is_unsupported_input(tmp_path: Path) -> None:
    report = verify_path(r"\\.\pipe\lsass").to_dict()
    assert [error["code"] for error in report["errors"]] == ["unsupported_input"]


@windows_only
def test_a_named_pipe_registry_entry_names_no_regular_file() -> None:
    bundle = Path(__file__).resolve().parent / "fixtures" / "link_valid_bundle"
    report = verify_path(bundle, registry_entry_path=r"\\.\pipe\lsass").to_dict()
    codes = [error["code"] for error in report["errors"]]
    assert "registry_link_verification_failed" in codes
    assert "registry_link_read_failed" not in codes


def test_paths_outside_the_pipe_namespace_are_not_pipes() -> None:
    assert in_pipe_namespace("pipe/x") is False
    assert in_pipe_namespace(r"C:\pipe\x") is False


@windows_only
def test_a_member_held_open_with_delete_access_is_read(tmp_path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    root = Bundle().write(tmp_path / "bundle")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    generic_read, delete, share_all, open_existing = 0x80000000, 0x00010000, 0x7, 3
    handle = kernel32.CreateFileW(
        os.fspath(root / "manifest.json"), generic_read | delete, share_all, None, open_existing, 0x80, None
    )
    assert handle not in (None, wintypes.HANDLE(-1).value)
    try:
        assert read_file_bytes(root / "manifest.json")
        report = verify_path(root).to_dict()
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(handle))
    assert [error["code"] for error in report["errors"]] == []
    assert report["status"] == "OFFLINE_OK"


# ---------------------------------------------------------------- states made real on the host

_LX_SYMLINK = 0xA000001D  # IO_REPARSE_TAG_LX_SYMLINK: a reparse tag that is neither a symlink nor a junction
_AF_UNIX = 0x80000023  # IO_REPARSE_TAG_AF_UNIX


def _kernel32():  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return ctypes, wintypes, kernel32


def _set_reparse_tag(path: Path, tag: int) -> str | None:  # pragma: no cover - Windows only
    """Give the empty file ``path`` the reparse ``tag``; None on success, else why the host refused."""
    import struct

    ctypes, wintypes, kernel32 = _kernel32()
    generic_write, open_existing, open_reparse_point = 0x40000000, 3, 0x00200000
    handle = kernel32.CreateFileW(os.fspath(path), generic_write, 0, None, open_existing, open_reparse_point, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        return f"the host refused to open the file for writing its reparse data (error {ctypes.get_last_error()})"
    try:
        data = (2).to_bytes(4, "little") + b"x.json" if tag == _LX_SYMLINK else bytes(4)
        buffer = struct.pack("<IHH", tag, len(data), 0) + data
        returned = wintypes.DWORD(0)
        fsctl_set_reparse_point = 0x000900A4
        ok = kernel32.DeviceIoControl(
            handle, fsctl_set_reparse_point, buffer, len(buffer), None, 0, ctypes.byref(returned), None
        )
        if not ok:
            return f"the host refused to set reparse tag {tag:#x} here (error {ctypes.get_last_error()})"
    finally:
        kernel32.CloseHandle(handle)
    return None


@windows_only
@pytest.mark.parametrize("tag", [_LX_SYMLINK, _AF_UNIX], ids=["lx-symlink", "af-unix"])
@pytest.mark.parametrize("where", ["rp.txt", "sub/rp.txt"], ids=["at-the-root", "in-a-subdirectory"])
def test_a_member_with_a_reparse_tag_that_is_not_a_link_is_unsafe(tmp_path: Path, tag: int, where: str) -> None:
    root = Bundle().write(tmp_path / "bundle")
    member = root / where
    member.parent.mkdir(parents=True, exist_ok=True)
    member.write_bytes(b"")
    refused = _set_reparse_tag(member, tag)
    if refused is not None:
        pytest.skip(refused)
    attributes = os.lstat(member).st_file_attributes
    assert attributes & 0x400, "the member carries no reparse point, so the case is not made"
    report = verify_path(root).to_dict()
    assert report["status"] == "OFFLINE_FAIL"
    assert [error["code"] for error in report["errors"]] == ["unsafe_bundle_member"]


class _HeldPipe:  # pragma: no cover - Windows only
    """A named pipe this process serves: busy (its one instance taken) or with an empty DACL."""

    def __init__(self, name: str, *, denied: bool) -> None:
        ctypes, wintypes, kernel32 = _kernel32()
        self._kernel32, self._wintypes = kernel32, wintypes
        self.path = f"\\\\.\\pipe\\{name}-{os.getpid()}"
        self.handles: list[int] = []
        attributes = None
        if denied:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
            convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), wintypes.LPVOID]
            descriptor = ctypes.c_void_p()
            if not convert("D:", 1, ctypes.byref(descriptor), None):
                raise OSError(None, "no security descriptor", "D:", ctypes.get_last_error())

            class SecurityAttributes(ctypes.Structure):
                _fields_ = [
                    ("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL),
                ]

            self._attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            attributes = ctypes.byref(self._attributes)
        duplex, one_instance = 0x3, (255 if denied else 1)
        server = kernel32.CreateNamedPipeW(self.path, duplex, 0, one_instance, 4096, 4096, 0, attributes)
        if server in (None, wintypes.HANDLE(-1).value):
            raise OSError(None, "no named pipe", self.path, ctypes.get_last_error())
        self.handles.append(server)
        if not denied:
            client = kernel32.CreateFileW(self.path, 0x80000000, 0, None, 3, 0, None)
            if client in (None, wintypes.HANDLE(-1).value):
                raise OSError(None, "the pipe's one instance could not be taken", self.path, ctypes.get_last_error())
            self.handles.append(client)

    def close(self) -> None:
        for handle in self.handles:
            self._kernel32.CloseHandle(handle)


@windows_only
@pytest.mark.parametrize("denied", [False, True], ids=["busy", "denied"])
def test_a_pipe_the_verifier_cannot_open_is_neither_input_nor_document(denied: bool) -> None:
    pipe = _HeldPipe("loquitur-verify-held", denied=denied)
    try:
        as_input = verify_path(pipe.path).to_dict()
        bundle = Path(__file__).resolve().parent / "fixtures" / "link_valid_bundle"
        as_entry = verify_path(bundle, registry_entry_path=pipe.path).to_dict()
    finally:
        pipe.close()
    assert (as_input["status"], [e["code"] for e in as_input["errors"]]) == ("OFFLINE_FAIL", ["unsupported_input"])
    entry_codes = [error["code"] for error in as_entry["errors"]]
    assert as_entry["status"] == "OFFLINE_FAIL"
    assert entry_codes == ["registry_link_verification_failed"]


@windows_only
@pytest.mark.parametrize("member", ["p1.json", "manifest.json", "."], ids=["p1", "manifest", "bundle-directory"])
def test_an_alternate_data_stream_is_not_a_member(tmp_path: Path, member: str) -> None:
    # bundle-objects.md section 1: a member is a file's default data stream. A named stream beside
    # it is neither verified nor reported, so it neither breaks the digest nor counts as an
    # undeclared member.
    root = Bundle().write(tmp_path / "bundle")
    before = verify_path(root).to_dict()
    target = root / member
    stream = f"{os.fspath(target)}:hidden"
    try:
        with open(stream, "wb") as handle:
            handle.write(b"x" * 100000)
    except OSError as exc:
        pytest.skip(f"this filesystem holds no alternate data stream: {exc}")
    with open(stream, "rb") as handle:
        assert len(handle.read()) == 100000, "the stream was not written, so the case is not made"
    report = verify_path(root).to_dict()
    assert report["status"] == "OFFLINE_OK"
    assert report["errors"] == []
    assert report["review_reasons"] == []
    assert report == before


DOT_ROOTS = [
    "\\\\..\\C:\\Windows",
    "\\\\127.0.0.1\\.\\x",
    "\\\\127.0.0.1\\..\\x",
    "\\\\..\\share\\x",
    "\\\\?\\UNC\\..\\C:\\Windows",
    "//127.0.0.1/../x",
]


@windows_only
@pytest.mark.parametrize("path", DOT_ROOTS)
def test_a_share_with_a_dot_server_or_share_names_nothing(path: str) -> None:
    assert unc_root_folds(path) is True
    assert inspect_path(path) is None


@windows_only
@pytest.mark.parametrize("path", DOT_ROOTS)
def test_a_dot_share_input_is_input_not_found(path: str) -> None:
    report = verify_path(path).to_dict()
    assert report["status"] == "HOST_FAILURE"
    assert [error["code"] for error in report["errors"]] == ["input_not_found"]


@windows_only
def test_a_dot_share_registry_entry_names_nothing() -> None:
    bundle = Path(__file__).resolve().parent / "fixtures" / "link_valid_bundle"
    report = verify_path(bundle, registry_entry_path="\\\\127.0.0.1\\..\\entry.json").to_dict()
    codes = [error["code"] for error in report["errors"]]
    assert report["status"] == "HOST_FAILURE"
    assert codes == ["input_not_found"]


@windows_only
@pytest.mark.parametrize(
    "path",
    ["\\\\.", "\\\\?", "\\\\.\\C:\\x", "\\\\?\\C:\\x", "\\\\server\\share\\..", "\\\\.server\\share", "C:\\..\\x"],
)
def test_other_roots_do_not_fold(path: str) -> None:
    assert unc_root_folds(path) is False
