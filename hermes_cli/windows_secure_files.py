"""Protected current-user/SYSTEM files for native Windows secret state."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any

_OPEN_REPARSE_POINT = 0x00200000
_MOVE_REPLACE_EXISTING = 0x00000001
_MOVE_WRITE_THROUGH = 0x00000008


def _win32() -> tuple[Any, ...]:
    if sys.platform != "win32":
        raise RuntimeError("Windows secure files are only available on Windows")
    import ntsecuritycon
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32security

    return ntsecuritycon, pywintypes, win32api, win32con, win32file, win32security


def current_sid():
    _, _, win32api, win32con, _, win32security = _win32()
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    return win32security.GetTokenInformation(token, win32security.TokenUser)[0]


def system_sid():
    return _win32()[5].ConvertStringSidToSid("S-1-5-18")


def security_attributes():
    ntsecuritycon, _, _, _, _, win32security = _win32()
    owner = current_sid()
    acl = win32security.ACL()
    for sid in (owner, system_sid()):
        acl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION,
            0,
            ntsecuritycon.FILE_ALL_ACCESS,
            sid,
        )
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(owner, False)
    descriptor.SetSecurityDescriptorDacl(True, acl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED,
        win32security.SE_DACL_PROTECTED,
    )
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def _allowed_sid_strings() -> set[str]:
    win32security = _win32()[5]
    return {
        win32security.ConvertSidToStringSid(current_sid()),
        win32security.ConvertSidToStringSid(system_sid()),
    }


def verify_handle_security(handle, *, label: str = "secret file") -> None:
    """Fail unless *handle* has a protected current-user/SYSTEM DACL."""
    win32security = _win32()[5]
    info = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT, info
    )
    owner = descriptor.GetSecurityDescriptorOwner()
    owner_value = win32security.ConvertSidToStringSid(owner)
    current_owner = win32security.ConvertSidToStringSid(current_sid())
    allowed = _allowed_sid_strings()
    if owner_value != current_owner:
        raise OSError(f"{label} has the wrong Windows owner")
    control = descriptor.GetSecurityDescriptorControl()[0]
    if not control & win32security.SE_DACL_PROTECTED:
        raise OSError(f"{label} has an inherited Windows DACL")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        raise OSError(f"{label} has a null Windows DACL")
    ntsecuritycon = _win32()[0]
    principals: set[str] = set()
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise OSError(f"{label} has an unexpected Windows ACE")
        principal = win32security.ConvertSidToStringSid(ace[-1])
        if principal not in allowed:
            raise OSError(f"{label} has a permissive Windows DACL")
        if ace[1] & ntsecuritycon.FILE_ALL_ACCESS != ntsecuritycon.FILE_ALL_ACCESS:
            raise OSError(f"{label} has an incomplete Windows DACL")
        principals.add(principal)
    if principals != allowed:
        raise OSError(f"{label} is missing a required Windows principal")


def open_secure_file(
    path: Path,
    *,
    access: int,
    creation: int,
    flags: int,
    share: int = 0,
    label: str = "secret file",
):
    """Open a non-reparse file and verify its owner and protected DACL."""
    win32file = _win32()[4]
    handle = win32file.CreateFile(
        str(path),
        access,
        share,
        security_attributes(),
        creation,
        flags | _OPEN_REPARSE_POINT,
        None,
    )
    try:
        actual = win32file.GetFinalPathNameByHandle(handle, 0)
        if actual.startswith("\\\\?\\UNC\\"):
            actual = "\\\\" + actual[8:]
        elif actual.startswith("\\\\?\\"):
            actual = actual[4:]
        expected = os.path.abspath(str(path))
        if os.path.normcase(actual) != os.path.normcase(expected):
            raise OSError(f"{label} escaped its expected Windows path")
        attributes = win32file.GetFileInformationByHandle(handle)[0]
        if attributes & 0x400:
            raise OSError(f"{label} is a Windows reparse point")
        verify_handle_security(handle, label=label)
        return handle
    except BaseException:
        win32file.CloseHandle(handle)
        raise


def ensure_secure_directory(path: Path, *, label: str = "secret directory") -> None:
    """Create or verify a protected directory without following reparse points."""
    _, pywintypes, _, win32con, win32file, _ = _win32()
    if path.parent != path and path.parent not in (Path(path.anchor), path):
        if not path.parent.exists():
            ensure_secure_directory(path.parent, label=label)
    if not path.exists():
        try:
            win32file.CreateDirectory(str(path), security_attributes())
        except pywintypes.error as exc:
            if exc.winerror != 183:
                raise
    handle = open_secure_file(
        path,
        access=win32con.GENERIC_READ | win32con.READ_CONTROL,
        creation=win32con.OPEN_EXISTING,
        flags=win32con.FILE_FLAG_BACKUP_SEMANTICS,
        share=(
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE
        ),
        label=label,
    )
    win32file.CloseHandle(handle)


def read_secure_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    """Read through a share-delete handle so atomic replacement stays atomic."""
    _, _, _, win32con, win32file, _ = _win32()
    handle = open_secure_file(
        path,
        access=win32con.GENERIC_READ | win32con.READ_CONTROL,
        creation=win32con.OPEN_EXISTING,
        flags=win32con.FILE_ATTRIBUTE_NORMAL,
        share=(
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE
        ),
        label=label,
    )
    try:
        _, data = win32file.ReadFile(handle, maximum + 1)
    finally:
        win32file.CloseHandle(handle)
    if len(data) > maximum:
        raise OSError(f"{label} is too large")
    return data


def atomic_write_secure_bytes(path: Path, data: bytes, *, label: str) -> None:
    """Publish bytes with a protected DACL and no in-place rewrite fallback."""
    _, _, _, win32con, win32file, _ = _win32()
    temporary = path.parent / f".{path.name}.{os.urandom(8).hex()}.tmp"
    handle = open_secure_file(
        temporary,
        access=win32con.GENERIC_WRITE | win32con.READ_CONTROL,
        creation=win32con.CREATE_NEW,
        flags=win32con.FILE_ATTRIBUTE_NORMAL,
        label=f"temporary {label}",
    )
    try:
        win32file.WriteFile(handle, data)
        win32file.FlushFileBuffers(handle)
    except BaseException:
        win32file.CloseHandle(handle)
        temporary.unlink(missing_ok=True)
        raise
    win32file.CloseHandle(handle)
    try:
        win32file.MoveFileEx(
            str(temporary),
            str(path),
            _MOVE_REPLACE_EXISTING | _MOVE_WRITE_THROUGH,
        )
        verification = open_secure_file(
            path,
            access=win32con.READ_CONTROL,
            creation=win32con.OPEN_EXISTING,
            flags=win32con.FILE_ATTRIBUTE_NORMAL,
            share=(
                win32con.FILE_SHARE_READ
                | win32con.FILE_SHARE_WRITE
                | win32con.FILE_SHARE_DELETE
            ),
            label=label,
        )
        win32file.CloseHandle(verification)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def acquire_secure_lock(path: Path, *, label: str):
    """Open, verify, and exclusively lock one byte of a protected lock file."""
    _, pywintypes, _, win32con, win32file, _ = _win32()
    handle = open_secure_file(
        path,
        access=win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.READ_CONTROL,
        creation=win32con.OPEN_ALWAYS,
        flags=win32con.FILE_ATTRIBUTE_NORMAL,
        share=(
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE
        ),
        label=label,
    )
    overlapped = pywintypes.OVERLAPPED()
    try:
        win32file.LockFileEx(
            handle,
            win32con.LOCKFILE_EXCLUSIVE_LOCK,
            1,
            0,
            overlapped,
        )
    except BaseException:
        win32file.CloseHandle(handle)
        raise
    return handle, overlapped


def release_secure_lock(handle, overlapped) -> None:
    win32file = _win32()[4]
    try:
        win32file.UnlockFileEx(handle, 1, 0, overlapped)
    finally:
        win32file.CloseHandle(handle)
