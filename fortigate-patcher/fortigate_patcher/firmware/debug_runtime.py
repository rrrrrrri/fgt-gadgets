"""Validation of the pinned self-contained GDB runtime."""

from __future__ import annotations

import io
import json
import lzma
import posixpath
import tarfile

from fortigate_patcher.domain.errors import FirmwareError

from .hashing import sha256_bytes
from .paths import normalize_archive_path
from .resources import BINARY_SHA256, read_binary

DEBUG_RUNTIME_NAME = "gdb-runtime.tar.xz"
DEBUG_RUNTIME_SHA256 = BINARY_SHA256[DEBUG_RUNTIME_NAME]
GDBSERVER_COMPAT_OFFSET = 0x52690
GDBSERVER_COMPAT_BYTES = bytes.fromhex("41 83 3c 24 02 73 32 90")


def verify_debug_runtime_data(data: bytes) -> None:
    """Require an archive to match and contain the pinned debugger runtime."""
    if sha256_bytes(data) != DEBUG_RUNTIME_SHA256:
        raise FirmwareError("debugger runtime fingerprint mismatch")
    required = {
        "fortigdb/MANIFEST.json": False,
        "fortigdb/bin/gdb.real": True,
        "fortigdb/bin/gdbserver.real": True,
        "fortigdb/lib/ld-linux-x86-64.so.2": True,
        "fortigdb/lib/libc.so.6": False,
        "fortigdb/lib/libstdc++.so.6": False,
        "fortigdb/lib/libpython3.12.so.1.0": False,
        "fortigdb/lib/python3.12/encodings/__init__.py": False,
        "fortigdb/share/gdb/python/gdb/__init__.py": False,
        "fortigdb/licenses/gdb.copyright": False,
        "fortigdb/licenses/gdbserver.copyright": False,
    }
    members: dict[str, tarfile.TarInfo] = {}
    selected: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
            for member in archive.getmembers():
                name = normalize_archive_path(member.name)
                if name in members:
                    raise FirmwareError(f"debugger runtime has duplicate member: {name}")
                if member.issym():
                    if member.linkname.startswith("/"):
                        allowed = (
                            name == "fortigdb/lib/python3.12/sitecustomize.py"
                            and member.linkname == "/etc/python3.12/sitecustomize.py"
                        )
                        if not allowed:
                            raise FirmwareError(f"debugger runtime has unsafe link: {name}")
                    else:
                        target = posixpath.normpath(
                            posixpath.join(posixpath.dirname(name), member.linkname)
                        )
                        if not target.startswith("fortigdb/"):
                            raise FirmwareError(f"debugger runtime has unsafe link: {name}")
                elif member.islnk() and not posixpath.normpath(member.linkname).startswith(
                    "fortigdb/"
                ):
                    raise FirmwareError(f"debugger runtime has unsafe hard link: {name}")
                members[name] = member
                if name in {"fortigdb/MANIFEST.json", "fortigdb/bin/gdbserver.real"}:
                    extracted = archive.extractfile(member)
                    if extracted is not None:
                        selected[name] = extracted.read()
    except (lzma.LZMAError, tarfile.TarError) as exc:
        raise FirmwareError(f"cannot read debugger runtime archive: {exc}") from exc
    for name, executable in required.items():
        required_member = members.get(name)
        if required_member is None or not required_member.isfile():
            raise FirmwareError(f"debugger runtime is missing: /{name}")
        if executable and not required_member.mode & 0o111:
            raise FirmwareError(f"debugger runtime executable bit is missing: /{name}")

    gdbserver = selected.get("fortigdb/bin/gdbserver.real", b"")
    actual = gdbserver[
        GDBSERVER_COMPAT_OFFSET : GDBSERVER_COMPAT_OFFSET + len(GDBSERVER_COMPAT_BYTES)
    ]
    if actual != GDBSERVER_COMPAT_BYTES:
        raise FirmwareError("debugger runtime lacks the FortiOS detach compatibility patch")
    try:
        manifest = json.loads(selected["fortigdb/MANIFEST.json"])
        compat = manifest["compatibility_patches"]["fortios-4.19-x86-debug-register-eperm"]
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareError("invalid debugger runtime manifest") from exc
    if (
        compat.get("file_offset") != f"0x{GDBSERVER_COMPAT_OFFSET:x}"
        or compat.get("replacement") != GDBSERVER_COMPAT_BYTES.hex()
    ):
        raise FirmwareError("debugger runtime manifest lacks its compatibility patch record")


def verified_debug_runtime() -> bytes:
    """Return the packaged debugger archive after structural and patch checks."""
    data = read_binary(DEBUG_RUNTIME_NAME)
    verify_debug_runtime_data(data)
    return data
