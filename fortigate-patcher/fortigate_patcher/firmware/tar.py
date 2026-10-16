"""Deterministic rewriting and verification of the rootfs bin.tar.xz archive."""

from __future__ import annotations

import copy
import io
import lzma
import tarfile
from collections.abc import Mapping

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.profile import FirmwareProfile

from .hashing import sha256_bytes
from .paths import normalize_archive_path
from .resources import ResourceAsset

BUSYBOX_APPLETS = (
    "sh",
    "id",
    "whoami",
    "uname",
    "hostname",
    "df",
    "free",
    "uptime",
    "base64",
    "wget",
    "md5sum",
    "sha256sum",
    "cat",
    "ls",
    "cp",
    "chmod",
    "mkdir",
    "mount",
    "umount",
    "sleep",
    "pgrep",
    "kill",
    "udhcpc",
)


def _regular_member(
    template: tarfile.TarInfo | None, name: str, data: bytes, mode: int
) -> tarfile.TarInfo:
    member = copy.copy(template) if template is not None else tarfile.TarInfo(name)
    member.pax_headers = dict(getattr(member, "pax_headers", {}))
    member.type = tarfile.REGTYPE
    member.name = name
    member.linkname = ""
    member.size = len(data)
    member.mode = mode
    member.uid = member.gid = 0
    member.uname = member.gname = "root"
    if template is None:
        member.mtime = 0
    member.pax_headers.pop("linkpath", None)
    return member


def _symlink_member(template: tarfile.TarInfo | None, name: str, target: str) -> tarfile.TarInfo:
    member = copy.copy(template) if template is not None else tarfile.TarInfo(name)
    member.pax_headers = dict(getattr(member, "pax_headers", {}))
    member.type = tarfile.SYMTYPE
    member.name = name
    member.linkname = target
    member.size = 0
    member.mode = 0o777
    member.uid = member.gid = 0
    member.uname = member.gname = "root"
    if template is None:
        member.mtime = 0
    member.pax_headers.pop("linkpath", None)
    return member


def rewrite_bin_tar_xz(
    data: bytes,
    assets: Mapping[str, ResourceAsset],
    profile: FirmwareProfile,
) -> tuple[bytes, Mapping[str, str]]:
    """Replace payload files, preserve stock init, and add BusyBox applet links."""
    found_assets: set[str] = set()
    found_applets: set[str] = set()
    found_init = False
    buffer = io.BytesIO()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as source:
            with tarfile.open(fileobj=buffer, mode="w", format=source.format) as output:
                seen: set[str] = set()
                for member in source.getmembers():
                    normalized = normalize_archive_path(member.name)
                    if normalized in seen:
                        raise FirmwareError(f"bin.tar.xz has duplicate member: {normalized}")
                    seen.add(normalized)
                    basename = normalized[4:] if normalized.startswith("bin/") else None
                    if normalized == "bin/init":
                        found_init = True
                        extracted = source.extractfile(member)
                        if extracted is None:
                            raise FirmwareError("bin.tar.xz /bin/init is not a regular file")
                        init_data = extracted.read()
                        expected = profile.expected_original_files.get("bin/init")
                        if expected is not None and sha256_bytes(init_data) != expected:
                            raise FirmwareError("unexpected /bin/init fingerprint")
                        output.addfile(
                            _regular_member(member, member.name, init_data, member.mode),
                            io.BytesIO(init_data),
                        )
                    elif basename is not None and basename in assets:
                        asset = assets[basename]
                        output.addfile(
                            _regular_member(member, member.name, asset.data, asset.mode),
                            io.BytesIO(asset.data),
                        )
                        found_assets.add(basename)
                    elif basename is not None and basename in BUSYBOX_APPLETS:
                        output.addfile(_symlink_member(member, member.name, "busybox"))
                        found_applets.add(basename)
                    else:
                        fileobj = source.extractfile(member) if member.isfile() else None
                        output.addfile(copy.copy(member), fileobj)
                for basename, asset in assets.items():
                    if basename not in found_assets:
                        name = f"./bin/{basename}"
                        output.addfile(
                            _regular_member(None, name, asset.data, asset.mode),
                            io.BytesIO(asset.data),
                        )
                for applet in BUSYBOX_APPLETS:
                    if applet not in found_applets:
                        output.addfile(_symlink_member(None, f"./bin/{applet}", "busybox"))
    except (lzma.LZMAError, tarfile.TarError) as exc:
        raise FirmwareError(f"cannot rewrite bin.tar.xz: {exc}") from exc
    if not found_init:
        raise FirmwareError("bin.tar.xz does not contain ./bin/init")
    compressed = lzma.compress(buffer.getvalue(), preset=9 | lzma.PRESET_EXTREME)
    hashes = {
        f"/bin/{name}": sha256_bytes(asset.data)
        for name, asset in assets.items()
        if asset.mode & 0o111
    }
    hashes["/bin/init"] = profile.expected_original_files["bin/init"]
    return compressed, hashes


def read_bin_tar_xz(data: bytes) -> tuple[dict[str, tarfile.TarInfo], dict[str, bytes]]:
    """Read normalized tar metadata and regular-file bytes for verification."""
    members: dict[str, tarfile.TarInfo] = {}
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
            for member in archive.getmembers():
                name = normalize_archive_path(member.name)
                if name in members:
                    raise FirmwareError(f"bin.tar.xz has duplicate member: {name}")
                members[name] = member
                if member.isfile():
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise FirmwareError(f"cannot read bin.tar.xz member: {name}")
                    files[name] = extracted.read()
    except (lzma.LZMAError, tarfile.TarError) as exc:
        raise FirmwareError(f"cannot read bin.tar.xz: {exc}") from exc
    return members, files
