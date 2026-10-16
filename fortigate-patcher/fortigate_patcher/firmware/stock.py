"""Stock-file whitelist and manifest strategy validation."""

from __future__ import annotations

import json
import zlib
from collections.abc import Callable
from pathlib import Path

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.profile import FirmwareProfile

from .hashing import hash_file
from .paths import normalize_archive_path


def verify_db(directory: Path) -> None:
    """Validate a FortiOS JSON .db size/digest manifest."""
    try:
        document = json.loads((directory / ".db").read_text(encoding="utf-8"))
        entries = document["files"]
        if not isinstance(entries, list):
            raise TypeError
        for entry in entries:
            relative = normalize_archive_path(entry["path"].lstrip("/"))
            path = directory / relative
            if path.stat().st_size != entry["size"]:
                raise FirmwareError(f".db size mismatch: {entry['path']}")
            for digest in entry["digests"]:
                if hash_file(path, digest["algorithm"]) != digest["digest"].lower():
                    raise FirmwareError(f".db digest mismatch: {entry['path']}")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FirmwareError("invalid FortiOS .db document") from exc


def verify_filechecksum(directory: Path) -> None:
    """Validate the two-entry CRC32 filechecksum manifest."""
    try:
        lines = (directory / "filechecksum").read_text(encoding="ascii").splitlines()
        entries: dict[str, int] = {}
        for line in lines:
            path, algorithm, value = line.split(",")
            if algorithm != "CRC32" or not path.startswith("/"):
                raise ValueError
            name = normalize_archive_path(path[1:])
            if name in entries:
                raise ValueError
            entries[name] = int(value, 16)
    except (OSError, UnicodeError, ValueError) as exc:
        raise FirmwareError("invalid FortiOS filechecksum document") from exc
    if set(entries) != {"flatkc", "rootfs.gz"}:
        raise FirmwareError("filechecksum must cover exactly flatkc and rootfs.gz")
    for name, expected in entries.items():
        actual = 0
        with (directory / name).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                actual = zlib.crc32(chunk, actual)
        if actual & 0xFFFFFFFF != expected:
            raise FirmwareError(f"filechecksum CRC32 mismatch: /{name}")


ManifestValidator = Callable[[Path], None]
MANIFEST_STRATEGIES: dict[str, ManifestValidator] = {
    "db": verify_db,
    "filechecksum": verify_filechecksum,
}


def validate_stock_tree(directory: Path, profile: FirmwareProfile) -> None:
    """Require exactly the profile's known stock contents and embedded manifest validity."""
    if not directory.is_dir():
        raise FirmwareError(f"stock BOOT directory does not exist: {directory}")
    missing = [name for name in profile.required_inputs if not (directory / name).is_file()]
    if missing:
        raise FirmwareError("stock BOOT directory is missing: " + ", ".join(missing))
    mismatches: list[str] = []
    for name, expected in profile.scan_file_sha256.items():
        actual = hash_file(directory / name)
        if actual != expected:
            mismatches.append(f"  {name} {actual} (expected {expected})")
    if mismatches:
        raise FirmwareError("stock BOOT fingerprints differ:\n" + "\n".join(mismatches))
    try:
        validator = MANIFEST_STRATEGIES[profile.manifest_strategy]
    except KeyError as exc:
        raise FirmwareError(
            f"unsupported stock-manifest strategy: {profile.manifest_strategy}"
        ) from exc
    validator(directory)
