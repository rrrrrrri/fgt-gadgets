"""Safe path normalization for firmware archives and manifests."""

from __future__ import annotations

import posixpath

from fortigate_patcher.domain.errors import FirmwareError


def normalize_archive_path(name: str) -> str:
    """Normalize an archive path and reject absolute paths or traversal."""
    normalized = posixpath.normpath(name.replace("\\", "/"))
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        return ""
    if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
        raise FirmwareError(f"unsafe archive path: {name}")
    return normalized
