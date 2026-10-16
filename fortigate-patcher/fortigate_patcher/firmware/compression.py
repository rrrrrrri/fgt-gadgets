"""Deterministic compression primitives."""

from __future__ import annotations

import gzip

from fortigate_patcher.domain.errors import FirmwareError

GZIP_MAGIC = b"\x1f\x8b\x08"


def deterministic_gzip_compress(data: bytes, compresslevel: int = 9) -> bytes:
    """Compress bytes with a host-independent gzip header and zero timestamp."""
    result = bytearray(gzip.compress(data, compresslevel=compresslevel, mtime=0))
    if len(result) < 10 or result[:3] != GZIP_MAGIC or result[4:8] != b"\0" * 4:
        raise FirmwareError("gzip compressor produced an unexpected wrapper")
    result[9] = 0xFF
    return bytes(result)
