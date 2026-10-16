"""Fail-closed binary patch application."""

from __future__ import annotations

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.profile import PatchSpec


def apply_offset_patch(data: bytes, patch: PatchSpec) -> bytes:
    """Apply one guarded patch, accepting an already-patched input idempotently."""
    start = patch.offset_or_va
    end = start + len(patch.expected)
    if end > len(data):
        raise FirmwareError(f"{patch.label}: patch range 0x{start:x}:0x{end:x} exceeds input size")
    current = data[start:end]
    if current == patch.replacement:
        return data
    if current != patch.expected:
        raise FirmwareError(
            f"{patch.label}: expected {patch.expected.hex()} at offset 0x{start:x}, "
            f"got {current.hex()}"
        )
    output = bytearray(data)
    output[start:end] = patch.replacement
    return bytes(output)


def verify_offset_patch(data: bytes, patch: PatchSpec) -> None:
    """Require the replacement bytes for one patch to be present."""
    start = patch.offset_or_va
    end = start + len(patch.replacement)
    if data[start:end] != patch.replacement:
        raise FirmwareError(f"required patch is absent: {patch.label} at offset 0x{start:x}")
