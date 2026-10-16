"""Minimal PE/COFF section mapping used by the flatkc decompressor stub."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from fortigate_patcher.domain.errors import FirmwareError


@dataclass(frozen=True, slots=True)
class PeSection:
    """The address and file extents of one PE section."""

    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


def _u16(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def parse_pe_sections(data: bytes) -> tuple[PeSection, ...]:
    """Return PE sections, or an empty tuple for a non-PE flat binary."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return ()
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise FirmwareError("flatkc has an invalid PE header")
    count = _u16(data, pe_offset + 6)
    optional_size = _u16(data, pe_offset + 20)
    table = pe_offset + 24 + optional_size
    if table + count * 40 > len(data):
        raise FirmwareError("flatkc PE section table is truncated")
    return tuple(
        PeSection(
            virtual_address=_u32(data, table + index * 40 + 12),
            virtual_size=_u32(data, table + index * 40 + 8),
            raw_offset=_u32(data, table + index * 40 + 20),
            raw_size=_u32(data, table + index * 40 + 16),
        )
        for index in range(count)
    )


def file_offset_to_rva(sections: tuple[PeSection, ...], file_offset: int) -> int:
    """Translate a PE file offset to an RVA, treating headers as identity-mapped."""
    for section in sections:
        if section.raw_offset <= file_offset < section.raw_offset + section.raw_size:
            return section.virtual_address + file_offset - section.raw_offset
    return file_offset


def rva_to_file_offset(sections: tuple[PeSection, ...], rva: int) -> int | None:
    """Translate a PE RVA to a file offset, returning None for zero-fill data."""
    for section in sections:
        span = max(section.raw_size, section.virtual_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            delta = rva - section.virtual_address
            return section.raw_offset + delta if delta < section.raw_size else None
    return rva
