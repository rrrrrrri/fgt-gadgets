"""Minimal, bounds-checked little-endian ELF64 parsing."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from fortigate_patcher.domain.errors import FirmwareError

ELF_MAGIC = b"\x7fELF"


@dataclass(frozen=True, slots=True)
class LoadSegment:
    """A file-backed ELF program load segment."""

    file_offset: int
    virtual_address: int
    file_size: int


class Elf64Image:
    """Map file offsets and virtual addresses in a little-endian ELF64 image."""

    def __init__(self, data: bytes | bytearray) -> None:
        """Parse and validate file-backed load segments from *data*."""
        if len(data) < 0x40 or data[:4] != ELF_MAGIC:
            raise FirmwareError("kernel payload is not ELF")
        if data[4] != 2 or data[5] != 1:
            raise FirmwareError("kernel payload is not little-endian ELF64")
        program_offset = struct.unpack_from("<Q", data, 0x20)[0]
        program_entry_size = struct.unpack_from("<H", data, 0x36)[0]
        program_count = struct.unpack_from("<H", data, 0x38)[0]
        if program_entry_size < 56:
            raise FirmwareError("ELF program-header entry is too small")
        if program_offset + program_entry_size * program_count > len(data):
            raise FirmwareError("ELF program headers extend past the kernel payload")
        segments: list[LoadSegment] = []
        for index in range(program_count):
            offset = program_offset + index * program_entry_size
            program_type, _, file_offset, virtual_address, _, file_size, _, _ = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if program_type != 1 or not file_size:
                continue
            if file_offset + file_size > len(data):
                raise FirmwareError("ELF load segment extends past the kernel payload")
            segments.append(LoadSegment(file_offset, virtual_address, file_size))
        if not segments:
            raise FirmwareError("ELF contains no file-backed load segments")
        self.segments = tuple(segments)

    def offset_for_va(self, virtual_address: int, size: int = 1) -> int:
        """Translate a file-backed virtual-address range to its file offset."""
        if size < 0:
            raise FirmwareError("ELF mapping size must not be negative")
        for segment in self.segments:
            start = segment.virtual_address
            end = start + segment.file_size
            if start <= virtual_address and virtual_address + size <= end:
                return segment.file_offset + virtual_address - start
        raise FirmwareError(
            f"virtual address 0x{virtual_address:x} is not file-backed in the kernel ELF"
        )

    def va_for_offset(self, file_offset: int, size: int = 1) -> int:
        """Translate a file-offset range to its load virtual address."""
        if size < 0:
            raise FirmwareError("ELF mapping size must not be negative")
        for segment in self.segments:
            start = segment.file_offset
            end = start + segment.file_size
            if start <= file_offset and file_offset + size <= end:
                return segment.virtual_address + file_offset - start
        raise FirmwareError(f"file offset 0x{file_offset:x} is not mapped by an ELF segment")


@dataclass(frozen=True, slots=True)
class Elf64Section:
    """Fields needed from one ELF64 section header."""

    section_type: int
    offset: int
    size: int
    link: int
    entry_size: int


def relocation_symbols(data: bytes) -> dict[str, tuple[int, ...]]:
    """Map relocation symbol names to their relocation target virtual addresses."""
    Elf64Image(data)
    section_offset = struct.unpack_from("<Q", data, 0x28)[0]
    section_entry_size = struct.unpack_from("<H", data, 0x3A)[0]
    section_count = struct.unpack_from("<H", data, 0x3C)[0]
    if section_entry_size < 64:
        raise FirmwareError("ELF section-header entry is too small")
    if section_offset + section_entry_size * section_count > len(data):
        raise FirmwareError("ELF section headers are missing or truncated")
    sections: list[Elf64Section] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        _, section_type, _, _, file_offset, size, link, _, _, entry_size = struct.unpack_from(
            "<IIQQQQIIQQ", data, offset
        )
        if section_type != 8 and file_offset + size > len(data):
            raise FirmwareError(f"ELF section {index} extends past end of file")
        sections.append(Elf64Section(section_type, file_offset, size, link, entry_size))

    result: dict[str, list[int]] = {}
    for section in sections:
        if section.section_type not in (4, 9):
            continue
        if section.link >= len(sections):
            raise FirmwareError("ELF relocation section has an invalid symbol-table link")
        symbols = sections[section.link]
        if symbols.entry_size < 24 or symbols.link >= len(sections):
            raise FirmwareError("ELF relocation section has an invalid symbol table")
        strings = sections[symbols.link]
        relocation_size = section.entry_size or (24 if section.section_type == 4 else 16)
        if relocation_size < 16 or section.size % relocation_size:
            raise FirmwareError("ELF relocation section has an invalid entry size")
        for offset in range(section.offset, section.offset + section.size, relocation_size):
            target, info_value = struct.unpack_from("<QQ", data, offset)
            symbol_index = info_value >> 32
            symbol_offset = symbols.offset + symbol_index * symbols.entry_size
            if symbol_offset + 24 > symbols.offset + symbols.size:
                raise FirmwareError("ELF relocation references a symbol outside its table")
            name_offset = struct.unpack_from("<I", data, symbol_offset)[0]
            if name_offset >= strings.size:
                raise FirmwareError("ELF symbol name lies outside its string table")
            start = strings.offset + name_offset
            end = data.find(b"\0", start, strings.offset + strings.size)
            if end < 0:
                raise FirmwareError("ELF symbol name is not NUL terminated")
            try:
                name = data[start:end].decode("ascii")
            except UnicodeDecodeError as exc:
                raise FirmwareError("ELF symbol name is not ASCII") from exc
            if name:
                result.setdefault(name, []).append(target)
    return {name: tuple(targets) for name, targets in result.items()}
