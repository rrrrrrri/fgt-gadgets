"""Strict reader and deterministic writer for ASCII newc archives."""

from __future__ import annotations

from dataclasses import dataclass

from fortigate_patcher.domain.errors import FirmwareError

NEWC_MAGIC = b"070701"
TRAILER_NAME = "TRAILER!!!"


def align4(value: int) -> int:
    """Round an integer up to the next four-byte boundary."""
    return (value + 3) & ~3


@dataclass(frozen=True, slots=True)
class CpioEntry:
    """One newc member, retaining all numeric header fields."""

    name: str
    fields: tuple[int, ...]
    data: bytes

    @property
    def mode(self) -> int:
        """Return the member's POSIX mode including its file type."""
        return self.fields[1]

    def with_data(self, data: bytes, mode: int | None = None) -> CpioEntry:
        """Return a copy with replacement content and optionally mode."""
        fields = list(self.fields)
        if mode is not None:
            fields[1] = mode
        return CpioEntry(self.name, tuple(fields), data)


def read_newc(data: bytes) -> tuple[CpioEntry, ...]:
    """Parse a complete newc archive through its trailer."""
    entries: list[CpioEntry] = []
    offset = 0
    while offset + 110 <= len(data):
        if data[offset : offset + 6] != NEWC_MAGIC:
            raise FirmwareError(f"bad newc magic at offset 0x{offset:x}")
        try:
            fields = tuple(
                int(data[offset + 6 + index * 8 : offset + 14 + index * 8], 16)
                for index in range(13)
            )
        except ValueError as exc:
            raise FirmwareError(f"invalid newc header at offset 0x{offset:x}") from exc
        size = fields[6]
        name_size = fields[11]
        name_start = offset + 110
        name_end = name_start + name_size
        if name_size < 1 or name_end > len(data) or data[name_end - 1] != 0:
            raise FirmwareError(f"invalid newc member name at offset 0x{offset:x}")
        data_start = align4(name_end)
        data_end = data_start + size
        if data_end > len(data):
            raise FirmwareError(f"truncated newc member at offset 0x{offset:x}")
        name = data[name_start : name_end - 1].decode("utf-8", errors="surrogateescape")
        entry = CpioEntry(name, fields, data[data_start:data_end])
        entries.append(entry)
        offset = align4(data_end)
        if name == TRAILER_NAME:
            return tuple(entries)
    raise FirmwareError("newc archive has no TRAILER!!! entry")


def _write_entry(output: bytearray, entry: CpioEntry) -> None:
    if len(entry.fields) != 13:
        raise FirmwareError(f"newc member has {len(entry.fields)} fields: {entry.name}")
    name = entry.name.encode("utf-8", errors="surrogateescape")
    if b"\0" in name:
        raise FirmwareError(f"newc member name contains NUL: {entry.name!r}")
    fields = list(entry.fields)
    fields[6] = len(entry.data)
    fields[11] = len(name) + 1
    output.extend(
        ("070701" + "".join(f"{field & 0xFFFFFFFF:08x}" for field in fields)).encode("ascii")
    )
    output.extend(name + b"\0")
    output.extend(b"\0" * (align4(len(output)) - len(output)))
    output.extend(entry.data)
    output.extend(b"\0" * (align4(len(output)) - len(output)))


def write_newc(entries: tuple[CpioEntry, ...], block_size: int = 512) -> bytes:
    """Serialize members deterministically and pad through a single trailer."""
    if not entries or entries[-1].name != TRAILER_NAME:
        raise FirmwareError("newc output must end with TRAILER!!!")
    if sum(entry.name == TRAILER_NAME for entry in entries) != 1:
        raise FirmwareError("newc output must contain exactly one trailer")
    output = bytearray()
    for entry in entries:
        _write_entry(output, entry)
    if block_size:
        output.extend(b"\0" * ((block_size - len(output) % block_size) % block_size))
    return bytes(output)


def new_entry(name: str, data: bytes, mode: int, inode: int) -> CpioEntry:
    """Construct a deterministic root-owned newc member."""
    fields = (
        inode,
        mode,
        0,
        0,
        1,
        0,
        len(data),
        0,
        0,
        0,
        0,
        len(name.encode("utf-8")) + 1,
        0,
    )
    return CpioEntry(name, fields, data)
