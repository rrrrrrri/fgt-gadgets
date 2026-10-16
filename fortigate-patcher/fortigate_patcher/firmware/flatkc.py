"""Locate, verify, patch, and replace the compressed kernel inside flatkc."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.profile import FirmwareProfile

from .compression import GZIP_MAGIC, deterministic_gzip_compress
from .elf import ELF_MAGIC, Elf64Image
from .hashing import sha256_bytes
from .patching import apply_offset_patch, verify_offset_patch
from .pe import file_offset_to_rva, parse_pe_sections, rva_to_file_offset


@dataclass(frozen=True, slots=True)
class DecompressorStub:
    """Immediate fields in flatkc that describe the compressed kernel."""

    input_length_offset: int
    input_length: int
    output_length_offset: int | None
    output_length: int | None


@dataclass(frozen=True, slots=True)
class KernelPiggy:
    """A validated gzip-compressed ELF embedded in flatkc."""

    start: int
    size: int
    decompressed: bytes
    stub: DecompressorStub


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _s32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<i", data, offset)[0])


def _find_decompressor_stub(data: bytes, piggy_offset: int) -> DecompressorStub | None:
    sections = parse_pe_sections(data)
    target_rva = file_offset_to_rva(sections, piggy_offset)
    position = 0
    while True:
        offset = data.find(b"\x48\x8d\x15", position)
        if offset < 0:
            return None
        position = offset + 1
        if offset + 7 > len(data):
            continue
        reference_rva = (
            file_offset_to_rva(sections, offset) + 7 + _s32(data, offset + 3)
        ) & 0xFFFFFFFFFFFFFFFF
        if (
            rva_to_file_offset(sections, reference_rva) != piggy_offset
            and reference_rva != target_rva
        ):
            continue
        window = data[offset + 7 : min(len(data), offset + 103)]
        length_candidates: list[tuple[int, int]] = []
        index = window.find(b"\xb9")
        if index >= 0 and offset + 7 + index + 5 <= len(data):
            immediate = offset + 7 + index + 1
            length_candidates.append((immediate, _u32(data, immediate)))
        index = window.find(b"\x48\xc7\xc1")
        if index >= 0 and offset + 7 + index + 7 <= len(data):
            immediate = offset + 7 + index + 3
            length_candidates.append((immediate, _u32(data, immediate)))
        if not length_candidates:
            continue
        length_offset, length = min(length_candidates)
        output_offset: int | None = None
        output_length: int | None = None
        index = window.find(b"\x49\xc7\xc1")
        if index >= 0 and offset + 7 + index + 7 <= len(data):
            output_offset = offset + 7 + index + 3
            output_length = _u32(data, output_offset)
        return DecompressorStub(length_offset, length, output_offset, output_length)


def _gzip_offsets(data: bytes) -> tuple[int, ...]:
    offsets: list[int] = []
    offset = 0
    while True:
        offset = data.find(GZIP_MAGIC, offset)
        if offset < 0:
            return tuple(offsets)
        offsets.append(offset)
        offset += 1


def locate_kernel_piggy(flatkc: bytes) -> KernelPiggy:
    """Find the single referenced gzip-compressed ELF kernel in flatkc."""
    candidates: list[tuple[int, int, bytes, DecompressorStub | None]] = []
    for offset in _gzip_offsets(flatkc):
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            decompressed = inflater.decompress(flatkc[offset:]) + inflater.flush()
        except zlib.error:
            continue
        if not inflater.eof or not decompressed.startswith(ELF_MAGIC):
            continue
        Elf64Image(decompressed)
        consumed = len(flatkc) - offset - len(inflater.unused_data)
        candidates.append((offset, consumed, decompressed, _find_decompressor_stub(flatkc, offset)))
    if len(candidates) != 1:
        raise FirmwareError(f"expected one gzip-compressed ELF in flatkc, found {len(candidates)}")
    offset, size, kernel, stub = candidates[0]
    if stub is None or stub.input_length != size:
        raise FirmwareError("could not validate flatkc decompressor reference")
    return KernelPiggy(offset, size, kernel, stub)


def replace_kernel_piggy(flatkc: bytes, piggy: KernelPiggy, kernel: bytes) -> bytes:
    """Replace a validated compressed kernel slot and update stub lengths."""
    replacement = deterministic_gzip_compress(kernel)
    if len(replacement) > piggy.size:
        raise FirmwareError(
            f"patched kernel gzip exceeds flatkc slot: {len(replacement)} > {piggy.size}"
        )
    output = bytearray(flatkc)
    output[piggy.start : piggy.start + piggy.size] = b"\0" * piggy.size
    output[piggy.start : piggy.start + len(replacement)] = replacement
    struct.pack_into("<I", output, piggy.stub.input_length_offset, len(replacement))
    if len(kernel) != len(piggy.decompressed):
        if piggy.stub.output_length_offset is None:
            raise FirmwareError("kernel size changed but flatkc output length is unavailable")
        struct.pack_into("<I", output, piggy.stub.output_length_offset, len(kernel))
    verified = locate_kernel_piggy(bytes(output))
    if verified.start != piggy.start or verified.size != len(replacement):
        raise FirmwareError("patched flatkc failed compressed-kernel verification")
    return bytes(output)


def patch_flatkc(flatkc: bytes, profile: FirmwareProfile) -> bytes:
    """Apply a profile's guarded kernel patches and enforce golden hashes."""
    piggy = locate_kernel_piggy(flatkc)
    kernel = piggy.decompressed
    for patch in profile.kernel_patches:
        kernel = apply_offset_patch(kernel, patch)
    if sha256_bytes(kernel) != profile.expected_patched_kernel_sha256:
        raise FirmwareError("patched kernel fingerprint mismatch")
    output = replace_kernel_piggy(flatkc, piggy, kernel)
    if sha256_bytes(output) != profile.expected_patched_flatkc_sha256:
        raise FirmwareError("patched flatkc fingerprint mismatch")
    return output


def verify_flatkc(flatkc: bytes, profile: FirmwareProfile) -> bytes:
    """Verify the patched flatkc and return its decompressed kernel."""
    if sha256_bytes(flatkc) != profile.expected_patched_flatkc_sha256:
        raise FirmwareError("patched flatkc fingerprint mismatch")
    kernel = locate_kernel_piggy(flatkc).decompressed
    if sha256_bytes(kernel) != profile.expected_patched_kernel_sha256:
        raise FirmwareError("patched kernel fingerprint mismatch")
    for patch in profile.kernel_patches:
        verify_offset_patch(kernel, patch)
    return kernel
