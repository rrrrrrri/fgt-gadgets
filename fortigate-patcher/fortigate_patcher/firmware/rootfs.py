"""FortiOS protected-rootfs key recovery, envelope parsing, and transformation."""

from __future__ import annotations

import gzip
import hashlib
import zlib
from dataclasses import dataclass
from typing import Protocol

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.profile import FirmwareProfile, RootfsEnvelopeSpec

from .cipher import stream_crypt
from .compression import GZIP_MAGIC
from .elf import Elf64Image
from .flatkc import locate_kernel_piggy


@dataclass(frozen=True, slots=True)
class RsaPublicKey:
    """The two public integer components needed for raw RSA verification."""

    modulus: int
    exponent: int


@dataclass(frozen=True, slots=True)
class RootfsEnvelope:
    """Parsed fields from a protected rootfs container."""

    encrypted_payload: bytes
    signature: bytes
    signed_digest: bytes
    auxiliary: bytes
    stream_key: bytes


def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise FirmwareError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise FirmwareError("invalid DER length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise FirmwareError("non-canonical DER length")
    return length, offset + count


def _der_value(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise FirmwareError(f"unexpected DER tag at offset 0x{offset:x}")
    length, body = _der_length(data, offset + 1)
    end = body + length
    if end > len(data):
        raise FirmwareError("DER value extends past the public-key blob")
    return data[body:end], end


def parse_rsa_public_key(der: bytes, expected_bits: int = 2048) -> RsaPublicKey:
    """Parse a canonical PKCS#1 DER RSA public key."""
    sequence, end = _der_value(der, 0, 0x30)
    if end != len(der):
        raise FirmwareError("trailing bytes after the embedded RSA public key")
    modulus_bytes, offset = _der_value(sequence, 0, 0x02)
    exponent_bytes, offset = _der_value(sequence, offset, 0x02)
    if offset != len(sequence) or not modulus_bytes or not exponent_bytes:
        raise FirmwareError("invalid embedded RSA public key")
    if modulus_bytes[0] == 0:
        modulus_bytes = modulus_bytes[1:]
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if modulus.bit_length() != expected_bits or exponent != 65537:
        raise FirmwareError("unexpected embedded RSA public-key parameters")
    return RsaPublicKey(modulus, exponent)


def recover_rootfs_public_key(kernel_elf: bytes, envelope_spec: RootfsEnvelopeSpec) -> RsaPublicKey:
    """Decode the XOR-obfuscated RSA key stored in the kernel ELF."""
    elf = Elf64Image(kernel_elf)
    blob_offset = elf.offset_for_va(
        envelope_spec.public_key_blob_va, envelope_spec.public_key_blob_length
    )
    xor_offset = elf.offset_for_va(
        envelope_spec.public_key_xor_va, envelope_spec.public_key_xor_length
    )
    encoded = kernel_elf[blob_offset : blob_offset + envelope_spec.public_key_blob_length]
    xor_key = kernel_elf[xor_offset : xor_offset + envelope_spec.public_key_xor_length]
    if not xor_key:
        raise FirmwareError("embedded public-key XOR mask is empty")
    der = bytes(value ^ xor_key[index % len(xor_key)] for index, value in enumerate(encoded))
    return parse_rsa_public_key(der, envelope_spec.signature_length * 8)


class EnvelopeAdapter(Protocol):
    """A parser for one protected-rootfs envelope format."""

    def parse(
        self,
        container: bytes,
        public_key: RsaPublicKey,
        spec: RootfsEnvelopeSpec,
        *,
        verify_digest: bool,
    ) -> RootfsEnvelope:
        """Parse the container, optionally requiring its signed digest."""
        ...


class FortiosV8RsaTrailerAdapter:
    """Parser for the 2048-bit raw-RSA trailer used by FortiOS 8 VM images."""

    def parse(
        self,
        container: bytes,
        public_key: RsaPublicKey,
        spec: RootfsEnvelopeSpec,
        *,
        verify_digest: bool,
    ) -> RootfsEnvelope:
        """Verify padding and recover the digest, auxiliary value, and stream key."""
        if spec.signature_length != 256:
            raise FirmwareError("FortiOS 8 RSA trailer must be 256 bytes")
        if len(container) <= spec.signature_length:
            raise FirmwareError("protected rootfs is too small")
        payload = container[: -spec.signature_length]
        signature = container[-spec.signature_length :]
        decoded = pow(
            int.from_bytes(signature, "big"), public_key.exponent, public_key.modulus
        ).to_bytes(spec.signature_length, "big")
        if decoded[0] != 0 or decoded[1] != 1 or decoded[159] != 0:
            raise FirmwareError("rootfs RSA trailer padding is invalid")
        if any(value != 0xFF for value in decoded[2:159]):
            raise FirmwareError("rootfs RSA trailer padding is invalid")
        signed_digest = decoded[160:192]
        actual_digest = hashlib.sha256(payload).digest()
        if verify_digest and signed_digest != actual_digest:
            raise FirmwareError(
                "rootfs encrypted-payload digest mismatch: "
                f"signed={signed_digest.hex()} actual={actual_digest.hex()}"
            )
        return RootfsEnvelope(
            encrypted_payload=payload,
            signature=signature,
            signed_digest=signed_digest,
            auxiliary=decoded[192:224],
            stream_key=decoded[224:256],
        )


ENVELOPE_ADAPTERS: dict[str, EnvelopeAdapter] = {
    "fortios-v8-rsa-trailer": FortiosV8RsaTrailerAdapter(),
}


def parse_rootfs_envelope(
    container: bytes,
    public_key: RsaPublicKey,
    spec: RootfsEnvelopeSpec,
    *,
    verify_digest: bool = True,
) -> RootfsEnvelope:
    """Parse a protected rootfs through its registered envelope adapter."""
    try:
        adapter = ENVELOPE_ADAPTERS[spec.adapter]
    except KeyError as exc:
        raise FirmwareError(f"unsupported rootfs envelope adapter: {spec.adapter}") from exc
    return adapter.parse(container, public_key, spec, verify_digest=verify_digest)


def decrypt_rootfs(
    container: bytes,
    flatkc: bytes,
    profile: FirmwareProfile,
    *,
    verify_digest: bool = True,
) -> tuple[bytes, RootfsEnvelope]:
    """Decrypt and structurally validate one protected rootfs container."""
    if container.startswith(GZIP_MAGIC):
        raise FirmwareError("rootfs is already plaintext")
    kernel = locate_kernel_piggy(flatkc).decompressed
    public_key = recover_rootfs_public_key(kernel, profile.rootfs_envelope)
    envelope = parse_rootfs_envelope(
        container, public_key, profile.rootfs_envelope, verify_digest=verify_digest
    )
    plaintext = stream_crypt(envelope.encrypted_payload, envelope.stream_key, profile.cipher)
    if not plaintext.startswith(GZIP_MAGIC):
        raise FirmwareError(
            f"decrypted rootfs does not have gzip magic (prefix={plaintext[:16].hex()})"
        )
    try:
        cpio = gzip.decompress(plaintext)
    except (EOFError, OSError, zlib.error) as exc:
        raise FirmwareError(f"decrypted rootfs gzip validation failed: {exc}") from exc
    if not cpio.startswith(b"070701"):
        raise FirmwareError(f"decrypted gzip is not a newc archive (prefix={cpio[:16]!r})")
    return plaintext, envelope


def encrypt_rootfs(
    plaintext_gzip: bytes,
    envelope: RootfsEnvelope,
    profile: FirmwareProfile,
) -> bytes:
    """Re-encrypt a patched gzip while preserving the stock signed trailer."""
    payload_size = len(envelope.encrypted_payload)
    if len(plaintext_gzip) > payload_size:
        raise FirmwareError(
            f"patched rootfs gzip exceeds encrypted payload: {len(plaintext_gzip)} > {payload_size}"
        )
    padded = plaintext_gzip + b"\0" * (payload_size - len(plaintext_gzip))
    encrypted = stream_crypt(padded, envelope.stream_key, profile.cipher)
    result = encrypted + envelope.signature
    if len(result) != payload_size + profile.rootfs_envelope.signature_length:
        raise FirmwareError("patched protected-rootfs size changed unexpectedly")
    return result


def split_gzip_stream(padded_gzip: bytes) -> tuple[bytes, bytes]:
    """Return the exact first gzip stream and its decompressed bytes."""
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decompressed = inflater.decompress(padded_gzip) + inflater.flush()
    except zlib.error as exc:
        raise FirmwareError(f"invalid gzip stream: {exc}") from exc
    if not inflater.eof:
        raise FirmwareError("gzip stream is incomplete")
    gzip_size = len(padded_gzip) - len(inflater.unused_data)
    return padded_gzip[:gzip_size], decompressed
