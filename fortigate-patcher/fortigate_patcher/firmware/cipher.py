"""Registered, streaming firmware cipher implementations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.profile import CipherSpec


class StreamCipher(Protocol):
    """A stateful symmetric stream transform."""

    def update(self, data: bytes) -> bytes:
        """Transform one chunk while retaining stream state."""
        ...


class FortiosV8StreamCipher:
    """FortiOS 8's RC4-derived symmetric rootfs transform."""

    def __init__(self, key: bytes, parameters: CipherSpec) -> None:
        """Initialize cipher state from a 32-byte key and profile parameters."""
        if len(key) != 32:
            raise FirmwareError(f"FortiOS 8 stream key must be 32 bytes, got {len(key)}")
        state = list(range(256))
        accumulator = 0
        for index in range(256):
            accumulator = (accumulator + state[index] + key[index & 31]) & 0xFF
            state[index], state[accumulator] = state[accumulator], state[index]
        self._state = state
        self._i = accumulator if parameters.carry_ksa_accumulator else 0
        self._j = 0
        self._left_shift = parameters.index_left_shift
        self._right_shift = parameters.index_right_shift

    def update(self, data: bytes) -> bytes:
        """Encrypt or decrypt one chunk and advance the cipher state."""
        output = bytearray(len(data))
        state = self._state
        i = self._i
        j = self._j
        for offset, value in enumerate(data):
            j = (j + 1) & 0xFF
            i = (i + state[j]) & 0xFF
            state[i], state[j] = state[j], state[i]
            left = ((j << self._left_shift) ^ (i >> self._right_shift)) & 0xFF
            right = ((i << self._left_shift) ^ (j >> self._right_shift)) & 0xFF
            keyed = ((state[right] + state[left]) ^ 0xAA) & 0xFF
            mixed = (state[(state[i] + state[j]) & 0xFF] + state[keyed]) & 0xFF
            output[offset] = value ^ mixed ^ state[(state[j] + i) & 0xFF]
        self._i = i
        self._j = j
        return bytes(output)


CipherFactory = Callable[[bytes, CipherSpec], StreamCipher]
CIPHER_REGISTRY: dict[str, CipherFactory] = {
    "fortios-v8-stream": FortiosV8StreamCipher,
}


def create_cipher(key: bytes, parameters: CipherSpec) -> StreamCipher:
    """Create a stream cipher through the named strategy registry."""
    try:
        factory = CIPHER_REGISTRY[parameters.algorithm]
    except KeyError as exc:
        raise FirmwareError(f"unsupported cipher algorithm: {parameters.algorithm}") from exc
    return factory(key, parameters)


def stream_crypt(data: bytes, key: bytes, parameters: CipherSpec) -> bytes:
    """Transform a complete byte string using a registered stream cipher."""
    return create_cipher(key, parameters).update(data)
