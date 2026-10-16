"""OpenSSH public-key parsing and fingerprints without private-key handling."""

from __future__ import annotations

import base64
import binascii
import hashlib

from fortigate_patcher.domain.errors import FirmwareError

PRIVATE_KEY_LABELS = (
    b"OPENSSH PRIVATE KEY",
    b"RSA PRIVATE KEY",
    b"EC PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"PRIVATE KEY",
    b"ENCRYPTED PRIVATE KEY",
)


def public_key_fingerprint(public_key: bytes) -> str:
    """Return the OpenSSH SHA-256 fingerprint of a public-key line."""
    fields = public_key.strip().split()
    if len(fields) < 2 or not (fields[0].startswith(b"ssh-") or fields[0].startswith(b"ecdsa-")):
        raise FirmwareError("expected an OpenSSH public key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FirmwareError("public key contains invalid base64") from exc
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def contains_private_key_block(data: bytes) -> bool:
    """Return whether data contains a complete, decodable PEM/OpenSSH private-key block."""
    for label in PRIVATE_KEY_LABELS:
        begin = b"-----BEGIN " + label + b"-----"
        end = b"-----END " + label + b"-----"
        position = 0
        while (start := data.find(begin, position)) >= 0:
            body_start = start + len(begin)
            finish = data.find(end, body_start)
            if finish < 0:
                break
            body = b"".join(data[body_start:finish].split())
            if len(body) >= 64:
                try:
                    decoded = base64.b64decode(body, validate=True)
                except (ValueError, binascii.Error):
                    pass
                else:
                    if len(decoded) >= 32:
                        return True
            position = body_start
    return False
