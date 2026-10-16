"""Cryptographic hashing helpers used across firmware workflows."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

IO_CHUNK_SIZE = 1024 * 1024
PROGRESS_INTERVAL = 64 * 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 digest for *data*."""
    return hashlib.sha256(data).hexdigest()


def hash_file(
    path: Path,
    algorithm: str = "sha256",
    limit: int | None = None,
    *,
    progress: Callable[[int], None] | None = None,
) -> str:
    """Hash a file, optionally requiring and hashing exactly *limit* bytes."""
    try:
        digest = hashlib.new(algorithm.lower().replace("-", ""))
    except ValueError as exc:
        raise ValueError(f"unsupported hash algorithm: {algorithm}") from exc
    remaining = limit
    completed = 0
    next_progress = PROGRESS_INTERVAL
    if progress is not None:
        progress(0)
    with path.open("rb") as source:
        while remaining is None or remaining:
            request = IO_CHUNK_SIZE if remaining is None else min(IO_CHUNK_SIZE, remaining)
            chunk = source.read(request)
            if not chunk:
                break
            digest.update(chunk)
            completed += len(chunk)
            if progress is not None and completed >= next_progress:
                progress(completed)
                next_progress = completed + PROGRESS_INTERVAL
            if remaining is not None:
                remaining -= len(chunk)
    if remaining:
        raise OSError(f"{path} ended before the expected {limit}-byte boundary")
    if progress is not None and completed % PROGRESS_INTERVAL:
        progress(completed)
    return digest.hexdigest()
