"""Protected-rootfs decryption use case."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.domain.profile import FirmwareProfile
from fortigate_patcher.firmware.hashing import hash_file, sha256_bytes
from fortigate_patcher.firmware.rootfs import decrypt_rootfs, split_gzip_stream


@dataclass(frozen=True, slots=True)
class DecryptResult:
    """Metadata returned after an atomic rootfs decryption."""

    output: Path
    sha256: str
    gzip_size: int
    cpio_size: int


def decrypt_rootfs_file(
    *,
    profile: FirmwareProfile,
    flatkc_path: Path,
    rootfs_path: Path,
    output_path: Path,
    replace: bool = False,
    progress: ProgressCallback | None = None,
) -> DecryptResult:
    """Validate a stock pair, decrypt rootfs, and atomically write its gzip stream."""
    flatkc_path = flatkc_path.resolve()
    rootfs_path = rootfs_path.resolve()
    output_path = output_path.resolve()
    if output_path in {flatkc_path, rootfs_path}:
        raise FirmwareError("output must not replace either input file")
    if output_path.exists() and not replace:
        raise FirmwareError(f"output already exists: {output_path} (use --replace)")
    report_progress(progress, "rootfs.decrypt", "validating input fingerprints")
    flatkc_size = flatkc_path.stat().st_size
    actual_flatkc = hash_file(
        flatkc_path,
        progress=lambda completed: report_progress(
            progress,
            "rootfs.decrypt",
            "hashing flatkc",
            completed=completed,
            total=flatkc_size,
        ),
    )
    rootfs_size = rootfs_path.stat().st_size
    actual_rootfs = hash_file(
        rootfs_path,
        progress=lambda completed: report_progress(
            progress,
            "rootfs.decrypt",
            "hashing protected rootfs",
            completed=completed,
            total=rootfs_size,
        ),
    )
    if actual_flatkc != profile.flatkc_sha256 or actual_rootfs != profile.rootfs_sha256:
        raise FirmwareError(
            f"input fingerprints do not match profile {profile.profile_id}:\n"
            f"  flatkc    {actual_flatkc} (expected {profile.flatkc_sha256})\n"
            f"  rootfs.gz {actual_rootfs} (expected {profile.rootfs_sha256})"
        )
    report_progress(progress, "rootfs.decrypt", "decrypting and authenticating rootfs")
    plaintext, _ = decrypt_rootfs(
        rootfs_path.read_bytes(), flatkc_path.read_bytes(), profile, verify_digest=True
    )
    report_progress(progress, "rootfs.decrypt", "locating the plaintext gzip stream")
    gzip_stream, cpio = split_gzip_stream(plaintext)

    report_progress(progress, "rootfs.decrypt", f"writing output atomically: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(gzip_stream)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output_path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    result = DecryptResult(
        output=output_path,
        sha256=sha256_bytes(gzip_stream),
        gzip_size=len(gzip_stream),
        cpio_size=len(cpio),
    )
    report_progress(progress, "rootfs.decrypt", "completed")
    return result
