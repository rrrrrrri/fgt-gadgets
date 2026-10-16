"""Full-disk zstd backup and verified restoration without a command shell."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from fortigate_patcher.domain.errors import PlatformError
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.firmware.hashing import PROGRESS_INTERVAL, hash_file

from .process import Runner


@dataclass(frozen=True, slots=True)
class DiskBackup:
    """Verified fingerprints for one compressed full-disk recovery image."""

    image: Path
    compressed_sha256: str
    disk_sha256: str
    disk_size: int


def create_disk_backup(
    *,
    device: Path,
    image: Path,
    expected_size: int,
    runner: Runner,
    progress: ProgressCallback | None = None,
) -> DiskBackup:
    """Hash and compress a whole disk, verify zstd, and write a sidecar manifest."""
    if image.exists():
        raise PlatformError(f"refusing to overwrite existing disk backup: {image}")
    image.parent.mkdir(parents=True, exist_ok=True)
    zstd = runner.require("zstd")
    temporary = image.with_name(f".{image.name}.partial")
    temporary.unlink(missing_ok=True)
    try:
        report_progress(
            progress,
            "disk.backup",
            "reading and compressing the complete disk",
            completed=0,
            total=expected_size,
        )
        with temporary.open("wb") as output:
            compressor = subprocess.Popen(
                [zstd, "-T0", "-3", "-c"],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.PIPE,
            )
            assert compressor.stdin is not None
            disk_digest = hashlib.sha256()
            disk_size = 0
            last_reported = 0
            try:
                with device.open("rb", buffering=0) as source:
                    while chunk := source.read(1024 * 1024):
                        disk_digest.update(chunk)
                        disk_size += len(chunk)
                        compressor.stdin.write(chunk)
                        if disk_size - last_reported >= PROGRESS_INTERVAL:
                            report_progress(
                                progress,
                                "disk.backup",
                                "reading and compressing the complete disk",
                                completed=disk_size,
                                total=expected_size,
                            )
                            last_reported = disk_size
                compressor.stdin.close()
                assert compressor.stderr is not None
                compressor_stderr = compressor.stderr.read()
                compressor.stderr.close()
                returncode = compressor.wait()
            except BaseException:
                compressor.kill()
                compressor.wait()
                raise
            output.flush()
            os.fsync(output.fileno())
        if disk_size != last_reported:
            report_progress(
                progress,
                "disk.backup",
                "reading and compressing the complete disk",
                completed=disk_size,
                total=expected_size,
            )
        if returncode != 0:
            diagnostic = compressor_stderr.decode("utf-8", errors="replace").strip()
            raise PlatformError(f"zstd disk backup failed: {diagnostic}")
        disk_sha256 = disk_digest.hexdigest()
        if disk_size != expected_size:
            raise PlatformError(f"disk source size mismatch: {disk_size} != {expected_size}")
        report_progress(progress, "disk.backup", "testing the compressed zstd stream")
        runner.run([zstd, "--test", "--", temporary])
        backup_sha256, backup_size = _hash_zstd_contents(
            temporary,
            zstd,
            progress=progress,
            stage="disk.backup",
            message="verifying decompressed backup contents",
            total=expected_size,
        )
        if backup_size != expected_size:
            raise PlatformError(f"disk backup size mismatch: {backup_size} != {expected_size}")
        if backup_sha256 != disk_sha256:
            raise PlatformError("decompressed disk backup differs from the bytes read from source")
        os.replace(temporary, image)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    compressed_size = image.stat().st_size
    report_progress(progress, "disk.backup", "hashing the compressed backup image")
    compressed_sha256 = hash_file(
        image,
        progress=lambda completed: report_progress(
            progress,
            "disk.backup",
            "hashing the compressed backup image",
            completed=completed,
            total=compressed_size,
        ),
    )
    backup = DiskBackup(image, compressed_sha256, disk_sha256, expected_size)
    sidecar = image.with_suffix(image.suffix + ".json")
    sidecar.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "image": image.name,
                "compressed_sha256": compressed_sha256,
                "disk_sha256": disk_sha256,
                "disk_size": expected_size,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    report_progress(progress, "disk.backup", f"verified backup: {image}")
    return backup


def restore_disk_backup(
    *,
    image: Path,
    device: Path,
    confirm_device: Path,
    expected_size: int,
    runner: Runner,
    progress: ProgressCallback | None = None,
) -> str:
    """Restore a zstd image to an explicitly confirmed device and verify its SHA-256."""
    report_progress(progress, "disk.restore", "validating target and backup metadata")
    device = device.resolve(strict=True)
    if confirm_device.resolve(strict=True) != device:
        raise PlatformError("--confirm-device does not match the restore target")
    sidecar = image.with_suffix(image.suffix + ".json")
    try:
        document = json.loads(sidecar.read_text(encoding="utf-8"))
        compressed_sha256 = document["compressed_sha256"]
        expected_disk_sha256 = document["disk_sha256"]
        recorded_size = document["disk_size"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PlatformError(f"invalid backup sidecar: {sidecar}") from exc
    if recorded_size != expected_size:
        raise PlatformError("backup disk size differs from target device")
    if not isinstance(compressed_sha256, str) or not isinstance(expected_disk_sha256, str):
        raise PlatformError("backup sidecar contains invalid fingerprints")
    image_size = image.stat().st_size
    if hash_file(
        image,
        progress=lambda completed: report_progress(
            progress,
            "disk.restore",
            "hashing the compressed backup image",
            completed=completed,
            total=image_size,
        ),
    ) != compressed_sha256:
        raise PlatformError("compressed backup fingerprint mismatch")
    zstd = runner.require("zstd")
    backup_sha256, backup_size = _hash_zstd_contents(
        image,
        zstd,
        progress=progress,
        stage="disk.restore",
        message="verifying decompressed backup contents",
        total=expected_size,
    )
    if backup_size != expected_size:
        raise PlatformError("decompressed backup size differs from target device")
    if backup_sha256 != expected_disk_sha256:
        raise PlatformError("decompressed backup fingerprint differs from its sidecar")
    dd = runner.require("dd")
    report_progress(
        progress,
        "disk.restore",
        "writing the complete backup to the target disk",
        completed=0,
        total=expected_size,
    )
    decompressor = subprocess.Popen(
        [zstd, "-d", "-c", "--", str(image)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert decompressor.stdout is not None
    writer = subprocess.Popen(
        [dd, f"of={device}", "bs=4M", "conv=fsync", "status=none"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    assert writer.stdin is not None
    written = 0
    last_reported = 0
    try:
        while chunk := decompressor.stdout.read(1024 * 1024):
            writer.stdin.write(chunk)
            written += len(chunk)
            if written - last_reported >= PROGRESS_INTERVAL:
                report_progress(
                    progress,
                    "disk.restore",
                    "writing the complete backup to the target disk",
                    completed=written,
                    total=expected_size,
                )
                last_reported = written
        writer.stdin.close()
        writer_returncode = writer.wait()
        decompressor_returncode = decompressor.wait()
    except BaseException:
        writer.kill()
        decompressor.kill()
        writer.wait()
        decompressor.wait()
        raise
    finally:
        decompressor.stdout.close()
    assert writer.stderr is not None
    writer_stderr = writer.stderr.read()
    writer.stderr.close()
    assert decompressor.stderr is not None
    decompressor_stderr = decompressor.stderr.read()
    decompressor.stderr.close()
    if writer_returncode != 0 or decompressor_returncode != 0:
        detail = (writer_stderr + decompressor_stderr).decode("utf-8", errors="replace")
        raise PlatformError(f"disk restore failed: {detail.strip()}")
    if written != expected_size:
        raise PlatformError(f"restored byte count differs from target size: {written}")
    report_progress(
        progress,
        "disk.restore",
        "writing the complete backup to the target disk",
        completed=expected_size,
        total=expected_size,
    )
    actual = hash_file(
        device,
        progress=lambda completed: report_progress(
            progress,
            "disk.restore",
            "verifying the restored disk SHA-256",
            completed=completed,
            total=expected_size,
        ),
    )
    if actual != expected_disk_sha256:
        raise PlatformError(
            f"restored disk fingerprint mismatch: {actual} != {expected_disk_sha256}"
        )
    report_progress(progress, "disk.restore", "completed")
    return actual


def _hash_zstd_contents(
    image: Path,
    zstd: str,
    *,
    progress: ProgressCallback | None,
    stage: str,
    message: str,
    total: int,
) -> tuple[str, int]:
    """Stream-decompress an image and return its content digest and byte count."""
    process = subprocess.Popen(
        [zstd, "-d", "-c", "--", str(image)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    size = 0
    last_reported = 0
    report_progress(progress, stage, message, completed=0, total=total)
    try:
        while chunk := process.stdout.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if size - last_reported >= PROGRESS_INTERVAL:
                report_progress(progress, stage, message, completed=size, total=total)
                last_reported = size
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    assert process.stderr is not None
    stderr = process.stderr.read()
    process.stderr.close()
    returncode = process.wait()
    if returncode != 0:
        diagnostic = stderr.decode("utf-8", errors="replace").strip()
        raise PlatformError(f"cannot verify decompressed disk backup: {diagnostic}")
    if size != last_reported:
        report_progress(progress, stage, message, completed=size, total=total)
    return digest.hexdigest(), size
