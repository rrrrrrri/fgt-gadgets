"""Static direct-kernel QEMU smoke-test use case."""

from __future__ import annotations

import os
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path

from fortigate_patcher.application.profiles import resolve_profile
from fortigate_patcher.domain.errors import PlatformError
from fortigate_patcher.domain.manifest import BUILD_MANIFEST_NAME, load_build_manifest
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.platform.process import Runner, SubprocessRunner
from fortigate_patcher.platform.qemu import QemuRunResult, run_qemu

from .verify import verify_image

MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SmokeResult:
    """Files and QEMU outcome from a direct-kernel smoke test."""

    disk_image: Path
    serial_log: Path
    qemu: QemuRunResult


def qemu_smoke(
    *,
    build_directory: Path,
    work_directory: Path,
    runner: Runner | None = None,
    timeout_seconds: float = 90,
    progress: ProgressCallback | None = None,
) -> SmokeResult:
    """Verify a build, create an isolated raw scan disk, and boot its kernel/rootfs."""
    runner = runner or SubprocessRunner(progress=progress)
    build_directory = build_directory.resolve(strict=True)
    report_progress(progress, "qemu.smoke", f"loading build manifest: {build_directory}")
    manifest = load_build_manifest(build_directory / BUILD_MANIFEST_NAME)
    profile = resolve_profile(manifest.profile_id)
    verify_image(build_directory, profile, progress=progress)
    work_directory = work_directory.expanduser().resolve(strict=False)
    work_directory.mkdir(parents=True, exist_ok=True)
    prefix = f"qemu-{profile.profile_id}"
    filesystem = work_directory / f"{prefix}.ext3"
    disk_image = work_directory / f"{prefix}.img"
    serial_log = work_directory / f"{prefix}.log"
    for path in (filesystem, disk_image, serial_log):
        if path.exists():
            raise PlatformError(f"refusing to replace QEMU work artifact: {path}")
    report_progress(progress, "qemu.smoke", "creating the isolated ext3 scan filesystem")
    with filesystem.open("wb") as target:
        target.truncate(384 * MIB)
    runner.run(
        [
            runner.require("mke2fs"),
            "-q",
            "-t",
            "ext3",
            "-F",
            "-d",
            build_directory,
            filesystem,
        ]
    )
    report_progress(progress, "qemu.smoke", "assembling the partitioned raw disk image")
    _create_partitioned_disk(filesystem, disk_image)
    arguments: list[str | Path] = [
        runner.require("qemu-system-x86_64"),
        "-nodefaults",
        "-M",
        "q35",
        "-cpu",
        "max",
        "-m",
        "4096",
        "-kernel",
        build_directory / profile.patched_flatkc_name,
        "-initrd",
        build_directory / profile.patched_rootfs_name,
        "-append",
        profile.grub_kernel_args,
        "-drive",
        f"file={disk_image},format=raw",
        "-serial",
        "stdio",
        "-display",
        "none",
        "-no-reboot",
    ]
    report_progress(
        progress,
        "qemu.smoke",
        f"booting QEMU with a {timeout_seconds:g}s timeout",
    )
    result = run_qemu(
        arguments=arguments,
        log_path=serial_log,
        timeout_seconds=timeout_seconds,
        progress=progress,
    )
    report_progress(progress, "qemu.smoke", "checking the serial log")
    log = serial_log.read_text(encoding="utf-8", errors="replace")
    if "Run /init as init process" not in log:
        raise PlatformError("QEMU smoke log did not reach /init")
    failures = (
        "fos_ima: System Integrity check failed",
        "signature mismatched for file",
        "Kernel panic",
    )
    if any(value in log for value in failures):
        raise PlatformError("QEMU smoke log contains an integrity failure or kernel panic")
    report_progress(progress, "qemu.smoke", "completed")
    return SmokeResult(disk_image, serial_log, result)


def _create_partitioned_disk(filesystem: Path, disk_image: Path) -> None:
    start_sector = 2048
    filesystem_sectors = filesystem.stat().st_size // 512
    with disk_image.open("wb") as target:
        target.truncate(448 * MIB)
        mbr = bytearray(512)
        entry = bytearray(16)
        entry[0] = 0x80
        entry[1:4] = b"\xfe\xff\xff"
        entry[4] = 0x83
        entry[5:8] = b"\xfe\xff\xff"
        struct.pack_into("<II", entry, 8, start_sector, filesystem_sectors)
        mbr[446:462] = entry
        mbr[510:512] = b"\x55\xaa"
        target.seek(0)
        target.write(mbr)
        target.seek(start_sector * 512)
        with filesystem.open("rb") as source:
            shutil.copyfileobj(source, target, length=MIB)
        target.flush()
        os.fsync(target.fileno())
