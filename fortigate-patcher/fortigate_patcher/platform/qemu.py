"""QEMU process and qcow2 overlay adapters."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from fortigate_patcher.domain.errors import PlatformError
from fortigate_patcher.domain.progress import ProgressCallback, report_progress

from .process import Runner


@dataclass(frozen=True, slots=True)
class QemuRunResult:
    """Exit status and serial log from one bounded QEMU run."""

    returncode: int
    log_path: Path
    timed_out: bool


def create_overlay(
    *,
    runner: Runner,
    base_device: Path,
    overlay: Path,
    replace: bool = False,
) -> Path:
    """Create a qcow2 overlay backed by a raw disk or block device."""
    if overlay.exists():
        if not replace:
            raise PlatformError(f"QEMU overlay already exists: {overlay}")
        overlay.unlink()
    overlay.parent.mkdir(parents=True, exist_ok=True)
    runner.run(
        [
            runner.require("qemu-img"),
            "create",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            base_device,
            overlay,
        ]
    )
    runner.run([runner.require("qemu-img"), "check", overlay])
    return overlay


def run_qemu(
    *,
    arguments: list[str | Path],
    log_path: Path,
    timeout_seconds: float,
    progress: ProgressCallback | None = None,
) -> QemuRunResult:
    """Run QEMU with a serial log and terminate it after a bounded timeout."""
    values = [str(value) for value in arguments]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as log:
        process = subprocess.Popen(values, stdout=log, stderr=subprocess.STDOUT)
        timed_out = False
        started = time.monotonic()
        deadline = started + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                report_progress(
                    progress,
                    "qemu.smoke",
                    "QEMU reached the configured timeout; terminating it",
                )
                process.terminate()
                try:
                    returncode = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    returncode = process.wait(timeout=10)
                break
            try:
                returncode = process.wait(timeout=min(5.0, remaining))
                break
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                report_progress(
                    progress,
                    "qemu.smoke",
                    f"QEMU is still running ({elapsed:.0f}s elapsed)",
                )
    return QemuRunResult(returncode, log_path, timed_out)


def whole_disk_arguments(
    *,
    qemu_executable: str,
    overlay: Path,
    ssh_host_port: int,
    enable_kvm: bool = True,
) -> list[str | Path]:
    """Build arguments for an isolated whole-disk FortiOS boot."""
    arguments: list[str | Path] = [
        qemu_executable,
        "-nodefaults",
        "-M",
        "q35",
        "-m",
        "4096",
    ]
    if enable_kvm:
        arguments.extend(("-enable-kvm", "-cpu", "host"))
    else:
        arguments.extend(("-cpu", "max"))
    arguments.extend(
        (
            "-drive",
            f"file={overlay},format=qcow2,if=ide",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_host_port}-:23",
            "-device",
            "e1000,netdev=net0",
            "-serial",
            "stdio",
            "-display",
            "none",
            "-no-reboot",
        )
    )
    return arguments
