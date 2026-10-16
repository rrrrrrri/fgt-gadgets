"""Byte-verified deployment of build artifacts to mounted target filesystems."""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from pathlib import Path

from fortigate_patcher.domain.errors import PlatformError
from fortigate_patcher.domain.policy import BuildPolicy
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.domain.profile import FirmwareProfile
from fortigate_patcher.firmware.debug_runtime import (
    DEBUG_RUNTIME_NAME,
    DEBUG_RUNTIME_SHA256,
    verify_debug_runtime_data,
)
from fortigate_patcher.firmware.hashing import hash_file
from fortigate_patcher.firmware.stock import validate_stock_tree

from .credentials import HostIdentity
from .grub import install_grub
from .process import Runner


def deploy_build(
    *,
    runner: Runner,
    profile: FirmwareProfile,
    policy: BuildPolicy,
    build_directory: Path,
    boot_mount: Path,
    patch_mount: Path,
    device: Path,
    host_identity: HostIdentity | None,
    progress: ProgressCallback | None = None,
) -> None:
    """Deploy patched artifacts, debugger runtime, identities, and GRUB."""
    report_progress(progress, "disk.deploy", "validating stock files on the BOOT partition")
    validate_stock_tree(boot_mount, profile)
    patched_kernel_source = build_directory / profile.patched_flatkc_name
    patched_rootfs_source = build_directory / profile.patched_rootfs_name
    patched_kernel_target = boot_mount / profile.patched_flatkc_name
    patched_rootfs_target = patch_mount / profile.patched_rootfs_name
    report_progress(progress, "disk.deploy", "copying and verifying the patched kernel")
    _copy_verified(patched_kernel_source, patched_kernel_target, 0o755)
    report_progress(progress, "disk.deploy", "copying and verifying the patched rootfs")
    _copy_verified(patched_rootfs_source, patched_rootfs_target, 0o644)

    if policy.debug.gdb or policy.debug.gdbserver:
        report_progress(progress, "disk.deploy", "expanding the verified debugger runtime")
        _deploy_debug_runtime(build_directory / DEBUG_RUNTIME_NAME, patch_mount)
    if policy.ssh.enabled:
        if host_identity is None:
            raise PlatformError("SSH policy requires generated Dropbear host keys")
        report_progress(progress, "disk.deploy", "installing the generated Dropbear host keys")
        _deploy_host_identity(host_identity, patch_mount)

    report_progress(progress, "disk.deploy", "installing GRUB on the target disk")
    install_grub(
        runner=runner,
        device=device,
        boot_mount=boot_mount,
        grub_config=build_directory / "boot/grub/grub.cfg",
    )
    report_progress(progress, "disk.deploy", "flushing target filesystems")
    runner.run([runner.require("sync")])
    report_progress(progress, "disk.deploy", "performing final byte-for-byte checks")
    _require_equal(patched_kernel_source, patched_kernel_target)
    _require_equal(patched_rootfs_source, patched_rootfs_target)
    validate_stock_tree(boot_mount, profile)
    report_progress(progress, "disk.deploy", "completed")


def _copy_verified(source: Path, target: Path, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)
    _require_equal(source, target)


def _require_equal(source: Path, target: Path) -> None:
    if source.stat().st_size != target.stat().st_size or hash_file(source) != hash_file(target):
        raise PlatformError(f"deployed file failed byte verification: {target}")


def _deploy_debug_runtime(archive_path: Path, patch_mount: Path) -> None:
    data = archive_path.read_bytes()
    verify_debug_runtime_data(data)
    target = patch_mount / "gdb-runtime"
    # The fixed-size patch partition cannot hold two expanded debugger runtimes at once.
    # ``apply_disk_plan`` has already created and verified a full-disk recovery image, so
    # reclaim the old tree before staging its verified replacement. Any later failure is
    # handled by the enclosing deployment transaction's full-disk rollback.
    if target.exists():
        shutil.rmtree(target)
    stage = Path(tempfile.mkdtemp(prefix=".gdb-runtime-", dir=patch_mount))
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            archive.extractall(stage, filter="fully_trusted")
        extracted = stage / "fortigdb"
        required = (
            extracted / "bin/gdb.real",
            extracted / "bin/gdbserver.real",
            extracted / "lib/ld-linux-x86-64.so.2",
        )
        if any(not path.is_file() or not os.access(path, os.X_OK) for path in required):
            raise PlatformError("expanded debugger runtime is incomplete")
        (extracted / ".runtime-sha256").write_text(DEBUG_RUNTIME_SHA256 + "\n", encoding="ascii")
        os.replace(extracted, target)
        if (target / ".runtime-sha256").read_text(encoding="ascii").strip() != (
            DEBUG_RUNTIME_SHA256
        ):
            raise PlatformError("deployed debugger runtime fingerprint marker is invalid")
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _deploy_host_identity(host_identity: HostIdentity, patch_mount: Path) -> None:
    identity = patch_mount / "identity"
    identity.mkdir(mode=0o700, exist_ok=True)
    identity.chmod(0o700)
    targets = (
        (host_identity.rsa_private_key, identity / "dropbear_rsa_host_key"),
        (host_identity.ed25519_private_key, identity / "dropbear_ed25519_host_key"),
    )
    for source, target in targets:
        shutil.copyfile(source, target)
        target.chmod(0o600)
        _require_equal(source, target)
