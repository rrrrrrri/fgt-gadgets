"""BIOS GRUB installation for the decoupled FortiOS boot layout."""

from __future__ import annotations

import shutil
from pathlib import Path

from fortigate_patcher.domain.errors import PlatformError

from .process import Runner

GRUB_MODULES = "part_msdos ext2 normal biosdisk ls cat echo serial terminal"


def install_grub(
    *,
    runner: Runner,
    device: Path,
    boot_mount: Path,
    grub_config: Path,
) -> Path:
    """Install i386-pc GRUB and copy the verified configuration."""
    boot_directory = boot_mount / "boot-patch"
    config_target = boot_directory / "grub" / "grub.cfg"
    config_target.parent.mkdir(parents=True, exist_ok=True)
    runner.run(
        [
            runner.require("grub-install"),
            "--target=i386-pc",
            f"--boot-directory={boot_directory}",
            f"--modules={GRUB_MODULES}",
            "--skip-fs-probe",
            "--force",
            device,
        ]
    )
    shutil.copyfile(grub_config, config_target)
    config_target.chmod(0o644)
    if config_target.read_bytes() != grub_config.read_bytes():
        raise PlatformError("deployed GRUB configuration failed byte verification")
    return config_target
