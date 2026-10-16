"""Atomic deterministic image-build use case."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from fortigate_patcher import __version__
from fortigate_patcher.domain.environment import EnvironmentIdentity
from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.manifest import (
    BUILD_MANIFEST_NAME,
    BUILD_MANIFEST_SCHEMA_VERSION,
    ArtifactFingerprint,
    BuildManifest,
    serialize_build_manifest,
)
from fortigate_patcher.domain.policy import BuildPolicy
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.domain.profile import FirmwareProfile
from fortigate_patcher.firmware.debug_runtime import DEBUG_RUNTIME_NAME, verified_debug_runtime
from fortigate_patcher.firmware.flatkc import locate_kernel_piggy, patch_flatkc
from fortigate_patcher.firmware.hashing import hash_file, sha256_bytes
from fortigate_patcher.firmware.image import build_patched_rootfs
from fortigate_patcher.firmware.stock import validate_stock_tree

from .verify import GRUB_CONFIG_NAME, artifact_names, render_grub_config, verify_image


@dataclass(frozen=True, slots=True)
class BuildResult:
    """Paths and public identity returned by a completed image build."""

    output_directory: Path
    manifest_path: Path
    environment_id: str
    client_fingerprint: str


def build_image(
    *,
    profile: FirmwareProfile,
    boot_directory: Path,
    output_directory: Path,
    policy: BuildPolicy,
    environment: EnvironmentIdentity,
    replace: bool = False,
    progress: ProgressCallback | None = None,
) -> BuildResult:
    """Build and verify a decoupled BOOT tree, then atomically publish it."""
    environment.validate()
    boot_directory = boot_directory.resolve()
    output_directory = output_directory.resolve()
    _validate_directory_relationship(boot_directory, output_directory)
    report_progress(progress, "image.build", "validating stock BOOT files")
    validate_stock_tree(boot_directory, profile)
    if output_directory.exists() and not replace:
        raise FirmwareError(f"output directory already exists: {output_directory} (use --replace)")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}.build-", dir=output_directory.parent)
    )
    previous: Path | None = None
    try:
        report_progress(progress, "image.build", "copying the stock file set to staging")
        for name in profile.required_inputs:
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(boot_directory / name, target)

        stock_flatkc = (boot_directory / "flatkc").read_bytes()
        stock_rootfs = (boot_directory / "rootfs.gz").read_bytes()
        report_progress(progress, "image.build", "decrypting and patching rootfs")
        rootfs_result = build_patched_rootfs(
            protected_rootfs=stock_rootfs,
            stock_flatkc=stock_flatkc,
            profile=profile,
            policy=policy,
            environment=environment,
        )
        (staging / profile.patched_rootfs_name).write_bytes(rootfs_result.container)
        report_progress(progress, "image.build", "patching the kernel image")
        patched_flatkc = patch_flatkc(stock_flatkc, profile)
        (staging / profile.patched_flatkc_name).write_bytes(patched_flatkc)
        grub_path = staging / GRUB_CONFIG_NAME
        grub_path.parent.mkdir(parents=True, exist_ok=True)
        grub_path.write_bytes(render_grub_config(profile))
        if policy.debug.gdb or policy.debug.gdbserver:
            report_progress(progress, "image.build", "adding the verified debugger runtime")
            (staging / DEBUG_RUNTIME_NAME).write_bytes(verified_debug_runtime())

        report_progress(progress, "image.build", "fingerprinting generated artifacts")
        artifacts = {
            name: ArtifactFingerprint(
                size=(staging / name).stat().st_size,
                sha256=hash_file(staging / name),
            )
            for name in sorted(artifact_names(profile, policy))
        }
        kernel = locate_kernel_piggy(patched_flatkc).decompressed
        core = {
            "kernel_elf": sha256_bytes(kernel),
            profile.patched_flatkc_name: sha256_bytes(patched_flatkc),
            "plaintext_rootfs_gzip": rootfs_result.plaintext_gzip_sha256,
            "rootfs_cpio": rootfs_result.cpio_sha256,
            **{
                f"patched_file:{name}": digest
                for name, digest in sorted(rootfs_result.patched_file_sha256.items())
            },
        }
        manifest = BuildManifest(
            schema_version=BUILD_MANIFEST_SCHEMA_VERSION,
            tool_version=__version__,
            profile_id=profile.profile_id,
            firmware_version=profile.version,
            firmware_build=profile.build,
            environment_id=environment.environment_id,
            client_public_key_fingerprint=environment.client_fingerprint,
            policy=MappingProxyType(policy.manifest_value()),
            outputs=MappingProxyType(
                {
                    "flatkc": profile.patched_flatkc_name,
                    "rootfs": profile.patched_rootfs_name,
                    "grub": GRUB_CONFIG_NAME,
                }
            ),
            core_fingerprints=MappingProxyType(core),
            artifacts=MappingProxyType(artifacts),
        )
        report_progress(progress, "image.build", "writing and verifying the build manifest")
        (staging / BUILD_MANIFEST_NAME).write_bytes(serialize_build_manifest(manifest))
        verify_image(staging, profile, progress=progress)

        report_progress(progress, "image.build", f"publishing build: {output_directory}")
        if output_directory.exists():
            previous = Path(
                tempfile.mkdtemp(
                    prefix=f".{output_directory.name}.previous-",
                    dir=output_directory.parent,
                )
            )
            previous.rmdir()
            os.replace(output_directory, previous)
        try:
            os.replace(staging, output_directory)
        except BaseException:
            if previous is not None and previous.exists() and not output_directory.exists():
                os.replace(previous, output_directory)
            raise
        if previous is not None:
            shutil.rmtree(previous)
        result = BuildResult(
            output_directory=output_directory,
            manifest_path=output_directory / BUILD_MANIFEST_NAME,
            environment_id=environment.environment_id,
            client_fingerprint=environment.client_fingerprint,
        )
        report_progress(progress, "image.build", "completed")
        return result
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _validate_directory_relationship(boot_directory: Path, output_directory: Path) -> None:
    if boot_directory == output_directory:
        raise FirmwareError("output directory must differ from the stock BOOT directory")
    if boot_directory in output_directory.parents:
        raise FirmwareError("output directory must not be inside the stock BOOT directory")
    if output_directory in boot_directory.parents:
        raise FirmwareError("output directory must not contain the stock BOOT directory")
