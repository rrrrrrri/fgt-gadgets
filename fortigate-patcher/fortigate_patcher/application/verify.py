"""Static verification of a complete decoupled image build."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fortigate_patcher.domain.environment import EnvironmentIdentity
from fortigate_patcher.domain.errors import VerificationError
from fortigate_patcher.domain.manifest import (
    BUILD_MANIFEST_NAME,
    BuildManifest,
    load_build_manifest,
)
from fortigate_patcher.domain.policy import BuildPolicy, policy_from_mapping
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.domain.profile import FirmwareProfile
from fortigate_patcher.firmware.debug_runtime import (
    DEBUG_RUNTIME_NAME,
    verify_debug_runtime_data,
)
from fortigate_patcher.firmware.flatkc import verify_flatkc
from fortigate_patcher.firmware.hashing import hash_file, sha256_bytes
from fortigate_patcher.firmware.image import (
    extract_authorized_key,
    verify_patched_rootfs,
)
from fortigate_patcher.firmware.ssh import public_key_fingerprint
from fortigate_patcher.firmware.stock import validate_stock_tree

GRUB_CONFIG_NAME = "boot/grub/grub.cfg"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Verified build identity and artifact count."""

    directory: Path
    profile_id: str
    environment_id: str
    client_fingerprint: str
    artifact_count: int


def render_grub_config(profile: FirmwareProfile) -> bytes:
    """Render the deterministic GRUB configuration for a profile."""
    document = f"""set timeout=3
set default=0
serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console

menuentry \"{profile.grub_title}\" {{
    echo \"GRUB: loading {profile.patched_flatkc_name} from partition 1 ...\"
    linux (hd0,msdos1)/{profile.patched_flatkc_name} {profile.grub_kernel_args}
    echo \"GRUB: loading {profile.patched_rootfs_name} from partition 4 ...\"
    initrd (hd0,msdos4)/{profile.patched_rootfs_name}
    echo \"GRUB: booting kernel ...\"
    boot
}}
"""
    return document.encode("ascii")


def artifact_names(profile: FirmwareProfile, policy: BuildPolicy) -> set[str]:
    """Return the exact files represented in a build manifest."""
    names = {
        *profile.required_inputs,
        profile.patched_flatkc_name,
        profile.patched_rootfs_name,
        GRUB_CONFIG_NAME,
    }
    if policy.debug.gdb or policy.debug.gdbserver:
        names.add(DEBUG_RUNTIME_NAME)
    return names


def verify_image(
    directory: Path,
    profile: FirmwareProfile,
    *,
    progress: ProgressCallback | None = None,
) -> VerificationResult:
    """Fail closed unless a build is complete, decoupled, and reproducible."""
    directory = directory.resolve()
    report_progress(progress, "image.verify", f"loading build: {directory}")
    if not directory.is_dir():
        raise VerificationError(f"build directory does not exist: {directory}")
    manifest = load_build_manifest(directory / BUILD_MANIFEST_NAME)
    _verify_manifest_identity(manifest, profile)
    try:
        policy = policy_from_mapping(manifest.policy)
    except Exception as exc:
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError(f"invalid policy in build manifest: {exc}") from exc
    expected_artifacts = artifact_names(profile, policy)
    if set(manifest.artifacts) != expected_artifacts:
        missing = sorted(expected_artifacts - set(manifest.artifacts))
        extra = sorted(set(manifest.artifacts) - expected_artifacts)
        raise VerificationError(
            f"build artifact set mismatch: missing={missing or 'none'} extra={extra or 'none'}"
        )
    actual_files = {
        path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()
    }
    expected_files = expected_artifacts | {BUILD_MANIFEST_NAME}
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        raise VerificationError(
            f"build directory file set mismatch: missing={missing or 'none'} "
            f"extra={extra or 'none'}"
        )
    report_progress(progress, "image.verify", "checking artifact sizes and SHA-256 values")
    for index, (name, record) in enumerate(manifest.artifacts.items(), start=1):
        report_progress(
            progress,
            "image.verify",
            f"checking artifact {index}/{len(manifest.artifacts)}: {name}",
        )
        path = directory / name
        if path.stat().st_size != record.size or hash_file(path) != record.sha256:
            raise VerificationError(f"artifact fingerprint mismatch: {name}")

    report_progress(progress, "image.verify", "validating unchanged stock files")
    validate_stock_tree(directory, profile)
    stock_flatkc = (directory / "flatkc").read_bytes()
    patched_flatkc = (directory / profile.patched_flatkc_name).read_bytes()
    protected_rootfs = (directory / profile.patched_rootfs_name).read_bytes()
    if patched_flatkc == stock_flatkc:
        raise VerificationError("patched flatkc unexpectedly equals stock flatkc")
    if protected_rootfs == (directory / "rootfs.gz").read_bytes():
        raise VerificationError("patched rootfs unexpectedly equals stock rootfs")
    report_progress(progress, "image.verify", "verifying patched kernel invariants")
    kernel = verify_flatkc(patched_flatkc, profile)
    if (directory / GRUB_CONFIG_NAME).read_bytes() != render_grub_config(profile):
        raise VerificationError("GRUB configuration does not match the selected profile")
    if policy.debug.gdb or policy.debug.gdbserver:
        report_progress(progress, "image.verify", "verifying debugger runtime")
        verify_debug_runtime_data((directory / DEBUG_RUNTIME_NAME).read_bytes())

    report_progress(progress, "image.verify", "verifying payload and public-key identity")
    public_key = extract_authorized_key(protected_rootfs, stock_flatkc, profile)
    fingerprint = public_key_fingerprint(public_key)
    if fingerprint != manifest.client_public_key_fingerprint:
        raise VerificationError("client public-key fingerprint differs from build manifest")
    environment = EnvironmentIdentity(
        environment_id=manifest.environment_id,
        directory=Path("."),
        client_public_key=public_key,
        client_fingerprint=fingerprint,
    )
    rootfs_result = verify_patched_rootfs(
        protected_rootfs=protected_rootfs,
        stock_flatkc=stock_flatkc,
        profile=profile,
        policy=policy,
        environment=environment,
    )
    expected_core = {
        "kernel_elf": sha256_bytes(kernel),
        profile.patched_flatkc_name: sha256_bytes(patched_flatkc),
        "plaintext_rootfs_gzip": rootfs_result.plaintext_gzip_sha256,
        "rootfs_cpio": rootfs_result.cpio_sha256,
        **{
            f"patched_file:{name}": digest
            for name, digest in sorted(rootfs_result.patched_file_sha256.items())
        },
    }
    if dict(manifest.core_fingerprints) != expected_core:
        raise VerificationError("build core fingerprints differ from generated contents")
    result = VerificationResult(
        directory=directory,
        profile_id=profile.profile_id,
        environment_id=manifest.environment_id,
        client_fingerprint=fingerprint,
        artifact_count=len(manifest.artifacts),
    )
    report_progress(progress, "image.verify", "completed")
    return result


def _verify_manifest_identity(manifest: BuildManifest, profile: FirmwareProfile) -> None:
    if (
        manifest.profile_id != profile.profile_id
        or manifest.firmware_version != profile.version
        or manifest.firmware_build != profile.build
    ):
        raise VerificationError("build manifest does not match the selected profile")
    expected_outputs = {
        "flatkc": profile.patched_flatkc_name,
        "rootfs": profile.patched_rootfs_name,
        "grub": GRUB_CONFIG_NAME,
    }
    if dict(manifest.outputs) != expected_outputs:
        raise VerificationError("build manifest output names do not match the profile")
