"""Read-only disk planning, stale-plan validation, deployment, and recovery."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

from fortigate_patcher.application.profiles import resolve_profile
from fortigate_patcher.domain.deployment import (
    DEPLOYMENT_PLAN_NAME,
    DEPLOYMENT_PLAN_SCHEMA_VERSION,
    DeploymentPlan,
    PlannedDevice,
    PlannedLayout,
    PlannedPartition,
    load_deployment_plan,
    serialize_deployment_plan,
)
from fortigate_patcher.domain.errors import PlanError
from fortigate_patcher.domain.manifest import BUILD_MANIFEST_NAME, load_build_manifest
from fortigate_patcher.domain.policy import BuildPolicy, policy_from_mapping
from fortigate_patcher.domain.progress import ProgressCallback, report_progress
from fortigate_patcher.domain.profile import FirmwareProfile
from fortigate_patcher.firmware.hashing import hash_file
from fortigate_patcher.platform.backup import create_disk_backup, restore_disk_backup
from fortigate_patcher.platform.block_device import (
    BlockDeviceState,
    LayoutPlan,
    LinuxBlockDeviceInspector,
    calculate_layout,
)
from fortigate_patcher.platform.credentials import (
    create_or_load_environment,
    generate_dropbear_host_keys,
    load_environment,
)
from fortigate_patcher.platform.deployment import deploy_build
from fortigate_patcher.platform.mounts import MountManager
from fortigate_patcher.platform.process import Runner, SubprocessRunner, require_root

from .build import build_image
from .verify import verify_image


def create_disk_plan(
    *,
    profile: FirmwareProfile,
    device: Path,
    workspace: Path,
    backup_directory: Path,
    policy: BuildPolicy,
    environment_directory: Path | None = None,
    runner: Runner | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    """Build artifacts and write a plan while proving the target disk is unchanged."""
    report_progress(progress, "disk.plan", "checking privileges")
    require_root()
    runner = runner or SubprocessRunner(progress=progress)
    inspector = LinuxBlockDeviceInspector(runner)
    report_progress(progress, "disk.plan", "preparing workspace and backup paths")
    workspace = workspace.expanduser().resolve(strict=False)
    backup_directory = backup_directory.expanduser().resolve(strict=False)
    workspace.mkdir(parents=True, exist_ok=True)
    backup_directory.mkdir(parents=True, exist_ok=True)
    plan_path = workspace / DEPLOYMENT_PLAN_NAME
    if plan_path.exists():
        raise PlanError(f"deployment plan already exists: {plan_path}")

    report_progress(progress, "disk.plan", f"inspecting target device: {device}")
    initial = inspector.inspect(device)
    report_progress(
        progress,
        "disk.plan",
        f"validating safety constraints and partition layout for {initial.path}",
    )
    inspector.assert_safe_host_paths(initial, (workspace, backup_directory))
    if any(partition.mountpoints for partition in initial.partitions):
        raise PlanError("all target-disk partitions must be unmounted for disk plan")
    layout = calculate_layout(initial)
    disk_hash_before = _hash_device(
        initial.path,
        initial.size_bytes,
        progress,
        "disk.plan",
        "hashing target disk before planning",
    )
    report_progress(progress, "disk.plan", "loading or creating the target environment")
    environment = create_or_load_environment(environment_directory, runner)
    plan_id = str(uuid.uuid4())
    build_directory = workspace / f"build-{profile.profile_id}-{environment.environment_id}"
    mountpoint = workspace / f".boot-readonly-{plan_id}"
    mounts = MountManager(runner)
    boot_partition = initial.partition(1)
    report_progress(progress, "disk.plan", "mounting the BOOT partition read-only")
    with mounts.mounted(
        boot_partition.path,
        mountpoint,
        read_only=True,
        filesystem=boot_partition.filesystem,
    ) as boot:
        build_image(
            profile=profile,
            boot_directory=boot,
            output_directory=build_directory,
            policy=policy,
            environment=environment,
            replace=False,
            progress=progress,
        )
    report_progress(progress, "disk.plan", "verifying the completed build")
    verification = verify_image(build_directory, profile, progress=progress)
    if verification.environment_id != environment.environment_id:
        raise PlanError("built image environment differs from requested environment")

    report_progress(progress, "disk.plan", "re-inspecting the target after read-only work")
    final = inspector.inspect(initial.path)
    disk_hash_after = _hash_device(
        final.path,
        final.size_bytes,
        progress,
        "disk.plan",
        "hashing target disk after planning",
    )
    if disk_hash_after != disk_hash_before:
        raise PlanError("disk changed during read-only planning")
    _require_same_device_snapshot(initial, final)
    plan_backup_directory = backup_directory / plan_id
    backup_image = plan_backup_directory / f"{initial.path.name}.img.zst"
    plan = DeploymentPlan(
        schema_version=DEPLOYMENT_PLAN_SCHEMA_VERSION,
        plan_id=plan_id,
        created_at=datetime.now(UTC).isoformat(),
        profile_id=profile.profile_id,
        device=_planned_device(initial, disk_hash_before),
        layout=_planned_layout(layout),
        stock_fingerprints=MappingProxyType(dict(profile.scan_file_sha256)),
        artifact_manifest_sha256=hash_file(build_directory / BUILD_MANIFEST_NAME),
        environment_id=environment.environment_id,
        client_public_key_fingerprint=environment.client_fingerprint,
        build_directory=str(build_directory),
        environment_directory=str(environment.directory),
        backup_directory=str(plan_backup_directory),
        backup_image=str(backup_image),
        operations=_planned_operations(layout),
    )
    report_progress(progress, "disk.plan", f"writing deployment plan: {plan_path}")
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=".deployment-plan-",
        suffix=".json",
        dir=workspace,
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(serialize_deployment_plan(plan))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, plan_path)
    finally:
        temporary.unlink(missing_ok=True)
    report_progress(progress, "disk.plan", "completed without modifying the target disk")
    return plan_path


def apply_disk_plan(
    *,
    plan_file: Path,
    confirm_device: Path,
    runner: Runner | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    """Revalidate a plan, back up the disk, apply it, and auto-restore on failure."""
    report_progress(progress, "disk.apply", "checking privileges and loading the plan")
    require_root()
    runner = runner or SubprocessRunner(progress=progress)
    plan = load_deployment_plan(plan_file)
    profile = resolve_profile(plan.profile_id)
    if dict(plan.stock_fingerprints) != dict(profile.scan_file_sha256):
        raise PlanError("deployment plan stock fingerprints do not match its profile")
    _validate_plan_paths(plan)
    inspector = LinuxBlockDeviceInspector(runner)
    report_progress(progress, "disk.apply", f"inspecting planned device: {plan.device.path}")
    current = inspector.inspect(Path(plan.device.path))
    current_hash = _hash_device(
        current.path,
        current.size_bytes,
        progress,
        "disk.apply",
        "revalidating the complete target-disk SHA-256",
    )
    report_progress(progress, "disk.apply", "checking device identity, layout, and host paths")
    validate_plan_device(plan, current, current_hash, confirm_device)
    inspector.assert_safe_host_paths(
        current,
        (
            Path(plan.build_directory),
            Path(plan.environment_directory),
            Path(plan.backup_directory),
        ),
    )
    if any(partition.mountpoints for partition in current.partitions):
        raise PlanError("all target-disk partitions must be unmounted before disk apply")
    build_directory = Path(plan.build_directory)
    report_progress(progress, "disk.apply", "revalidating planned build artifacts")
    verification = verify_image(build_directory, profile, progress=progress)
    if (
        hash_file(build_directory / BUILD_MANIFEST_NAME) != plan.artifact_manifest_sha256
        or verification.environment_id != plan.environment_id
        or verification.client_fingerprint != plan.client_public_key_fingerprint
    ):
        raise PlanError("build artifacts no longer match the deployment plan")
    report_progress(progress, "disk.apply", "revalidating the target environment")
    environment = load_environment(Path(plan.environment_directory))
    if environment.environment_id != plan.environment_id:
        raise PlanError("environment no longer matches the deployment plan")
    manifest = load_build_manifest(build_directory / BUILD_MANIFEST_NAME)
    policy = policy_from_mapping(manifest.policy)

    backup_directory = Path(plan.backup_directory)
    if backup_directory.exists():
        raise PlanError(f"backup directory already exists: {backup_directory}")
    backup_directory.mkdir(parents=True, mode=0o700)
    report_progress(progress, "disk.apply", "saving pre-write recovery metadata")
    _save_prewrite_metadata(current, backup_directory, runner, plan_file)
    report_progress(progress, "disk.apply", "creating and verifying the full-disk backup")
    backup = create_disk_backup(
        device=current.path,
        image=Path(plan.backup_image),
        expected_size=current.size_bytes,
        runner=runner,
        progress=progress,
    )
    if backup.disk_sha256 != plan.device.content_sha256:
        raise PlanError("backup source hash differs from the validated plan")
    if policy.ssh.enabled:
        report_progress(progress, "disk.apply", "creating or validating Dropbear host identity")
        host_identity = generate_dropbear_host_keys(environment, runner)
    else:
        host_identity = None

    mutated = False
    try:
        layout = calculate_layout(current)
        if _planned_layout(layout) != plan.layout:
            raise PlanError("calculated partition layout differs from the plan")
        if not layout.reuse_partition4:
            mutated = True
            report_progress(progress, "disk.apply", "applying the reviewed partition layout")
            _apply_partition_layout(current, layout, runner, progress=progress)
        else:
            report_progress(progress, "disk.apply", "reusing the existing FGT_PATCH partition")
        report_progress(progress, "disk.apply", "re-inspecting the written partition layout")
        refreshed = inspector.inspect(current.path)
        partition1 = refreshed.partition(1)
        partition4 = refreshed.partition(4)
        if partition4.filesystem != "ext4" or partition4.label != "FGT_PATCH":
            raise PlanError("partition 4 did not become the expected FGT_PATCH ext4 filesystem")
        mount_root = plan_file.resolve().parent / f".apply-mount-{plan.plan_id}"
        mount_root.mkdir(mode=0o700, exist_ok=False)
        mounts = MountManager(runner)
        try:
            report_progress(progress, "disk.apply", "mounting BOOT and FGT_PATCH")
            with ExitStack() as stack:
                boot_mount = stack.enter_context(
                    mounts.mounted(partition1.path, mount_root / "boot")
                )
                patch_mount = stack.enter_context(
                    mounts.mounted(partition4.path, mount_root / "patch", filesystem="ext4")
                )
                mutated = True
                deploy_build(
                    runner=runner,
                    profile=profile,
                    policy=policy,
                    build_directory=build_directory,
                    boot_mount=boot_mount,
                    patch_mount=patch_mount,
                    device=current.path,
                    host_identity=host_identity,
                    progress=progress,
                )
        finally:
            try:
                mount_root.rmdir()
            except OSError:
                pass
        report = backup_directory / "deployment-report.json"
        report_progress(progress, "disk.apply", f"writing deployment report: {report}")
        report.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "success",
                    "plan_id": plan.plan_id,
                    "profile": profile.profile_id,
                    "device": str(current.path),
                    "backup_image": str(backup.image),
                    "backup_sha256": backup.compressed_sha256,
                    "original_disk_sha256": backup.disk_sha256,
                    "environment_id": environment.environment_id,
                    "client_public_key_fingerprint": environment.client_fingerprint,
                    "host_public_key_fingerprints": (
                        {
                            "rsa": host_identity.rsa_fingerprint,
                            "ed25519": host_identity.ed25519_fingerprint,
                        }
                        if host_identity is not None
                        else {}
                    ),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        report_progress(progress, "disk.apply", "completed and verified")
        return report
    except BaseException as original:
        if not mutated:
            raise
        try:
            report_progress(
                progress,
                "disk.apply",
                "deployment failed after a write; restoring the verified backup",
            )
            restore_disk_backup(
                image=backup.image,
                device=current.path,
                confirm_device=current.path,
                expected_size=current.size_bytes,
                runner=runner,
                progress=progress,
            )
            _settle_partition_table(current.path, runner)
            report_progress(progress, "disk.apply", "automatic recovery completed")
        except BaseException as restore_error:
            raise PlanError(
                f"deployment failed and automatic recovery also failed: "
                f"deployment={original}; recovery={restore_error}"
            ) from restore_error
        raise PlanError(
            f"deployment failed; original disk image was restored: {original}"
        ) from original


def restore_disk(
    *,
    backup: Path,
    device: Path,
    confirm_device: Path,
    runner: Runner | None = None,
    progress: ProgressCallback | None = None,
) -> str:
    """Restore a recorded full-disk backup to an explicitly confirmed device."""
    report_progress(progress, "disk.restore", "checking privileges")
    require_root()
    runner = runner or SubprocessRunner(progress=progress)
    inspector = LinuxBlockDeviceInspector(runner)
    report_progress(progress, "disk.restore", f"inspecting restore target: {device}")
    state = inspector.inspect(device)
    if any(partition.mountpoints for partition in state.partitions):
        raise PlanError("all target-disk partitions must be unmounted before restore")
    digest = restore_disk_backup(
        image=backup,
        device=state.path,
        confirm_device=confirm_device,
        expected_size=state.size_bytes,
        runner=runner,
        progress=progress,
    )
    report_progress(progress, "disk.restore", "refreshing the kernel partition table")
    _settle_partition_table(state.path, runner)
    report_progress(progress, "disk.restore", "restore completed and verified")
    return digest


def validate_plan_device(
    plan: DeploymentPlan,
    current: BlockDeviceState,
    current_content_sha256: str,
    confirm_device: Path,
) -> None:
    """Reject a mismatched confirmation, changed identity, geometry, or disk content."""
    if confirm_device.resolve(strict=True) != current.path:
        raise PlanError("--confirm-device does not resolve to the planned device")
    expected = plan.device
    actual = _planned_device(current, current_content_sha256)
    if actual != expected:
        raise PlanError("deployment plan is stale or the target device does not match")
    layout = calculate_layout(current)
    if _planned_layout(layout) != plan.layout:
        raise PlanError("deployment plan layout is stale")


def _validate_plan_paths(plan: DeploymentPlan) -> None:
    paths = (
        Path(plan.build_directory),
        Path(plan.environment_directory),
        Path(plan.backup_directory),
        Path(plan.backup_image),
    )
    if any(not path.is_absolute() for path in paths):
        raise PlanError("deployment plan paths must be absolute")
    if Path(plan.backup_image).parent != Path(plan.backup_directory):
        raise PlanError("deployment plan backup image must be inside its backup directory")


def _planned_device(state: BlockDeviceState, content_sha256: str) -> PlannedDevice:
    return PlannedDevice(
        path=str(state.path),
        major_minor=state.major_minor,
        size_bytes=state.size_bytes,
        sector_size=state.sector_size,
        model=state.model,
        serial=state.serial,
        wwn=state.wwn,
        content_sha256=content_sha256,
        partition_table_sha256=state.partition_table_sha256,
        partitions=tuple(
            PlannedPartition(
                number=value.number,
                path=str(value.path),
                start_sector=value.start_sector,
                size_bytes=value.size_bytes,
                filesystem=value.filesystem,
                label=value.label,
            )
            for value in state.partitions
        ),
    )


def _planned_layout(layout: LayoutPlan) -> PlannedLayout:
    return PlannedLayout(
        partition2_start=layout.partition2_start,
        partition2_current_size=layout.partition2_current_size,
        partition2_new_size=layout.partition2_new_size,
        partition2_resize_mib=layout.partition2_resize_mib,
        partition4_start=layout.partition4_start,
        partition4_size=layout.partition4_size,
        reuse_partition4=layout.reuse_partition4,
    )


def _planned_operations(layout: LayoutPlan) -> tuple[str, ...]:
    operations = ["create and verify full compressed disk backup"]
    if layout.partition2_resize_mib is not None:
        operations.append("check and shrink partition 2 ext3 filesystem")
        operations.append("shrink partition 2 table entry")
    if not layout.reuse_partition4:
        operations.append("create and format partition 4 as ext4 FGT_PATCH")
    operations.extend(
        (
            "deploy flatkc_p to partition 1",
            "deploy rootfs_p.gz, debugger runtime, and host identity to partition 4",
            "install i386-pc GRUB and verify deployed bytes",
        )
    )
    return tuple(operations)


def _require_same_device_snapshot(before: BlockDeviceState, after: BlockDeviceState) -> None:
    if before != after:
        raise PlanError("device identity or partition table changed during planning")


def _save_prewrite_metadata(
    state: BlockDeviceState,
    directory: Path,
    runner: Runner,
    plan_file: Path,
) -> None:
    (directory / "partition-table.sfdisk").write_text(state.partition_table, encoding="utf-8")
    partitions = [partition.path for partition in state.partitions]
    blkid = runner.run([runner.require("blkid"), *partitions], allowed_returncodes=(0, 2))
    (directory / "blkid.txt").write_text(blkid.stdout, encoding="utf-8")
    runner.run(
        [
            runner.require("dd"),
            f"if={state.path}",
            f"of={directory / 'first-4MiB.bin'}",
            "bs=1M",
            "count=4",
            "status=none",
        ]
    )
    shutil.copyfile(plan_file, directory / DEPLOYMENT_PLAN_NAME)


def _apply_partition_layout(
    state: BlockDeviceState,
    layout: LayoutPlan,
    runner: Runner,
    *,
    progress: ProgressCallback | None = None,
) -> None:
    partition2 = state.partition(2)
    report_progress(progress, "disk.partition", "checking partition 2 filesystem")
    runner.run(
        [runner.require("e2fsck"), "-f", "-y", partition2.path],
        allowed_returncodes=(0, 1),
    )
    sfdisk = runner.require("sfdisk")
    if layout.partition2_resize_mib is not None:
        report_progress(progress, "disk.partition", "shrinking partition 2 filesystem")
        runner.run(
            [
                runner.require("resize2fs"),
                partition2.path,
                f"{layout.partition2_resize_mib}M",
            ]
        )
        report_progress(progress, "disk.partition", "updating partition 2 table entry")
        runner.run(
            [sfdisk, "--force", "-N", "2", state.path],
            input_text=(f"{layout.partition2_start},{layout.partition2_new_size},83\n"),
        )
        _settle_partition_table(state.path, runner)
        report_progress(progress, "disk.partition", "expanding partition 2 to its table boundary")
        runner.run([runner.require("resize2fs"), partition2.path])
    report_progress(progress, "disk.partition", "creating partition 4 table entry")
    runner.run(
        [sfdisk, "--force", "-N", "4", state.path],
        input_text=f"{layout.partition4_start},{layout.partition4_size},83\n",
    )
    _settle_partition_table(state.path, runner)
    refreshed = LinuxBlockDeviceInspector(runner).inspect(state.path)
    partition4 = refreshed.partition(4)
    report_progress(progress, "disk.partition", "formatting partition 4 as FGT_PATCH ext4")
    runner.run(
        [
            runner.require("mkfs.ext4"),
            "-F",
            "-L",
            "FGT_PATCH",
            "-m",
            "0",
            "-T",
            "largefile4",
            "-N",
            "4096",
            "-J",
            "size=4",
            partition4.path,
        ]
    )
    _settle_partition_table(state.path, runner)


def _hash_device(
    device: Path,
    size_bytes: int,
    progress: ProgressCallback | None,
    stage: str,
    message: str,
) -> str:
    return hash_file(
        device,
        progress=lambda completed: report_progress(
            progress,
            stage,
            message,
            completed=completed,
            total=size_bytes,
        ),
    )


def _settle_partition_table(device: Path, runner: Runner) -> None:
    runner.run([runner.require("partprobe"), device])
    runner.run([runner.require("udevadm"), "settle"])
