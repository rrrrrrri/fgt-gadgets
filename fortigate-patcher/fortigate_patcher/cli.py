"""The single hierarchical command-line interface for FortiGate Patcher."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import TextIO

from .application.build import build_image
from .application.decrypt import decrypt_rootfs_file
from .application.disk import apply_disk_plan, create_disk_plan, restore_disk
from .application.profiles import get_profile_registry, resolve_profile
from .application.qemu import qemu_smoke
from .application.verify import verify_image
from .domain.deployment import load_deployment_plan
from .domain.errors import FortiGatePatcherError
from .domain.policy import load_policy
from .domain.progress import ProgressCallback, ProgressEvent
from .domain.profile import FirmwareProfile
from .platform.credentials import CLIENT_PRIVATE_KEY, create_or_load_environment
from .platform.process import SubprocessRunner


def create_parser() -> argparse.ArgumentParser:
    """Create the complete argument parser without performing I/O."""
    parser = argparse.ArgumentParser(
        prog="fortigate-patcher",
        description="FortiGate Patcher: version-aware FortiGate VM firmware research tooling",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show staged progress and subprocess diagnostics on stderr",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    profile = commands.add_parser("profile", help="inspect bundled firmware profiles")
    profile_commands = profile.add_subparsers(dest="profile_command", required=True)
    profile_commands.add_parser("list", help="list supported profiles")
    profile_show = profile_commands.add_parser("show", help="show one validated profile")
    profile_show.add_argument("profile")

    rootfs = commands.add_parser("rootfs", help="work with protected rootfs containers")
    rootfs_commands = rootfs.add_subparsers(dest="rootfs_command", required=True)
    decrypt = rootfs_commands.add_parser("decrypt", help="verify and decrypt rootfs")
    decrypt.add_argument("--profile", required=True)
    decrypt.add_argument("--flatkc", required=True, type=Path)
    decrypt.add_argument("--rootfs", required=True, type=Path)
    decrypt.add_argument("--output", required=True, type=Path)
    decrypt.add_argument("--replace", action="store_true")
    _add_verbose_option(decrypt)

    image = commands.add_parser("image", help="build or verify decoupled images")
    image_commands = image.add_subparsers(dest="image_command", required=True)
    build = image_commands.add_parser("build", help="build a verified decoupled image")
    build.add_argument("--profile", required=True)
    build.add_argument("--boot-dir", required=True, type=Path)
    build.add_argument("--output-dir", required=True, type=Path)
    build.add_argument("--policy", type=Path)
    build.add_argument("--environment-dir", type=Path)
    build.add_argument("--replace", action="store_true")
    _add_verbose_option(build)
    verify = image_commands.add_parser("verify", help="verify a completed image build")
    verify.add_argument("--profile", required=True)
    verify.add_argument("--directory", required=True, type=Path)
    _add_verbose_option(verify)

    disk = commands.add_parser("disk", help="plan, apply, or recover disk deployment")
    disk_commands = disk.add_subparsers(dest="disk_command", required=True)
    plan = disk_commands.add_parser("plan", help="create a read-only deployment plan")
    plan.add_argument("--profile", required=True)
    plan.add_argument("--device", required=True, type=Path)
    plan.add_argument("--workspace", required=True, type=Path)
    plan.add_argument("--backup-dir", required=True, type=Path)
    plan.add_argument("--policy", type=Path)
    plan.add_argument("--environment-dir", type=Path)
    _add_verbose_option(plan)
    apply = disk_commands.add_parser("apply", help="apply a fully revalidated plan")
    apply.add_argument("--plan-file", required=True, type=Path)
    apply.add_argument("--confirm-device", required=True, type=Path)
    _add_verbose_option(apply)
    restore = disk_commands.add_parser("restore", help="restore a full-disk zstd backup")
    restore.add_argument("--backup", required=True, type=Path)
    restore.add_argument("--device", required=True, type=Path)
    restore.add_argument("--confirm-device", required=True, type=Path)
    _add_verbose_option(restore)

    qemu = commands.add_parser("qemu", help="run isolated QEMU checks")
    qemu_commands = qemu.add_subparsers(dest="qemu_command", required=True)
    smoke = qemu_commands.add_parser("smoke", help="run a direct-kernel smoke boot")
    smoke.add_argument("--build-dir", required=True, type=Path)
    smoke.add_argument("--work-dir", required=True, type=Path)
    smoke.add_argument("--timeout", type=float, default=90.0)
    _add_verbose_option(smoke)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and translate expected failures into a status-one diagnostic."""
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    progress: ProgressCallback | None = _VerboseProgress(sys.stderr) if args.verbose else None
    try:
        if args.command == "profile":
            return _profile_command(args)
        if args.command == "rootfs":
            return _rootfs_command(args, progress)
        if args.command == "image":
            return _image_command(args, progress)
        if args.command == "disk":
            return _disk_command(args, progress)
        if args.command == "qemu":
            return _qemu_command(args, progress)
        parser.error("unknown command")
    except (FortiGatePatcherError, OSError) as exc:
        print(f"fortigate-patcher: error: {exc}", file=sys.stderr)
        return 1
    return 2


def _profile_command(args: argparse.Namespace) -> int:
    registry = get_profile_registry()
    if args.profile_command == "list":
        print(registry.format_table())
        return 0
    profile = registry.resolve(args.profile)
    print(json.dumps(_profile_document(profile), indent=2, sort_keys=True))
    return 0


def _rootfs_command(args: argparse.Namespace, progress: ProgressCallback | None) -> int:
    profile = resolve_profile(args.profile)
    result = decrypt_rootfs_file(
        profile=profile,
        flatkc_path=args.flatkc,
        rootfs_path=args.rootfs,
        output_path=args.output,
        replace=args.replace,
        progress=progress,
    )
    print(
        f"plaintext rootfs: {result.output}\n"
        f"sha256: {result.sha256}\n"
        f"gzip bytes: {result.gzip_size}\n"
        f"cpio bytes: {result.cpio_size}"
    )
    return 0


def _image_command(args: argparse.Namespace, progress: ProgressCallback | None) -> int:
    profile = resolve_profile(args.profile)
    if args.image_command == "verify":
        verification = verify_image(args.directory, profile, progress=progress)
        print(
            f"verified {verification.artifact_count} artifacts for {verification.profile_id}\n"
            f"environment: {verification.environment_id}\n"
            f"client key: {verification.client_fingerprint}"
        )
        return 0
    runner = SubprocessRunner(progress=progress)
    policy = load_policy(args.policy)
    environment = create_or_load_environment(args.environment_dir, runner)
    build = build_image(
        profile=profile,
        boot_directory=args.boot_dir,
        output_directory=args.output_dir,
        policy=policy,
        environment=environment,
        replace=args.replace,
        progress=progress,
    )
    _print_environment(environment.directory, environment.client_fingerprint, policy.ssh.port)
    print(f"build: {build.output_directory}\nmanifest: {build.manifest_path}")
    return 0


def _disk_command(args: argparse.Namespace, progress: ProgressCallback | None) -> int:
    if args.disk_command == "plan":
        profile = resolve_profile(args.profile)
        policy = load_policy(args.policy)
        path = create_disk_plan(
            profile=profile,
            device=args.device,
            workspace=args.workspace,
            backup_directory=args.backup_dir,
            policy=policy,
            environment_directory=args.environment_dir,
            progress=progress,
        )
        plan = load_deployment_plan(path)
        _print_environment(
            Path(plan.environment_directory),
            plan.client_public_key_fingerprint,
            policy.ssh.port,
        )
        print(f"read-only deployment plan: {path}\ndisk SHA-256: {plan.device.content_sha256}")
        return 0
    if args.disk_command == "apply":
        report = apply_disk_plan(
            plan_file=args.plan_file,
            confirm_device=args.confirm_device,
            progress=progress,
        )
        plan = load_deployment_plan(args.plan_file)
        report_data = json.loads(report.read_text(encoding="utf-8"))
        manifest = json.loads(
            (Path(plan.build_directory) / "BUILD_MANIFEST.json").read_text(encoding="utf-8")
        )
        port = int(manifest["policy"]["ssh"]["port"])
        _print_environment(
            Path(plan.environment_directory),
            plan.client_public_key_fingerprint,
            port,
        )
        host_fingerprints = report_data.get("host_public_key_fingerprints", {})
        for key_type, fingerprint in sorted(host_fingerprints.items()):
            print(f"Dropbear {key_type} host key: {fingerprint}")
        print(f"deployment completed and verified: {report}")
        return 0
    digest = restore_disk(
        backup=args.backup,
        device=args.device,
        confirm_device=args.confirm_device,
        progress=progress,
    )
    print(f"disk restored and verified: sha256={digest}")
    return 0


def _qemu_command(args: argparse.Namespace, progress: ProgressCallback | None) -> int:
    result = qemu_smoke(
        build_directory=args.build_dir,
        work_directory=args.work_dir,
        timeout_seconds=args.timeout,
        progress=progress,
    )
    print(
        f"QEMU smoke passed\ndisk: {result.disk_image}\nserial log: {result.serial_log}\n"
        f"timed out after successful boot: {result.qemu.timed_out}"
    )
    return 0


def _print_environment(directory: Path, fingerprint: str, port: int) -> None:
    private_key = directory / CLIENT_PRIVATE_KEY
    print(
        f"environment: {directory}\n"
        f"client key fingerprint: {fingerprint}\n"
        f"SSH: ssh -i {private_key} -p {port} root@TARGET_IP"
    )


def _add_verbose_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="show staged progress and subprocess diagnostics on stderr",
    )


class _VerboseProgress:
    """Render structured progress events without changing normal stdout."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream
        self._started = time.monotonic()
        self._broken = False

    def __call__(self, event: ProgressEvent) -> None:
        if self._broken:
            return
        elapsed = time.monotonic() - self._started
        suffix = ""
        if event.completed is not None:
            suffix = f" [{_format_bytes(event.completed)}"
            if event.total is not None:
                suffix += f" / {_format_bytes(event.total)}"
                if event.total > 0:
                    suffix += f", {event.completed / event.total * 100:.1f}%"
            suffix += "]"
        try:
            print(
                f"[+{elapsed:7.1f}s] {event.stage}: {event.message}{suffix}",
                file=self._stream,
                flush=True,
            )
        except BrokenPipeError:
            self._broken = True


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"
        amount /= 1024
    raise AssertionError("unreachable")


def _profile_document(profile: FirmwareProfile) -> dict[str, object]:
    return {
        "schema_version": profile.schema_version,
        "id": profile.profile_id,
        "fortios_version": profile.version,
        "build": profile.build,
        "firmware_adapter": profile.firmware_adapter,
        "manifest_strategy": profile.manifest_strategy,
        "stock_files": dict(profile.scan_file_sha256),
        "rootfs_envelope": {
            "adapter": profile.rootfs_envelope.adapter,
            "public_key_blob_va": f"0x{profile.rootfs_envelope.public_key_blob_va:x}",
            "public_key_blob_length": profile.rootfs_envelope.public_key_blob_length,
            "public_key_xor_va": f"0x{profile.rootfs_envelope.public_key_xor_va:x}",
            "public_key_xor_length": profile.rootfs_envelope.public_key_xor_length,
        },
        "cipher": {
            "algorithm": profile.cipher.algorithm,
            "carry_ksa_accumulator": profile.cipher.carry_ksa_accumulator,
            "index_left_shift": profile.cipher.index_left_shift,
            "index_right_shift": profile.cipher.index_right_shift,
        },
        "patch_counts": {
            "kernel": len(profile.kernel_patches),
            "userland": sum(len(value) for value in profile.userland_patches.values()),
        },
        "outputs": {
            "flatkc": profile.patched_flatkc_name,
            "rootfs": profile.patched_rootfs_name,
        },
    }
