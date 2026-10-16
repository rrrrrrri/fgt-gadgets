"""Read-only block-device inspection and partition-layout planning."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fortigate_patcher.domain.errors import PlatformError

from .process import Runner

MIB = 1024 * 1024
PATCH_PARTITION_BYTES = 256 * MIB
MIN_DATA_PARTITION_BYTES = 512 * MIB


@dataclass(frozen=True, slots=True)
class PartitionState:
    """Stable geometry and filesystem identity for one partition."""

    number: int
    path: Path
    start_sector: int
    size_bytes: int
    filesystem: str | None
    label: str | None
    mountpoints: tuple[str, ...]

    def size_sectors(self, sector_size: int) -> int:
        """Return partition size in the parent device's logical sectors."""
        if self.size_bytes % sector_size:
            raise PlatformError(f"partition size is not sector aligned: {self.path}")
        return self.size_bytes // sector_size


@dataclass(frozen=True, slots=True)
class BlockDeviceState:
    """Identity, geometry, and exact partition-table fingerprint for a disk."""

    path: Path
    major_minor: str
    size_bytes: int
    sector_size: int
    model: str
    serial: str
    wwn: str
    read_only: bool
    partition_table: str
    partition_table_sha256: str
    partitions: tuple[PartitionState, ...]

    def partition(self, number: int) -> PartitionState:
        """Return a numbered partition or raise a platform error."""
        matches = [partition for partition in self.partitions if partition.number == number]
        if len(matches) != 1:
            raise PlatformError(f"expected exactly one partition {number} on {self.path}")
        return matches[0]


@dataclass(frozen=True, slots=True)
class LayoutPlan:
    """Calculated partition-2 and partition-4 geometry."""

    partition2_start: int
    partition2_current_size: int
    partition2_new_size: int
    partition2_resize_mib: int | None
    partition4_start: int
    partition4_size: int
    reuse_partition4: bool


def parse_lsblk_document(
    document: Mapping[str, Any],
    *,
    device: Path,
    partition_table: str,
    major_minor: str,
    read_only: bool,
) -> BlockDeviceState:
    """Parse lsblk JSON into an immutable device snapshot."""
    devices = document.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
        raise PlatformError("lsblk did not return exactly one block device")
    root = devices[0]
    if root.get("type") != "disk":
        raise PlatformError(f"target is not a whole disk: {device}")
    size = _required_int(root, "size")
    sector_size = _required_int(root, "log-sec")
    children = root.get("children", [])
    if not isinstance(children, list):
        raise PlatformError("lsblk children field is invalid")
    partitions: list[PartitionState] = []
    for child in children:
        if not isinstance(child, dict) or child.get("type") != "part":
            continue
        part_number = _required_int(child, "partn")
        path_value = child.get("path")
        if not isinstance(path_value, str) or not path_value.startswith("/"):
            raise PlatformError("lsblk partition path is invalid")
        mountpoints_value = child.get("mountpoints")
        if isinstance(mountpoints_value, list):
            mountpoints = tuple(
                value for value in mountpoints_value if isinstance(value, str) and value
            )
        elif isinstance(mountpoints_value, str) and mountpoints_value:
            mountpoints = (mountpoints_value,)
        else:
            mountpoints = ()
        partitions.append(
            PartitionState(
                number=part_number,
                path=Path(path_value),
                start_sector=_required_int(child, "start"),
                size_bytes=_required_int(child, "size"),
                filesystem=_optional_string(child.get("fstype")),
                label=_optional_string(child.get("label")),
                mountpoints=mountpoints,
            )
        )
    return BlockDeviceState(
        path=device,
        major_minor=major_minor,
        size_bytes=size,
        sector_size=sector_size,
        model=_optional_string(root.get("model")) or "",
        serial=_optional_string(root.get("serial")) or "",
        wwn=_optional_string(root.get("wwn")) or "",
        read_only=read_only,
        partition_table=partition_table,
        partition_table_sha256=hashlib.sha256(partition_table.encode("utf-8")).hexdigest(),
        partitions=tuple(sorted(partitions, key=lambda value: value.number)),
    )


class LinuxBlockDeviceInspector:
    """Inspect Linux disks using lsblk, blockdev, and sfdisk argument arrays."""

    def __init__(self, runner: Runner) -> None:
        """Create an inspector backed by an injectable command runner."""
        self._runner = runner

    def inspect(self, requested_device: Path) -> BlockDeviceState:
        """Return a fresh immutable snapshot of a whole block device."""
        device = requested_device.resolve(strict=True)
        mode = device.stat().st_mode
        if not stat.S_ISBLK(mode):
            raise PlatformError(f"not a block device: {device}")
        lsblk = self._runner.require("lsblk")
        result = self._runner.run(
            [
                lsblk,
                "--json",
                "--tree",
                "--bytes",
                "--output",
                "NAME,PATH,TYPE,SIZE,LOG-SEC,MODEL,SERIAL,WWN,FSTYPE,LABEL,MOUNTPOINTS,PARTN,START",
                device,
            ]
        )
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise PlatformError("lsblk returned invalid JSON") from exc
        table = self._runner.run([self._runner.require("sfdisk"), "--dump", device]).stdout
        read_only_text = self._runner.run(
            [self._runner.require("blockdev"), "--getro", device]
        ).stdout.strip()
        if read_only_text not in {"0", "1"}:
            raise PlatformError("blockdev returned an invalid read-only flag")
        device_stat = device.stat()
        major_minor = f"{os.major(device_stat.st_rdev)}:{os.minor(device_stat.st_rdev)}"
        return parse_lsblk_document(
            document,
            device=device,
            partition_table=table,
            major_minor=major_minor,
            read_only=read_only_text == "1",
        )

    def assert_safe_host_paths(
        self,
        state: BlockDeviceState,
        paths: tuple[Path, ...],
    ) -> None:
        """Reject the running root disk or work/backup paths hosted on the target."""
        findmnt = self._runner.require("findmnt")
        root_source = self._runner.run([findmnt, "-nro", "SOURCE", "-T", "/"]).stdout.strip()
        if root_source and self._source_belongs_to_device(Path(root_source), state.path):
            raise PlatformError(f"refusing to operate on the running root disk: {state.path}")
        for path in paths:
            probe = path.resolve(strict=False)
            while not probe.exists() and probe != probe.parent:
                probe = probe.parent
            source = self._runner.run(
                [findmnt, "-nro", "SOURCE", "-T", probe], allowed_returncodes=(0, 1)
            ).stdout.strip()
            if source and self._source_belongs_to_device(Path(source), state.path):
                raise PlatformError(f"path must not reside on target disk {state.path}: {path}")

    def _source_belongs_to_device(self, source: Path, device: Path) -> bool:
        try:
            source = source.resolve(strict=True)
        except OSError:
            return False
        result = self._runner.run(
            [self._runner.require("lsblk"), "-srnpo", "PATH", source],
            allowed_returncodes=(0, 1),
        )
        return str(device) in result.stdout.splitlines()


def calculate_layout(state: BlockDeviceState) -> LayoutPlan:
    """Calculate a 256 MiB partition 4 before partition 3 without writing."""
    if state.read_only:
        raise PlatformError(f"target disk is read-only: {state.path}")
    if state.sector_size != 512:
        raise PlatformError(f"unsupported logical sector size {state.sector_size}; expected 512")
    if "label: dos" not in state.partition_table.splitlines():
        raise PlatformError("target disk must use an MBR/DOS partition table")
    partition1 = state.partition(1)
    partition2 = state.partition(2)
    partition3 = state.partition(3)
    if partition1.filesystem != "ext3" or partition1.label != "FORTIOS":
        raise PlatformError("partition 1 must be the ext3 FORTIOS BOOT filesystem")
    if partition2.filesystem != "ext3":
        raise PlatformError("partition 2 must be the FortiOS ext3 data filesystem")

    existing4 = [partition for partition in state.partitions if partition.number == 4]
    if existing4:
        partition4 = existing4[0]
        if (
            partition4.filesystem != "ext4"
            or partition4.label != "FGT_PATCH"
            or partition4.size_bytes < 240 * MIB
        ):
            raise PlatformError("existing partition 4 is not a usable FGT_PATCH ext4 filesystem")
        return LayoutPlan(
            partition2_start=partition2.start_sector,
            partition2_current_size=partition2.size_sectors(state.sector_size),
            partition2_new_size=partition2.size_sectors(state.sector_size),
            partition2_resize_mib=None,
            partition4_start=partition4.start_sector,
            partition4_size=partition4.size_sectors(state.sector_size),
            reuse_partition4=True,
        )

    partition4_size = PATCH_PARTITION_BYTES // state.sector_size
    partition4_start = partition3.start_sector - partition4_size
    partition2_start = partition2.start_sector
    current_size = partition2.size_sectors(state.sector_size)
    current_end = partition2_start + current_size
    if partition4_start <= partition2_start:
        raise PlatformError("not enough address space before partition 3 for FGT_PATCH")
    new_size = min(current_size, partition4_start - partition2_start)
    new_bytes = new_size * state.sector_size
    if new_bytes < MIN_DATA_PARTITION_BYTES:
        raise PlatformError("refusing to shrink partition 2 below 512 MiB")
    resize_mib = None
    if new_size < current_size:
        resize_mib = new_bytes // MIB - 16
        if resize_mib <= 0:
            raise PlatformError("could not calculate a safe ext3 resize target")
    if current_end <= partition4_start:
        resize_mib = None
    return LayoutPlan(
        partition2_start=partition2_start,
        partition2_current_size=current_size,
        partition2_new_size=new_size,
        partition2_resize_mib=resize_mib,
        partition4_start=partition4_start,
        partition4_size=partition4_size,
        reuse_partition4=False,
    )


def _required_int(document: Mapping[str, Any], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise PlatformError(f"lsblk field {key!r} is not an integer")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PlatformError("lsblk returned a non-string identity field")
    return value.strip() or None
