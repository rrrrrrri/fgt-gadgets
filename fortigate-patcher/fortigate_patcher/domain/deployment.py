"""Versioned deployment-plan model and stale-device safeguards."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import PlanError
from .profile import is_sha256

DEPLOYMENT_PLAN_SCHEMA_VERSION = 1
DEPLOYMENT_PLAN_NAME = "deployment-plan.json"


@dataclass(frozen=True, slots=True)
class PlannedPartition:
    """Recorded pre-apply identity of one disk partition."""

    number: int
    path: str
    start_sector: int
    size_bytes: int
    filesystem: str | None
    label: str | None


@dataclass(frozen=True, slots=True)
class PlannedDevice:
    """Every disk identity field revalidated before applying a plan."""

    path: str
    major_minor: str
    size_bytes: int
    sector_size: int
    model: str
    serial: str
    wwn: str
    content_sha256: str
    partition_table_sha256: str
    partitions: tuple[PlannedPartition, ...]


@dataclass(frozen=True, slots=True)
class PlannedLayout:
    """Intended partition geometry captured at plan time."""

    partition2_start: int
    partition2_current_size: int
    partition2_new_size: int
    partition2_resize_mib: int | None
    partition4_start: int
    partition4_size: int
    reuse_partition4: bool


@dataclass(frozen=True, slots=True)
class DeploymentPlan:
    """Immutable authorization boundary between disk planning and writing."""

    schema_version: int
    plan_id: str
    created_at: str
    profile_id: str
    device: PlannedDevice
    layout: PlannedLayout
    stock_fingerprints: Mapping[str, str]
    artifact_manifest_sha256: str
    environment_id: str
    client_public_key_fingerprint: str
    build_directory: str
    environment_directory: str
    backup_directory: str
    backup_image: str
    operations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible plan object."""
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "created_at": self.created_at,
            "profile_id": self.profile_id,
            "device": {
                **asdict(self.device),
                "partitions": [asdict(value) for value in self.device.partitions],
            },
            "layout": asdict(self.layout),
            "stock_fingerprints": dict(self.stock_fingerprints),
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "environment": {
                "id": self.environment_id,
                "client_public_key_fingerprint": self.client_public_key_fingerprint,
                "directory": self.environment_directory,
            },
            "paths": {
                "build_directory": self.build_directory,
                "backup_directory": self.backup_directory,
                "backup_image": self.backup_image,
            },
            "operations": list(self.operations),
        }


def serialize_deployment_plan(plan: DeploymentPlan) -> bytes:
    """Serialize a deployment plan as stable UTF-8 JSON."""
    return (json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_deployment_plan(path: Path) -> DeploymentPlan:
    """Load a deployment plan and validate all required types and hashes."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot read deployment plan {path}: {exc}") from exc
    root = _mapping(document, "plan")
    required = {
        "schema_version",
        "plan_id",
        "created_at",
        "profile_id",
        "device",
        "layout",
        "stock_fingerprints",
        "artifact_manifest_sha256",
        "environment",
        "paths",
        "operations",
    }
    if set(root) != required or root.get("schema_version") != DEPLOYMENT_PLAN_SCHEMA_VERSION:
        raise PlanError("deployment plan has an unsupported schema or field set")
    device_data = _mapping(root["device"], "device")
    partition_values = device_data.get("partitions")
    if not isinstance(partition_values, list):
        raise PlanError("deployment plan device partitions must be an array")
    partitions = tuple(_parse_partition(value) for value in partition_values)
    device = PlannedDevice(
        path=_string(device_data, "path"),
        major_minor=_string(device_data, "major_minor"),
        size_bytes=_integer(device_data, "size_bytes"),
        sector_size=_integer(device_data, "sector_size"),
        model=_string(device_data, "model", allow_empty=True),
        serial=_string(device_data, "serial", allow_empty=True),
        wwn=_string(device_data, "wwn", allow_empty=True),
        content_sha256=_string(device_data, "content_sha256"),
        partition_table_sha256=_string(device_data, "partition_table_sha256"),
        partitions=partitions,
    )
    layout_data = _mapping(root["layout"], "layout")
    resize = layout_data.get("partition2_resize_mib")
    if resize is not None and (not isinstance(resize, int) or isinstance(resize, bool)):
        raise PlanError("partition2_resize_mib must be an integer or null")
    reuse = layout_data.get("reuse_partition4")
    if not isinstance(reuse, bool):
        raise PlanError("reuse_partition4 must be a boolean")
    layout = PlannedLayout(
        partition2_start=_integer(layout_data, "partition2_start"),
        partition2_current_size=_integer(layout_data, "partition2_current_size"),
        partition2_new_size=_integer(layout_data, "partition2_new_size"),
        partition2_resize_mib=resize,
        partition4_start=_integer(layout_data, "partition4_start"),
        partition4_size=_integer(layout_data, "partition4_size"),
        reuse_partition4=reuse,
    )
    fingerprints = _string_mapping(_mapping(root["stock_fingerprints"], "stock_fingerprints"))
    environment = _mapping(root["environment"], "environment")
    paths = _mapping(root["paths"], "paths")
    operations_value = root["operations"]
    if not isinstance(operations_value, list) or not all(
        isinstance(value, str) and value for value in operations_value
    ):
        raise PlanError("deployment plan operations must be non-empty strings")
    plan = DeploymentPlan(
        schema_version=DEPLOYMENT_PLAN_SCHEMA_VERSION,
        plan_id=_string(root, "plan_id"),
        created_at=_string(root, "created_at"),
        profile_id=_string(root, "profile_id"),
        device=device,
        layout=layout,
        stock_fingerprints=fingerprints,
        artifact_manifest_sha256=_string(root, "artifact_manifest_sha256"),
        environment_id=_string(environment, "id"),
        client_public_key_fingerprint=_string(environment, "client_public_key_fingerprint"),
        build_directory=_string(paths, "build_directory"),
        environment_directory=_string(environment, "directory"),
        backup_directory=_string(paths, "backup_directory"),
        backup_image=_string(paths, "backup_image"),
        operations=tuple(operations_value),
    )
    if (
        not is_sha256(plan.device.content_sha256)
        or not is_sha256(plan.device.partition_table_sha256)
        or not is_sha256(plan.artifact_manifest_sha256)
    ):
        raise PlanError("deployment plan contains an invalid SHA-256")
    if any(not is_sha256(value) for value in plan.stock_fingerprints.values()):
        raise PlanError("deployment plan contains an invalid stock fingerprint")
    return plan


def _parse_partition(value: Any) -> PlannedPartition:
    document = _mapping(value, "partition")
    filesystem = document.get("filesystem")
    label = document.get("label")
    if filesystem is not None and not isinstance(filesystem, str):
        raise PlanError("partition filesystem must be a string or null")
    if label is not None and not isinstance(label, str):
        raise PlanError("partition label must be a string or null")
    return PlannedPartition(
        number=_integer(document, "number"),
        path=_string(document, "path"),
        start_sector=_integer(document, "start_sector"),
        size_bytes=_integer(document, "size_bytes"),
        filesystem=filesystem,
        label=label,
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PlanError(f"deployment plan {label} must be an object")
    return value


def _string(document: Mapping[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = document.get(key)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise PlanError(f"deployment plan field {key!r} must be a string")
    return value


def _integer(document: Mapping[str, Any], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PlanError(f"deployment plan field {key!r} must be a non-negative integer")
    return value


def _string_mapping(document: Mapping[str, Any]) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for key, value in document.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise PlanError("deployment plan mapping must contain strings")
        result[key] = value
    return result
