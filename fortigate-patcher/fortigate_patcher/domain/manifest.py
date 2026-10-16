"""Typed build-manifest model and strict JSON serialization."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .errors import VerificationError
from .profile import is_safe_relative_path, is_sha256

BUILD_MANIFEST_SCHEMA_VERSION = 1
BUILD_MANIFEST_NAME = "BUILD_MANIFEST.json"


@dataclass(frozen=True, slots=True)
class ArtifactFingerprint:
    """Recorded size and SHA-256 for one build artifact."""

    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class BuildManifest:
    """Reproducible metadata for one decoupled firmware build."""

    schema_version: int
    tool_version: str
    profile_id: str
    firmware_version: str
    firmware_build: str
    environment_id: str
    client_public_key_fingerprint: str
    policy: Mapping[str, object]
    outputs: Mapping[str, str]
    core_fingerprints: Mapping[str, str]
    artifacts: Mapping[str, ArtifactFingerprint]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable object with no secret material."""
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "profile": {
                "id": self.profile_id,
                "fortios_version": self.firmware_version,
                "build": self.firmware_build,
            },
            "environment": {
                "id": self.environment_id,
                "client_public_key_fingerprint": self.client_public_key_fingerprint,
            },
            "policy": dict(self.policy),
            "outputs": dict(self.outputs),
            "core_fingerprints": dict(self.core_fingerprints),
            "artifacts": {
                name: {"size": value.size, "sha256": value.sha256}
                for name, value in self.artifacts.items()
            },
        }


def serialize_build_manifest(manifest: BuildManifest) -> bytes:
    """Serialize a build manifest deterministically as UTF-8 JSON."""
    return (json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_build_manifest(path: Path) -> BuildManifest:
    """Read and strictly validate a build manifest from disk."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read {BUILD_MANIFEST_NAME}: {exc}") from exc
    if not isinstance(document, dict):
        raise VerificationError("build manifest root must be an object")
    required = {
        "schema_version",
        "tool_version",
        "profile",
        "environment",
        "policy",
        "outputs",
        "core_fingerprints",
        "artifacts",
    }
    if set(document) != required:
        raise VerificationError("build manifest has an unexpected field set")
    if document["schema_version"] != BUILD_MANIFEST_SCHEMA_VERSION:
        raise VerificationError("unsupported build-manifest schema")
    profile = _mapping(document["profile"], "profile")
    environment = _mapping(document["environment"], "environment")
    policy = _mapping(document["policy"], "policy")
    outputs = _string_mapping(_mapping(document["outputs"], "outputs"), "outputs")
    core = _string_mapping(
        _mapping(document["core_fingerprints"], "core_fingerprints"),
        "core_fingerprints",
    )
    artifact_data = _mapping(document["artifacts"], "artifacts")
    artifacts: dict[str, ArtifactFingerprint] = {}
    for name, value in artifact_data.items():
        if not isinstance(name, str) or not is_safe_relative_path(name):
            raise VerificationError(f"unsafe artifact path in build manifest: {name!r}")
        fields = _mapping(value, f"artifacts[{name!r}]")
        if set(fields) != {"size", "sha256"}:
            raise VerificationError(f"invalid artifact record: {name}")
        size = fields["size"]
        digest = fields["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise VerificationError(f"invalid artifact size: {name}")
        if not isinstance(digest, str) or not is_sha256(digest):
            raise VerificationError(f"invalid artifact digest: {name}")
        artifacts[name] = ArtifactFingerprint(size, digest)
    manifest = BuildManifest(
        schema_version=BUILD_MANIFEST_SCHEMA_VERSION,
        tool_version=_required_string(document, "tool_version"),
        profile_id=_required_string(profile, "id"),
        firmware_version=_required_string(profile, "fortios_version"),
        firmware_build=_required_string(profile, "build"),
        environment_id=_required_string(environment, "id"),
        client_public_key_fingerprint=_required_string(
            environment, "client_public_key_fingerprint"
        ),
        policy=MappingProxyType(dict(policy)),
        outputs=MappingProxyType(outputs),
        core_fingerprints=MappingProxyType(core),
        artifacts=MappingProxyType(artifacts),
    )
    if not manifest.client_public_key_fingerprint.startswith("SHA256:"):
        raise VerificationError("invalid client public-key fingerprint")
    if any(not is_sha256(value) for value in manifest.core_fingerprints.values()):
        raise VerificationError("invalid core fingerprint")
    return manifest


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"build manifest {label} must be an object")
    return value


def _required_string(document: Mapping[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(f"build manifest field {key!r} must be a string")
    return value


def _string_mapping(document: Mapping[str, Any], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in document.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise VerificationError(f"build manifest {label} must contain strings")
        result[key] = value
    return result
