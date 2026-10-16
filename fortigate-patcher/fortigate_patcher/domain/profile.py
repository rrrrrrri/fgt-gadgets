"""Typed, immutable firmware-profile domain objects."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeVar

from .errors import ProfileError

PROFILE_SCHEMA_VERSION = 1
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class CipherSpec:
    """Parameters for a registered firmware stream-cipher implementation."""

    algorithm: str
    carry_ksa_accumulator: bool
    index_left_shift: int
    index_right_shift: int


@dataclass(frozen=True, slots=True)
class RootfsEnvelopeSpec:
    """Addresses and lengths used to recover the rootfs verification key."""

    adapter: str
    public_key_blob_va: int
    public_key_blob_length: int
    public_key_xor_va: int
    public_key_xor_length: int
    signature_length: int


@dataclass(frozen=True, slots=True)
class PatchSpec:
    """One length-preserving, original-byte-guarded binary patch."""

    label: str
    offset_or_va: int
    expected: bytes
    replacement: bytes


@dataclass(frozen=True, slots=True)
class OutputSpec:
    """Names of the decoupled artifacts loaded by GRUB."""

    flatkc: str
    rootfs: str


@dataclass(frozen=True, slots=True)
class FirmwareProfile:
    """A validated firmware profile loaded from a bundled TOML resource."""

    schema_version: int
    profile_id: str
    version: str
    build: str
    firmware_adapter: str
    manifest_strategy: str
    rootfs_envelope: RootfsEnvelopeSpec
    cipher: CipherSpec
    scan_file_sha256: Mapping[str, str]
    userland_patches: Mapping[str, tuple[PatchSpec, ...]]
    kernel_patches: tuple[PatchSpec, ...]
    expected_original_files: Mapping[str, str]
    expected_patched_files: Mapping[str, str]
    expected_patched_kernel_sha256: str
    expected_patched_flatkc_sha256: str
    outputs: OutputSpec
    grub_kernel_args: str

    @property
    def selectors(self) -> tuple[str, str]:
        """Return the exact ID and convenient version selector."""
        return (self.profile_id, self.version)

    @property
    def required_inputs(self) -> tuple[str, ...]:
        """Return the complete whitelisted stock-file set."""
        return tuple(self.scan_file_sha256)

    @property
    def flatkc_sha256(self) -> str:
        """Return the expected stock kernel-container fingerprint."""
        return self.scan_file_sha256["flatkc"]

    @property
    def rootfs_sha256(self) -> str:
        """Return the expected stock protected-rootfs fingerprint."""
        return self.scan_file_sha256["rootfs.gz"]

    @property
    def patched_flatkc_name(self) -> str:
        """Return the decoupled patched-kernel output name."""
        return self.outputs.flatkc

    @property
    def patched_rootfs_name(self) -> str:
        """Return the decoupled patched-rootfs output name."""
        return self.outputs.rootfs

    @property
    def grub_title(self) -> str:
        """Return the GRUB menu title for this firmware build."""
        return f"FortiOS {self.version} (FortiGate Patcher research environment)"


T = TypeVar("T")


def frozen_mapping(values: Mapping[str, T]) -> Mapping[str, T]:
    """Return an immutable copy of a string-keyed mapping."""
    return MappingProxyType(dict(values))


def is_sha256(value: str) -> bool:
    """Return whether *value* is a canonical lowercase SHA-256 digest."""
    return SHA256_PATTERN.fullmatch(value) is not None


def is_safe_relative_path(value: str) -> bool:
    """Return whether *value* is a normalized, non-traversing POSIX path."""
    normalized = posixpath.normpath(value.replace("\\", "/"))
    return bool(value) and normalized == value and not normalized.startswith(("/", "../"))


def validate_profile(profile: FirmwareProfile, source: str = "<unknown>") -> None:
    """Validate all schema, path, hash, and patch invariants in a profile."""
    if profile.schema_version != PROFILE_SCHEMA_VERSION:
        raise ProfileError(
            f"{source}: unsupported profile schema {profile.schema_version}; "
            f"expected {PROFILE_SCHEMA_VERSION}"
        )
    for label, value in (
        ("profile_id", profile.profile_id),
        ("version", profile.version),
        ("build", profile.build),
        ("firmware_adapter", profile.firmware_adapter),
    ):
        if not value or value.strip() != value:
            raise ProfileError(f"{source}: invalid {label}")
    if profile.manifest_strategy not in {"db", "filechecksum"}:
        raise ProfileError(f"{source}: unsupported manifest strategy {profile.manifest_strategy!r}")
    envelope = profile.rootfs_envelope
    if not envelope.adapter:
        raise ProfileError(f"{source}: rootfs envelope adapter is empty")
    if (
        min(
            envelope.public_key_blob_length,
            envelope.public_key_xor_length,
            envelope.signature_length,
        )
        <= 0
    ):
        raise ProfileError(f"{source}: rootfs envelope lengths must be positive")
    cipher = profile.cipher
    if not cipher.algorithm or min(cipher.index_left_shift, cipher.index_right_shift) < 0:
        raise ProfileError(f"{source}: invalid cipher definition")
    if not profile.scan_file_sha256:
        raise ProfileError(f"{source}: empty stock-file whitelist")
    if not {"flatkc", "rootfs.gz"}.issubset(profile.scan_file_sha256):
        raise ProfileError(f"{source}: stock-file whitelist must include flatkc and rootfs.gz")

    paths = [*profile.scan_file_sha256, *profile.userland_patches]
    paths.extend((profile.outputs.flatkc, profile.outputs.rootfs))
    for path in paths:
        if not is_safe_relative_path(path):
            raise ProfileError(f"{source}: unsafe profile path {path!r}")
    if profile.outputs.flatkc in profile.scan_file_sha256:
        raise ProfileError(f"{source}: patched flatkc name collides with stock files")
    if profile.outputs.rootfs in profile.scan_file_sha256:
        raise ProfileError(f"{source}: patched rootfs name collides with stock files")

    digests: list[tuple[str, str]] = [
        *[(f"stock.files[{name!r}]", value) for name, value in profile.scan_file_sha256.items()],
        *[
            (f"invariants.original[{name!r}]", value)
            for name, value in profile.expected_original_files.items()
        ],
        *[
            (f"invariants.patched[{name!r}]", value)
            for name, value in profile.expected_patched_files.items()
        ],
        ("invariants.patched_kernel_sha256", profile.expected_patched_kernel_sha256),
        ("invariants.patched_flatkc_sha256", profile.expected_patched_flatkc_sha256),
    ]
    for label, digest in digests:
        if not is_sha256(digest):
            raise ProfileError(f"{source}: {label} is not a lowercase SHA-256")

    for target, patches in profile.userland_patches.items():
        _validate_patch_group(patches, f"{source}: userland target {target!r}")
        if target not in profile.expected_original_files:
            raise ProfileError(f"{source}: no original invariant for patched file {target!r}")
        if target not in profile.expected_patched_files:
            raise ProfileError(f"{source}: no patched invariant for patched file {target!r}")
    _validate_patch_group(profile.kernel_patches, f"{source}: kernel")


def _validate_patch_group(patches: tuple[PatchSpec, ...], source: str) -> None:
    if not patches:
        raise ProfileError(f"{source}: patch group is empty")
    ranges: list[tuple[int, int, str]] = []
    labels: set[str] = set()
    for patch in patches:
        if not patch.label or patch.label in labels:
            raise ProfileError(f"{source}: empty or duplicate patch label {patch.label!r}")
        labels.add(patch.label)
        if patch.offset_or_va < 0:
            raise ProfileError(f"{source}: patch {patch.label!r} has a negative offset")
        if not patch.expected or len(patch.expected) != len(patch.replacement):
            raise ProfileError(f"{source}: patch {patch.label!r} has invalid byte lengths")
        end = patch.offset_or_va + len(patch.expected)
        for other_start, other_end, other_label in ranges:
            if patch.offset_or_va < other_end and other_start < end:
                raise ProfileError(f"{source}: patches {other_label!r} and {patch.label!r} overlap")
        ranges.append((patch.offset_or_va, end, patch.label))
