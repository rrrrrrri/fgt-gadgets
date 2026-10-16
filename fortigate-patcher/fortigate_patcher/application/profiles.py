"""Load, validate, list, and select declarative firmware profiles."""

from __future__ import annotations

import tomllib
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from fortigate_patcher.domain.errors import ProfileError
from fortigate_patcher.domain.profile import (
    CipherSpec,
    FirmwareProfile,
    OutputSpec,
    PatchSpec,
    RootfsEnvelopeSpec,
    frozen_mapping,
    validate_profile,
)

PROFILE_PACKAGE = "fortigate_patcher.profiles"


def _table(document: Mapping[str, Any], key: str, source: str) -> Mapping[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ProfileError(f"{source}: {key} must be a TOML table")
    return value


def _string(document: Mapping[str, Any], key: str, source: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise ProfileError(f"{source}: {key} must be a string")
    return value


def _integer(document: Mapping[str, Any], key: str, source: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProfileError(f"{source}: {key} must be an integer")
    return value


def _boolean(document: Mapping[str, Any], key: str, source: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise ProfileError(f"{source}: {key} must be a boolean")
    return value


def _string_map(document: Mapping[str, Any], source: str) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for key, value in document.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ProfileError(f"{source}: keys and values must be strings")
        result[key] = value
    return frozen_mapping(result)


def _hex_bytes(document: Mapping[str, Any], key: str, source: str) -> bytes:
    value = _string(document, key, source)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ProfileError(f"{source}: {key} is not hexadecimal bytes") from exc


def _patch(document: Mapping[str, Any], source: str) -> PatchSpec:
    allowed = {"target", "label", "offset", "expected", "replacement"}
    extra = sorted(set(document) - allowed)
    if extra:
        raise ProfileError(f"{source}: unknown patch fields: {', '.join(extra)}")
    return PatchSpec(
        label=_string(document, "label", source),
        offset_or_va=_integer(document, "offset", source),
        expected=_hex_bytes(document, "expected", source),
        replacement=_hex_bytes(document, "replacement", source),
    )


def _patch_list(document: Mapping[str, Any], key: str, source: str) -> list[Mapping[str, Any]]:
    value = document.get(key)
    if not isinstance(value, list):
        raise ProfileError(f"{source}: {key} must be an array of tables")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ProfileError(f"{source}: {key}[{index}] must be a table")
        result.append(item)
    return result


def profile_from_mapping(document: Mapping[str, Any], source: str = "<memory>") -> FirmwareProfile:
    """Construct and validate one profile from parsed TOML data."""
    allowed = {
        "schema_version",
        "profile_id",
        "fortios_version",
        "build",
        "firmware_adapter",
        "manifest_strategy",
        "rootfs_envelope",
        "cipher",
        "outputs",
        "grub",
        "stock",
        "invariants",
        "userland_patches",
        "kernel_patches",
    }
    extra = sorted(set(document) - allowed)
    if extra:
        raise ProfileError(f"{source}: unknown top-level fields: {', '.join(extra)}")

    envelope_data = _table(document, "rootfs_envelope", source)
    cipher_data = _table(document, "cipher", source)
    output_data = _table(document, "outputs", source)
    grub_data = _table(document, "grub", source)
    stock_data = _table(document, "stock", source)
    invariant_data = _table(document, "invariants", source)

    grouped: defaultdict[str, list[PatchSpec]] = defaultdict(list)
    for index, item in enumerate(_patch_list(document, "userland_patches", source)):
        patch_source = f"{source}: userland_patches[{index}]"
        target = _string(item, "target", patch_source)
        grouped[target].append(_patch(item, patch_source))
    userland = frozen_mapping({target: tuple(patches) for target, patches in grouped.items()})
    kernel = tuple(
        _patch(item, f"{source}: kernel_patches[{index}]")
        for index, item in enumerate(_patch_list(document, "kernel_patches", source))
    )

    profile = FirmwareProfile(
        schema_version=_integer(document, "schema_version", source),
        profile_id=_string(document, "profile_id", source),
        version=_string(document, "fortios_version", source),
        build=_string(document, "build", source),
        firmware_adapter=_string(document, "firmware_adapter", source),
        manifest_strategy=_string(document, "manifest_strategy", source),
        rootfs_envelope=RootfsEnvelopeSpec(
            adapter=_string(envelope_data, "adapter", source),
            public_key_blob_va=_integer(envelope_data, "public_key_blob_va", source),
            public_key_blob_length=_integer(envelope_data, "public_key_blob_length", source),
            public_key_xor_va=_integer(envelope_data, "public_key_xor_va", source),
            public_key_xor_length=_integer(envelope_data, "public_key_xor_length", source),
            signature_length=_integer(envelope_data, "signature_length", source),
        ),
        cipher=CipherSpec(
            algorithm=_string(cipher_data, "algorithm", source),
            carry_ksa_accumulator=_boolean(cipher_data, "carry_ksa_accumulator", source),
            index_left_shift=_integer(cipher_data, "index_left_shift", source),
            index_right_shift=_integer(cipher_data, "index_right_shift", source),
        ),
        scan_file_sha256=_string_map(_table(stock_data, "files", source), source),
        userland_patches=userland,
        kernel_patches=kernel,
        expected_original_files=_string_map(_table(invariant_data, "original", source), source),
        expected_patched_files=_string_map(_table(invariant_data, "patched", source), source),
        expected_patched_kernel_sha256=_string(invariant_data, "patched_kernel_sha256", source),
        expected_patched_flatkc_sha256=_string(invariant_data, "patched_flatkc_sha256", source),
        outputs=OutputSpec(
            flatkc=_string(output_data, "flatkc", source),
            rootfs=_string(output_data, "rootfs", source),
        ),
        grub_kernel_args=_string(grub_data, "kernel_args", source),
    )
    validate_profile(profile, source)
    return profile


def load_profile_text(text: str, source: str = "<memory>") -> FirmwareProfile:
    """Parse and validate one TOML profile document."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"{source}: invalid TOML: {exc}") from exc
    return profile_from_mapping(document, source)


def load_profile_file(path: Path) -> FirmwareProfile:
    """Load one profile from an explicit filesystem path."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    return load_profile_text(text, str(path))


def discover_profiles() -> tuple[FirmwareProfile, ...]:
    """Discover all TOML profiles bundled in the installed package."""
    package_root = resources.files(PROFILE_PACKAGE)
    profiles = [
        load_profile_text(resource.read_text(encoding="utf-8"), str(resource))
        for resource in package_root.iterdir()
        if resource.name.endswith(".toml")
    ]
    if not profiles:
        raise ProfileError("no bundled firmware profiles were discovered")
    return tuple(sorted(profiles, key=lambda item: (item.version, item.build, item.profile_id)))


@dataclass(frozen=True, slots=True)
class ProfileRegistry:
    """An immutable, conflict-checked collection of firmware profiles."""

    profiles: tuple[FirmwareProfile, ...]

    @classmethod
    def create(cls, profiles: Iterable[FirmwareProfile]) -> ProfileRegistry:
        """Create a registry and reject exact and shorthand selector conflicts."""
        values = tuple(profiles)
        if not values:
            raise ProfileError("no bundled firmware profiles were discovered")
        identifiers: set[str] = set()
        for profile in values:
            validate_profile(profile)
            if profile.profile_id in identifiers:
                raise ProfileError(f"duplicate profile ID: {profile.profile_id}")
            identifiers.add(profile.profile_id)
        versions = {profile.version for profile in values}
        conflicts = sorted(identifiers & versions)
        if conflicts:
            raise ProfileError(
                "profile ID conflicts with a short-version selector: " + ", ".join(conflicts)
            )
        return cls(
            tuple(sorted(values, key=lambda item: (item.version, item.build, item.profile_id)))
        )

    def resolve(self, selector: str) -> FirmwareProfile:
        """Resolve an exact profile ID or an unambiguous FortiOS version."""
        exact = [profile for profile in self.profiles if profile.profile_id == selector]
        if exact:
            return exact[0]
        matches = [profile for profile in self.profiles if profile.version == selector]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            choices = ", ".join(profile.profile_id for profile in matches)
            raise ProfileError(f"version selector {selector!r} is ambiguous; use one of: {choices}")
        raise ProfileError(
            f"unsupported firmware profile {selector!r}; supported profiles:\n{self.format_table()}"
        )

    def format_table(self) -> str:
        """Return a stable human-readable profile table."""
        lines = ["VERSION  BUILD  PROFILE"]
        lines.extend(
            f"{profile.version:<8} {profile.build:<6} {profile.profile_id}"
            for profile in self.profiles
        )
        return "\n".join(lines)


@lru_cache(maxsize=1)
def get_profile_registry() -> ProfileRegistry:
    """Return the process-wide bundled profile registry."""
    return ProfileRegistry.create(discover_profiles())


def resolve_profile(selector: str) -> FirmwareProfile:
    """Resolve one bundled profile by exact ID or version."""
    return get_profile_registry().resolve(selector)
