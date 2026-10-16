"""Version-neutral rootfs patching and structural verification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from fortigate_patcher.domain.environment import EnvironmentIdentity
from fortigate_patcher.domain.errors import FirmwareError, VerificationError
from fortigate_patcher.domain.policy import BuildPolicy
from fortigate_patcher.domain.profile import FirmwareProfile

from .compression import deterministic_gzip_compress
from .cpio import CpioEntry, new_entry, read_newc, write_newc
from .hashing import sha256_bytes
from .patching import apply_offset_patch, verify_offset_patch
from .paths import normalize_archive_path
from .resources import ResourceAsset, build_payload_assets
from .rootfs import decrypt_rootfs, encrypt_rootfs, split_gzip_stream
from .ssh import contains_private_key_block
from .tar import BUSYBOX_APPLETS, read_bin_tar_xz, rewrite_bin_tar_xz

ROOTFS_ACCOUNT_FILES: Mapping[str, tuple[bytes | None, int]] = {
    "root": (b"", 0o040755),
    "root/.ssh": (b"", 0o040700),
    "root/.ssh/authorized_keys": (None, 0o100600),
    "data/etc/passwd": (b"root:x:0:0:root:/root:/bin/rootshell\n", 0o100644),
    "data/etc/shadow": (b"root:!:0:0:99999:7:::\n", 0o100600),
    "data/etc/shells": (
        b"/bin/rootshell\n/bin/sh\n/bin/ash\n/bin/busybox\n",
        0o100644,
    ),
}

FORBIDDEN_PRIVATE_NAMES = {
    "bin/client_ed25519",
    "bin/client_ed25519.priv",
    "bin/dropbear_rsa_host_key",
    "bin/dropbear_ed25519_host_key",
    "bin/dropbear_ecdsa_host_key",
}


@dataclass(frozen=True, slots=True)
class RootfsBuildResult:
    """A protected patched rootfs plus stable core fingerprints."""

    container: bytes
    plaintext_gzip_sha256: str
    cpio_sha256: str
    patched_file_sha256: Mapping[str, str]


def _entry_map(entries: tuple[CpioEntry, ...]) -> dict[str, CpioEntry]:
    result: dict[str, CpioEntry] = {}
    for entry in entries:
        if entry.name == "TRAILER!!!":
            continue
        name = normalize_archive_path(entry.name)
        if name in result:
            raise FirmwareError(f"rootfs newc has duplicate member: {name}")
        result[name] = entry
    return result


def patch_rootfs_cpio(
    cpio: bytes,
    profile: FirmwareProfile,
    assets: Mapping[str, ResourceAsset],
) -> tuple[bytes, Mapping[str, str]]:
    """Apply guarded userland patches and inject the rendered guest payload."""
    entries = read_newc(cpio)
    originals = _entry_map(entries)
    required = set(profile.userland_patches) | {"bin.tar.xz"}
    missing = sorted(required - originals.keys())
    if missing:
        raise FirmwareError("rootfs newc is missing: " + ", ".join(missing))

    replacements: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for name, patches in profile.userland_patches.items():
        original = originals[name].data
        if sha256_bytes(original) != profile.expected_original_files[name]:
            raise FirmwareError(f"unexpected /{name} fingerprint; refusing patch")
        patched = original
        for patch in patches:
            patched = apply_offset_patch(patched, patch)
        if sha256_bytes(patched) != profile.expected_patched_files[name]:
            raise FirmwareError(f"patched /{name} fingerprint mismatch")
        replacements[name] = patched
        hashes[f"/{name}"] = sha256_bytes(patched)

    patched_bin, payload_hashes = rewrite_bin_tar_xz(originals["bin.tar.xz"].data, assets, profile)
    replacements["bin.tar.xz"] = patched_bin
    hashes.update(payload_hashes)

    authorized_keys = assets["authorized_keys"].data
    additions = {
        name: (authorized_keys if content is None else content, mode)
        for name, (content, mode) in ROOTFS_ACCOUNT_FILES.items()
    }
    output_entries: list[CpioEntry] = []
    emitted: set[str] = set()
    trailer: CpioEntry | None = None
    for entry in entries:
        if entry.name == "TRAILER!!!":
            trailer = entry
            break
        normalized = normalize_archive_path(entry.name)
        if normalized in additions:
            content, mode = additions[normalized]
            output_entries.append(entry.with_data(content, mode))
            emitted.add(normalized)
        elif normalized in replacements:
            output_entries.append(entry.with_data(replacements[normalized]))
        else:
            output_entries.append(entry)
    inode = 0x70000000
    for name, (content, mode) in additions.items():
        if name not in emitted:
            output_entries.append(new_entry(name, content, mode, inode))
            inode += 1
    if trailer is None:
        raise FirmwareError("rootfs newc has no trailer")
    output_entries.append(trailer)
    return write_newc(tuple(output_entries)), hashes


def build_patched_rootfs(
    *,
    protected_rootfs: bytes,
    stock_flatkc: bytes,
    profile: FirmwareProfile,
    policy: BuildPolicy,
    environment: EnvironmentIdentity,
) -> RootfsBuildResult:
    """Decrypt, patch, deterministically compress, and re-encrypt rootfs."""
    plaintext, envelope = decrypt_rootfs(
        protected_rootfs, stock_flatkc, profile, verify_digest=True
    )
    _, cpio = split_gzip_stream(plaintext)
    assets = build_payload_assets(policy, environment)
    patched_cpio, patched_hashes = patch_rootfs_cpio(cpio, profile, assets)
    patched_gzip = deterministic_gzip_compress(patched_cpio)
    round_trip_gzip, round_trip_cpio = split_gzip_stream(patched_gzip)
    if round_trip_gzip != patched_gzip or round_trip_cpio != patched_cpio:
        raise FirmwareError("patched rootfs gzip round trip failed")
    container = encrypt_rootfs(patched_gzip, envelope, profile)
    if len(container) != len(protected_rootfs):
        raise FirmwareError("patched protected-rootfs size differs from stock")
    return RootfsBuildResult(
        container=container,
        plaintext_gzip_sha256=sha256_bytes(patched_gzip),
        cpio_sha256=sha256_bytes(patched_cpio),
        patched_file_sha256=patched_hashes,
    )


def verify_patched_rootfs(
    *,
    protected_rootfs: bytes,
    stock_flatkc: bytes,
    profile: FirmwareProfile,
    policy: BuildPolicy,
    environment: EnvironmentIdentity,
) -> RootfsBuildResult:
    """Structurally verify patches, accounts, policy, and absence of private keys."""
    plaintext, _ = decrypt_rootfs(protected_rootfs, stock_flatkc, profile, verify_digest=False)
    gzip_stream, cpio = split_gzip_stream(plaintext)
    entries = _entry_map(read_newc(cpio))
    for name, patches in profile.userland_patches.items():
        try:
            data = entries[name].data
        except KeyError as exc:
            raise VerificationError(f"patched rootfs is missing /{name}") from exc
        for patch in patches:
            verify_offset_patch(data, patch)
        if sha256_bytes(data) != profile.expected_patched_files[name]:
            raise VerificationError(f"patched /{name} fingerprint mismatch")

    expected_assets = build_payload_assets(policy, environment)
    try:
        members, files = read_bin_tar_xz(entries["bin.tar.xz"].data)
    except KeyError as exc:
        raise VerificationError("patched rootfs is missing bin.tar.xz") from exc
    if sha256_bytes(files.get("bin/init", b"")) != profile.expected_patched_files["bin/init"]:
        raise VerificationError("/bin/init fingerprint mismatch")
    for basename, asset in expected_assets.items():
        name = f"bin/{basename}"
        member = members.get(name)
        if member is None or not member.isfile() or files.get(name) != asset.data:
            raise VerificationError(f"guest payload mismatch: /{name}")
        if member.mode & 0o7777 != asset.mode:
            raise VerificationError(f"guest payload mode mismatch: /{name}")
    for applet in BUSYBOX_APPLETS:
        member = members.get(f"bin/{applet}")
        if member is None or not member.issym() or member.linkname != "busybox":
            raise VerificationError(f"BusyBox applet link mismatch: /bin/{applet}")
    forbidden = FORBIDDEN_PRIVATE_NAMES & set(members)
    if forbidden:
        raise VerificationError(
            "private key files are present in rootfs: " + ", ".join(sorted(forbidden))
        )
    if any(contains_private_key_block(value) for value in files.values()):
        raise VerificationError("private-key material is present in rootfs")

    authorized_keys = expected_assets["authorized_keys"].data
    additions = {
        name: (authorized_keys if content is None else content, mode)
        for name, (content, mode) in ROOTFS_ACCOUNT_FILES.items()
    }
    for name, (content, mode) in additions.items():
        entry = entries.get(name)
        if entry is None or entry.data != content or entry.mode != mode:
            raise VerificationError(f"rootfs account overlay mismatch: /{name}")
    hashes = {f"/{name}": sha256_bytes(entries[name].data) for name in profile.userland_patches}
    hashes.update(
        {
            f"/bin/{name}": sha256_bytes(asset.data)
            for name, asset in expected_assets.items()
            if asset.mode & 0o111
        }
    )
    hashes["/bin/init"] = sha256_bytes(files["bin/init"])
    return RootfsBuildResult(
        container=protected_rootfs,
        plaintext_gzip_sha256=sha256_bytes(gzip_stream),
        cpio_sha256=sha256_bytes(cpio),
        patched_file_sha256=hashes,
    )


def extract_authorized_key(
    protected_rootfs: bytes,
    stock_flatkc: bytes,
    profile: FirmwareProfile,
) -> bytes:
    """Extract the public authorized key from a generated protected rootfs."""
    plaintext, _ = decrypt_rootfs(protected_rootfs, stock_flatkc, profile, verify_digest=False)
    _, cpio = split_gzip_stream(plaintext)
    entries = _entry_map(read_newc(cpio))
    try:
        return entries["root/.ssh/authorized_keys"].data
    except KeyError as exc:
        raise VerificationError("patched rootfs has no authorized_keys") from exc
