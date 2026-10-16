"""Per-environment client and Dropbear host credential lifecycle."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from fortigate_patcher.domain.environment import EnvironmentIdentity
from fortigate_patcher.domain.errors import CredentialError, PlatformError
from fortigate_patcher.firmware.resources import read_binary
from fortigate_patcher.firmware.ssh import public_key_fingerprint

from .process import Runner

ENVIRONMENT_SCHEMA_VERSION = 1
ENVIRONMENT_MANIFEST = "environment.json"
CLIENT_PRIVATE_KEY = "client_ed25519"
CLIENT_PUBLIC_KEY = "client_ed25519.pub"


@dataclass(frozen=True, slots=True)
class HostIdentity:
    """Generated Dropbear host-key paths and public fingerprints."""

    rsa_private_key: Path
    ed25519_private_key: Path
    rsa_fingerprint: str
    ed25519_fingerprint: str


def default_environment_root() -> Path:
    """Return the per-user FortiGate Patcher environment root."""
    return Path.home() / ".local" / "share" / "fortigate-patcher" / "environments"


def create_or_load_environment(
    directory: Path | None,
    runner: Runner,
) -> EnvironmentIdentity:
    """Load an existing environment or atomically create a unique Ed25519 client key."""
    if directory is None:
        root = default_environment_root()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        environment_id = str(uuid.uuid4())
        directory = root / environment_id
    else:
        directory = directory.expanduser().resolve(strict=False)
        environment_id = str(uuid.uuid4())
    manifest = directory / ENVIRONMENT_MANIFEST
    if manifest.is_file():
        return load_environment(directory)
    if directory.exists() and any(directory.iterdir()):
        raise CredentialError(
            f"environment directory is non-empty but has no {ENVIRONMENT_MANIFEST}: {directory}"
        )

    created = not directory.exists()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    private_key = directory / CLIENT_PRIVATE_KEY
    try:
        runner.run(
            [
                runner.require("ssh-keygen"),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"fortigate-patcher:{environment_id}",
                "-f",
                private_key,
            ]
        )
        private_key.chmod(0o600)
        public_path = directory / CLIENT_PUBLIC_KEY
        public_path.chmod(0o644)
        public_key = public_path.read_bytes()
        fingerprint = public_key_fingerprint(public_key)
        _write_environment_manifest(
            directory,
            environment_id=environment_id,
            client_fingerprint=fingerprint,
            host_fingerprints={},
        )
        return EnvironmentIdentity(
            environment_id=environment_id,
            directory=directory,
            client_public_key=public_key,
            client_fingerprint=fingerprint,
        )
    except BaseException:
        if created:
            shutil.rmtree(directory, ignore_errors=True)
        else:
            for name in (CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY, ENVIRONMENT_MANIFEST):
                (directory / name).unlink(missing_ok=True)
        raise


def load_environment(directory: Path) -> EnvironmentIdentity:
    """Load an environment and reject missing, altered, or over-permissive private keys."""
    directory = directory.expanduser().resolve(strict=True)
    try:
        document = json.loads((directory / ENVIRONMENT_MANIFEST).read_text(encoding="utf-8"))
        environment_id = document["environment_id"]
        recorded_fingerprint = document["client_public_key_fingerprint"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CredentialError(f"invalid environment manifest: {directory}") from exc
    try:
        parsed = uuid.UUID(environment_id)
    except (ValueError, TypeError) as exc:
        raise CredentialError("environment manifest contains an invalid UUID") from exc
    if str(parsed) != environment_id:
        raise CredentialError("environment UUID is not canonical")
    private_key = directory / CLIENT_PRIVATE_KEY
    public_key_path = directory / CLIENT_PUBLIC_KEY
    if not private_key.is_file() or not public_key_path.is_file():
        raise CredentialError("environment client key pair is incomplete")
    _require_private_mode(private_key)
    if directory.stat().st_mode & 0o077:
        raise CredentialError(f"environment directory permissions are too broad: {directory}")
    public_key = public_key_path.read_bytes()
    actual_fingerprint = public_key_fingerprint(public_key)
    if actual_fingerprint != recorded_fingerprint:
        raise CredentialError("environment client public-key fingerprint mismatch")
    identity = EnvironmentIdentity(
        environment_id=environment_id,
        directory=directory,
        client_public_key=public_key,
        client_fingerprint=actual_fingerprint,
    )
    identity.validate()
    return identity


def generate_dropbear_host_keys(environment: EnvironmentIdentity, runner: Runner) -> HostIdentity:
    """Generate unique RSA and Ed25519 Dropbear host keys using the pinned binary."""
    environment.validate()
    host_directory = environment.directory / "host"
    host_directory.mkdir(mode=0o700, exist_ok=True)
    host_directory.chmod(0o700)
    rsa_key = host_directory / "dropbear_rsa_host_key"
    ed25519_key = host_directory / "dropbear_ed25519_host_key"
    if rsa_key.exists() or ed25519_key.exists():
        if not rsa_key.is_file() or not ed25519_key.is_file():
            raise CredentialError("environment host identity is incomplete")
        _require_private_mode(rsa_key)
        _require_private_mode(ed25519_key)
    else:
        _run_dropbear_keygen(runner, host_directory, rsa_key, ed25519_key)
    tool = _materialize_dropbear(host_directory)
    try:
        rsa_public = _dropbear_public_key(tool, rsa_key, runner)
        ed25519_public = _dropbear_public_key(tool, ed25519_key, runner)
    finally:
        tool.unlink(missing_ok=True)
    (host_directory / "dropbear_rsa_host_key.pub").write_bytes(rsa_public)
    (host_directory / "dropbear_ed25519_host_key.pub").write_bytes(ed25519_public)
    rsa_fingerprint = public_key_fingerprint(rsa_public)
    ed25519_fingerprint = public_key_fingerprint(ed25519_public)
    _update_host_fingerprints(
        environment.directory,
        {"rsa": rsa_fingerprint, "ed25519": ed25519_fingerprint},
    )
    return HostIdentity(rsa_key, ed25519_key, rsa_fingerprint, ed25519_fingerprint)


def _run_dropbear_keygen(
    runner: Runner,
    host_directory: Path,
    rsa_key: Path,
    ed25519_key: Path,
) -> None:
    tool = _materialize_dropbear(host_directory)
    try:
        runner.run([tool, "dropbearkey", "-t", "rsa", "-s", "2048", "-f", rsa_key])
        runner.run([tool, "dropbearkey", "-t", "ed25519", "-f", ed25519_key])
        rsa_key.chmod(0o600)
        ed25519_key.chmod(0o600)
    except BaseException:
        rsa_key.unlink(missing_ok=True)
        ed25519_key.unlink(missing_ok=True)
        raise
    finally:
        tool.unlink(missing_ok=True)


def _materialize_dropbear(directory: Path) -> Path:
    data = read_binary("dropbearmulti")
    handle = tempfile.NamedTemporaryFile(
        mode="wb", prefix=".dropbearmulti-", dir=directory, delete=False
    )
    path = Path(handle.name)
    with handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o700)
    return path


def _dropbear_public_key(tool: Path, private_key: Path, runner: Runner) -> bytes:
    result = runner.run([tool, "dropbearkey", "-y", "-f", private_key])
    for line in result.stdout.splitlines():
        if line.startswith(("ssh-", "ecdsa-")):
            return line.encode("ascii") + b"\n"
    raise CredentialError(f"dropbearkey did not emit a public key for {private_key.name}")


def _require_private_mode(path: Path) -> None:
    if path.stat().st_mode & 0o077:
        raise CredentialError(f"private key permissions are too broad: {path}")


def _write_environment_manifest(
    directory: Path,
    *,
    environment_id: str,
    client_fingerprint: str,
    host_fingerprints: dict[str, str],
) -> None:
    path = directory / ENVIRONMENT_MANIFEST
    path.write_text(
        json.dumps(
            {
                "schema_version": ENVIRONMENT_SCHEMA_VERSION,
                "environment_id": environment_id,
                "client_public_key_fingerprint": client_fingerprint,
                "host_public_key_fingerprints": host_fingerprints,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _update_host_fingerprints(directory: Path, fingerprints: dict[str, str]) -> None:
    manifest = directory / ENVIRONMENT_MANIFEST
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PlatformError(f"cannot update environment manifest: {manifest}") from exc
    _write_environment_manifest(
        directory,
        environment_id=document["environment_id"],
        client_fingerprint=document["client_public_key_fingerprint"],
        host_fingerprints=fingerprints,
    )
