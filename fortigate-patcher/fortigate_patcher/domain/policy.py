"""Typed build policy with safe defaults and explicit unsafe opt-in."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import ProfileError

POLICY_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class SshPolicy:
    """Key-only Dropbear service configuration."""

    enabled: bool = True
    port: int = 23


@dataclass(frozen=True, slots=True)
class DebugPolicy:
    """Debugger programs made available in the guest."""

    gdb: bool = True
    gdbserver: bool = True


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Optional acceptance-only DHCP behavior."""

    dhcp: bool = False
    interface: str = "port1"


@dataclass(frozen=True, slots=True)
class UnsafePolicy:
    """Legacy listeners that require one explicit master switch."""

    enabled: bool = False
    telnet_shell: bool = False
    telnet_port: int = 2323
    bind_shell: bool = False
    bind_port: int = 5555
    reverse_shell: bool = False
    reverse_host: str | None = None
    reverse_port: int | None = None


@dataclass(frozen=True, slots=True)
class BuildPolicy:
    """Complete payload policy; its defaults expose only key-authenticated SSH."""

    schema_version: int = POLICY_SCHEMA_VERSION
    ssh: SshPolicy = SshPolicy()
    debug: DebugPolicy = DebugPolicy()
    network: NetworkPolicy = NetworkPolicy()
    unsafe: UnsafePolicy = UnsafePolicy()

    def manifest_value(self) -> dict[str, object]:
        """Return a JSON-serializable policy value without credentials."""
        return asdict(self)


def _table(document: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = document.get(key, {})
    if not isinstance(value, dict):
        raise ProfileError(f"policy field {key!r} must be a TOML table")
    return value


def _boolean(table: Mapping[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ProfileError(f"policy field {key!r} must be a boolean")
    return value


def _integer(table: Mapping[str, Any], key: str, default: int) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProfileError(f"policy field {key!r} must be an integer")
    return value


def _string(table: Mapping[str, Any], key: str, default: str) -> str:
    value = table.get(key, default)
    if not isinstance(value, str):
        raise ProfileError(f"policy field {key!r} must be a string")
    return value


def _optional_string(table: Mapping[str, Any], key: str) -> str | None:
    value = table.get(key)
    if value is not None and not isinstance(value, str):
        raise ProfileError(f"policy field {key!r} must be a string")
    return value


def _optional_integer(table: Mapping[str, Any], key: str) -> int | None:
    value = table.get(key)
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise ProfileError(f"policy field {key!r} must be an integer")
    return value


def _check_keys(table: Mapping[str, Any], allowed: set[str], section: str) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise ProfileError(f"unknown {section} policy fields: {', '.join(extra)}")


def policy_from_mapping(document: Mapping[str, Any]) -> BuildPolicy:
    """Parse and validate a policy mapping."""
    allowed = {"schema_version", "ssh", "debug", "network", "unsafe"}
    extra = sorted(set(document) - allowed)
    if extra:
        raise ProfileError(f"unknown policy fields: {', '.join(extra)}")
    schema_version = document.get("schema_version", POLICY_SCHEMA_VERSION)
    if schema_version != POLICY_SCHEMA_VERSION:
        raise ProfileError(f"unsupported policy schema: {schema_version!r}")

    ssh_data = _table(document, "ssh")
    debug_data = _table(document, "debug")
    network_data = _table(document, "network")
    unsafe_data = _table(document, "unsafe")
    _check_keys(ssh_data, {"enabled", "port"}, "ssh")
    _check_keys(debug_data, {"gdb", "gdbserver"}, "debug")
    _check_keys(network_data, {"dhcp", "interface"}, "network")
    _check_keys(
        unsafe_data,
        {
            "enabled",
            "telnet_shell",
            "telnet_port",
            "bind_shell",
            "bind_port",
            "reverse_shell",
            "reverse_host",
            "reverse_port",
        },
        "unsafe",
    )
    policy = BuildPolicy(
        schema_version=POLICY_SCHEMA_VERSION,
        ssh=SshPolicy(
            enabled=_boolean(ssh_data, "enabled", True),
            port=_integer(ssh_data, "port", 23),
        ),
        debug=DebugPolicy(
            gdb=_boolean(debug_data, "gdb", True),
            gdbserver=_boolean(debug_data, "gdbserver", True),
        ),
        network=NetworkPolicy(
            dhcp=_boolean(network_data, "dhcp", False),
            interface=_string(network_data, "interface", "port1"),
        ),
        unsafe=UnsafePolicy(
            enabled=_boolean(unsafe_data, "enabled", False),
            telnet_shell=_boolean(unsafe_data, "telnet_shell", False),
            telnet_port=_integer(unsafe_data, "telnet_port", 2323),
            bind_shell=_boolean(unsafe_data, "bind_shell", False),
            bind_port=_integer(unsafe_data, "bind_port", 5555),
            reverse_shell=_boolean(unsafe_data, "reverse_shell", False),
            reverse_host=_optional_string(unsafe_data, "reverse_host"),
            reverse_port=_optional_integer(unsafe_data, "reverse_port"),
        ),
    )
    validate_policy(policy)
    return policy


def validate_policy(policy: BuildPolicy) -> None:
    """Enforce port, interface, and unsafe-feature invariants."""
    ports = [policy.ssh.port, policy.unsafe.telnet_port, policy.unsafe.bind_port]
    if policy.unsafe.reverse_port is not None:
        ports.append(policy.unsafe.reverse_port)
    if any(port < 1 or port > 65535 for port in ports):
        raise ProfileError("policy ports must be in the range 1..65535")
    if not policy.network.interface or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        for character in policy.network.interface
    ):
        raise ProfileError("network interface contains unsafe characters")
    requested_unsafe = (
        policy.unsafe.telnet_shell or policy.unsafe.bind_shell or policy.unsafe.reverse_shell
    )
    if requested_unsafe and not policy.unsafe.enabled:
        raise ProfileError("unsafe listeners require unsafe.enabled = true")
    if policy.unsafe.reverse_shell and (
        not policy.unsafe.reverse_host or policy.unsafe.reverse_port is None
    ):
        raise ProfileError("reverse shell requires reverse_host and reverse_port")
    if policy.unsafe.reverse_host and any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
        for character in policy.unsafe.reverse_host
    ):
        raise ProfileError("reverse-shell destination contains unsafe characters")


def load_policy(path: Path | None) -> BuildPolicy:
    """Load a TOML policy or return the safe default policy."""
    if path is None:
        return BuildPolicy()
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"cannot load policy {path}: {exc}") from exc
    return policy_from_mapping(document)
