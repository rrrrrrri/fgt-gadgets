#!/bin/busybox sh
# Generated-policy guest bootstrap. Substitutions are made by the Python build engine.
bb=/bin/busybox
dropbear=/bin/dropbearmulti
media=/tmp/fortigate-patcher-media

fortios_data_ready() {
    # /etc is a symlink to /data/etc.  Writing before FortiOS mounts /data
    # only changes the initramfs directory that the mount later hides.
    [ -f /data/flatkc ] || [ -f /data/flatkc_p ] || [ -f /data/rootfs.gz ]
}

install_login_state() {
    # Keep the root password locked.  Password authentication is also disabled
    # independently with Dropbear -s; only the injected public key is accepted.
    $bb mkdir -p /etc /root/.ssh 2>/dev/null || return 1
    $bb printf 'root:x:0:0:root:/root:/bin/rootshell\n' > /etc/passwd 2>/dev/null || return 1
    $bb printf 'root:!:0:0:99999:7:::\n' > /etc/shadow 2>/dev/null || return 1
    $bb printf '/bin/rootshell\n/bin/sh\n/bin/ash\n/bin/busybox\n' > /etc/shells \
        2>/dev/null || return 1
    $bb cp /bin/authorized_keys /root/.ssh/authorized_keys 2>/dev/null || return 1
    $bb chmod 644 /etc/passwd /etc/shells 2>/dev/null || return 1
    $bb chmod 600 /etc/shadow /root/.ssh/authorized_keys 2>/dev/null || return 1
    $bb chmod 700 /root/.ssh 2>/dev/null || return 1
}

account_ready=0
account_attempts=0
while ! fortios_data_ready && [ "$account_attempts" -lt 240 ]; do
    $bb sleep 1
    account_attempts=$((account_attempts + 1))
done
if fortios_data_ready && install_login_state; then
    account_ready=1
    $bb printf 'FGT_PATCHER_ACCOUNT_READY data=/data\n' >/dev/ttyS0 2>/dev/null
else
    $bb printf 'FGT_PATCHER_ACCOUNT_FAILED status=data-or-write\n' \
        >/dev/ttyS0 2>/dev/null
fi

mount_patch_media() {
    $bb mkdir -p "$media" 2>/dev/null
    for device in /dev/sd?4 /dev/vd?4 /dev/xvd?4 /dev/nvme*n?p4; do
        [ -b "$device" ] || continue
        $bb mount -t ext4 -o ro "$device" "$media" 2>/dev/null || continue
        [ -f "$media/identity/dropbear_rsa_host_key" ] &&
            [ -f "$media/identity/dropbear_ed25519_host_key" ] && return 0
        $bb umount "$media" 2>/dev/null || true
    done
    return 1
}

@@NETWORK_SETUP@@

if [ "@@SSH_ENABLED@@" = 1 ] && [ "$account_ready" = 1 ]; then
    attempts=0
    while ! mount_patch_media && [ "$attempts" -lt 240 ]; do
        $bb sleep 1
        attempts=$((attempts + 1))
    done
    if [ -f "$media/identity/dropbear_rsa_host_key" ] &&
       [ -f "$media/identity/dropbear_ed25519_host_key" ]; then
        dropbear_pid_file=/tmp/fortigate-patcher-dropbear.pid
        "$bb" rm -f "$dropbear_pid_file"
        "$dropbear" dropbear -s -g -E -p 0.0.0.0:@@SSH_PORT@@ -P "$dropbear_pid_file" \
            -r "$media/identity/dropbear_rsa_host_key" \
            -r "$media/identity/dropbear_ed25519_host_key" \
            >/dev/null 2>/dev/ttyS0
        dropbear_status=$?
        dropbear_pid=$("$bb" cat "$dropbear_pid_file" 2>/dev/null)
        dropbear_port_hex=$("$bb" printf '%04X' @@SSH_PORT@@)
        if [ "$dropbear_status" -eq 0 ] && [ -n "$dropbear_pid" ] &&
           "$bb" kill -0 "$dropbear_pid" 2>/dev/null &&
           "$bb" grep -Eiq ":${dropbear_port_hex}[[:space:]]" /proc/net/tcp; then
            "$bb" printf 'FGT_PATCHER_SSH_READY port=@@SSH_PORT@@\n' \
                >/dev/ttyS0 2>/dev/null
        else
            "$bb" printf 'FGT_PATCHER_SSH_FAILED status=%s\n' "$dropbear_status" \
                >/dev/ttyS0 2>/dev/null
        fi
    else
        "$bb" printf 'FGT_PATCHER_SSH_FAILED status=missing-host-identity\n' \
            >/dev/ttyS0 2>/dev/null
    fi
elif [ "@@SSH_ENABLED@@" = 1 ]; then
    "$bb" printf 'FGT_PATCHER_SSH_FAILED status=account-overlay\n' \
        >/dev/ttyS0 2>/dev/null
fi

@@UNSAFE_SERVICES@@

$bb printf 'FGT_PATCHER_READY environment=@@ENVIRONMENT_ID@@\n' >/dev/ttyS0 2>/dev/null
