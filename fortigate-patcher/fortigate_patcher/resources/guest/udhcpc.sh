#!/bin/busybox sh
# Minimal udhcpc hook for isolated QEMU acceptance networking.
bb=/bin/busybox

case "$1" in
    deconfig)
        "$bb" ifconfig "$interface" 0.0.0.0 up
        ;;
    bound|renew)
        [ -n "$subnet" ] || subnet=255.255.255.0
        "$bb" ifconfig "$interface" "$ip" netmask "$subnet" up || exit 1
        "$bb" printf '%s\n' "$ip" > "/tmp/fortigate-patcher-dhcp.${interface}.lease" || exit 1
        for gateway in $router; do
            "$bb" ip route replace default via "$gateway" dev "$interface" 2>/dev/null || true
            break
        done
        ;;
esac

exit 0
