#!/bin/busybox sh
# FortiGate Patcher early-init handoff. This script intentionally provides no TTY login.
bb=/bin/busybox

$bb mkdir -p /tmp/bb 2>/dev/null
for applet in $($bb --list 2>/dev/null); do
    $bb ln -sf "$bb" "/tmp/bb/$applet" 2>/dev/null
done

$bb sh /bin/persist.sh >/dev/null 2>&1 &
exec $bb env -i PATH=/bin:/sbin:/usr/bin:/usr/sbin HOME=/root USER=root /bin/init
