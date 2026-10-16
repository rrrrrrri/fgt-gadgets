#!/bin/sh
# Login shell for dropbear root.  FortiOS remounts /tmp after wini starts, so
# rebuild the BusyBox applet links at login time rather than relying on the
# early-boot copy that has already disappeared.
bb=/bin/busybox
$bb mkdir -p /tmp/bb 2>/dev/null
for applet in $($bb --list 2>/dev/null); do
    $bb ln -sf "$bb" "/tmp/bb/$applet" 2>/dev/null
done
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/tmp/bb
export HOME=/root
export TERM=xterm
exec "$bb" sh "$@"
