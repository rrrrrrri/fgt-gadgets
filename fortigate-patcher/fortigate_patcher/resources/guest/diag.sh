#!/bin/busybox sh
# diagnostics: dump system state to stdout (run: busybox sh /bin/diag)
bb=/bin/busybox
echo "=== uname ==="; $bb uname -a 2>/dev/null
echo "=== id ==="; $bb id 2>/dev/null
echo "=== ps ==="; $bb ps 2>/dev/null
echo "=== mounts ==="; $bb cat /proc/mounts 2>/dev/null
echo "=== partitions ==="; $bb cat /proc/partitions 2>/dev/null
echo "=== listeners ==="; $bb cat /proc/net/tcp 2>/dev/null
echo "=== dmesg tail ==="; $bb dmesg 2>/dev/null | $bb tail -20
