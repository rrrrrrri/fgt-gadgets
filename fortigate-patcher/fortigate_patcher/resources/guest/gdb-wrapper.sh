#!/bin/busybox sh
# Launcher for the self-contained debugger runtime stored on FGT_PATCH.
# The deployment step expands the verified archive on the Linux host because
# FortiOS intentionally forbids creating executable files on /tmp.

bb=/bin/busybox
media=/tmp/fortigdb-media
runtime=$media/gdb-runtime
expected=b706f527a529963aef42da46932d97b9189c41c2565b56804718783d70fd0b45
ready=$runtime/.runtime-sha256

case ${0##*/} in
    gdb) debugger=gdb.real ;;
    gdbserver) debugger=gdbserver.real ;;
    *) echo "fortigdb: launcher must be invoked as gdb or gdbserver" >&2; exit 64 ;;
esac

runtime_ready() {
    [ -x "$runtime/bin/gdb.real" ] &&
        [ -x "$runtime/bin/gdbserver.real" ] &&
        [ -x "$runtime/lib/ld-linux-x86-64.so.2" ] &&
        [ -f "$ready" ] &&
        [ "$($bb cat "$ready" 2>/dev/null)" = "$expected" ]
}

if ! runtime_ready; then
    $bb mkdir -p "$media" || exit 1
    for device in /dev/sd?4 /dev/vd?4 /dev/xvd?4 /dev/nvme*n?p4; do
        [ -b "$device" ] || continue
        $bb mount -t ext4 -o ro "$device" "$media" 2>/dev/null || continue
        runtime_ready && break
        $bb umount "$media" 2>/dev/null || true
    done
fi

runtime_ready || {
    echo "fortigdb: cannot find a verified FGT_PATCH/gdb-runtime" >&2
    exit 1
}

export LC_ALL=C
export PYTHONHOME=$runtime
export PYTHONNOUSERSITE=1
export DEBUGINFOD_URLS=
exec "$runtime/lib/ld-linux-x86-64.so.2" \
    --library-path "$runtime/lib" \
    "$runtime/bin/$debugger" "$@"
