"""Exception-safe Linux mount lifecycle management."""

from __future__ import annotations

import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from fortigate_patcher.domain.errors import PlatformError

from .process import Runner

JOURNALED_EXT_FILESYSTEMS = frozenset({"ext3", "ext4"})


class MountManager:
    """Mount block devices and guarantee best-effort unmount on every exit path."""

    def __init__(self, runner: Runner) -> None:
        """Create a mount manager backed by an injectable command runner."""
        self._runner = runner

    @contextmanager
    def mounted(
        self,
        device: Path,
        mountpoint: Path,
        *,
        read_only: bool = False,
        filesystem: str | None = None,
    ) -> Iterator[Path]:
        """Mount *device* for the duration of a context manager."""
        mountpoint.mkdir(parents=True, exist_ok=False)
        arguments: list[str | Path] = [self._runner.require("mount")]
        if filesystem is not None:
            arguments.extend(("-t", filesystem))
        if read_only:
            options = ["ro"]
            if filesystem in JOURNALED_EXT_FILESYSTEMS:
                options.append("noload")
            arguments.extend(("-o", ",".join(options)))
        arguments.extend((device, mountpoint))
        mounted = False
        try:
            self._runner.run(arguments)
            mounted = True
            yield mountpoint
        finally:
            active_exception = sys.exc_info()[0] is not None
            cleanup_error: Exception | None = None
            if mounted:
                try:
                    self._runner.run([self._runner.require("umount"), mountpoint])
                except Exception as exc:  # preserve the body exception when present
                    cleanup_error = exc
            try:
                mountpoint.rmdir()
            except OSError:
                pass
            if cleanup_error is not None and not active_exception:
                raise PlatformError(
                    f"failed to unmount {mountpoint}: {cleanup_error}"
                ) from cleanup_error

    def unmount_partitions(self, partitions: Sequence[Path]) -> None:
        """Unmount every mount target for the supplied partitions."""
        findmnt = self._runner.require("findmnt")
        umount = self._runner.require("umount")
        for partition in partitions:
            result = self._runner.run(
                [findmnt, "-rn", "-S", partition, "-o", "TARGET"],
                allowed_returncodes=(0, 1),
            )
            targets = [Path(line) for line in result.stdout.splitlines() if line.strip()]
            for target in reversed(targets):
                self._runner.run([umount, target])
