"""Shell-free subprocess execution with injectable test adapters."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fortigate_patcher.domain.errors import PlatformError
from fortigate_patcher.domain.progress import ProgressCallback, report_progress


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured output from one external command."""

    arguments: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    """Interface used by platform services and fake test runners."""

    def run(
        self,
        arguments: Sequence[str | Path],
        *,
        input_text: str | None = None,
        allowed_returncodes: tuple[int, ...] = (0,),
        timeout: float | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Execute one argument-array command."""
        ...

    def require(self, executable: str) -> str:
        """Return an executable path or raise a platform error."""
        ...


class SubprocessRunner:
    """Production subprocess adapter; it never invokes a command shell."""

    def __init__(self, progress: ProgressCallback | None = None) -> None:
        """Create a runner with optional command diagnostics."""
        self._progress = progress

    def run(
        self,
        arguments: Sequence[str | Path],
        *,
        input_text: str | None = None,
        allowed_returncodes: tuple[int, ...] = (0,),
        timeout: float | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Run a command and raise a concise error for disallowed status codes."""
        values = tuple(str(value) for value in arguments)
        if not values:
            raise PlatformError("cannot run an empty command")
        display = shlex.join(values)
        report_progress(self._progress, "command", f"running: {display}")
        process_environment = None
        if environment is not None:
            process_environment = os.environ.copy()
            process_environment.update(environment)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                values,
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
                env=process_environment,
            )
        except FileNotFoundError as exc:
            report_progress(self._progress, "command", f"missing executable: {values[0]}")
            raise PlatformError(f"required command is missing: {values[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            report_progress(
                self._progress,
                "command",
                f"timed out after {timeout}s: {values[0]}",
            )
            raise PlatformError(f"command timed out after {timeout}s: {values[0]}") from exc
        result = CommandResult(values, completed.returncode, completed.stdout, completed.stderr)
        elapsed = time.monotonic() - started
        report_progress(
            self._progress,
            "command",
            f"status {result.returncode} after {elapsed:.1f}s: {values[0]}",
        )
        if result.returncode not in allowed_returncodes:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise PlatformError(
                f"command failed with status {result.returncode}: {values[0]}: {detail}"
            )
        return result

    def require(self, executable: str) -> str:
        """Resolve an executable without relying on a shell."""
        resolved = shutil.which(executable)
        if resolved is None:
            raise PlatformError(f"required command is missing: {executable}")
        return resolved


def require_root() -> None:
    """Require direct root execution; commands never invoke sudo internally."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PlatformError("disk operations must be run as root; sudo is never invoked internally")
