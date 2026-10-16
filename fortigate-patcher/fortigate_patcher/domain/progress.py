"""Structured progress events shared by long-running application workflows."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One user-facing stage update, optionally with byte-level completion."""

    stage: str
    message: str
    completed: int | None = None
    total: int | None = None


ProgressCallback = Callable[[ProgressEvent], None]


def report_progress(
    callback: ProgressCallback | None,
    stage: str,
    message: str,
    *,
    completed: int | None = None,
    total: int | None = None,
) -> None:
    """Send one event when a progress callback is configured."""
    if callback is not None:
        callback(ProgressEvent(stage, message, completed, total))
