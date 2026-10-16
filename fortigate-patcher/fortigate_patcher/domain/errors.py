"""Exceptions raised by FortiGate Patcher."""

from __future__ import annotations


class FortiGatePatcherError(Exception):
    """Base class for expected, user-facing failures."""


class ProfileError(FortiGatePatcherError):
    """A firmware profile is invalid or cannot be selected."""


class FirmwareError(FortiGatePatcherError):
    """Firmware input is unsupported, corrupt, or fails a safety invariant."""


class VerificationError(FortiGatePatcherError):
    """A generated artifact fails structural or fingerprint verification."""


class PlatformError(FortiGatePatcherError):
    """A host platform operation fails or violates a safety precondition."""


class PlanError(FortiGatePatcherError):
    """A deployment plan is invalid, stale, or targets the wrong device."""


class CredentialError(FortiGatePatcherError):
    """An environment credential cannot be generated or validated safely."""
