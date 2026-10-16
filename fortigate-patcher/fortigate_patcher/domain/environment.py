"""Public build-time identity material."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import CredentialError


@dataclass(frozen=True, slots=True)
class EnvironmentIdentity:
    """Public identity fields consumed by deterministic image builds."""

    environment_id: str
    directory: Path
    client_public_key: bytes
    client_fingerprint: str

    def validate(self) -> None:
        """Validate the UUID, public key form, and public fingerprint."""
        try:
            parsed = uuid.UUID(self.environment_id)
        except ValueError as exc:
            raise CredentialError("environment ID is not a UUID") from exc
        if str(parsed) != self.environment_id:
            raise CredentialError("environment ID must use canonical lowercase UUID form")
        fields = self.client_public_key.strip().split()
        if len(fields) < 2 or fields[0] != b"ssh-ed25519":
            raise CredentialError("client public key must be OpenSSH Ed25519 format")
        if not self.client_fingerprint.startswith("SHA256:"):
            raise CredentialError("client public-key fingerprint is not SHA-256")
