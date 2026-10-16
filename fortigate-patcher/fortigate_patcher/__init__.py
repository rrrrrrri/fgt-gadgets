"""Version-independent FortiGate VM firmware research tooling."""

from .domain.profile import PROFILE_SCHEMA_VERSION

__version__ = "0.2.1"

__all__ = ["PROFILE_SCHEMA_VERSION", "__version__"]
