"""A required local authenticator owns each transient command authentication."""

from dataclasses import dataclass, field
from typing import Protocol

from packages.domain.runtime_owner_contracts import RuntimeOwnerAuthentication


@dataclass(frozen=True, slots=True, weakref_slot=True)
class AuthenticatedRuntimeOwnerCommand:
    authentication: RuntimeOwnerAuthentication
    seal: object = field(repr=False, compare=False)


class RuntimeOwnerAuthenticator(Protocol):
    def require_authenticated(self, value: AuthenticatedRuntimeOwnerCommand) -> None:
        """Require the original authenticator-issued token and bound content."""
        ...
