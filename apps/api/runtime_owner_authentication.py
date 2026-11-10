"""Authenticate exact simulation commands through the existing local session."""

from datetime import datetime
from weakref import WeakValueDictionary, finalize

from apps.api.backtest_views import LocalOperatorSecurity
from packages.application.runtime_owner_authentication import AuthenticatedRuntimeOwnerCommand
from packages.domain.personal_contracts import require_utc
from packages.domain.runtime_owner_contracts import RuntimeOwnerAuthentication
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand


class LocalRuntimeOwnerAuthenticator:
    """No cookie, CSRF value or session signature enters retained evidence."""

    def __init__(self, security: LocalOperatorSecurity) -> None:
        if type(security) is not LocalOperatorSecurity:
            raise ValueError("the actual local operator security instance is required")
        self.security = security
        self._seal = object()
        self._owned: WeakValueDictionary[int, AuthenticatedRuntimeOwnerCommand] = (
            WeakValueDictionary()
        )
        self._original: dict[int, tuple[RuntimeOwnerAuthentication, str]] = {}

    def authenticate(
        self,
        command: RuntimeAssignmentCommand,
        *,
        session_cookie: str | None,
        csrf_token: str,
        now: datetime,
    ) -> AuthenticatedRuntimeOwnerCommand:
        require_utc(now, "authentication time")
        if type(command) is not RuntimeAssignmentCommand:
            raise ValueError("exact simulation assignment command required")
        command.__post_init__()
        owner_id, session_expires_at = self.security.authenticate_with_expiry(
            session_cookie, csrf_token, now=now
        )
        if command.owner_id != owner_id or command.requested_at != now:
            raise ValueError("command owner or original authentication time differs")
        authentication = RuntimeOwnerAuthentication(
            owner_id=owner_id,
            command_sha256=command.semantic_sha256,
            authenticated_at=now,
            session_expires_at=session_expires_at,
            command_expires_at=command.expires_at,
        )
        value = AuthenticatedRuntimeOwnerCommand(authentication, self._seal)
        self._owned[id(value)] = value
        self._original[id(value)] = (authentication, authentication.semantic_sha256)
        finalize(value, self._original.pop, id(value), None)
        return value

    def require_authenticated(self, value: AuthenticatedRuntimeOwnerCommand) -> None:
        if (
            type(value) is not AuthenticatedRuntimeOwnerCommand
            or value.seal is not self._seal
            or self._owned.get(id(value)) is not value
        ):
            raise ValueError("original local authentication required")
        authentication, digest = self._original[id(value)]
        if value.authentication is not authentication or authentication.semantic_sha256 != digest:
            raise ValueError("original local authentication content changed")
