"""Private actual shared authentication for one detached operator statement.

Supplied operation samples are not clock provenance or physical-return expiry
guarantees. No journal, durable control membership or re-arm authority is added.
"""

from __future__ import annotations

from datetime import UTC, datetime
from weakref import WeakValueDictionary, finalize

from apps.api import backtest_views
from apps.api.backtest_views import LocalOperatorSecurity
from packages.application import operational_control_operator_authentication as tokens
from packages.application.operational_control_operator_authentication import (
    AuthenticatedOperationalControlOperatorStatement,
)
from packages.domain import operational_control_operator_statement as statements
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
    _require_sha256,
    _require_text,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)

_INVALID = "OPERATOR_STATEMENT_AUTHENTICATION_INVALID"
_CHANGED = "OPERATOR_STATEMENT_AUTHENTICATION_BINDING_CHANGED"
_ORIGINAL = "ORIGINAL_OPERATOR_STATEMENT_AUTHENTICATION_REQUIRED"
_SECURITY = LocalOperatorSecurity
_AUTHENTICATE = LocalOperatorSecurity.authenticate_with_expiry
_DECODE = LocalOperatorSecurity._decode
_TOKEN = AuthenticatedOperationalControlOperatorStatement
_STATEMENT = OperationalControlOperatorStatement
_COPY = statements.copy_operational_control_operator_statement
_TEXT = _require_text
_DIGEST = _require_sha256

type _Baseline = tuple[OperationalControlOperatorStatement, str, str, datetime]


def _bindings() -> None:
    for module, name, expected in _REFERENCES:
        if vars(module).get(name) is not expected:
            raise ValueError(_CHANGED)
    for owner, name, expected in _METHODS:
        if vars(owner).get(name) is not expected:
            raise ValueError(_CHANGED)
    for name, expected in _HELPERS:
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _arguments(session_cookie: str | None, csrf_token: str, now: datetime) -> None:
    if (
        type(now) is not datetime
        or now.tzinfo is not UTC
        or (
            session_cookie is not None
            and (type(session_cookie) is not str or len(session_cookie) > 2048)
        )
        or type(csrf_token) is not str
        or len(csrf_token) > 128
    ):
        raise ValueError(_INVALID)


def _entry(owner: LocalOperationalControlOperatorStatementAuthenticator) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    if type(owner) is not _ISSUER or owner._self is not owner:
        raise ValueError(_ORIGINAL)
    original, security, scope, authority, seal, owned, records = (
        owner._configuration,
        owner.security,
        owner.scope_id,
        owner.actor_authority_sha256,
        owner._seal,
        owner._owned,
        owner._original,
    )
    if type(original) is not tuple or len(original) != 6:
        raise ValueError(_CHANGED)
    if (
        type(security) is not _SECURITY
        or type(scope) is not str
        or type(authority) is not str
        or type(security._enabled) is not bool
        or type(security._operator_id) is not str
        or type(security._key) is not bytes
        or security is not original[0]
        or scope is not original[1]
        or authority is not original[2]
        or seal is not original[3]
        or owned is not original[4]
        or records is not original[5]
    ):
        raise ValueError(_CHANGED)


def _session(
    owner: LocalOperationalControlOperatorStatementAuthenticator,
    session_cookie: str | None,
    csrf_token: str,
    now: datetime,
) -> tuple[str, datetime]:
    value = _AUTHENTICATE(owner.security, session_cookie, csrf_token, now=now)
    _ENTRY(owner)
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(_INVALID)
    operator, expiry = value
    if type(operator) is not str or type(expiry) is not datetime or expiry.tzinfo is not UTC:
        raise ValueError(_INVALID)
    _TEXT(operator, "authenticated operator statement actor")
    if not now < expiry:
        raise ValueError(_INVALID)
    return operator, expiry


def _owned_statement(
    owner: LocalOperationalControlOperatorStatementAuthenticator,
    value: AuthenticatedOperationalControlOperatorStatement,
    now: datetime,
) -> tuple[str, datetime]:
    _ENTRY(owner)
    if type(value) is not _TOKEN:
        raise ValueError(_ORIGINAL)
    statement, expiry, seal = value.statement, value.session_expires_at, value.seal
    if (
        type(statement) is not _STATEMENT
        or type(expiry) is not datetime
        or expiry.tzinfo is not UTC
        or seal is not owner._seal
        or owner._owned.get(id(value)) is not value
    ):
        raise ValueError(_ORIGINAL)
    baseline = owner._original.get(id(value))
    if baseline is None or statement is not baseline[0]:
        raise ValueError(_ORIGINAL)
    copied = _COPY(statement)
    canonical, digest = copied.canonical_json, copied.semantic_sha256
    _ENTRY(owner)
    if (
        canonical != baseline[1]
        or digest != baseline[2]
        or expiry != baseline[3]
        or not copied.authentication_checked_at <= now < expiry
    ):
        raise ValueError(_ORIGINAL)
    return copied.actor.actor_id, expiry


class LocalOperationalControlOperatorStatementAuthenticator:
    """Own original transient tokens under configured actual shared security."""

    __slots__ = (
        "_configuration",
        "_original",
        "_owned",
        "_seal",
        "_self",
        "actor_authority_sha256",
        "scope_id",
        "security",
    )

    def __init__(
        self,
        security: LocalOperatorSecurity,
        *,
        scope_id: str,
        actor_authority_sha256: str,
    ) -> None:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        if (
            type(self) is not _ISSUER
            or type(security) is not _SECURITY
            or type(scope_id) is not str
            or type(actor_authority_sha256) is not str
            or type(security._enabled) is not bool
            or type(security._operator_id) is not str
            or type(security._key) is not bytes
        ):
            raise ValueError(_INVALID)
        _TEXT(scope_id, "operator statement configured scope ID")
        _DIGEST(actor_authority_sha256, "operator statement configured authority")
        self.security = security
        self.scope_id = scope_id
        self.actor_authority_sha256 = actor_authority_sha256
        self._self = self
        self._seal = object()
        self._owned: WeakValueDictionary[int, AuthenticatedOperationalControlOperatorStatement] = (
            WeakValueDictionary()
        )
        self._original: dict[int, _Baseline] = {}
        self._configuration = (
            security,
            scope_id,
            actor_authority_sha256,
            self._seal,
            self._owned,
            self._original,
        )
        _ENTRY(self)

    def authenticate(
        self,
        statement: OperationalControlOperatorStatement,
        *,
        session_cookie: str | None,
        csrf_token: str,
        now: datetime,
    ) -> AuthenticatedOperationalControlOperatorStatement:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        _ENTRY(self)
        _ARGUMENTS(session_cookie, csrf_token, now)
        copied = _COPY(statement)
        if (
            copied.scope_id != self.scope_id
            or copied.actor.authority_sha256 != self.actor_authority_sha256
            or copied.actor.authenticated_at != now
            or copied.authentication_checked_at != now
            or copied.attested_at != now
        ):
            raise ValueError(_INVALID)
        operator = copied.actor.actor_id
        canonical, digest = copied.canonical_json, copied.semantic_sha256
        _ENTRY(self)
        authenticated_operator, expiry = _SESSION(self, session_cookie, csrf_token, now)
        if authenticated_operator != operator:
            raise ValueError(_INVALID)
        value = _TOKEN(copied, expiry, self._seal)
        self._owned[id(value)] = value
        self._original[id(value)] = (copied, canonical, digest, expiry)
        finalize(value, self._original.pop, id(value), None)
        _OWNED_STATEMENT(self, value, now)
        return value

    def require_authenticated(
        self,
        token: AuthenticatedOperationalControlOperatorStatement,
        *,
        session_cookie: str | None,
        csrf_token: str,
        now: datetime,
    ) -> None:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        _ENTRY(self)
        _ARGUMENTS(session_cookie, csrf_token, now)
        operator, expiry = _OWNED_STATEMENT(self, token, now)
        current_operator, current_expiry = _SESSION(self, session_cookie, csrf_token, now)
        if current_operator != operator or current_expiry != expiry:
            raise ValueError(_ORIGINAL)
        # A new native snapshot detects mutation during actual authentication.
        _OWNED_STATEMENT(self, token, now)


_ISSUER = LocalOperationalControlOperatorStatementAuthenticator
_BINDINGS = _bindings
_ENTRY = _entry
_ARGUMENTS = _arguments
_SESSION = _session
_OWNED_STATEMENT = _owned_statement
_METHODS = (
    (_SECURITY, "authenticate_with_expiry", _AUTHENTICATE),
    (_SECURITY, "_decode", _DECODE),
    (_TOKEN, "__init__", _TOKEN.__init__),
    (_STATEMENT, "__init__", _STATEMENT.__init__),
    (_STATEMENT, "__post_init__", _STATEMENT.__post_init__),
    (_STATEMENT, "statement_id", vars(_STATEMENT)["statement_id"]),
    (_STATEMENT, "canonical_json", vars(_STATEMENT)["canonical_json"]),
    (_STATEMENT, "semantic_sha256", vars(_STATEMENT)["semantic_sha256"]),
    (_ISSUER, "authenticate", _ISSUER.authenticate),
    (_ISSUER, "require_authenticated", _ISSUER.require_authenticated),
    *(
        (original, name, vars(original)[name])
        for original in (
            OperationalControlActor,
            OperationalControlBlockingEvent,
            OperationalControlIncidentDisposition,
        )
        for name in ("__init__", "__post_init__", "semantic_sha256")
    ),
    (
        OperationalControlBlockingEvent,
        "event_id",
        vars(OperationalControlBlockingEvent)["event_id"],
    ),
)
_REFERENCES = (
    (backtest_views, "LocalOperatorSecurity", _SECURITY),
    (tokens, "AuthenticatedOperationalControlOperatorStatement", _TOKEN),
    *(
        (statements, name, vars(statements)[name])
        for name in (
            "OperationalControlOperatorStatement",
            "copy_operational_control_operator_statement",
            "_validated_values",
            "_non_running_state",
            "_statement_id",
            "_semantic_material",
            "OperationalControlActor",
            "OperationalControlActorKind",
            "OperationalControlBlockingEvent",
            "OperationalControlIncidentDisposition",
            "OperationalControlState",
            "_require_text",
            "_require_sha256",
            "_require_idempotency_key",
            "_require_utc",
            "canonical_id",
            "canonical_json_bytes",
            "canonical_json_text",
            "UTC",
            "datetime",
            "hashlib",
            "_FIELDS",
            "OPERATOR_STATEMENT_DATA_VERSION",
            "OPERATIONAL_CONTROL_POLICY_SHA256",
        )
    ),
)
_HELPERS = tuple(
    (name, globals()[name])
    for name in (
        "_bindings",
        "_BINDINGS",
        "_entry",
        "_ENTRY",
        "_arguments",
        "_ARGUMENTS",
        "_session",
        "_SESSION",
        "_owned_statement",
        "_OWNED_STATEMENT",
        "_SECURITY",
        "_AUTHENTICATE",
        "_DECODE",
        "_TOKEN",
        "_STATEMENT",
        "_ISSUER",
        "_COPY",
        "_TEXT",
        "_DIGEST",
    )
)
