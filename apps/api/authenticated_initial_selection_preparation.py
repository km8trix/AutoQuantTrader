"""Authenticate one original preparation dispatch without owning its lifecycle.

The host retains its original work and delivery deadlines. Later authentication
or cancellation can deny this helper's delivery without undoing an admitted
preparation or a retained dependency object. No bootstrap authority is added.
"""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Event
from typing import TypeGuard

from apps.api import backtest_views
from apps.api.backtest_views import LocalOperatorSecurity
from apps.trader import initial_selection_descriptor as descriptors
from apps.trader import initial_selection_preparation_owner as host
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionPreparationOwner,
    InitialSelectionPreparationResult,
)
from packages.domain import research_job_contracts
from packages.domain.research_job_contracts import require_identifier

_INVALID = "INITIAL_SELECTION_PREPARATION_ACCESS_INVALID"
_CHANGED = "INITIAL_SELECTION_PREPARATION_ACCESS_BINDING_CHANGED"
_SECURITY = LocalOperatorSecurity
_AUTHENTICATE = LocalOperatorSecurity.authenticate_with_expiry
_DECODE = LocalOperatorSecurity._decode
_OWNER = InitialSelectionPreparationOwner
_ENTRY = host._entry
_PREPARE = InitialSelectionPreparationOwner.prepare_initial_selection
_RESULT = InitialSelectionPreparationResult
_RESULT_INIT = InitialSelectionPreparationResult.__init__
_RESULT_VALIDATE = InitialSelectionPreparationResult.__post_init__
_D_CLASS = InitialSelectionDescriptor
_D_INIT = InitialSelectionDescriptor.__init__
_D_POST_INIT = InitialSelectionDescriptor.__post_init__
_D_VALUES = descriptors._descriptor_values
_D_VALIDATE = descriptors._validated_values
_D_COPY = descriptors._from_values
_IDENTIFIER_VALIDATOR = require_identifier
_EVENT = Event
_EVENT_IS_SET = Event.is_set
_REASONS = host._REASONS
_DATETIME = datetime

type _Graph = tuple[
    LocalOperatorSecurity,
    InitialSelectionPreparationOwner,
    tuple[object, ...],
    tuple[object, ...],
    str,
    str,
    Event | None,
]

_METHOD_PINS = (
    (_SECURITY, "authenticate_with_expiry", _AUTHENTICATE),
    (_SECURITY, "_decode", _DECODE),
    (_OWNER, "prepare_initial_selection", _PREPARE),
    (_RESULT, "__init__", _RESULT_INIT),
    (_RESULT, "__post_init__", _RESULT_VALIDATE),
    (_D_CLASS, "__init__", _D_INIT),
    (_D_CLASS, "__post_init__", _D_POST_INIT),
    (_EVENT, "is_set", _EVENT_IS_SET),
)
_REFERENCES = (
    (backtest_views, "LocalOperatorSecurity", _SECURITY),
    (host, "InitialSelectionPreparationOwner", _OWNER),
    (host, "_OWNER", _OWNER),
    (host, "_entry", _ENTRY),
    (host, "_HOST_ENTRY", _ENTRY),
    (host, "_OWN_METHODS", host._OWN_METHODS),
    (host, "_INSTALL_METHODS", host._INSTALL_METHODS),
    (host, "_INSTALL_HELPERS", host._INSTALL_HELPERS),
    (host, "InitialSelectionPreparationResult", _RESULT),
    (host, "_identifier", host._identifier),
    (host, "require_identifier", require_identifier),
    (host, "_data_bindings", host._data_bindings),
    (host, "_REASONS", _REASONS),
    (host, "_D_CLASS", _D_CLASS),
    (host, "_D_INIT", _D_POST_INIT),
    (host, "_D_VALUES", _D_VALUES),
    (host, "_D_VALIDATE", _D_VALIDATE),
    (host, "_D_COPY", _D_COPY),
    (descriptors, "InitialSelectionDescriptor", _D_CLASS),
    (descriptors, "_descriptor_values", _D_VALUES),
    (descriptors, "_validated_values", _D_VALIDATE),
    (descriptors, "_from_values", _D_COPY),
    (research_job_contracts, "require_identifier", _IDENTIFIER_VALIDATOR),
)


def _bindings() -> None:
    for owner, name, expected in _METHOD_PINS:
        if vars(owner).get(name) is not expected:
            raise ValueError(_CHANGED)
    for module, name, reference_expected in _REFERENCES:
        if vars(module).get(name) is not reference_expected:
            raise ValueError(_CHANGED)
    for name, expected in (*_HELPERS, *_DISPATCH_PINS):
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _identifier(value: object) -> str:
    if type(value) is not str:
        raise ValueError(_INVALID)
    try:
        _IDENTIFIER_VALIDATOR(value, "preparation access identifier")
    except ValueError:
        raise ValueError(_INVALID) from None
    return value


def _operator(value: object) -> str:
    # The shared session permits Unicode and internal spaces. Host research-ID
    # grammar is deliberately not an operator identity policy.
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 128
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(_INVALID)
    return value


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError(_INVALID)
    return value


def _graph(
    security: LocalOperatorSecurity,
    owner: InitialSelectionPreparationOwner,
    account_id: str,
    cancel_event: Event | None,
) -> _Graph:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    if (
        type(security) is not _SECURITY
        or type(owner) is not _OWNER
        or (cancel_event is not None and type(cancel_event) is not _EVENT)
    ):
        raise ValueError(_INVALID)
    _ENTRY(owner)
    attributes = vars(owner)
    original = attributes.get("_original")
    if type(original) is not tuple or len(original) != 7:
        raise ValueError(_INVALID)
    actual_account = _IDENTIFIER(attributes.get("_account_id"))
    incarnation = _IDENTIFIER(attributes.get("_incarnation"))
    if actual_account != _IDENTIFIER(account_id):
        raise ValueError(_INVALID)
    # Independent references survive replacement of today's _original tuple.
    baseline = tuple(value for value in original)
    graph = (security, owner, original, baseline, actual_account, incarnation, cancel_event)
    _REQUIRE_GRAPH(graph)
    return graph


def _require_graph(graph: _Graph) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    security, owner, original, baseline, account_id, incarnation, cancel_event = graph
    if type(security) is not _SECURITY or type(owner) is not _OWNER:
        raise ValueError(_CHANGED)
    # Exact shared security is slotted: there is no instance method dictionary.
    # Do not inspect its key/configuration; original authentication owns those.
    attributes = vars(owner)
    if attributes.get("_original") is not original:
        raise ValueError(_CHANGED)
    current = tuple(
        attributes.get(name)
        for name in (
            "_configuration_file",
            "_account_id",
            "_lock_path",
            "_limits",
            "_condition",
            "_stop_event",
            "_incarnation",
        )
    )
    if (
        any(actual is not expected for actual, expected in zip(current, baseline, strict=True))
        or attributes.get("_account_id") is not account_id
        or attributes.get("_incarnation") is not incarnation
    ):
        raise ValueError(_CHANGED)
    if cancel_event is not None and (
        type(cancel_event) is not _EVENT or "is_set" in vars(cancel_event)
    ):
        raise ValueError(_CHANGED)
    _ENTRY(owner)


def _session(
    security: LocalOperatorSecurity,
    session_cookie: str | None,
    csrf_token: str,
    at: datetime,
) -> tuple[str, datetime]:
    value = _AUTHENTICATE(security, session_cookie, csrf_token, now=at)
    _BINDINGS()
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(_INVALID)
    operator, expiry = _OPERATOR(value[0]), _UTC(value[1])
    if expiry <= at:
        raise ValueError(_INVALID)
    return operator, expiry


def _reason(value: object) -> TypeGuard[host._Reason]:
    return type(value) is str and value in _REASONS


def _project_result(
    value: object, *, account_id: str, call_id: str, incarnation: str
) -> InitialSelectionPreparationResult:
    _BINDINGS()
    if type(value) is not _RESULT or not isinstance(value, InitialSelectionPreparationResult):
        raise ValueError(_INVALID)
    status, reason, returned_call, returned_incarnation, descriptor = (
        value.status,
        value.reason,
        value.call_id,
        value.incarnation,
        value.descriptor,
    )
    if any(type(item) is not str for item in (status, reason, returned_call, returned_incarnation)):
        raise ValueError(_INVALID)
    if (
        not _REASON(reason)
        or _IDENTIFIER(returned_call) != call_id
        or _IDENTIFIER(returned_incarnation) != incarnation
    ):
        raise ValueError(_INVALID)
    if status == "prepared" and reason == "prepared":
        values = _D_VALUES(descriptor)
        if values[0] != account_id:
            raise ValueError(_INVALID)
        _BINDINGS()
        copied = _D_COPY(values)
        _BINDINGS()
        # Original validation runs only on the new snapshot-built graph. Never
        # invoke the H validator on its returned mutable result/D a second time.
        result = _RESULT("prepared", "prepared", returned_call, returned_incarnation, copied)
    elif status == "unavailable" and reason != "prepared" and descriptor is None:
        result = _RESULT("unavailable", reason, returned_call, returned_incarnation, None)
    else:
        raise ValueError(_INVALID)
    _BINDINGS()
    return result


def _cancelled(value: Event | None) -> bool:
    if value is None:
        return False
    if type(value) is not _EVENT or "is_set" in vars(value):
        raise ValueError(_CHANGED)
    observed = _EVENT_IS_SET(value)
    if type(observed) is not bool:
        raise ValueError(_INVALID)
    return observed


def _prepare_authenticated_initial_selection(
    *,
    security: LocalOperatorSecurity,
    owner: InitialSelectionPreparationOwner,
    account_id: str,
    call_id: str,
    session_cookie: str | None,
    csrf_token: str,
    cancel_event: Event | None = None,
) -> InitialSelectionPreparationResult:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    bindings = _BINDINGS
    bindings()
    identifier, utc_value = _IDENTIFIER, _UTC
    graph_factory, require_graph = _GRAPH, _REQUIRE_GRAPH
    session, prepare = _SESSION, _PREPARE
    project_result, cancelled, result_type = _PROJECT_RESULT, _CANCELLED, _RESULT
    clock, utc_timezone = _DATETIME, UTC
    account_id, call_id = identifier(account_id), identifier(call_id)
    if (
        (
            session_cookie is not None
            and (type(session_cookie) is not str or len(session_cookie) > 2048)
        )
        or type(csrf_token) is not str
        or len(csrf_token) > 128
    ):
        raise ValueError(_INVALID)
    graph = graph_factory(security, owner, account_id, cancel_event)
    incarnation = graph[5]
    at = utc_value(clock.now(utc_timezone))
    admitted = session(security, session_cookie, csrf_token, at)
    require_graph(graph)
    # No exception interception: original authentication/dispatch exceptions
    # propagate by identity, and this helper owns no cleanup or second attempt.
    returned = prepare(owner, call_id, cancel_event=cancel_event)
    # This check precedes every returned-object getter/validator/copy callback.
    require_graph(graph)
    result = project_result(
        returned, account_id=account_id, call_id=call_id, incarnation=incarnation
    )
    require_graph(graph)
    delivery_at = utc_value(clock.now(utc_timezone))
    if delivery_at < at:
        raise ValueError(_INVALID)
    delivered = session(security, session_cookie, csrf_token, delivery_at)
    require_graph(graph)
    if delivered != admitted:
        raise ValueError(_INVALID)
    observed_cancel = cancelled(cancel_event)
    require_graph(graph)
    if result.status == "prepared" and observed_cancel:
        result = result_type("unavailable", "cancelled", call_id, incarnation, None)
    bindings()
    return result


_BINDINGS = _bindings
_IDENTIFIER = _identifier
_OPERATOR = _operator
_UTC = _utc
_GRAPH = _graph
_REQUIRE_GRAPH = _require_graph
_SESSION = _session
_REASON = _reason
_PROJECT_RESULT = _project_result
_CANCELLED = _cancelled
_HELPERS = tuple(
    (name, globals()[name])
    for name in (
        "_bindings",
        "_identifier",
        "_operator",
        "_utc",
        "_graph",
        "_require_graph",
        "_session",
        "_reason",
        "_project_result",
        "_cancelled",
        "_BINDINGS",
        "_IDENTIFIER",
        "_OPERATOR",
        "_UTC",
        "_GRAPH",
        "_REQUIRE_GRAPH",
        "_SESSION",
        "_REASON",
        "_PROJECT_RESULT",
        "_CANCELLED",
    )
)
_DISPATCH_PINS = tuple(
    (name, globals()[name])
    for name in (
        "_SECURITY",
        "_AUTHENTICATE",
        "_DECODE",
        "_OWNER",
        "_ENTRY",
        "_PREPARE",
        "_RESULT",
        "_RESULT_INIT",
        "_RESULT_VALIDATE",
        "_D_CLASS",
        "_D_INIT",
        "_D_POST_INIT",
        "_D_VALUES",
        "_D_VALIDATE",
        "_D_COPY",
        "_IDENTIFIER_VALIDATOR",
        "_EVENT",
        "_EVENT_IS_SET",
        "_REASONS",
        "_DATETIME",
        "datetime",
        "UTC",
        "Event",
        "LocalOperatorSecurity",
        "InitialSelectionPreparationOwner",
        "InitialSelectionPreparationResult",
        "InitialSelectionDescriptor",
    )
)
