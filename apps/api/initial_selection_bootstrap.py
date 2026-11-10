"""Privately stage the original shared bootstrap after one same-owner proof.

This joins existing authority; it creates no read-only credential or lifecycle.
The outer deadline admits delivery only and cannot interrupt the original proof
or issuer. The host remains the sole owner of its financial graph and cleanup.
"""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Condition, Event, Thread, current_thread
from time import monotonic_ns

from fastapi import HTTPException, Response

from apps.api import backtest_views, contracts
from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.contracts import BacktestLaunchCapability
from apps.trader import initial_selection_preparation_owner as host
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionPreparationOwner,
    InitialSelectionReadinessResult,
)
from packages.domain import research_job_contracts
from packages.domain.research_job_contracts import require_identifier

_INVALID = "INITIAL_SELECTION_BOOTSTRAP_INVALID"
_CHANGED = "INITIAL_SELECTION_BOOTSTRAP_BINDING_CHANGED"
_SECURITY = LocalOperatorSecurity
_BOOTSTRAP = LocalOperatorSecurity.bootstrap_capability
_AUTHENTICATE = LocalOperatorSecurity.authenticate_with_expiry
_DECODE = LocalOperatorSecurity._decode
_ISSUE = LocalOperatorSecurity._issue
_DISABLED = LocalOperatorSecurity._disabled
_OWNER = InitialSelectionPreparationOwner
_PROOF = InitialSelectionPreparationOwner.check_initial_selection_readiness
_ENTRY = host._entry
_STATE = host._state
_NOW = host._NOW
_READINESS = InitialSelectionReadinessResult
_READINESS_INIT = InitialSelectionReadinessResult.__init__
_READINESS_VALIDATE = InitialSelectionReadinessResult.__post_init__
_CAPABILITY = BacktestLaunchCapability
_CAPABILITY_INIT = BacktestLaunchCapability.__init__
_CAPABILITY_VALIDATOR = BacktestLaunchCapability.__pydantic_validator__
_RESPONSE = Response
_RESPONSE_INIT = Response.__init__
_RESPONSE_RENDER = Response.render
_RESPONSE_HEADERS = Response.init_headers
_RESPONSE_SET_COOKIE = Response.set_cookie
_RESPONSE_DELETE_COOKIE = Response.delete_cookie
_EVENT = Event
_EVENT_IS_SET = Event.is_set
_CONDITION = Condition
_CONDITION_ENTER = Condition.__enter__
_CONDITION_EXIT = Condition.__exit__
_THREAD = Thread
_THREAD_ALIVE = Thread.is_alive
_CURRENT_THREAD = current_thread
_IDENTIFIER_VALIDATOR = require_identifier
_DATETIME = datetime
_CLOCK_NOW = datetime.now
_MONOTONIC_NS = monotonic_ns
_MAX_NS = host._MAX_NS
_PROOF_REASONS = host._PROOF_REASONS
_SAFE_TOKEN = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_COOKIE_TOKEN = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.")
_BASE_HEADERS = (
    (b"cache-control", b"no-store"),
    (b"pragma", b"no-cache"),
    (b"content-length", b"0"),
)
_COOKIE_PREFIX = b"aqt_local_session="
_COOKIE_SUFFIX = b"; HttpOnly; Max-Age=28800; Path=/api/v1; SameSite=strict"
_DELETE_PREFIX = b'aqt_local_session=""; expires='
_DELETE_SUFFIX = b"; Max-Age=0; Path=/api/v1; SameSite=lax"
_MAX_COOKIE_HEADER = len(_COOKIE_PREFIX) + 2048 + len(_COOKIE_SUFFIX)
_DISABLED_REASONS = (
    "local operator authentication is disabled",
    "durable backtest persistence is unavailable",
)

type _CapabilityValues = tuple[bool, str | None, str | None, str, str, str | None]
type _Headers = tuple[tuple[bytes, bytes], ...]
type _Graph = tuple[
    LocalOperatorSecurity,
    InitialSelectionPreparationOwner,
    tuple[object, ...],
    tuple[object, ...],
    str,
    str,
    Condition,
    Thread | None,
    bool,
    str,
    Event | None,
]

_METHOD_PINS = (
    (_SECURITY, "bootstrap_capability", _BOOTSTRAP),
    (_SECURITY, "authenticate_with_expiry", _AUTHENTICATE),
    (_SECURITY, "_decode", _DECODE),
    (_SECURITY, "_issue", _ISSUE),
    (_SECURITY, "_disabled", _DISABLED),
    (_OWNER, "check_initial_selection_readiness", _PROOF),
    (_OWNER, "_now", _NOW),
    (_READINESS, "__init__", _READINESS_INIT),
    (_READINESS, "__post_init__", _READINESS_VALIDATE),
    (_RESPONSE, "__init__", _RESPONSE_INIT),
    (_RESPONSE, "render", _RESPONSE_RENDER),
    (_RESPONSE, "init_headers", _RESPONSE_HEADERS),
    (_RESPONSE, "set_cookie", _RESPONSE_SET_COOKIE),
    (_RESPONSE, "delete_cookie", _RESPONSE_DELETE_COOKIE),
    (_EVENT, "is_set", _EVENT_IS_SET),
    (_CONDITION, "__enter__", _CONDITION_ENTER),
    (_CONDITION, "__exit__", _CONDITION_EXIT),
    (_THREAD, "is_alive", _THREAD_ALIVE),
)
_REFERENCES = (
    (backtest_views, "LocalOperatorSecurity", _SECURITY),
    (backtest_views, "BacktestLaunchCapability", _CAPABILITY),
    (backtest_views, "Response", _RESPONSE),
    (backtest_views, "LOCAL_SESSION_COOKIE", backtest_views.LOCAL_SESSION_COOKIE),
    (backtest_views, "CSRF_HEADER", backtest_views.CSRF_HEADER),
    (backtest_views, "IDEMPOTENCY_HEADER", backtest_views.IDEMPOTENCY_HEADER),
    (backtest_views, "_SESSION_VERSION", backtest_views._SESSION_VERSION),
    (backtest_views, "_SESSION_LIFETIME", backtest_views._SESSION_LIFETIME),
    (backtest_views, "_SAFE_TOKEN_CHARACTERS", backtest_views._SAFE_TOKEN_CHARACTERS),
    (contracts, "BacktestLaunchCapability", _CAPABILITY),
    (host, "InitialSelectionPreparationOwner", _OWNER),
    (host, "_OWNER", _OWNER),
    (host, "_entry", _ENTRY),
    (host, "_HOST_ENTRY", _ENTRY),
    (host, "_state", _STATE),
    (host, "_HOST_STATE", _STATE),
    (host, "_NOW", _NOW),
    (host, "_MAX_NS", _MAX_NS),
    (host, "_event_is_set", host._event_is_set),
    (host, "_EVENT_IS_SET", _EVENT_IS_SET),
    (host, "_THREAD_ALIVE", _THREAD_ALIVE),
    (host, "_OWN_METHODS", host._OWN_METHODS),
    (host, "_INSTALL_METHODS", host._INSTALL_METHODS),
    (host, "_INSTALL_HELPERS", host._INSTALL_HELPERS),
    (host, "_PROOF_METHODS", host._PROOF_METHODS),
    (host, "_PROOF_HELPERS", host._PROOF_HELPERS),
    (host, "_PROOF_DISPATCH", host._PROOF_DISPATCH),
    (host, "InitialSelectionReadinessResult", _READINESS),
    (host, "_PROOF_RESULT_CLASS", _READINESS),
    (host, "_PROOF_RESULT_INIT", _READINESS_INIT),
    (host, "_PROOF_RESULT_VALIDATE", _READINESS_VALIDATE),
    (host, "_PROOF_REASONS", _PROOF_REASONS),
    (research_job_contracts, "require_identifier", _IDENTIFIER_VALIDATOR),
)


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="initial selection bootstrap is unavailable",
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _bindings() -> None:
    for cls, name, expected in _METHOD_PINS:
        if vars(cls).get(name) is not expected:
            raise ValueError(_CHANGED)
    if (
        _CAPABILITY.__init__ is not _CAPABILITY_INIT
        or _CAPABILITY.__pydantic_validator__ is not _CAPABILITY_VALIDATOR
    ):
        raise ValueError(_CHANGED)
    for module, name, expected_reference in _REFERENCES:
        if vars(module).get(name) is not expected_reference:
            raise ValueError(_CHANGED)
    for name, expected in (*_HELPERS, *_DISPATCH_PINS):
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _identifier(value: object) -> str:
    if type(value) is not str:
        raise ValueError(_INVALID)
    try:
        _IDENTIFIER_VALIDATOR(value, "bootstrap identifier")
    except ValueError:
        raise ValueError(_INVALID) from None
    return value


def _operator(value: object) -> str:
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
    if type(value) is not _DATETIME or not isinstance(value, datetime) or value.tzinfo is not UTC:
        raise _UNAVAILABLE()
    return value


def _sample_utc(previous: datetime | None = None) -> datetime:
    clock, admit, unavailable = _CLOCK_NOW, _UTC, _UNAVAILABLE
    try:
        value = clock(UTC)
    except BaseException:
        raise unavailable() from None
    value = admit(value)
    if previous is not None and value < previous:
        raise unavailable()
    return value


def _monotonic() -> int:
    clock, unavailable = _MONOTONIC_NS, _UNAVAILABLE
    try:
        value = clock()
    except BaseException:
        raise unavailable() from None
    if type(value) is not int or not 0 <= value <= _MAX_NS:
        raise unavailable()
    return value


def _graph(
    security: LocalOperatorSecurity,
    owner: InitialSelectionPreparationOwner,
    account_id: str,
    cancel_event: Event | None,
) -> _Graph:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    bindings = _BINDINGS
    bindings()
    entry, identifier, operator, require_graph = _ENTRY, _IDENTIFIER, _OPERATOR, _REQUIRE_GRAPH
    if (
        type(security) is not _SECURITY
        or type(owner) is not _OWNER
        or (cancel_event is not None and type(cancel_event) is not _EVENT)
    ):
        raise ValueError(_INVALID)
    attributes = vars(owner)
    original = attributes.get("_original")
    condition, worker = attributes.get("_condition"), attributes.get("_thread")
    if (
        type(original) is not tuple
        or len(original) != 7
        or type(condition) is not _CONDITION
        or not isinstance(condition, Condition)
        or (worker is not None and type(worker) is not _THREAD)
        or (worker is not None and not isinstance(worker, Thread))
    ):
        raise ValueError(_INVALID)
    actual_account, incarnation = attributes.get("_account_id"), attributes.get("_incarnation")
    if type(actual_account) is not str or type(incarnation) is not str:
        raise ValueError(_INVALID)
    baseline = tuple(item for item in original)
    limits = baseline[3]
    if (
        type(limits) is not tuple
        or len(limits) != 4
        or any(
            type(value) is not int or not 0 < value <= cap
            for value, cap in zip(
                limits, (10_000_000_000, 5_000_000_000, 1_000_000_000, 60_000_000_000), strict=True
            )
        )
    ):
        raise ValueError(_INVALID)
    try:
        enabled, operator_id = security._enabled, security._operator_id
    except AttributeError:
        raise ValueError(_INVALID) from None
    if type(enabled) is not bool:
        raise ValueError(_INVALID)
    # All independent object references precede validators or caller-result work.
    graph = (
        security,
        owner,
        original,
        baseline,
        actual_account,
        incarnation,
        condition,
        worker,
        enabled,
        operator(operator_id),
        cancel_event,
    )
    entry(owner)
    require_graph(graph)
    if identifier(actual_account) != identifier(account_id):
        raise ValueError(_INVALID)
    identifier(incarnation)
    require_graph(graph)
    return graph


def _require_graph(graph: _Graph) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    bindings, entry = _BINDINGS, _ENTRY
    bindings()
    (
        security,
        owner,
        original,
        baseline,
        account,
        incarnation,
        condition,
        worker,
        enabled,
        operator,
        cancel,
    ) = graph
    if type(security) is not _SECURITY or type(owner) is not _OWNER:
        raise ValueError(_CHANGED)
    attributes = vars(owner)
    if (
        attributes.get("_original") is not original
        or attributes.get("_condition") is not condition
        or attributes.get("_thread") is not worker
        or attributes.get("_account_id") is not account
        or attributes.get("_incarnation") is not incarnation
    ):
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
    if any(actual is not expected for actual, expected in zip(current, baseline, strict=True)):
        raise ValueError(_CHANGED)
    try:
        current_enabled, current_operator = security._enabled, security._operator_id
    except AttributeError:
        raise ValueError(_CHANGED) from None
    if (
        type(current_enabled) is not bool
        or current_enabled is not enabled
        or type(current_operator) is not str
        or current_operator != operator
        or (cancel is not None and (type(cancel) is not _EVENT or "is_set" in vars(cancel)))
        or any(name in vars(condition) for name in ("__enter__", "__exit__"))
    ):
        raise ValueError(_CHANGED)
    entry(owner)


def _available(
    graph: _Graph, deadline_ns: int, last_ns: int, *, eligible: bool = True
) -> tuple[int, int]:
    """Check cached host admission under its captured original Condition only."""
    bindings, require_graph, state, now_method = _BINDINGS, _REQUIRE_GRAPH, _STATE, _NOW
    event_is_set, alive, unavailable = _EVENT_IS_SET, _THREAD_ALIVE, _UNAVAILABLE
    if (
        type(deadline_ns) is not int
        or not 0 <= deadline_ns <= _MAX_NS
        or type(last_ns) is not int
        or not 0 <= last_ns <= _MAX_NS
        or type(eligible) is not bool
    ):
        raise ValueError(_INVALID)
    require_graph(graph)
    owner, condition, worker, cancel = graph[1], graph[6], graph[7], graph[10]
    state(owner)
    require_graph(graph)
    now = now_method(owner)
    # Preserve every original clock/stop side effect, even when it denies us.
    require_graph(graph)
    if now is None:
        raise unavailable()
    if type(now) is not int or not 0 <= now <= _MAX_NS or now < last_ns:
        raise unavailable()
    attributes = vars(owner)
    work, lifetime = attributes.get("_work_deadline"), attributes.get("_lifetime_deadline")
    if type(work) is not int or type(lifetime) is not int:
        raise ValueError(_INVALID)
    # Original H's cached work already includes its reserve and original R1
    # ceiling. This join only decreases that retained bound.
    deadline_ns = min(deadline_ns, work, lifetime)
    if now >= deadline_ns:
        raise unavailable()
    if eligible and (
        attributes.get("_phase") != "idle"
        or attributes.get("_busy") is not False
        or attributes.get("_slot") is not None
        or attributes.get("_active_nonce") is not None
        or attributes.get("_finalized") is not False
        or attributes.get("_stop_latched") is not False
        or attributes.get("_attempted") is not False
        or attributes.get("_preparation_return_admitted") is not False
        or attributes.get("_prepared_proposal_sha256") is not None
        or attributes.get("_install_dispatched") is not False
        or attributes.get("_terminal_install") is not None
        or attributes.get("_install_observation") is not None
        or attributes.get("_install_succeeded") is not False
        or attributes.get("_install_return_admitted") is not False
        or attributes.get("_condition") is not condition
        or worker is None
        or worker is _CURRENT_THREAD()
        or not alive(worker)
    ):
        raise unavailable()
    if eligible and cancel is not None:
        observed = event_is_set(cancel)
        if type(observed) is not bool or observed:
            raise unavailable()
    bindings()
    require_graph(graph)
    return deadline_ns, now


def _ready(value: object, *, call_id: str, incarnation: str) -> None:
    bindings, identifier, result_class = _BINDINGS, _IDENTIFIER, _READINESS
    bindings()
    if type(value) is not _READINESS or not isinstance(value, InitialSelectionReadinessResult):
        raise ValueError(_INVALID)
    status, reason, returned_call, returned_incarnation = (
        value.status,
        value.reason,
        value.call_id,
        value.incarnation,
    )
    if any(type(item) is not str for item in (status, reason, returned_call, returned_incarnation)):
        raise ValueError(_INVALID)
    if (
        reason not in _PROOF_REASONS
        or identifier(returned_call) != call_id
        or identifier(returned_incarnation) != incarnation
        or (
            (status, reason) != ("ready", "verified")
            and (status != "unavailable" or reason == "verified")
        )
    ):
        raise ValueError(_INVALID)
    bindings()
    result_class(status, reason, returned_call, returned_incarnation)
    bindings()
    if (status, reason) != ("ready", "verified"):
        raise _UNAVAILABLE()


def _native_capability_values(value: object) -> _CapabilityValues:
    bindings, operator_validator = _BINDINGS, _OPERATOR
    bindings()
    if type(value) is not tuple or len(value) != 6:
        raise ValueError(_INVALID)
    enabled, operator, csrf, csrf_header, idempotency_header, disabled_reason = value
    if (
        type(enabled) is not bool
        or (operator is not None and type(operator) is not str)
        or (csrf is not None and type(csrf) is not str)
        or type(csrf_header) is not str
        or type(idempotency_header) is not str
        or (disabled_reason is not None and type(disabled_reason) is not str)
    ):
        raise ValueError(_INVALID)
    if csrf_header != "X-CSRF-Token" or idempotency_header != "Idempotency-Key":
        raise ValueError(_INVALID)
    if enabled:
        operator_validator(operator)
        if (
            csrf is None
            or not 32 <= len(csrf) <= 128
            or any(character not in _SAFE_TOKEN for character in csrf)
            or disabled_reason is not None
        ):
            raise ValueError(_INVALID)
    elif operator is not None or csrf is not None or disabled_reason not in _DISABLED_REASONS:
        raise ValueError(_INVALID)
    return enabled, operator, csrf, csrf_header, idempotency_header, disabled_reason


def _capability_values(value: object) -> _CapabilityValues:
    bindings, native = _BINDINGS, _NATIVE_CAPABILITY_VALUES
    bindings()
    if type(value) is not _CAPABILITY or not isinstance(value, BacktestLaunchCapability):
        raise ValueError(_INVALID)
    values = (
        value.enabled,
        value.operator_id,
        value.csrf_token,
        value.csrf_header,
        value.idempotency_header,
        value.disabled_reason,
    )
    bindings()
    return native(values)


def _capability_from_values(values: _CapabilityValues) -> BacktestLaunchCapability:
    bindings, native, capability, snapshot = (
        _BINDINGS,
        _NATIVE_CAPABILITY_VALUES,
        _CAPABILITY,
        _CAPABILITY_VALUES,
    )
    bindings()
    values = native(values)
    copied = capability(
        enabled=values[0],
        operator_id=values[1],
        csrf_token=values[2],
        csrf_header=values[3],
        idempotency_header=values[4],
        disabled_reason=values[5],
    )
    bindings()
    if snapshot(copied) != values:
        raise ValueError(_INVALID)
    return copied


def _headers(response: object) -> _Headers:
    bindings = _BINDINGS
    bindings()
    if type(response) is not _RESPONSE or not isinstance(response, Response):
        raise ValueError(_INVALID)
    attributes = vars(response)
    if any(
        name in attributes for name in ("render", "init_headers", "set_cookie", "delete_cookie")
    ):
        raise ValueError(_CHANGED)
    body, status, background, raw = (
        response.body,
        response.status_code,
        response.background,
        response.raw_headers,
    )
    if (
        type(body) is not bytes
        or body != b""
        or type(status) is not int
        or status != 200
        or background is not None
        or type(raw) is not list
        or len(raw) not in (3, 4)
        or any(type(item) is not tuple or len(item) != 2 for item in raw)
        or any(type(leaf) is not bytes for item in raw for leaf in item)
    ):
        raise ValueError(_INVALID)
    values = tuple((name, value) for name, value in raw)
    if values[:3] != _BASE_HEADERS:
        raise ValueError(_INVALID)
    if len(values) == 4 and (
        values[3][0] != b"set-cookie" or len(values[3][1]) > _MAX_COOKIE_HEADER
    ):
        raise ValueError(_INVALID)
    bindings()
    return values


def _candidate_cookie(
    headers: _Headers, incoming_cookie: str | None, *, enabled: bool
) -> str | None:
    _BINDINGS()
    if (
        type(headers) is not tuple
        or len(headers) not in (3, 4)
        or type(enabled) is not bool
        or (
            incoming_cookie is not None
            and (type(incoming_cookie) is not str or len(incoming_cookie) > 2048)
        )
        or any(type(item) is not tuple or len(item) != 2 for item in headers)
        or any(type(leaf) is not bytes for item in headers for leaf in item)
    ):
        raise ValueError(_INVALID)
    if headers[:3] != _BASE_HEADERS:
        raise ValueError(_INVALID)
    if len(headers) == 3:
        if not enabled or incoming_cookie is None:
            raise ValueError(_INVALID)
        return incoming_cookie
    name, value = headers[3]
    if name != b"set-cookie" or len(value) > _MAX_COOKIE_HEADER:
        raise ValueError(_INVALID)
    if not enabled:
        if not value.startswith(_DELETE_PREFIX) or not value.endswith(_DELETE_SUFFIX):
            raise ValueError(_INVALID)
        expiry = value[len(_DELETE_PREFIX) : -len(_DELETE_SUFFIX)]
        # SimpleCookie formats expires=0 against its actual current wall clock.
        # Admit only that native RFC1123 shape, not an invented epoch literal.
        if (
            len(expiry) != 29
            or expiry[:3] not in (b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun")
            or expiry[3:5] != b", "
            or expiry[7:8] != b" "
            or expiry[8:11]
            not in (
                b"Jan",
                b"Feb",
                b"Mar",
                b"Apr",
                b"May",
                b"Jun",
                b"Jul",
                b"Aug",
                b"Sep",
                b"Oct",
                b"Nov",
                b"Dec",
            )
            or expiry[11:12] != b" "
            or expiry[16:17] != b" "
            or expiry[19:20] != b":"
            or expiry[22:23] != b":"
            or expiry[25:] != b" GMT"
            or any(
                not 48 <= expiry[index] <= 57
                for index in (5, 6, 12, 13, 14, 15, 17, 18, 20, 21, 23, 24)
            )
        ):
            raise ValueError(_INVALID)
        return None
    if not value.startswith(_COOKIE_PREFIX) or not value.endswith(_COOKIE_SUFFIX):
        raise ValueError(_INVALID)
    token = value[len(_COOKIE_PREFIX) : -len(_COOKIE_SUFFIX)]
    if not token or len(token) > 2048 or any(character not in _COOKIE_TOKEN for character in token):
        raise ValueError(_INVALID)
    try:
        return token.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(_INVALID) from None


def _authenticate_delivery(
    security: LocalOperatorSecurity,
    cookie: str | None,
    csrf: str,
    at: datetime,
    operator: str,
) -> datetime:
    bindings, authenticate, admit_operator, utc = _BINDINGS, _AUTHENTICATE, _OPERATOR, _UTC
    value = authenticate(security, cookie, csrf, now=at)
    bindings()
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(_INVALID)
    if (
        type(value[1]) is not _DATETIME
        or not isinstance(value[1], datetime)
        or value[1].tzinfo is not UTC
    ):
        raise ValueError(_INVALID)
    returned_operator, expiry = admit_operator(value[0]), utc(value[1])
    if returned_operator != operator or expiry <= at:
        raise ValueError(_INVALID)
    return expiry


def _bootstrap_initial_selection_operator(
    *,
    security: LocalOperatorSecurity,
    owner: InitialSelectionPreparationOwner,
    account_id: str,
    call_id: str,
    session_cookie: str | None = None,
    cancel_event: Event | None = None,
) -> tuple[BacktestLaunchCapability, Response]:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    bindings = _BINDINGS
    bindings()
    graph_factory, require_graph, identifier = _GRAPH, _REQUIRE_GRAPH, _IDENTIFIER
    available, sample_utc, monotonic = _AVAILABLE, _SAMPLE_UTC, _MONOTONIC
    proof, ready, bootstrap, response_class = _PROOF, _READY, _BOOTSTRAP, _RESPONSE
    capability_values, capability_copy = _CAPABILITY_VALUES, _CAPABILITY_FROM_VALUES
    headers_snapshot, candidate_cookie = _HEADERS, _CANDIDATE_COOKIE
    authenticate, unavailable = _AUTHENTICATE_DELIVERY, _UNAVAILABLE
    enter, exit_context = _CONDITION_ENTER, _CONDITION_EXIT
    graph = graph_factory(security, owner, account_id, cancel_event)
    call_id = identifier(call_id)
    if session_cookie is not None and (
        type(session_cookie) is not str or len(session_cookie) > 2048
    ):
        raise ValueError(_INVALID)
    require_graph(graph)
    condition, enabled, operator = graph[6], graph[8], graph[9]
    joined_ns: int | None = None
    admitted_at: datetime | None = None
    if enabled:
        joined_ns = monotonic()
        admitted_at = sample_utc()
        require_graph(graph)
    response = response_class(
        content=b"",
        status_code=200,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
    require_graph(graph)
    headers_snapshot(response)
    if not enabled:
        at = sample_utc()
        require_graph(graph)
        if headers_snapshot(response) != _BASE_HEADERS:
            raise ValueError(_INVALID)
        returned = bootstrap(
            security, response, persistence_ready=False, issued_at=at, session_cookie=session_cookie
        )
        require_graph(graph)
        values = capability_values(returned)
        if values != (False, None, None, "X-CSRF-Token", "Idempotency-Key", _DISABLED_REASONS[0]):
            raise ValueError(_INVALID)
        headers = headers_snapshot(response)
        candidate_cookie(headers, session_cookie, enabled=False)
        result = capability_copy(values)
        require_graph(graph)
        if capability_values(result) != values or headers_snapshot(response) != headers:
            raise ValueError(_INVALID)
        require_graph(graph)
        return result, response

    if joined_ns is None or admitted_at is None:
        raise ValueError(_INVALID)
    require_graph(graph)
    # Saved native context methods cannot be redirected by an instance shadow.
    enter(condition)
    try:
        require_graph(graph)
        limits = graph[3][3]
        if type(limits) is not tuple or len(limits) != 4 or type(limits[1]) is not int:
            raise ValueError(_INVALID)
        deadline = min(_MAX_NS, joined_ns + limits[1])
        deadline, last_ns = available(graph, deadline, joined_ns, eligible=False)
    except BaseException as error:
        exit_context(condition, type(error), error, error.__traceback__)
        raise
    else:
        exit_context(condition, None, None, None)

    # This is the only proof dispatch, outside the original nonreentrant lock.
    returned_proof = proof(owner, call_id, cancel_event=cancel_event)
    require_graph(graph)
    ready(returned_proof, call_id=call_id, incarnation=graph[5])
    require_graph(graph)
    enter(condition)
    try:
        require_graph(graph)
        deadline, last_ns = available(graph, deadline, last_ns)
        issued_at = sample_utc(admitted_at)
        require_graph(graph)
        if headers_snapshot(response) != _BASE_HEADERS:
            raise ValueError(_INVALID)
        returned = bootstrap(
            security,
            response,
            persistence_ready=True,
            issued_at=issued_at,
            session_cookie=session_cookie,
        )
        require_graph(graph)
        values = capability_values(returned)
        if not values[0] or values[1] != operator or values[2] is None:
            raise ValueError(_INVALID)
        headers = headers_snapshot(response)
        cookie = candidate_cookie(headers, session_cookie, enabled=True)
        copied = capability_copy(values)
        require_graph(graph)
        deadline, last_ns = available(graph, deadline, last_ns)
        delivery_at = sample_utc(issued_at)
        require_graph(graph)
        expiry = authenticate(security, cookie, values[2], delivery_at, operator)
        require_graph(graph)
        if capability_values(copied) != values or headers_snapshot(response) != headers:
            raise ValueError(_INVALID)
        require_graph(graph)
        # Authentication and copying can consume the remaining interval. No
        # second authentication or issuer call repairs an expired staged result.
        deadline, last_ns = available(graph, deadline, last_ns)
        final_at = sample_utc(delivery_at)
        if final_at >= expiry:
            raise unavailable()
        require_graph(graph)
        # The final original clock callbacks can mutate staged native output.
        if capability_values(copied) != values or headers_snapshot(response) != headers:
            raise ValueError(_INVALID)
        require_graph(graph)
    except BaseException as error:
        exit_context(condition, type(error), error, error.__traceback__)
        raise
    else:
        exit_context(condition, None, None, None)
    return copied, response


_BINDINGS = _bindings
_IDENTIFIER = _identifier
_OPERATOR = _operator
_UTC = _utc
_SAMPLE_UTC = _sample_utc
_MONOTONIC = _monotonic
_UNAVAILABLE = _unavailable
_GRAPH = _graph
_REQUIRE_GRAPH = _require_graph
_AVAILABLE = _available
_READY = _ready
_NATIVE_CAPABILITY_VALUES = _native_capability_values
_CAPABILITY_VALUES = _capability_values
_CAPABILITY_FROM_VALUES = _capability_from_values
_HEADERS = _headers
_CANDIDATE_COOKIE = _candidate_cookie
_AUTHENTICATE_DELIVERY = _authenticate_delivery
_HELPERS = tuple(
    (name, globals()[name])
    for name in (
        "_bindings",
        "_identifier",
        "_operator",
        "_utc",
        "_sample_utc",
        "_monotonic",
        "_unavailable",
        "_graph",
        "_require_graph",
        "_available",
        "_ready",
        "_native_capability_values",
        "_capability_values",
        "_capability_from_values",
        "_headers",
        "_candidate_cookie",
        "_authenticate_delivery",
        "_BINDINGS",
        "_IDENTIFIER",
        "_OPERATOR",
        "_UTC",
        "_SAMPLE_UTC",
        "_MONOTONIC",
        "_UNAVAILABLE",
        "_GRAPH",
        "_REQUIRE_GRAPH",
        "_AVAILABLE",
        "_READY",
        "_NATIVE_CAPABILITY_VALUES",
        "_CAPABILITY_VALUES",
        "_CAPABILITY_FROM_VALUES",
        "_HEADERS",
        "_CANDIDATE_COOKIE",
        "_AUTHENTICATE_DELIVERY",
    )
)
_DISPATCH_PINS = tuple(
    (name, globals()[name])
    for name in (
        "_SECURITY",
        "_BOOTSTRAP",
        "_AUTHENTICATE",
        "_DECODE",
        "_ISSUE",
        "_DISABLED",
        "_OWNER",
        "_PROOF",
        "_ENTRY",
        "_STATE",
        "_NOW",
        "_READINESS",
        "_READINESS_INIT",
        "_READINESS_VALIDATE",
        "_CAPABILITY",
        "_CAPABILITY_INIT",
        "_CAPABILITY_VALIDATOR",
        "_RESPONSE",
        "_RESPONSE_INIT",
        "_RESPONSE_RENDER",
        "_RESPONSE_HEADERS",
        "_RESPONSE_SET_COOKIE",
        "_RESPONSE_DELETE_COOKIE",
        "_EVENT",
        "_EVENT_IS_SET",
        "_CONDITION",
        "_CONDITION_ENTER",
        "_CONDITION_EXIT",
        "_THREAD",
        "_THREAD_ALIVE",
        "_CURRENT_THREAD",
        "_IDENTIFIER_VALIDATOR",
        "_DATETIME",
        "_CLOCK_NOW",
        "_MONOTONIC_NS",
        "_MAX_NS",
        "_PROOF_REASONS",
        "_SAFE_TOKEN",
        "_COOKIE_TOKEN",
        "_BASE_HEADERS",
        "_COOKIE_PREFIX",
        "_COOKIE_SUFFIX",
        "_DELETE_PREFIX",
        "_DELETE_SUFFIX",
        "_MAX_COOKIE_HEADER",
        "_DISABLED_REASONS",
        "UTC",
        "datetime",
        "Condition",
        "Thread",
        "Response",
        "LocalOperatorSecurity",
        "BacktestLaunchCapability",
        "InitialSelectionPreparationOwner",
        "InitialSelectionReadinessResult",
    )
)
