"""Authenticated, read-only Alpaca paper UNKNOWN-submission lookup runtime.

Phase 4I admits one exact ``GET /v2/orders:by_client_order_id`` for a durable
submission attempt whose current terminal state is ``UNKNOWN``.  It consumes a
new protected request-budget permit, reauthenticates the UNKNOWN attempt and
the terminal Phase 4G account-identity binding before and after transport, and
records a completed raw response before strict Phase 4B decoding.

Every accepted result remains historical reconciliation input.  A matching
order, an economics mismatch, an independently pinned asset-ID mismatch, and a
404 are all non-authorizing and cannot resolve the UNKNOWN attempt.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

import httpx

from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT,
    AlpacaPaperAccountBindingRuntimePort,
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionReceipt,
    BrokerRequestBudgetRuntimePort,
    _AlpacaPaperAuthenticationHeaders,
    _resolve_alpaca_paper_credentials_for_operation,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    AlpacaPaperSecurityReference,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
    ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
    PersistedAlpacaClientOrderLookupObservation,
)
from packages.adapters.broker.alpaca_paper_observations import (
    AlpacaClientOrderLookupDescription,
    AlpacaClientOrderLookupObservation,
    AlpacaClientOrderLookupOutcome,
    decode_alpaca_client_order_lookup_response,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorPort,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.broker_ingress import (
    MAX_BROKER_INGRESS_BODY_BYTES,
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
    BrokerIngressRecorder,
)
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetPolicy,
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPermitFreshnessReceipt,
    BrokerRequestPurpose,
    require_fresh_broker_request_permit,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    reduce_submission_attempt,
)

ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION = (
    "phase4i-authenticated-alpaca-paper-unknown-lookup-v1"
)
ALPACA_PAPER_UNKNOWN_ATTEMPT_FRESHNESS_CONTRACT_VERSION = (
    "phase4i-terminal-unknown-attempt-freshness-v1"
)
ALPACA_PAPER_LOOKUP_HTTPX_PHASE_TIMEOUT = ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT
ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE = ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
ALPACA_PAPER_LOOKUP_TRANSPORT_ID = "strict-httpx-alpaca-paper-client-order-lookup"
ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION = "1.0.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AlpacaPaperLookupRuntimeError(AlpacaPaperContractError):
    """Authenticated lookup evidence is malformed or inconsistent."""


class AlpacaPaperLookupTransportError(AlpacaPaperLookupRuntimeError):
    """The exact restricted lookup transport failed."""


class AlpacaPaperLookupConflict(AlpacaPaperLookupRuntimeError):
    """Lookup evidence conflicts with another immutable source."""


class AlpacaPaperAuthenticatedLookupOutcome(StrEnum):
    """Closed historical outcomes for one authenticated client-ID lookup."""

    FOUND_MATCHED = "found_matched"
    FOUND_MISMATCH = "found_mismatch"
    SECURITY_IDENTITY_MISMATCH = "security_identity_mismatch"
    NOT_VISIBLE_INCONCLUSIVE = "not_visible_inconclusive"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: object, field_name: str, *, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperLookupRuntimeError(f"{field_name} must be bounded, non-empty trimmed text")
    return value


def _require_safe_text(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if _SAFE_TEXT.fullmatch(text) is None:
        raise AlpacaPaperLookupRuntimeError(f"{field_name} is not canonical safe text")
    return text


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperLookupRuntimeError(f"{field_name} must be a lowercase SHA-256")
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperLookupRuntimeError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperLookupRuntimeError(str(error)) from error
    return value


def _trusted_now(clock: Clock, field_name: str) -> datetime:
    try:
        instant = clock.now()
    except Exception as error:
        raise AlpacaPaperLookupRuntimeError(f"{field_name} clock failed") from error
    return _require_utc(instant, field_name)


def _bounded_transport_metadata(value: object, *, maximum: int) -> str | None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    return value


def _require_unknown_attempt(
    attempt: CanonicalSubmissionAttempt,
) -> CanonicalSubmissionAttempt:
    if type(attempt) is not CanonicalSubmissionAttempt:
        raise AlpacaPaperLookupConflict(
            "authenticated lookup requires an exact canonical submission attempt"
        )
    try:
        reconstructed = reduce_submission_attempt(
            attempt.preparation,
            attempt.events,
        )
    except SubmissionAttemptError as error:
        raise AlpacaPaperLookupConflict(
            "authenticated lookup attempt is not reducer-produced"
        ) from error
    if reconstructed != attempt:
        raise AlpacaPaperLookupConflict(
            "authenticated lookup attempt conflicts with its immutable history"
        )
    if (
        attempt.state is not SubmissionAttemptState.UNKNOWN
        or attempt.events[-1].state is not SubmissionAttemptState.UNKNOWN
    ):
        raise AlpacaPaperLookupConflict(
            "authenticated client-order lookup requires a terminal UNKNOWN attempt"
        )
    return attempt


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperUnknownAttemptFreshnessReceipt:
    """Repository proof that an exact attempt was terminal UNKNOWN at one instant."""

    account_id: str
    attempt_id: str
    attempt_sha256: str
    terminal_event_id: str
    terminal_event_sha256: str
    terminal_sequence_number: int
    parent_decision_id: str
    reservation_id: str
    client_order_id: str
    checked_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperUnknownAttemptFreshnessReceipt must be repository-produced")

    def _validate(self) -> None:
        for value, field_name in (
            (self.account_id, "UNKNOWN freshness account ID"),
            (self.attempt_id, "UNKNOWN freshness attempt ID"),
            (self.terminal_event_id, "UNKNOWN freshness event ID"),
            (self.parent_decision_id, "UNKNOWN freshness parent decision ID"),
            (self.reservation_id, "UNKNOWN freshness reservation ID"),
            (self.client_order_id, "UNKNOWN freshness client order ID"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.attempt_sha256, "UNKNOWN freshness attempt digest")
        _require_sha256(self.terminal_event_sha256, "UNKNOWN freshness event digest")
        if type(self.terminal_sequence_number) is not int or self.terminal_sequence_number <= 0:
            raise AlpacaPaperLookupConflict("UNKNOWN freshness terminal sequence must be positive")
        _require_utc(self.checked_at, "UNKNOWN freshness checked_at")

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_UNKNOWN_ATTEMPT_FRESHNESS_CONTRACT_VERSION,
                "terminal_unknown_attempt_freshness",
                self.account_id,
                self.attempt_id,
                self.attempt_sha256,
                self.terminal_event_id,
                self.terminal_event_sha256,
                self.terminal_sequence_number,
                self.parent_decision_id,
                self.reservation_id,
                self.client_order_id,
                self.checked_at,
            )
        )

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-terminal-unknown-attempt-freshness",
            self.semantic_sha256,
        )

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _alpaca_paper_unknown_attempt_freshness_receipt(
    attempt: CanonicalSubmissionAttempt,
    *,
    checked_at: datetime,
) -> AlpacaPaperUnknownAttemptFreshnessReceipt:
    """Construct proof only after a repository authenticates terminal position."""

    _require_unknown_attempt(attempt)
    _require_utc(checked_at, "UNKNOWN freshness checked_at")
    event = attempt.events[-1]
    receipt = object.__new__(AlpacaPaperUnknownAttemptFreshnessReceipt)
    for field_name, value in (
        ("account_id", attempt.preparation.account_id),
        ("attempt_id", attempt.attempt_id),
        ("attempt_sha256", attempt.semantic_sha256),
        ("terminal_event_id", event.event_id),
        ("terminal_event_sha256", event.semantic_sha256),
        ("terminal_sequence_number", event.sequence_number),
        ("parent_decision_id", attempt.parent_decision_id),
        ("reservation_id", attempt.preparation.reservation_id),
        ("client_order_id", attempt.preparation.client_order_id),
        ("checked_at", checked_at),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


class AlpacaPaperUnknownAttemptRuntimePort(Protocol):
    """Durable terminal-UNKNOWN authentication required around lookup I/O."""

    def authenticate_terminal_unknown(
        self,
        attempt: CanonicalSubmissionAttempt,
        checked_at: datetime,
    ) -> AlpacaPaperUnknownAttemptFreshnessReceipt: ...


class AlpacaPaperLookupCredentialResolver(Protocol):
    """Secret-read authority restricted to the Phase 4I lookup boundary."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_client_order_lookup(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object: ...


def _validate_lookup_sources(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaClientOrderLookupDescription,
) -> None:
    if type(security_reference) is not AlpacaPaperSecurityReference:
        raise AlpacaPaperLookupConflict(
            "lookup requires an exact operator-pinned security reference"
        )
    if type(account_binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperLookupConflict("lookup requires an exact authenticated account binding")
    if type(description) is not AlpacaClientOrderLookupDescription:
        raise AlpacaPaperLookupConflict("lookup requires an exact client-order description")
    security_reference.__post_init__()
    account_binding._validate()
    _require_unknown_attempt(attempt)
    description.__post_init__()
    credential_reference = security_reference.credential_reference
    intent = attempt.preparation.intent
    if (
        description.account_id != attempt.preparation.account_id
        or credential_reference.account_id != attempt.preparation.account_id
        or account_binding.account_id != attempt.preparation.account_id
        or account_binding.expected_provider_account_id
        != credential_reference.expected_provider_account_id
        or account_binding.credential_reference_sha256 != credential_reference.semantic_sha256
        or account_binding.secret_ref != credential_reference.secret_ref
        or account_binding.secret_version != credential_reference.secret_version
    ):
        raise AlpacaPaperLookupConflict("lookup sources cross local or provider account identities")
    if (
        description.submission.intent != intent
        or description.submission.request != attempt.preparation.request
        or description.submission.request.client_order_id != attempt.preparation.client_order_id
        or description.submission.request.order_id != attempt.preparation.order_id
    ):
        raise AlpacaPaperLookupConflict(
            "lookup description does not bind the exact UNKNOWN submission"
        )
    if (
        security_reference.instrument_id != intent.instrument_id
        or security_reference.symbol != intent.symbol
        or description.submission.body["symbol"] != security_reference.symbol
    ):
        raise AlpacaPaperLookupConflict("lookup security pin does not bind the UNKNOWN intent")


def alpaca_paper_unknown_lookup_correlation_sha256(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaClientOrderLookupDescription,
) -> str:
    """Bind one budget demand to the exact UNKNOWN recovery observation."""

    _validate_lookup_sources(
        security_reference=security_reference,
        account_binding=account_binding,
        attempt=attempt,
        description=description,
    )
    return _semantic_sha256(
        (
            ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
            "unknown_lookup_correlation",
            security_reference.semantic_sha256,
            account_binding.semantic_sha256,
            attempt.semantic_sha256,
            attempt.events[-1].semantic_sha256,
            description.semantic_sha256,
        )
    )


def create_alpaca_paper_unknown_lookup_demand(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaClientOrderLookupDescription,
    idempotency_key: str,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Create the fixed new-only UNKNOWN lookup demand."""

    return create_alpaca_paper_request_demand(
        account_id=attempt.preparation.account_id,
        idempotency_key=idempotency_key,
        operation=AlpacaPaperBudgetOperation.LOOKUP_UNKNOWN_BY_CLIENT_ORDER_ID,
        correlation_sha256=alpaca_paper_unknown_lookup_correlation_sha256(
            security_reference=security_reference,
            account_binding=account_binding,
            attempt=attempt,
            description=description,
        ),
        requested_at=requested_at,
    )


@dataclass(frozen=True, slots=True)
class AlpacaPaperLookupTransportRequest:
    """Secret-free description of one exact preauthorized UNKNOWN lookup."""

    description: AlpacaClientOrderLookupDescription
    credential_reference_sha256: str
    security_reference_sha256: str
    attempt_sha256: str
    unknown_attempt_freshness_sha256: str
    account_binding_sha256: str
    account_identity_sha256: str
    demand_sha256: str
    permit_sha256: str
    permit_freshness_sha256: str
    fence_receipt_sha256: str
    started_at: datetime
    httpx_phase_timeout: timedelta = ALPACA_PAPER_LOOKUP_HTTPX_PHASE_TIMEOUT

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaClientOrderLookupDescription:
            raise AlpacaPaperLookupTransportError(
                "lookup transport requires an exact lookup description"
            )
        self.description.__post_init__()
        for value, field_name in (
            (self.credential_reference_sha256, "credential reference"),
            (self.security_reference_sha256, "security reference"),
            (self.attempt_sha256, "UNKNOWN attempt"),
            (self.unknown_attempt_freshness_sha256, "UNKNOWN freshness"),
            (self.account_binding_sha256, "account binding"),
            (self.account_identity_sha256, "account identity continuity"),
            (self.demand_sha256, "request demand"),
            (self.permit_sha256, "request permit"),
            (self.permit_freshness_sha256, "permit freshness"),
            (self.fence_receipt_sha256, "fence receipt"),
        ):
            _require_sha256(value, f"lookup transport {field_name} digest")
        _require_utc(self.started_at, "lookup transport started_at")
        if (
            type(self.httpx_phase_timeout) is not timedelta
            or self.httpx_phase_timeout != ALPACA_PAPER_LOOKUP_HTTPX_PHASE_TIMEOUT
        ):
            raise AlpacaPaperLookupTransportError(
                "lookup transport must use the fixed socket-I/O inactivity timeout"
            )
        if (
            self.description.method != "GET"
            or self.description.base_url != ALPACA_PAPER_TRADING_BASE_URL
            or self.description.path != ALPACA_PAPER_CAPABILITIES.order_by_client_id_path
            or tuple(self.description.query) != ("client_order_id",)
            or self.description.query["client_order_id"]
            != self.description.submission.request.client_order_id
        ):
            raise AlpacaPaperLookupTransportError(
                "lookup transport request escaped the fixed client-ID GET"
            )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def url(self) -> str:
        return str(
            httpx.URL(
                f"{self.description.base_url}{self.description.path}",
                params=tuple(self.description.query.items()),
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
                "lookup_transport_request",
                self.description.semantic_sha256,
                self.credential_reference_sha256,
                self.security_reference_sha256,
                self.attempt_sha256,
                self.unknown_attempt_freshness_sha256,
                self.account_binding_sha256,
                self.account_identity_sha256,
                self.demand_sha256,
                self.permit_sha256,
                self.permit_freshness_sha256,
                self.fence_receipt_sha256,
                self.started_at,
                int(self.httpx_phase_timeout.total_seconds() * 1_000_000),
                self.method,
                self.url,
            )
        )

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class AlpacaPaperLookupTransportResponse:
    """Bounded exact entity bytes from one restricted lookup GET."""

    request_sha256: str
    transport_id: str
    transport_version: str
    http_status: int
    provider_request_id: str | None
    media_type: str | None
    response_body: bytes = field(repr=False)
    tls_verified: bool = True
    redirects_followed: bool = False

    def __post_init__(self) -> None:
        _require_sha256(self.request_sha256, "lookup response request digest")
        _require_safe_text(self.transport_id, "lookup transport ID")
        _require_safe_text(self.transport_version, "lookup transport version")
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise AlpacaPaperLookupTransportError(
                "lookup response status must be an exact HTTP status"
            )
        if self.provider_request_id is not None:
            _require_text(
                self.provider_request_id,
                "lookup X-Request-ID",
                maximum=256,
            )
        if self.media_type is not None:
            _require_text(self.media_type, "lookup response media type", maximum=128)
        if type(self.response_body) is not bytes:
            raise AlpacaPaperLookupTransportError("lookup response body must be exact bytes")
        if len(self.response_body) > MAX_BROKER_INGRESS_BODY_BYTES:
            raise AlpacaPaperLookupTransportError("lookup response exceeds the durable raw bound")
        if type(self.tls_verified) is not bool or not self.tls_verified:
            raise AlpacaPaperLookupTransportError("lookup transport must verify TLS")
        if type(self.redirects_followed) is not bool or self.redirects_followed:
            raise AlpacaPaperLookupTransportError("lookup transport cannot follow redirects")

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
                "lookup_transport_response",
                self.request_sha256,
                self.transport_id,
                self.transport_version,
                self.http_status,
                self.provider_request_id,
                self.media_type,
                len(self.response_body),
                self.response_sha256,
                self.tls_verified,
                self.redirects_followed,
            )
        )

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


class _AlpacaPaperLookupTransport(Protocol):
    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def execute(
        self,
        request: AlpacaPaperLookupTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperLookupTransportResponse: ...


class _HttpxAlpacaPaperLookupTransport:
    """Concrete TLS-verifying, no-redirect, no-proxy lookup-only transport."""

    __slots__ = ()

    @property
    def transport_id(self) -> str:
        return ALPACA_PAPER_LOOKUP_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION

    def execute(
        self,
        request: AlpacaPaperLookupTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperLookupTransportResponse:
        if type(request) is not AlpacaPaperLookupTransportRequest:
            raise AlpacaPaperLookupTransportError(
                "strict lookup transport requires an exact request"
            )
        request.__post_init__()
        if type(headers) is not _AlpacaPaperAuthenticationHeaders:
            raise AlpacaPaperLookupTransportError(
                "strict lookup transport requires redacted authentication headers"
            )
        if tuple(headers) != ALPACA_AUTH_HEADER_NAMES:
            raise AlpacaPaperLookupTransportError(
                "strict lookup transport requires the exact authentication headers"
            )
        timeout_seconds = request.httpx_phase_timeout.total_seconds()
        result: AlpacaPaperLookupTransportResponse | None = None
        request_failed = False
        try:
            with (
                httpx.Client(
                    verify=True,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(
                        connect=timeout_seconds,
                        read=timeout_seconds,
                        write=timeout_seconds,
                        pool=timeout_seconds,
                    ),
                    headers={
                        "Accept": ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE,
                        "Accept-Encoding": "identity",
                        "User-Agent": (
                            f"autoquant-trader/{ALPACA_PAPER_ADAPTER_VERSION} "
                            "phase4i-unknown-lookup"
                        ),
                    },
                ) as client,
                client.stream(
                    request.method,
                    request.url,
                    headers=headers,
                ) as response,
            ):
                body = bytearray()
                for chunk in response.iter_raw():
                    if len(body) + len(chunk) > MAX_BROKER_INGRESS_BODY_BYTES:
                        raise AlpacaPaperLookupTransportError(
                            "lookup response exceeds the durable raw bound"
                        )
                    body.extend(chunk)
                request_id = _bounded_transport_metadata(
                    response.headers.get("x-request-id"),
                    maximum=256,
                )
                content_type = response.headers.get("content-type")
                content_encoding = response.headers.get("content-encoding")
                encoding_is_identity = content_encoding is None or (
                    content_encoding.strip().lower() == "identity"
                )
                media_type = None
                if content_type is not None and encoding_is_identity:
                    media_type = _bounded_transport_metadata(
                        content_type.partition(";")[0].strip().lower(),
                        maximum=128,
                    )
                response_request = response.request
                if response_request.method != "GET" or str(response_request.url) != request.url:
                    raise AlpacaPaperLookupTransportError(
                        "lookup response changed the fixed request target"
                    )
                result = AlpacaPaperLookupTransportResponse(
                    request_sha256=request.semantic_sha256,
                    transport_id=self.transport_id,
                    transport_version=self.transport_version,
                    http_status=response.status_code,
                    provider_request_id=request_id,
                    media_type=media_type,
                    response_body=bytes(body),
                )
        except AlpacaPaperLookupTransportError:
            raise
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise AlpacaPaperLookupTransportError(
                "authenticated Alpaca lookup failed without a retained response"
            ) from None
        if result is None:
            raise AlpacaPaperLookupTransportError(
                "authenticated Alpaca lookup produced no response"
            )
        return result


def _persist_then_decode_lookup(
    recorder: BrokerIngressRecorder,
    description: AlpacaClientOrderLookupDescription,
    *,
    delivery_idempotency_key: str,
    response: AlpacaPaperLookupTransportResponse,
    received_at: datetime,
    recorded_at: datetime,
) -> PersistedAlpacaClientOrderLookupObservation:
    """Commit raw bytes before any metadata qualification or provider decode."""

    if not callable(getattr(recorder, "record", None)):
        raise BrokerIngressError("authenticated Alpaca lookup requires a durable recorder")
    delivery = BrokerIngressDelivery(
        account_id=description.account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        environment="paper",
        channel=ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
        correlation_sha256=description.semantic_sha256,
        transport_status=response.http_status,
        provider_request_id=response.provider_request_id,
        media_type=response.media_type,
        received_at=received_at,
        recorded_at=recorded_at,
        body=response.response_body,
    )
    receipt = recorder.record(delivery)
    if type(receipt) is not BrokerIngressReceipt:
        raise BrokerIngressError(
            "durable recorder returned an invalid authenticated lookup receipt"
        )
    receipt.__post_init__()
    if receipt.delivery != delivery:
        raise BrokerIngressError("durable recorder returned a receipt for different lookup bytes")
    if response.provider_request_id is None:
        raise AlpacaPaperLookupConflict(
            "authenticated lookup response is missing X-Request-ID after raw persistence"
        )
    if response.media_type != ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE:
        raise AlpacaPaperLookupConflict(
            "authenticated lookup response is not JSON after raw persistence"
        )
    observation = decode_alpaca_client_order_lookup_response(
        description,
        http_status=response.http_status,
        provider_request_id=response.provider_request_id,
        response_body=response.response_body,
        received_at=received_at,
    )
    return PersistedAlpacaClientOrderLookupObservation(
        receipt=receipt,
        observation=observation,
    )


def _authenticate_unknown(
    port: AlpacaPaperUnknownAttemptRuntimePort,
    attempt: CanonicalSubmissionAttempt,
    *,
    checked_at: datetime,
    phase: str,
) -> AlpacaPaperUnknownAttemptFreshnessReceipt:
    failed = False
    receipt: object | None = None
    try:
        receipt = port.authenticate_terminal_unknown(attempt, checked_at)
    except Exception:
        failed = True
    if failed:
        raise AlpacaPaperLookupConflict(
            f"terminal UNKNOWN attempt authentication failed {phase} lookup transport"
        ) from None
    if type(receipt) is not AlpacaPaperUnknownAttemptFreshnessReceipt:
        raise AlpacaPaperLookupConflict(
            f"UNKNOWN authenticator returned invalid {phase} lookup evidence"
        )
    receipt._validate()
    expected = _alpaca_paper_unknown_attempt_freshness_receipt(
        attempt,
        checked_at=checked_at,
    )
    if receipt != expected:
        raise AlpacaPaperLookupConflict(
            f"UNKNOWN freshness receipt conflicts {phase} lookup transport"
        )
    return receipt


def _authenticate_account_binding(
    port: AlpacaPaperAccountBindingRuntimePort,
    binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    checked_at: datetime,
    phase: str,
) -> AlpacaPaperAccountIdentityContinuityReceipt:
    failed = False
    receipt: object | None = None
    try:
        receipt = port.authenticate_terminal_identity(binding, checked_at)
    except Exception:
        failed = True
    if failed:
        raise AlpacaPaperLookupConflict(
            f"terminal account-binding authentication failed {phase} lookup transport"
        ) from None
    if type(receipt) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperLookupConflict(
            f"account-identity authenticator returned invalid {phase} lookup evidence"
        )
    receipt._validate()
    if (
        receipt.account_id != binding.account_id
        or receipt.binding_id != binding.binding_id
        or receipt.binding_sha256 != binding.semantic_sha256
        or receipt.credential_reference_sha256 != binding.credential_reference_sha256
        or receipt.expected_provider_account_id != binding.expected_provider_account_id
        or receipt.sequence_number != binding.sequence_number
        or receipt.binding_qualified_at != binding.qualified_at
        or receipt.checked_at != checked_at
    ):
        raise AlpacaPaperLookupConflict(
            f"account identity continuity conflicts {phase} lookup transport"
        )
    return receipt


def _lookup_outcome(
    observation: AlpacaClientOrderLookupObservation,
    security_reference: AlpacaPaperSecurityReference,
) -> AlpacaPaperAuthenticatedLookupOutcome:
    if observation.outcome is AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE:
        return AlpacaPaperAuthenticatedLookupOutcome.NOT_VISIBLE_INCONCLUSIVE
    order = observation.order
    if order is None:
        raise AlpacaPaperLookupConflict("found lookup lacks its exact order observation")
    request_mismatch = observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    asset_mismatch = order.asset_id != security_reference.expected_provider_asset_id
    if asset_mismatch:
        return AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH
    if request_mismatch:
        return AlpacaPaperAuthenticatedLookupOutcome.FOUND_MISMATCH
    return AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedLookupEvidence:
    """Complete transient evidence supplied to the durable lookup recorder."""

    security_reference: AlpacaPaperSecurityReference
    credential_receipt: AlpacaPaperCredentialResolutionReceipt
    attempt: CanonicalSubmissionAttempt
    pre_attempt_freshness: AlpacaPaperUnknownAttemptFreshnessReceipt
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    description: AlpacaClientOrderLookupDescription
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    permit_freshness: BrokerRequestPermitFreshnessReceipt
    pre_fence_receipt: AccountFenceReceipt
    request: AlpacaPaperLookupTransportRequest
    response: AlpacaPaperLookupTransportResponse
    persisted_observation: PersistedAlpacaClientOrderLookupObservation
    post_fence_receipt: AccountFenceReceipt
    post_attempt_freshness: AlpacaPaperUnknownAttemptFreshnessReceipt
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    outcome: AlpacaPaperAuthenticatedLookupOutcome
    authenticated_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedLookupEvidence must be proof-constructed")

    def _validate(self) -> None:
        exact_types = (
            (self.security_reference, AlpacaPaperSecurityReference, "security reference"),
            (
                self.credential_receipt,
                AlpacaPaperCredentialResolutionReceipt,
                "credential receipt",
            ),
            (self.attempt, CanonicalSubmissionAttempt, "UNKNOWN attempt"),
            (
                self.pre_attempt_freshness,
                AlpacaPaperUnknownAttemptFreshnessReceipt,
                "pre-request UNKNOWN freshness",
            ),
            (
                self.account_binding,
                AlpacaPaperAuthenticatedAccountBinding,
                "account binding",
            ),
            (
                self.pre_account_identity,
                AlpacaPaperAccountIdentityContinuityReceipt,
                "pre-request account identity continuity",
            ),
            (
                self.description,
                AlpacaClientOrderLookupDescription,
                "lookup description",
            ),
            (self.policy, BrokerRequestBudgetPolicy, "budget policy"),
            (self.demand, BrokerRequestDemand, "request demand"),
            (self.permit, BrokerRequestPermit, "request permit"),
            (
                self.permit_freshness,
                BrokerRequestPermitFreshnessReceipt,
                "permit freshness",
            ),
            (self.pre_fence_receipt, AccountFenceReceipt, "pre-request fence"),
            (self.request, AlpacaPaperLookupTransportRequest, "transport request"),
            (self.response, AlpacaPaperLookupTransportResponse, "transport response"),
            (
                self.persisted_observation,
                PersistedAlpacaClientOrderLookupObservation,
                "persisted lookup observation",
            ),
            (self.post_fence_receipt, AccountFenceReceipt, "post-request fence"),
            (
                self.post_attempt_freshness,
                AlpacaPaperUnknownAttemptFreshnessReceipt,
                "post-request UNKNOWN freshness",
            ),
            (
                self.post_account_identity,
                AlpacaPaperAccountIdentityContinuityReceipt,
                "post-request account identity continuity",
            ),
            (
                self.outcome,
                AlpacaPaperAuthenticatedLookupOutcome,
                "authenticated lookup outcome",
            ),
        )
        for value, expected_type, field_name in exact_types:
            if type(value) is not expected_type:
                raise AlpacaPaperLookupConflict(
                    f"authenticated lookup evidence requires an exact {field_name}"
                )
        self.security_reference.__post_init__()
        self.credential_receipt.__post_init__()
        _validate_lookup_sources(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            attempt=self.attempt,
            description=self.description,
        )
        self.pre_attempt_freshness._validate()
        self.pre_account_identity._validate()
        self.policy.__post_init__()
        self.demand.__post_init__()
        self.permit.__post_init__()
        self.permit_freshness._validate()
        self.pre_fence_receipt._validate()
        self.request.__post_init__()
        self.response.__post_init__()
        self.persisted_observation.__post_init__()
        self.post_fence_receipt._validate()
        self.post_attempt_freshness._validate()
        self.post_account_identity._validate()
        _require_utc(self.authenticated_at, "lookup authenticated_at")

        if self.credential_receipt.reference != self.security_reference.credential_reference:
            raise AlpacaPaperLookupConflict("credential receipt does not bind the lookup reference")
        for attempt_receipt, phase in (
            (self.pre_attempt_freshness, "pre-request"),
            (self.post_attempt_freshness, "post-request"),
        ):
            expected = _alpaca_paper_unknown_attempt_freshness_receipt(
                self.attempt,
                checked_at=attempt_receipt.checked_at,
            )
            if attempt_receipt != expected:
                raise AlpacaPaperLookupConflict(
                    f"{phase} UNKNOWN receipt conflicts with the exact attempt"
                )
        for identity_receipt, phase in (
            (self.pre_account_identity, "pre-request"),
            (self.post_account_identity, "post-request"),
        ):
            if (
                identity_receipt.account_id != self.account_binding.account_id
                or identity_receipt.binding_id != self.account_binding.binding_id
                or identity_receipt.binding_sha256 != self.account_binding.semantic_sha256
                or identity_receipt.credential_reference_sha256
                != self.account_binding.credential_reference_sha256
                or identity_receipt.expected_provider_account_id
                != self.account_binding.expected_provider_account_id
                or identity_receipt.sequence_number != self.account_binding.sequence_number
                or identity_receipt.binding_qualified_at != self.account_binding.qualified_at
            ):
                raise AlpacaPaperLookupConflict(
                    f"{phase} account-identity receipt conflicts with the exact source"
                )
        if self.policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY:
            raise AlpacaPaperLookupConflict(
                "lookup requires the exact Alpaca request-budget policy"
            )
        expected_demand = create_alpaca_paper_unknown_lookup_demand(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            attempt=self.attempt,
            description=self.description,
            idempotency_key=self.demand.idempotency_key,
            requested_at=self.demand.requested_at,
        )
        if (
            self.demand != expected_demand
            or self.demand.operation
            != AlpacaPaperBudgetOperation.LOOKUP_UNKNOWN_BY_CLIENT_ORDER_ID.value
            or self.demand.purpose is not BrokerRequestPurpose.UNKNOWN_LOOKUP
        ):
            raise AlpacaPaperLookupConflict(
                "lookup demand does not bind the protected UNKNOWN purpose"
            )
        try:
            require_fresh_broker_request_permit(
                permit=self.permit,
                policy=self.policy,
                demand=self.demand,
                checked_at=self.permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperLookupConflict(
                "lookup permit is not fresh for the exact durable demand"
            ) from error
        if (
            self.permit_freshness.permit_id != self.permit.permit_id
            or self.permit_freshness.permit_sha256 != self.permit.semantic_sha256
            or self.permit_freshness.policy_sha256 != self.policy.semantic_sha256
            or self.permit_freshness.demand_sha256 != self.demand.semantic_sha256
            or self.permit_freshness.expires_at != self.permit.expires_at
        ):
            raise AlpacaPaperLookupConflict(
                "durable permit freshness conflicts with lookup evidence"
            )
        if (
            self.pre_fence_receipt.fence != self.post_fence_receipt.fence
            or self.pre_fence_receipt.policy_sha256 != self.post_fence_receipt.policy_sha256
        ):
            raise AlpacaPaperLookupConflict("account fence changed during the authenticated lookup")
        expected_request = AlpacaPaperLookupTransportRequest(
            description=self.description,
            credential_reference_sha256=(
                self.security_reference.credential_reference.semantic_sha256
            ),
            security_reference_sha256=self.security_reference.semantic_sha256,
            attempt_sha256=self.attempt.semantic_sha256,
            unknown_attempt_freshness_sha256=(self.pre_attempt_freshness.semantic_sha256),
            account_binding_sha256=self.account_binding.semantic_sha256,
            account_identity_sha256=self.pre_account_identity.semantic_sha256,
            demand_sha256=self.demand.semantic_sha256,
            permit_sha256=self.permit.semantic_sha256,
            permit_freshness_sha256=self.permit_freshness.semantic_sha256,
            fence_receipt_sha256=self.pre_fence_receipt.semantic_sha256,
            started_at=self.request.started_at,
        )
        if self.request != expected_request:
            raise AlpacaPaperLookupConflict(
                "lookup request does not bind its exact pre-send evidence"
            )
        if (
            self.response.request_sha256 != self.request.semantic_sha256
            or self.response.transport_id != ALPACA_PAPER_LOOKUP_TRANSPORT_ID
            or self.response.transport_version != ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION
            or not self.response.tls_verified
            or self.response.redirects_followed
        ):
            raise AlpacaPaperLookupConflict(
                "lookup response lacks the exact restricted transport profile"
            )
        observation = self.persisted_observation.observation
        delivery = self.persisted_observation.receipt.delivery
        if (
            delivery.body != self.response.response_body
            or delivery.transport_status != self.response.http_status
            or delivery.provider_request_id != self.response.provider_request_id
            or delivery.media_type != self.response.media_type
            or observation.response_sha256 != self.response.response_sha256
        ):
            raise AlpacaPaperLookupConflict(
                "lookup response conflicts with its raw-first observation"
            )
        if (
            self.response.http_status not in (200, 404)
            or self.response.provider_request_id is None
            or self.response.media_type != ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE
            or self.outcome is not _lookup_outcome(observation, self.security_reference)
        ):
            raise AlpacaPaperLookupConflict(
                "lookup response does not have a closed historical outcome"
            )
        received_at = observation.received_at
        recorded_at = delivery.recorded_at
        if not (
            self.demand.requested_at
            <= self.credential_receipt.started_at
            <= self.credential_receipt.resolved_at
            <= self.permit.issued_at
            <= self.pre_fence_receipt.validated_at
            <= self.permit_freshness.checked_at
            <= self.pre_attempt_freshness.checked_at
            <= self.pre_account_identity.checked_at
            <= self.request.started_at
            <= received_at
            <= recorded_at
            <= self.post_fence_receipt.validated_at
            <= self.post_attempt_freshness.checked_at
            <= self.post_account_identity.checked_at
            == self.authenticated_at
        ):
            raise AlpacaPaperLookupConflict(
                "authenticated lookup evidence has conflicting trusted-time order"
            )
        if (
            not self.credential_receipt.is_fresh(self.request.started_at)
            or not self.credential_receipt.is_fresh(received_at)
            or not self.permit.is_fresh(self.request.started_at)
            or not self.permit.is_fresh(received_at)
            or not (
                self.pre_fence_receipt.validated_at
                <= self.request.started_at
                < self.pre_fence_receipt.valid_until
            )
            or received_at >= self.pre_fence_receipt.valid_until
            or self.authenticated_at >= self.post_fence_receipt.valid_until
        ):
            raise AlpacaPaperLookupConflict(
                "authenticated lookup authority expired during transport"
            )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
                "authenticated_lookup_evidence",
                self.security_reference.semantic_sha256,
                self.credential_receipt.semantic_sha256,
                self.attempt.semantic_sha256,
                self.pre_attempt_freshness.semantic_sha256,
                self.account_binding.semantic_sha256,
                self.pre_account_identity.semantic_sha256,
                self.description.semantic_sha256,
                self.policy.semantic_sha256,
                self.demand.semantic_sha256,
                self.permit.semantic_sha256,
                self.permit_freshness.semantic_sha256,
                self.pre_fence_receipt.semantic_sha256,
                self.request.semantic_sha256,
                self.response.semantic_sha256,
                self.persisted_observation.receipt.semantic_sha256,
                self.persisted_observation.observation.semantic_sha256,
                self.post_fence_receipt.semantic_sha256,
                self.post_attempt_freshness.semantic_sha256,
                self.post_account_identity.semantic_sha256,
                self.outcome,
                self.authenticated_at,
            )
        )

    @property
    def reconciliation_required(self) -> bool:
        return True

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _authenticated_lookup_evidence(
    *,
    security_reference: AlpacaPaperSecurityReference,
    credential_receipt: AlpacaPaperCredentialResolutionReceipt,
    attempt: CanonicalSubmissionAttempt,
    pre_attempt_freshness: AlpacaPaperUnknownAttemptFreshnessReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    description: AlpacaClientOrderLookupDescription,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    permit_freshness: BrokerRequestPermitFreshnessReceipt,
    pre_fence_receipt: AccountFenceReceipt,
    request: AlpacaPaperLookupTransportRequest,
    response: AlpacaPaperLookupTransportResponse,
    persisted_observation: PersistedAlpacaClientOrderLookupObservation,
    post_fence_receipt: AccountFenceReceipt,
    post_attempt_freshness: AlpacaPaperUnknownAttemptFreshnessReceipt,
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
) -> AlpacaPaperAuthenticatedLookupEvidence:
    evidence = object.__new__(AlpacaPaperAuthenticatedLookupEvidence)
    values = (
        ("security_reference", security_reference),
        ("credential_receipt", credential_receipt),
        ("attempt", attempt),
        ("pre_attempt_freshness", pre_attempt_freshness),
        ("account_binding", account_binding),
        ("pre_account_identity", pre_account_identity),
        ("description", description),
        ("policy", policy),
        ("demand", demand),
        ("permit", permit),
        ("permit_freshness", permit_freshness),
        ("pre_fence_receipt", pre_fence_receipt),
        ("request", request),
        ("response", response),
        ("persisted_observation", persisted_observation),
        ("post_fence_receipt", post_fence_receipt),
        ("post_attempt_freshness", post_attempt_freshness),
        ("post_account_identity", post_account_identity),
        (
            "outcome",
            _lookup_outcome(
                persisted_observation.observation,
                security_reference,
            ),
        ),
        ("authenticated_at", post_account_identity.checked_at),
    )
    for field_name, value in values:
        object.__setattr__(evidence, field_name, value)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedLookupReceipt:
    """Append-only scalar receipt suitable for durable Phase 4I persistence."""

    account_id: str
    provider_id: str
    environment: str
    attempt_id: str
    attempt_sha256: str
    terminal_event_id: str
    terminal_event_sha256: str
    terminal_event_sequence: int
    parent_decision_id: str
    reservation_id: str
    order_id: str
    client_order_id: str
    instrument_id: str
    symbol: str
    expected_provider_account_id: str
    expected_provider_asset_id: str
    outcome: AlpacaPaperAuthenticatedLookupOutcome
    provider_order_id: str | None
    provider_order_status: str | None
    observed_provider_asset_id: str | None
    mismatch_fields: tuple[str, ...]
    secret_ref: str
    secret_version: str
    credential_reference_sha256: str
    security_reference_sha256: str
    credential_resolution_sha256: str
    resolver_id: str
    resolver_version: str
    capability_sha256: str
    account_binding_id: str
    account_binding_sha256: str
    pre_attempt_freshness_sha256: str
    post_attempt_freshness_sha256: str
    pre_account_identity_sha256: str
    post_account_identity_sha256: str
    description_sha256: str
    submission_sha256: str
    policy_sha256: str
    demand_id: str
    demand_sha256: str
    permit_id: str
    permit_sha256: str
    permit_freshness_sha256: str
    fence_owner_id: str
    fence_lease_id: str
    fence_fencing_generation: int
    fence_sha256: str
    fence_policy_sha256: str
    pre_fence_lease_sha256: str
    post_fence_lease_sha256: str
    pre_fence_receipt_sha256: str
    post_fence_receipt_sha256: str
    ingress_receipt_id: str
    ingress_receipt_sha256: str
    observation_sha256: str
    transport_request_sha256: str
    transport_response_sha256: str
    http_status: int
    provider_request_id: str
    requested_at: datetime
    credential_resolution_started_at: datetime
    resolved_at: datetime
    credential_resolution_valid_until: datetime
    permit_checked_at: datetime
    pre_fence_validated_at: datetime
    pre_fence_valid_until: datetime
    pre_attempt_checked_at: datetime
    pre_account_identity_checked_at: datetime
    request_started_at: datetime
    received_at: datetime
    raw_recorded_at: datetime
    post_fence_validated_at: datetime
    post_fence_valid_until: datetime
    post_attempt_checked_at: datetime
    post_account_identity_checked_at: datetime
    authenticated_at: datetime
    commit_checked_at: datetime
    sequence_number: int
    previous_receipt_sha256: str | None
    evidence_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedLookupReceipt must be recorder-produced")

    def _validate(self) -> None:
        for value, field_name in (
            (self.account_id, "lookup receipt account ID"),
            (self.attempt_id, "lookup receipt attempt ID"),
            (self.terminal_event_id, "lookup receipt terminal event ID"),
            (self.parent_decision_id, "lookup receipt parent decision ID"),
            (self.reservation_id, "lookup receipt reservation ID"),
            (self.order_id, "lookup receipt order ID"),
            (self.client_order_id, "lookup receipt client order ID"),
            (self.instrument_id, "lookup receipt instrument ID"),
            (self.symbol, "lookup receipt symbol"),
            (self.secret_ref, "lookup receipt secret reference"),
            (self.secret_version, "lookup receipt secret version"),
            (self.provider_request_id, "lookup receipt provider request ID"),
            (self.fence_owner_id, "lookup receipt fence owner ID"),
            (self.fence_lease_id, "lookup receipt fence lease ID"),
        ):
            _require_text(value, field_name, maximum=256)
        if self.provider_id != ALPACA_PAPER_ADAPTER_ID or self.environment != "paper":
            raise AlpacaPaperLookupConflict(
                "authenticated lookup receipt must remain Alpaca paper scoped"
            )
        if type(self.outcome) is not AlpacaPaperAuthenticatedLookupOutcome:
            raise AlpacaPaperLookupConflict("lookup receipt outcome is unsupported")
        for optional_value, field_name in (
            (self.provider_order_id, "provider order ID"),
            (self.provider_order_status, "provider order status"),
            (self.observed_provider_asset_id, "observed provider asset ID"),
        ):
            if optional_value is not None:
                _require_text(optional_value, f"lookup receipt {field_name}")
        if (
            type(self.mismatch_fields) is not tuple
            or len(set(self.mismatch_fields)) != len(self.mismatch_fields)
            or any(type(value) is not str for value in self.mismatch_fields)
        ):
            raise AlpacaPaperLookupConflict("lookup receipt mismatch fields must be a unique tuple")
        for digest, field_name in (
            (self.attempt_sha256, "attempt"),
            (self.terminal_event_sha256, "terminal event"),
            (self.credential_reference_sha256, "credential reference"),
            (self.security_reference_sha256, "security reference"),
            (self.credential_resolution_sha256, "credential resolution"),
            (self.capability_sha256, "capability"),
            (self.account_binding_sha256, "account binding"),
            (self.pre_attempt_freshness_sha256, "pre UNKNOWN freshness"),
            (self.post_attempt_freshness_sha256, "post UNKNOWN freshness"),
            (
                self.pre_account_identity_sha256,
                "pre account identity continuity",
            ),
            (
                self.post_account_identity_sha256,
                "post account identity continuity",
            ),
            (self.description_sha256, "description"),
            (self.submission_sha256, "submission"),
            (self.policy_sha256, "policy"),
            (self.demand_id, "demand ID"),
            (self.demand_sha256, "demand"),
            (self.permit_id, "permit ID"),
            (self.permit_sha256, "permit"),
            (self.permit_freshness_sha256, "permit freshness"),
            (self.fence_sha256, "fence"),
            (self.fence_policy_sha256, "fence policy"),
            (self.pre_fence_lease_sha256, "pre fence lease"),
            (self.post_fence_lease_sha256, "post fence lease"),
            (self.pre_fence_receipt_sha256, "pre fence"),
            (self.post_fence_receipt_sha256, "post fence"),
            (self.ingress_receipt_id, "ingress receipt ID"),
            (self.ingress_receipt_sha256, "ingress receipt"),
            (self.observation_sha256, "observation"),
            (self.transport_request_sha256, "transport request"),
            (self.transport_response_sha256, "transport response"),
            (self.evidence_sha256, "evidence"),
        ):
            _require_sha256(digest, f"lookup receipt {field_name} digest")
        _require_text(
            self.expected_provider_account_id,
            "lookup receipt provider account ID",
            maximum=36,
        )
        _require_text(
            self.expected_provider_asset_id,
            "lookup receipt provider asset ID",
            maximum=36,
        )
        _require_text(
            self.account_binding_id,
            "lookup receipt account binding ID",
            maximum=36,
        )
        _require_safe_text(self.resolver_id, "lookup receipt resolver ID")
        _require_safe_text(self.resolver_version, "lookup receipt resolver version")
        if (
            type(self.terminal_event_sequence) is not int
            or self.terminal_event_sequence <= 0
            or type(self.fence_fencing_generation) is not int
            or self.fence_fencing_generation <= 0
            or type(self.sequence_number) is not int
            or self.sequence_number <= 0
            or (self.sequence_number == 1 and self.previous_receipt_sha256 is not None)
            or (self.sequence_number > 1 and self.previous_receipt_sha256 is None)
        ):
            raise AlpacaPaperLookupConflict(
                "lookup receipt sequence or predecessor shape is invalid"
            )
        _require_optional_sha256(
            self.previous_receipt_sha256,
            "lookup receipt predecessor digest",
        )
        if self.http_status not in (200, 404):
            raise AlpacaPaperLookupConflict(
                "lookup receipt supports only historical 200 or 404 outcomes"
            )
        timestamps = (
            (self.requested_at, "requested_at"),
            (
                self.credential_resolution_started_at,
                "credential_resolution_started_at",
            ),
            (self.resolved_at, "resolved_at"),
            (
                self.credential_resolution_valid_until,
                "credential_resolution_valid_until",
            ),
            (self.pre_fence_validated_at, "pre_fence_validated_at"),
            (self.pre_fence_valid_until, "pre_fence_valid_until"),
            (self.permit_checked_at, "permit_checked_at"),
            (self.pre_attempt_checked_at, "pre_attempt_checked_at"),
            (
                self.pre_account_identity_checked_at,
                "pre_account_identity_checked_at",
            ),
            (self.request_started_at, "request_started_at"),
            (self.received_at, "received_at"),
            (self.raw_recorded_at, "raw_recorded_at"),
            (self.post_fence_validated_at, "post_fence_validated_at"),
            (self.post_fence_valid_until, "post_fence_valid_until"),
            (self.post_attempt_checked_at, "post_attempt_checked_at"),
            (
                self.post_account_identity_checked_at,
                "post_account_identity_checked_at",
            ),
            (self.authenticated_at, "authenticated_at"),
            (self.commit_checked_at, "commit_checked_at"),
        )
        for timestamp, timestamp_field_name in timestamps:
            _require_utc(timestamp, f"lookup receipt {timestamp_field_name}")
        if not (
            self.requested_at
            <= self.credential_resolution_started_at
            <= self.resolved_at
            <= self.pre_fence_validated_at
            <= self.permit_checked_at
            <= self.pre_attempt_checked_at
            <= self.pre_account_identity_checked_at
            <= self.request_started_at
            <= self.received_at
            <= self.raw_recorded_at
            <= self.post_fence_validated_at
            <= self.post_attempt_checked_at
            <= self.post_account_identity_checked_at
            == self.authenticated_at
            <= self.commit_checked_at
        ):
            raise AlpacaPaperLookupConflict("lookup receipt has conflicting trusted-time order")
        if (
            self.resolved_at >= self.credential_resolution_valid_until
            or self.request_started_at >= self.credential_resolution_valid_until
            or self.received_at >= self.credential_resolution_valid_until
            or self.commit_checked_at >= self.post_fence_valid_until
            or self.pre_fence_validated_at >= self.pre_fence_valid_until
            or self.received_at >= self.pre_fence_valid_until
            or self.post_fence_validated_at >= self.post_fence_valid_until
        ):
            raise AlpacaPaperLookupConflict(
                "lookup receipt fence validity does not cover authentication"
            )
        if self.capability_sha256 != ALPACA_PAPER_CAPABILITIES.semantic_sha256:
            raise AlpacaPaperLookupConflict("lookup receipt capability digest is not current")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
            "authenticated_lookup_receipt",
            self.account_id,
            self.provider_id,
            self.environment,
            self.attempt_id,
            self.attempt_sha256,
            self.terminal_event_id,
            self.terminal_event_sha256,
            self.terminal_event_sequence,
            self.parent_decision_id,
            self.reservation_id,
            self.order_id,
            self.client_order_id,
            self.instrument_id,
            self.symbol,
            self.expected_provider_account_id,
            self.expected_provider_asset_id,
            self.outcome,
            self.provider_order_id,
            self.provider_order_status,
            self.observed_provider_asset_id,
            self.mismatch_fields,
            self.secret_ref,
            self.secret_version,
            self.credential_reference_sha256,
            self.security_reference_sha256,
            self.credential_resolution_sha256,
            self.resolver_id,
            self.resolver_version,
            self.capability_sha256,
            self.account_binding_id,
            self.account_binding_sha256,
            self.pre_attempt_freshness_sha256,
            self.post_attempt_freshness_sha256,
            self.pre_account_identity_sha256,
            self.post_account_identity_sha256,
            self.description_sha256,
            self.submission_sha256,
            self.policy_sha256,
            self.demand_id,
            self.demand_sha256,
            self.permit_id,
            self.permit_sha256,
            self.permit_freshness_sha256,
            self.fence_owner_id,
            self.fence_lease_id,
            self.fence_fencing_generation,
            self.fence_sha256,
            self.fence_policy_sha256,
            self.pre_fence_lease_sha256,
            self.post_fence_lease_sha256,
            self.pre_fence_receipt_sha256,
            self.post_fence_receipt_sha256,
            self.ingress_receipt_id,
            self.ingress_receipt_sha256,
            self.observation_sha256,
            self.transport_request_sha256,
            self.transport_response_sha256,
            self.http_status,
            self.provider_request_id,
            self.requested_at,
            self.credential_resolution_started_at,
            self.resolved_at,
            self.credential_resolution_valid_until,
            self.permit_checked_at,
            self.pre_fence_validated_at,
            self.pre_fence_valid_until,
            self.pre_attempt_checked_at,
            self.pre_account_identity_checked_at,
            self.request_started_at,
            self.received_at,
            self.raw_recorded_at,
            self.post_fence_validated_at,
            self.post_fence_valid_until,
            self.post_attempt_checked_at,
            self.post_account_identity_checked_at,
            self.authenticated_at,
            self.commit_checked_at,
            self.sequence_number,
            self.previous_receipt_sha256,
            self.evidence_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-unknown-lookup",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def raw_response_persisted(self) -> bool:
        return True

    @property
    def authenticated_lookup_established(self) -> bool:
        return True

    @property
    def reconciliation_required(self) -> bool:
        return True

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def retry_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _alpaca_paper_authenticated_lookup_receipt(
    evidence: AlpacaPaperAuthenticatedLookupEvidence,
    *,
    commit_checked_at: datetime,
    sequence_number: int,
    previous_receipt_sha256: str | None,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    """Construct the scalar receipt a durable recorder must append."""

    if type(evidence) is not AlpacaPaperAuthenticatedLookupEvidence:
        raise AlpacaPaperLookupConflict("lookup receipt requires exact authenticated evidence")
    evidence._validate()
    _require_utc(commit_checked_at, "lookup receipt commit_checked_at")
    attempt = evidence.attempt
    event = attempt.events[-1]
    observation = evidence.persisted_observation.observation
    raw_receipt = evidence.persisted_observation.receipt
    order = observation.order
    credential_reference = evidence.security_reference.credential_reference
    values = (
        ("account_id", attempt.preparation.account_id),
        ("provider_id", ALPACA_PAPER_ADAPTER_ID),
        ("environment", "paper"),
        ("attempt_id", attempt.attempt_id),
        ("attempt_sha256", attempt.semantic_sha256),
        ("terminal_event_id", event.event_id),
        ("terminal_event_sha256", event.semantic_sha256),
        ("terminal_event_sequence", event.sequence_number),
        ("parent_decision_id", attempt.parent_decision_id),
        ("reservation_id", attempt.preparation.reservation_id),
        ("order_id", attempt.preparation.order_id),
        ("client_order_id", attempt.preparation.client_order_id),
        ("instrument_id", evidence.security_reference.instrument_id),
        ("symbol", evidence.security_reference.symbol),
        (
            "expected_provider_account_id",
            credential_reference.expected_provider_account_id,
        ),
        (
            "expected_provider_asset_id",
            evidence.security_reference.expected_provider_asset_id,
        ),
        ("outcome", evidence.outcome),
        ("provider_order_id", None if order is None else order.provider_order_id),
        (
            "provider_order_status",
            None if order is None else order.status.value,
        ),
        ("observed_provider_asset_id", None if order is None else order.asset_id),
        ("mismatch_fields", observation.mismatch_fields),
        ("secret_ref", credential_reference.secret_ref),
        ("secret_version", credential_reference.secret_version),
        (
            "credential_reference_sha256",
            credential_reference.semantic_sha256,
        ),
        (
            "security_reference_sha256",
            evidence.security_reference.semantic_sha256,
        ),
        (
            "credential_resolution_sha256",
            evidence.credential_receipt.semantic_sha256,
        ),
        ("resolver_id", evidence.credential_receipt.resolver_id),
        ("resolver_version", evidence.credential_receipt.resolver_version),
        ("capability_sha256", ALPACA_PAPER_CAPABILITIES.semantic_sha256),
        ("account_binding_id", evidence.account_binding.binding_id),
        ("account_binding_sha256", evidence.account_binding.semantic_sha256),
        (
            "pre_attempt_freshness_sha256",
            evidence.pre_attempt_freshness.semantic_sha256,
        ),
        (
            "post_attempt_freshness_sha256",
            evidence.post_attempt_freshness.semantic_sha256,
        ),
        (
            "pre_account_identity_sha256",
            evidence.pre_account_identity.semantic_sha256,
        ),
        (
            "post_account_identity_sha256",
            evidence.post_account_identity.semantic_sha256,
        ),
        ("description_sha256", evidence.description.semantic_sha256),
        ("submission_sha256", evidence.description.submission.semantic_sha256),
        ("policy_sha256", evidence.policy.semantic_sha256),
        ("demand_id", evidence.demand.demand_id),
        ("demand_sha256", evidence.demand.semantic_sha256),
        ("permit_id", evidence.permit.permit_id),
        ("permit_sha256", evidence.permit.semantic_sha256),
        (
            "permit_freshness_sha256",
            evidence.permit_freshness.semantic_sha256,
        ),
        ("fence_owner_id", evidence.pre_fence_receipt.fence.owner_id),
        ("fence_lease_id", evidence.pre_fence_receipt.fence.lease_id),
        (
            "fence_fencing_generation",
            evidence.pre_fence_receipt.fence.fencing_generation,
        ),
        ("fence_sha256", evidence.pre_fence_receipt.fence.semantic_sha256),
        ("fence_policy_sha256", evidence.pre_fence_receipt.policy_sha256),
        (
            "pre_fence_lease_sha256",
            evidence.pre_fence_receipt.lease_sha256,
        ),
        (
            "post_fence_lease_sha256",
            evidence.post_fence_receipt.lease_sha256,
        ),
        (
            "pre_fence_receipt_sha256",
            evidence.pre_fence_receipt.semantic_sha256,
        ),
        (
            "post_fence_receipt_sha256",
            evidence.post_fence_receipt.semantic_sha256,
        ),
        ("ingress_receipt_id", raw_receipt.receipt_id),
        ("ingress_receipt_sha256", raw_receipt.semantic_sha256),
        ("observation_sha256", observation.semantic_sha256),
        ("transport_request_sha256", evidence.request.semantic_sha256),
        ("transport_response_sha256", evidence.response.semantic_sha256),
        ("http_status", observation.http_status),
        ("provider_request_id", observation.provider_request_id),
        ("requested_at", evidence.demand.requested_at),
        (
            "credential_resolution_started_at",
            evidence.credential_receipt.started_at,
        ),
        ("resolved_at", evidence.credential_receipt.resolved_at),
        (
            "credential_resolution_valid_until",
            evidence.credential_receipt.valid_until,
        ),
        ("permit_checked_at", evidence.permit_freshness.checked_at),
        (
            "pre_fence_validated_at",
            evidence.pre_fence_receipt.validated_at,
        ),
        (
            "pre_fence_valid_until",
            evidence.pre_fence_receipt.valid_until,
        ),
        (
            "pre_attempt_checked_at",
            evidence.pre_attempt_freshness.checked_at,
        ),
        (
            "pre_account_identity_checked_at",
            evidence.pre_account_identity.checked_at,
        ),
        ("request_started_at", evidence.request.started_at),
        ("received_at", observation.received_at),
        ("raw_recorded_at", raw_receipt.delivery.recorded_at),
        (
            "post_fence_validated_at",
            evidence.post_fence_receipt.validated_at,
        ),
        (
            "post_fence_valid_until",
            evidence.post_fence_receipt.valid_until,
        ),
        (
            "post_attempt_checked_at",
            evidence.post_attempt_freshness.checked_at,
        ),
        (
            "post_account_identity_checked_at",
            evidence.post_account_identity.checked_at,
        ),
        ("authenticated_at", evidence.authenticated_at),
        ("commit_checked_at", commit_checked_at),
        ("sequence_number", sequence_number),
        ("previous_receipt_sha256", previous_receipt_sha256),
        ("evidence_sha256", evidence.semantic_sha256),
    )
    receipt = object.__new__(AlpacaPaperAuthenticatedLookupReceipt)
    for field_name, value in values:
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


class AlpacaPaperLookupRecorder(Protocol):
    """Durable append-only recorder for authenticated lookup evidence."""

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedLookupEvidence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt: ...


def _observe_authenticated_alpaca_paper_unknown_lookup_with_transport(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaClientOrderLookupDescription,
    credential_resolver: AlpacaPaperLookupCredentialResolver,
    transport: _AlpacaPaperLookupTransport,
    budget: BrokerRequestBudgetRuntimePort,
    unknown_attempts: AlpacaPaperUnknownAttemptRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    lookup_recorder: AlpacaPaperLookupRecorder,
    clock: Clock,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    """Trusted internal seam for deterministic transport-contract testing."""

    _require_text(
        delivery_idempotency_key,
        "lookup delivery idempotency key",
        maximum=128,
    )
    _validate_lookup_sources(
        security_reference=security_reference,
        account_binding=account_binding,
        attempt=attempt,
        description=description,
    )
    if type(fence) is not AccountFence or fence.account_id != attempt.preparation.account_id:
        raise AlpacaPaperLookupConflict("lookup requires the current exact account fence")
    for port, method_name, field_name in (
        (budget, "issue_new", "durable new-permit issuer"),
        (budget, "authenticate_fresh", "durable budget authenticator"),
        (
            unknown_attempts,
            "authenticate_terminal_unknown",
            "terminal UNKNOWN authenticator",
        ),
        (
            account_bindings,
            "authenticate_terminal_identity",
            "terminal account-identity authenticator",
        ),
        (coordinator, "revalidate", "account coordinator"),
        (ingress_recorder, "record", "raw ingress recorder"),
        (lookup_recorder, "record", "lookup evidence recorder"),
        (transport, "execute", "restricted lookup transport"),
    ):
        if not callable(getattr(port, method_name, None)):
            raise AlpacaPaperLookupRuntimeError(f"lookup runtime requires a {field_name}")
    if getattr(coordinator, "account_id", None) != attempt.preparation.account_id:
        raise AlpacaPaperLookupConflict("lookup account coordinator belongs to another account")
    if (
        getattr(transport, "transport_id", None) != ALPACA_PAPER_LOOKUP_TRANSPORT_ID
        or getattr(transport, "transport_version", None) != ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION
    ):
        raise AlpacaPaperLookupTransportError(
            "lookup runtime requires the exact restricted transport profile"
        )

    requested_at = _trusted_now(clock, "lookup requested_at")
    demand = create_alpaca_paper_unknown_lookup_demand(
        security_reference=security_reference,
        account_binding=account_binding,
        attempt=attempt,
        description=description,
        idempotency_key=request_idempotency_key,
        requested_at=requested_at,
    )
    credential_session = _resolve_alpaca_paper_credentials_for_operation(
        reference=security_reference.credential_reference,
        resolver=credential_resolver,
        resolver_method_name="_resolve_for_client_order_lookup",
        clock=clock,
    )
    try:
        permit = budget.issue_new(
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        if type(permit) is not BrokerRequestPermit:
            raise AlpacaPaperLookupRuntimeError(
                "durable budget issuer returned an invalid lookup permit"
            )
        pre_fence_receipt = coordinator.revalidate(fence)
        if type(pre_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperLookupRuntimeError(
                "account coordinator returned an invalid pre-lookup receipt"
            )
        pre_fence_receipt._validate()
        if pre_fence_receipt.fence != fence:
            raise AlpacaPaperLookupConflict(
                "account coordinator returned a receipt for another pre-lookup fence"
            )
        permit_freshness = budget.authenticate_fresh(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        if type(permit_freshness) is not BrokerRequestPermitFreshnessReceipt:
            raise AlpacaPaperLookupRuntimeError(
                "budget authenticator returned invalid lookup freshness"
            )
        permit_freshness._validate()
        try:
            require_fresh_broker_request_permit(
                permit=permit,
                policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
                demand=demand,
                checked_at=permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperLookupConflict(
                "durable UNKNOWN lookup permit is invalid before transport"
            ) from error
        pre_attempt_checked_at = _trusted_now(
            clock,
            "pre-lookup UNKNOWN checked_at",
        )
        pre_attempt_freshness = _authenticate_unknown(
            unknown_attempts,
            attempt,
            checked_at=pre_attempt_checked_at,
            phase="before",
        )
        pre_account_checked_at = _trusted_now(
            clock,
            "pre-lookup account-binding checked_at",
        )
        pre_account_identity = _authenticate_account_binding(
            account_bindings,
            account_binding,
            checked_at=pre_account_checked_at,
            phase="before",
        )
        started_at = _trusted_now(clock, "lookup transport started_at")
        if permit_freshness.checked_at > started_at or not permit.is_fresh(started_at):
            raise AlpacaPaperLookupConflict(
                "durable request permit is not current at lookup transport start"
            )
        if not (pre_fence_receipt.validated_at <= started_at < pre_fence_receipt.valid_until):
            raise AlpacaPaperLookupConflict(
                "account fence is not current at lookup transport start"
            )
        request = AlpacaPaperLookupTransportRequest(
            description=description,
            credential_reference_sha256=(security_reference.credential_reference.semantic_sha256),
            security_reference_sha256=security_reference.semantic_sha256,
            attempt_sha256=attempt.semantic_sha256,
            unknown_attempt_freshness_sha256=(pre_attempt_freshness.semantic_sha256),
            account_binding_sha256=account_binding.semantic_sha256,
            account_identity_sha256=pre_account_identity.semantic_sha256,
            demand_sha256=demand.semantic_sha256,
            permit_sha256=permit.semantic_sha256,
            permit_freshness_sha256=permit_freshness.semantic_sha256,
            fence_receipt_sha256=pre_fence_receipt.semantic_sha256,
            started_at=started_at,
        )
        headers = credential_session.authentication_headers(checked_at=started_at)
        response: object | None = None
        transport_failed = False
        try:
            response = transport.execute(request, headers)
        except Exception:
            transport_failed = True
        if transport_failed:
            raise AlpacaPaperLookupTransportError(
                "restricted lookup transport failed with sanitized diagnostics"
            ) from None
        received_at = _trusted_now(clock, "lookup transport received_at")
    finally:
        credential_session.close()

    if type(response) is not AlpacaPaperLookupTransportResponse:
        raise AlpacaPaperLookupTransportError("lookup transport returned an invalid response")
    response.__post_init__()
    if response.request_sha256 != request.semantic_sha256:
        raise AlpacaPaperLookupTransportError(
            "lookup transport returned a response for another request"
        )
    if received_at < started_at:
        raise AlpacaPaperLookupRuntimeError("lookup transport clock regressed")
    recorded_at = _trusted_now(clock, "lookup raw response recorded_at")
    if recorded_at < received_at:
        raise AlpacaPaperLookupRuntimeError("lookup raw-record clock regressed")
    persisted_observation = _persist_then_decode_lookup(
        ingress_recorder,
        description,
        delivery_idempotency_key=delivery_idempotency_key,
        response=response,
        received_at=received_at,
        recorded_at=recorded_at,
    )
    post_fence_receipt = coordinator.revalidate(fence)
    if type(post_fence_receipt) is not AccountFenceReceipt:
        raise AlpacaPaperLookupRuntimeError(
            "account coordinator returned an invalid post-lookup receipt"
        )
    post_fence_receipt._validate()
    if post_fence_receipt.fence != fence:
        raise AlpacaPaperLookupConflict("account fence changed during authenticated lookup")
    post_attempt_checked_at = _trusted_now(
        clock,
        "post-lookup UNKNOWN checked_at",
    )
    post_attempt_freshness = _authenticate_unknown(
        unknown_attempts,
        attempt,
        checked_at=post_attempt_checked_at,
        phase="after",
    )
    post_account_checked_at = _trusted_now(
        clock,
        "post-lookup account-binding checked_at",
    )
    post_account_identity = _authenticate_account_binding(
        account_bindings,
        account_binding,
        checked_at=post_account_checked_at,
        phase="after",
    )
    evidence = _authenticated_lookup_evidence(
        security_reference=security_reference,
        credential_receipt=credential_session.receipt,
        attempt=attempt,
        pre_attempt_freshness=pre_attempt_freshness,
        account_binding=account_binding,
        pre_account_identity=pre_account_identity,
        description=description,
        policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
        demand=demand,
        permit=permit,
        permit_freshness=permit_freshness,
        pre_fence_receipt=pre_fence_receipt,
        request=request,
        response=response,
        persisted_observation=persisted_observation,
        post_fence_receipt=post_fence_receipt,
        post_attempt_freshness=post_attempt_freshness,
        post_account_identity=post_account_identity,
    )
    receipt = lookup_recorder.record(evidence)
    if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
        raise AlpacaPaperLookupRuntimeError("lookup recorder returned an invalid durable receipt")
    receipt._validate()
    if receipt.evidence_sha256 != evidence.semantic_sha256:
        raise AlpacaPaperLookupConflict(
            "durable lookup receipt does not bind the exact runtime evidence"
        )
    expected_receipt = _alpaca_paper_authenticated_lookup_receipt(
        evidence,
        commit_checked_at=receipt.commit_checked_at,
        sequence_number=receipt.sequence_number,
        previous_receipt_sha256=receipt.previous_receipt_sha256,
    )
    if receipt != expected_receipt:
        raise AlpacaPaperLookupConflict(
            "durable lookup receipt conflicts with the exact runtime evidence"
        )
    return receipt


def observe_authenticated_alpaca_paper_unknown_lookup(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaClientOrderLookupDescription,
    credential_resolver: AlpacaPaperLookupCredentialResolver,
    budget: BrokerRequestBudgetRuntimePort,
    unknown_attempts: AlpacaPaperUnknownAttemptRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    lookup_recorder: AlpacaPaperLookupRecorder,
    clock: Clock,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    """Execute the exact production lookup and persist non-authorizing evidence."""

    return _observe_authenticated_alpaca_paper_unknown_lookup_with_transport(
        security_reference=security_reference,
        account_binding=account_binding,
        attempt=attempt,
        description=description,
        credential_resolver=credential_resolver,
        transport=_HttpxAlpacaPaperLookupTransport(),
        budget=budget,
        unknown_attempts=unknown_attempts,
        account_bindings=account_bindings,
        coordinator=coordinator,
        fence=fence,
        ingress_recorder=ingress_recorder,
        lookup_recorder=lookup_recorder,
        clock=clock,
        request_idempotency_key=request_idempotency_key,
        delivery_idempotency_key=delivery_idempotency_key,
    )


__all__ = [
    "ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE",
    "ALPACA_PAPER_LOOKUP_HTTPX_PHASE_TIMEOUT",
    "ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_LOOKUP_TRANSPORT_ID",
    "ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION",
    "ALPACA_PAPER_UNKNOWN_ATTEMPT_FRESHNESS_CONTRACT_VERSION",
    "AlpacaPaperAuthenticatedLookupEvidence",
    "AlpacaPaperAuthenticatedLookupOutcome",
    "AlpacaPaperAuthenticatedLookupReceipt",
    "AlpacaPaperLookupConflict",
    "AlpacaPaperLookupCredentialResolver",
    "AlpacaPaperLookupRecorder",
    "AlpacaPaperLookupRuntimeError",
    "AlpacaPaperLookupTransportError",
    "AlpacaPaperLookupTransportRequest",
    "AlpacaPaperLookupTransportResponse",
    "AlpacaPaperUnknownAttemptFreshnessReceipt",
    "AlpacaPaperUnknownAttemptRuntimePort",
    "alpaca_paper_unknown_lookup_correlation_sha256",
    "create_alpaca_paper_unknown_lookup_demand",
    "observe_authenticated_alpaca_paper_unknown_lookup",
]
