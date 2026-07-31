"""Authenticated one-page runtime for Alpaca paper account activities.

Phase 4AE advances exactly one page of the bounded Phase 4AD ascending FILL
traversal.  The exact cursor and predecessor are durably claimed before secret
resolution or request admission, response bytes are retained before decoding,
and one stable account fence and terminal Phase 4G provider-account binding
are authenticated around transport and commit.

A failed call after preparation remains a visible single-use stall.  No retry,
execution, revision, deduplication, application, readiness, or trading
authority is inferred from the historical page evidence.
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
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_account_activities import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES,
    AlpacaPaperAccountActivityCapture,
    AlpacaPaperAccountActivityPageDescription,
    AlpacaPaperAccountActivityPlan,
    PersistedAlpacaPaperAccountActivityPage,
    append_alpaca_paper_account_activity_page,
    create_alpaca_paper_account_activity_page_demand,
    persist_then_decode_alpaca_paper_account_activity_page,
    start_alpaca_paper_account_activity_capture,
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
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorPort,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.broker_ingress import BrokerIngressRecorder
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

ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION = (
    "phase4ae-authenticated-durable-account-activity-page-v1"
)
ALPACA_PAPER_ACCOUNT_ACTIVITY_HTTPX_PHASE_TIMEOUT = ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT
ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE = ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID = "strict-httpx-alpaca-paper-account-activity-page"
ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION = "1.0.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AlpacaPaperAccountActivityRuntimeError(AlpacaPaperContractError):
    """Authenticated account-activity runtime evidence is malformed."""


class AlpacaPaperAccountActivityTransportError(AlpacaPaperAccountActivityRuntimeError):
    """The exact restricted account-activity transport failed."""


class AlpacaPaperAccountActivityConflict(AlpacaPaperAccountActivityRuntimeError):
    """Account-activity evidence conflicts with durable authority."""


class AlpacaPaperAccountActivityTraversalStage(StrEnum):
    """Closed durable meanings for a Phase 4AE traversal head."""

    ABSENT = "absent"
    ACTIVE = "active"
    STALLED = "stalled"
    CURSOR_EXHAUSTED = "cursor_exhausted_unisolated"
    BOUNDED_TRUNCATED = "bounded_truncated"


class _NoAccountActivityRuntimeAuthority:
    __slots__ = ()

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def authenticated_account_activity_page_established(self) -> bool:
        return False

    @property
    def committed_prefix_established(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
        return False

    @property
    def activity_history_complete(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False

    @property
    def provider_execution_identity_qualified(self) -> bool:
        return False

    @property
    def canonical_execution_identity_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_revision_authorized(self) -> bool:
        return False

    @property
    def execution_application_authorized(self) -> bool:
        return False

    @property
    def correction_application_authorized(self) -> bool:
        return False

    @property
    def bust_application_authorized(self) -> bool:
        return False

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_complete(self) -> bool:
        return False

    @property
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def activity_snapshot_pagination_ready(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def transport_submission_ready(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum: int = 128,
) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperAccountActivityRuntimeError(
            f"{field_name} must be bounded, non-empty trimmed text"
        )
    return value


def _require_safe_text(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if _SAFE_TEXT.fullmatch(text) is None:
        raise AlpacaPaperAccountActivityRuntimeError(f"{field_name} is not canonical safe text")
    return text


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAccountActivityRuntimeError(f"{field_name} must be a lowercase SHA-256")
    return value


def _require_optional_sha256(
    value: object,
    field_name: str,
) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAccountActivityRuntimeError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAccountActivityRuntimeError(str(error)) from error
    return value


def _trusted_now(clock: Clock, field_name: str) -> datetime:
    now = getattr(clock, "now", None)
    if not callable(now):
        raise AlpacaPaperAccountActivityRuntimeError(
            "account-activity runtime requires a trusted clock"
        )
    try:
        instant = now()
    except Exception:
        raise AlpacaPaperAccountActivityRuntimeError(f"{field_name} clock failed") from None
    return _require_utc(instant, field_name)


def _bounded_transport_metadata(
    value: object,
    *,
    maximum: int,
) -> str | None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    return value


def _runtime_store_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            f"{field_name} durable-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise AlpacaPaperAccountActivityConflict(f"{field_name} durable-store identity is invalid")
    return identity


def _validate_runtime_store_composition(
    *,
    page_runtime: object,
    budget: object,
    account_bindings: object,
    coordinator: object,
    ingress_recorder: object,
) -> None:
    ports = (
        (page_runtime, "account-activity page runtime"),
        (budget, "request-budget runtime"),
        (account_bindings, "account-binding runtime"),
        (coordinator, "account coordinator"),
        (ingress_recorder, "raw ingress recorder"),
    )
    identities = tuple(_runtime_store_identity(port, field_name) for port, field_name in ports)
    if len(set(identities)) != 1:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity runtime ports do not share one durable store"
        )


def alpaca_paper_account_activity_page_delivery_idempotency_key(
    description: AlpacaPaperAccountActivityPageDescription,
) -> str:
    """Return the deterministic raw-delivery identity for one exact page."""

    if type(description) is not AlpacaPaperAccountActivityPageDescription:
        raise AlpacaPaperAccountActivityConflict(
            "delivery identity requires an exact account-activity page"
        )
    description.__post_init__()
    return f"account-activity:{description.plan.capture_id}:{description.page_number:02d}"


def _validate_reference_binding(
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
) -> None:
    if type(reference) is not AlpacaPaperCredentialReference:
        raise AlpacaPaperAccountActivityConflict(
            "account activity requires an exact credential reference"
        )
    if type(account_binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperAccountActivityConflict(
            "account activity requires an exact authenticated account binding"
        )
    try:
        reference.__post_init__()
        account_binding._validate()
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity credential or binding evidence is malformed"
        ) from None
    if (
        reference.account_id != account_binding.account_id
        or reference.provider_id != account_binding.provider_id
        or reference.environment != account_binding.environment
        or reference.expected_provider_account_id != account_binding.expected_provider_account_id
        or reference.secret_ref != account_binding.secret_ref
        or reference.secret_version != account_binding.secret_version
        or reference.semantic_sha256 != account_binding.credential_reference_sha256
    ):
        raise AlpacaPaperAccountActivityConflict(
            "credential reference conflicts with the authenticated account binding"
        )


def _validate_account_identity(
    identity: AlpacaPaperAccountIdentityContinuityReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    phase: str,
) -> None:
    if type(identity) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperAccountActivityConflict(
            f"{phase} account identity must be exact repository evidence"
        )
    try:
        identity._validate()
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            f"{phase} account identity evidence is malformed"
        ) from None
    if (
        identity.account_id != account_binding.account_id
        or identity.binding_id != account_binding.binding_id
        or identity.binding_sha256 != account_binding.semantic_sha256
        or identity.credential_reference_sha256 != account_binding.credential_reference_sha256
        or identity.expected_provider_account_id != account_binding.expected_provider_account_id
        or identity.sequence_number != account_binding.sequence_number
        or identity.binding_qualified_at != account_binding.qualified_at
    ):
        raise AlpacaPaperAccountActivityConflict(
            f"{phase} account identity conflicts with the terminal binding"
        )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountActivityPagePreparationReceipt(_NoAccountActivityRuntimeAuthority):
    """Repository proof that an exact cursor/predecessor is durably claimed."""

    description: AlpacaPaperAccountActivityPageDescription
    prefix_capture_sha256: str
    prefix_page_count: int
    previous_page_receipt_id: str | None
    previous_page_receipt_sha256: str | None
    prepared_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAccountActivityPagePreparationReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.description) is not AlpacaPaperAccountActivityPageDescription:
            raise AlpacaPaperAccountActivityConflict(
                "activity-page preparation requires an exact description"
            )
        self.description.__post_init__()
        _require_sha256(
            self.prefix_capture_sha256,
            "prepared account-activity prefix digest",
        )
        if (
            type(self.prefix_page_count) is not int
            or self.prefix_page_count != self.description.page_number - 1
        ):
            raise AlpacaPaperAccountActivityConflict(
                "activity-page preparation prefix count is not contiguous"
            )
        if self.description.page_number == 1:
            if (
                self.previous_page_receipt_id is not None
                or self.previous_page_receipt_sha256 is not None
            ):
                raise AlpacaPaperAccountActivityConflict(
                    "first activity-page preparation cannot name a predecessor"
                )
            empty = start_alpaca_paper_account_activity_capture(self.description.plan)
            if self.prefix_capture_sha256 != empty.semantic_sha256:
                raise AlpacaPaperAccountActivityConflict(
                    "first activity-page preparation conflicts with empty prefix"
                )
        else:
            _require_text(
                self.previous_page_receipt_id,
                "prepared activity-page predecessor receipt ID",
                maximum=64,
            )
            _require_sha256(
                self.previous_page_receipt_sha256,
                "prepared activity-page predecessor receipt digest",
            )
        _require_utc(self.prepared_at, "activity-page preparation prepared_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
            "account_activity_page_preparation",
            self.description.semantic_sha256,
            self.prefix_capture_sha256,
            self.prefix_page_count,
            self.previous_page_receipt_id,
            self.previous_page_receipt_sha256,
            self.prepared_at,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def preparation_id(self) -> str:
        return canonical_id(
            "alpaca-paper-account-activity-page-preparation",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def fresh_single_use_claim_established(self) -> bool:
        return True


def _alpaca_paper_account_activity_page_preparation_receipt(
    description: AlpacaPaperAccountActivityPageDescription,
    *,
    prefix_capture_sha256: str,
    prefix_page_count: int,
    previous_page_receipt_id: str | None,
    previous_page_receipt_sha256: str | None,
    prepared_at: datetime,
) -> AlpacaPaperAccountActivityPagePreparationReceipt:
    receipt = object.__new__(AlpacaPaperAccountActivityPagePreparationReceipt)
    for field_name, value in (
        ("description", description),
        ("prefix_capture_sha256", prefix_capture_sha256),
        ("prefix_page_count", prefix_page_count),
        ("previous_page_receipt_id", previous_page_receipt_id),
        ("previous_page_receipt_sha256", previous_page_receipt_sha256),
        ("prepared_at", prepared_at),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


class AlpacaPaperAccountActivityCredentialResolver(Protocol):
    """Secret-read authority restricted to one Phase 4AE page."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_account_activity_page(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountActivityTransportRequest(_NoAccountActivityRuntimeAuthority):
    """Secret-free description of one exact preauthorized page GET."""

    description: AlpacaPaperAccountActivityPageDescription
    credential_reference_sha256: str
    account_binding_sha256: str
    pre_account_identity_sha256: str
    preparation_sha256: str
    demand_sha256: str
    permit_sha256: str
    permit_freshness_sha256: str
    fence_receipt_sha256: str
    started_at: datetime
    httpx_phase_timeout: timedelta = ALPACA_PAPER_ACCOUNT_ACTIVITY_HTTPX_PHASE_TIMEOUT

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperAccountActivityPageDescription:
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity transport requires an exact page description"
            )
        self.description.__post_init__()
        for value, field_name in (
            (self.credential_reference_sha256, "credential reference"),
            (self.account_binding_sha256, "account binding"),
            (self.pre_account_identity_sha256, "pre-request account identity"),
            (self.preparation_sha256, "page preparation"),
            (self.demand_sha256, "request demand"),
            (self.permit_sha256, "request permit"),
            (self.permit_freshness_sha256, "permit freshness"),
            (self.fence_receipt_sha256, "fence receipt"),
        ):
            _require_sha256(
                value,
                f"account-activity transport {field_name} digest",
            )
        _require_utc(
            self.started_at,
            "account-activity transport started_at",
        )
        if (
            type(self.httpx_phase_timeout) is not timedelta
            or self.httpx_phase_timeout != ALPACA_PAPER_ACCOUNT_ACTIVITY_HTTPX_PHASE_TIMEOUT
        ):
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity transport must use the fixed I/O timeout"
            )
        expected_pairs = [
            "activity_types=FILL",
            "direction=asc",
            f"page_size={self.description.page_size}",
        ]
        if self.description.page_token is not None:
            expected_pairs.append(f"page_token={self.description.page_token}")
        if (
            self.description.method != "GET"
            or self.description.base_url != ALPACA_PAPER_TRADING_BASE_URL
            or self.description.path != ALPACA_PAPER_CAPABILITIES.account_activities_path
            or self.description.request_target
            != f"{self.description.path}?{'&'.join(expected_pairs)}"
        ):
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity request escaped the frozen page GET"
            )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def url(self) -> str:
        return f"{self.description.base_url}{self.description.request_target}"

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
                "account_activity_transport_request",
                self.description.semantic_sha256,
                self.credential_reference_sha256,
                self.account_binding_sha256,
                self.pre_account_identity_sha256,
                self.preparation_sha256,
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


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountActivityTransportResponse(_NoAccountActivityRuntimeAuthority):
    """Bounded exact entity bytes from one restricted activity-page GET."""

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
        _require_sha256(
            self.request_sha256,
            "account-activity response request digest",
        )
        _require_safe_text(
            self.transport_id,
            "account-activity transport ID",
        )
        _require_safe_text(
            self.transport_version,
            "account-activity transport version",
        )
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity response status must be an HTTP status"
            )
        if self.provider_request_id is not None:
            _require_text(
                self.provider_request_id,
                "account-activity X-Request-ID",
                maximum=256,
            )
        if self.media_type is not None:
            _require_text(
                self.media_type,
                "account-activity response media type",
                maximum=128,
            )
        if type(self.response_body) is not bytes:
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity response body must be exact bytes"
            )
        if len(self.response_body) > ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES:
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity response exceeds the durable raw bound"
            )
        if type(self.tls_verified) is not bool or not self.tls_verified:
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity transport must verify TLS"
            )
        if type(self.redirects_followed) is not bool or self.redirects_followed:
            raise AlpacaPaperAccountActivityTransportError(
                "account-activity transport cannot follow redirects"
            )

    @property
    def response_sha256(self) -> str:
        self.__post_init__()
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
                "account_activity_transport_response",
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


class _AlpacaPaperAccountActivityTransport(Protocol):
    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def execute(
        self,
        request: AlpacaPaperAccountActivityTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountActivityTransportResponse: ...


class _HttpxAlpacaPaperAccountActivityTransport:
    """TLS-verifying, no-redirect, no-proxy activity-page-only transport."""

    __slots__ = ()

    @property
    def transport_id(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION

    def execute(
        self,
        request: AlpacaPaperAccountActivityTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountActivityTransportResponse:
        if type(request) is not AlpacaPaperAccountActivityTransportRequest:
            raise AlpacaPaperAccountActivityTransportError(
                "strict account-activity transport requires an exact request"
            )
        request.__post_init__()
        if type(headers) is not _AlpacaPaperAuthenticationHeaders:
            raise AlpacaPaperAccountActivityTransportError(
                "strict account-activity transport requires redacted auth headers"
            )
        if tuple(headers) != ALPACA_AUTH_HEADER_NAMES:
            raise AlpacaPaperAccountActivityTransportError(
                "strict account-activity transport requires exact auth headers"
            )
        timeout_seconds = request.httpx_phase_timeout.total_seconds()
        result: AlpacaPaperAccountActivityTransportResponse | None = None
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
                        "Accept": (ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE),
                        "Accept-Encoding": "identity",
                        "User-Agent": (
                            f"autoquant-trader/{ALPACA_PAPER_ADAPTER_VERSION} "
                            "phase4ae-account-activity-page"
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
                    if len(body) + len(chunk) > ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES:
                        raise AlpacaPaperAccountActivityTransportError(
                            "account-activity response exceeds the durable raw bound"
                        )
                    body.extend(chunk)
                request_id = _bounded_transport_metadata(
                    response.headers.get("x-request-id"),
                    maximum=256,
                )
                content_type = response.headers.get("content-type")
                content_encoding = response.headers.get("content-encoding")
                identity_encoding = content_encoding is None or (
                    content_encoding.strip().lower() == "identity"
                )
                media_type = None
                if content_type is not None and identity_encoding:
                    media_type = _bounded_transport_metadata(
                        content_type.partition(";")[0].strip().lower(),
                        maximum=128,
                    )
                if response.request.method != "GET" or str(response.request.url) != request.url:
                    raise AlpacaPaperAccountActivityTransportError(
                        "account-activity response changed the fixed target"
                    )
                result = AlpacaPaperAccountActivityTransportResponse(
                    request_sha256=request.semantic_sha256,
                    transport_id=self.transport_id,
                    transport_version=self.transport_version,
                    http_status=response.status_code,
                    provider_request_id=request_id,
                    media_type=media_type,
                    response_body=bytes(body),
                )
        except AlpacaPaperAccountActivityTransportError:
            raise
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise AlpacaPaperAccountActivityTransportError(
                "authenticated account-activity request failed without a retained response"
            ) from None
        if result is None:
            raise AlpacaPaperAccountActivityTransportError(
                "authenticated account-activity request produced no response"
            )
        return result


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivityPageEvidence(_NoAccountActivityRuntimeAuthority):
    """Complete transient proof for one raw-first authenticated page."""

    reference: AlpacaPaperCredentialReference
    credential_receipt: AlpacaPaperCredentialResolutionReceipt
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    description: AlpacaPaperAccountActivityPageDescription
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    permit_freshness: BrokerRequestPermitFreshnessReceipt
    pre_fence_receipt: AccountFenceReceipt
    request: AlpacaPaperAccountActivityTransportRequest
    response: AlpacaPaperAccountActivityTransportResponse
    persisted_page: PersistedAlpacaPaperAccountActivityPage
    post_fence_receipt: AccountFenceReceipt
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    authenticated_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedAccountActivityPageEvidence must be proof-constructed"
        )

    def _validate(self) -> None:
        exact_types = (
            (self.reference, AlpacaPaperCredentialReference, "credential reference"),
            (
                self.credential_receipt,
                AlpacaPaperCredentialResolutionReceipt,
                "credential receipt",
            ),
            (
                self.account_binding,
                AlpacaPaperAuthenticatedAccountBinding,
                "account binding",
            ),
            (
                self.pre_account_identity,
                AlpacaPaperAccountIdentityContinuityReceipt,
                "pre-request account identity",
            ),
            (
                self.description,
                AlpacaPaperAccountActivityPageDescription,
                "page description",
            ),
            (
                self.preparation,
                AlpacaPaperAccountActivityPagePreparationReceipt,
                "page preparation",
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
            (
                self.request,
                AlpacaPaperAccountActivityTransportRequest,
                "transport request",
            ),
            (
                self.response,
                AlpacaPaperAccountActivityTransportResponse,
                "transport response",
            ),
            (
                self.persisted_page,
                PersistedAlpacaPaperAccountActivityPage,
                "persisted page",
            ),
            (
                self.post_fence_receipt,
                AccountFenceReceipt,
                "post-request fence",
            ),
            (
                self.post_account_identity,
                AlpacaPaperAccountIdentityContinuityReceipt,
                "post-request account identity",
            ),
        )
        for value, exact_type, field_name in exact_types:
            if type(value) is not exact_type:
                raise AlpacaPaperAccountActivityConflict(
                    f"authenticated account activity requires an exact {field_name}"
                )
        _validate_reference_binding(self.reference, self.account_binding)
        self.credential_receipt.__post_init__()
        self.description.__post_init__()
        self.preparation._validate()
        self.policy.__post_init__()
        self.demand.__post_init__()
        self.permit.__post_init__()
        self.permit_freshness._validate()
        self.pre_fence_receipt._validate()
        self.request.__post_init__()
        self.response.__post_init__()
        self.persisted_page.__post_init__()
        self.post_fence_receipt._validate()
        _validate_account_identity(
            self.pre_account_identity,
            self.account_binding,
            phase="pre-request",
        )
        _validate_account_identity(
            self.post_account_identity,
            self.account_binding,
            phase="post-request",
        )
        _require_utc(
            self.authenticated_at,
            "account-activity authenticated_at",
        )
        if self.credential_receipt.reference != self.reference:
            raise AlpacaPaperAccountActivityConflict(
                "credential receipt does not bind the exact reference"
            )
        if (
            self.description.plan.account_id != self.reference.account_id
            or self.description.plan.account_id != self.account_binding.account_id
            or self.preparation.description != self.description
        ):
            raise AlpacaPaperAccountActivityConflict(
                "account-activity page crosses exact plan identities"
            )
        if self.policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY:
            raise AlpacaPaperAccountActivityConflict(
                "account activity requires the fixed request-budget policy"
            )
        expected_demand = create_alpaca_paper_account_activity_page_demand(
            self.description,
            requested_at=self.demand.requested_at,
        )
        if (
            self.demand != expected_demand
            or self.demand.purpose is not BrokerRequestPurpose.RECONCILIATION
            or self.demand.idempotency_key
            != alpaca_paper_account_activity_page_delivery_idempotency_key(self.description)
        ):
            raise AlpacaPaperAccountActivityConflict(
                "request demand does not bind the exact activity page"
            )
        if (
            self.permit.account_id != self.demand.account_id
            or self.permit.purpose is not self.demand.purpose
            or self.permit.demand_id != self.demand.demand_id
            or self.permit.demand_sha256 != self.demand.semantic_sha256
            or self.permit.policy_sha256 != self.policy.semantic_sha256
        ):
            raise AlpacaPaperAccountActivityConflict(
                "request permit does not bind the exact activity-page demand"
            )
        if (
            self.permit_freshness.permit_id != self.permit.permit_id
            or self.permit_freshness.permit_sha256 != self.permit.semantic_sha256
            or self.permit_freshness.policy_sha256 != self.policy.semantic_sha256
            or self.permit_freshness.demand_sha256 != self.demand.semantic_sha256
            or self.permit_freshness.expires_at != self.permit.expires_at
        ):
            raise AlpacaPaperAccountActivityConflict(
                "permit freshness does not bind the exact activity-page permit"
            )
        try:
            require_fresh_broker_request_permit(
                permit=self.permit,
                policy=self.policy,
                demand=self.demand,
                checked_at=self.permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperAccountActivityConflict(
                "activity-page permit was not freshly authenticated"
            ) from error
        pre_fence = self.pre_fence_receipt.fence
        post_fence = self.post_fence_receipt.fence
        if pre_fence != post_fence or pre_fence.account_id != self.description.plan.account_id:
            raise AlpacaPaperAccountActivityConflict(
                "account fence changed around activity-page transport"
            )
        expected_request = AlpacaPaperAccountActivityTransportRequest(
            description=self.description,
            credential_reference_sha256=self.reference.semantic_sha256,
            account_binding_sha256=self.account_binding.semantic_sha256,
            pre_account_identity_sha256=(self.pre_account_identity.semantic_sha256),
            preparation_sha256=self.preparation.semantic_sha256,
            demand_sha256=self.demand.semantic_sha256,
            permit_sha256=self.permit.semantic_sha256,
            permit_freshness_sha256=self.permit_freshness.semantic_sha256,
            fence_receipt_sha256=self.pre_fence_receipt.semantic_sha256,
            started_at=self.request.started_at,
        )
        if self.request != expected_request:
            raise AlpacaPaperAccountActivityConflict(
                "transport request does not bind the authenticated inputs"
            )
        if (
            self.response.request_sha256 != self.request.semantic_sha256
            or self.response.transport_id != ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID
            or self.response.transport_version != ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION
            or self.response.media_type != ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE
        ):
            raise AlpacaPaperAccountActivityConflict(
                "transport response conflicts with the restricted request"
            )
        observation = self.persisted_page.observation
        ingress = self.persisted_page.receipt
        delivery = ingress.delivery
        if (
            observation.description != self.description
            or observation.http_status != self.response.http_status
            or observation.provider_request_id != self.response.provider_request_id
            or observation.response_body != self.response.response_body
            or delivery.media_type != self.response.media_type
            or delivery.received_at != observation.received_at
            or delivery.delivery_idempotency_key
            != alpaca_paper_account_activity_page_delivery_idempotency_key(self.description)
        ):
            raise AlpacaPaperAccountActivityConflict(
                "persisted activity page conflicts with transport response"
            )
        if not (
            self.preparation.prepared_at
            <= self.demand.requested_at
            <= self.credential_receipt.started_at
            <= self.credential_receipt.resolved_at
            <= self.permit.issued_at
            <= self.pre_fence_receipt.validated_at
            <= self.permit_freshness.checked_at
            <= self.pre_account_identity.checked_at
            <= self.request.started_at
            <= observation.received_at
            <= delivery.recorded_at
            <= self.post_fence_receipt.validated_at
            <= self.post_account_identity.checked_at
            <= self.authenticated_at
        ):
            raise AlpacaPaperAccountActivityConflict(
                "authenticated activity-page time order is inconsistent"
            )
        if not (
            self.credential_receipt.resolved_at
            <= self.request.started_at
            < self.credential_receipt.valid_until
            and observation.received_at < self.credential_receipt.valid_until
            and self.permit_freshness.checked_at <= self.request.started_at < self.permit.expires_at
            and self.pre_fence_receipt.validated_at
            <= self.request.started_at
            < self.pre_fence_receipt.valid_until
            and self.post_fence_receipt.validated_at
            <= self.authenticated_at
            < self.post_fence_receipt.valid_until
        ):
            raise AlpacaPaperAccountActivityConflict(
                "activity-page transport authority was not current"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
            "authenticated_account_activity_page_evidence",
            self.reference.semantic_sha256,
            self.credential_receipt.semantic_sha256,
            self.account_binding.semantic_sha256,
            self.pre_account_identity.semantic_sha256,
            self.description.semantic_sha256,
            self.preparation.semantic_sha256,
            self.policy.semantic_sha256,
            self.demand.semantic_sha256,
            self.permit.semantic_sha256,
            self.permit_freshness.semantic_sha256,
            self.pre_fence_receipt.semantic_sha256,
            self.request.semantic_sha256,
            self.response.semantic_sha256,
            self.persisted_page.semantic_sha256,
            self.post_fence_receipt.semantic_sha256,
            self.post_account_identity.semantic_sha256,
            self.authenticated_at,
            self.request_budget_enforced,
            self.authenticated_provider_evidence,
            self.raw_response_persisted,
            self.runtime_current,
            self.provider_snapshot_complete,
            self.activity_history_complete,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def evidence_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-account-activity-page-evidence",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def request_budget_enforced(self) -> bool:
        return True

    @property
    def authenticated_provider_evidence(self) -> bool:
        return True

    @property
    def raw_response_persisted(self) -> bool:
        return True

    @property
    def authenticated_account_activity_page_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_account_activity_page_evidence(
    *,
    reference: AlpacaPaperCredentialReference,
    credential_receipt: AlpacaPaperCredentialResolutionReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    description: AlpacaPaperAccountActivityPageDescription,
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    permit_freshness: BrokerRequestPermitFreshnessReceipt,
    pre_fence_receipt: AccountFenceReceipt,
    request: AlpacaPaperAccountActivityTransportRequest,
    response: AlpacaPaperAccountActivityTransportResponse,
    persisted_page: PersistedAlpacaPaperAccountActivityPage,
    post_fence_receipt: AccountFenceReceipt,
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    authenticated_at: datetime,
) -> AlpacaPaperAuthenticatedAccountActivityPageEvidence:
    evidence = object.__new__(AlpacaPaperAuthenticatedAccountActivityPageEvidence)
    for field_name, value in (
        ("reference", reference),
        ("credential_receipt", credential_receipt),
        ("account_binding", account_binding),
        ("pre_account_identity", pre_account_identity),
        ("description", description),
        ("preparation", preparation),
        ("policy", policy),
        ("demand", demand),
        ("permit", permit),
        ("permit_freshness", permit_freshness),
        ("pre_fence_receipt", pre_fence_receipt),
        ("request", request),
        ("response", response),
        ("persisted_page", persisted_page),
        ("post_fence_receipt", post_fence_receipt),
        ("post_account_identity", post_account_identity),
        ("authenticated_at", authenticated_at),
    ):
        object.__setattr__(evidence, field_name, value)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivityPageReceipt(_NoAccountActivityRuntimeAuthority):
    """Durable commit proof for one authenticated activity page."""

    evidence: AlpacaPaperAuthenticatedAccountActivityPageEvidence
    commit_fence_receipt: AccountFenceReceipt
    previous_page_receipt_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedAccountActivityPageReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.evidence) is not AlpacaPaperAuthenticatedAccountActivityPageEvidence:
            raise AlpacaPaperAccountActivityConflict(
                "activity-page receipt requires exact authenticated evidence"
            )
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperAccountActivityConflict(
                "activity-page receipt requires an exact commit fence"
            )
        self.evidence._validate()
        self.commit_fence_receipt._validate()
        post = self.evidence.post_fence_receipt
        if (
            self.commit_fence_receipt.fence != post.fence
            or self.commit_fence_receipt.policy_sha256 != post.policy_sha256
            or self.commit_fence_receipt.lease_sha256 != post.lease_sha256
            or self.commit_fence_receipt.valid_until != post.valid_until
            or self.commit_fence_receipt.validated_at < self.evidence.authenticated_at
            or self.commit_fence_receipt.validated_at >= self.commit_fence_receipt.valid_until
        ):
            raise AlpacaPaperAccountActivityConflict(
                "commit fence does not continue the post-response lease"
            )
        if self.page_number == 1:
            if self.previous_page_receipt_sha256 is not None:
                raise AlpacaPaperAccountActivityConflict(
                    "first authenticated activity page cannot name a predecessor"
                )
        else:
            _require_sha256(
                self.previous_page_receipt_sha256,
                "authenticated activity-page predecessor digest",
            )
            if (
                self.previous_page_receipt_sha256
                != self.evidence.preparation.previous_page_receipt_sha256
            ):
                raise AlpacaPaperAccountActivityConflict(
                    "activity-page predecessor conflicts with preparation"
                )

    @property
    def plan(self) -> AlpacaPaperAccountActivityPlan:
        return self.evidence.description.plan

    @property
    def description(self) -> AlpacaPaperAccountActivityPageDescription:
        return self.evidence.description

    @property
    def persisted_page(self) -> PersistedAlpacaPaperAccountActivityPage:
        return self.evidence.persisted_page

    @property
    def account_id(self) -> str:
        return self.plan.account_id

    @property
    def page_number(self) -> int:
        return self.description.page_number

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
            "authenticated_account_activity_page_receipt",
            self.evidence.semantic_sha256,
            self.commit_fence_receipt.semantic_sha256,
            self.previous_page_receipt_sha256,
            self.page_number,
            self.persisted_page.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-account-activity-page",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def request_budget_enforced(self) -> bool:
        return True

    @property
    def authenticated_provider_evidence(self) -> bool:
        return True

    @property
    def raw_response_persisted(self) -> bool:
        return True

    @property
    def authenticated_account_activity_page_established(self) -> bool:
        return True

    @property
    def committed_prefix_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_account_activity_page_receipt(
    evidence: AlpacaPaperAuthenticatedAccountActivityPageEvidence,
    *,
    commit_fence_receipt: AccountFenceReceipt,
    previous_page_receipt_sha256: str | None,
) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
    receipt = object.__new__(AlpacaPaperAuthenticatedAccountActivityPageReceipt)
    object.__setattr__(receipt, "evidence", evidence)
    object.__setattr__(
        receipt,
        "commit_fence_receipt",
        commit_fence_receipt,
    )
    object.__setattr__(
        receipt,
        "previous_page_receipt_sha256",
        previous_page_receipt_sha256,
    )
    receipt._validate()
    return receipt


def _capture_from_authenticated_account_activity_page_receipts(
    plan: AlpacaPaperAccountActivityPlan,
    page_receipts: tuple[
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
        ...,
    ],
) -> AlpacaPaperAccountActivityCapture:
    capture = start_alpaca_paper_account_activity_capture(plan)
    previous: AlpacaPaperAuthenticatedAccountActivityPageReceipt | None = None
    for expected_page_number, receipt in enumerate(page_receipts, start=1):
        if type(receipt) is not AlpacaPaperAuthenticatedAccountActivityPageReceipt:
            raise AlpacaPaperAccountActivityConflict(
                "authenticated activity prefix contains an invalid receipt"
            )
        receipt._validate()
        expected_description = capture.next_page_description
        if (
            receipt.plan != plan
            or receipt.page_number != expected_page_number
            or expected_description is None
            or receipt.description != expected_description
            or receipt.evidence.preparation.prefix_capture_sha256 != capture.semantic_sha256
            or receipt.evidence.preparation.prefix_page_count != capture.page_count
        ):
            raise AlpacaPaperAccountActivityConflict(
                "authenticated prefix is not the exact gap-free Phase 4AD chain"
            )
        expected_id = None if previous is None else previous.receipt_id
        expected_sha256 = None if previous is None else previous.semantic_sha256
        if (
            receipt.evidence.preparation.previous_page_receipt_id != expected_id
            or receipt.evidence.preparation.previous_page_receipt_sha256 != expected_sha256
            or receipt.previous_page_receipt_sha256 != expected_sha256
        ):
            raise AlpacaPaperAccountActivityConflict(
                "authenticated activity-prefix lineage is inconsistent"
            )
        capture = append_alpaca_paper_account_activity_page(
            capture,
            receipt.persisted_page,
        )
        previous = receipt
    return capture


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivityPrefix(_NoAccountActivityRuntimeAuthority):
    """An exact durable prefix of authenticated activity-page receipts."""

    plan: AlpacaPaperAccountActivityPlan
    page_receipts: tuple[
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
        ...,
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedAccountActivityPrefix must be repository-produced")

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperAccountActivityPlan:
            raise AlpacaPaperAccountActivityConflict(
                "authenticated activity prefix requires an exact plan"
            )
        self.plan.__post_init__()
        if type(self.page_receipts) is not tuple:
            raise AlpacaPaperAccountActivityConflict(
                "authenticated activity receipts must be an exact tuple"
            )
        _capture_from_authenticated_account_activity_page_receipts(
            self.plan,
            self.page_receipts,
        )

    @property
    def capture(self) -> AlpacaPaperAccountActivityCapture:
        self._validate()
        return _capture_from_authenticated_account_activity_page_receipts(
            self.plan,
            self.page_receipts,
        )

    @property
    def page_count(self) -> int:
        return len(self.page_receipts)

    @property
    def authenticated_page_count(self) -> int:
        return len(self.page_receipts)

    @property
    def next_page_description(
        self,
    ) -> AlpacaPaperAccountActivityPageDescription | None:
        return self.capture.next_page_description

    def _semantic_material(self) -> tuple[object, ...]:
        capture = _capture_from_authenticated_account_activity_page_receipts(
            self.plan,
            self.page_receipts,
        )
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
            "authenticated_account_activity_prefix",
            self.plan.semantic_sha256,
            tuple(receipt.semantic_sha256 for receipt in self.page_receipts),
            capture.semantic_sha256,
            capture.pagination_exhausted,
            capture.bounded_truncation,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def prefix_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-account-activity-prefix",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def committed_prefix_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_account_activity_prefix(
    plan: AlpacaPaperAccountActivityPlan,
    *,
    page_receipts: tuple[
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
        ...,
    ],
) -> AlpacaPaperAuthenticatedAccountActivityPrefix:
    prefix = object.__new__(AlpacaPaperAuthenticatedAccountActivityPrefix)
    object.__setattr__(prefix, "plan", plan)
    object.__setattr__(prefix, "page_receipts", page_receipts)
    prefix._validate()
    return prefix


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivityTraversalState(_NoAccountActivityRuntimeAuthority):
    """Authenticated durable head meaning, including an explicit stall."""

    stage: AlpacaPaperAccountActivityTraversalStage
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt | None
    source_head_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedAccountActivityTraversalState must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.stage) is not AlpacaPaperAccountActivityTraversalStage:
            raise AlpacaPaperAccountActivityConflict(
                "activity traversal state requires an exact stage"
            )
        if type(self.prefix) is not AlpacaPaperAuthenticatedAccountActivityPrefix:
            raise AlpacaPaperAccountActivityConflict(
                "activity traversal state requires an exact prefix"
            )
        self.prefix._validate()
        if self.stage is AlpacaPaperAccountActivityTraversalStage.ABSENT:
            if (
                self.prefix.page_count != 0
                or self.preparation is not None
                or self.source_head_sha256 is not None
            ):
                raise AlpacaPaperAccountActivityConflict(
                    "absent activity traversal has durable state"
                )
            return
        _require_sha256(
            self.source_head_sha256,
            "activity traversal source head digest",
        )
        if self.stage is AlpacaPaperAccountActivityTraversalStage.STALLED:
            if type(self.preparation) is not AlpacaPaperAccountActivityPagePreparationReceipt:
                raise AlpacaPaperAccountActivityConflict(
                    "stalled activity traversal requires its preparation"
                )
            self.preparation._validate()
            if (
                self.preparation.description != self.prefix.next_page_description
                or self.preparation.prefix_capture_sha256 != self.prefix.capture.semantic_sha256
                or self.preparation.prefix_page_count != self.prefix.page_count
            ):
                raise AlpacaPaperAccountActivityConflict(
                    "stalled activity traversal conflicts with its prefix"
                )
        elif self.preparation is not None:
            raise AlpacaPaperAccountActivityConflict(
                "non-stalled activity traversal cannot retain a preparation"
            )
        capture = self.prefix.capture
        if (
            self.stage is AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED
            and not capture.pagination_exhausted
        ):
            raise AlpacaPaperAccountActivityConflict(
                "cursor-exhausted stage lacks terminal-page evidence"
            )
        if (
            self.stage is AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED
            and not capture.bounded_truncation
        ):
            raise AlpacaPaperAccountActivityConflict(
                "bounded-truncated stage lacks truncation evidence"
            )
        if self.stage is AlpacaPaperAccountActivityTraversalStage.ACTIVE and (
            self.prefix.page_count == 0 or self.prefix.next_page_description is None
        ):
            raise AlpacaPaperAccountActivityConflict(
                "active activity traversal has no committed continuation"
            )

    @property
    def stalled(self) -> bool:
        return self.stage is AlpacaPaperAccountActivityTraversalStage.STALLED

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
                "authenticated_account_activity_traversal_state",
                self.stage,
                self.prefix.semantic_sha256,
                (None if self.preparation is None else self.preparation.semantic_sha256),
                self.source_head_sha256,
            )
        )


def _alpaca_paper_authenticated_account_activity_traversal_state(
    *,
    stage: AlpacaPaperAccountActivityTraversalStage,
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt | None,
    source_head_sha256: str | None,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    state = object.__new__(AlpacaPaperAuthenticatedAccountActivityTraversalState)
    object.__setattr__(state, "stage", stage)
    object.__setattr__(state, "prefix", prefix)
    object.__setattr__(state, "preparation", preparation)
    object.__setattr__(state, "source_head_sha256", source_head_sha256)
    state._validate()
    return state


class AlpacaPaperAccountActivityPageRuntimePort(Protocol):
    """Atomic durable operations around one fresh single-use page claim."""

    @property
    def runtime_store_identity(self) -> int: ...

    def prepare_next(
        self,
        description: AlpacaPaperAccountActivityPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperAccountActivityPagePreparationReceipt: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityPageEvidence,
    ) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt: ...

    def load_prefix(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityPrefix: ...

    def load_state(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityTraversalState: ...


def _revalidate_fence(
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    *,
    phase: str,
) -> AccountFenceReceipt:
    try:
        result = coordinator.revalidate(fence)
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            f"account fence authentication failed {phase} activity transport"
        ) from None
    if type(result) is not AccountFenceReceipt:
        raise AlpacaPaperAccountActivityRuntimeError(
            f"account coordinator returned invalid {phase} fence evidence"
        )
    result._validate()
    if result.fence != fence:
        raise AlpacaPaperAccountActivityConflict(
            f"account fence changed {phase} activity transport"
        )
    return result


def _authenticate_account_binding_identity(
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    checked_at: datetime,
    phase: str,
) -> AlpacaPaperAccountIdentityContinuityReceipt:
    try:
        result = account_bindings.authenticate_terminal_identity(
            account_binding,
            checked_at,
        )
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            f"terminal account identity failed {phase} activity transport"
        ) from None
    if type(result) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperAccountActivityRuntimeError(
            f"account identity repository returned invalid {phase} evidence"
        )
    _validate_account_identity(result, account_binding, phase=phase)
    if result.checked_at != checked_at:
        raise AlpacaPaperAccountActivityConflict(
            f"account identity repository used another {phase} instant"
        )
    return result


def _validate_issued_permit(
    permit: object,
    demand: BrokerRequestDemand,
) -> BrokerRequestPermit:
    if type(permit) is not BrokerRequestPermit:
        raise AlpacaPaperAccountActivityRuntimeError(
            "budget issuer returned an invalid activity-page permit"
        )
    permit.__post_init__()
    if (
        permit.account_id != demand.account_id
        or permit.purpose is not BrokerRequestPurpose.RECONCILIATION
        or permit.demand_id != demand.demand_id
        or permit.demand_sha256 != demand.semantic_sha256
        or permit.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
    ):
        raise AlpacaPaperAccountActivityConflict(
            "budget issuer returned a permit for another demand"
        )
    return permit


def _authenticate_page_permit(
    budget: BrokerRequestBudgetRuntimePort,
    permit: BrokerRequestPermit,
    demand: BrokerRequestDemand,
) -> BrokerRequestPermitFreshnessReceipt:
    try:
        result = budget.authenticate_fresh(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            "activity-page permit authentication failed before transport"
        ) from None
    if type(result) is not BrokerRequestPermitFreshnessReceipt:
        raise AlpacaPaperAccountActivityRuntimeError(
            "budget authenticator returned invalid activity-page freshness"
        )
    result._validate()
    if (
        result.permit_id != permit.permit_id
        or result.permit_sha256 != permit.semantic_sha256
        or result.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
        or result.demand_sha256 != demand.semantic_sha256
        or result.expires_at != permit.expires_at
    ):
        raise AlpacaPaperAccountActivityConflict(
            "permit freshness conflicts before activity transport"
        )
    try:
        require_fresh_broker_request_permit(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            checked_at=result.checked_at,
        )
    except ValueError as error:
        raise AlpacaPaperAccountActivityConflict(
            "activity-page permit is invalid before transport"
        ) from error
    return result


def _observe_authenticated_alpaca_paper_account_activity_page_with_transport(
    *,
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAccountActivityPageDescription,
    credential_resolver: AlpacaPaperAccountActivityCredentialResolver,
    transport: _AlpacaPaperAccountActivityTransport,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    page_runtime: AlpacaPaperAccountActivityPageRuntimePort,
    clock: Clock,
) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
    """Trusted test seam: prepare, execute, and commit exactly one page."""

    _validate_runtime_store_composition(
        page_runtime=page_runtime,
        budget=budget,
        account_bindings=account_bindings,
        coordinator=coordinator,
        ingress_recorder=ingress_recorder,
    )
    _validate_reference_binding(reference, account_binding)
    if type(description) is not AlpacaPaperAccountActivityPageDescription:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity runtime requires an exact page description"
        )
    description.__post_init__()
    if description.plan.account_id != reference.account_id:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity description belongs to another account"
        )
    if type(fence) is not AccountFence or fence.account_id != reference.account_id:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity runtime requires the current exact fence"
        )
    for port, method_name, field_name in (
        (page_runtime, "prepare_next", "durable page preparer"),
        (page_runtime, "record", "durable page recorder"),
        (page_runtime, "load_prefix", "durable prefix loader"),
        (budget, "issue_new", "durable new-permit issuer"),
        (budget, "authenticate_fresh", "durable budget authenticator"),
        (
            account_bindings,
            "authenticate_terminal_identity",
            "account-identity authenticator",
        ),
        (coordinator, "revalidate", "account coordinator"),
        (ingress_recorder, "record", "raw ingress recorder"),
        (transport, "execute", "restricted activity transport"),
    ):
        if not callable(getattr(port, method_name, None)):
            raise AlpacaPaperAccountActivityRuntimeError(
                f"account-activity runtime requires a {field_name}"
            )
    if getattr(coordinator, "account_id", None) != reference.account_id:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity coordinator belongs to another account"
        )
    if (
        getattr(transport, "transport_id", None) != ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID
        or getattr(transport, "transport_version", None)
        != ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION
    ):
        raise AlpacaPaperAccountActivityTransportError(
            "account-activity runtime requires the restricted transport"
        )

    prepared_at = _trusted_now(
        clock,
        "account-activity preparation checked_at",
    )
    try:
        preparation_value = page_runtime.prepare_next(
            description,
            checked_at=prepared_at,
        )
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            "durable next-page preparation failed before credential resolution"
        ) from None
    if type(preparation_value) is not AlpacaPaperAccountActivityPagePreparationReceipt:
        raise AlpacaPaperAccountActivityRuntimeError(
            "durable activity-page preparer returned invalid evidence"
        )
    preparation = preparation_value
    preparation._validate()
    if preparation.description != description or preparation.prepared_at > prepared_at:
        raise AlpacaPaperAccountActivityConflict(
            "durable preparation does not bind the requested activity page"
        )
    try:
        prefix_value = page_runtime.load_prefix(description.plan)
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            "durable activity prefix failed authentication before credentials"
        ) from None
    if type(prefix_value) is not AlpacaPaperAuthenticatedAccountActivityPrefix:
        raise AlpacaPaperAccountActivityRuntimeError(
            "durable activity-prefix loader returned invalid evidence"
        )
    prefix = prefix_value
    prefix._validate()
    previous = None if not prefix.page_receipts else prefix.page_receipts[-1]
    if (
        prefix.plan != description.plan
        or prefix.next_page_description != description
        or preparation.prefix_capture_sha256 != prefix.capture.semantic_sha256
        or preparation.prefix_page_count != prefix.page_count
        or preparation.previous_page_receipt_id
        != (None if previous is None else previous.receipt_id)
        or preparation.previous_page_receipt_sha256
        != (None if previous is None else previous.semantic_sha256)
    ):
        raise AlpacaPaperAccountActivityConflict(
            "durable preparation conflicts with the committed activity prefix"
        )

    requested_at = _trusted_now(clock, "account-activity requested_at")
    demand = create_alpaca_paper_account_activity_page_demand(
        description,
        requested_at=requested_at,
    )
    credential_session = _resolve_alpaca_paper_credentials_for_operation(
        reference=reference,
        resolver=credential_resolver,
        resolver_method_name="_resolve_for_account_activity_page",
        clock=clock,
    )
    try:
        permit_value = budget.issue_new(
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        permit = _validate_issued_permit(permit_value, demand)
        pre_fence_receipt = _revalidate_fence(
            coordinator,
            fence,
            phase="before",
        )
        permit_freshness = _authenticate_page_permit(
            budget,
            permit,
            demand,
        )
        pre_identity_checked_at = _trusted_now(
            clock,
            "pre-account-activity identity checked_at",
        )
        pre_account_identity = _authenticate_account_binding_identity(
            account_bindings,
            account_binding,
            checked_at=pre_identity_checked_at,
            phase="before",
        )
        started_at = _trusted_now(
            clock,
            "account-activity transport started_at",
        )
        if (
            preparation.prepared_at > started_at
            or credential_session.receipt.resolved_at > started_at
            or not credential_session.receipt.is_fresh(started_at)
            or permit_freshness.checked_at > started_at
            or not permit.is_fresh(started_at)
            or not (pre_fence_receipt.validated_at <= started_at < pre_fence_receipt.valid_until)
            or pre_account_identity.checked_at > started_at
        ):
            raise AlpacaPaperAccountActivityConflict(
                "activity-page authority is not current at transport start"
            )
        request = AlpacaPaperAccountActivityTransportRequest(
            description=description,
            credential_reference_sha256=reference.semantic_sha256,
            account_binding_sha256=account_binding.semantic_sha256,
            pre_account_identity_sha256=(pre_account_identity.semantic_sha256),
            preparation_sha256=preparation.semantic_sha256,
            demand_sha256=demand.semantic_sha256,
            permit_sha256=permit.semantic_sha256,
            permit_freshness_sha256=permit_freshness.semantic_sha256,
            fence_receipt_sha256=pre_fence_receipt.semantic_sha256,
            started_at=started_at,
        )
        headers = credential_session.authentication_headers(checked_at=started_at)
        try:
            response_value = transport.execute(request, headers)
        except Exception:
            raise AlpacaPaperAccountActivityTransportError(
                "restricted account-activity transport failed with sanitized diagnostics"
            ) from None
        received_at = _trusted_now(
            clock,
            "account-activity transport received_at",
        )
    finally:
        credential_session.close()

    if type(response_value) is not AlpacaPaperAccountActivityTransportResponse:
        raise AlpacaPaperAccountActivityTransportError(
            "account-activity transport returned an invalid response"
        )
    response = response_value
    response.__post_init__()
    if (
        response.request_sha256 != request.semantic_sha256
        or response.transport_id != ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID
        or response.transport_version != ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION
    ):
        raise AlpacaPaperAccountActivityTransportError(
            "account-activity response binds another request or profile"
        )
    if received_at < started_at or received_at >= credential_session.receipt.valid_until:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity response completed outside credential validity"
        )
    recorded_at = _trusted_now(
        clock,
        "account-activity raw response recorded_at",
    )
    if recorded_at < received_at:
        raise AlpacaPaperAccountActivityRuntimeError("account-activity raw-record clock regressed")
    persisted_page = persist_then_decode_alpaca_paper_account_activity_page(
        ingress_recorder,
        description,
        delivery_idempotency_key=(
            alpaca_paper_account_activity_page_delivery_idempotency_key(description)
        ),
        http_status=response.http_status,
        provider_request_id=response.provider_request_id,
        response_body=response.response_body,
        received_at=received_at,
        recorded_at=recorded_at,
        media_type=response.media_type,
    )
    if response.media_type != ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE:
        raise AlpacaPaperAccountActivityConflict(
            "account-activity media type is not exact JSON after raw persistence"
        )
    post_fence_receipt = _revalidate_fence(
        coordinator,
        fence,
        phase="after",
    )
    post_identity_checked_at = _trusted_now(
        clock,
        "post-account-activity identity checked_at",
    )
    post_account_identity = _authenticate_account_binding_identity(
        account_bindings,
        account_binding,
        checked_at=post_identity_checked_at,
        phase="after",
    )
    authenticated_at = _trusted_now(
        clock,
        "account-activity authenticated_at",
    )
    evidence = _alpaca_paper_authenticated_account_activity_page_evidence(
        reference=reference,
        credential_receipt=credential_session.receipt,
        account_binding=account_binding,
        pre_account_identity=pre_account_identity,
        description=description,
        preparation=preparation,
        policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
        demand=demand,
        permit=permit,
        permit_freshness=permit_freshness,
        pre_fence_receipt=pre_fence_receipt,
        request=request,
        response=response,
        persisted_page=persisted_page,
        post_fence_receipt=post_fence_receipt,
        post_account_identity=post_account_identity,
        authenticated_at=authenticated_at,
    )
    try:
        receipt_value = page_runtime.record(evidence)
    except Exception:
        raise AlpacaPaperAccountActivityConflict(
            "durable authenticated activity-page commit failed"
        ) from None
    if type(receipt_value) is not AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        raise AlpacaPaperAccountActivityRuntimeError(
            "durable activity-page recorder returned an invalid receipt"
        )
    receipt = receipt_value
    receipt._validate()
    if receipt.evidence != evidence:
        raise AlpacaPaperAccountActivityConflict(
            "durable activity-page receipt binds different evidence"
        )
    expected = _alpaca_paper_authenticated_account_activity_page_receipt(
        evidence,
        commit_fence_receipt=receipt.commit_fence_receipt,
        previous_page_receipt_sha256=(receipt.previous_page_receipt_sha256),
    )
    if receipt != expected:
        raise AlpacaPaperAccountActivityConflict(
            "durable activity-page receipt conflicts with runtime evidence"
        )
    return receipt


def observe_authenticated_alpaca_paper_account_activity_page(
    *,
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAccountActivityPageDescription,
    credential_resolver: AlpacaPaperAccountActivityCredentialResolver,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    page_runtime: AlpacaPaperAccountActivityPageRuntimePort,
    clock: Clock,
) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
    """Execute one production account-activity page GET and commit evidence."""

    return _observe_authenticated_alpaca_paper_account_activity_page_with_transport(
        reference=reference,
        account_binding=account_binding,
        description=description,
        credential_resolver=credential_resolver,
        transport=_HttpxAlpacaPaperAccountActivityTransport(),
        budget=budget,
        account_bindings=account_bindings,
        coordinator=coordinator,
        fence=fence,
        ingress_recorder=ingress_recorder,
        page_runtime=page_runtime,
        clock=clock,
    )


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_HTTPX_PHASE_TIMEOUT",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION",
    "AlpacaPaperAccountActivityConflict",
    "AlpacaPaperAccountActivityCredentialResolver",
    "AlpacaPaperAccountActivityPagePreparationReceipt",
    "AlpacaPaperAccountActivityPageRuntimePort",
    "AlpacaPaperAccountActivityRuntimeError",
    "AlpacaPaperAccountActivityTransportError",
    "AlpacaPaperAccountActivityTransportRequest",
    "AlpacaPaperAccountActivityTransportResponse",
    "AlpacaPaperAccountActivityTraversalStage",
    "AlpacaPaperAuthenticatedAccountActivityPageEvidence",
    "AlpacaPaperAuthenticatedAccountActivityPageReceipt",
    "AlpacaPaperAuthenticatedAccountActivityPrefix",
    "AlpacaPaperAuthenticatedAccountActivityTraversalState",
    "alpaca_paper_account_activity_page_delivery_idempotency_key",
    "observe_authenticated_alpaca_paper_account_activity_page",
]
