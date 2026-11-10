"""Authenticated one-page runtime for bounded Alpaca paper order snapshots.

Phase 4O admits exactly one page from the offline Phase 4M traversal contract.
The durable prefix is authenticated before credentials or request capacity are
consumed, the completed response is retained before decoding, and the same
account fence and terminal Phase 4G account identity are proved around I/O.

The resulting evidence is historical reconciliation input only.  It does not
claim snapshot isolation, provider completeness, convergence, lifecycle
authority, UNKNOWN resolution, execution facts, or any trading effect.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

import httpx

from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
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
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES,
    AlpacaPaperOrderSnapshotCapture,
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
    PersistedAlpacaPaperOrderSnapshotPage,
    append_alpaca_paper_order_snapshot_page,
    create_alpaca_paper_order_snapshot_page_demand,
    persist_then_decode_alpaca_paper_order_snapshot_page,
    start_alpaca_paper_order_snapshot,
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

ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION = (
    "phase4o-authenticated-durable-order-snapshot-page-v2"
)
ALPACA_PAPER_ORDER_SNAPSHOT_HTTPX_PHASE_TIMEOUT = ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT
ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE = ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID = "strict-httpx-alpaca-paper-order-snapshot-page"
ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION = "1.0.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AlpacaPaperOrderSnapshotRuntimeError(AlpacaPaperContractError):
    """Authenticated order-snapshot runtime evidence is malformed."""


class AlpacaPaperOrderSnapshotTransportError(AlpacaPaperOrderSnapshotRuntimeError):
    """The exact restricted order-snapshot transport failed."""


class AlpacaPaperOrderSnapshotConflict(AlpacaPaperOrderSnapshotRuntimeError):
    """Order-snapshot evidence conflicts with a durable authority."""


class _NoOrderSnapshotRuntimeAuthority:
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
    def authenticated_order_snapshot_page_established(self) -> bool:
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
    def converged(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
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
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
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


def _require_text(value: object, field_name: str, *, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperOrderSnapshotRuntimeError(
            f"{field_name} must be bounded, non-empty trimmed text"
        )
    return value


def _require_safe_text(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if _SAFE_TEXT.fullmatch(text) is None:
        raise AlpacaPaperOrderSnapshotRuntimeError(f"{field_name} is not canonical safe text")
    return text


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperOrderSnapshotRuntimeError(f"{field_name} must be a lowercase SHA-256")
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperOrderSnapshotRuntimeError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperOrderSnapshotRuntimeError(str(error)) from error
    return value


def _trusted_now(clock: Clock, field_name: str) -> datetime:
    if not callable(getattr(clock, "now", None)):
        raise AlpacaPaperOrderSnapshotRuntimeError(
            "order-snapshot runtime requires a trusted clock"
        )
    try:
        instant = clock.now()
    except Exception as error:
        raise AlpacaPaperOrderSnapshotRuntimeError(f"{field_name} clock failed") from error
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


def alpaca_paper_order_snapshot_page_delivery_idempotency_key(
    description: AlpacaPaperOrderSnapshotPageDescription,
) -> str:
    """Return the deterministic raw-delivery identity for one exact page."""

    if type(description) is not AlpacaPaperOrderSnapshotPageDescription:
        raise AlpacaPaperOrderSnapshotConflict(
            "delivery identity requires an exact page description"
        )
    description.__post_init__()
    return f"order-snapshot:{description.plan.snapshot_id}:{description.page_number:02d}"


def _validate_reference_binding(
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
) -> None:
    if type(reference) is not AlpacaPaperCredentialReference:
        raise AlpacaPaperOrderSnapshotConflict(
            "order snapshot requires an exact credential reference"
        )
    if type(account_binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperOrderSnapshotConflict(
            "order snapshot requires an exact authenticated account binding"
        )
    reference.__post_init__()
    account_binding._validate()
    if (
        reference.account_id != account_binding.account_id
        or reference.provider_id != account_binding.provider_id
        or reference.environment != account_binding.environment
        or reference.expected_provider_account_id != account_binding.expected_provider_account_id
        or reference.secret_ref != account_binding.secret_ref
        or reference.secret_version != account_binding.secret_version
        or reference.semantic_sha256 != account_binding.credential_reference_sha256
    ):
        raise AlpacaPaperOrderSnapshotConflict(
            "credential reference conflicts with the authenticated account binding"
        )


def _validate_account_identity(
    identity: AlpacaPaperAccountIdentityContinuityReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    phase: str,
) -> None:
    if type(identity) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperOrderSnapshotConflict(
            f"{phase} account identity must be exact repository evidence"
        )
    identity._validate()
    if (
        identity.account_id != account_binding.account_id
        or identity.binding_id != account_binding.binding_id
        or identity.binding_sha256 != account_binding.semantic_sha256
        or identity.credential_reference_sha256 != account_binding.credential_reference_sha256
        or identity.expected_provider_account_id != account_binding.expected_provider_account_id
        or identity.sequence_number != account_binding.sequence_number
        or identity.binding_qualified_at != account_binding.qualified_at
    ):
        raise AlpacaPaperOrderSnapshotConflict(
            f"{phase} account identity conflicts with the exact terminal binding"
        )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperOrderSnapshotPagePreparationReceipt(_NoOrderSnapshotRuntimeAuthority):
    """Repository proof that an exact page is the durable next page."""

    description: AlpacaPaperOrderSnapshotPageDescription
    prefix_capture_sha256: str
    prefix_page_count: int
    previous_page_receipt_id: str | None
    previous_page_receipt_sha256: str | None
    prepared_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperOrderSnapshotPagePreparationReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.description) is not AlpacaPaperOrderSnapshotPageDescription:
            raise AlpacaPaperOrderSnapshotConflict("page preparation requires an exact description")
        self.description.__post_init__()
        _require_sha256(
            self.prefix_capture_sha256,
            "prepared order-snapshot prefix digest",
        )
        if (
            type(self.prefix_page_count) is not int
            or self.prefix_page_count != self.description.page_number - 1
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "page preparation prefix count does not precede the requested page"
            )
        if self.description.page_number == 1:
            if (
                self.previous_page_receipt_id is not None
                or self.previous_page_receipt_sha256 is not None
            ):
                raise AlpacaPaperOrderSnapshotConflict(
                    "first page preparation cannot name a predecessor receipt"
                )
            empty_capture = start_alpaca_paper_order_snapshot(self.description.plan)
            if self.prefix_capture_sha256 != empty_capture.semantic_sha256:
                raise AlpacaPaperOrderSnapshotConflict(
                    "first page preparation conflicts with the empty prefix"
                )
        else:
            _require_text(
                self.previous_page_receipt_id,
                "prepared predecessor receipt ID",
                maximum=64,
            )
            _require_sha256(
                self.previous_page_receipt_sha256,
                "prepared predecessor receipt digest",
            )
        _require_utc(self.prepared_at, "page preparation prepared_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "order_snapshot_page_preparation",
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
            "alpaca-paper-order-snapshot-page-preparation",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _alpaca_paper_order_snapshot_page_preparation_receipt(
    description: AlpacaPaperOrderSnapshotPageDescription,
    *,
    prefix_capture_sha256: str,
    prefix_page_count: int,
    previous_page_receipt_id: str | None,
    previous_page_receipt_sha256: str | None,
    prepared_at: datetime,
) -> AlpacaPaperOrderSnapshotPagePreparationReceipt:
    """Construct preparation proof after the repository locks the prefix."""

    receipt = object.__new__(AlpacaPaperOrderSnapshotPagePreparationReceipt)
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


class AlpacaPaperOrderSnapshotCredentialResolver(Protocol):
    """Secret-read authority restricted to one Phase 4O page."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_order_snapshot_page(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class AlpacaPaperOrderSnapshotTransportRequest(_NoOrderSnapshotRuntimeAuthority):
    """Secret-free description of one exact preauthorized page GET."""

    description: AlpacaPaperOrderSnapshotPageDescription
    credential_reference_sha256: str
    account_binding_sha256: str
    pre_account_identity_sha256: str
    preparation_sha256: str
    demand_sha256: str
    permit_sha256: str
    permit_freshness_sha256: str
    fence_receipt_sha256: str
    started_at: datetime
    httpx_phase_timeout: timedelta = ALPACA_PAPER_ORDER_SNAPSHOT_HTTPX_PHASE_TIMEOUT

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperOrderSnapshotPageDescription:
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot transport requires an exact page description"
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
                f"order-snapshot transport {field_name} digest",
            )
        _require_utc(self.started_at, "order-snapshot transport started_at")
        if (
            type(self.httpx_phase_timeout) is not timedelta
            or self.httpx_phase_timeout != ALPACA_PAPER_ORDER_SNAPSHOT_HTTPX_PHASE_TIMEOUT
        ):
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot transport must use the fixed I/O timeout"
            )
        if (
            self.description.method != "GET"
            or self.description.base_url != ALPACA_PAPER_TRADING_BASE_URL
            or self.description.path != ALPACA_PAPER_CAPABILITIES.orders_path
            or self.description.request_target
            != f"{self.description.path}?"
            + "&".join(
                (
                    "status=all",
                    f"limit={self.description.plan.page_limit}",
                    "direction=desc",
                    "nested=false",
                    "asset_class=us_equity",
                    *(
                        ()
                        if self.description.before_order_id is None
                        else (f"before_order_id={self.description.before_order_id}",)
                    ),
                )
            )
        ):
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot request escaped the frozen page GET"
            )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def url(self) -> str:
        return f"{self.description.base_url}{self.description.request_target}"

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
                "order_snapshot_transport_request",
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
class AlpacaPaperOrderSnapshotTransportResponse(_NoOrderSnapshotRuntimeAuthority):
    """Bounded exact entity bytes from one restricted page GET."""

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
            "order-snapshot response request digest",
        )
        _require_safe_text(self.transport_id, "order-snapshot transport ID")
        _require_safe_text(
            self.transport_version,
            "order-snapshot transport version",
        )
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot response status must be an exact HTTP status"
            )
        if self.provider_request_id is not None:
            _require_text(
                self.provider_request_id,
                "order-snapshot X-Request-ID",
                maximum=256,
            )
        if self.media_type is not None:
            _require_text(
                self.media_type,
                "order-snapshot response media type",
                maximum=128,
            )
        if type(self.response_body) is not bytes:
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot response body must be exact bytes"
            )
        if len(self.response_body) > ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES:
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot response exceeds the durable raw bound"
            )
        if type(self.tls_verified) is not bool or not self.tls_verified:
            raise AlpacaPaperOrderSnapshotTransportError("order-snapshot transport must verify TLS")
        if type(self.redirects_followed) is not bool or self.redirects_followed:
            raise AlpacaPaperOrderSnapshotTransportError(
                "order-snapshot transport cannot follow redirects"
            )

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
                "order_snapshot_transport_response",
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


class _AlpacaPaperOrderSnapshotTransport(Protocol):
    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def execute(
        self,
        request: AlpacaPaperOrderSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperOrderSnapshotTransportResponse: ...


class _HttpxAlpacaPaperOrderSnapshotTransport:
    """TLS-verifying, no-redirect, no-proxy order-page-only transport."""

    __slots__ = ()

    @property
    def transport_id(self) -> str:
        return ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION

    def execute(
        self,
        request: AlpacaPaperOrderSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperOrderSnapshotTransportResponse:
        if type(request) is not AlpacaPaperOrderSnapshotTransportRequest:
            raise AlpacaPaperOrderSnapshotTransportError(
                "strict order-snapshot transport requires an exact request"
            )
        request.__post_init__()
        if type(headers) is not _AlpacaPaperAuthenticationHeaders:
            raise AlpacaPaperOrderSnapshotTransportError(
                "strict order-snapshot transport requires redacted auth headers"
            )
        if tuple(headers) != ALPACA_AUTH_HEADER_NAMES:
            raise AlpacaPaperOrderSnapshotTransportError(
                "strict order-snapshot transport requires exact auth headers"
            )
        timeout_seconds = request.httpx_phase_timeout.total_seconds()
        result: AlpacaPaperOrderSnapshotTransportResponse | None = None
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
                        "Accept": ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE,
                        "Accept-Encoding": "identity",
                        "User-Agent": (
                            f"autoquant-trader/{ALPACA_PAPER_ADAPTER_VERSION} "
                            "phase4o-order-snapshot-page"
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
                    if len(body) + len(chunk) > ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES:
                        raise AlpacaPaperOrderSnapshotTransportError(
                            "order-snapshot response exceeds the durable raw bound"
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
                    raise AlpacaPaperOrderSnapshotTransportError(
                        "order-snapshot response changed the fixed request target"
                    )
                result = AlpacaPaperOrderSnapshotTransportResponse(
                    request_sha256=request.semantic_sha256,
                    transport_id=self.transport_id,
                    transport_version=self.transport_version,
                    http_status=response.status_code,
                    provider_request_id=request_id,
                    media_type=media_type,
                    response_body=bytes(body),
                )
        except AlpacaPaperOrderSnapshotTransportError:
            raise
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise AlpacaPaperOrderSnapshotTransportError(
                "authenticated Alpaca order-snapshot request failed without a retained response"
            ) from None
        if result is None:
            raise AlpacaPaperOrderSnapshotTransportError(
                "authenticated Alpaca order-snapshot request produced no response"
            )
        return result


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedOrderSnapshotPageEvidence(_NoOrderSnapshotRuntimeAuthority):
    """Complete transient proof for one retained and authenticated page."""

    reference: AlpacaPaperCredentialReference
    credential_receipt: AlpacaPaperCredentialResolutionReceipt
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    description: AlpacaPaperOrderSnapshotPageDescription
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    permit_freshness: BrokerRequestPermitFreshnessReceipt
    pre_fence_receipt: AccountFenceReceipt
    request: AlpacaPaperOrderSnapshotTransportRequest
    response: AlpacaPaperOrderSnapshotTransportResponse
    persisted_page: PersistedAlpacaPaperOrderSnapshotPage
    post_fence_receipt: AccountFenceReceipt
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    authenticated_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedOrderSnapshotPageEvidence must be proof-constructed"
        )

    def _validate(self) -> None:
        exact_types = (
            (
                self.reference,
                AlpacaPaperCredentialReference,
                "credential reference",
            ),
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
                AlpacaPaperOrderSnapshotPageDescription,
                "page description",
            ),
            (
                self.preparation,
                AlpacaPaperOrderSnapshotPagePreparationReceipt,
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
                AlpacaPaperOrderSnapshotTransportRequest,
                "transport request",
            ),
            (
                self.response,
                AlpacaPaperOrderSnapshotTransportResponse,
                "transport response",
            ),
            (
                self.persisted_page,
                PersistedAlpacaPaperOrderSnapshotPage,
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
                raise AlpacaPaperOrderSnapshotConflict(
                    f"authenticated order snapshot requires an exact {field_name}"
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
        _require_utc(self.authenticated_at, "order-snapshot authenticated_at")

        if self.credential_receipt.reference != self.reference:
            raise AlpacaPaperOrderSnapshotConflict(
                "credential receipt does not bind the exact reference"
            )
        if (
            self.description.plan.account_id != self.reference.account_id
            or self.description.plan.account_id != self.account_binding.account_id
        ):
            raise AlpacaPaperOrderSnapshotConflict("order-snapshot page crosses account identities")
        if self.preparation.description != self.description:
            raise AlpacaPaperOrderSnapshotConflict(
                "durable page preparation names another description"
            )
        if self.policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY:
            raise AlpacaPaperOrderSnapshotConflict(
                "order snapshot requires the exact fixed request-budget policy"
            )

        expected_demand = create_alpaca_paper_order_snapshot_page_demand(
            self.description,
            requested_at=self.demand.requested_at,
        )
        if (
            self.demand != expected_demand
            or self.demand.purpose is not BrokerRequestPurpose.RECONCILIATION
            or self.demand.idempotency_key
            != alpaca_paper_order_snapshot_page_delivery_idempotency_key(self.description)
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "request demand does not bind the exact reconciliation page"
            )
        if (
            self.permit.account_id != self.demand.account_id
            or self.permit.purpose is not self.demand.purpose
            or self.permit.demand_id != self.demand.demand_id
            or self.permit.demand_sha256 != self.demand.semantic_sha256
            or self.permit.policy_sha256 != self.policy.semantic_sha256
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "request permit does not bind the exact page demand"
            )
        if (
            self.permit_freshness.permit_id != self.permit.permit_id
            or self.permit_freshness.permit_sha256 != self.permit.semantic_sha256
            or self.permit_freshness.policy_sha256 != self.policy.semantic_sha256
            or self.permit_freshness.demand_sha256 != self.demand.semantic_sha256
            or self.permit_freshness.expires_at != self.permit.expires_at
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "permit freshness does not bind the exact request permit"
            )
        try:
            require_fresh_broker_request_permit(
                permit=self.permit,
                policy=self.policy,
                demand=self.demand,
                checked_at=self.permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperOrderSnapshotConflict(
                "request permit was not freshly authenticated"
            ) from error

        pre_fence = self.pre_fence_receipt.fence
        post_fence = self.post_fence_receipt.fence
        if pre_fence != post_fence or pre_fence.account_id != self.description.plan.account_id:
            raise AlpacaPaperOrderSnapshotConflict(
                "account fence changed around order-snapshot transport"
            )

        expected_request = AlpacaPaperOrderSnapshotTransportRequest(
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
            raise AlpacaPaperOrderSnapshotConflict(
                "transport request does not bind the exact authenticated inputs"
            )
        if (
            self.response.request_sha256 != self.request.semantic_sha256
            or self.response.transport_id != ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID
            or self.response.transport_version != ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION
            or self.response.media_type != ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "transport response conflicts with the restricted request"
            )

        observation = self.persisted_page.observation
        raw_receipt = self.persisted_page.receipt
        delivery = raw_receipt.delivery
        if (
            observation.description != self.description
            or observation.http_status != self.response.http_status
            or observation.provider_request_id != self.response.provider_request_id
            or observation.response_body != self.response.response_body
            or delivery.media_type != self.response.media_type
            or delivery.received_at != observation.received_at
            or delivery.delivery_idempotency_key
            != alpaca_paper_order_snapshot_page_delivery_idempotency_key(self.description)
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "persisted page conflicts with the exact transport response"
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
            raise AlpacaPaperOrderSnapshotConflict(
                "authenticated order-snapshot time order is inconsistent"
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
            raise AlpacaPaperOrderSnapshotConflict(
                "order-snapshot transport authority was not current at its bound"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "authenticated_order_snapshot_page_evidence",
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
            self.converged,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def evidence_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-order-snapshot-page-evidence",
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
    def authenticated_order_snapshot_page_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_order_snapshot_page_evidence(
    *,
    reference: AlpacaPaperCredentialReference,
    credential_receipt: AlpacaPaperCredentialResolutionReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    description: AlpacaPaperOrderSnapshotPageDescription,
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    permit_freshness: BrokerRequestPermitFreshnessReceipt,
    pre_fence_receipt: AccountFenceReceipt,
    request: AlpacaPaperOrderSnapshotTransportRequest,
    response: AlpacaPaperOrderSnapshotTransportResponse,
    persisted_page: PersistedAlpacaPaperOrderSnapshotPage,
    post_fence_receipt: AccountFenceReceipt,
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    authenticated_at: datetime,
) -> AlpacaPaperAuthenticatedOrderSnapshotPageEvidence:
    evidence = object.__new__(AlpacaPaperAuthenticatedOrderSnapshotPageEvidence)
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
class AlpacaPaperAuthenticatedOrderSnapshotPageReceipt(_NoOrderSnapshotRuntimeAuthority):
    """Durable commit proof for one authenticated page."""

    evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence
    commit_fence_receipt: AccountFenceReceipt
    previous_page_receipt_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedOrderSnapshotPageReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.evidence) is not AlpacaPaperAuthenticatedOrderSnapshotPageEvidence:
            raise AlpacaPaperOrderSnapshotConflict(
                "page receipt requires exact authenticated evidence"
            )
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperOrderSnapshotConflict("page receipt requires an exact commit fence")
        self.evidence._validate()
        self.commit_fence_receipt._validate()
        post_fence = self.evidence.post_fence_receipt
        if (
            self.commit_fence_receipt.fence != post_fence.fence
            or self.commit_fence_receipt.policy_sha256 != post_fence.policy_sha256
            or self.commit_fence_receipt.lease_sha256 != post_fence.lease_sha256
            or self.commit_fence_receipt.valid_until != post_fence.valid_until
            or self.commit_fence_receipt.validated_at < self.evidence.authenticated_at
            or self.commit_fence_receipt.validated_at >= self.commit_fence_receipt.valid_until
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "commit fence does not continue the exact post-request lease"
            )
        if self.page_number == 1:
            if self.previous_page_receipt_sha256 is not None:
                raise AlpacaPaperOrderSnapshotConflict(
                    "first authenticated page cannot name a predecessor"
                )
        else:
            _require_sha256(
                self.previous_page_receipt_sha256,
                "authenticated page predecessor digest",
            )
            if (
                self.previous_page_receipt_sha256
                != self.evidence.preparation.previous_page_receipt_sha256
            ):
                raise AlpacaPaperOrderSnapshotConflict(
                    "authenticated page predecessor conflicts with preparation"
                )

    @property
    def plan(self) -> AlpacaPaperOrderSnapshotPlan:
        return self.evidence.description.plan

    @property
    def description(self) -> AlpacaPaperOrderSnapshotPageDescription:
        return self.evidence.description

    @property
    def persisted_page(self) -> PersistedAlpacaPaperOrderSnapshotPage:
        return self.evidence.persisted_page

    @property
    def account_id(self) -> str:
        return self.plan.account_id

    @property
    def page_number(self) -> int:
        return self.description.page_number

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "authenticated_order_snapshot_page_receipt",
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
            "alpaca-paper-authenticated-order-snapshot-page",
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
    def authenticated_order_snapshot_page_established(self) -> bool:
        return True

    @property
    def committed_prefix_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_order_snapshot_page_receipt(
    evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    *,
    commit_fence_receipt: AccountFenceReceipt,
    previous_page_receipt_sha256: str | None,
) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
    receipt = object.__new__(AlpacaPaperAuthenticatedOrderSnapshotPageReceipt)
    for field_name, value in (
        ("evidence", evidence),
        ("commit_fence_receipt", commit_fence_receipt),
        ("previous_page_receipt_sha256", previous_page_receipt_sha256),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


def _capture_from_authenticated_page_receipts(
    plan: AlpacaPaperOrderSnapshotPlan,
    page_receipts: tuple[AlpacaPaperAuthenticatedOrderSnapshotPageReceipt, ...],
) -> AlpacaPaperOrderSnapshotCapture:
    capture = start_alpaca_paper_order_snapshot(plan)
    previous: AlpacaPaperAuthenticatedOrderSnapshotPageReceipt | None = None
    for expected_page_number, receipt in enumerate(page_receipts, start=1):
        if type(receipt) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
            raise AlpacaPaperOrderSnapshotConflict(
                "authenticated prefix contains an invalid page receipt"
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
            raise AlpacaPaperOrderSnapshotConflict(
                "authenticated prefix is not the exact gap-free Phase 4M chain"
            )
        expected_previous_id = None if previous is None else previous.receipt_id
        expected_previous_sha256 = None if previous is None else previous.semantic_sha256
        if (
            receipt.evidence.preparation.previous_page_receipt_id != expected_previous_id
            or receipt.evidence.preparation.previous_page_receipt_sha256 != expected_previous_sha256
            or receipt.previous_page_receipt_sha256 != expected_previous_sha256
        ):
            raise AlpacaPaperOrderSnapshotConflict(
                "authenticated prefix receipt lineage is inconsistent"
            )
        capture = append_alpaca_paper_order_snapshot_page(
            capture,
            receipt.persisted_page,
        )
        previous = receipt
    return capture


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedOrderSnapshotPrefix(_NoOrderSnapshotRuntimeAuthority):
    """An exact durable prefix of authenticated Phase 4O page receipts."""

    plan: AlpacaPaperOrderSnapshotPlan
    page_receipts: tuple[AlpacaPaperAuthenticatedOrderSnapshotPageReceipt, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedOrderSnapshotPrefix must be repository-produced")

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperOrderSnapshotPlan:
            raise AlpacaPaperOrderSnapshotConflict("authenticated prefix requires an exact plan")
        self.plan.__post_init__()
        if type(self.page_receipts) is not tuple:
            raise AlpacaPaperOrderSnapshotConflict(
                "authenticated prefix page receipts must be an exact tuple"
            )
        _capture_from_authenticated_page_receipts(
            self.plan,
            self.page_receipts,
        )

    @property
    def capture(self) -> AlpacaPaperOrderSnapshotCapture:
        self._validate()
        return _capture_from_authenticated_page_receipts(
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
    ) -> AlpacaPaperOrderSnapshotPageDescription | None:
        return self.capture.next_page_description

    def _semantic_material(self) -> tuple[object, ...]:
        capture = _capture_from_authenticated_page_receipts(
            self.plan,
            self.page_receipts,
        )
        return (
            ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "authenticated_order_snapshot_prefix",
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
            "alpaca-paper-authenticated-order-snapshot-prefix",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def committed_prefix_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_order_snapshot_prefix(
    plan: AlpacaPaperOrderSnapshotPlan,
    *,
    page_receipts: tuple[AlpacaPaperAuthenticatedOrderSnapshotPageReceipt, ...],
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    prefix = object.__new__(AlpacaPaperAuthenticatedOrderSnapshotPrefix)
    object.__setattr__(prefix, "plan", plan)
    object.__setattr__(prefix, "page_receipts", page_receipts)
    prefix._validate()
    return prefix


class AlpacaPaperOrderSnapshotPageRuntimePort(Protocol):
    """Atomic durable operations needed around one page request.

    ``prepare_next`` is a fresh single-use claim operation. The transaction
    that first persists a preparation may return it; every later call for that
    unresolved preparation must raise before credentials, request admission,
    or transport. A conforming port must never return an existing stalled
    preparation to another or restarted caller.
    """

    def prepare_next(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperOrderSnapshotPagePreparationReceipt: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt: ...

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix: ...


def _revalidate_fence(
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    *,
    phase: str,
) -> AccountFenceReceipt:
    failed = False
    result: object | None = None
    try:
        result = coordinator.revalidate(fence)
    except Exception:
        failed = True
    if failed:
        raise AlpacaPaperOrderSnapshotConflict(
            f"account fence authentication failed {phase} order-snapshot transport"
        ) from None
    if type(result) is not AccountFenceReceipt:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            f"account coordinator returned invalid {phase} page evidence"
        )
    result._validate()
    if result.fence != fence:
        raise AlpacaPaperOrderSnapshotConflict(
            f"account fence changed {phase} order-snapshot transport"
        )
    return result


def _authenticate_account_binding_identity(
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    checked_at: datetime,
    phase: str,
) -> AlpacaPaperAccountIdentityContinuityReceipt:
    failed = False
    result: object | None = None
    try:
        result = account_bindings.authenticate_terminal_identity(
            account_binding,
            checked_at,
        )
    except Exception:
        failed = True
    if failed:
        raise AlpacaPaperOrderSnapshotConflict(
            f"terminal account identity authentication failed {phase} order-snapshot transport"
        ) from None
    if type(result) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            f"account identity repository returned invalid {phase} evidence"
        )
    _validate_account_identity(result, account_binding, phase=phase)
    if result.checked_at != checked_at:
        raise AlpacaPaperOrderSnapshotConflict(
            f"account identity repository used another {phase} check instant"
        )
    return result


def _validate_issued_permit(
    permit: object,
    demand: BrokerRequestDemand,
) -> BrokerRequestPermit:
    if type(permit) is not BrokerRequestPermit:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            "durable budget issuer returned an invalid page permit"
        )
    permit.__post_init__()
    if (
        permit.account_id != demand.account_id
        or permit.purpose is not BrokerRequestPurpose.RECONCILIATION
        or permit.demand_id != demand.demand_id
        or permit.demand_sha256 != demand.semantic_sha256
        or permit.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
    ):
        raise AlpacaPaperOrderSnapshotConflict(
            "durable budget issuer returned a permit for another demand"
        )
    return permit


def _authenticate_page_permit(
    budget: BrokerRequestBudgetRuntimePort,
    permit: BrokerRequestPermit,
    demand: BrokerRequestDemand,
) -> BrokerRequestPermitFreshnessReceipt:
    failed = False
    result: object | None = None
    try:
        result = budget.authenticate_fresh(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
    except Exception:
        failed = True
    if failed:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable page permit authentication failed before transport"
        ) from None
    if type(result) is not BrokerRequestPermitFreshnessReceipt:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            "budget authenticator returned invalid page freshness"
        )
    result._validate()
    if (
        result.permit_id != permit.permit_id
        or result.permit_sha256 != permit.semantic_sha256
        or result.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
        or result.demand_sha256 != demand.semantic_sha256
        or result.expires_at != permit.expires_at
    ):
        raise AlpacaPaperOrderSnapshotConflict(
            "durable permit freshness receipt conflicts before page transport"
        )
    try:
        require_fresh_broker_request_permit(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            checked_at=result.checked_at,
        )
    except ValueError as error:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable order-snapshot page permit is invalid before transport"
        ) from error
    return result


def _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport(
    *,
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperOrderSnapshotPageDescription,
    credential_resolver: AlpacaPaperOrderSnapshotCredentialResolver,
    transport: _AlpacaPaperOrderSnapshotTransport,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    page_runtime: AlpacaPaperOrderSnapshotPageRuntimePort,
    clock: Clock,
) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
    """Trusted test seam; execute and commit exactly one prepared page."""

    _validate_reference_binding(reference, account_binding)
    if type(description) is not AlpacaPaperOrderSnapshotPageDescription:
        raise AlpacaPaperOrderSnapshotConflict(
            "order-snapshot runtime requires an exact page description"
        )
    description.__post_init__()
    if description.plan.account_id != reference.account_id:
        raise AlpacaPaperOrderSnapshotConflict(
            "order-snapshot description belongs to another account"
        )
    if type(fence) is not AccountFence or fence.account_id != reference.account_id:
        raise AlpacaPaperOrderSnapshotConflict(
            "order-snapshot runtime requires the current exact account fence"
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
            "terminal account-identity authenticator",
        ),
        (coordinator, "revalidate", "account coordinator"),
        (ingress_recorder, "record", "raw ingress recorder"),
        (transport, "execute", "restricted order-snapshot transport"),
    ):
        if not callable(getattr(port, method_name, None)):
            raise AlpacaPaperOrderSnapshotRuntimeError(
                f"order-snapshot runtime requires a {field_name}"
            )
    if getattr(coordinator, "account_id", None) != reference.account_id:
        raise AlpacaPaperOrderSnapshotConflict(
            "order-snapshot coordinator belongs to another account"
        )
    if (
        getattr(transport, "transport_id", None) != ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID
        or getattr(transport, "transport_version", None)
        != ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION
    ):
        raise AlpacaPaperOrderSnapshotTransportError(
            "order-snapshot runtime requires the exact restricted transport"
        )

    # Preparation is deliberately the first durable operation.  A duplicate,
    # stale, terminal, or concurrently claimed page fails before secret access
    # and before a non-refundable request permit is allocated.
    prepared_at = _trusted_now(clock, "order-snapshot preparation checked_at")
    preparation_failed = False
    preparation_value: object | None = None
    try:
        preparation_value = page_runtime.prepare_next(
            description,
            checked_at=prepared_at,
        )
    except Exception:
        preparation_failed = True
    if preparation_failed:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable next-page preparation failed before credential resolution"
        ) from None
    if type(preparation_value) is not AlpacaPaperOrderSnapshotPagePreparationReceipt:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            "durable page preparer returned invalid evidence"
        )
    preparation = preparation_value
    preparation._validate()
    if preparation.description != description or preparation.prepared_at > prepared_at:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable preparation does not bind the exact requested page"
        )
    prefix_failed = False
    prefix_value: object | None = None
    try:
        prefix_value = page_runtime.load_prefix(description.plan)
    except Exception:
        prefix_failed = True
    if prefix_failed:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable order-snapshot prefix authentication failed before credential resolution"
        ) from None
    if type(prefix_value) is not AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            "durable prefix loader returned invalid evidence"
        )
    prefix = prefix_value
    prefix._validate()
    previous_receipt = None if not prefix.page_receipts else prefix.page_receipts[-1]
    if (
        prefix.plan != description.plan
        or prefix.next_page_description != description
        or preparation.prefix_capture_sha256 != prefix.capture.semantic_sha256
        or preparation.prefix_page_count != prefix.page_count
        or preparation.previous_page_receipt_id
        != (None if previous_receipt is None else previous_receipt.receipt_id)
        or preparation.previous_page_receipt_sha256
        != (None if previous_receipt is None else previous_receipt.semantic_sha256)
    ):
        raise AlpacaPaperOrderSnapshotConflict(
            "durable preparation conflicts with its authenticated committed prefix"
        )

    requested_at = _trusted_now(clock, "order-snapshot requested_at")
    demand = create_alpaca_paper_order_snapshot_page_demand(
        description,
        requested_at=requested_at,
    )
    credential_session = _resolve_alpaca_paper_credentials_for_operation(
        reference=reference,
        resolver=credential_resolver,
        resolver_method_name="_resolve_for_order_snapshot_page",
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
        pre_account_checked_at = _trusted_now(
            clock,
            "pre-order-snapshot account identity checked_at",
        )
        pre_account_identity = _authenticate_account_binding_identity(
            account_bindings,
            account_binding,
            checked_at=pre_account_checked_at,
            phase="before",
        )
        started_at = _trusted_now(
            clock,
            "order-snapshot transport started_at",
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
            raise AlpacaPaperOrderSnapshotConflict(
                "page authority is not current at transport start"
            )
        request = AlpacaPaperOrderSnapshotTransportRequest(
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
        response_value: object | None = None
        transport_failed = False
        try:
            response_value = transport.execute(request, headers)
        except Exception:
            transport_failed = True
        if transport_failed:
            raise AlpacaPaperOrderSnapshotTransportError(
                "restricted order-snapshot transport failed with sanitized diagnostics"
            ) from None
        received_at = _trusted_now(
            clock,
            "order-snapshot transport received_at",
        )
    finally:
        credential_session.close()

    if type(response_value) is not AlpacaPaperOrderSnapshotTransportResponse:
        raise AlpacaPaperOrderSnapshotTransportError(
            "order-snapshot transport returned an invalid response"
        )
    response = response_value
    response.__post_init__()
    if (
        response.request_sha256 != request.semantic_sha256
        or response.transport_id != ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID
        or response.transport_version != ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION
    ):
        raise AlpacaPaperOrderSnapshotTransportError(
            "order-snapshot transport response binds another request or profile"
        )
    if received_at < started_at or received_at >= credential_session.receipt.valid_until:
        raise AlpacaPaperOrderSnapshotConflict(
            "order-snapshot response completed outside its credential bound"
        )

    recorded_at = _trusted_now(
        clock,
        "order-snapshot raw response recorded_at",
    )
    if recorded_at < received_at:
        raise AlpacaPaperOrderSnapshotRuntimeError("order-snapshot raw-record clock regressed")
    persisted_page = persist_then_decode_alpaca_paper_order_snapshot_page(
        ingress_recorder,
        description,
        delivery_idempotency_key=(
            alpaca_paper_order_snapshot_page_delivery_idempotency_key(description)
        ),
        http_status=response.http_status,
        provider_request_id=response.provider_request_id,
        response_body=response.response_body,
        received_at=received_at,
        recorded_at=recorded_at,
        media_type=response.media_type,
    )
    if response.media_type != ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE:
        raise AlpacaPaperOrderSnapshotConflict(
            "order-snapshot response media type is not the exact JSON profile after raw persistence"
        )

    post_fence_receipt = _revalidate_fence(
        coordinator,
        fence,
        phase="after",
    )
    post_account_checked_at = _trusted_now(
        clock,
        "post-order-snapshot account identity checked_at",
    )
    post_account_identity = _authenticate_account_binding_identity(
        account_bindings,
        account_binding,
        checked_at=post_account_checked_at,
        phase="after",
    )
    authenticated_at = _trusted_now(
        clock,
        "order-snapshot authenticated_at",
    )
    evidence = _alpaca_paper_authenticated_order_snapshot_page_evidence(
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

    record_failed = False
    receipt_value: object | None = None
    try:
        receipt_value = page_runtime.record(evidence)
    except Exception:
        record_failed = True
    if record_failed:
        raise AlpacaPaperOrderSnapshotConflict("durable authenticated page commit failed") from None
    if type(receipt_value) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        raise AlpacaPaperOrderSnapshotRuntimeError(
            "durable page recorder returned an invalid receipt"
        )
    receipt = receipt_value
    receipt._validate()
    if receipt.evidence != evidence:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable page receipt does not bind the exact runtime evidence"
        )
    expected_receipt = _alpaca_paper_authenticated_order_snapshot_page_receipt(
        evidence,
        commit_fence_receipt=receipt.commit_fence_receipt,
        previous_page_receipt_sha256=(receipt.previous_page_receipt_sha256),
    )
    if receipt != expected_receipt:
        raise AlpacaPaperOrderSnapshotConflict(
            "durable page receipt conflicts with the exact runtime evidence"
        )
    return receipt


def observe_authenticated_alpaca_paper_order_snapshot_page(
    *,
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperOrderSnapshotPageDescription,
    credential_resolver: AlpacaPaperOrderSnapshotCredentialResolver,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    page_runtime: AlpacaPaperOrderSnapshotPageRuntimePort,
    clock: Clock,
) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
    """Execute the exact production page GET and commit scoped evidence."""

    return _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport(
        reference=reference,
        account_binding=account_binding,
        description=description,
        credential_resolver=credential_resolver,
        transport=_HttpxAlpacaPaperOrderSnapshotTransport(),
        budget=budget,
        account_bindings=account_bindings,
        coordinator=coordinator,
        fence=fence,
        ingress_recorder=ingress_recorder,
        page_runtime=page_runtime,
        clock=clock,
    )


__all__ = [
    "ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE",
    "ALPACA_PAPER_ORDER_SNAPSHOT_HTTPX_PHASE_TIMEOUT",
    "ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID",
    "ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION",
    "AlpacaPaperAuthenticatedOrderSnapshotPageEvidence",
    "AlpacaPaperAuthenticatedOrderSnapshotPageReceipt",
    "AlpacaPaperAuthenticatedOrderSnapshotPrefix",
    "AlpacaPaperOrderSnapshotConflict",
    "AlpacaPaperOrderSnapshotCredentialResolver",
    "AlpacaPaperOrderSnapshotPagePreparationReceipt",
    "AlpacaPaperOrderSnapshotPageRuntimePort",
    "AlpacaPaperOrderSnapshotRuntimeError",
    "AlpacaPaperOrderSnapshotTransportError",
    "AlpacaPaperOrderSnapshotTransportRequest",
    "AlpacaPaperOrderSnapshotTransportResponse",
    "alpaca_paper_order_snapshot_page_delivery_idempotency_key",
    "observe_authenticated_alpaca_paper_order_snapshot_page",
]
