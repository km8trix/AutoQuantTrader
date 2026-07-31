"""Authenticated single-use runtime for one Alpaca paper position capture.

The runtime binds the Phase 4R request description to one credential reference
and one terminal Phase 4G account binding.  A durable repository must claim the
capture before credentials or request capacity are touched.  The one strict
``GET /v2/positions`` response is retained raw-first, fenced and
account-identity checked around I/O, committed, then reloaded exactly.

Authenticated bytes remain historical reconciliation input only.  They do not
establish provider snapshot completeness, canonical positions, convergence,
reconciliation completion, readiness, lifecycle authority, or trading
authority.
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
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.adapters.broker.alpaca_paper_positions import (
    ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES,
    AlpacaPaperPositionSnapshotDescription,
    AlpacaPaperPositionSnapshotError,
    PersistedAlpacaPaperPositionSnapshot,
    persist_then_decode_alpaca_paper_position_snapshot_response,
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

ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION = (
    "phase4t-authenticated-single-use-position-snapshot-v1"
)
ALPACA_PAPER_POSITION_SNAPSHOT_HTTPX_PHASE_TIMEOUT = ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT
ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE = ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID = "strict-httpx-alpaca-paper-position-snapshot"
ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION = "1.0.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AlpacaPaperPositionSnapshotRuntimeError(AlpacaPaperContractError):
    """Authenticated position-snapshot runtime evidence is malformed."""


class AlpacaPaperPositionSnapshotTransportError(AlpacaPaperPositionSnapshotRuntimeError):
    """The exact restricted position-snapshot transport failed."""


class AlpacaPaperPositionSnapshotConflict(AlpacaPaperPositionSnapshotRuntimeError):
    """Position-snapshot evidence conflicts with a durable authority."""


class _NoPositionSnapshotRuntimeAuthority:
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
    def fresh_single_use_claim_established(self) -> bool:
        return False

    @property
    def authenticated_position_snapshot_established(self) -> bool:
        return False

    @property
    def durable_authenticated_position_snapshot_established(self) -> bool:
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
    def snapshot_complete(self) -> bool:
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
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def reconciliation_complete(self) -> bool:
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
    def canonical_position_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_ledger_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_cash_fact_authorized(self) -> bool:
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
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
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
        raise AlpacaPaperPositionSnapshotRuntimeError(
            f"{field_name} must be bounded, non-empty trimmed text"
        )
    return value


def _require_safe_text(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if _SAFE_TEXT.fullmatch(text) is None:
        raise AlpacaPaperPositionSnapshotRuntimeError(f"{field_name} is not canonical safe text")
    return text


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperPositionSnapshotRuntimeError(f"{field_name} must be a lowercase SHA-256")
    return value


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperPositionSnapshotRuntimeError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperPositionSnapshotRuntimeError(str(error)) from error
    return value


def _trusted_now(clock: Clock, field_name: str) -> datetime:
    try:
        now_method = clock.now
    except Exception:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "position-snapshot trusted clock access failed"
        ) from None
    if not callable(now_method):
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "position-snapshot runtime requires a trusted clock"
        )
    try:
        instant = now_method()
    except Exception:
        raise AlpacaPaperPositionSnapshotRuntimeError(f"{field_name} clock failed") from None
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


def _validate_reference_binding(
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
) -> None:
    if type(reference) is not AlpacaPaperCredentialReference:
        raise AlpacaPaperPositionSnapshotConflict(
            "position snapshot requires an exact credential reference"
        )
    if type(account_binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperPositionSnapshotConflict(
            "position snapshot requires an exact authenticated account binding"
        )
    try:
        reference.__post_init__()
        account_binding._validate()
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "position snapshot credential or account binding is malformed"
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
        raise AlpacaPaperPositionSnapshotConflict(
            "credential reference conflicts with the authenticated account binding"
        )


def _validate_account_identity(
    identity: AlpacaPaperAccountIdentityContinuityReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    phase: str,
) -> None:
    if type(identity) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperPositionSnapshotConflict(
            f"{phase} account identity must be exact repository evidence"
        )
    try:
        identity._validate()
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
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
        raise AlpacaPaperPositionSnapshotConflict(
            f"{phase} account identity conflicts with the exact terminal binding"
        )


@dataclass(frozen=True, slots=True)
class AlpacaPaperPositionSnapshotRuntimePlan(_NoPositionSnapshotRuntimeAuthority):
    """Exact one-shot runtime plan for one Phase 4R capture identity."""

    description: AlpacaPaperPositionSnapshotDescription
    reference: AlpacaPaperCredentialReference
    account_binding: AlpacaPaperAuthenticatedAccountBinding

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperPositionSnapshotDescription:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot runtime plan requires an exact Phase 4R description"
            )
        try:
            self.description.__post_init__()
        except Exception:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot runtime description is malformed"
            ) from None
        _validate_reference_binding(self.reference, self.account_binding)
        if self.description.account_id != self.reference.account_id:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot runtime plan crosses account identities"
            )

    @property
    def plan_id(self) -> str:
        self.__post_init__()
        return canonical_id(
            "alpaca-paper-position-snapshot-runtime-plan",
            self.description.capture_id,
            self.reference.semantic_sha256,
            self.account_binding.semantic_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "position_snapshot_runtime_plan",
            self.plan_id,
            self.description.semantic_sha256,
            self.reference.semantic_sha256,
            self.account_binding.semantic_sha256,
            self.account_binding.binding_id,
            self.account_binding.sequence_number,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def create_alpaca_paper_position_snapshot_runtime_plan(
    *,
    description: AlpacaPaperPositionSnapshotDescription,
    reference: AlpacaPaperCredentialReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    """Bind one offline description to exact authenticated runtime identities."""

    return AlpacaPaperPositionSnapshotRuntimePlan(
        description=description,
        reference=reference,
        account_binding=account_binding,
    )


def create_alpaca_paper_position_snapshot_demand(
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Create one new reconciliation-purpose demand for the one-shot capture."""

    if type(plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot demand requires an exact runtime plan"
        )
    plan.__post_init__()
    return create_alpaca_paper_request_demand(
        account_id=plan.description.account_id,
        idempotency_key=plan.description.capture_idempotency_key,
        operation=AlpacaPaperBudgetOperation.RECONCILE_ACCOUNT,
        correlation_sha256=plan.semantic_sha256,
        requested_at=requested_at,
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionSnapshotPreparationReceipt(_NoPositionSnapshotRuntimeAuthority):
    """Repository proof that this exact capture received a fresh one-shot claim."""

    plan: AlpacaPaperPositionSnapshotRuntimePlan
    prepared_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperPositionSnapshotPreparationReceipt must be repository-produced")

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot preparation requires an exact runtime plan"
            )
        self.plan.__post_init__()
        _require_utc(self.prepared_at, "position-snapshot preparation prepared_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "position_snapshot_single_use_preparation",
            self.plan.semantic_sha256,
            self.plan.description.capture_id,
            self.prepared_at,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def preparation_id(self) -> str:
        return canonical_id(
            "alpaca-paper-position-snapshot-preparation",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def fresh_single_use_claim_established(self) -> bool:
        return True


def _alpaca_paper_position_snapshot_preparation_receipt(
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    prepared_at: datetime,
) -> AlpacaPaperPositionSnapshotPreparationReceipt:
    receipt = object.__new__(AlpacaPaperPositionSnapshotPreparationReceipt)
    object.__setattr__(receipt, "plan", plan)
    object.__setattr__(receipt, "prepared_at", prepared_at)
    receipt._validate()
    return receipt


class AlpacaPaperPositionSnapshotCredentialResolver(Protocol):
    """Secret-read authority restricted to one Phase 4T capture."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_position_snapshot(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class AlpacaPaperPositionSnapshotTransportRequest(_NoPositionSnapshotRuntimeAuthority):
    """Secret-free description of one exact preauthorized positions GET."""

    plan: AlpacaPaperPositionSnapshotRuntimePlan
    preparation_sha256: str
    pre_account_identity_sha256: str
    demand_sha256: str
    permit_sha256: str
    permit_freshness_sha256: str
    pre_fence_receipt_sha256: str
    started_at: datetime
    httpx_phase_timeout: timedelta = ALPACA_PAPER_POSITION_SNAPSHOT_HTTPX_PHASE_TIMEOUT

    def __post_init__(self) -> None:
        if type(self.plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot transport requires an exact runtime plan"
            )
        self.plan.__post_init__()
        for value, field_name in (
            (self.preparation_sha256, "preparation"),
            (self.pre_account_identity_sha256, "pre-request account identity"),
            (self.demand_sha256, "request demand"),
            (self.permit_sha256, "request permit"),
            (self.permit_freshness_sha256, "permit freshness"),
            (self.pre_fence_receipt_sha256, "pre-request fence"),
        ):
            _require_sha256(
                value,
                f"position-snapshot transport {field_name} digest",
            )
        _require_utc(self.started_at, "position-snapshot transport started_at")
        if (
            type(self.httpx_phase_timeout) is not timedelta
            or self.httpx_phase_timeout != ALPACA_PAPER_POSITION_SNAPSHOT_HTTPX_PHASE_TIMEOUT
        ):
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot transport must use the fixed I/O timeout"
            )
        description = self.plan.description
        if (
            description.method != "GET"
            or description.base_url != ALPACA_PAPER_TRADING_BASE_URL
            or description.path != ALPACA_PAPER_CAPABILITIES.positions_path
            or description.request_target != description.path
            or dict(description.query)
        ):
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot request escaped the frozen GET /v2/positions"
            )

    @property
    def method(self) -> str:
        return "GET"

    @property
    def url(self) -> str:
        return f"{self.plan.description.base_url}{self.plan.description.request_target}"

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
                "position_snapshot_transport_request",
                self.plan.semantic_sha256,
                self.preparation_sha256,
                self.pre_account_identity_sha256,
                self.demand_sha256,
                self.permit_sha256,
                self.permit_freshness_sha256,
                self.pre_fence_receipt_sha256,
                self.started_at,
                int(self.httpx_phase_timeout.total_seconds() * 1_000_000),
                self.method,
                self.url,
            )
        )


@dataclass(frozen=True, slots=True)
class AlpacaPaperPositionSnapshotTransportResponse(_NoPositionSnapshotRuntimeAuthority):
    """Bounded exact entity bytes from one restricted positions GET."""

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
            "position-snapshot response request digest",
        )
        _require_safe_text(self.transport_id, "position-snapshot transport ID")
        _require_safe_text(
            self.transport_version,
            "position-snapshot transport version",
        )
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot response status must be an exact HTTP status"
            )
        if self.provider_request_id is not None:
            _require_text(
                self.provider_request_id,
                "position-snapshot X-Request-ID",
                maximum=256,
            )
        if self.media_type is not None:
            _require_text(
                self.media_type,
                "position-snapshot response media type",
                maximum=128,
            )
        if type(self.response_body) is not bytes:
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot response body must be exact bytes"
            )
        if len(self.response_body) > ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES:
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot response exceeds the durable raw bound"
            )
        if type(self.tls_verified) is not bool or not self.tls_verified:
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot transport must verify TLS"
            )
        if type(self.redirects_followed) is not bool or self.redirects_followed:
            raise AlpacaPaperPositionSnapshotTransportError(
                "position-snapshot transport cannot follow redirects"
            )

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
                "position_snapshot_transport_response",
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


class _AlpacaPaperPositionSnapshotTransport(Protocol):
    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def execute(
        self,
        request: AlpacaPaperPositionSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperPositionSnapshotTransportResponse: ...


class _HttpxAlpacaPaperPositionSnapshotTransport:
    """TLS-verifying, no-redirect, no-proxy position-only transport."""

    __slots__ = ()

    @property
    def transport_id(self) -> str:
        return ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION

    def execute(
        self,
        request: AlpacaPaperPositionSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperPositionSnapshotTransportResponse:
        if type(request) is not AlpacaPaperPositionSnapshotTransportRequest:
            raise AlpacaPaperPositionSnapshotTransportError(
                "strict position-snapshot transport requires an exact request"
            )
        request.__post_init__()
        if type(headers) is not _AlpacaPaperAuthenticationHeaders:
            raise AlpacaPaperPositionSnapshotTransportError(
                "strict position-snapshot transport requires redacted auth headers"
            )
        if tuple(headers) != ALPACA_AUTH_HEADER_NAMES:
            raise AlpacaPaperPositionSnapshotTransportError(
                "strict position-snapshot transport requires exact auth headers"
            )
        timeout_seconds = request.httpx_phase_timeout.total_seconds()
        result: AlpacaPaperPositionSnapshotTransportResponse | None = None
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
                        "Accept": ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE,
                        "Accept-Encoding": "identity",
                        "User-Agent": (
                            f"autoquant-trader/{ALPACA_PAPER_ADAPTER_VERSION} "
                            "phase4t-position-snapshot"
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
                    if len(body) + len(chunk) > ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES:
                        raise AlpacaPaperPositionSnapshotTransportError(
                            "position-snapshot response exceeds the durable raw bound"
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
                    raise AlpacaPaperPositionSnapshotTransportError(
                        "position-snapshot response changed the fixed request target"
                    )
                result = AlpacaPaperPositionSnapshotTransportResponse(
                    request_sha256=request.semantic_sha256,
                    transport_id=self.transport_id,
                    transport_version=self.transport_version,
                    http_status=response.status_code,
                    provider_request_id=request_id,
                    media_type=media_type,
                    response_body=bytes(body),
                )
        except AlpacaPaperPositionSnapshotTransportError:
            raise
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise AlpacaPaperPositionSnapshotTransportError(
                "authenticated Alpaca position-snapshot request failed without a retained response"
            ) from None
        if result is None:
            raise AlpacaPaperPositionSnapshotTransportError(
                "authenticated Alpaca position-snapshot request produced no response"
            )
        return result


def _same_fence_lease(
    left: AccountFenceReceipt,
    right: AccountFenceReceipt,
) -> bool:
    return (
        left.fence == right.fence
        and left.policy_sha256 == right.policy_sha256
        and left.lease_sha256 == right.lease_sha256
        and left.valid_until == right.valid_until
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionSnapshotEvidence(_NoPositionSnapshotRuntimeAuthority):
    """Complete transient proof for one raw-first authenticated capture."""

    plan: AlpacaPaperPositionSnapshotRuntimePlan
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt
    credential_receipt: AlpacaPaperCredentialResolutionReceipt
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    permit_freshness: BrokerRequestPermitFreshnessReceipt
    pre_fence_receipt: AccountFenceReceipt
    request: AlpacaPaperPositionSnapshotTransportRequest
    response: AlpacaPaperPositionSnapshotTransportResponse
    persisted_snapshot: PersistedAlpacaPaperPositionSnapshot
    post_fence_receipt: AccountFenceReceipt
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt
    final_fence_receipt: AccountFenceReceipt
    authenticated_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionSnapshotEvidence must be proof-constructed"
        )

    def _validate(self) -> None:
        exact_types = (
            (self.plan, AlpacaPaperPositionSnapshotRuntimePlan, "runtime plan"),
            (
                self.preparation,
                AlpacaPaperPositionSnapshotPreparationReceipt,
                "preparation",
            ),
            (
                self.credential_receipt,
                AlpacaPaperCredentialResolutionReceipt,
                "credential receipt",
            ),
            (
                self.pre_account_identity,
                AlpacaPaperAccountIdentityContinuityReceipt,
                "pre-request account identity",
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
                AlpacaPaperPositionSnapshotTransportRequest,
                "transport request",
            ),
            (
                self.response,
                AlpacaPaperPositionSnapshotTransportResponse,
                "transport response",
            ),
            (
                self.persisted_snapshot,
                PersistedAlpacaPaperPositionSnapshot,
                "persisted snapshot",
            ),
            (self.post_fence_receipt, AccountFenceReceipt, "post-request fence"),
            (
                self.post_account_identity,
                AlpacaPaperAccountIdentityContinuityReceipt,
                "post-request account identity",
            ),
            (self.final_fence_receipt, AccountFenceReceipt, "final fence"),
        )
        for value, exact_type, field_name in exact_types:
            if type(value) is not exact_type:
                raise AlpacaPaperPositionSnapshotConflict(
                    f"authenticated position snapshot requires an exact {field_name}"
                )

        self.plan.__post_init__()
        self.preparation._validate()
        try:
            self.credential_receipt.__post_init__()
            self.policy.__post_init__()
            self.demand.__post_init__()
            self.permit.__post_init__()
            self.permit_freshness._validate()
            self.pre_fence_receipt._validate()
            self.request.__post_init__()
            self.response.__post_init__()
            self.persisted_snapshot.__post_init__()
            self.post_fence_receipt._validate()
            self.final_fence_receipt._validate()
        except AlpacaPaperPositionSnapshotRuntimeError:
            raise
        except Exception:
            raise AlpacaPaperPositionSnapshotConflict(
                "authenticated position-snapshot source evidence is malformed"
            ) from None
        _validate_account_identity(
            self.pre_account_identity,
            self.plan.account_binding,
            phase="pre-request",
        )
        _validate_account_identity(
            self.post_account_identity,
            self.plan.account_binding,
            phase="post-request",
        )
        _require_utc(
            self.authenticated_at,
            "position-snapshot authenticated_at",
        )

        if self.credential_receipt.reference != self.plan.reference:
            raise AlpacaPaperPositionSnapshotConflict(
                "credential receipt does not bind the runtime-plan reference"
            )
        if self.preparation.plan != self.plan or self.policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot preparation or policy conflicts with the plan"
            )
        expected_demand = create_alpaca_paper_position_snapshot_demand(
            self.plan,
            requested_at=self.demand.requested_at,
        )
        if (
            self.demand != expected_demand
            or self.demand.purpose is not BrokerRequestPurpose.RECONCILIATION
            or self.demand.idempotency_key != self.plan.description.capture_idempotency_key
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "request demand does not bind the exact position capture"
            )
        if (
            self.permit.account_id != self.demand.account_id
            or self.permit.purpose is not self.demand.purpose
            or self.permit.demand_id != self.demand.demand_id
            or self.permit.demand_sha256 != self.demand.semantic_sha256
            or self.permit.policy_sha256 != self.policy.semantic_sha256
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "request permit does not bind the exact position demand"
            )
        if (
            self.permit_freshness.permit_id != self.permit.permit_id
            or self.permit_freshness.permit_sha256 != self.permit.semantic_sha256
            or self.permit_freshness.policy_sha256 != self.policy.semantic_sha256
            or self.permit_freshness.demand_sha256 != self.demand.semantic_sha256
            or self.permit_freshness.expires_at != self.permit.expires_at
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "permit freshness does not bind the exact position permit"
            )
        try:
            require_fresh_broker_request_permit(
                permit=self.permit,
                policy=self.policy,
                demand=self.demand,
                checked_at=self.permit_freshness.checked_at,
            )
        except ValueError:
            raise AlpacaPaperPositionSnapshotConflict(
                "request permit was not freshly authenticated"
            ) from None

        if not (
            _same_fence_lease(
                self.pre_fence_receipt,
                self.post_fence_receipt,
            )
            and _same_fence_lease(
                self.post_fence_receipt,
                self.final_fence_receipt,
            )
            and self.pre_fence_receipt.fence.account_id == self.plan.description.account_id
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "account fence or exact lease changed across position transport"
            )

        expected_request = AlpacaPaperPositionSnapshotTransportRequest(
            plan=self.plan,
            preparation_sha256=self.preparation.semantic_sha256,
            pre_account_identity_sha256=(self.pre_account_identity.semantic_sha256),
            demand_sha256=self.demand.semantic_sha256,
            permit_sha256=self.permit.semantic_sha256,
            permit_freshness_sha256=self.permit_freshness.semantic_sha256,
            pre_fence_receipt_sha256=self.pre_fence_receipt.semantic_sha256,
            started_at=self.request.started_at,
        )
        if self.request != expected_request:
            raise AlpacaPaperPositionSnapshotConflict(
                "transport request does not bind the exact authenticated inputs"
            )
        if (
            self.response.request_sha256 != self.request.semantic_sha256
            or self.response.transport_id != ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID
            or self.response.transport_version != ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION
            or self.response.media_type != ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "transport response conflicts with the restricted request"
            )

        observation = self.persisted_snapshot.observation
        delivery = self.persisted_snapshot.receipt.delivery
        if (
            observation.description != self.plan.description
            or observation.http_status != self.response.http_status
            or observation.provider_request_id != self.response.provider_request_id
            or observation.response_body != self.response.response_body
            or delivery.media_type != self.response.media_type
            or delivery.received_at != observation.received_at
            or delivery.delivery_idempotency_key != self.demand.idempotency_key
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "persisted position capture conflicts with the transport response"
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
            <= self.final_fence_receipt.validated_at
            <= self.authenticated_at
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "authenticated position-snapshot time order is inconsistent"
            )
        if not (
            self.credential_receipt.resolved_at
            <= self.request.started_at
            < self.credential_receipt.valid_until
            and observation.received_at < self.credential_receipt.valid_until
            and self.permit_freshness.checked_at
            <= self.request.started_at
            <= observation.received_at
            < self.permit.expires_at
            and self.pre_fence_receipt.validated_at
            <= self.request.started_at
            < self.pre_fence_receipt.valid_until
            and self.post_fence_receipt.validated_at
            <= self.post_account_identity.checked_at
            < self.post_fence_receipt.valid_until
            and self.final_fence_receipt.validated_at
            <= self.authenticated_at
            < self.final_fence_receipt.valid_until
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot authority was not current at its exact bounds"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "authenticated_position_snapshot_evidence",
            self.plan.semantic_sha256,
            self.preparation.semantic_sha256,
            self.credential_receipt.semantic_sha256,
            self.pre_account_identity.semantic_sha256,
            self.policy.semantic_sha256,
            self.demand.semantic_sha256,
            self.permit.semantic_sha256,
            self.permit_freshness.semantic_sha256,
            self.pre_fence_receipt.semantic_sha256,
            self.request.semantic_sha256,
            self.response.semantic_sha256,
            self.persisted_snapshot.semantic_sha256,
            self.post_fence_receipt.semantic_sha256,
            self.post_account_identity.semantic_sha256,
            self.final_fence_receipt.semantic_sha256,
            self.authenticated_at,
            self.request_budget_enforced,
            self.authenticated_provider_evidence,
            self.raw_response_persisted,
            self.authenticated_position_snapshot_established,
            self.runtime_current,
            self.provider_snapshot_complete,
            self.canonical_position_fact_authorized,
            self.reconciliation_complete,
            self.converged,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def evidence_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-position-snapshot-evidence",
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
    def fresh_single_use_claim_established(self) -> bool:
        return True

    @property
    def authenticated_position_snapshot_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_position_snapshot_evidence(
    *,
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
    credential_receipt: AlpacaPaperCredentialResolutionReceipt,
    pre_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    permit_freshness: BrokerRequestPermitFreshnessReceipt,
    pre_fence_receipt: AccountFenceReceipt,
    request: AlpacaPaperPositionSnapshotTransportRequest,
    response: AlpacaPaperPositionSnapshotTransportResponse,
    persisted_snapshot: PersistedAlpacaPaperPositionSnapshot,
    post_fence_receipt: AccountFenceReceipt,
    post_account_identity: AlpacaPaperAccountIdentityContinuityReceipt,
    final_fence_receipt: AccountFenceReceipt,
    authenticated_at: datetime,
) -> AlpacaPaperAuthenticatedPositionSnapshotEvidence:
    evidence = object.__new__(AlpacaPaperAuthenticatedPositionSnapshotEvidence)
    for field_name, value in (
        ("plan", plan),
        ("preparation", preparation),
        ("credential_receipt", credential_receipt),
        ("pre_account_identity", pre_account_identity),
        ("policy", policy),
        ("demand", demand),
        ("permit", permit),
        ("permit_freshness", permit_freshness),
        ("pre_fence_receipt", pre_fence_receipt),
        ("request", request),
        ("response", response),
        ("persisted_snapshot", persisted_snapshot),
        ("post_fence_receipt", post_fence_receipt),
        ("post_account_identity", post_account_identity),
        ("final_fence_receipt", final_fence_receipt),
        ("authenticated_at", authenticated_at),
    ):
        object.__setattr__(evidence, field_name, value)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionSnapshotReceipt(_NoPositionSnapshotRuntimeAuthority):
    """Durable and reloadable commit proof for one authenticated capture."""

    evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence
    commit_fence_receipt: AccountFenceReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionSnapshotReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.evidence) is not AlpacaPaperAuthenticatedPositionSnapshotEvidence:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot receipt requires exact authenticated evidence"
            )
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot receipt requires an exact commit fence"
            )
        self.evidence._validate()
        try:
            self.commit_fence_receipt._validate()
        except Exception:
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot commit fence is malformed"
            ) from None
        if not (
            _same_fence_lease(
                self.commit_fence_receipt,
                self.evidence.final_fence_receipt,
            )
            and self.evidence.authenticated_at
            <= self.commit_fence_receipt.validated_at
            < self.commit_fence_receipt.valid_until
        ):
            raise AlpacaPaperPositionSnapshotConflict(
                "commit fence does not independently continue the final fence lease"
            )

    @property
    def plan(self) -> AlpacaPaperPositionSnapshotRuntimePlan:
        return self.evidence.plan

    @property
    def persisted_snapshot(self) -> PersistedAlpacaPaperPositionSnapshot:
        return self.evidence.persisted_snapshot

    @property
    def account_id(self) -> str:
        return self.plan.description.account_id

    @property
    def capture_id(self) -> str:
        return self.plan.description.capture_id

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
            "authenticated_position_snapshot_receipt",
            self.evidence.semantic_sha256,
            self.commit_fence_receipt.semantic_sha256,
            self.persisted_snapshot.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-position-snapshot",
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
    def fresh_single_use_claim_established(self) -> bool:
        return True

    @property
    def authenticated_position_snapshot_established(self) -> bool:
        return True

    @property
    def durable_authenticated_position_snapshot_established(self) -> bool:
        return True


def _alpaca_paper_authenticated_position_snapshot_receipt(
    evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    *,
    commit_fence_receipt: AccountFenceReceipt,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    receipt = object.__new__(AlpacaPaperAuthenticatedPositionSnapshotReceipt)
    object.__setattr__(receipt, "evidence", evidence)
    object.__setattr__(receipt, "commit_fence_receipt", commit_fence_receipt)
    receipt._validate()
    return receipt


class AlpacaPaperPositionSnapshotRuntimePort(Protocol):
    """Atomic durable operations around one single-use position capture.

    ``prepare`` must durably persist a fresh claim and return it only to the
    transaction that created it.  Any unresolved, completed, concurrent, or
    restarted attempt for the same runtime plan must raise before credentials,
    request admission, or transport.  ``record`` must independently revalidate
    the evidence's exact fence, policy, lease, and expiry in its commit
    transaction; the commit check must be at or after ``authenticated_at`` and
    strictly before lease expiry.  There is intentionally no retry API.
    """

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt: ...

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None: ...


def _revalidate_fence(
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    *,
    phase: str,
) -> AccountFenceReceipt:
    try:
        result = coordinator.revalidate(fence)
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            f"account fence authentication failed {phase} position transport"
        ) from None
    if type(result) is not AccountFenceReceipt:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            f"account coordinator returned invalid {phase} fence evidence"
        )
    try:
        result._validate()
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            f"account coordinator returned malformed {phase} fence evidence"
        ) from None
    if result.fence != fence:
        raise AlpacaPaperPositionSnapshotConflict(
            f"account fence changed {phase} position transport"
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
        raise AlpacaPaperPositionSnapshotConflict(
            f"terminal account identity authentication failed {phase} position transport"
        ) from None
    if type(result) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            f"account identity repository returned invalid {phase} evidence"
        )
    _validate_account_identity(result, account_binding, phase=phase)
    if result.checked_at != checked_at:
        raise AlpacaPaperPositionSnapshotConflict(
            f"account identity repository used another {phase} check instant"
        )
    return result


def _validate_issued_permit(
    permit: object,
    demand: BrokerRequestDemand,
) -> BrokerRequestPermit:
    if type(permit) is not BrokerRequestPermit:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "durable budget issuer returned an invalid position permit"
        )
    try:
        permit.__post_init__()
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable budget issuer returned a malformed position permit"
        ) from None
    if (
        permit.account_id != demand.account_id
        or permit.purpose is not BrokerRequestPurpose.RECONCILIATION
        or permit.demand_id != demand.demand_id
        or permit.demand_sha256 != demand.semantic_sha256
        or permit.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
    ):
        raise AlpacaPaperPositionSnapshotConflict(
            "durable budget issuer returned a permit for another demand"
        )
    return permit


def _authenticate_permit(
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
        raise AlpacaPaperPositionSnapshotConflict(
            "durable position permit authentication failed before transport"
        ) from None
    if type(result) is not BrokerRequestPermitFreshnessReceipt:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "budget authenticator returned invalid position freshness"
        )
    try:
        result._validate()
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "budget authenticator returned malformed position freshness"
        ) from None
    if (
        result.permit_id != permit.permit_id
        or result.permit_sha256 != permit.semantic_sha256
        or result.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
        or result.demand_sha256 != demand.semantic_sha256
        or result.expires_at != permit.expires_at
    ):
        raise AlpacaPaperPositionSnapshotConflict(
            "durable permit freshness receipt conflicts before position transport"
        )
    try:
        require_fresh_broker_request_permit(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
            checked_at=result.checked_at,
        )
    except ValueError:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable position-snapshot permit is invalid before transport"
        ) from None
    return result


def _observe_authenticated_alpaca_paper_position_snapshot_with_transport(
    *,
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    credential_resolver: AlpacaPaperPositionSnapshotCredentialResolver,
    transport: _AlpacaPaperPositionSnapshotTransport,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    snapshot_runtime: AlpacaPaperPositionSnapshotRuntimePort,
    clock: Clock,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    """Trusted test seam; execute, commit, and reload one prepared capture."""

    if type(plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot runtime requires an exact runtime plan"
        )
    plan.__post_init__()
    if type(fence) is not AccountFence:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot runtime requires the current exact account fence"
        )
    try:
        fence.__post_init__()
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot runtime fence is malformed"
        ) from None
    if fence.account_id != plan.description.account_id:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot runtime fence belongs to another account"
        )
    for port, method_name, field_name in (
        (snapshot_runtime, "prepare", "durable snapshot preparer"),
        (snapshot_runtime, "record", "durable snapshot recorder"),
        (snapshot_runtime, "load", "durable snapshot loader"),
        (budget, "issue_new", "durable new-permit issuer"),
        (budget, "authenticate_fresh", "durable budget authenticator"),
        (
            account_bindings,
            "authenticate_terminal_identity",
            "terminal account-identity authenticator",
        ),
        (coordinator, "revalidate", "account coordinator"),
        (ingress_recorder, "record", "raw ingress recorder"),
        (transport, "execute", "restricted position-snapshot transport"),
    ):
        try:
            method = getattr(port, method_name)
        except Exception:
            raise AlpacaPaperPositionSnapshotRuntimeError(
                f"position-snapshot {field_name} access failed"
            ) from None
        if not callable(method):
            raise AlpacaPaperPositionSnapshotRuntimeError(
                f"position-snapshot runtime requires a {field_name}"
            )
    try:
        coordinator_account_id = coordinator.account_id
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot coordinator identity access failed"
        ) from None
    if coordinator_account_id != plan.description.account_id:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot coordinator belongs to another account"
        )
    try:
        transport_identity = (
            transport.transport_id,
            transport.transport_version,
        )
    except Exception:
        raise AlpacaPaperPositionSnapshotTransportError(
            "position-snapshot transport identity access failed"
        ) from None
    if transport_identity != (
        ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID,
        ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION,
    ):
        raise AlpacaPaperPositionSnapshotTransportError(
            "position-snapshot runtime requires the exact restricted transport"
        )

    # The fresh durable claim is intentionally the first external mutation.
    # A stalled, terminal, overlapping, or restarted plan fails here before
    # secret access and before allocating a non-refundable request permit.
    prepared_at = _trusted_now(
        clock,
        "position-snapshot preparation checked_at",
    )
    try:
        preparation_value = snapshot_runtime.prepare(
            plan,
            checked_at=prepared_at,
        )
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable position-snapshot preparation failed before credential resolution"
        ) from None
    if type(preparation_value) is not AlpacaPaperPositionSnapshotPreparationReceipt:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "durable position preparer returned invalid evidence"
        )
    preparation = preparation_value
    preparation._validate()
    if preparation.plan != plan or preparation.prepared_at != prepared_at:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable preparation does not bind the exact fresh position claim"
        )

    requested_at = _trusted_now(clock, "position-snapshot requested_at")
    demand = create_alpaca_paper_position_snapshot_demand(
        plan,
        requested_at=requested_at,
    )
    credential_session = _resolve_alpaca_paper_credentials_for_operation(
        reference=plan.reference,
        resolver=credential_resolver,
        resolver_method_name="_resolve_for_position_snapshot",
        clock=clock,
    )
    try:
        try:
            permit_value = budget.issue_new(
                policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
                demand=demand,
            )
        except Exception:
            raise AlpacaPaperPositionSnapshotConflict(
                "durable position permit issuance failed"
            ) from None
        permit = _validate_issued_permit(permit_value, demand)
        pre_fence_receipt = _revalidate_fence(
            coordinator,
            fence,
            phase="before",
        )
        permit_freshness = _authenticate_permit(
            budget,
            permit,
            demand,
        )
        pre_account_checked_at = _trusted_now(
            clock,
            "pre-position-snapshot account identity checked_at",
        )
        pre_account_identity = _authenticate_account_binding_identity(
            account_bindings,
            plan.account_binding,
            checked_at=pre_account_checked_at,
            phase="before",
        )
        started_at = _trusted_now(
            clock,
            "position-snapshot transport started_at",
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
            raise AlpacaPaperPositionSnapshotConflict(
                "position-snapshot authority is not current at transport start"
            )
        request = AlpacaPaperPositionSnapshotTransportRequest(
            plan=plan,
            preparation_sha256=preparation.semantic_sha256,
            pre_account_identity_sha256=pre_account_identity.semantic_sha256,
            demand_sha256=demand.semantic_sha256,
            permit_sha256=permit.semantic_sha256,
            permit_freshness_sha256=permit_freshness.semantic_sha256,
            pre_fence_receipt_sha256=pre_fence_receipt.semantic_sha256,
            started_at=started_at,
        )
        headers = credential_session.authentication_headers(checked_at=started_at)
        try:
            response_value = transport.execute(request, headers)
        except Exception:
            raise AlpacaPaperPositionSnapshotTransportError(
                "restricted position-snapshot transport failed with sanitized diagnostics"
            ) from None
        received_at = _trusted_now(
            clock,
            "position-snapshot transport received_at",
        )
    finally:
        credential_session.close()

    if type(response_value) is not AlpacaPaperPositionSnapshotTransportResponse:
        raise AlpacaPaperPositionSnapshotTransportError(
            "position-snapshot transport returned an invalid response"
        )
    response = response_value
    try:
        response.__post_init__()
    except Exception:
        raise AlpacaPaperPositionSnapshotTransportError(
            "position-snapshot transport returned a malformed response"
        ) from None
    if (
        response.request_sha256 != request.semantic_sha256
        or response.transport_id != ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID
        or response.transport_version != ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION
    ):
        raise AlpacaPaperPositionSnapshotTransportError(
            "position-snapshot response binds another request or profile"
        )
    recorded_at = _trusted_now(
        clock,
        "position-snapshot raw response recorded_at",
    )
    if recorded_at < received_at:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "position-snapshot raw-record clock regressed"
        )
    try:
        persisted_snapshot = persist_then_decode_alpaca_paper_position_snapshot_response(
            ingress_recorder,
            plan.description,
            http_status=response.http_status,
            provider_request_id=response.provider_request_id,
            response_body=response.response_body,
            received_at=received_at,
            recorded_at=recorded_at,
            media_type=response.media_type,
        )
    except AlpacaPaperPositionSnapshotError:
        raise
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "raw position-snapshot persistence failed"
        ) from None
    if response.media_type != ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot response media type is not the exact JSON "
            "profile after raw persistence"
        )
    if received_at < started_at or received_at >= credential_session.receipt.valid_until:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot response completed outside its credential bound "
            "after raw persistence"
        )
    if received_at >= permit.expires_at:
        raise AlpacaPaperPositionSnapshotConflict(
            "position-snapshot response completed after its request permit "
            "expired after raw persistence"
        )

    post_fence_receipt = _revalidate_fence(
        coordinator,
        fence,
        phase="after",
    )
    if not _same_fence_lease(pre_fence_receipt, post_fence_receipt):
        raise AlpacaPaperPositionSnapshotConflict(
            "account fence lease changed after position transport"
        )
    post_account_checked_at = _trusted_now(
        clock,
        "post-position-snapshot account identity checked_at",
    )
    post_account_identity = _authenticate_account_binding_identity(
        account_bindings,
        plan.account_binding,
        checked_at=post_account_checked_at,
        phase="after",
    )
    final_fence_receipt = _revalidate_fence(
        coordinator,
        fence,
        phase="at final",
    )
    if not _same_fence_lease(
        post_fence_receipt,
        final_fence_receipt,
    ):
        raise AlpacaPaperPositionSnapshotConflict(
            "account fence lease changed before position commit"
        )
    authenticated_at = _trusted_now(
        clock,
        "position-snapshot authenticated_at",
    )
    evidence = _alpaca_paper_authenticated_position_snapshot_evidence(
        plan=plan,
        preparation=preparation,
        credential_receipt=credential_session.receipt,
        pre_account_identity=pre_account_identity,
        policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
        demand=demand,
        permit=permit,
        permit_freshness=permit_freshness,
        pre_fence_receipt=pre_fence_receipt,
        request=request,
        response=response,
        persisted_snapshot=persisted_snapshot,
        post_fence_receipt=post_fence_receipt,
        post_account_identity=post_account_identity,
        final_fence_receipt=final_fence_receipt,
        authenticated_at=authenticated_at,
    )

    try:
        receipt_value = snapshot_runtime.record(evidence)
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable authenticated position-snapshot commit failed"
        ) from None
    if type(receipt_value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "durable position recorder returned an invalid receipt"
        )
    receipt = receipt_value
    receipt._validate()
    if receipt.evidence != evidence:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable position receipt does not bind the exact runtime evidence"
        )
    expected_receipt = _alpaca_paper_authenticated_position_snapshot_receipt(
        evidence,
        commit_fence_receipt=receipt.commit_fence_receipt,
    )
    if receipt != expected_receipt:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable position receipt conflicts with the runtime evidence"
        )

    try:
        loaded_value = snapshot_runtime.load(plan)
    except Exception:
        raise AlpacaPaperPositionSnapshotConflict(
            "durable authenticated position-snapshot reload failed"
        ) from None
    if type(loaded_value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        raise AlpacaPaperPositionSnapshotRuntimeError(
            "durable position loader returned invalid committed evidence"
        )
    loaded = loaded_value
    loaded._validate()
    if (
        loaded != receipt
        or loaded.evidence != evidence
        or loaded.semantic_sha256 != receipt.semantic_sha256
    ):
        raise AlpacaPaperPositionSnapshotConflict(
            "reloaded position receipt differs from the exact committed evidence"
        )
    return loaded


def observe_authenticated_alpaca_paper_position_snapshot(
    *,
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    credential_resolver: AlpacaPaperPositionSnapshotCredentialResolver,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    snapshot_runtime: AlpacaPaperPositionSnapshotRuntimePort,
    clock: Clock,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    """Execute the exact production positions GET and reload durable evidence."""

    return _observe_authenticated_alpaca_paper_position_snapshot_with_transport(
        plan=plan,
        credential_resolver=credential_resolver,
        transport=_HttpxAlpacaPaperPositionSnapshotTransport(),
        budget=budget,
        account_bindings=account_bindings,
        coordinator=coordinator,
        fence=fence,
        ingress_recorder=ingress_recorder,
        snapshot_runtime=snapshot_runtime,
        clock=clock,
    )


__all__ = [
    "ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE",
    "ALPACA_PAPER_POSITION_SNAPSHOT_HTTPX_PHASE_TIMEOUT",
    "ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID",
    "ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION",
    "AlpacaPaperAuthenticatedPositionSnapshotEvidence",
    "AlpacaPaperAuthenticatedPositionSnapshotReceipt",
    "AlpacaPaperPositionSnapshotConflict",
    "AlpacaPaperPositionSnapshotCredentialResolver",
    "AlpacaPaperPositionSnapshotPreparationReceipt",
    "AlpacaPaperPositionSnapshotRuntimeError",
    "AlpacaPaperPositionSnapshotRuntimePlan",
    "AlpacaPaperPositionSnapshotRuntimePort",
    "AlpacaPaperPositionSnapshotTransportError",
    "AlpacaPaperPositionSnapshotTransportRequest",
    "AlpacaPaperPositionSnapshotTransportResponse",
    "create_alpaca_paper_position_snapshot_demand",
    "create_alpaca_paper_position_snapshot_runtime_plan",
    "observe_authenticated_alpaca_paper_position_snapshot",
]
