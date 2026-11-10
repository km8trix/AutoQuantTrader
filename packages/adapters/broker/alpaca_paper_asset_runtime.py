"""Authenticated, read-only Alpaca paper asset/security-binding runtime.

Phase 4H admits one exact fixed-candidate ``GET /v2/assets/{symbol}``.  It
requires a fresh terminal Phase 4G account binding, consumes protected durable
request capacity, revalidates the stable account fence, and records the raw
response before strict decoding.  A successful result is a short-lived,
operator-pinned provider-asset binding, never order or trading authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

import httpx

from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CANDIDATE_INSTRUMENTS,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES,
    AlpacaAssetClass,
    AlpacaAssetExchange,
    AlpacaAssetObservationOutcome,
    AlpacaAssetStatus,
    AlpacaPaperAssetObservationDescription,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT,
    AlpacaPaperAccountBindingFreshnessReceipt,
    AlpacaPaperAccountBindingRuntimePort,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionReceipt,
    BrokerRequestBudgetRuntimePort,
    _AlpacaPaperAuthenticationHeaders,
    _resolve_alpaca_paper_asset_credentials,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaAssetObservation,
    persist_then_decode_alpaca_asset_observation_response,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorPort,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.broker_ingress import (
    MAX_BROKER_INGRESS_BODY_BYTES,
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

ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION = "phase4h-authenticated-alpaca-paper-asset-binding-v1"
ALPACA_PAPER_ASSET_BINDING_TTL = timedelta(seconds=5)
ALPACA_PAPER_ASSET_HTTPX_PHASE_TIMEOUT = ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT
ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE = ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
ALPACA_PAPER_ASSET_TRANSPORT_ID = "strict-httpx-alpaca-paper-asset-get"
ALPACA_PAPER_ASSET_TRANSPORT_VERSION = "1.0.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AlpacaPaperAssetRuntimeError(AlpacaPaperContractError):
    """Authenticated asset-runtime evidence is malformed or inconsistent."""


class AlpacaPaperAssetTransportError(AlpacaPaperAssetRuntimeError):
    """The exact restricted asset transport failed."""


class AlpacaPaperAssetBindingConflict(AlpacaPaperAssetRuntimeError):
    """Asset/security evidence conflicts with another immutable fact."""


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: object, field_name: str, *, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperAssetRuntimeError(f"{field_name} must be bounded, non-empty trimmed text")
    return value


def _require_safe_text(value: object, field_name: str) -> str:
    text = _require_text(value, field_name, maximum=128)
    if _SAFE_TEXT.fullmatch(text) is None:
        raise AlpacaPaperAssetRuntimeError(f"{field_name} is not canonical safe text")
    return text


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAssetRuntimeError(f"{field_name} must be a lowercase SHA-256")
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAssetRuntimeError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAssetRuntimeError(str(error)) from error
    return value


def _require_uuid(value: object, field_name: str) -> str:
    text = _require_text(value, field_name, maximum=36)
    try:
        parsed = UUID(text)
    except ValueError as error:
        raise AlpacaPaperAssetRuntimeError(f"{field_name} must be a canonical UUID") from error
    if str(parsed) != text:
        raise AlpacaPaperAssetRuntimeError(f"{field_name} must be a canonical lowercase UUID")
    return text


def _trusted_now(clock: Clock, field_name: str) -> datetime:
    try:
        instant = clock.now()
    except Exception as error:
        raise AlpacaPaperAssetRuntimeError(f"{field_name} clock failed") from error
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


@dataclass(frozen=True, slots=True)
class AlpacaPaperSecurityReference:
    """Nonsecret operator pin for one fixed local/provider security identity."""

    credential_reference: AlpacaPaperCredentialReference
    instrument_id: str
    symbol: str
    expected_provider_asset_id: str

    def __post_init__(self) -> None:
        if type(self.credential_reference) is not AlpacaPaperCredentialReference:
            raise AlpacaPaperAssetBindingConflict(
                "security reference requires an exact credential reference"
            )
        self.credential_reference.__post_init__()
        description = AlpacaPaperAssetObservationDescription(
            account_id=self.credential_reference.account_id,
            instrument_id=self.instrument_id,
            symbol=self.symbol,
        )
        description.__post_init__()
        _require_uuid(
            self.expected_provider_asset_id,
            "expected Alpaca provider asset ID",
        )

    @property
    def account_id(self) -> str:
        return self.credential_reference.account_id

    @property
    def expected_provider_account_id(self) -> str:
        return self.credential_reference.expected_provider_account_id

    @property
    def provider_id(self) -> str:
        return ALPACA_PAPER_ADAPTER_ID

    @property
    def environment(self) -> str:
        return "paper"

    @property
    def capability_sha256(self) -> str:
        return ALPACA_PAPER_CAPABILITIES.semantic_sha256

    @property
    def candidate_instrument_symbols(self) -> tuple[tuple[str, str], ...]:
        return ALPACA_PAPER_CANDIDATE_INSTRUMENTS

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
                "security_reference",
                self.credential_reference.semantic_sha256,
                self.provider_id,
                self.environment,
                self.capability_sha256,
                self.candidate_instrument_symbols,
                self.instrument_id,
                self.symbol,
                self.expected_provider_asset_id,
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
                "security_reference",
                self.credential_reference.semantic_sha256,
                self.provider_id,
                self.environment,
                self.capability_sha256,
                self.candidate_instrument_symbols,
                self.instrument_id,
                self.symbol,
                self.expected_provider_asset_id,
            )
        )

    @property
    def credential_values_present(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


class AlpacaPaperAssetCredentialResolver(Protocol):
    """Trusted resolver port scoped to the exact asset-observation boundary."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_asset_observation(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object: ...


def alpaca_paper_asset_observation_correlation_sha256(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAssetObservationDescription,
) -> str:
    """Bind asset request capacity to the exact account and security pins."""

    _validate_security_account_description(
        security_reference=security_reference,
        account_binding=account_binding,
        description=description,
    )
    return _semantic_sha256(
        (
            ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
            "asset_observation_correlation",
            security_reference.semantic_sha256,
            account_binding.semantic_sha256,
            description.semantic_sha256,
        )
    )


def create_alpaca_paper_asset_observation_demand(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAssetObservationDescription,
    idempotency_key: str,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Create the fixed reconciliation-tier demand for one asset GET."""

    return create_alpaca_paper_request_demand(
        account_id=security_reference.account_id,
        idempotency_key=idempotency_key,
        operation=AlpacaPaperBudgetOperation.OBSERVE_ASSET,
        correlation_sha256=alpaca_paper_asset_observation_correlation_sha256(
            security_reference=security_reference,
            account_binding=account_binding,
            description=description,
        ),
        requested_at=requested_at,
    )


def _validate_security_account_description(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAssetObservationDescription,
) -> None:
    if type(security_reference) is not AlpacaPaperSecurityReference:
        raise AlpacaPaperAssetBindingConflict("asset runtime requires an exact security reference")
    if type(account_binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperAssetBindingConflict(
            "asset runtime requires an exact authenticated account binding"
        )
    if type(description) is not AlpacaPaperAssetObservationDescription:
        raise AlpacaPaperAssetBindingConflict("asset runtime requires an exact asset description")
    security_reference.__post_init__()
    account_binding._validate()
    description.__post_init__()
    credential_reference = security_reference.credential_reference
    if (
        account_binding.account_id != security_reference.account_id
        or account_binding.expected_provider_account_id
        != security_reference.expected_provider_account_id
        or account_binding.credential_reference_sha256 != credential_reference.semantic_sha256
        or account_binding.secret_ref != credential_reference.secret_ref
        or account_binding.secret_version != credential_reference.secret_version
        or account_binding.capability_sha256 != security_reference.capability_sha256
        or description.account_id != security_reference.account_id
        or description.instrument_id != security_reference.instrument_id
        or description.symbol != security_reference.symbol
    ):
        raise AlpacaPaperAssetBindingConflict(
            "security reference, account binding, and asset description conflict"
        )


@dataclass(frozen=True, slots=True)
class AlpacaPaperAssetTransportRequest:
    """Secret-free description of one exact preauthorized asset GET."""

    description: AlpacaPaperAssetObservationDescription
    credential_reference_sha256: str
    security_reference_sha256: str
    account_binding_sha256: str
    account_binding_freshness_sha256: str
    demand_sha256: str
    permit_sha256: str
    permit_freshness_sha256: str
    fence_receipt_sha256: str
    started_at: datetime
    httpx_phase_timeout: timedelta = ALPACA_PAPER_ASSET_HTTPX_PHASE_TIMEOUT

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperAssetObservationDescription:
            raise AlpacaPaperAssetTransportError(
                "asset transport requires an exact asset description"
            )
        self.description.__post_init__()
        for value, field_name in (
            (self.credential_reference_sha256, "credential reference"),
            (self.security_reference_sha256, "security reference"),
            (self.account_binding_sha256, "account binding"),
            (self.account_binding_freshness_sha256, "account-binding freshness"),
            (self.demand_sha256, "request demand"),
            (self.permit_sha256, "request permit"),
            (self.permit_freshness_sha256, "permit freshness"),
            (self.fence_receipt_sha256, "fence receipt"),
        ):
            _require_sha256(value, f"asset transport {field_name} digest")
        _require_utc(self.started_at, "asset transport started_at")
        if (
            type(self.httpx_phase_timeout) is not timedelta
            or self.httpx_phase_timeout != ALPACA_PAPER_ASSET_HTTPX_PHASE_TIMEOUT
        ):
            raise AlpacaPaperAssetTransportError(
                "asset transport must use the fixed socket-I/O inactivity timeout"
            )
        expected_path = f"/v2/assets/{self.description.symbol}"
        if (
            self.description.method != "GET"
            or self.description.base_url != ALPACA_PAPER_TRADING_BASE_URL
            or self.description.path != expected_path
            or self.description.query
        ):
            raise AlpacaPaperAssetTransportError(
                "asset transport request escaped the fixed candidate GET"
            )

    @property
    def method(self) -> str:
        return self.description.method

    @property
    def url(self) -> str:
        return self.description.url

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
                "asset_transport_request",
                self.description.semantic_sha256,
                self.credential_reference_sha256,
                self.security_reference_sha256,
                self.account_binding_sha256,
                self.account_binding_freshness_sha256,
                self.demand_sha256,
                self.permit_sha256,
                self.permit_freshness_sha256,
                self.fence_receipt_sha256,
                self.started_at,
                int(self.httpx_phase_timeout.total_seconds() * 1_000_000),
            )
        )

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class AlpacaPaperAssetTransportResponse:
    """Bounded raw entity bytes from one restricted asset GET."""

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
        _require_sha256(self.request_sha256, "asset response request digest")
        _require_safe_text(self.transport_id, "asset transport ID")
        _require_safe_text(self.transport_version, "asset transport version")
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise AlpacaPaperAssetTransportError(
                "asset response status must be an exact HTTP status"
            )
        if self.provider_request_id is not None:
            _require_text(
                self.provider_request_id,
                "Alpaca asset X-Request-ID",
                maximum=256,
            )
        if self.media_type is not None:
            _require_text(
                self.media_type,
                "Alpaca asset response media type",
                maximum=128,
            )
        if type(self.response_body) is not bytes:
            raise AlpacaPaperAssetTransportError(
                "asset transport response body must be exact bytes"
            )
        if len(self.response_body) > MAX_BROKER_INGRESS_BODY_BYTES:
            raise AlpacaPaperAssetTransportError(
                "asset transport response exceeds the durable raw bound"
            )
        if type(self.tls_verified) is not bool or not self.tls_verified:
            raise AlpacaPaperAssetTransportError("asset transport must verify provider TLS")
        if type(self.redirects_followed) is not bool or self.redirects_followed:
            raise AlpacaPaperAssetTransportError("asset transport cannot follow redirects")

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
                "asset_transport_response",
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
    def submission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


class _AlpacaPaperAssetTransport(Protocol):
    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def execute(
        self,
        request: AlpacaPaperAssetTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAssetTransportResponse: ...


class _HttpxAlpacaPaperAssetTransport:
    """Concrete TLS-verifying, no-redirect, no-proxy asset-only transport."""

    __slots__ = ()

    @property
    def transport_id(self) -> str:
        return ALPACA_PAPER_ASSET_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ALPACA_PAPER_ASSET_TRANSPORT_VERSION

    def execute(
        self,
        request: AlpacaPaperAssetTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAssetTransportResponse:
        if type(request) is not AlpacaPaperAssetTransportRequest:
            raise AlpacaPaperAssetTransportError(
                "strict Alpaca transport requires an exact asset request"
            )
        request.__post_init__()
        if type(headers) is not _AlpacaPaperAuthenticationHeaders:
            raise AlpacaPaperAssetTransportError(
                "strict Alpaca transport requires redacted authentication headers"
            )
        if tuple(headers) != ALPACA_AUTH_HEADER_NAMES:
            raise AlpacaPaperAssetTransportError(
                "strict Alpaca transport requires the exact authentication header names"
            )
        timeout_seconds = request.httpx_phase_timeout.total_seconds()
        result: AlpacaPaperAssetTransportResponse | None = None
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
                        "Accept": ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE,
                        "Accept-Encoding": "identity",
                        "User-Agent": (
                            f"autoquant-trader/{ALPACA_PAPER_ADAPTER_VERSION} phase4h-asset-probe"
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
                        raise AlpacaPaperAssetTransportError(
                            "asset transport response exceeds the durable raw bound"
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
                    raise AlpacaPaperAssetTransportError(
                        "asset transport response changed the fixed request target"
                    )
                result = AlpacaPaperAssetTransportResponse(
                    request_sha256=request.semantic_sha256,
                    transport_id=self.transport_id,
                    transport_version=self.transport_version,
                    http_status=response.status_code,
                    provider_request_id=request_id,
                    media_type=media_type,
                    response_body=bytes(body),
                )
        except AlpacaPaperAssetTransportError:
            raise
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise AlpacaPaperAssetTransportError(
                "authenticated Alpaca asset request failed without a retained response"
            ) from None
        if result is None:
            raise AlpacaPaperAssetTransportError(
                "authenticated Alpaca asset request produced no response"
            )
        return result


def _authenticate_terminal_account_binding(
    port: AlpacaPaperAccountBindingRuntimePort,
    binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    checked_at: datetime,
    phase: str,
) -> AlpacaPaperAccountBindingFreshnessReceipt:
    result: object | None = None
    failed = False
    try:
        result = port.authenticate_terminal_fresh(binding, checked_at)
    except Exception:
        failed = True
    if failed:
        raise AlpacaPaperAssetBindingConflict(
            f"terminal account-binding authentication failed {phase} asset transport"
        ) from None
    if type(result) is not AlpacaPaperAccountBindingFreshnessReceipt:
        raise AlpacaPaperAssetBindingConflict(
            "account-binding authenticator returned an invalid freshness receipt"
        )
    result._validate()
    if (
        result.account_id != binding.account_id
        or result.binding_id != binding.binding_id
        or result.binding_sha256 != binding.semantic_sha256
        or result.expected_provider_account_id != binding.expected_provider_account_id
        or result.sequence_number != binding.sequence_number
        or result.checked_at != checked_at
        or result.expires_at != binding.valid_until
    ):
        raise AlpacaPaperAssetBindingConflict(
            "terminal account-binding freshness receipt conflicts with its source"
        )
    return result


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAssetEvidence:
    """Complete transient evidence supplied to the durable asset recorder."""

    security_reference: AlpacaPaperSecurityReference
    credential_receipt: AlpacaPaperCredentialResolutionReceipt
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    pre_account_binding_freshness: AlpacaPaperAccountBindingFreshnessReceipt
    description: AlpacaPaperAssetObservationDescription
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    permit_freshness: BrokerRequestPermitFreshnessReceipt
    pre_fence_receipt: AccountFenceReceipt
    request: AlpacaPaperAssetTransportRequest
    response: AlpacaPaperAssetTransportResponse
    persisted_observation: PersistedAlpacaAssetObservation
    post_fence_receipt: AccountFenceReceipt
    post_account_binding_freshness: AlpacaPaperAccountBindingFreshnessReceipt
    qualified_at: datetime
    valid_until: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedAssetEvidence must be proof-constructed")

    def _validate(self) -> None:
        exact_types = (
            (self.security_reference, AlpacaPaperSecurityReference, "security reference"),
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
                self.pre_account_binding_freshness,
                AlpacaPaperAccountBindingFreshnessReceipt,
                "pre-request account-binding freshness",
            ),
            (
                self.description,
                AlpacaPaperAssetObservationDescription,
                "asset description",
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
            (self.request, AlpacaPaperAssetTransportRequest, "transport request"),
            (self.response, AlpacaPaperAssetTransportResponse, "transport response"),
            (
                self.persisted_observation,
                PersistedAlpacaAssetObservation,
                "persisted asset observation",
            ),
            (self.post_fence_receipt, AccountFenceReceipt, "post-request fence"),
            (
                self.post_account_binding_freshness,
                AlpacaPaperAccountBindingFreshnessReceipt,
                "post-request account-binding freshness",
            ),
        )
        for value, expected_type, field_name in exact_types:
            if type(value) is not expected_type:
                raise AlpacaPaperAssetBindingConflict(
                    f"authenticated asset evidence requires an exact {field_name}"
                )
        self.security_reference.__post_init__()
        self.credential_receipt.__post_init__()
        self.account_binding._validate()
        self.pre_account_binding_freshness._validate()
        self.description.__post_init__()
        self.policy.__post_init__()
        self.demand.__post_init__()
        self.permit.__post_init__()
        self.permit_freshness._validate()
        self.pre_fence_receipt._validate()
        self.request.__post_init__()
        self.response.__post_init__()
        self.persisted_observation.__post_init__()
        self.post_fence_receipt._validate()
        self.post_account_binding_freshness._validate()
        _require_utc(self.qualified_at, "asset binding qualified_at")
        _require_utc(self.valid_until, "asset binding valid_until")

        _validate_security_account_description(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            description=self.description,
        )
        reference = self.security_reference.credential_reference
        if self.credential_receipt.reference != reference:
            raise AlpacaPaperAssetBindingConflict(
                "credential receipt does not bind the exact asset credential reference"
            )
        for freshness_receipt, phase in (
            (self.pre_account_binding_freshness, "pre-request"),
            (self.post_account_binding_freshness, "post-request"),
        ):
            if (
                freshness_receipt.account_id != self.account_binding.account_id
                or freshness_receipt.binding_id != self.account_binding.binding_id
                or freshness_receipt.binding_sha256 != self.account_binding.semantic_sha256
                or freshness_receipt.expected_provider_account_id
                != self.account_binding.expected_provider_account_id
                or freshness_receipt.sequence_number != self.account_binding.sequence_number
                or freshness_receipt.expires_at != self.account_binding.valid_until
            ):
                raise AlpacaPaperAssetBindingConflict(
                    f"{phase} account-binding receipt conflicts with exact source"
                )
        if self.policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY:
            raise AlpacaPaperAssetBindingConflict(
                "asset binding requires the exact Alpaca request-budget policy"
            )
        expected_demand = create_alpaca_paper_asset_observation_demand(
            security_reference=self.security_reference,
            account_binding=self.account_binding,
            description=self.description,
            idempotency_key=self.demand.idempotency_key,
            requested_at=self.demand.requested_at,
        )
        if (
            self.demand != expected_demand
            or self.demand.operation != AlpacaPaperBudgetOperation.OBSERVE_ASSET.value
            or self.demand.purpose is not BrokerRequestPurpose.RECONCILIATION
        ):
            raise AlpacaPaperAssetBindingConflict(
                "asset demand does not bind the exact protected observation purpose"
            )
        try:
            require_fresh_broker_request_permit(
                permit=self.permit,
                policy=self.policy,
                demand=self.demand,
                checked_at=self.permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperAssetBindingConflict(
                "asset permit is not fresh for the exact durable demand"
            ) from error
        if (
            self.permit_freshness.permit_id != self.permit.permit_id
            or self.permit_freshness.permit_sha256 != self.permit.semantic_sha256
            or self.permit_freshness.policy_sha256 != self.policy.semantic_sha256
            or self.permit_freshness.demand_sha256 != self.demand.semantic_sha256
            or self.permit_freshness.expires_at != self.permit.expires_at
        ):
            raise AlpacaPaperAssetBindingConflict(
                "durable permit freshness receipt conflicts with asset evidence"
            )
        if (
            self.pre_fence_receipt.fence != self.post_fence_receipt.fence
            or self.pre_fence_receipt.policy_sha256 != self.post_fence_receipt.policy_sha256
        ):
            raise AlpacaPaperAssetBindingConflict(
                "account fence changed during the authenticated asset read"
            )
        expected_request = AlpacaPaperAssetTransportRequest(
            description=self.description,
            credential_reference_sha256=reference.semantic_sha256,
            security_reference_sha256=self.security_reference.semantic_sha256,
            account_binding_sha256=self.account_binding.semantic_sha256,
            account_binding_freshness_sha256=(self.pre_account_binding_freshness.semantic_sha256),
            demand_sha256=self.demand.semantic_sha256,
            permit_sha256=self.permit.semantic_sha256,
            permit_freshness_sha256=self.permit_freshness.semantic_sha256,
            fence_receipt_sha256=self.pre_fence_receipt.semantic_sha256,
            started_at=self.request.started_at,
        )
        if self.request != expected_request:
            raise AlpacaPaperAssetBindingConflict(
                "asset request does not bind its exact pre-send evidence"
            )
        if (
            self.response.request_sha256 != self.request.semantic_sha256
            or self.response.transport_id != ALPACA_PAPER_ASSET_TRANSPORT_ID
            or self.response.transport_version != ALPACA_PAPER_ASSET_TRANSPORT_VERSION
            or not self.response.tls_verified
            or self.response.redirects_followed
        ):
            raise AlpacaPaperAssetBindingConflict(
                "asset response lacks the exact restricted transport profile"
            )
        observation = self.persisted_observation.observation
        raw_receipt = self.persisted_observation.receipt
        delivery = raw_receipt.delivery
        if (
            delivery.body != self.response.response_body
            or delivery.transport_status != self.response.http_status
            or delivery.provider_request_id != self.response.provider_request_id
            or delivery.media_type != self.response.media_type
            or observation.response_sha256 != self.response.response_sha256
        ):
            raise AlpacaPaperAssetBindingConflict(
                "asset response conflicts with its raw-first observation"
            )
        if (
            self.response.http_status != 200
            or self.response.provider_request_id is None
            or self.response.media_type != ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE
            or observation.outcome is not AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
            or observation.provider_asset_id != self.security_reference.expected_provider_asset_id
        ):
            raise AlpacaPaperAssetBindingConflict(
                "asset response is not the exact usable operator-pinned security"
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
            <= self.pre_account_binding_freshness.checked_at
            <= self.request.started_at
            <= received_at
            <= recorded_at
            <= self.post_fence_receipt.validated_at
            <= self.post_account_binding_freshness.checked_at
            == self.qualified_at
            < self.valid_until
        ):
            raise AlpacaPaperAssetBindingConflict(
                "authenticated asset evidence has conflicting trusted-time order"
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
            or not self.account_binding.is_fresh(self.pre_account_binding_freshness.checked_at)
            or not self.account_binding.is_fresh(received_at)
            or not self.account_binding.is_fresh(self.post_account_binding_freshness.checked_at)
        ):
            raise AlpacaPaperAssetBindingConflict(
                "authenticated asset authority expired during transport"
            )
        expected_valid_until = min(
            self.qualified_at + ALPACA_PAPER_ASSET_BINDING_TTL,
            self.account_binding.valid_until,
            self.post_fence_receipt.valid_until,
        )
        if self.valid_until != expected_valid_until or self.valid_until <= self.qualified_at:
            raise AlpacaPaperAssetBindingConflict(
                "asset binding validity does not match its bounded source window"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
                "authenticated_asset_evidence",
                self.security_reference.semantic_sha256,
                self.credential_receipt.semantic_sha256,
                self.account_binding.semantic_sha256,
                self.pre_account_binding_freshness.semantic_sha256,
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
                self.post_account_binding_freshness.semantic_sha256,
                self.qualified_at,
                self.valid_until,
            )
        )

    @property
    def credential_values_present(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _authenticated_asset_evidence(
    *,
    security_reference: AlpacaPaperSecurityReference,
    credential_receipt: AlpacaPaperCredentialResolutionReceipt,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    pre_account_binding_freshness: AlpacaPaperAccountBindingFreshnessReceipt,
    description: AlpacaPaperAssetObservationDescription,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    permit_freshness: BrokerRequestPermitFreshnessReceipt,
    pre_fence_receipt: AccountFenceReceipt,
    request: AlpacaPaperAssetTransportRequest,
    response: AlpacaPaperAssetTransportResponse,
    persisted_observation: PersistedAlpacaAssetObservation,
    post_fence_receipt: AccountFenceReceipt,
    post_account_binding_freshness: AlpacaPaperAccountBindingFreshnessReceipt,
) -> AlpacaPaperAuthenticatedAssetEvidence:
    qualified_at = post_account_binding_freshness.checked_at
    valid_until = min(
        qualified_at + ALPACA_PAPER_ASSET_BINDING_TTL,
        account_binding.valid_until,
        post_fence_receipt.valid_until,
    )
    evidence = object.__new__(AlpacaPaperAuthenticatedAssetEvidence)
    for field_name, value in (
        ("security_reference", security_reference),
        ("credential_receipt", credential_receipt),
        ("account_binding", account_binding),
        ("pre_account_binding_freshness", pre_account_binding_freshness),
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
        ("post_account_binding_freshness", post_account_binding_freshness),
        ("qualified_at", qualified_at),
        ("valid_until", valid_until),
    ):
        object.__setattr__(evidence, field_name, value)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAssetBinding:
    """Append-only, secret-free authenticated asset/security-binding fact."""

    account_id: str
    provider_id: str
    environment: str
    expected_provider_account_id: str
    instrument_id: str
    symbol: str
    expected_provider_asset_id: str
    observed_provider_asset_id: str
    asset_class: AlpacaAssetClass
    exchange: AlpacaAssetExchange
    asset_status: AlpacaAssetStatus
    tradable: bool
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
    pre_account_binding_freshness_sha256: str
    post_account_binding_freshness_sha256: str
    description_sha256: str
    policy_sha256: str
    demand_id: str
    demand_sha256: str
    permit_id: str
    permit_sha256: str
    permit_freshness_sha256: str
    pre_fence_receipt_sha256: str
    post_fence_receipt_sha256: str
    ingress_receipt_id: str
    ingress_receipt_sha256: str
    observation_sha256: str
    transport_request_sha256: str
    transport_response_sha256: str
    requested_at: datetime
    resolved_at: datetime
    pre_fence_validated_at: datetime
    permit_checked_at: datetime
    pre_account_binding_checked_at: datetime
    request_started_at: datetime
    received_at: datetime
    raw_recorded_at: datetime
    post_fence_validated_at: datetime
    post_account_binding_checked_at: datetime
    account_binding_valid_until: datetime
    post_fence_valid_until: datetime
    qualified_at: datetime
    valid_until: datetime
    sequence_number: int
    previous_binding_sha256: str | None
    evidence_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedAssetBinding must be recorder-produced")

    def _validate(self) -> None:
        _require_text(self.account_id, "asset binding account ID", maximum=64)
        if self.provider_id != ALPACA_PAPER_ADAPTER_ID or self.environment != "paper":
            raise AlpacaPaperAssetBindingConflict("asset binding must remain Alpaca paper scoped")
        _require_uuid(
            self.expected_provider_account_id,
            "asset binding provider account ID",
        )
        _require_text(self.instrument_id, "asset binding instrument ID", maximum=64)
        _require_text(self.symbol, "asset binding symbol", maximum=32)
        _require_uuid(
            self.expected_provider_asset_id,
            "asset binding expected provider asset ID",
        )
        _require_uuid(
            self.observed_provider_asset_id,
            "asset binding observed provider asset ID",
        )
        if self.expected_provider_asset_id != self.observed_provider_asset_id:
            raise AlpacaPaperAssetBindingConflict("durable asset binding provider UUIDs disagree")
        if (
            type(self.asset_class) is not AlpacaAssetClass
            or type(self.exchange) is not AlpacaAssetExchange
            or type(self.asset_status) is not AlpacaAssetStatus
            or type(self.tradable) is not bool
            or self.asset_class is not AlpacaAssetClass.US_EQUITY
            or self.exchange not in ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES
            or self.asset_status is not AlpacaAssetStatus.ACTIVE
            or not self.tradable
        ):
            raise AlpacaPaperAssetBindingConflict(
                "durable asset binding is not an active tradable U.S. equity"
            )
        credential_reference = AlpacaPaperCredentialReference(
            account_id=self.account_id,
            expected_provider_account_id=self.expected_provider_account_id,
            secret_ref=self.secret_ref,
            secret_version=self.secret_version,
        )
        security_reference = AlpacaPaperSecurityReference(
            credential_reference=credential_reference,
            instrument_id=self.instrument_id,
            symbol=self.symbol,
            expected_provider_asset_id=self.expected_provider_asset_id,
        )
        if (
            credential_reference.semantic_sha256 != self.credential_reference_sha256
            or security_reference.semantic_sha256 != self.security_reference_sha256
            or security_reference.capability_sha256 != self.capability_sha256
        ):
            raise AlpacaPaperAssetBindingConflict(
                "durable asset binding conflicts with its operator pins"
            )
        _require_safe_text(self.resolver_id, "asset binding resolver ID")
        _require_safe_text(self.resolver_version, "asset binding resolver version")
        _require_uuid(self.account_binding_id, "asset binding source account-binding ID")
        for digest_value, field_name in (
            (self.credential_reference_sha256, "credential reference"),
            (self.security_reference_sha256, "security reference"),
            (self.credential_resolution_sha256, "credential resolution"),
            (self.capability_sha256, "capability"),
            (self.account_binding_sha256, "account binding"),
            (
                self.pre_account_binding_freshness_sha256,
                "pre account-binding freshness",
            ),
            (
                self.post_account_binding_freshness_sha256,
                "post account-binding freshness",
            ),
            (self.description_sha256, "asset description"),
            (self.policy_sha256, "budget policy"),
            (self.demand_id, "request demand ID"),
            (self.demand_sha256, "request demand"),
            (self.permit_id, "request permit ID"),
            (self.permit_sha256, "request permit"),
            (self.permit_freshness_sha256, "permit freshness"),
            (self.pre_fence_receipt_sha256, "pre-request fence"),
            (self.post_fence_receipt_sha256, "post-request fence"),
            (self.ingress_receipt_id, "ingress receipt ID"),
            (self.ingress_receipt_sha256, "ingress receipt"),
            (self.observation_sha256, "asset observation"),
            (self.transport_request_sha256, "transport request"),
            (self.transport_response_sha256, "transport response"),
            (self.evidence_sha256, "asset evidence"),
        ):
            _require_sha256(digest_value, f"asset binding {field_name} digest")
        for timestamp_value, field_name in (
            (self.requested_at, "requested_at"),
            (self.resolved_at, "resolved_at"),
            (self.pre_fence_validated_at, "pre_fence_validated_at"),
            (self.permit_checked_at, "permit_checked_at"),
            (
                self.pre_account_binding_checked_at,
                "pre_account_binding_checked_at",
            ),
            (self.request_started_at, "request_started_at"),
            (self.received_at, "received_at"),
            (self.raw_recorded_at, "raw_recorded_at"),
            (self.post_fence_validated_at, "post_fence_validated_at"),
            (
                self.post_account_binding_checked_at,
                "post_account_binding_checked_at",
            ),
            (self.account_binding_valid_until, "account_binding_valid_until"),
            (self.post_fence_valid_until, "post_fence_valid_until"),
            (self.qualified_at, "qualified_at"),
            (self.valid_until, "valid_until"),
        ):
            _require_utc(timestamp_value, f"asset binding {field_name}")
        if not (
            self.requested_at
            <= self.resolved_at
            <= self.pre_fence_validated_at
            <= self.permit_checked_at
            <= self.pre_account_binding_checked_at
            <= self.request_started_at
            <= self.received_at
            <= self.raw_recorded_at
            <= self.post_fence_validated_at
            <= self.post_account_binding_checked_at
            == self.qualified_at
            < self.valid_until
            <= self.account_binding_valid_until
            and self.valid_until <= self.post_fence_valid_until
        ):
            raise AlpacaPaperAssetBindingConflict(
                "durable asset binding has conflicting time order"
            )
        if self.valid_until > self.qualified_at + ALPACA_PAPER_ASSET_BINDING_TTL:
            raise AlpacaPaperAssetBindingConflict(
                "durable asset binding exceeds the fixed maximum TTL"
            )
        if (
            type(self.sequence_number) is not int
            or self.sequence_number <= 0
            or (self.sequence_number == 1 and self.previous_binding_sha256 is not None)
            or (self.sequence_number > 1 and self.previous_binding_sha256 is None)
        ):
            raise AlpacaPaperAssetBindingConflict("asset binding predecessor shape is invalid")
        _require_optional_sha256(
            self.previous_binding_sha256,
            "asset binding predecessor digest",
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
            "authenticated_asset_binding",
            self.account_id,
            self.provider_id,
            self.environment,
            self.expected_provider_account_id,
            self.instrument_id,
            self.symbol,
            self.expected_provider_asset_id,
            self.observed_provider_asset_id,
            self.asset_class,
            self.exchange,
            self.asset_status,
            self.tradable,
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
            self.pre_account_binding_freshness_sha256,
            self.post_account_binding_freshness_sha256,
            self.description_sha256,
            self.policy_sha256,
            self.demand_id,
            self.demand_sha256,
            self.permit_id,
            self.permit_sha256,
            self.permit_freshness_sha256,
            self.pre_fence_receipt_sha256,
            self.post_fence_receipt_sha256,
            self.ingress_receipt_id,
            self.ingress_receipt_sha256,
            self.observation_sha256,
            self.transport_request_sha256,
            self.transport_response_sha256,
            self.requested_at,
            self.resolved_at,
            self.pre_fence_validated_at,
            self.permit_checked_at,
            self.pre_account_binding_checked_at,
            self.request_started_at,
            self.received_at,
            self.raw_recorded_at,
            self.post_fence_validated_at,
            self.post_account_binding_checked_at,
            self.account_binding_valid_until,
            self.post_fence_valid_until,
            self.qualified_at,
            self.valid_until,
            self.sequence_number,
            self.previous_binding_sha256,
            self.evidence_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def binding_id(self) -> str:
        return canonical_id(
            "alpaca-paper-authenticated-asset-binding",
            self.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def is_fresh(self, checked_at: datetime) -> bool:
        """Check only the sealed receipt window, never current-head authority."""

        _require_utc(checked_at, "asset binding checked_at")
        return self.qualified_at <= checked_at < self.valid_until

    @property
    def credential_resolution_established(self) -> bool:
        return True

    @property
    def authenticated_account_established(self) -> bool:
        return True

    @property
    def authenticated_security_established(self) -> bool:
        return True

    @property
    def durable_security_identity_binding_established(self) -> bool:
        return True

    @property
    def asset_tradability_established(self) -> bool:
        return True

    @property
    def security_master_ready(self) -> bool:
        return False

    @property
    def security_mapping_ready(self) -> bool:
        return False

    @property
    def asset_tradability_validation_ready(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return True

    @property
    def fractional_quantity_authorized(self) -> bool:
        return False

    @property
    def short_exposure_authorized(self) -> bool:
        return False

    @property
    def reduce_only_validation_ready(self) -> bool:
        return False

    @property
    def exchange_calendar_binding_ready(self) -> bool:
        return False

    @property
    def quote_collar_ready(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def transport_submission_ready(self) -> bool:
        return False

    @property
    def mark_in_flight_ready(self) -> bool:
        return False

    @property
    def coordinator_dispatch_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _alpaca_paper_authenticated_asset_binding(
    evidence: AlpacaPaperAuthenticatedAssetEvidence,
    *,
    sequence_number: int,
    previous_binding_sha256: str | None,
) -> AlpacaPaperAuthenticatedAssetBinding:
    """Construct the exact scalar binding a durable recorder must persist."""

    if type(evidence) is not AlpacaPaperAuthenticatedAssetEvidence:
        raise AlpacaPaperAssetBindingConflict("asset binding requires exact authenticated evidence")
    evidence._validate()
    observation = evidence.persisted_observation.observation
    if (
        observation.provider_asset_id is None
        or observation.asset_class is None
        or observation.exchange is None
        or observation.status is None
        or observation.tradable is None
    ):
        raise AlpacaPaperAssetBindingConflict(
            "asset binding requires complete normalized provider identity"
        )
    reference = evidence.security_reference
    credential_reference = reference.credential_reference
    receipt = evidence.persisted_observation.receipt
    binding = object.__new__(AlpacaPaperAuthenticatedAssetBinding)
    values: tuple[tuple[str, object], ...] = (
        ("account_id", reference.account_id),
        ("provider_id", reference.provider_id),
        ("environment", reference.environment),
        ("expected_provider_account_id", reference.expected_provider_account_id),
        ("instrument_id", reference.instrument_id),
        ("symbol", reference.symbol),
        ("expected_provider_asset_id", reference.expected_provider_asset_id),
        ("observed_provider_asset_id", observation.provider_asset_id),
        ("asset_class", observation.asset_class),
        ("exchange", observation.exchange),
        ("asset_status", observation.status),
        ("tradable", observation.tradable),
        ("secret_ref", credential_reference.secret_ref),
        ("secret_version", credential_reference.secret_version),
        ("credential_reference_sha256", credential_reference.semantic_sha256),
        ("security_reference_sha256", reference.semantic_sha256),
        (
            "credential_resolution_sha256",
            evidence.credential_receipt.semantic_sha256,
        ),
        ("resolver_id", evidence.credential_receipt.resolver_id),
        ("resolver_version", evidence.credential_receipt.resolver_version),
        ("capability_sha256", reference.capability_sha256),
        ("account_binding_id", evidence.account_binding.binding_id),
        ("account_binding_sha256", evidence.account_binding.semantic_sha256),
        (
            "pre_account_binding_freshness_sha256",
            evidence.pre_account_binding_freshness.semantic_sha256,
        ),
        (
            "post_account_binding_freshness_sha256",
            evidence.post_account_binding_freshness.semantic_sha256,
        ),
        ("description_sha256", evidence.description.semantic_sha256),
        ("policy_sha256", evidence.policy.semantic_sha256),
        ("demand_id", evidence.demand.demand_id),
        ("demand_sha256", evidence.demand.semantic_sha256),
        ("permit_id", evidence.permit.permit_id),
        ("permit_sha256", evidence.permit.semantic_sha256),
        (
            "permit_freshness_sha256",
            evidence.permit_freshness.semantic_sha256,
        ),
        ("pre_fence_receipt_sha256", evidence.pre_fence_receipt.semantic_sha256),
        ("post_fence_receipt_sha256", evidence.post_fence_receipt.semantic_sha256),
        ("ingress_receipt_id", receipt.receipt_id),
        ("ingress_receipt_sha256", receipt.semantic_sha256),
        ("observation_sha256", observation.semantic_sha256),
        ("transport_request_sha256", evidence.request.semantic_sha256),
        ("transport_response_sha256", evidence.response.semantic_sha256),
        ("requested_at", evidence.demand.requested_at),
        ("resolved_at", evidence.credential_receipt.resolved_at),
        ("pre_fence_validated_at", evidence.pre_fence_receipt.validated_at),
        ("permit_checked_at", evidence.permit_freshness.checked_at),
        (
            "pre_account_binding_checked_at",
            evidence.pre_account_binding_freshness.checked_at,
        ),
        ("request_started_at", evidence.request.started_at),
        ("received_at", observation.received_at),
        ("raw_recorded_at", receipt.delivery.recorded_at),
        ("post_fence_validated_at", evidence.post_fence_receipt.validated_at),
        (
            "post_account_binding_checked_at",
            evidence.post_account_binding_freshness.checked_at,
        ),
        ("account_binding_valid_until", evidence.account_binding.valid_until),
        ("post_fence_valid_until", evidence.post_fence_receipt.valid_until),
        ("qualified_at", evidence.qualified_at),
        ("valid_until", evidence.valid_until),
        ("sequence_number", sequence_number),
        ("previous_binding_sha256", previous_binding_sha256),
        ("evidence_sha256", evidence.semantic_sha256),
    )
    for field_name, value in values:
        object.__setattr__(binding, field_name, value)
    binding._validate()
    return binding


class AlpacaPaperAssetBindingRecorder(Protocol):
    """Durable append-only recorder for authenticated asset evidence."""

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAssetEvidence,
    ) -> AlpacaPaperAuthenticatedAssetBinding: ...


def _observe_authenticated_alpaca_paper_asset_with_transport(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAssetObservationDescription,
    credential_resolver: AlpacaPaperAssetCredentialResolver,
    transport: _AlpacaPaperAssetTransport,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    binding_recorder: AlpacaPaperAssetBindingRecorder,
    clock: Clock,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedAssetBinding:
    """Trusted internal seam for deterministic transport-contract testing."""

    _validate_security_account_description(
        security_reference=security_reference,
        account_binding=account_binding,
        description=description,
    )
    if type(fence) is not AccountFence:
        raise AlpacaPaperAssetRuntimeError("asset runtime requires an exact fence")
    if fence.account_id != security_reference.account_id:
        raise AlpacaPaperAssetBindingConflict(
            "asset runtime fence belongs to another local account"
        )
    for port, method_name, field_name in (
        (budget, "issue_new", "durable new-permit issuer"),
        (budget, "authenticate_fresh", "durable budget authenticator"),
        (
            account_bindings,
            "authenticate_terminal_fresh",
            "terminal account-binding authenticator",
        ),
        (coordinator, "revalidate", "account coordinator"),
        (ingress_recorder, "record", "raw ingress recorder"),
        (binding_recorder, "record", "asset binding recorder"),
        (transport, "execute", "restricted asset transport"),
    ):
        if not callable(getattr(port, method_name, None)):
            raise AlpacaPaperAssetRuntimeError(f"asset runtime requires a {field_name}")
    if getattr(coordinator, "account_id", None) != security_reference.account_id:
        raise AlpacaPaperAssetBindingConflict(
            "account coordinator belongs to another local account"
        )
    if (
        getattr(transport, "transport_id", None) != ALPACA_PAPER_ASSET_TRANSPORT_ID
        or getattr(transport, "transport_version", None) != ALPACA_PAPER_ASSET_TRANSPORT_VERSION
    ):
        raise AlpacaPaperAssetTransportError(
            "asset runtime requires the exact restricted transport profile"
        )

    requested_at = _trusted_now(clock, "asset observation requested_at")
    demand = create_alpaca_paper_asset_observation_demand(
        security_reference=security_reference,
        account_binding=account_binding,
        description=description,
        idempotency_key=request_idempotency_key,
        requested_at=requested_at,
    )
    credential_session = _resolve_alpaca_paper_asset_credentials(
        reference=security_reference.credential_reference,
        resolver=credential_resolver,
        clock=clock,
    )
    try:
        permit = budget.issue_new(
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        if type(permit) is not BrokerRequestPermit:
            raise AlpacaPaperAssetRuntimeError("durable budget issuer returned an invalid permit")
        pre_fence_receipt = coordinator.revalidate(fence)
        if type(pre_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperAssetRuntimeError(
                "account coordinator returned an invalid pre-request receipt"
            )
        pre_fence_receipt._validate()
        if pre_fence_receipt.fence != fence:
            raise AlpacaPaperAssetBindingConflict(
                "account coordinator returned a receipt for another pre-request fence"
            )
        permit_freshness = budget.authenticate_fresh(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        if type(permit_freshness) is not BrokerRequestPermitFreshnessReceipt:
            raise AlpacaPaperAssetRuntimeError(
                "durable budget authenticator returned an invalid freshness receipt"
            )
        permit_freshness._validate()
        if (
            permit_freshness.permit_id != permit.permit_id
            or permit_freshness.permit_sha256 != permit.semantic_sha256
            or permit_freshness.policy_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256
            or permit_freshness.demand_sha256 != demand.semantic_sha256
            or permit_freshness.expires_at != permit.expires_at
        ):
            raise AlpacaPaperAssetBindingConflict(
                "durable permit freshness receipt conflicts before asset transport"
            )
        try:
            require_fresh_broker_request_permit(
                permit=permit,
                policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
                demand=demand,
                checked_at=permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperAssetBindingConflict(
                "durable asset-observation permit is invalid before transport"
            ) from error
        pre_account_binding_checked_at = _trusted_now(
            clock,
            "pre-request account-binding checked_at",
        )
        pre_account_binding_freshness = _authenticate_terminal_account_binding(
            account_bindings,
            account_binding,
            checked_at=pre_account_binding_checked_at,
            phase="before",
        )
        started_at = _trusted_now(clock, "asset transport started_at")
        if permit_freshness.checked_at > started_at or not permit.is_fresh(started_at):
            raise AlpacaPaperAssetBindingConflict(
                "durable request permit is not current at asset transport start"
            )
        if not (pre_fence_receipt.validated_at <= started_at < pre_fence_receipt.valid_until):
            raise AlpacaPaperAssetBindingConflict(
                "account fence is not current at asset transport start"
            )
        if not account_binding.is_fresh(started_at):
            raise AlpacaPaperAssetBindingConflict(
                "terminal account binding is not current at asset transport start"
            )
        request = AlpacaPaperAssetTransportRequest(
            description=description,
            credential_reference_sha256=(security_reference.credential_reference.semantic_sha256),
            security_reference_sha256=security_reference.semantic_sha256,
            account_binding_sha256=account_binding.semantic_sha256,
            account_binding_freshness_sha256=(pre_account_binding_freshness.semantic_sha256),
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
            raise AlpacaPaperAssetTransportError(
                "restricted asset transport failed with sanitized diagnostics"
            ) from None
        received_at = _trusted_now(clock, "asset transport received_at")
    finally:
        credential_session.close()

    if type(response) is not AlpacaPaperAssetTransportResponse:
        raise AlpacaPaperAssetTransportError("asset transport returned an invalid response")
    response.__post_init__()
    if response.request_sha256 != request.semantic_sha256:
        raise AlpacaPaperAssetTransportError(
            "asset transport returned a response for another request"
        )
    if received_at < started_at:
        raise AlpacaPaperAssetRuntimeError("asset transport clock regressed")
    recorded_at = _trusted_now(clock, "asset raw response recorded_at")
    if recorded_at < received_at:
        raise AlpacaPaperAssetRuntimeError("asset raw-record clock regressed")
    persisted_observation = persist_then_decode_alpaca_asset_observation_response(
        ingress_recorder,
        description,
        delivery_idempotency_key=delivery_idempotency_key,
        http_status=response.http_status,
        provider_request_id=response.provider_request_id,
        response_body=response.response_body,
        received_at=received_at,
        recorded_at=recorded_at,
        media_type=response.media_type,
    )
    if (
        persisted_observation.observation.provider_asset_id
        != security_reference.expected_provider_asset_id
    ):
        raise AlpacaPaperAssetBindingConflict(
            "observed Alpaca asset does not match the operator-pinned provider UUID"
        )
    post_fence_receipt = coordinator.revalidate(fence)
    if type(post_fence_receipt) is not AccountFenceReceipt:
        raise AlpacaPaperAssetRuntimeError(
            "account coordinator returned an invalid post-request receipt"
        )
    post_fence_receipt._validate()
    if post_fence_receipt.fence != fence:
        raise AlpacaPaperAssetBindingConflict(
            "account fence changed during the authenticated asset read"
        )
    post_account_binding_checked_at = _trusted_now(
        clock,
        "post-request account-binding checked_at",
    )
    post_account_binding_freshness = _authenticate_terminal_account_binding(
        account_bindings,
        account_binding,
        checked_at=post_account_binding_checked_at,
        phase="after",
    )
    evidence = _authenticated_asset_evidence(
        security_reference=security_reference,
        credential_receipt=credential_session.receipt,
        account_binding=account_binding,
        pre_account_binding_freshness=pre_account_binding_freshness,
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
        post_account_binding_freshness=post_account_binding_freshness,
    )
    binding = binding_recorder.record(evidence)
    if type(binding) is not AlpacaPaperAuthenticatedAssetBinding:
        raise AlpacaPaperAssetRuntimeError(
            "asset binding recorder returned an invalid durable fact"
        )
    binding._validate()
    if binding.evidence_sha256 != evidence.semantic_sha256:
        raise AlpacaPaperAssetBindingConflict(
            "durable asset binding does not bind the exact runtime evidence"
        )
    expected_binding = _alpaca_paper_authenticated_asset_binding(
        evidence,
        sequence_number=binding.sequence_number,
        previous_binding_sha256=binding.previous_binding_sha256,
    )
    if binding != expected_binding:
        raise AlpacaPaperAssetBindingConflict(
            "durable asset binding conflicts with the exact runtime evidence"
        )
    return binding


def observe_authenticated_alpaca_paper_asset(
    *,
    security_reference: AlpacaPaperSecurityReference,
    account_binding: AlpacaPaperAuthenticatedAccountBinding,
    description: AlpacaPaperAssetObservationDescription,
    credential_resolver: AlpacaPaperAssetCredentialResolver,
    budget: BrokerRequestBudgetRuntimePort,
    account_bindings: AlpacaPaperAccountBindingRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    binding_recorder: AlpacaPaperAssetBindingRecorder,
    clock: Clock,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedAssetBinding:
    """Execute the exact production asset GET and persist a non-trading binding."""

    return _observe_authenticated_alpaca_paper_asset_with_transport(
        security_reference=security_reference,
        account_binding=account_binding,
        description=description,
        credential_resolver=credential_resolver,
        transport=_HttpxAlpacaPaperAssetTransport(),
        budget=budget,
        account_bindings=account_bindings,
        coordinator=coordinator,
        fence=fence,
        ingress_recorder=ingress_recorder,
        binding_recorder=binding_recorder,
        clock=clock,
        request_idempotency_key=request_idempotency_key,
        delivery_idempotency_key=delivery_idempotency_key,
    )


__all__ = [
    "ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE",
    "ALPACA_PAPER_ASSET_BINDING_TTL",
    "ALPACA_PAPER_ASSET_HTTPX_PHASE_TIMEOUT",
    "ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_ASSET_TRANSPORT_ID",
    "ALPACA_PAPER_ASSET_TRANSPORT_VERSION",
    "AlpacaPaperAssetBindingConflict",
    "AlpacaPaperAssetBindingRecorder",
    "AlpacaPaperAssetCredentialResolver",
    "AlpacaPaperAssetRuntimeError",
    "AlpacaPaperAssetTransportError",
    "AlpacaPaperAssetTransportRequest",
    "AlpacaPaperAssetTransportResponse",
    "AlpacaPaperAuthenticatedAssetBinding",
    "AlpacaPaperAuthenticatedAssetEvidence",
    "AlpacaPaperSecurityReference",
    "alpaca_paper_asset_observation_correlation_sha256",
    "create_alpaca_paper_asset_observation_demand",
    "observe_authenticated_alpaca_paper_asset",
]
