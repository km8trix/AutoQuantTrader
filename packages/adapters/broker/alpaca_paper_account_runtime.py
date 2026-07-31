"""Authenticated, read-only Alpaca paper account-binding runtime.

Phase 4G deliberately exposes one exact network operation: ``GET /v2/account``.
It resolves paper-scoped credentials ephemerally, consumes durable
reconciliation-tier request capacity, revalidates the stable account fence,
retains a completed in-bound raw entity body before decoding when trusted
receive/record times and the ingress recorder are available, and can persist a
short-lived local-alias-to-provider-account binding.

The module cannot submit, replace, or cancel orders.  A successful account
binding is not reconciliation evidence and grants no trading effect.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import NoReturn, Protocol
from uuid import UUID

import httpx

from packages.adapters.broker.alpaca_paper import (
    ALPACA_AUTH_HEADER_NAMES,
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAccountObservationOutcome,
    AlpacaPaperAccountObservationDescription,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaAccountObservation,
    persist_then_decode_alpaca_account_observation_response,
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

ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION = (
    "phase4g-authenticated-alpaca-paper-account-binding-v1"
)
ALPACA_PAPER_ACCOUNT_BINDING_FRESHNESS_CONTRACT_VERSION = (
    "phase4h-terminal-alpaca-paper-account-binding-freshness-v1"
)
ALPACA_PAPER_ACCOUNT_IDENTITY_CONTINUITY_CONTRACT_VERSION = (
    "phase4i-terminal-alpaca-paper-account-identity-continuity-v1"
)
ALPACA_PAPER_CREDENTIAL_SESSION_TTL = timedelta(seconds=30)
ALPACA_PAPER_ACCOUNT_BINDING_TTL = timedelta(seconds=5)
ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT = timedelta(seconds=2)
ALPACA_PAPER_ACCOUNT_TRANSPORT_ID = "strict-httpx-alpaca-paper-account-get"
ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION = "1.0.0"
ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE = "application/json"
ALPACA_PAPER_MAX_SECRET_REFERENCE_LENGTH = 256
ALPACA_PAPER_MAX_SECRET_VALUE_BYTES = 512

_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRET_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AlpacaPaperAccountRuntimeError(AlpacaPaperContractError):
    """Authenticated account-runtime evidence is malformed or inconsistent."""


class AlpacaPaperCredentialResolutionError(AlpacaPaperAccountRuntimeError):
    """Paper credential resolution failed without disclosing secret material."""


class AlpacaPaperCredentialExpired(AlpacaPaperCredentialResolutionError):
    """An ephemeral credential session is closed or outside its validity window."""


class AlpacaPaperAccountTransportError(AlpacaPaperAccountRuntimeError):
    """The restricted account transport failed or violated its contract."""


class AlpacaPaperAccountBindingConflict(AlpacaPaperAccountRuntimeError):
    """Account evidence conflicts with its operator-pinned identity."""


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
        raise AlpacaPaperAccountRuntimeError(
            f"{field_name} must be bounded, non-empty trimmed text"
        )
    return value


def _require_safe_text(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name)
    if _SAFE_TEXT.fullmatch(raw) is None:
        raise AlpacaPaperAccountRuntimeError(f"{field_name} must use the closed safe-text alphabet")
    return raw


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAccountRuntimeError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAccountRuntimeError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAccountRuntimeError(str(error)) from error
    return value


def _require_uuid(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum=36)
    try:
        parsed = UUID(raw)
    except (AttributeError, TypeError, ValueError) as error:
        raise AlpacaPaperAccountRuntimeError(f"{field_name} must be a canonical UUID") from error
    if str(parsed) != raw:
        raise AlpacaPaperAccountRuntimeError(f"{field_name} must be a canonical lowercase UUID")
    return raw


def _require_secret_reference(value: object) -> str:
    raw = _require_text(
        value,
        "paper broker secret reference",
        maximum=ALPACA_PAPER_MAX_SECRET_REFERENCE_LENGTH,
    )
    prefix = "secret://paper/"
    if not raw.startswith(prefix):
        raise AlpacaPaperAccountRuntimeError(
            "paper broker credentials require a paper-scoped secret reference"
        )
    path = raw.removeprefix(prefix)
    segments = path.split("/")
    if not segments or any(
        not segment or segment in {".", ".."} or _SECRET_SEGMENT.fullmatch(segment) is None
        for segment in segments
    ):
        raise AlpacaPaperAccountRuntimeError(
            "paper broker secret reference must use canonical safe path segments"
        )
    return raw


def _trusted_now(clock: Clock, field_name: str) -> datetime:
    if not callable(getattr(clock, "now", None)):
        raise AlpacaPaperAccountRuntimeError("account runtime requires a trusted clock")
    return _require_utc(clock.now(), field_name)


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
class AlpacaPaperCredentialReference:
    """Nonsecret operator pin for one paper account credential version."""

    account_id: str
    expected_provider_account_id: str
    secret_ref: str
    secret_version: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "credential reference account ID", maximum=64)
        _require_uuid(
            self.expected_provider_account_id,
            "expected Alpaca provider account ID",
        )
        _require_secret_reference(self.secret_ref)
        _require_safe_text(self.secret_version, "paper broker secret version")
        ALPACA_PAPER_CAPABILITIES.__post_init__()

    @property
    def provider_id(self) -> str:
        return ALPACA_PAPER_ADAPTER_ID

    @property
    def environment(self) -> str:
        return "paper"

    @property
    def capability_sha256(self) -> str:
        return ALPACA_PAPER_CAPABILITIES.semantic_sha256

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
            "credential_reference",
            self.provider_id,
            self.environment,
            self.capability_sha256,
            self.account_id,
            self.expected_provider_account_id,
            self.secret_ref,
            self.secret_version,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def credential_values_present(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


class _AlpacaPaperCredentialMaterial:
    """Ephemeral API key bytes with redacted representation and explicit closure."""

    __slots__ = ("_api_key_id", "_closed", "_secret_key")

    def __init__(self, *, api_key_id: str, secret_key: str) -> None:
        self._api_key_id = bytearray()
        self._secret_key = bytearray()
        self._closed = False
        try:
            self._api_key_id = self._encode_secret(api_key_id)
            self._secret_key = self._encode_secret(secret_key)
        except Exception:
            self.close()
            raise

    @staticmethod
    def _encode_secret(value: object) -> bytearray:
        if type(value) is not str:
            raise AlpacaPaperCredentialResolutionError(
                "resolved Alpaca credential values must be exact strings"
            )
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise AlpacaPaperCredentialResolutionError(
                "resolved Alpaca credential values must use visible ASCII"
            ) from error
        if (
            not encoded
            or len(encoded) > ALPACA_PAPER_MAX_SECRET_VALUE_BYTES
            or any(byte < 33 or byte > 126 for byte in encoded)
        ):
            raise AlpacaPaperCredentialResolutionError(
                "resolved Alpaca credential values violate the secret bound"
            )
        return bytearray(encoded)

    def _require_open(self) -> None:
        if self._closed:
            raise AlpacaPaperCredentialExpired("Alpaca credential material is closed")

    def _header_value(self, header_name: str) -> str:
        self._require_open()
        if header_name == ALPACA_AUTH_HEADER_NAMES[0]:
            return bytes(self._api_key_id).decode("ascii")
        if header_name == ALPACA_AUTH_HEADER_NAMES[1]:
            return bytes(self._secret_key).decode("ascii")
        raise KeyError(header_name)

    def close(self) -> None:
        if self._closed:
            return
        for secret in (self._api_key_id, self._secret_key):
            for index in range(len(secret)):
                secret[index] = 0
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> _AlpacaPaperCredentialMaterial:
        self._require_open()
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def __copy__(self) -> None:
        raise TypeError("Alpaca credential material cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("Alpaca credential material cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Alpaca credential material cannot be serialized")

    def __repr__(self) -> str:
        return f"_AlpacaPaperCredentialMaterial(<redacted>, closed={self._closed})"

    def __str__(self) -> str:
        return "<redacted Alpaca paper credential material>"

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


class _AlpacaPaperAuthenticationHeaders(Mapping[str, str]):
    """Mapping view that redacts both Alpaca authentication values in reprs."""

    __slots__ = ("_material",)

    def __init__(self, material: _AlpacaPaperCredentialMaterial) -> None:
        if type(material) is not _AlpacaPaperCredentialMaterial:
            raise AlpacaPaperCredentialResolutionError(
                "authentication headers require exact credential material"
            )
        material._require_open()
        self._material = material

    def __getitem__(self, key: str) -> str:
        if key not in ALPACA_AUTH_HEADER_NAMES:
            raise KeyError(key)
        return self._material._header_value(key)

    def __iter__(self) -> Iterator[str]:
        self._material._require_open()
        return iter(ALPACA_AUTH_HEADER_NAMES)

    def __len__(self) -> int:
        self._material._require_open()
        return len(ALPACA_AUTH_HEADER_NAMES)

    def __repr__(self) -> str:
        return "AlpacaPaperAuthenticationHeaders(<redacted>)"

    def __str__(self) -> str:
        return "<redacted Alpaca paper authentication headers>"

    def __copy__(self) -> None:
        raise TypeError("Alpaca authentication headers cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("Alpaca authentication headers cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Alpaca authentication headers cannot be serialized")


class AlpacaPaperCredentialResolver(Protocol):
    """Trusted port returning one opaque envelope for an exact reference."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_account_observation(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object: ...


class _AlpacaPaperCredentialResolverMetadata(Protocol):
    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...


def create_alpaca_paper_credential_envelope(
    *,
    api_key_id: str,
    secret_key: str,
) -> object:
    """Seal credential values for consumption only by the exact account runtime."""

    return _AlpacaPaperCredentialMaterial(
        api_key_id=api_key_id,
        secret_key=secret_key,
    )


@dataclass(frozen=True, slots=True)
class AlpacaPaperCredentialResolutionReceipt:
    """Secret-free receipt for one ephemeral resolution."""

    reference: AlpacaPaperCredentialReference
    resolver_id: str
    resolver_version: str
    started_at: datetime
    resolved_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if type(self.reference) is not AlpacaPaperCredentialReference:
            raise AlpacaPaperCredentialResolutionError(
                "credential receipt requires an exact paper reference"
            )
        self.reference.__post_init__()
        _require_safe_text(self.resolver_id, "credential resolver ID")
        _require_safe_text(self.resolver_version, "credential resolver version")
        _require_utc(self.started_at, "credential resolution started_at")
        _require_utc(self.resolved_at, "credential resolution resolved_at")
        _require_utc(self.valid_until, "credential resolution valid_until")
        if self.resolved_at < self.started_at:
            raise AlpacaPaperCredentialResolutionError("credential resolution clock cannot regress")
        if self.valid_until != self.resolved_at + ALPACA_PAPER_CREDENTIAL_SESSION_TTL:
            raise AlpacaPaperCredentialResolutionError(
                "credential resolution validity must bind the fixed session TTL"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
                "credential_resolution_receipt",
                self.reference.semantic_sha256,
                self.resolver_id,
                self.resolver_version,
                self.started_at,
                self.resolved_at,
                self.valid_until,
            )
        )

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-credential-resolution",
            self.semantic_sha256,
        )

    def is_fresh(self, checked_at: datetime) -> bool:
        _require_utc(checked_at, "credential checked_at")
        return self.resolved_at <= checked_at < self.valid_until

    @property
    def credential_values_present(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


class _AlpacaPaperCredentialSession:
    """Proof-constructed ephemeral session; only its receipt is persistable."""

    __slots__ = ("_material", "receipt")

    _material: _AlpacaPaperCredentialMaterial
    receipt: AlpacaPaperCredentialResolutionReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("_AlpacaPaperCredentialSession must be resolver-produced")

    def authentication_headers(
        self,
        *,
        checked_at: datetime,
    ) -> _AlpacaPaperAuthenticationHeaders:
        if not self.receipt.is_fresh(checked_at):
            raise AlpacaPaperCredentialExpired(
                "Alpaca credential session is outside its validity window"
            )
        self._material._require_open()
        return _AlpacaPaperAuthenticationHeaders(self._material)

    @property
    def closed(self) -> bool:
        return self._material.closed

    def close(self) -> None:
        self._material.close()

    def __enter__(self) -> _AlpacaPaperCredentialSession:
        self._material._require_open()
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def __repr__(self) -> str:
        return (
            "_AlpacaPaperCredentialSession("
            f"receipt={self.receipt!r}, material=<redacted>, closed={self.closed})"
        )

    def __str__(self) -> str:
        return "<redacted Alpaca paper credential session>"

    def __copy__(self) -> None:
        raise TypeError("Alpaca credential sessions cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        del memo
        raise TypeError("Alpaca credential sessions cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Alpaca credential sessions cannot be serialized")


def _resolve_alpaca_paper_credentials_for_operation(
    *,
    reference: AlpacaPaperCredentialReference,
    resolver: _AlpacaPaperCredentialResolverMetadata,
    resolver_method_name: str,
    clock: Clock,
) -> _AlpacaPaperCredentialSession:
    """Resolve one paper credential reference without retaining values in evidence."""

    if type(reference) is not AlpacaPaperCredentialReference:
        raise AlpacaPaperCredentialResolutionError(
            "credential resolution requires an exact paper reference"
        )
    reference.__post_init__()
    resolver_access_failed = False
    resolver_id_value: object = None
    resolver_version_value: object = None
    resolve_method: object = None
    try:
        resolver_id_value = resolver.resolver_id
        resolver_version_value = resolver.resolver_version
        resolve_method = getattr(resolver, resolver_method_name)
    except Exception:
        resolver_access_failed = True
    if resolver_access_failed:
        raise AlpacaPaperCredentialResolutionError(
            "paper credential resolver metadata access failed"
        ) from None
    resolver_id = _require_safe_text(
        resolver_id_value,
        "credential resolver ID",
    )
    resolver_version = _require_safe_text(
        resolver_version_value,
        "credential resolver version",
    )
    if not callable(resolve_method):
        raise AlpacaPaperCredentialResolutionError(
            "credential resolution requires a trusted resolver"
        )
    started_at = _trusted_now(clock, "credential resolution start")
    resolution_failed = False
    material: object | None = None
    try:
        material = resolve_method(reference)
    except Exception:
        resolution_failed = True
    if resolution_failed:
        raise AlpacaPaperCredentialResolutionError("paper credential resolution failed") from None
    if type(material) is not _AlpacaPaperCredentialMaterial:
        with suppress(Exception):
            close_method = material.__getattribute__("close")
            if callable(close_method):
                close_method()
        raise AlpacaPaperCredentialResolutionError(
            "credential resolver returned unsupported material"
        )
    try:
        material._require_open()
        resolved_at = _trusted_now(clock, "credential resolution completion")
        receipt = AlpacaPaperCredentialResolutionReceipt(
            reference=reference,
            resolver_id=resolver_id,
            resolver_version=resolver_version,
            started_at=started_at,
            resolved_at=resolved_at,
            valid_until=resolved_at + ALPACA_PAPER_CREDENTIAL_SESSION_TTL,
        )
        session = object.__new__(_AlpacaPaperCredentialSession)
        session.receipt = receipt
        session._material = material
        return session
    except Exception:
        material.close()
        raise


def _resolve_alpaca_paper_credentials(
    *,
    reference: AlpacaPaperCredentialReference,
    resolver: AlpacaPaperCredentialResolver,
    clock: Clock,
) -> _AlpacaPaperCredentialSession:
    """Resolve credentials only for the Phase 4G account-observation boundary."""

    return _resolve_alpaca_paper_credentials_for_operation(
        reference=reference,
        resolver=resolver,
        resolver_method_name="_resolve_for_account_observation",
        clock=clock,
    )


def _resolve_alpaca_paper_asset_credentials(
    *,
    reference: AlpacaPaperCredentialReference,
    resolver: _AlpacaPaperCredentialResolverMetadata,
    clock: Clock,
) -> _AlpacaPaperCredentialSession:
    """Resolve credentials only for the private Phase 4H asset-observation seam."""

    return _resolve_alpaca_paper_credentials_for_operation(
        reference=reference,
        resolver=resolver,
        resolver_method_name="_resolve_for_asset_observation",
        clock=clock,
    )


def alpaca_paper_account_observation_correlation_sha256(
    *,
    reference: AlpacaPaperCredentialReference,
    description: AlpacaPaperAccountObservationDescription,
) -> str:
    """Bind an account-observation demand to its exact alias and UUID pin."""

    if type(reference) is not AlpacaPaperCredentialReference:
        raise AlpacaPaperAccountRuntimeError(
            "account observation correlation requires an exact credential reference"
        )
    if type(description) is not AlpacaPaperAccountObservationDescription:
        raise AlpacaPaperAccountRuntimeError(
            "account observation correlation requires an exact account description"
        )
    reference.__post_init__()
    description.__post_init__()
    if description.account_id != reference.account_id:
        raise AlpacaPaperAccountBindingConflict(
            "account description belongs to another credential reference"
        )
    return _semantic_sha256(
        (
            ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
            "account_observation_correlation",
            reference.semantic_sha256,
            description.semantic_sha256,
        )
    )


def create_alpaca_paper_account_observation_demand(
    *,
    reference: AlpacaPaperCredentialReference,
    description: AlpacaPaperAccountObservationDescription,
    idempotency_key: str,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Create the fixed reconciliation-tier demand for one account GET."""

    return create_alpaca_paper_request_demand(
        account_id=reference.account_id,
        idempotency_key=idempotency_key,
        operation=AlpacaPaperBudgetOperation.OBSERVE_ACCOUNT,
        correlation_sha256=alpaca_paper_account_observation_correlation_sha256(
            reference=reference,
            description=description,
        ),
        requested_at=requested_at,
    )


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountTransportRequest:
    """Secret-free description of one exact preauthorized account GET."""

    description: AlpacaPaperAccountObservationDescription
    credential_reference_sha256: str
    demand_sha256: str
    permit_sha256: str
    permit_freshness_sha256: str
    fence_receipt_sha256: str
    started_at: datetime
    httpx_phase_timeout: timedelta = ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperAccountObservationDescription:
            raise AlpacaPaperAccountTransportError(
                "account transport requires an exact account description"
            )
        self.description.__post_init__()
        for value, field_name in (
            (self.credential_reference_sha256, "credential reference digest"),
            (self.demand_sha256, "request demand digest"),
            (self.permit_sha256, "request permit digest"),
            (self.permit_freshness_sha256, "permit freshness digest"),
            (self.fence_receipt_sha256, "fence receipt digest"),
        ):
            _require_sha256(value, f"account transport {field_name}")
        _require_utc(self.started_at, "account transport started_at")
        if (
            type(self.httpx_phase_timeout) is not timedelta
            or self.httpx_phase_timeout != ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT
        ):
            raise AlpacaPaperAccountTransportError(
                "account transport must use the fixed socket-I/O inactivity timeout"
            )
        if (
            self.description.method != "GET"
            or self.description.base_url != ALPACA_PAPER_TRADING_BASE_URL
            or self.description.path != ALPACA_PAPER_CAPABILITIES.account_path
            or self.description.query
        ):
            raise AlpacaPaperAccountTransportError(
                "account transport request escaped the fixed account GET"
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
                ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
                "account_transport_request",
                self.description.semantic_sha256,
                self.credential_reference_sha256,
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
class AlpacaPaperAccountTransportResponse:
    """Bounded exact bytes from one restricted account GET."""

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
        _require_sha256(self.request_sha256, "account response request digest")
        _require_safe_text(self.transport_id, "account transport ID")
        _require_safe_text(self.transport_version, "account transport version")
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise AlpacaPaperAccountTransportError(
                "account response status must be an exact HTTP status"
            )
        if self.provider_request_id is not None:
            _require_text(
                self.provider_request_id,
                "Alpaca account X-Request-ID",
                maximum=256,
            )
        if self.media_type is not None:
            _require_text(
                self.media_type,
                "Alpaca account response media type",
                maximum=128,
            )
        if type(self.response_body) is not bytes:
            raise AlpacaPaperAccountTransportError(
                "account transport response body must be exact bytes"
            )
        if len(self.response_body) > MAX_BROKER_INGRESS_BODY_BYTES:
            raise AlpacaPaperAccountTransportError(
                "account transport response exceeds the durable raw bound"
            )
        if type(self.tls_verified) is not bool or not self.tls_verified:
            raise AlpacaPaperAccountTransportError("account transport must verify provider TLS")
        if type(self.redirects_followed) is not bool or self.redirects_followed:
            raise AlpacaPaperAccountTransportError("account transport cannot follow redirects")

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
                "account_transport_response",
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


class _AlpacaPaperAccountTransport(Protocol):
    """Restricted transport port whose sole operation is one account GET."""

    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def execute(
        self,
        request: AlpacaPaperAccountTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountTransportResponse: ...


class _HttpxAlpacaPaperAccountTransport:
    """Concrete TLS-verifying, no-redirect, no-proxy account-only transport."""

    __slots__ = ()

    @property
    def transport_id(self) -> str:
        return ALPACA_PAPER_ACCOUNT_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION

    def execute(
        self,
        request: AlpacaPaperAccountTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountTransportResponse:
        if type(request) is not AlpacaPaperAccountTransportRequest:
            raise AlpacaPaperAccountTransportError(
                "strict Alpaca transport requires an exact account request"
            )
        request.__post_init__()
        if type(headers) is not _AlpacaPaperAuthenticationHeaders:
            raise AlpacaPaperAccountTransportError(
                "strict Alpaca transport requires redacted authentication headers"
            )
        if tuple(headers) != ALPACA_AUTH_HEADER_NAMES:
            raise AlpacaPaperAccountTransportError(
                "strict Alpaca transport requires the exact authentication header names"
            )
        timeout_seconds = request.httpx_phase_timeout.total_seconds()
        result: AlpacaPaperAccountTransportResponse | None = None
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
                        "Accept": ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
                        "Accept-Encoding": "identity",
                        "User-Agent": (
                            f"autoquant-trader/{ALPACA_PAPER_ADAPTER_VERSION} phase4g-account-probe"
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
                        raise AlpacaPaperAccountTransportError(
                            "account transport response exceeds the durable raw bound"
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
                    raise AlpacaPaperAccountTransportError(
                        "account transport response changed the fixed request target"
                    )
                result = AlpacaPaperAccountTransportResponse(
                    request_sha256=request.semantic_sha256,
                    transport_id=self.transport_id,
                    transport_version=self.transport_version,
                    http_status=response.status_code,
                    provider_request_id=request_id,
                    media_type=media_type,
                    response_body=bytes(body),
                    tls_verified=True,
                    redirects_followed=False,
                )
        except AlpacaPaperAccountTransportError:
            raise
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise AlpacaPaperAccountTransportError(
                "authenticated Alpaca account request failed without a retained response"
            ) from None
        if result is None:
            raise AlpacaPaperAccountTransportError(
                "authenticated Alpaca account request produced no response"
            )
        return result


class BrokerRequestBudgetRuntimePort(Protocol):
    """Durable request-admission operations required by the account probe."""

    def issue_new(
        self,
        *,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit: ...

    def authenticate_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermitFreshnessReceipt: ...


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountEvidence:
    """Complete transient evidence supplied to the durable binding recorder."""

    reference: AlpacaPaperCredentialReference
    credential_receipt: AlpacaPaperCredentialResolutionReceipt
    description: AlpacaPaperAccountObservationDescription
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    permit_freshness: BrokerRequestPermitFreshnessReceipt
    pre_fence_receipt: AccountFenceReceipt
    request: AlpacaPaperAccountTransportRequest
    response: AlpacaPaperAccountTransportResponse
    persisted_observation: PersistedAlpacaAccountObservation
    post_fence_receipt: AccountFenceReceipt
    qualified_at: datetime
    valid_until: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedAccountEvidence must be proof-constructed")

    def _validate(self) -> None:
        for value, expected_type, field_name in (
            (self.reference, AlpacaPaperCredentialReference, "credential reference"),
            (
                self.credential_receipt,
                AlpacaPaperCredentialResolutionReceipt,
                "credential receipt",
            ),
            (
                self.description,
                AlpacaPaperAccountObservationDescription,
                "account description",
            ),
            (self.policy, BrokerRequestBudgetPolicy, "budget policy"),
            (self.demand, BrokerRequestDemand, "request demand"),
            (self.permit, BrokerRequestPermit, "request permit"),
            (
                self.permit_freshness,
                BrokerRequestPermitFreshnessReceipt,
                "permit freshness receipt",
            ),
            (
                self.pre_fence_receipt,
                AccountFenceReceipt,
                "pre-request fence receipt",
            ),
            (
                self.request,
                AlpacaPaperAccountTransportRequest,
                "account transport request",
            ),
            (
                self.response,
                AlpacaPaperAccountTransportResponse,
                "account transport response",
            ),
            (
                self.persisted_observation,
                PersistedAlpacaAccountObservation,
                "persisted account observation",
            ),
            (
                self.post_fence_receipt,
                AccountFenceReceipt,
                "post-request fence receipt",
            ),
        ):
            if type(value) is not expected_type:
                raise AlpacaPaperAccountBindingConflict(
                    f"authenticated account evidence requires an exact {field_name}"
                )
        self.reference.__post_init__()
        self.credential_receipt.__post_init__()
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
        _require_utc(self.qualified_at, "account binding qualified_at")
        _require_utc(self.valid_until, "account binding valid_until")

        account_id = self.reference.account_id
        if (
            self.description.account_id != account_id
            or self.demand.account_id != account_id
            or self.permit.account_id != account_id
            or self.pre_fence_receipt.fence.account_id != account_id
            or self.post_fence_receipt.fence.account_id != account_id
            or self.persisted_observation.observation.description.account_id != account_id
        ):
            raise AlpacaPaperAccountBindingConflict(
                "authenticated account evidence crosses local account identities"
            )
        if self.credential_receipt.reference != self.reference:
            raise AlpacaPaperAccountBindingConflict(
                "credential receipt does not bind the exact account reference"
            )
        if self.policy.semantic_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256:
            raise AlpacaPaperAccountBindingConflict(
                "account binding requires the exact Alpaca budget policy"
            )
        expected_demand = create_alpaca_paper_account_observation_demand(
            reference=self.reference,
            description=self.description,
            idempotency_key=self.demand.idempotency_key,
            requested_at=self.demand.requested_at,
        )
        if self.demand != expected_demand or (
            self.demand.operation != AlpacaPaperBudgetOperation.OBSERVE_ACCOUNT.value
            or self.demand.purpose is not BrokerRequestPurpose.RECONCILIATION
        ):
            raise AlpacaPaperAccountBindingConflict(
                "account demand does not bind the exact observation purpose"
            )
        try:
            require_fresh_broker_request_permit(
                permit=self.permit,
                policy=self.policy,
                demand=self.demand,
                checked_at=self.permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperAccountBindingConflict(
                "account permit is not fresh for the exact durable demand"
            ) from error
        freshness_expected = (
            self.permit_freshness.permit_id == self.permit.permit_id
            and self.permit_freshness.permit_sha256 == self.permit.semantic_sha256
            and self.permit_freshness.policy_sha256 == self.policy.semantic_sha256
            and self.permit_freshness.demand_sha256 == self.demand.semantic_sha256
            and self.permit_freshness.expires_at == self.permit.expires_at
        )
        if not freshness_expected:
            raise AlpacaPaperAccountBindingConflict(
                "durable permit freshness receipt conflicts with account evidence"
            )
        if (
            self.pre_fence_receipt.fence != self.post_fence_receipt.fence
            or self.pre_fence_receipt.policy_sha256 != self.post_fence_receipt.policy_sha256
        ):
            raise AlpacaPaperAccountBindingConflict(
                "account fence changed during the authenticated read"
            )
        expected_request = AlpacaPaperAccountTransportRequest(
            description=self.description,
            credential_reference_sha256=self.reference.semantic_sha256,
            demand_sha256=self.demand.semantic_sha256,
            permit_sha256=self.permit.semantic_sha256,
            permit_freshness_sha256=self.permit_freshness.semantic_sha256,
            fence_receipt_sha256=self.pre_fence_receipt.semantic_sha256,
            started_at=self.request.started_at,
        )
        if self.request != expected_request:
            raise AlpacaPaperAccountBindingConflict(
                "account request does not bind its exact pre-send authority evidence"
            )
        if self.response.request_sha256 != self.request.semantic_sha256:
            raise AlpacaPaperAccountBindingConflict(
                "account response belongs to another transport request"
            )
        if (
            self.response.transport_id != ALPACA_PAPER_ACCOUNT_TRANSPORT_ID
            or self.response.transport_version != ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION
            or not self.response.tls_verified
            or self.response.redirects_followed
        ):
            raise AlpacaPaperAccountBindingConflict(
                "account response lacks the exact restricted transport profile"
            )
        observation = self.persisted_observation.observation
        receipt = self.persisted_observation.receipt
        if (
            receipt.delivery.body != self.response.response_body
            or receipt.delivery.transport_status != self.response.http_status
            or receipt.delivery.provider_request_id != self.response.provider_request_id
            or receipt.delivery.media_type != self.response.media_type
            or observation.response_sha256 != self.response.response_sha256
        ):
            raise AlpacaPaperAccountBindingConflict(
                "account response conflicts with its raw-first observation"
            )
        if (
            self.response.http_status != 200
            or self.response.provider_request_id is None
            or self.response.media_type != ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
            or observation.outcome is not AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
        ):
            raise AlpacaPaperAccountBindingConflict(
                "account response is not a usable authenticated observation"
            )
        if observation.provider_account_id != self.reference.expected_provider_account_id:
            raise AlpacaPaperAccountBindingConflict(
                "observed Alpaca account does not match the operator-pinned provider UUID"
            )
        received_at = observation.received_at
        recorded_at = receipt.delivery.recorded_at
        if not (
            self.demand.requested_at
            <= self.credential_receipt.started_at
            <= self.credential_receipt.resolved_at
            <= self.permit.issued_at
            <= self.pre_fence_receipt.validated_at
            <= self.permit_freshness.checked_at
            <= self.request.started_at
            <= received_at
            <= recorded_at
            <= self.post_fence_receipt.validated_at
            == self.qualified_at
        ):
            raise AlpacaPaperAccountBindingConflict(
                "authenticated account evidence has conflicting trusted-time order"
            )
        if not self.credential_receipt.is_fresh(self.request.started_at):
            raise AlpacaPaperAccountBindingConflict(
                "credential session was not fresh at account request start"
            )
        if not self.credential_receipt.is_fresh(received_at):
            raise AlpacaPaperAccountBindingConflict(
                "credential session expired before the account response completed"
            )
        if not self.permit.is_fresh(self.request.started_at):
            raise AlpacaPaperAccountBindingConflict(
                "request permit expired before account transport began"
            )
        if not self.permit.is_fresh(received_at):
            raise AlpacaPaperAccountBindingConflict(
                "request permit expired before the account response completed"
            )
        if not (
            self.pre_fence_receipt.validated_at
            <= self.request.started_at
            < self.pre_fence_receipt.valid_until
        ):
            raise AlpacaPaperAccountBindingConflict(
                "pre-request fence was not current when account transport began"
            )
        if received_at >= self.pre_fence_receipt.valid_until:
            raise AlpacaPaperAccountBindingConflict(
                "pre-request fence expired before the account response completed"
            )
        expected_valid_until = min(
            self.qualified_at + ALPACA_PAPER_ACCOUNT_BINDING_TTL,
            self.post_fence_receipt.valid_until,
        )
        if self.valid_until != expected_valid_until or self.valid_until <= self.qualified_at:
            raise AlpacaPaperAccountBindingConflict(
                "account binding validity does not match its fixed bounded window"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
                "authenticated_account_evidence",
                self.reference.semantic_sha256,
                self.credential_receipt.semantic_sha256,
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


def _authenticated_account_evidence(
    *,
    reference: AlpacaPaperCredentialReference,
    credential_receipt: AlpacaPaperCredentialResolutionReceipt,
    description: AlpacaPaperAccountObservationDescription,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    permit_freshness: BrokerRequestPermitFreshnessReceipt,
    pre_fence_receipt: AccountFenceReceipt,
    request: AlpacaPaperAccountTransportRequest,
    response: AlpacaPaperAccountTransportResponse,
    persisted_observation: PersistedAlpacaAccountObservation,
    post_fence_receipt: AccountFenceReceipt,
) -> AlpacaPaperAuthenticatedAccountEvidence:
    qualified_at = post_fence_receipt.validated_at
    valid_until = min(
        qualified_at + ALPACA_PAPER_ACCOUNT_BINDING_TTL,
        post_fence_receipt.valid_until,
    )
    evidence = object.__new__(AlpacaPaperAuthenticatedAccountEvidence)
    for field_name, value in (
        ("reference", reference),
        ("credential_receipt", credential_receipt),
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
        ("qualified_at", qualified_at),
        ("valid_until", valid_until),
    ):
        object.__setattr__(evidence, field_name, value)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountBinding:
    """Append-only, secret-free authenticated account-binding fact."""

    account_id: str
    provider_id: str
    environment: str
    expected_provider_account_id: str
    observed_provider_account_id: str
    secret_ref: str
    secret_version: str
    credential_reference_sha256: str
    credential_resolution_sha256: str
    resolver_id: str
    resolver_version: str
    capability_sha256: str
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
    permit_checked_at: datetime
    pre_fence_validated_at: datetime
    request_started_at: datetime
    received_at: datetime
    raw_recorded_at: datetime
    qualified_at: datetime
    post_fence_valid_until: datetime
    valid_until: datetime
    sequence_number: int
    previous_binding_sha256: str | None
    evidence_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAuthenticatedAccountBinding must be recorder-produced")

    def _validate(self) -> None:
        _require_text(self.account_id, "account binding account ID", maximum=64)
        if self.provider_id != ALPACA_PAPER_ADAPTER_ID or self.environment != "paper":
            raise AlpacaPaperAccountBindingConflict(
                "account binding must remain Alpaca paper scoped"
            )
        _require_uuid(
            self.expected_provider_account_id,
            "binding expected provider account ID",
        )
        _require_uuid(
            self.observed_provider_account_id,
            "binding observed provider account ID",
        )
        if self.expected_provider_account_id != self.observed_provider_account_id:
            raise AlpacaPaperAccountBindingConflict(
                "durable account binding provider UUIDs disagree"
            )
        _require_secret_reference(self.secret_ref)
        _require_safe_text(self.secret_version, "binding secret version")
        _require_safe_text(self.resolver_id, "binding resolver ID")
        _require_safe_text(self.resolver_version, "binding resolver version")
        for value, field_name in (
            (self.credential_reference_sha256, "credential reference"),
            (self.credential_resolution_sha256, "credential resolution"),
            (self.capability_sha256, "capability"),
            (self.description_sha256, "account description"),
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
            (self.observation_sha256, "account observation"),
            (self.transport_request_sha256, "transport request"),
            (self.transport_response_sha256, "transport response"),
            (self.evidence_sha256, "account evidence"),
        ):
            _require_sha256(value, f"binding {field_name} digest")
        for timestamp_value, timestamp_field_name in (
            (self.requested_at, "requested_at"),
            (self.resolved_at, "resolved_at"),
            (self.permit_checked_at, "permit_checked_at"),
            (self.pre_fence_validated_at, "pre_fence_validated_at"),
            (self.request_started_at, "request_started_at"),
            (self.received_at, "received_at"),
            (self.raw_recorded_at, "raw_recorded_at"),
            (self.qualified_at, "qualified_at"),
            (self.post_fence_valid_until, "post_fence_valid_until"),
            (self.valid_until, "valid_until"),
        ):
            _require_utc(
                timestamp_value,
                f"account binding {timestamp_field_name}",
            )
        if not (
            self.requested_at
            <= self.resolved_at
            <= self.pre_fence_validated_at
            <= self.permit_checked_at
            <= self.request_started_at
            <= self.received_at
            <= self.raw_recorded_at
            <= self.qualified_at
            < self.valid_until
            <= self.post_fence_valid_until
        ):
            raise AlpacaPaperAccountBindingConflict(
                "durable account binding has conflicting time order"
            )
        if self.valid_until > self.qualified_at + ALPACA_PAPER_ACCOUNT_BINDING_TTL:
            raise AlpacaPaperAccountBindingConflict(
                "durable account binding exceeds the fixed maximum TTL"
            )
        if (
            type(self.sequence_number) is not int
            or self.sequence_number <= 0
            or (self.sequence_number == 1 and self.previous_binding_sha256 is not None)
            or (self.sequence_number > 1 and self.previous_binding_sha256 is None)
        ):
            raise AlpacaPaperAccountBindingConflict("account binding predecessor shape is invalid")
        _require_optional_sha256(
            self.previous_binding_sha256,
            "account binding predecessor digest",
        )
        if self.capability_sha256 != ALPACA_PAPER_CAPABILITIES.semantic_sha256:
            raise AlpacaPaperAccountBindingConflict(
                "account binding capability digest is not current"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
            "authenticated_account_binding",
            self.account_id,
            self.provider_id,
            self.environment,
            self.expected_provider_account_id,
            self.observed_provider_account_id,
            self.secret_ref,
            self.secret_version,
            self.credential_reference_sha256,
            self.credential_resolution_sha256,
            self.resolver_id,
            self.resolver_version,
            self.capability_sha256,
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
            self.permit_checked_at,
            self.pre_fence_validated_at,
            self.request_started_at,
            self.received_at,
            self.raw_recorded_at,
            self.qualified_at,
            self.post_fence_valid_until,
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
        return canonical_id("alpaca-paper-authenticated-account-binding", self.semantic_sha256)

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def is_fresh(self, checked_at: datetime) -> bool:
        _require_utc(checked_at, "account binding checked_at")
        return self.qualified_at <= checked_at < self.valid_until

    @property
    def credential_resolution_established(self) -> bool:
        return True

    @property
    def authenticated_account_established(self) -> bool:
        return True

    @property
    def raw_response_persisted(self) -> bool:
        return True

    @property
    def durable_account_binding_established(self) -> bool:
        return True

    @property
    def account_economics_canonicalized(self) -> bool:
        return False

    @property
    def security_mapping_ready(self) -> bool:
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


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountIdentityContinuityReceipt:
    """Proof of the current terminal credential-version/account-UUID binding.

    This receipt deliberately does not assert that the retained account-status
    observation is still fresh or that the account is eligible to trade.
    """

    account_id: str
    binding_id: str
    binding_sha256: str
    credential_reference_sha256: str
    expected_provider_account_id: str
    sequence_number: int
    binding_qualified_at: datetime
    checked_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAccountIdentityContinuityReceipt must be repository-produced")

    def _validate(self) -> None:
        _require_text(
            self.account_id,
            "account-identity continuity account ID",
            maximum=64,
        )
        _require_uuid(self.binding_id, "account-identity continuity binding ID")
        _require_sha256(
            self.binding_sha256,
            "account-identity continuity binding digest",
        )
        _require_sha256(
            self.credential_reference_sha256,
            "account-identity continuity credential-reference digest",
        )
        _require_uuid(
            self.expected_provider_account_id,
            "account-identity continuity provider account ID",
        )
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise AlpacaPaperAccountBindingConflict(
                "account-identity continuity sequence must be positive"
            )
        _require_utc(
            self.binding_qualified_at,
            "account-identity continuity binding_qualified_at",
        )
        _require_utc(self.checked_at, "account-identity continuity checked_at")
        if self.checked_at < self.binding_qualified_at:
            raise AlpacaPaperAccountBindingConflict(
                "account identity cannot be checked before its durable binding"
            )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_IDENTITY_CONTINUITY_CONTRACT_VERSION,
                "terminal_account_identity_continuity",
                self.account_id,
                self.binding_id,
                self.binding_sha256,
                self.credential_reference_sha256,
                self.expected_provider_account_id,
                self.sequence_number,
                self.binding_qualified_at,
                self.checked_at,
            )
        )

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-terminal-account-identity-continuity",
            self.semantic_sha256,
        )

    @property
    def account_identity_continuity_established(self) -> bool:
        return True

    @property
    def account_status_current(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _alpaca_paper_account_identity_continuity_receipt(
    binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    checked_at: datetime,
) -> AlpacaPaperAccountIdentityContinuityReceipt:
    """Construct identity-only evidence after proving terminal SQL position."""

    if type(binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperAccountBindingConflict(
            "account-identity continuity requires an exact durable binding"
        )
    binding._validate()
    _require_utc(checked_at, "account-identity continuity checked_at")
    receipt = object.__new__(AlpacaPaperAccountIdentityContinuityReceipt)
    for field_name, value in (
        ("account_id", binding.account_id),
        ("binding_id", binding.binding_id),
        ("binding_sha256", binding.semantic_sha256),
        ("credential_reference_sha256", binding.credential_reference_sha256),
        ("expected_provider_account_id", binding.expected_provider_account_id),
        ("sequence_number", binding.sequence_number),
        ("binding_qualified_at", binding.qualified_at),
        ("checked_at", checked_at),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountBindingFreshnessReceipt:
    """Proof that one exact Phase 4G binding was terminal and fresh in SQL."""

    account_id: str
    binding_id: str
    binding_sha256: str
    expected_provider_account_id: str
    sequence_number: int
    checked_at: datetime
    expires_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAccountBindingFreshnessReceipt must be repository-produced")

    def _validate(self) -> None:
        _require_text(
            self.account_id,
            "account-binding freshness account ID",
            maximum=64,
        )
        _require_uuid(self.binding_id, "account-binding freshness binding ID")
        _require_sha256(
            self.binding_sha256,
            "account-binding freshness binding digest",
        )
        _require_uuid(
            self.expected_provider_account_id,
            "account-binding freshness provider account ID",
        )
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise AlpacaPaperAccountBindingConflict(
                "account-binding freshness sequence must be positive"
            )
        _require_utc(self.checked_at, "account-binding freshness checked_at")
        _require_utc(self.expires_at, "account-binding freshness expires_at")
        if self.checked_at >= self.expires_at:
            raise AlpacaPaperAccountBindingConflict(
                "account-binding freshness receipt is not fresh"
            )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_BINDING_FRESHNESS_CONTRACT_VERSION,
                "terminal_account_binding_freshness",
                self.account_id,
                self.binding_id,
                self.binding_sha256,
                self.expected_provider_account_id,
                self.sequence_number,
                self.checked_at,
                self.expires_at,
            )
        )

    @property
    def receipt_id(self) -> str:
        return canonical_id(
            "alpaca-paper-terminal-account-binding-freshness",
            self.semantic_sha256,
        )

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _alpaca_paper_account_binding_freshness_receipt(
    binding: AlpacaPaperAuthenticatedAccountBinding,
    *,
    checked_at: datetime,
) -> AlpacaPaperAccountBindingFreshnessReceipt:
    """Construct a receipt after a repository proves terminal position."""

    if type(binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperAccountBindingConflict(
            "account-binding freshness requires an exact durable binding"
        )
    binding._validate()
    _require_utc(checked_at, "account-binding freshness checked_at")
    if not binding.is_fresh(checked_at):
        raise AlpacaPaperAccountBindingConflict(
            "terminal Alpaca paper account binding is not fresh"
        )
    receipt = object.__new__(AlpacaPaperAccountBindingFreshnessReceipt)
    for field_name, value in (
        ("account_id", binding.account_id),
        ("binding_id", binding.binding_id),
        ("binding_sha256", binding.semantic_sha256),
        ("expected_provider_account_id", binding.expected_provider_account_id),
        ("sequence_number", binding.sequence_number),
        ("checked_at", checked_at),
        ("expires_at", binding.valid_until),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


class AlpacaPaperAccountBindingRuntimePort(Protocol):
    """Durable terminal-binding authentication required by later reads."""

    def authenticate_terminal_identity(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountIdentityContinuityReceipt: ...

    def authenticate_terminal_fresh(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountBindingFreshnessReceipt: ...


def _alpaca_paper_authenticated_account_binding(
    evidence: AlpacaPaperAuthenticatedAccountEvidence,
    *,
    sequence_number: int,
    previous_binding_sha256: str | None,
) -> AlpacaPaperAuthenticatedAccountBinding:
    if type(evidence) is not AlpacaPaperAuthenticatedAccountEvidence:
        raise AlpacaPaperAccountBindingConflict(
            "account binding requires exact authenticated evidence"
        )
    evidence._validate()
    observation = evidence.persisted_observation.observation
    receipt = evidence.persisted_observation.receipt
    binding = object.__new__(AlpacaPaperAuthenticatedAccountBinding)
    values: tuple[tuple[str, object], ...] = (
        ("account_id", evidence.reference.account_id),
        ("provider_id", evidence.reference.provider_id),
        ("environment", evidence.reference.environment),
        (
            "expected_provider_account_id",
            evidence.reference.expected_provider_account_id,
        ),
        ("observed_provider_account_id", observation.provider_account_id),
        ("secret_ref", evidence.reference.secret_ref),
        ("secret_version", evidence.reference.secret_version),
        (
            "credential_reference_sha256",
            evidence.reference.semantic_sha256,
        ),
        (
            "credential_resolution_sha256",
            evidence.credential_receipt.semantic_sha256,
        ),
        ("resolver_id", evidence.credential_receipt.resolver_id),
        ("resolver_version", evidence.credential_receipt.resolver_version),
        ("capability_sha256", evidence.reference.capability_sha256),
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
        (
            "pre_fence_receipt_sha256",
            evidence.pre_fence_receipt.semantic_sha256,
        ),
        (
            "post_fence_receipt_sha256",
            evidence.post_fence_receipt.semantic_sha256,
        ),
        ("ingress_receipt_id", receipt.receipt_id),
        ("ingress_receipt_sha256", receipt.semantic_sha256),
        ("observation_sha256", observation.semantic_sha256),
        ("transport_request_sha256", evidence.request.semantic_sha256),
        ("transport_response_sha256", evidence.response.semantic_sha256),
        ("requested_at", evidence.demand.requested_at),
        ("resolved_at", evidence.credential_receipt.resolved_at),
        ("permit_checked_at", evidence.permit_freshness.checked_at),
        (
            "pre_fence_validated_at",
            evidence.pre_fence_receipt.validated_at,
        ),
        ("request_started_at", evidence.request.started_at),
        ("received_at", observation.received_at),
        ("raw_recorded_at", receipt.delivery.recorded_at),
        ("qualified_at", evidence.qualified_at),
        ("post_fence_valid_until", evidence.post_fence_receipt.valid_until),
        ("valid_until", evidence.valid_until),
        ("sequence_number", sequence_number),
        ("previous_binding_sha256", previous_binding_sha256),
        ("evidence_sha256", evidence.semantic_sha256),
    )
    for field_name, value in values:
        object.__setattr__(binding, field_name, value)
    binding._validate()
    return binding


class AlpacaPaperAccountBindingRecorder(Protocol):
    """Durable append-only recorder for authenticated account evidence."""

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountEvidence,
    ) -> AlpacaPaperAuthenticatedAccountBinding: ...


def _observe_authenticated_alpaca_paper_account_with_transport(
    *,
    reference: AlpacaPaperCredentialReference,
    description: AlpacaPaperAccountObservationDescription,
    credential_resolver: AlpacaPaperCredentialResolver,
    transport: _AlpacaPaperAccountTransport,
    budget: BrokerRequestBudgetRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    binding_recorder: AlpacaPaperAccountBindingRecorder,
    clock: Clock,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedAccountBinding:
    """Trusted internal seam for deterministic transport-contract testing."""

    if type(reference) is not AlpacaPaperCredentialReference:
        raise AlpacaPaperAccountRuntimeError(
            "account runtime requires an exact credential reference"
        )
    if type(description) is not AlpacaPaperAccountObservationDescription:
        raise AlpacaPaperAccountRuntimeError(
            "account runtime requires an exact account description"
        )
    if type(fence) is not AccountFence:
        raise AlpacaPaperAccountRuntimeError("account runtime requires an exact fence")
    reference.__post_init__()
    description.__post_init__()
    if description.account_id != reference.account_id or fence.account_id != reference.account_id:
        raise AlpacaPaperAccountBindingConflict(
            "account runtime inputs cross local account identities"
        )
    for port, method_name, field_name in (
        (budget, "issue_new", "durable new-permit issuer"),
        (budget, "authenticate_fresh", "durable budget authenticator"),
        (coordinator, "revalidate", "account coordinator"),
        (ingress_recorder, "record", "raw ingress recorder"),
        (binding_recorder, "record", "account binding recorder"),
        (transport, "execute", "restricted account transport"),
    ):
        if not callable(getattr(port, method_name, None)):
            raise AlpacaPaperAccountRuntimeError(f"account runtime requires a {field_name}")
    if getattr(coordinator, "account_id", None) != reference.account_id:
        raise AlpacaPaperAccountBindingConflict(
            "account coordinator belongs to another local account"
        )
    if (
        getattr(transport, "transport_id", None) != ALPACA_PAPER_ACCOUNT_TRANSPORT_ID
        or getattr(transport, "transport_version", None) != ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION
    ):
        raise AlpacaPaperAccountTransportError(
            "account runtime requires the exact restricted transport profile"
        )

    requested_at = _trusted_now(clock, "account observation requested_at")
    demand = create_alpaca_paper_account_observation_demand(
        reference=reference,
        description=description,
        idempotency_key=request_idempotency_key,
        requested_at=requested_at,
    )
    credential_session = _resolve_alpaca_paper_credentials(
        reference=reference,
        resolver=credential_resolver,
        clock=clock,
    )
    try:
        permit = budget.issue_new(
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        if type(permit) is not BrokerRequestPermit:
            raise AlpacaPaperAccountRuntimeError("durable budget issuer returned an invalid permit")
        pre_fence_receipt = coordinator.revalidate(fence)
        if type(pre_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperAccountRuntimeError(
                "account coordinator returned an invalid pre-request receipt"
            )
        pre_fence_receipt._validate()
        if pre_fence_receipt.fence != fence:
            raise AlpacaPaperAccountBindingConflict(
                "account coordinator returned a receipt for another pre-request fence"
            )
        permit_freshness = budget.authenticate_fresh(
            permit=permit,
            policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=demand,
        )
        if type(permit_freshness) is not BrokerRequestPermitFreshnessReceipt:
            raise AlpacaPaperAccountRuntimeError(
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
            raise AlpacaPaperAccountBindingConflict(
                "durable permit freshness receipt conflicts before transport"
            )
        try:
            require_fresh_broker_request_permit(
                permit=permit,
                policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
                demand=demand,
                checked_at=permit_freshness.checked_at,
            )
        except ValueError as error:
            raise AlpacaPaperAccountBindingConflict(
                "durable account-observation permit is invalid before transport"
            ) from error
        started_at = _trusted_now(clock, "account transport started_at")
        if permit_freshness.checked_at > started_at or not permit.is_fresh(started_at):
            raise AlpacaPaperAccountBindingConflict(
                "durable request permit is not current at transport start"
            )
        if not (pre_fence_receipt.validated_at <= started_at < pre_fence_receipt.valid_until):
            raise AlpacaPaperAccountBindingConflict(
                "account fence is not current at transport start"
            )
        request = AlpacaPaperAccountTransportRequest(
            description=description,
            credential_reference_sha256=reference.semantic_sha256,
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
            raise AlpacaPaperAccountTransportError(
                "restricted account transport failed with sanitized diagnostics"
            ) from None
        received_at = _trusted_now(clock, "account transport received_at")
    finally:
        credential_session.close()

    if type(response) is not AlpacaPaperAccountTransportResponse:
        raise AlpacaPaperAccountTransportError("account transport returned an invalid response")
    response.__post_init__()
    if response.request_sha256 != request.semantic_sha256:
        raise AlpacaPaperAccountTransportError(
            "account transport returned a response for another request"
        )
    if received_at < started_at:
        raise AlpacaPaperAccountRuntimeError("account transport clock regressed")
    recorded_at = _trusted_now(clock, "account raw response recorded_at")
    if recorded_at < received_at:
        raise AlpacaPaperAccountRuntimeError("account raw-record clock regressed")
    persisted_observation = persist_then_decode_alpaca_account_observation_response(
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
        persisted_observation.observation.provider_account_id
        != reference.expected_provider_account_id
    ):
        raise AlpacaPaperAccountBindingConflict(
            "observed Alpaca account does not match the operator-pinned provider UUID"
        )
    post_fence_receipt = coordinator.revalidate(fence)
    if type(post_fence_receipt) is not AccountFenceReceipt:
        raise AlpacaPaperAccountRuntimeError(
            "account coordinator returned an invalid post-request receipt"
        )
    post_fence_receipt._validate()
    if post_fence_receipt.fence != fence:
        raise AlpacaPaperAccountBindingConflict(
            "account fence changed: coordinator returned another post-request fence"
        )
    evidence = _authenticated_account_evidence(
        reference=reference,
        credential_receipt=credential_session.receipt,
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
    )
    binding = binding_recorder.record(evidence)
    if type(binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperAccountRuntimeError(
            "account binding recorder returned an invalid durable fact"
        )
    binding._validate()
    if binding.evidence_sha256 != evidence.semantic_sha256:
        raise AlpacaPaperAccountBindingConflict(
            "durable account binding does not bind the exact runtime evidence"
        )
    expected_binding = _alpaca_paper_authenticated_account_binding(
        evidence,
        sequence_number=binding.sequence_number,
        previous_binding_sha256=binding.previous_binding_sha256,
    )
    if binding != expected_binding:
        raise AlpacaPaperAccountBindingConflict(
            "durable account binding conflicts with the exact runtime evidence"
        )
    return binding


def observe_authenticated_alpaca_paper_account(
    *,
    reference: AlpacaPaperCredentialReference,
    description: AlpacaPaperAccountObservationDescription,
    credential_resolver: AlpacaPaperCredentialResolver,
    budget: BrokerRequestBudgetRuntimePort,
    coordinator: AccountCoordinatorPort,
    fence: AccountFence,
    ingress_recorder: BrokerIngressRecorder,
    binding_recorder: AlpacaPaperAccountBindingRecorder,
    clock: Clock,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedAccountBinding:
    """Execute the exact production account GET and persist a non-trading binding."""

    return _observe_authenticated_alpaca_paper_account_with_transport(
        reference=reference,
        description=description,
        credential_resolver=credential_resolver,
        transport=_HttpxAlpacaPaperAccountTransport(),
        budget=budget,
        coordinator=coordinator,
        fence=fence,
        ingress_recorder=ingress_recorder,
        binding_recorder=binding_recorder,
        clock=clock,
        request_idempotency_key=request_idempotency_key,
        delivery_idempotency_key=delivery_idempotency_key,
    )


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE",
    "ALPACA_PAPER_ACCOUNT_BINDING_FRESHNESS_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_BINDING_TTL",
    "ALPACA_PAPER_ACCOUNT_HTTPX_PHASE_TIMEOUT",
    "ALPACA_PAPER_ACCOUNT_IDENTITY_CONTINUITY_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_TRANSPORT_ID",
    "ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION",
    "ALPACA_PAPER_CREDENTIAL_SESSION_TTL",
    "ALPACA_PAPER_MAX_SECRET_REFERENCE_LENGTH",
    "ALPACA_PAPER_MAX_SECRET_VALUE_BYTES",
    "AlpacaPaperAccountBindingConflict",
    "AlpacaPaperAccountBindingFreshnessReceipt",
    "AlpacaPaperAccountBindingRecorder",
    "AlpacaPaperAccountBindingRuntimePort",
    "AlpacaPaperAccountIdentityContinuityReceipt",
    "AlpacaPaperAccountRuntimeError",
    "AlpacaPaperAccountTransportError",
    "AlpacaPaperAccountTransportRequest",
    "AlpacaPaperAccountTransportResponse",
    "AlpacaPaperAuthenticatedAccountBinding",
    "AlpacaPaperAuthenticatedAccountEvidence",
    "AlpacaPaperCredentialExpired",
    "AlpacaPaperCredentialReference",
    "AlpacaPaperCredentialResolutionError",
    "AlpacaPaperCredentialResolutionReceipt",
    "AlpacaPaperCredentialResolver",
    "BrokerRequestBudgetRuntimePort",
    "alpaca_paper_account_observation_correlation_sha256",
    "create_alpaca_paper_account_observation_demand",
    "create_alpaca_paper_credential_envelope",
    "observe_authenticated_alpaca_paper_account",
]
