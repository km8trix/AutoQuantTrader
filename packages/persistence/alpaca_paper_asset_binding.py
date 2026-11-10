"""Durable, instrument-local authenticated Alpaca paper asset-binding journal."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper import ALPACA_PAPER_ADAPTER_ID
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAssetClass,
    AlpacaAssetExchange,
    AlpacaAssetObservationOutcome,
    AlpacaAssetStatus,
    AlpacaPaperAccountAssetObservationError,
    AlpacaPaperAssetObservationDescription,
    decode_alpaca_asset_observation_response,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountBindingConflict,
    AlpacaPaperCredentialReference,
    _alpaca_paper_account_binding_freshness_receipt,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ASSET_BINDING_TTL,
    ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
    ALPACA_PAPER_ASSET_TRANSPORT_ID,
    ALPACA_PAPER_ASSET_TRANSPORT_VERSION,
    AlpacaPaperAssetBindingConflict,
    AlpacaPaperAssetRuntimeError,
    AlpacaPaperAssetTransportRequest,
    AlpacaPaperAssetTransportResponse,
    AlpacaPaperAuthenticatedAssetBinding,
    AlpacaPaperAuthenticatedAssetEvidence,
    AlpacaPaperSecurityReference,
    _alpaca_paper_authenticated_asset_binding,
    create_alpaca_paper_asset_observation_demand,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaAssetObservation,
)
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.broker_ingress import BrokerIngressError, BrokerIngressReceipt
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetError,
    _broker_request_permit_freshness_receipt,
    require_fresh_broker_request_permit,
)
from packages.domain.canonical import canonical_json_bytes
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.alpaca_paper_account_binding import (
    _authenticate_binding_position as _authenticate_account_binding_position,
)
from packages.persistence.alpaca_paper_account_binding import (
    _authenticate_durable_sources as _authenticate_account_binding_sources,
)
from packages.persistence.alpaca_paper_account_binding import (
    _binding_by_id as _account_binding_by_id,
)
from packages.persistence.alpaca_paper_account_binding import (
    _head as _account_binding_head,
)
from packages.persistence.alpaca_paper_account_binding import (
    _terminal_binding as _terminal_account_binding,
)
from packages.persistence.broker_ingress import (
    _authenticate_receipt_position as _authenticate_ingress_receipt_position,
)
from packages.persistence.broker_ingress import (
    _receipt_by_id as _broker_ingress_receipt_by_id,
)
from packages.persistence.broker_request_budget import (
    _authenticate_record_position as _authenticate_permit_position,
)
from packages.persistence.broker_request_budget import (
    _record_by_id as _broker_request_permit_by_id,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import ImmutableFactConflict, as_aware_utc, assert_immutable
from packages.persistence.schema import (
    phase4_alpaca_paper_asset_binding_heads,
    phase4_alpaca_paper_asset_bindings,
)

AlpacaPaperAssetBindingRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

_TEXT_FIELDS = (
    "account_id",
    "provider_id",
    "environment",
    "expected_provider_account_id",
    "instrument_id",
    "symbol",
    "expected_provider_asset_id",
    "observed_provider_asset_id",
    "secret_ref",
    "secret_version",
    "credential_reference_sha256",
    "security_reference_sha256",
    "credential_resolution_sha256",
    "resolver_id",
    "resolver_version",
    "capability_sha256",
    "account_binding_id",
    "account_binding_sha256",
    "pre_account_binding_freshness_sha256",
    "post_account_binding_freshness_sha256",
    "description_sha256",
    "policy_sha256",
    "demand_id",
    "demand_sha256",
    "permit_id",
    "permit_sha256",
    "permit_freshness_sha256",
    "pre_fence_receipt_sha256",
    "post_fence_receipt_sha256",
    "ingress_receipt_id",
    "ingress_receipt_sha256",
    "observation_sha256",
    "transport_request_sha256",
    "transport_response_sha256",
)
_DATETIME_FIELDS = (
    "requested_at",
    "resolved_at",
    "pre_fence_validated_at",
    "permit_checked_at",
    "pre_account_binding_checked_at",
    "request_started_at",
    "received_at",
    "raw_recorded_at",
    "post_fence_validated_at",
    "post_account_binding_checked_at",
    "account_binding_valid_until",
    "post_fence_valid_until",
    "qualified_at",
    "valid_until",
)


@dataclass(frozen=True, slots=True)
class _AlpacaPaperAssetBindingHead:
    account_id: str
    instrument_id: str
    provider_id: str
    environment: str
    expected_provider_account_id: str
    symbol: str
    expected_provider_asset_id: str
    last_sequence_number: int
    last_binding_sha256: str
    last_qualified_at: datetime
    last_valid_until: datetime


def _required_text(row: AlpacaPaperAssetBindingRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AlpacaPaperAssetBindingConflict(
            f"persisted Alpaca paper asset binding {field_name} must be a string"
        )
    return value


def _optional_text(
    row: AlpacaPaperAssetBindingRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise AlpacaPaperAssetBindingConflict(
            f"persisted Alpaca paper asset binding {field_name} must be a string or null"
        )
    return value


def _required_integer(row: AlpacaPaperAssetBindingRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperAssetBindingConflict(
            f"persisted Alpaca paper asset binding {field_name} must be an integer"
        )
    return value


def _required_boolean(row: AlpacaPaperAssetBindingRow, field_name: str) -> bool:
    value = row[field_name]
    if type(value) is not bool:
        raise AlpacaPaperAssetBindingConflict(
            f"persisted Alpaca paper asset binding {field_name} must be a boolean"
        )
    return value


def _required_datetime(
    row: AlpacaPaperAssetBindingRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperAssetBindingConflict(
            f"persisted Alpaca paper asset binding {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def alpaca_paper_asset_binding_from_row(
    row: AlpacaPaperAssetBindingRow,
) -> AlpacaPaperAuthenticatedAssetBinding:
    """Strictly reconstruct and authenticate one persisted asset binding."""

    try:
        binding = object.__new__(AlpacaPaperAuthenticatedAssetBinding)
        for field_name in _TEXT_FIELDS:
            object.__setattr__(binding, field_name, _required_text(row, field_name))
        object.__setattr__(
            binding,
            "asset_class",
            AlpacaAssetClass(_required_text(row, "asset_class")),
        )
        object.__setattr__(
            binding,
            "exchange",
            AlpacaAssetExchange(_required_text(row, "exchange")),
        )
        object.__setattr__(
            binding,
            "asset_status",
            AlpacaAssetStatus(_required_text(row, "asset_status")),
        )
        object.__setattr__(
            binding,
            "tradable",
            _required_boolean(row, "tradable"),
        )
        for field_name in _DATETIME_FIELDS:
            object.__setattr__(
                binding,
                field_name,
                _required_datetime(row, field_name),
            )
        object.__setattr__(
            binding,
            "sequence_number",
            _required_integer(row, "sequence_number"),
        )
        object.__setattr__(
            binding,
            "previous_binding_sha256",
            _optional_text(row, "previous_binding_sha256"),
        )
        object.__setattr__(
            binding,
            "evidence_sha256",
            _required_text(row, "evidence_sha256"),
        )
        binding._validate()
        expected_evidence_sha256 = hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_ASSET_RUNTIME_CONTRACT_VERSION,
                    "authenticated_asset_evidence",
                    binding.security_reference_sha256,
                    binding.credential_resolution_sha256,
                    binding.account_binding_sha256,
                    binding.pre_account_binding_freshness_sha256,
                    binding.description_sha256,
                    binding.policy_sha256,
                    binding.demand_sha256,
                    binding.permit_sha256,
                    binding.permit_freshness_sha256,
                    binding.pre_fence_receipt_sha256,
                    binding.transport_request_sha256,
                    binding.transport_response_sha256,
                    binding.ingress_receipt_sha256,
                    binding.observation_sha256,
                    binding.post_fence_receipt_sha256,
                    binding.post_account_binding_freshness_sha256,
                    binding.qualified_at,
                    binding.valid_until,
                )
            )
        ).hexdigest()
        if binding.evidence_sha256 != expected_evidence_sha256:
            raise AlpacaPaperAssetBindingConflict(
                "persisted Alpaca paper asset binding evidence digest conflicts"
            )
        for field_name, expected in (
            ("binding_id", binding.binding_id),
            ("canonical_payload", binding.canonical_json),
            ("semantic_sha256", binding.semantic_sha256),
        ):
            if row[field_name] != expected:
                raise AlpacaPaperAssetBindingConflict(
                    f"persisted Alpaca paper asset binding {field_name} conflicts"
                )
        return binding
    except AlpacaPaperAssetRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAssetBindingConflict(
            "persisted Alpaca paper asset binding is malformed"
        ) from error


def immutable_alpaca_paper_asset_binding_values(
    binding: AlpacaPaperAuthenticatedAssetBinding,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one binding."""

    if type(binding) is not AlpacaPaperAuthenticatedAssetBinding:
        raise AlpacaPaperAssetBindingConflict(
            "asset binding persistence requires an exact durable binding"
        )
    binding._validate()
    values: dict[str, Any] = {
        "binding_id": binding.binding_id,
        "sequence_number": binding.sequence_number,
        "previous_binding_sha256": binding.previous_binding_sha256,
        "asset_class": binding.asset_class.value,
        "exchange": binding.exchange.value,
        "asset_status": binding.asset_status.value,
        "tradable": binding.tradable,
        "evidence_sha256": binding.evidence_sha256,
        "canonical_payload": binding.canonical_json,
        "semantic_sha256": binding.semantic_sha256,
    }
    values.update((field_name, getattr(binding, field_name)) for field_name in _TEXT_FIELDS)
    values.update((field_name, getattr(binding, field_name)) for field_name in _DATETIME_FIELDS)
    return values


def _head_from_row(row: AlpacaPaperAssetBindingRow) -> _AlpacaPaperAssetBindingHead:
    try:
        head = _AlpacaPaperAssetBindingHead(
            account_id=_required_text(row, "account_id"),
            instrument_id=_required_text(row, "instrument_id"),
            provider_id=_required_text(row, "provider_id"),
            environment=_required_text(row, "environment"),
            expected_provider_account_id=_required_text(
                row,
                "expected_provider_account_id",
            ),
            symbol=_required_text(row, "symbol"),
            expected_provider_asset_id=_required_text(
                row,
                "expected_provider_asset_id",
            ),
            last_sequence_number=_required_integer(row, "last_sequence_number"),
            last_binding_sha256=_required_text(row, "last_binding_sha256"),
            last_qualified_at=_required_datetime(row, "last_qualified_at"),
            last_valid_until=_required_datetime(row, "last_valid_until"),
        )
        _require_identity(head.account_id, "account ID")
        _require_identity(head.instrument_id, "instrument ID")
        _require_identity(head.symbol, "symbol", maximum=32)
        for value, field_name in (
            (head.expected_provider_account_id, "provider account"),
            (head.expected_provider_asset_id, "provider asset"),
        ):
            parsed = UUID(value)
            if str(parsed) != value:
                raise ValueError(field_name)
        if (
            head.provider_id != ALPACA_PAPER_ADAPTER_ID
            or head.environment != "paper"
            or head.last_sequence_number <= 0
            or len(head.last_binding_sha256) != 64
            or any(character not in "0123456789abcdef" for character in head.last_binding_sha256)
            or head.last_valid_until <= head.last_qualified_at
        ):
            raise AlpacaPaperAssetBindingConflict(
                "persisted Alpaca paper asset-binding head is malformed"
            )
        return head
    except AlpacaPaperAssetRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAssetBindingConflict(
            "persisted Alpaca paper asset-binding head is malformed"
        ) from error


def _head(
    connection: Connection,
    *,
    account_id: str,
    instrument_id: str,
) -> _AlpacaPaperAssetBindingHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_asset_binding_heads).where(
                phase4_alpaca_paper_asset_binding_heads.c.account_id == account_id,
                phase4_alpaca_paper_asset_binding_heads.c.instrument_id == instrument_id,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _binding_by_id(
    connection: Connection,
    binding_id: str,
) -> AlpacaPaperAuthenticatedAssetBinding | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_asset_bindings).where(
                phase4_alpaca_paper_asset_bindings.c.binding_id == binding_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_asset_binding_from_row(row)


def _binding_by_evidence(
    connection: Connection,
    evidence_sha256: str,
) -> AlpacaPaperAuthenticatedAssetBinding | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_asset_bindings).where(
                phase4_alpaca_paper_asset_bindings.c.evidence_sha256 == evidence_sha256
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_asset_binding_from_row(row)


def _binding_by_semantic_sha256(
    connection: Connection,
    *,
    account_id: str,
    instrument_id: str,
    semantic_sha256: str,
) -> AlpacaPaperAuthenticatedAssetBinding | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_asset_bindings).where(
                phase4_alpaca_paper_asset_bindings.c.account_id == account_id,
                phase4_alpaca_paper_asset_bindings.c.instrument_id == instrument_id,
                phase4_alpaca_paper_asset_bindings.c.semantic_sha256 == semantic_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_asset_binding_from_row(row)


def _terminal_binding(
    connection: Connection,
    head: _AlpacaPaperAssetBindingHead,
) -> AlpacaPaperAuthenticatedAssetBinding:
    successor_exists = connection.scalar(
        sa.select(
            sa.exists().where(
                phase4_alpaca_paper_asset_bindings.c.account_id == head.account_id,
                phase4_alpaca_paper_asset_bindings.c.instrument_id == head.instrument_id,
                phase4_alpaca_paper_asset_bindings.c.sequence_number > head.last_sequence_number,
            )
        )
    )
    if successor_exists:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset-binding head is rolled back from its terminal fact"
        )
    binding = _binding_by_semantic_sha256(
        connection,
        account_id=head.account_id,
        instrument_id=head.instrument_id,
        semantic_sha256=head.last_binding_sha256,
    )
    if (
        binding is None
        or binding.sequence_number != head.last_sequence_number
        or binding.semantic_sha256 != head.last_binding_sha256
        or binding.qualified_at != head.last_qualified_at
        or binding.valid_until != head.last_valid_until
        or binding.provider_id != head.provider_id
        or binding.environment != head.environment
        or binding.expected_provider_account_id != head.expected_provider_account_id
        or binding.symbol != head.symbol
        or binding.expected_provider_asset_id != head.expected_provider_asset_id
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset-binding head conflicts with its terminal fact"
        )
    return binding


def _authenticate_ingress_source(
    connection: Connection,
    binding: AlpacaPaperAuthenticatedAssetBinding,
) -> BrokerIngressReceipt:
    receipt = _broker_ingress_receipt_by_id(connection, binding.ingress_receipt_id)
    if receipt is None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding references a missing raw ingress receipt"
        )
    if (
        receipt.account_id != binding.account_id
        or receipt.semantic_sha256 != binding.ingress_receipt_sha256
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding conflicts with its raw ingress receipt"
        )
    _authenticate_ingress_receipt_position(connection, receipt)
    return receipt


def _authenticate_durable_sources(
    connection: Connection,
    binding: AlpacaPaperAuthenticatedAssetBinding,
) -> None:
    account_binding = _account_binding_by_id(connection, binding.account_binding_id)
    if account_binding is None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding references a missing account binding"
        )
    _authenticate_account_binding_position(connection, account_binding)
    _authenticate_account_binding_sources(connection, account_binding)
    if (
        account_binding.account_id != binding.account_id
        or account_binding.binding_id != binding.account_binding_id
        or account_binding.semantic_sha256 != binding.account_binding_sha256
        or account_binding.expected_provider_account_id != binding.expected_provider_account_id
        or account_binding.valid_until != binding.account_binding_valid_until
        or account_binding.credential_reference_sha256 != binding.credential_reference_sha256
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding conflicts with its account-binding source"
        )
    pre_account_freshness = _alpaca_paper_account_binding_freshness_receipt(
        account_binding,
        checked_at=binding.pre_account_binding_checked_at,
    )
    post_account_freshness = _alpaca_paper_account_binding_freshness_receipt(
        account_binding,
        checked_at=binding.post_account_binding_checked_at,
    )
    if (
        pre_account_freshness.semantic_sha256 != binding.pre_account_binding_freshness_sha256
        or post_account_freshness.semantic_sha256 != binding.post_account_binding_freshness_sha256
        or not account_binding.is_fresh(binding.received_at)
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding account source was not fresh during transport"
        )

    permit_record = _broker_request_permit_by_id(connection, binding.permit_id)
    if permit_record is None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding references a missing durable request permit"
        )
    _authenticate_permit_position(connection, permit_record)
    permit = permit_record.permit
    policy = permit_record.policy
    demand = permit_record.demand
    if any(
        actual != expected
        for actual, expected in (
            (permit.account_id, binding.account_id),
            (permit.permit_id, binding.permit_id),
            (permit.semantic_sha256, binding.permit_sha256),
            (policy.semantic_sha256, binding.policy_sha256),
            (demand.demand_id, binding.demand_id),
            (demand.semantic_sha256, binding.demand_sha256),
            (demand.requested_at, binding.requested_at),
        )
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding conflicts with its durable request permit"
        )

    credential_reference = AlpacaPaperCredentialReference(
        account_id=binding.account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=binding.secret_ref,
        secret_version=binding.secret_version,
    )
    security_reference = AlpacaPaperSecurityReference(
        credential_reference=credential_reference,
        instrument_id=binding.instrument_id,
        symbol=binding.symbol,
        expected_provider_asset_id=binding.expected_provider_asset_id,
    )
    description = AlpacaPaperAssetObservationDescription(
        account_id=binding.account_id,
        instrument_id=binding.instrument_id,
        symbol=binding.symbol,
    )
    expected_demand = create_alpaca_paper_asset_observation_demand(
        security_reference=security_reference,
        account_binding=account_binding,
        description=description,
        idempotency_key=demand.idempotency_key,
        requested_at=demand.requested_at,
    )
    if (
        credential_reference.semantic_sha256 != binding.credential_reference_sha256
        or security_reference.semantic_sha256 != binding.security_reference_sha256
        or security_reference.capability_sha256 != binding.capability_sha256
        or description.semantic_sha256 != binding.description_sha256
        or policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY
        or demand != expected_demand
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding conflicts with its observation authority"
        )
    freshness = _broker_request_permit_freshness_receipt(
        permit=permit,
        policy=policy,
        demand=demand,
        checked_at=binding.permit_checked_at,
    )
    if freshness.semantic_sha256 != binding.permit_freshness_sha256:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding conflicts with durable permit freshness"
        )
    try:
        require_fresh_broker_request_permit(
            permit=permit,
            policy=policy,
            demand=demand,
            checked_at=binding.request_started_at,
        )
        require_fresh_broker_request_permit(
            permit=permit,
            policy=policy,
            demand=demand,
            checked_at=binding.received_at,
        )
    except ValueError as error:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding permit was stale during transport"
        ) from error

    request = AlpacaPaperAssetTransportRequest(
        description=description,
        credential_reference_sha256=credential_reference.semantic_sha256,
        security_reference_sha256=security_reference.semantic_sha256,
        account_binding_sha256=account_binding.semantic_sha256,
        account_binding_freshness_sha256=pre_account_freshness.semantic_sha256,
        demand_sha256=demand.semantic_sha256,
        permit_sha256=permit.semantic_sha256,
        permit_freshness_sha256=freshness.semantic_sha256,
        fence_receipt_sha256=binding.pre_fence_receipt_sha256,
        started_at=binding.request_started_at,
    )
    if request.semantic_sha256 != binding.transport_request_sha256:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding transport request digest conflicts"
        )

    receipt = _authenticate_ingress_source(connection, binding)
    delivery = receipt.delivery
    if delivery.transport_status is None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding raw receipt lacks an HTTP status"
        )
    response = AlpacaPaperAssetTransportResponse(
        request_sha256=request.semantic_sha256,
        transport_id=ALPACA_PAPER_ASSET_TRANSPORT_ID,
        transport_version=ALPACA_PAPER_ASSET_TRANSPORT_VERSION,
        http_status=delivery.transport_status,
        provider_request_id=delivery.provider_request_id,
        media_type=delivery.media_type,
        response_body=delivery.body,
    )
    if response.semantic_sha256 != binding.transport_response_sha256:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding transport response digest conflicts"
        )
    if delivery.provider_request_id is None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding raw receipt lacks a provider request ID"
        )
    observation = decode_alpaca_asset_observation_response(
        description,
        http_status=delivery.transport_status,
        provider_request_id=delivery.provider_request_id,
        response_body=delivery.body,
        received_at=delivery.received_at,
    )
    PersistedAlpacaAssetObservation(
        receipt=receipt,
        observation=observation,
    )
    if any(
        actual != expected
        for actual, expected in (
            (observation.semantic_sha256, binding.observation_sha256),
            (observation.provider_asset_id, binding.observed_provider_asset_id),
            (observation.asset_class, binding.asset_class),
            (observation.exchange, binding.exchange),
            (observation.status, binding.asset_status),
            (observation.tradable, binding.tradable),
            (observation.received_at, binding.received_at),
            (delivery.recorded_at, binding.raw_recorded_at),
        )
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding conflicts with its decoded raw observation"
        )
    if (
        response.http_status != 200
        or response.provider_request_id is None
        or response.media_type != ALPACA_PAPER_ASSET_ACCEPT_MEDIA_TYPE
        or observation.outcome is not AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
        or observation.provider_asset_id != binding.expected_provider_asset_id
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding source no longer qualifies"
        )
    expected_valid_until = min(
        binding.qualified_at + ALPACA_PAPER_ASSET_BINDING_TTL,
        account_binding.valid_until,
        binding.post_fence_valid_until,
    )
    if binding.valid_until != expected_valid_until:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset binding validity conflicts with durable sources"
        )


def _validate_binding_stream(
    connection: Connection,
    *,
    account_id: str,
    instrument_id: str,
    bindings: Iterable[AlpacaPaperAuthenticatedAssetBinding],
    head: _AlpacaPaperAssetBindingHead | None,
) -> None:
    previous: AlpacaPaperAuthenticatedAssetBinding | None = None
    count = 0
    for count, binding in enumerate(bindings, start=1):
        if (
            binding.account_id != account_id
            or binding.instrument_id != instrument_id
            or binding.sequence_number != count
        ):
            raise AlpacaPaperAssetBindingConflict(
                "Alpaca paper asset-binding history is not a contiguous instrument sequence"
            )
        previous_digest = None if previous is None else previous.semantic_sha256
        if binding.previous_binding_sha256 != previous_digest:
            raise AlpacaPaperAssetBindingConflict(
                "Alpaca paper asset-binding predecessor chain conflicts"
            )
        if previous is not None and (
            binding.expected_provider_account_id != previous.expected_provider_account_id
            or binding.symbol != previous.symbol
            or binding.expected_provider_asset_id != previous.expected_provider_asset_id
        ):
            raise AlpacaPaperAssetBindingConflict(
                "Alpaca provider security identity changed within one instrument history"
            )
        if previous is not None and binding.qualified_at < previous.qualified_at:
            raise AlpacaPaperAssetBindingConflict(
                "Alpaca paper asset-binding qualification clock regressed"
            )
        try:
            _authenticate_durable_sources(connection, binding)
        except AlpacaPaperAssetRuntimeError:
            raise
        except (
            AlpacaPaperAccountAssetObservationError,
            AlpacaPaperAccountBindingConflict,
            BrokerIngressError,
            BrokerRequestBudgetError,
        ) as error:
            raise AlpacaPaperAssetBindingConflict(
                "durable Alpaca paper asset-binding sources failed authentication"
            ) from error
        previous = binding

    if count == 0:
        if head is not None:
            raise AlpacaPaperAssetBindingConflict(
                "Alpaca paper asset-binding head exists without durable facts"
            )
        return
    if head is None or previous is None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset bindings exist without a durable instrument head"
        )
    if (
        head.account_id != account_id
        or head.instrument_id != instrument_id
        or head.provider_id != previous.provider_id
        or head.environment != previous.environment
        or head.expected_provider_account_id != previous.expected_provider_account_id
        or head.symbol != previous.symbol
        or head.expected_provider_asset_id != previous.expected_provider_asset_id
        or head.last_sequence_number != previous.sequence_number
        or head.last_binding_sha256 != previous.semantic_sha256
        or head.last_qualified_at != previous.qualified_at
        or head.last_valid_until != previous.valid_until
    ):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset-binding head conflicts with durable terminal history"
        )


def _history(
    connection: Connection,
    *,
    account_id: str,
    instrument_id: str,
) -> tuple[AlpacaPaperAuthenticatedAssetBinding, ...]:
    rows = (
        connection.execute(
            sa.select(phase4_alpaca_paper_asset_bindings)
            .where(
                phase4_alpaca_paper_asset_bindings.c.account_id == account_id,
                phase4_alpaca_paper_asset_bindings.c.instrument_id == instrument_id,
            )
            .order_by(phase4_alpaca_paper_asset_bindings.c.sequence_number)
        )
        .mappings()
        .all()
    )
    bindings = tuple(alpaca_paper_asset_binding_from_row(row) for row in rows)
    _validate_binding_stream(
        connection,
        account_id=account_id,
        instrument_id=instrument_id,
        bindings=bindings,
        head=_head(
            connection,
            account_id=account_id,
            instrument_id=instrument_id,
        ),
    )
    return bindings


def _verify_alpaca_paper_asset_binding_integrity(connection: Connection) -> None:
    """Authenticate every asset-binding chain in a caller-owned snapshot."""

    orphan = connection.execute(
        sa.select(
            phase4_alpaca_paper_asset_bindings.c.account_id,
            phase4_alpaca_paper_asset_bindings.c.instrument_id,
        )
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_asset_binding_heads.c.account_id
                    == phase4_alpaca_paper_asset_bindings.c.account_id,
                    phase4_alpaca_paper_asset_binding_heads.c.instrument_id
                    == phase4_alpaca_paper_asset_bindings.c.instrument_id,
                )
            )
        )
        .limit(1)
    ).first()
    if orphan is not None:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset bindings exist without durable instrument heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_alpaca_paper_asset_binding_heads)
        .order_by(
            phase4_alpaca_paper_asset_binding_heads.c.account_id,
            phase4_alpaca_paper_asset_binding_heads.c.instrument_id,
        )
        .execution_options(yield_per=128)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        binding_rows = connection.execute(
            sa.select(phase4_alpaca_paper_asset_bindings)
            .where(
                phase4_alpaca_paper_asset_bindings.c.account_id == head.account_id,
                phase4_alpaca_paper_asset_bindings.c.instrument_id == head.instrument_id,
            )
            .order_by(phase4_alpaca_paper_asset_bindings.c.sequence_number)
            .execution_options(yield_per=128)
        ).mappings()
        _validate_binding_stream(
            connection,
            account_id=head.account_id,
            instrument_id=head.instrument_id,
            bindings=(alpaca_paper_asset_binding_from_row(row) for row in binding_rows),
            head=head,
        )


def verify_alpaca_paper_asset_binding_integrity(engine: Engine) -> None:
    """Authenticate all durable asset bindings in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset-binding verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperAssetBindingConflict(
            "Alpaca paper asset-binding verification does not support "
            f"dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_asset_binding_integrity(connection)


def _require_identity(value: object, field_name: str, *, maximum: int = 64) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperAssetBindingConflict(
            f"Alpaca paper asset-binding {field_name} must be bounded, trimmed text"
        )
    return value


class SqlAlpacaPaperAssetBindingRepository:
    """Append authenticated asset evidence under the shared account lock."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperAssetBindingConflict(
                "SQL Alpaca paper asset bindings require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperAssetBindingConflict(
                f"SQL Alpaca paper asset bindings do not support dialect {engine.dialect.name!r}"
            )
        self._engine = engine

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAssetEvidence,
    ) -> AlpacaPaperAuthenticatedAssetBinding:
        """Persist one authenticated, secret-free asset binding exactly once."""

        if type(evidence) is not AlpacaPaperAuthenticatedAssetEvidence:
            raise AlpacaPaperAssetBindingConflict(
                "asset binding recording requires exact authenticated evidence"
            )
        evidence._validate()
        account_id = evidence.security_reference.account_id
        instrument_id = evidence.security_reference.instrument_id
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, account_id)
                history = _history(
                    connection,
                    account_id=account_id,
                    instrument_id=instrument_id,
                )
                previous = None if not history else history[-1]

                existing = _binding_by_evidence(connection, evidence.semantic_sha256)
                if existing is not None:
                    if existing not in history:
                        raise AlpacaPaperAssetBindingConflict(
                            "asset-binding evidence exists outside its authenticated history"
                        )
                    expected = _alpaca_paper_authenticated_asset_binding(
                        evidence,
                        sequence_number=existing.sequence_number,
                        previous_binding_sha256=existing.previous_binding_sha256,
                    )
                    if existing != expected:
                        raise AlpacaPaperAssetBindingConflict(
                            "asset-binding evidence identity conflicts with durable content"
                        )
                    _authenticate_durable_sources(connection, existing)
                    return existing

                reference = evidence.security_reference
                if previous is not None and (
                    previous.expected_provider_account_id != reference.expected_provider_account_id
                    or previous.symbol != reference.symbol
                    or previous.expected_provider_asset_id != reference.expected_provider_asset_id
                ):
                    raise AlpacaPaperAssetBindingConflict(
                        "operator-pinned Alpaca security identity cannot change "
                        "for an existing local instrument"
                    )
                if previous is not None and evidence.qualified_at < previous.qualified_at:
                    raise AlpacaPaperAssetBindingConflict(
                        "asset-binding qualification clock moved backwards"
                    )
                # The shared account lock linearizes this check with account-binding
                # commits.  Historical replays are authenticated above and remain
                # valid after a later account observation; only a new append must
                # use the exact terminal account source at its commit point.
                account_head = _account_binding_head(connection, account_id)
                if (
                    account_head is None
                    or _terminal_account_binding(connection, account_head)
                    != evidence.account_binding
                ):
                    raise AlpacaPaperAssetBindingConflict(
                        "asset binding requires the exact current terminal account source"
                    )
                alias_conflict = connection.scalar(
                    sa.select(
                        sa.exists().where(
                            phase4_alpaca_paper_asset_binding_heads.c.account_id == account_id,
                            phase4_alpaca_paper_asset_binding_heads.c.instrument_id
                            != instrument_id,
                            sa.or_(
                                phase4_alpaca_paper_asset_binding_heads.c.symbol
                                == reference.symbol,
                                phase4_alpaca_paper_asset_binding_heads.c.expected_provider_asset_id
                                == reference.expected_provider_asset_id,
                            ),
                        )
                    )
                )
                if alias_conflict:
                    raise AlpacaPaperAssetBindingConflict(
                        "Alpaca provider security identity is already bound to another instrument"
                    )
                binding = _alpaca_paper_authenticated_asset_binding(
                    evidence,
                    sequence_number=(1 if previous is None else previous.sequence_number + 1),
                    previous_binding_sha256=(
                        None if previous is None else previous.semantic_sha256
                    ),
                )
                _authenticate_durable_sources(connection, binding)
                values = immutable_alpaca_paper_asset_binding_values(binding)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_asset_bindings).values(**values)
                    )
                except IntegrityError as error:
                    raise AlpacaPaperAssetBindingConflict(
                        "Alpaca paper asset binding conflicts with durable history"
                    ) from error

                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_alpaca_paper_asset_binding_heads).values(
                                account_id=account_id,
                                instrument_id=instrument_id,
                                provider_id=binding.provider_id,
                                environment=binding.environment,
                                expected_provider_account_id=(binding.expected_provider_account_id),
                                symbol=binding.symbol,
                                expected_provider_asset_id=(binding.expected_provider_asset_id),
                                last_sequence_number=binding.sequence_number,
                                last_binding_sha256=binding.semantic_sha256,
                                last_qualified_at=binding.qualified_at,
                                last_valid_until=binding.valid_until,
                            )
                        )
                    except IntegrityError as error:
                        raise AlpacaPaperAssetBindingConflict(
                            "Alpaca paper asset-binding head conflicts with durable history"
                        ) from error
                else:
                    updated = connection.execute(
                        sa.update(phase4_alpaca_paper_asset_binding_heads)
                        .where(
                            phase4_alpaca_paper_asset_binding_heads.c.account_id == account_id,
                            phase4_alpaca_paper_asset_binding_heads.c.instrument_id
                            == instrument_id,
                            phase4_alpaca_paper_asset_binding_heads.c.last_sequence_number
                            == previous.sequence_number,
                            phase4_alpaca_paper_asset_binding_heads.c.last_binding_sha256
                            == previous.semantic_sha256,
                            phase4_alpaca_paper_asset_binding_heads.c.last_qualified_at
                            == previous.qualified_at,
                            phase4_alpaca_paper_asset_binding_heads.c.last_valid_until
                            == previous.valid_until,
                        )
                        .values(
                            provider_id=binding.provider_id,
                            environment=binding.environment,
                            expected_provider_account_id=(binding.expected_provider_account_id),
                            symbol=binding.symbol,
                            expected_provider_asset_id=binding.expected_provider_asset_id,
                            last_sequence_number=binding.sequence_number,
                            last_binding_sha256=binding.semantic_sha256,
                            last_qualified_at=binding.qualified_at,
                            last_valid_until=binding.valid_until,
                        )
                    )
                    if updated.rowcount != 1:
                        raise AlpacaPaperAssetBindingConflict(
                            "Alpaca paper asset-binding head changed during sequence allocation"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_alpaca_paper_asset_bindings).where(
                            phase4_alpaca_paper_asset_bindings.c.binding_id == binding.binding_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = alpaca_paper_asset_binding_from_row(row)
                if persisted != binding:
                    raise AlpacaPaperAssetBindingConflict(
                        "Alpaca paper asset binding failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_alpaca_paper_asset_bindings,
                    binding.binding_id,
                    row,
                    values,
                )
                persisted_head = _head(
                    connection,
                    account_id=account_id,
                    instrument_id=instrument_id,
                )
                if (
                    persisted_head is None
                    or persisted_head.last_sequence_number != binding.sequence_number
                    or persisted_head.last_binding_sha256 != binding.semantic_sha256
                    or persisted_head.last_qualified_at != binding.qualified_at
                    or persisted_head.last_valid_until != binding.valid_until
                    or _terminal_binding(connection, persisted_head) != binding
                ):
                    raise AlpacaPaperAssetBindingConflict(
                        "Alpaca paper asset-binding head failed exact SQL readback"
                    )
                return persisted
        except AlpacaPaperAssetRuntimeError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperAccountAssetObservationError,
            AlpacaPaperAccountBindingConflict,
            BrokerIngressError,
            BrokerRequestBudgetError,
            ImmutableFactConflict,
        ) as error:
            raise AlpacaPaperAssetBindingConflict(
                "durable Alpaca paper asset-binding authentication failed"
            ) from error

    def load(
        self,
        binding_id: str,
    ) -> AlpacaPaperAuthenticatedAssetBinding | None:
        """Load one authenticated historical fact; this does not authorize trading."""

        _require_uuid_text(binding_id, "asset binding ID")
        with _repeatable_read_transaction(self._engine) as connection:
            binding = _binding_by_id(connection, binding_id)
            if binding is None:
                return None
            history = _history(
                connection,
                account_id=binding.account_id,
                instrument_id=binding.instrument_id,
            )
            if binding not in history:
                raise AlpacaPaperAssetBindingConflict(
                    "Alpaca paper asset binding exists outside its authenticated history"
                )
            return binding

    def history(
        self,
        account_id: str,
        instrument_id: str,
    ) -> tuple[AlpacaPaperAuthenticatedAssetBinding, ...]:
        """Return one fully authenticated instrument-local binding chain."""

        account_id = _require_identity(account_id, "account ID")
        instrument_id = _require_identity(instrument_id, "instrument ID")
        with _repeatable_read_transaction(self._engine) as connection:
            try:
                return _history(
                    connection,
                    account_id=account_id,
                    instrument_id=instrument_id,
                )
            except (
                AlpacaPaperAccountAssetObservationError,
                AlpacaPaperAccountBindingConflict,
                BrokerIngressError,
                BrokerRequestBudgetError,
            ) as error:
                raise AlpacaPaperAssetBindingConflict(
                    "durable Alpaca paper asset-binding history failed authentication"
                ) from error


def _require_uuid_text(value: object, field_name: str) -> str:
    if type(value) is not str or len(value) != 36 or value != value.lower():
        raise AlpacaPaperAssetBindingConflict(
            f"Alpaca paper {field_name} must be a canonical lowercase UUID"
        )
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise AlpacaPaperAssetBindingConflict(
            f"Alpaca paper {field_name} must be a canonical lowercase UUID"
        ) from error
    if str(parsed) != value:
        raise AlpacaPaperAssetBindingConflict(
            f"Alpaca paper {field_name} must be a canonical lowercase UUID"
        )
    return value


__all__ = [
    "SqlAlpacaPaperAssetBindingRepository",
    "alpaca_paper_asset_binding_from_row",
    "immutable_alpaca_paper_asset_binding_values",
    "verify_alpaca_paper_asset_binding_integrity",
]
