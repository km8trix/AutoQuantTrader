"""Durable, account-serialized Alpaca paper account-binding journal."""

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
    AlpacaAccountObservationOutcome,
    AlpacaPaperAccountAssetObservationError,
    AlpacaPaperAccountObservationDescription,
    decode_alpaca_account_observation_response,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
    ALPACA_PAPER_ACCOUNT_TRANSPORT_ID,
    ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION,
    AlpacaPaperAccountBindingConflict,
    AlpacaPaperAccountBindingFreshnessReceipt,
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperAccountRuntimeError,
    AlpacaPaperAccountTransportRequest,
    AlpacaPaperAccountTransportResponse,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperAuthenticatedAccountEvidence,
    AlpacaPaperCredentialReference,
    _alpaca_paper_account_binding_freshness_receipt,
    _alpaca_paper_account_identity_continuity_receipt,
    _alpaca_paper_authenticated_account_binding,
    create_alpaca_paper_account_observation_demand,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaAccountObservation,
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
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
)

AlpacaPaperAccountBindingRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

_TEXT_FIELDS = (
    "account_id",
    "provider_id",
    "environment",
    "expected_provider_account_id",
    "observed_provider_account_id",
    "secret_ref",
    "secret_version",
    "credential_reference_sha256",
    "credential_resolution_sha256",
    "resolver_id",
    "resolver_version",
    "capability_sha256",
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
    "permit_checked_at",
    "pre_fence_validated_at",
    "request_started_at",
    "received_at",
    "raw_recorded_at",
    "qualified_at",
    "post_fence_valid_until",
    "valid_until",
)


@dataclass(frozen=True, slots=True)
class _AlpacaPaperAccountBindingHead:
    account_id: str
    provider_id: str
    environment: str
    expected_provider_account_id: str
    last_sequence_number: int
    last_binding_sha256: str
    last_qualified_at: datetime
    last_valid_until: datetime


def _required_text(row: AlpacaPaperAccountBindingRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AlpacaPaperAccountBindingConflict(
            f"persisted Alpaca paper account binding {field_name} must be a string"
        )
    return value


def _optional_text(
    row: AlpacaPaperAccountBindingRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise AlpacaPaperAccountBindingConflict(
            f"persisted Alpaca paper account binding {field_name} must be a string or null"
        )
    return value


def _required_integer(row: AlpacaPaperAccountBindingRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperAccountBindingConflict(
            f"persisted Alpaca paper account binding {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: AlpacaPaperAccountBindingRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperAccountBindingConflict(
            f"persisted Alpaca paper account binding {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def alpaca_paper_account_binding_from_row(
    row: AlpacaPaperAccountBindingRow,
) -> AlpacaPaperAuthenticatedAccountBinding:
    """Strictly reconstruct and authenticate one persisted account binding."""

    try:
        binding = object.__new__(AlpacaPaperAuthenticatedAccountBinding)
        for field_name in _TEXT_FIELDS:
            object.__setattr__(binding, field_name, _required_text(row, field_name))
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
                    ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
                    "authenticated_account_evidence",
                    binding.credential_reference_sha256,
                    binding.credential_resolution_sha256,
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
                    binding.qualified_at,
                    binding.valid_until,
                )
            )
        ).hexdigest()
        if binding.evidence_sha256 != expected_evidence_sha256:
            raise AlpacaPaperAccountBindingConflict(
                "persisted Alpaca paper account binding evidence digest conflicts"
            )
        duplicated_values: tuple[tuple[str, object], ...] = (
            ("binding_id", binding.binding_id),
            ("canonical_payload", binding.canonical_json),
            ("semantic_sha256", binding.semantic_sha256),
        )
        for field_name, expected in duplicated_values:
            if row[field_name] != expected:
                raise AlpacaPaperAccountBindingConflict(
                    f"persisted Alpaca paper account binding {field_name} conflicts"
                )
        return binding
    except AlpacaPaperAccountRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAccountBindingConflict(
            "persisted Alpaca paper account binding is malformed"
        ) from error


def immutable_alpaca_paper_account_binding_values(
    binding: AlpacaPaperAuthenticatedAccountBinding,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one binding."""

    if type(binding) is not AlpacaPaperAuthenticatedAccountBinding:
        raise AlpacaPaperAccountBindingConflict(
            "account binding persistence requires an exact durable binding"
        )
    binding._validate()
    values: dict[str, Any] = {
        "binding_id": binding.binding_id,
        "sequence_number": binding.sequence_number,
        "previous_binding_sha256": binding.previous_binding_sha256,
        "evidence_sha256": binding.evidence_sha256,
        "canonical_payload": binding.canonical_json,
        "semantic_sha256": binding.semantic_sha256,
    }
    values.update((field_name, getattr(binding, field_name)) for field_name in _TEXT_FIELDS)
    values.update((field_name, getattr(binding, field_name)) for field_name in _DATETIME_FIELDS)
    return values


def _head_from_row(
    row: AlpacaPaperAccountBindingRow,
) -> _AlpacaPaperAccountBindingHead:
    try:
        head = _AlpacaPaperAccountBindingHead(
            account_id=_required_text(row, "account_id"),
            provider_id=_required_text(row, "provider_id"),
            environment=_required_text(row, "environment"),
            expected_provider_account_id=_required_text(
                row,
                "expected_provider_account_id",
            ),
            last_sequence_number=_required_integer(row, "last_sequence_number"),
            last_binding_sha256=_required_text(row, "last_binding_sha256"),
            last_qualified_at=_required_datetime(row, "last_qualified_at"),
            last_valid_until=_required_datetime(row, "last_valid_until"),
        )
        _require_account_id(head.account_id)
        try:
            parsed_provider_account_id = UUID(head.expected_provider_account_id)
        except ValueError as error:
            raise AlpacaPaperAccountBindingConflict(
                "persisted Alpaca paper account-binding head provider UUID is malformed"
            ) from error
        if (
            head.provider_id != ALPACA_PAPER_ADAPTER_ID
            or head.environment != "paper"
            or str(parsed_provider_account_id) != head.expected_provider_account_id
            or head.last_sequence_number <= 0
            or len(head.last_binding_sha256) != 64
            or any(character not in "0123456789abcdef" for character in head.last_binding_sha256)
            or head.last_valid_until <= head.last_qualified_at
        ):
            raise AlpacaPaperAccountBindingConflict(
                "persisted Alpaca paper account-binding head is malformed"
            )
        return head
    except AlpacaPaperAccountRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAccountBindingConflict(
            "persisted Alpaca paper account-binding head is malformed"
        ) from error


def _head(
    connection: Connection,
    account_id: str,
) -> _AlpacaPaperAccountBindingHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_binding_heads).where(
                phase4_alpaca_paper_account_binding_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _binding_by_id(
    connection: Connection,
    binding_id: str,
) -> AlpacaPaperAuthenticatedAccountBinding | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_bindings).where(
                phase4_alpaca_paper_account_bindings.c.binding_id == binding_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_account_binding_from_row(row)


def _binding_by_evidence(
    connection: Connection,
    evidence_sha256: str,
) -> AlpacaPaperAuthenticatedAccountBinding | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_bindings).where(
                phase4_alpaca_paper_account_bindings.c.evidence_sha256 == evidence_sha256
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_account_binding_from_row(row)


def _binding_by_semantic_sha256(
    connection: Connection,
    *,
    account_id: str,
    semantic_sha256: str,
) -> AlpacaPaperAuthenticatedAccountBinding | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_bindings).where(
                phase4_alpaca_paper_account_bindings.c.account_id == account_id,
                phase4_alpaca_paper_account_bindings.c.semantic_sha256 == semantic_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_account_binding_from_row(row)


def _terminal_binding(
    connection: Connection,
    head: _AlpacaPaperAccountBindingHead,
) -> AlpacaPaperAuthenticatedAccountBinding:
    successor_exists = connection.scalar(
        sa.select(
            sa.exists().where(
                phase4_alpaca_paper_account_bindings.c.account_id == head.account_id,
                phase4_alpaca_paper_account_bindings.c.sequence_number > head.last_sequence_number,
            )
        )
    )
    if successor_exists:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account-binding head is rolled back from its terminal fact"
        )
    binding = _binding_by_semantic_sha256(
        connection,
        account_id=head.account_id,
        semantic_sha256=head.last_binding_sha256,
    )
    if (
        binding is None
        or binding.sequence_number != head.last_sequence_number
        or binding.semantic_sha256 != head.last_binding_sha256
        or binding.qualified_at != head.last_qualified_at
        or binding.provider_id != head.provider_id
        or binding.environment != head.environment
        or binding.expected_provider_account_id != head.expected_provider_account_id
        or binding.valid_until != head.last_valid_until
    ):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account-binding head conflicts with its terminal fact"
        )
    return binding


def _authenticate_binding_position(
    connection: Connection,
    binding: AlpacaPaperAuthenticatedAccountBinding,
) -> _AlpacaPaperAccountBindingHead:
    history = _history(connection, binding.account_id)
    if binding not in history:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding exists outside its durable head"
        )
    head = _head(connection, binding.account_id)
    if head is None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account bindings exist without a durable account head"
        )
    return head


def _authenticate_ingress_source(
    connection: Connection,
    binding: AlpacaPaperAuthenticatedAccountBinding,
) -> BrokerIngressReceipt:
    receipt = _broker_ingress_receipt_by_id(connection, binding.ingress_receipt_id)
    if receipt is None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding references a missing raw ingress receipt"
        )
    if (
        receipt.account_id != binding.account_id
        or receipt.semantic_sha256 != binding.ingress_receipt_sha256
    ):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding conflicts with its raw ingress receipt"
        )
    _authenticate_ingress_receipt_position(connection, receipt)
    return receipt


def _authenticate_durable_sources(
    connection: Connection,
    binding: AlpacaPaperAuthenticatedAccountBinding,
) -> None:
    permit_record = _broker_request_permit_by_id(connection, binding.permit_id)
    if permit_record is None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding references a missing durable request permit"
        )
    _authenticate_permit_position(connection, permit_record)
    permit = permit_record.permit
    policy = permit_record.policy
    demand = permit_record.demand
    permit_values = (
        (permit.account_id, binding.account_id),
        (permit.permit_id, binding.permit_id),
        (permit.semantic_sha256, binding.permit_sha256),
        (policy.semantic_sha256, binding.policy_sha256),
        (demand.demand_id, binding.demand_id),
        (demand.semantic_sha256, binding.demand_sha256),
        (demand.requested_at, binding.requested_at),
    )
    if any(actual != expected for actual, expected in permit_values):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding conflicts with its durable request permit"
        )

    reference = AlpacaPaperCredentialReference(
        account_id=binding.account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=binding.secret_ref,
        secret_version=binding.secret_version,
    )
    description = AlpacaPaperAccountObservationDescription(
        account_id=binding.account_id,
    )
    expected_demand = create_alpaca_paper_account_observation_demand(
        reference=reference,
        description=description,
        idempotency_key=demand.idempotency_key,
        requested_at=demand.requested_at,
    )
    if (
        reference.semantic_sha256 != binding.credential_reference_sha256
        or reference.capability_sha256 != binding.capability_sha256
        or description.semantic_sha256 != binding.description_sha256
        or policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY
        or demand != expected_demand
    ):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding conflicts with its account-observation authority"
        )
    freshness = _broker_request_permit_freshness_receipt(
        permit=permit,
        policy=policy,
        demand=demand,
        checked_at=binding.permit_checked_at,
    )
    if freshness.semantic_sha256 != binding.permit_freshness_sha256:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding conflicts with durable permit freshness"
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
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding permit was stale during transport"
        ) from error
    request = AlpacaPaperAccountTransportRequest(
        description=description,
        credential_reference_sha256=reference.semantic_sha256,
        demand_sha256=demand.semantic_sha256,
        permit_sha256=permit.semantic_sha256,
        permit_freshness_sha256=freshness.semantic_sha256,
        fence_receipt_sha256=binding.pre_fence_receipt_sha256,
        started_at=binding.request_started_at,
    )
    if request.semantic_sha256 != binding.transport_request_sha256:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding transport request digest conflicts"
        )

    receipt = _authenticate_ingress_source(connection, binding)
    delivery = receipt.delivery
    if delivery.transport_status is None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding raw receipt lacks an HTTP status"
        )
    response = AlpacaPaperAccountTransportResponse(
        request_sha256=request.semantic_sha256,
        transport_id=ALPACA_PAPER_ACCOUNT_TRANSPORT_ID,
        transport_version=ALPACA_PAPER_ACCOUNT_TRANSPORT_VERSION,
        http_status=delivery.transport_status,
        provider_request_id=delivery.provider_request_id,
        media_type=delivery.media_type,
        response_body=delivery.body,
    )
    if response.semantic_sha256 != binding.transport_response_sha256:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding transport response digest conflicts"
        )
    if delivery.provider_request_id is None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding raw receipt lacks a provider request ID"
        )
    observation = decode_alpaca_account_observation_response(
        description,
        http_status=delivery.transport_status,
        provider_request_id=delivery.provider_request_id,
        response_body=delivery.body,
        received_at=delivery.received_at,
    )
    PersistedAlpacaAccountObservation(
        receipt=receipt,
        observation=observation,
    )
    observation_values = (
        (observation.semantic_sha256, binding.observation_sha256),
        (observation.provider_account_id, binding.observed_provider_account_id),
        (observation.received_at, binding.received_at),
        (delivery.recorded_at, binding.raw_recorded_at),
    )
    if any(actual != expected for actual, expected in observation_values):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding conflicts with its decoded raw observation"
        )
    if (
        response.http_status != 200
        or response.provider_request_id is None
        or response.media_type != ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
        or observation.outcome is not AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
        or observation.provider_account_id != binding.expected_provider_account_id
    ):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account binding source no longer qualifies"
        )


def _validate_binding_stream(
    connection: Connection,
    *,
    account_id: str,
    bindings: Iterable[AlpacaPaperAuthenticatedAccountBinding],
    head: _AlpacaPaperAccountBindingHead | None,
) -> None:
    previous: AlpacaPaperAuthenticatedAccountBinding | None = None
    count = 0
    pinned_provider_account_id: str | None = None
    for count, binding in enumerate(bindings, start=1):
        if binding.account_id != account_id or binding.sequence_number != count:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account-binding history is not a contiguous account-local sequence"
            )
        previous_digest = None if previous is None else previous.semantic_sha256
        if binding.previous_binding_sha256 != previous_digest:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account-binding predecessor chain conflicts"
            )
        if pinned_provider_account_id is None:
            pinned_provider_account_id = binding.expected_provider_account_id
        elif binding.expected_provider_account_id != pinned_provider_account_id:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca provider account UUID changed within one local account history"
            )
        if previous is not None and binding.qualified_at < previous.qualified_at:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account-binding qualification clock regressed"
            )
        try:
            _authenticate_durable_sources(connection, binding)
        except AlpacaPaperAccountRuntimeError:
            raise
        except (
            AlpacaPaperAccountAssetObservationError,
            BrokerIngressError,
            BrokerRequestBudgetError,
        ) as error:
            raise AlpacaPaperAccountBindingConflict(
                "durable Alpaca paper account-binding sources failed authentication"
            ) from error
        previous = binding

    if count == 0:
        if head is not None:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account-binding head exists without durable facts"
            )
        return
    if head is None or previous is None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account bindings exist without a durable account head"
        )
    if (
        head.account_id != account_id
        or head.provider_id != previous.provider_id
        or head.environment != previous.environment
        or head.expected_provider_account_id != previous.expected_provider_account_id
        or head.last_sequence_number != previous.sequence_number
        or head.last_binding_sha256 != previous.semantic_sha256
        or head.last_qualified_at != previous.qualified_at
        or head.last_valid_until != previous.valid_until
    ):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account-binding head conflicts with durable terminal history"
        )


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[AlpacaPaperAuthenticatedAccountBinding, ...]:
    rows = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_bindings)
            .where(phase4_alpaca_paper_account_bindings.c.account_id == account_id)
            .order_by(phase4_alpaca_paper_account_bindings.c.sequence_number)
        )
        .mappings()
        .all()
    )
    bindings = tuple(alpaca_paper_account_binding_from_row(row) for row in rows)
    _validate_binding_stream(
        connection,
        account_id=account_id,
        bindings=bindings,
        head=_head(connection, account_id),
    )
    return bindings


def _verify_alpaca_paper_account_binding_integrity(
    connection: Connection,
) -> None:
    """Authenticate every account-binding chain in a caller-owned snapshot."""

    binding_without_head = connection.scalar(
        sa.select(phase4_alpaca_paper_account_bindings.c.account_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_binding_heads.c.account_id
                    == phase4_alpaca_paper_account_bindings.c.account_id
                )
            )
        )
        .limit(1)
    )
    if binding_without_head is not None:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account bindings exist without durable account heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_alpaca_paper_account_binding_heads)
        .order_by(phase4_alpaca_paper_account_binding_heads.c.account_id)
        .execution_options(yield_per=128)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        binding_rows = connection.execute(
            sa.select(phase4_alpaca_paper_account_bindings)
            .where(phase4_alpaca_paper_account_bindings.c.account_id == head.account_id)
            .order_by(phase4_alpaca_paper_account_bindings.c.sequence_number)
            .execution_options(yield_per=128)
        ).mappings()
        _validate_binding_stream(
            connection,
            account_id=head.account_id,
            bindings=(alpaca_paper_account_binding_from_row(row) for row in binding_rows),
            head=head,
        )


def verify_alpaca_paper_account_binding_integrity(engine: Engine) -> None:
    """Authenticate all durable bindings in one stable database snapshot."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account-binding verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account-binding verification does not support "
            f"dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_account_binding_integrity(connection)


def _require_account_id(account_id: object) -> str:
    if (
        type(account_id) is not str
        or not account_id
        or account_id != account_id.strip()
        or len(account_id) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in account_id)
    ):
        raise AlpacaPaperAccountBindingConflict(
            "Alpaca paper account-binding account ID must be bounded, trimmed text"
        )
    return account_id


class SqlAlpacaPaperAccountBindingRepository:
    """Append authenticated account evidence under the shared account lock."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperAccountBindingConflict(
                "SQL Alpaca paper account bindings require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperAccountBindingConflict(
                f"SQL Alpaca paper account bindings do not support dialect {engine.dialect.name!r}"
            )
        self._engine = engine

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared SQL engine for process-local composition checks."""

        return id(self._engine)

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountEvidence,
    ) -> AlpacaPaperAuthenticatedAccountBinding:
        """Persist one authenticated, secret-free binding exactly once."""

        if type(evidence) is not AlpacaPaperAuthenticatedAccountEvidence:
            raise AlpacaPaperAccountBindingConflict(
                "account binding recording requires exact authenticated evidence"
            )
        evidence._validate()
        account_id = evidence.reference.account_id
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, account_id)
                history = _history(connection, account_id)
                previous = None if not history else history[-1]

                existing = _binding_by_evidence(
                    connection,
                    evidence.semantic_sha256,
                )
                if existing is not None:
                    if existing not in history:
                        raise AlpacaPaperAccountBindingConflict(
                            "account-binding evidence exists outside its authenticated history"
                        )
                    expected = _alpaca_paper_authenticated_account_binding(
                        evidence,
                        sequence_number=existing.sequence_number,
                        previous_binding_sha256=existing.previous_binding_sha256,
                    )
                    if existing != expected:
                        raise AlpacaPaperAccountBindingConflict(
                            "account-binding evidence identity conflicts with durable content"
                        )
                    _authenticate_durable_sources(connection, existing)
                    return existing

                if (
                    previous is not None
                    and previous.expected_provider_account_id
                    != evidence.reference.expected_provider_account_id
                ):
                    raise AlpacaPaperAccountBindingConflict(
                        "operator-pinned Alpaca provider account UUID cannot change "
                        "for an existing local account"
                    )
                if previous is not None and evidence.qualified_at < previous.qualified_at:
                    raise AlpacaPaperAccountBindingConflict(
                        "account-binding qualification clock moved backwards"
                    )
                binding = _alpaca_paper_authenticated_account_binding(
                    evidence,
                    sequence_number=(1 if previous is None else previous.sequence_number + 1),
                    previous_binding_sha256=(
                        None if previous is None else previous.semantic_sha256
                    ),
                )
                _authenticate_durable_sources(connection, binding)
                values = immutable_alpaca_paper_account_binding_values(binding)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_account_bindings).values(**values)
                    )
                except IntegrityError as error:
                    raise AlpacaPaperAccountBindingConflict(
                        "Alpaca paper account binding conflicts with durable history"
                    ) from error

                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_alpaca_paper_account_binding_heads).values(
                                account_id=account_id,
                                provider_id=binding.provider_id,
                                environment=binding.environment,
                                expected_provider_account_id=(binding.expected_provider_account_id),
                                last_sequence_number=binding.sequence_number,
                                last_binding_sha256=binding.semantic_sha256,
                                last_qualified_at=binding.qualified_at,
                                last_valid_until=binding.valid_until,
                            )
                        )
                    except IntegrityError as error:
                        raise AlpacaPaperAccountBindingConflict(
                            "Alpaca paper account-binding head conflicts with durable history"
                        ) from error
                else:
                    updated = connection.execute(
                        sa.update(phase4_alpaca_paper_account_binding_heads)
                        .where(
                            phase4_alpaca_paper_account_binding_heads.c.account_id == account_id,
                            phase4_alpaca_paper_account_binding_heads.c.provider_id
                            == previous.provider_id,
                            phase4_alpaca_paper_account_binding_heads.c.environment
                            == previous.environment,
                            phase4_alpaca_paper_account_binding_heads.c.expected_provider_account_id
                            == previous.expected_provider_account_id,
                            phase4_alpaca_paper_account_binding_heads.c.last_sequence_number
                            == previous.sequence_number,
                            phase4_alpaca_paper_account_binding_heads.c.last_binding_sha256
                            == previous.semantic_sha256,
                            phase4_alpaca_paper_account_binding_heads.c.last_qualified_at
                            == previous.qualified_at,
                            phase4_alpaca_paper_account_binding_heads.c.last_valid_until
                            == previous.valid_until,
                        )
                        .values(
                            provider_id=binding.provider_id,
                            environment=binding.environment,
                            expected_provider_account_id=(binding.expected_provider_account_id),
                            last_sequence_number=binding.sequence_number,
                            last_binding_sha256=binding.semantic_sha256,
                            last_qualified_at=binding.qualified_at,
                            last_valid_until=binding.valid_until,
                        )
                    )
                    if updated.rowcount != 1:
                        raise AlpacaPaperAccountBindingConflict(
                            "Alpaca paper account-binding head changed during sequence allocation"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_alpaca_paper_account_bindings).where(
                            phase4_alpaca_paper_account_bindings.c.binding_id == binding.binding_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = alpaca_paper_account_binding_from_row(row)
                if persisted != binding:
                    raise AlpacaPaperAccountBindingConflict(
                        "Alpaca paper account binding failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_alpaca_paper_account_bindings,
                    binding.binding_id,
                    row,
                    values,
                )
                persisted_head = _head(connection, account_id)
                if (
                    persisted_head is None
                    or persisted_head.provider_id != binding.provider_id
                    or persisted_head.environment != binding.environment
                    or persisted_head.expected_provider_account_id
                    != binding.expected_provider_account_id
                    or persisted_head.last_sequence_number != binding.sequence_number
                    or persisted_head.last_binding_sha256 != binding.semantic_sha256
                    or persisted_head.last_qualified_at != binding.qualified_at
                    or persisted_head.last_valid_until != binding.valid_until
                ):
                    raise AlpacaPaperAccountBindingConflict(
                        "Alpaca paper account-binding head failed exact SQL readback"
                    )
                if _terminal_binding(connection, persisted_head) != binding:
                    raise AlpacaPaperAccountBindingConflict(
                        "Alpaca paper terminal account binding failed exact SQL readback"
                    )
                return persisted
        except AlpacaPaperAccountRuntimeError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperAccountAssetObservationError,
            BrokerIngressError,
            BrokerRequestBudgetError,
            ImmutableFactConflict,
        ) as error:
            raise AlpacaPaperAccountBindingConflict(
                "durable Alpaca paper account-binding authentication failed"
            ) from error

    def load(
        self,
        binding_id: str,
    ) -> AlpacaPaperAuthenticatedAccountBinding | None:
        """Load one authenticated durable binding, or ``None`` when absent."""

        if type(binding_id) is not str or len(binding_id) != 36 or binding_id != binding_id.lower():
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account binding ID must be a canonical lowercase UUID"
            )
        try:
            parsed_binding_id = UUID(binding_id)
        except ValueError as error:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account binding ID must be a canonical lowercase UUID"
            ) from error
        if str(parsed_binding_id) != binding_id:
            raise AlpacaPaperAccountBindingConflict(
                "Alpaca paper account binding ID must be a canonical lowercase UUID"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            binding = _binding_by_id(connection, binding_id)
            if binding is None:
                return None
            _authenticate_binding_position(connection, binding)
            try:
                _authenticate_durable_sources(connection, binding)
            except (
                AlpacaPaperAccountAssetObservationError,
                BrokerIngressError,
                BrokerRequestBudgetError,
            ) as error:
                raise AlpacaPaperAccountBindingConflict(
                    "durable Alpaca paper account-binding sources failed authentication"
                ) from error
            return binding

    def authenticate_terminal_fresh(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountBindingFreshnessReceipt:
        """Reauthenticate one exact terminal binding and prove freshness."""

        if type(binding) is not AlpacaPaperAuthenticatedAccountBinding:
            raise AlpacaPaperAccountBindingConflict(
                "terminal account-binding authentication requires an exact binding"
            )
        binding._validate()
        with _repeatable_read_transaction(self._engine) as connection:
            persisted = _binding_by_id(connection, binding.binding_id)
            if persisted is None or persisted != binding:
                raise AlpacaPaperAccountBindingConflict(
                    "terminal account-binding authentication conflicts with durable content"
                )
            head = _authenticate_binding_position(connection, persisted)
            if _terminal_binding(connection, head) != persisted:
                raise AlpacaPaperAccountBindingConflict(
                    "account binding is not the exact durable terminal binding"
                )
            try:
                _authenticate_durable_sources(connection, persisted)
            except (
                AlpacaPaperAccountAssetObservationError,
                BrokerIngressError,
                BrokerRequestBudgetError,
            ) as error:
                raise AlpacaPaperAccountBindingConflict(
                    "terminal account-binding sources failed authentication"
                ) from error
            return _alpaca_paper_account_binding_freshness_receipt(
                persisted,
                checked_at=checked_at,
            )

    def authenticate_terminal_identity(
        self,
        binding: AlpacaPaperAuthenticatedAccountBinding,
        checked_at: datetime,
    ) -> AlpacaPaperAccountIdentityContinuityReceipt:
        """Reauthenticate one exact terminal binding without asserting status freshness."""

        if type(binding) is not AlpacaPaperAuthenticatedAccountBinding:
            raise AlpacaPaperAccountBindingConflict(
                "terminal account-identity authentication requires an exact binding"
            )
        binding._validate()
        with _repeatable_read_transaction(self._engine) as connection:
            persisted = _binding_by_id(connection, binding.binding_id)
            if persisted is None or persisted != binding:
                raise AlpacaPaperAccountBindingConflict(
                    "terminal account-identity authentication conflicts with durable content"
                )
            head = _authenticate_binding_position(connection, persisted)
            if _terminal_binding(connection, head) != persisted:
                raise AlpacaPaperAccountBindingConflict(
                    "account identity does not come from the exact durable terminal binding"
                )
            try:
                _authenticate_durable_sources(connection, persisted)
            except (
                AlpacaPaperAccountAssetObservationError,
                BrokerIngressError,
                BrokerRequestBudgetError,
            ) as error:
                raise AlpacaPaperAccountBindingConflict(
                    "terminal account-identity sources failed authentication"
                ) from error
            return _alpaca_paper_account_identity_continuity_receipt(
                persisted,
                checked_at=checked_at,
            )

    def authenticate_configured_terminal_identity(
        self,
        reference: AlpacaPaperCredentialReference,
        checked_at: datetime,
    ) -> AlpacaPaperAccountIdentityContinuityReceipt | None:
        """Attest one configured historical identity without asserting freshness.

        The complete binding and source history is authenticated in one stable
        database snapshot.  ``None`` means that the configured local account has
        no durable binding history; a mismatched identity is a conflict rather
        than absence.
        """

        if type(reference) is not AlpacaPaperCredentialReference:
            raise AlpacaPaperAccountBindingConflict(
                "configured account-identity authentication requires an exact "
                "paper credential reference"
            )
        reference.__post_init__()
        with _repeatable_read_transaction(self._engine) as connection:
            _verify_alpaca_paper_account_binding_integrity(connection)
            history = _history(connection, reference.account_id)
            if not history:
                return None
            terminal = history[-1]
            configured_values = (
                (terminal.account_id, reference.account_id),
                (terminal.provider_id, reference.provider_id),
                (terminal.environment, reference.environment),
                (
                    terminal.expected_provider_account_id,
                    reference.expected_provider_account_id,
                ),
                (
                    terminal.observed_provider_account_id,
                    reference.expected_provider_account_id,
                ),
                (terminal.secret_ref, reference.secret_ref),
                (terminal.secret_version, reference.secret_version),
                (
                    terminal.credential_reference_sha256,
                    reference.semantic_sha256,
                ),
                (terminal.capability_sha256, reference.capability_sha256),
            )
            if any(actual != expected for actual, expected in configured_values):
                raise AlpacaPaperAccountBindingConflict(
                    "configured paper account identity conflicts with its exact "
                    "durable terminal binding"
                )
            return _alpaca_paper_account_identity_continuity_receipt(
                terminal,
                checked_at=checked_at,
            )

    def history(
        self,
        account_id: str,
    ) -> tuple[AlpacaPaperAuthenticatedAccountBinding, ...]:
        """Return one fully authenticated account-local binding chain."""

        account_id = _require_account_id(account_id)
        with _repeatable_read_transaction(self._engine) as connection:
            try:
                return _history(connection, account_id)
            except (
                AlpacaPaperAccountAssetObservationError,
                BrokerIngressError,
                BrokerRequestBudgetError,
            ) as error:
                raise AlpacaPaperAccountBindingConflict(
                    "durable Alpaca paper account-binding history failed authentication"
                ) from error


__all__ = [
    "SqlAlpacaPaperAccountBindingRepository",
    "alpaca_paper_account_binding_from_row",
    "immutable_alpaca_paper_account_binding_values",
    "verify_alpaca_paper_account_binding_integrity",
]
