"""Durable, attempt-local authenticated Alpaca paper lookup observations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    AlpacaPaperContractError,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionReceipt,
    _alpaca_paper_account_identity_continuity_receipt,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    AlpacaPaperSecurityReference,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
    ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
    PersistedAlpacaClientOrderLookupObservation,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
    ALPACA_PAPER_LOOKUP_TRANSPORT_ID,
    ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedLookupEvidence,
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
    AlpacaPaperLookupConflict,
    AlpacaPaperLookupRuntimeError,
    AlpacaPaperLookupTransportRequest,
    AlpacaPaperLookupTransportResponse,
    _alpaca_paper_authenticated_lookup_receipt,
    _alpaca_paper_unknown_attempt_freshness_receipt,
    _lookup_outcome,
    create_alpaca_paper_unknown_lookup_demand,
)
from packages.adapters.broker.alpaca_paper_observations import (
    create_alpaca_client_order_lookup_description,
    decode_alpaca_client_order_lookup_response,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    AccountLeaseRelease,
    _account_fence_receipt,
)
from packages.domain.broker_ingress import BrokerIngressError, BrokerIngressReceipt
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetError,
    _broker_request_permit_freshness_receipt,
    require_fresh_broker_request_permit,
)
from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    reduce_submission_attempt,
)
from packages.persistence.account_coordinator import (
    _lease_head_from_row,
    _write_transaction,
    account_lease_from_row,
    account_lease_release_from_row,
    lock_account_capacity_serialization,
    verify_account_lease_history,
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
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase4_alpaca_paper_account_bindings,
    phase4_alpaca_paper_lookup_observation_heads,
    phase4_alpaca_paper_lookup_observations,
)
from packages.persistence.submission_attempt import (
    SubmissionAttemptPersistenceError,
    _authenticate_terminal_unknown,
    load_submission_attempt,
)

AlpacaPaperLookupObservationRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


class SqlAccountFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


_TEXT_FIELDS = (
    "account_id",
    "provider_id",
    "environment",
    "attempt_id",
    "attempt_sha256",
    "terminal_event_id",
    "terminal_event_sha256",
    "parent_decision_id",
    "reservation_id",
    "order_id",
    "client_order_id",
    "instrument_id",
    "symbol",
    "expected_provider_account_id",
    "expected_provider_asset_id",
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
    "pre_attempt_freshness_sha256",
    "post_attempt_freshness_sha256",
    "pre_account_identity_sha256",
    "post_account_identity_sha256",
    "description_sha256",
    "submission_sha256",
    "policy_sha256",
    "demand_id",
    "demand_sha256",
    "permit_id",
    "permit_sha256",
    "permit_freshness_sha256",
    "fence_owner_id",
    "fence_lease_id",
    "fence_sha256",
    "fence_policy_sha256",
    "pre_fence_lease_sha256",
    "post_fence_lease_sha256",
    "pre_fence_receipt_sha256",
    "post_fence_receipt_sha256",
    "ingress_receipt_id",
    "ingress_receipt_sha256",
    "observation_sha256",
    "transport_request_sha256",
    "transport_response_sha256",
    "provider_request_id",
    "evidence_sha256",
)
_OPTIONAL_TEXT_FIELDS = (
    "provider_order_id",
    "provider_order_status",
    "observed_provider_asset_id",
)
_INTEGER_FIELDS = (
    "terminal_event_sequence",
    "fence_fencing_generation",
    "http_status",
    "sequence_number",
)
_DATETIME_FIELDS = (
    "requested_at",
    "credential_resolution_started_at",
    "resolved_at",
    "credential_resolution_valid_until",
    "permit_checked_at",
    "pre_fence_validated_at",
    "pre_fence_valid_until",
    "pre_attempt_checked_at",
    "pre_account_identity_checked_at",
    "request_started_at",
    "received_at",
    "raw_recorded_at",
    "post_fence_validated_at",
    "post_fence_valid_until",
    "post_attempt_checked_at",
    "post_account_identity_checked_at",
    "authenticated_at",
    "commit_checked_at",
)


@dataclass(frozen=True, slots=True)
class _AlpacaPaperLookupObservationHead:
    account_id: str
    attempt_id: str
    terminal_event_id: str
    terminal_event_sha256: str
    last_sequence_number: int
    last_receipt_sha256: str
    last_authenticated_at: datetime


def _required_text(
    row: AlpacaPaperLookupObservationRow,
    field_name: str,
) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AlpacaPaperLookupConflict(
            f"persisted Alpaca paper lookup {field_name} must be a string"
        )
    return value


def _optional_text(
    row: AlpacaPaperLookupObservationRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise AlpacaPaperLookupConflict(
            f"persisted Alpaca paper lookup {field_name} must be a string or null"
        )
    return value


def _required_integer(
    row: AlpacaPaperLookupObservationRow,
    field_name: str,
) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperLookupConflict(
            f"persisted Alpaca paper lookup {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: AlpacaPaperLookupObservationRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperLookupConflict(
            f"persisted Alpaca paper lookup {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _mismatch_fields_from_row(
    row: AlpacaPaperLookupObservationRow,
) -> tuple[str, ...]:
    payload = _required_text(row, "mismatch_fields_payload")
    try:
        decoded = json.loads(payload)
    except (TypeError, ValueError) as error:
        raise AlpacaPaperLookupConflict(
            "persisted Alpaca paper lookup mismatch fields are malformed"
        ) from error
    if type(decoded) is not dict or set(decoded) != {"type", "value"}:
        raise AlpacaPaperLookupConflict(
            "persisted Alpaca paper lookup mismatch fields are malformed"
        )
    if decoded["type"] != "tuple" or type(decoded["value"]) is not list:
        raise AlpacaPaperLookupConflict(
            "persisted Alpaca paper lookup mismatch fields are malformed"
        )
    values: list[str] = []
    for node in decoded["value"]:
        if (
            type(node) is not dict
            or set(node) != {"type", "value"}
            or node["type"] != "string"
            or type(node["value"]) is not str
        ):
            raise AlpacaPaperLookupConflict(
                "persisted Alpaca paper lookup mismatch fields are malformed"
            )
        values.append(node["value"])
    result = tuple(values)
    if canonical_json_text(result) != payload:
        raise AlpacaPaperLookupConflict(
            "persisted Alpaca paper lookup mismatch fields are not canonical"
        )
    return result


def alpaca_paper_lookup_observation_from_row(
    row: AlpacaPaperLookupObservationRow,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    """Strictly reconstruct one scalar authenticated lookup receipt."""

    try:
        receipt = object.__new__(AlpacaPaperAuthenticatedLookupReceipt)
        for field_name in _TEXT_FIELDS:
            object.__setattr__(receipt, field_name, _required_text(row, field_name))
        for field_name in _OPTIONAL_TEXT_FIELDS:
            object.__setattr__(receipt, field_name, _optional_text(row, field_name))
        for field_name in _INTEGER_FIELDS:
            object.__setattr__(
                receipt,
                field_name,
                _required_integer(row, field_name),
            )
        for field_name in _DATETIME_FIELDS:
            object.__setattr__(
                receipt,
                field_name,
                _required_datetime(row, field_name),
            )
        object.__setattr__(
            receipt,
            "outcome",
            AlpacaPaperAuthenticatedLookupOutcome(_required_text(row, "outcome")),
        )
        object.__setattr__(
            receipt,
            "mismatch_fields",
            _mismatch_fields_from_row(row),
        )
        object.__setattr__(
            receipt,
            "previous_receipt_sha256",
            _optional_text(row, "previous_receipt_sha256"),
        )
        receipt._validate()
        if row["receipt_id"] != receipt.receipt_id:
            raise AlpacaPaperLookupConflict("persisted Alpaca paper lookup receipt ID conflicts")
        if row["canonical_payload"] != receipt.canonical_json:
            raise AlpacaPaperLookupConflict(
                "persisted Alpaca paper lookup canonical_payload conflicts"
            )
        if row["semantic_sha256"] != receipt.semantic_sha256:
            raise AlpacaPaperLookupConflict(
                "persisted Alpaca paper lookup semantic digest conflicts"
            )
        return receipt
    except AlpacaPaperLookupRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperLookupConflict(
            "persisted Alpaca paper lookup receipt is malformed"
        ) from error


def immutable_alpaca_paper_lookup_observation_values(
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one receipt."""

    if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
        raise AlpacaPaperLookupConflict(
            "lookup persistence requires an exact authenticated receipt"
        )
    receipt._validate()
    values: dict[str, Any] = {
        "receipt_id": receipt.receipt_id,
        "outcome": receipt.outcome.value,
        "mismatch_fields_payload": canonical_json_text(receipt.mismatch_fields),
        "previous_receipt_sha256": receipt.previous_receipt_sha256,
        "canonical_payload": receipt.canonical_json,
        "semantic_sha256": receipt.semantic_sha256,
    }
    values.update((field_name, getattr(receipt, field_name)) for field_name in _TEXT_FIELDS)
    values.update(
        (field_name, getattr(receipt, field_name)) for field_name in _OPTIONAL_TEXT_FIELDS
    )
    values.update((field_name, getattr(receipt, field_name)) for field_name in _INTEGER_FIELDS)
    values.update((field_name, getattr(receipt, field_name)) for field_name in _DATETIME_FIELDS)
    return values


def _head_from_row(
    row: AlpacaPaperLookupObservationRow,
) -> _AlpacaPaperLookupObservationHead:
    try:
        head = _AlpacaPaperLookupObservationHead(
            account_id=_required_text(row, "account_id"),
            attempt_id=_required_text(row, "attempt_id"),
            terminal_event_id=_required_text(row, "terminal_event_id"),
            terminal_event_sha256=_required_text(
                row,
                "terminal_event_sha256",
            ),
            last_sequence_number=_required_integer(
                row,
                "last_sequence_number",
            ),
            last_receipt_sha256=_required_text(row, "last_receipt_sha256"),
            last_authenticated_at=_required_datetime(
                row,
                "last_authenticated_at",
            ),
        )
        if (
            head.last_sequence_number <= 0
            or len(head.terminal_event_sha256) != 64
            or len(head.last_receipt_sha256) != 64
        ):
            raise AlpacaPaperLookupConflict("persisted Alpaca paper lookup head is malformed")
        return head
    except AlpacaPaperLookupRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperLookupConflict(
            "persisted Alpaca paper lookup head is malformed"
        ) from error


def _head(
    connection: Connection,
    *,
    account_id: str,
    attempt_id: str,
) -> _AlpacaPaperLookupObservationHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observation_heads).where(
                phase4_alpaca_paper_lookup_observation_heads.c.account_id == account_id,
                phase4_alpaca_paper_lookup_observation_heads.c.attempt_id == attempt_id,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _receipt_by_id(
    connection: Connection,
    receipt_id: str,
) -> AlpacaPaperAuthenticatedLookupReceipt | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observations).where(
                phase4_alpaca_paper_lookup_observations.c.receipt_id == receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_lookup_observation_from_row(row)


def _receipt_by_evidence(
    connection: Connection,
    evidence_sha256: str,
) -> AlpacaPaperAuthenticatedLookupReceipt | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observations).where(
                phase4_alpaca_paper_lookup_observations.c.evidence_sha256 == evidence_sha256
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_lookup_observation_from_row(row)


def _receipt_by_ingress_source(
    connection: Connection,
    ingress_receipt_id: str,
) -> AlpacaPaperAuthenticatedLookupReceipt | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observations).where(
                phase4_alpaca_paper_lookup_observations.c.ingress_receipt_id == ingress_receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_lookup_observation_from_row(row)


def _terminal_receipt(
    connection: Connection,
    head: _AlpacaPaperLookupObservationHead,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    successor_exists = connection.scalar(
        sa.select(
            sa.exists().where(
                phase4_alpaca_paper_lookup_observations.c.account_id == head.account_id,
                phase4_alpaca_paper_lookup_observations.c.attempt_id == head.attempt_id,
                phase4_alpaca_paper_lookup_observations.c.sequence_number
                > head.last_sequence_number,
            )
        )
    )
    if successor_exists:
        raise AlpacaPaperLookupConflict(
            "Alpaca paper lookup head is rolled back from its terminal fact"
        )
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observations).where(
                phase4_alpaca_paper_lookup_observations.c.account_id == head.account_id,
                phase4_alpaca_paper_lookup_observations.c.attempt_id == head.attempt_id,
                phase4_alpaca_paper_lookup_observations.c.sequence_number
                == head.last_sequence_number,
                phase4_alpaca_paper_lookup_observations.c.semantic_sha256
                == head.last_receipt_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise AlpacaPaperLookupConflict(
            "Alpaca paper lookup head references a missing terminal fact"
        )
    receipt = alpaca_paper_lookup_observation_from_row(row)
    if (
        receipt.terminal_event_id != head.terminal_event_id
        or receipt.terminal_event_sha256 != head.terminal_event_sha256
        or receipt.authenticated_at != head.last_authenticated_at
    ):
        raise AlpacaPaperLookupConflict("Alpaca paper lookup head conflicts with its terminal fact")
    return receipt


def _historical_unknown_attempt(
    connection: Connection,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> CanonicalSubmissionAttempt:
    current = load_submission_attempt(connection, receipt.attempt_id)
    if current is None or len(current.events) < receipt.terminal_event_sequence:
        raise AlpacaPaperLookupConflict(
            "lookup receipt references a missing UNKNOWN attempt history"
        )
    try:
        historical = reduce_submission_attempt(
            current.preparation,
            current.events[: receipt.terminal_event_sequence],
        )
    except SubmissionAttemptError as error:
        raise AlpacaPaperLookupConflict("lookup UNKNOWN attempt prefix is not canonical") from error
    event = historical.events[-1]
    if (
        historical.state is not SubmissionAttemptState.UNKNOWN
        or event.state is not SubmissionAttemptState.UNKNOWN
        or historical.preparation.account_id != receipt.account_id
        or historical.attempt_id != receipt.attempt_id
        or historical.semantic_sha256 != receipt.attempt_sha256
        or event.event_id != receipt.terminal_event_id
        or event.semantic_sha256 != receipt.terminal_event_sha256
        or event.sequence_number != receipt.terminal_event_sequence
        or historical.parent_decision_id != receipt.parent_decision_id
        or historical.preparation.reservation_id != receipt.reservation_id
        or historical.preparation.order_id != receipt.order_id
        or historical.preparation.client_order_id != receipt.client_order_id
        or historical.preparation.intent.instrument_id != receipt.instrument_id
        or historical.preparation.intent.symbol != receipt.symbol
        or receipt.pre_attempt_checked_at < historical.as_of
        or receipt.post_attempt_checked_at < historical.as_of
    ):
        raise AlpacaPaperLookupConflict(
            "lookup receipt conflicts with its exact historical UNKNOWN source"
        )
    if any(
        successor.recorded_at < receipt.commit_checked_at
        for successor in current.events[receipt.terminal_event_sequence :]
    ):
        raise AlpacaPaperLookupConflict(
            "lookup receipt commit check conflicts with a later recorded attempt event"
        )
    return historical


def _fence_receipt(
    connection: Connection,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    *,
    phase: str,
) -> AccountFenceReceipt:
    if phase not in {"pre", "post"}:
        raise AssertionError("lookup fence phase must be pre or post")
    lease_sha256 = getattr(receipt, f"{phase}_fence_lease_sha256")
    lease_row = (
        connection.execute(
            sa.select(phase2_account_leases).where(
                phase2_account_leases.c.account_id == receipt.account_id,
                phase2_account_leases.c.fencing_generation == receipt.fence_fencing_generation,
                phase2_account_leases.c.lease_sha256 == lease_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if lease_row is None:
        raise AlpacaPaperLookupConflict(f"lookup {phase}-request fence references a missing lease")
    try:
        lease = account_lease_from_row(lease_row)
        validated_at = getattr(receipt, f"{phase}_fence_validated_at")
        valid_until = getattr(receipt, f"{phase}_fence_valid_until")
        source = _account_fence_receipt(
            fence=lease.fence,
            validated_at=validated_at,
            valid_until=valid_until,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
    except (TypeError, ValueError, AccountCoordinatorError) as error:
        raise AlpacaPaperLookupConflict(
            f"lookup {phase}-request fence source is malformed"
        ) from error
    if (
        lease.account_id != receipt.account_id
        or lease.owner_id != receipt.fence_owner_id
        or lease.lease_id != receipt.fence_lease_id
        or lease.fencing_generation != receipt.fence_fencing_generation
        or validated_at < lease.heartbeat_at
        or valid_until != lease.expires_at
        or lease.fence.semantic_sha256 != receipt.fence_sha256
        or lease.policy_sha256 != receipt.fence_policy_sha256
        or source.semantic_sha256 != getattr(receipt, f"{phase}_fence_receipt_sha256")
    ):
        raise AlpacaPaperLookupConflict(
            f"lookup {phase}-request fence conflicts with its lease source"
        )
    _authenticate_fence_position_at(
        connection,
        source,
        checked_at=validated_at,
    )
    return source


def _authenticate_lease_history(
    connection: Connection,
    *,
    account_id: str,
    expected_policy_sha256: str,
) -> tuple[tuple[AccountLease, ...], tuple[AccountLeaseRelease, ...]]:
    head_row = (
        connection.execute(
            sa.select(phase2_account_lease_heads).where(
                phase2_account_lease_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if head_row is None:
        raise AlpacaPaperLookupConflict("lookup recovery fence lacks a durable lease head")
    try:
        head = _lease_head_from_row(head_row)
        leases = tuple(
            account_lease_from_row(row)
            for row in connection.execute(
                sa.select(phase2_account_leases).where(
                    phase2_account_leases.c.account_id == account_id
                )
            ).mappings()
        )
        releases = tuple(
            account_lease_release_from_row(row)
            for row in connection.execute(
                sa.select(phase2_account_lease_releases).where(
                    phase2_account_lease_releases.c.account_id == account_id
                )
            ).mappings()
        )
        verify_account_lease_history(
            account_id=account_id,
            head=head,
            leases=leases,
            releases=releases,
            expected_policy_sha256=expected_policy_sha256,
        )
    except (TypeError, ValueError, AccountCoordinatorError) as error:
        raise AlpacaPaperLookupConflict("lookup recovery fence history is malformed") from error
    return leases, releases


def _authenticate_fence_position_at(
    connection: Connection,
    source: AccountFenceReceipt,
    *,
    checked_at: datetime,
) -> None:
    leases, releases = _authenticate_lease_history(
        connection,
        account_id=source.fence.account_id,
        expected_policy_sha256=source.policy_sha256,
    )
    matches = tuple(lease for lease in leases if lease.semantic_sha256 == source.lease_sha256)
    if len(matches) != 1:
        raise AlpacaPaperLookupConflict(
            "lookup fence receipt is not a unique durable lease revision"
        )
    lease = matches[0]
    if (
        lease.fence != source.fence
        or lease.policy_sha256 != source.policy_sha256
        or checked_at < lease.heartbeat_at
        or checked_at >= lease.expires_at
        or any(
            candidate.fencing_generation == lease.fencing_generation
            and candidate.revision_number > lease.revision_number
            and candidate.heartbeat_at < checked_at
            for candidate in leases
        )
        or any(
            candidate.fencing_generation > lease.fencing_generation
            and candidate.acquired_at < checked_at
            for candidate in leases
        )
        or any(
            release.fence.fencing_generation == lease.fencing_generation
            and release.released_at < checked_at
            for release in releases
        )
    ):
        raise AlpacaPaperLookupConflict(
            "lookup fence receipt was not current at its retained check time"
        )


def _authenticate_ingress_source(
    connection: Connection,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> BrokerIngressReceipt:
    ingress = _broker_ingress_receipt_by_id(
        connection,
        receipt.ingress_receipt_id,
    )
    if ingress is None:
        raise AlpacaPaperLookupConflict("lookup receipt references a missing raw ingress receipt")
    if (
        ingress.delivery.account_id != receipt.account_id
        or ingress.semantic_sha256 != receipt.ingress_receipt_sha256
    ):
        raise AlpacaPaperLookupConflict("lookup receipt conflicts with its raw ingress receipt")
    _authenticate_ingress_receipt_position(connection, ingress)
    return ingress


def _authenticate_durable_sources_unchecked(
    connection: Connection,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> None:
    attempt = _historical_unknown_attempt(connection, receipt)
    for checked_at, expected_digest in (
        (
            receipt.pre_attempt_checked_at,
            receipt.pre_attempt_freshness_sha256,
        ),
        (
            receipt.post_attempt_checked_at,
            receipt.post_attempt_freshness_sha256,
        ),
    ):
        unknown_freshness = _alpaca_paper_unknown_attempt_freshness_receipt(
            attempt,
            checked_at=checked_at,
        )
        if unknown_freshness.semantic_sha256 != expected_digest:
            raise AlpacaPaperLookupConflict(
                "lookup receipt conflicts with UNKNOWN-at-send evidence"
            )

    account_binding = _account_binding_by_id(
        connection,
        receipt.account_binding_id,
    )
    if account_binding is None:
        raise AlpacaPaperLookupConflict("lookup receipt references a missing account binding")
    _authenticate_account_binding_position(connection, account_binding)
    _authenticate_account_binding_sources(connection, account_binding)
    successor_binding_before_commit = connection.scalar(
        sa.select(phase4_alpaca_paper_account_bindings.c.binding_id)
        .where(
            phase4_alpaca_paper_account_bindings.c.account_id == account_binding.account_id,
            phase4_alpaca_paper_account_bindings.c.sequence_number
            > account_binding.sequence_number,
            phase4_alpaca_paper_account_bindings.c.qualified_at < receipt.commit_checked_at,
        )
        .limit(1)
    )
    if successor_binding_before_commit is not None:
        raise AlpacaPaperLookupConflict(
            "lookup receipt account identity was not terminal at durable commit"
        )
    if (
        account_binding.account_id != receipt.account_id
        or account_binding.semantic_sha256 != receipt.account_binding_sha256
        or account_binding.expected_provider_account_id != receipt.expected_provider_account_id
        or account_binding.credential_reference_sha256 != receipt.credential_reference_sha256
        or account_binding.secret_ref != receipt.secret_ref
        or account_binding.secret_version != receipt.secret_version
    ):
        raise AlpacaPaperLookupConflict("lookup receipt conflicts with its account-binding source")
    for checked_at, expected_digest in (
        (
            receipt.pre_account_identity_checked_at,
            receipt.pre_account_identity_sha256,
        ),
        (
            receipt.post_account_identity_checked_at,
            receipt.post_account_identity_sha256,
        ),
    ):
        identity = _alpaca_paper_account_identity_continuity_receipt(
            account_binding,
            checked_at=checked_at,
        )
        if identity.semantic_sha256 != expected_digest:
            raise AlpacaPaperLookupConflict(
                "lookup receipt conflicts with account-identity continuity"
            )

    credential_reference = AlpacaPaperCredentialReference(
        account_id=receipt.account_id,
        expected_provider_account_id=receipt.expected_provider_account_id,
        secret_ref=receipt.secret_ref,
        secret_version=receipt.secret_version,
    )
    credential_resolution = AlpacaPaperCredentialResolutionReceipt(
        reference=credential_reference,
        resolver_id=receipt.resolver_id,
        resolver_version=receipt.resolver_version,
        started_at=receipt.credential_resolution_started_at,
        resolved_at=receipt.resolved_at,
        valid_until=receipt.credential_resolution_valid_until,
    )
    security_reference = AlpacaPaperSecurityReference(
        credential_reference=credential_reference,
        instrument_id=receipt.instrument_id,
        symbol=receipt.symbol,
        expected_provider_asset_id=receipt.expected_provider_asset_id,
    )
    submission = create_alpaca_paper_submission_description(attempt.preparation.intent)
    description = create_alpaca_client_order_lookup_description(
        account_id=receipt.account_id,
        submission=submission,
    )
    if (
        submission.request != attempt.preparation.request
        or submission.semantic_sha256 != receipt.submission_sha256
        or description.semantic_sha256 != receipt.description_sha256
        or credential_reference.semantic_sha256 != receipt.credential_reference_sha256
        or credential_resolution.semantic_sha256 != receipt.credential_resolution_sha256
        or security_reference.semantic_sha256 != receipt.security_reference_sha256
        or security_reference.capability_sha256 != receipt.capability_sha256
        or not credential_resolution.is_fresh(receipt.request_started_at)
        or not credential_resolution.is_fresh(receipt.received_at)
    ):
        raise AlpacaPaperLookupConflict(
            "lookup receipt conflicts with its immutable request description"
        )

    permit_record = _broker_request_permit_by_id(connection, receipt.permit_id)
    if permit_record is None:
        raise AlpacaPaperLookupConflict(
            "lookup receipt references a missing durable request permit"
        )
    _authenticate_permit_position(connection, permit_record)
    permit = permit_record.permit
    policy = permit_record.policy
    demand = permit_record.demand
    expected_demand = create_alpaca_paper_unknown_lookup_demand(
        security_reference=security_reference,
        account_binding=account_binding,
        attempt=attempt,
        description=description,
        idempotency_key=demand.idempotency_key,
        requested_at=demand.requested_at,
    )
    if (
        policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY
        or policy.semantic_sha256 != receipt.policy_sha256
        or demand != expected_demand
        or demand.demand_id != receipt.demand_id
        or demand.semantic_sha256 != receipt.demand_sha256
        or permit.account_id != receipt.account_id
        or permit.semantic_sha256 != receipt.permit_sha256
        or permit.demand_sha256 != demand.semantic_sha256
        or demand.requested_at != receipt.requested_at
        or not (
            credential_resolution.resolved_at <= permit.issued_at <= receipt.pre_fence_validated_at
        )
    ):
        raise AlpacaPaperLookupConflict("lookup receipt conflicts with protected request admission")
    permit_freshness = _broker_request_permit_freshness_receipt(
        permit=permit,
        policy=policy,
        demand=demand,
        checked_at=receipt.permit_checked_at,
    )
    if permit_freshness.semantic_sha256 != receipt.permit_freshness_sha256:
        raise AlpacaPaperLookupConflict("lookup receipt conflicts with durable permit freshness")
    try:
        require_fresh_broker_request_permit(
            permit=permit,
            policy=policy,
            demand=demand,
            checked_at=receipt.request_started_at,
        )
        require_fresh_broker_request_permit(
            permit=permit,
            policy=policy,
            demand=demand,
            checked_at=receipt.received_at,
        )
    except ValueError as error:
        raise AlpacaPaperLookupConflict(
            "lookup permit was stale during retained transport"
        ) from error

    pre_fence = _fence_receipt(connection, receipt, phase="pre")
    post_fence = _fence_receipt(connection, receipt, phase="post")
    if pre_fence.fence != post_fence.fence or pre_fence.policy_sha256 != post_fence.policy_sha256:
        raise AlpacaPaperLookupConflict("lookup recovery fence changed during retained transport")
    _authenticate_fence_position_at(
        connection,
        post_fence,
        checked_at=receipt.commit_checked_at,
    )
    request = AlpacaPaperLookupTransportRequest(
        description=description,
        credential_reference_sha256=credential_reference.semantic_sha256,
        security_reference_sha256=security_reference.semantic_sha256,
        attempt_sha256=attempt.semantic_sha256,
        unknown_attempt_freshness_sha256=(receipt.pre_attempt_freshness_sha256),
        account_binding_sha256=account_binding.semantic_sha256,
        account_identity_sha256=receipt.pre_account_identity_sha256,
        demand_sha256=demand.semantic_sha256,
        permit_sha256=permit.semantic_sha256,
        permit_freshness_sha256=permit_freshness.semantic_sha256,
        fence_receipt_sha256=pre_fence.semantic_sha256,
        started_at=receipt.request_started_at,
    )
    if request.semantic_sha256 != receipt.transport_request_sha256:
        raise AlpacaPaperLookupConflict(
            "lookup transport request digest conflicts with its sources"
        )

    ingress = _authenticate_ingress_source(connection, receipt)
    delivery = ingress.delivery
    if (
        delivery.provider_id != ALPACA_PAPER_ADAPTER_ID
        or delivery.adapter_version != ALPACA_PAPER_ADAPTER_VERSION
        or delivery.environment != "paper"
        or delivery.channel != ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL
        or delivery.operation != ALPACA_PAPER_LOOKUP_INGRESS_OPERATION
        or delivery.correlation_sha256 != description.semantic_sha256
        or delivery.transport_status != receipt.http_status
        or delivery.provider_request_id != receipt.provider_request_id
        or delivery.received_at != receipt.received_at
        or delivery.recorded_at != receipt.raw_recorded_at
    ):
        raise AlpacaPaperLookupConflict(
            "lookup raw ingress receipt conflicts with the fixed transport"
        )
    response = AlpacaPaperLookupTransportResponse(
        request_sha256=request.semantic_sha256,
        transport_id=ALPACA_PAPER_LOOKUP_TRANSPORT_ID,
        transport_version=ALPACA_PAPER_LOOKUP_TRANSPORT_VERSION,
        http_status=receipt.http_status,
        provider_request_id=delivery.provider_request_id,
        media_type=delivery.media_type,
        response_body=delivery.body,
    )
    if (
        response.semantic_sha256 != receipt.transport_response_sha256
        or response.media_type != ALPACA_PAPER_LOOKUP_ACCEPT_MEDIA_TYPE
        or response.provider_request_id is None
    ):
        raise AlpacaPaperLookupConflict(
            "lookup transport response digest conflicts with raw ingress"
        )
    observation = decode_alpaca_client_order_lookup_response(
        description,
        http_status=receipt.http_status,
        provider_request_id=receipt.provider_request_id,
        response_body=delivery.body,
        received_at=receipt.received_at,
    )
    PersistedAlpacaClientOrderLookupObservation(
        receipt=ingress,
        observation=observation,
    )
    order = observation.order
    if (
        observation.semantic_sha256 != receipt.observation_sha256
        or _lookup_outcome(observation, security_reference) is not receipt.outcome
        or observation.mismatch_fields != receipt.mismatch_fields
        or (None if order is None else order.provider_order_id) != receipt.provider_order_id
        or (None if order is None else order.status.value) != receipt.provider_order_status
        or (None if order is None else order.asset_id) != receipt.observed_provider_asset_id
    ):
        raise AlpacaPaperLookupConflict("lookup receipt conflicts with its decoded raw observation")

    evidence_sha256 = hashlib.sha256(
        canonical_json_bytes(
            (
                ALPACA_PAPER_LOOKUP_RUNTIME_CONTRACT_VERSION,
                "authenticated_lookup_evidence",
                receipt.security_reference_sha256,
                receipt.credential_resolution_sha256,
                receipt.attempt_sha256,
                receipt.pre_attempt_freshness_sha256,
                receipt.account_binding_sha256,
                receipt.pre_account_identity_sha256,
                receipt.description_sha256,
                receipt.policy_sha256,
                receipt.demand_sha256,
                receipt.permit_sha256,
                receipt.permit_freshness_sha256,
                receipt.pre_fence_receipt_sha256,
                receipt.transport_request_sha256,
                receipt.transport_response_sha256,
                receipt.ingress_receipt_sha256,
                receipt.observation_sha256,
                receipt.post_fence_receipt_sha256,
                receipt.post_attempt_freshness_sha256,
                receipt.post_account_identity_sha256,
                receipt.outcome,
                receipt.authenticated_at,
            )
        )
    ).hexdigest()
    if evidence_sha256 != receipt.evidence_sha256:
        raise AlpacaPaperLookupConflict(
            "lookup evidence digest conflicts with authenticated sources"
        )


def _authenticate_durable_sources(
    connection: Connection,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> None:
    try:
        _authenticate_durable_sources_unchecked(connection, receipt)
    except AlpacaPaperLookupRuntimeError:
        raise
    except Exception:
        raise AlpacaPaperLookupConflict(
            "durable Alpaca paper lookup sources failed with sanitized diagnostics"
        ) from None


def _validate_stream(
    connection: Connection,
    *,
    account_id: str,
    attempt_id: str,
    receipts: Iterable[AlpacaPaperAuthenticatedLookupReceipt],
    head: _AlpacaPaperLookupObservationHead | None,
) -> None:
    previous: AlpacaPaperAuthenticatedLookupReceipt | None = None
    count = 0
    for count, receipt in enumerate(receipts, start=1):
        if (
            receipt.account_id != account_id
            or receipt.attempt_id != attempt_id
            or receipt.sequence_number != count
        ):
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup history is not a contiguous attempt-local sequence"
            )
        if receipt.previous_receipt_sha256 != (
            None if previous is None else previous.semantic_sha256
        ):
            raise AlpacaPaperLookupConflict("Alpaca paper lookup predecessor chain conflicts")
        if previous is not None and (
            receipt.authenticated_at < previous.authenticated_at
            or receipt.commit_checked_at < previous.commit_checked_at
            or receipt.terminal_event_id != previous.terminal_event_id
            or receipt.terminal_event_sha256 != previous.terminal_event_sha256
        ):
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup history regressed or changed UNKNOWN identity"
            )
        _authenticate_durable_sources(connection, receipt)
        previous = receipt
    if count == 0:
        if head is not None:
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup head exists without durable observations"
            )
        return
    if head is None or previous is None:
        raise AlpacaPaperLookupConflict(
            "Alpaca paper lookup observations exist without a durable head"
        )
    if (
        head.account_id != account_id
        or head.attempt_id != attempt_id
        or head.terminal_event_id != previous.terminal_event_id
        or head.terminal_event_sha256 != previous.terminal_event_sha256
        or head.last_sequence_number != previous.sequence_number
        or head.last_receipt_sha256 != previous.semantic_sha256
        or head.last_authenticated_at != previous.authenticated_at
    ):
        raise AlpacaPaperLookupConflict("Alpaca paper lookup head conflicts with terminal history")


def _history(
    connection: Connection,
    *,
    account_id: str,
    attempt_id: str,
) -> tuple[AlpacaPaperAuthenticatedLookupReceipt, ...]:
    rows = (
        connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observations)
            .where(
                phase4_alpaca_paper_lookup_observations.c.account_id == account_id,
                phase4_alpaca_paper_lookup_observations.c.attempt_id == attempt_id,
            )
            .order_by(phase4_alpaca_paper_lookup_observations.c.sequence_number)
        )
        .mappings()
        .all()
    )
    receipts = tuple(alpaca_paper_lookup_observation_from_row(row) for row in rows)
    _validate_stream(
        connection,
        account_id=account_id,
        attempt_id=attempt_id,
        receipts=receipts,
        head=_head(
            connection,
            account_id=account_id,
            attempt_id=attempt_id,
        ),
    )
    return receipts


def _verify_alpaca_paper_lookup_observation_integrity(
    connection: Connection,
) -> None:
    observation_without_head = connection.scalar(
        sa.select(phase4_alpaca_paper_lookup_observations.c.receipt_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_lookup_observation_heads.c.account_id
                    == phase4_alpaca_paper_lookup_observations.c.account_id,
                    phase4_alpaca_paper_lookup_observation_heads.c.attempt_id
                    == phase4_alpaca_paper_lookup_observations.c.attempt_id,
                )
            )
        )
        .limit(1)
    )
    if observation_without_head is not None:
        raise AlpacaPaperLookupConflict(
            "Alpaca paper lookup observations exist without durable heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_alpaca_paper_lookup_observation_heads)
        .order_by(
            phase4_alpaca_paper_lookup_observation_heads.c.account_id,
            phase4_alpaca_paper_lookup_observation_heads.c.attempt_id,
        )
        .execution_options(yield_per=128)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        rows = connection.execute(
            sa.select(phase4_alpaca_paper_lookup_observations)
            .where(
                phase4_alpaca_paper_lookup_observations.c.account_id == head.account_id,
                phase4_alpaca_paper_lookup_observations.c.attempt_id == head.attempt_id,
            )
            .order_by(phase4_alpaca_paper_lookup_observations.c.sequence_number)
            .execution_options(yield_per=128)
        ).mappings()
        _validate_stream(
            connection,
            account_id=head.account_id,
            attempt_id=head.attempt_id,
            receipts=(alpaca_paper_lookup_observation_from_row(row) for row in rows),
            head=head,
        )


def verify_alpaca_paper_lookup_observation_integrity(engine: Engine) -> None:
    """Authenticate every durable lookup chain in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperLookupConflict("Alpaca paper lookup verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperLookupConflict(
            f"Alpaca paper lookup verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_lookup_observation_integrity(connection)


def _require_identifier(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperLookupConflict(
            f"Alpaca paper lookup {field_name} must be bounded trimmed text"
        )
    return value


class SqlAlpacaPaperLookupObservationRepository:
    """Append authenticated historical lookup evidence under the account lock."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperLookupConflict(
                "SQL Alpaca paper lookup observations require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperLookupConflict(
                "SQL Alpaca paper lookup observations do not support "
                f"dialect {engine.dialect.name!r}"
            )
        if not callable(
            getattr(
                coordinator,
                "revalidate_for_commit_in_transaction",
                None,
            )
        ):
            raise AlpacaPaperLookupConflict(
                "SQL Alpaca paper lookup observations require a SQL fence validator"
            )
        self._engine = engine
        self._coordinator = coordinator

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared SQL engine for process-local composition checks."""

        return id(self._engine)

    def _commit_fence(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        try:
            receipt = self._coordinator.revalidate_for_commit_in_transaction(
                connection,
                fence,
            )
            if type(receipt) is not AccountFenceReceipt:
                raise TypeError("non-canonical commit fence receipt")
            receipt._validate()
            return receipt
        except Exception:
            raise AlpacaPaperLookupConflict(
                "lookup commit fence validation failed with sanitized diagnostics"
            ) from None

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedLookupEvidence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        """Persist one authenticated lookup without mutating submission state."""

        if type(evidence) is not AlpacaPaperAuthenticatedLookupEvidence:
            raise AlpacaPaperLookupConflict(
                "lookup recording requires exact authenticated evidence"
            )
        evidence._validate()
        account_id = evidence.attempt.preparation.account_id
        attempt_id = evidence.attempt.attempt_id
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, account_id)
                history = _history(
                    connection,
                    account_id=account_id,
                    attempt_id=attempt_id,
                )
                previous = None if not history else history[-1]
                existing = _receipt_by_evidence(
                    connection,
                    evidence.semantic_sha256,
                )
                if existing is not None:
                    if existing not in history:
                        raise AlpacaPaperLookupConflict(
                            "lookup evidence exists outside authenticated history"
                        )
                    expected = _alpaca_paper_authenticated_lookup_receipt(
                        evidence,
                        commit_checked_at=existing.commit_checked_at,
                        sequence_number=existing.sequence_number,
                        previous_receipt_sha256=(existing.previous_receipt_sha256),
                    )
                    if existing != expected:
                        raise AlpacaPaperLookupConflict(
                            "lookup evidence identity conflicts with durable content"
                        )
                    _authenticate_durable_sources(connection, existing)
                    return existing

                terminal_unknown = _authenticate_terminal_unknown(
                    connection,
                    evidence.attempt,
                    checked_at=evidence.post_attempt_freshness.checked_at,
                )
                if terminal_unknown != evidence.post_attempt_freshness:
                    raise AlpacaPaperLookupConflict("lookup attempt changed before durable commit")
                account_binding = _account_binding_by_id(
                    connection,
                    evidence.account_binding.binding_id,
                )
                if account_binding is None or account_binding != evidence.account_binding:
                    raise AlpacaPaperLookupConflict(
                        "lookup account binding changed before durable commit"
                    )
                account_head = _authenticate_account_binding_position(
                    connection,
                    account_binding,
                )
                if _terminal_account_binding(connection, account_head) != account_binding:
                    raise AlpacaPaperLookupConflict(
                        "lookup account binding is no longer terminal at commit"
                    )
                _authenticate_account_binding_sources(connection, account_binding)
                account_identity = _alpaca_paper_account_identity_continuity_receipt(
                    account_binding,
                    checked_at=evidence.post_account_identity.checked_at,
                )
                if account_identity != evidence.post_account_identity:
                    raise AlpacaPaperLookupConflict(
                        "lookup account identity changed before durable commit"
                    )
                commit_fence = self._commit_fence(
                    connection,
                    evidence.post_fence_receipt.fence,
                )
                expected_commit_fence = _account_fence_receipt(
                    fence=evidence.post_fence_receipt.fence,
                    validated_at=commit_fence.validated_at,
                    valid_until=evidence.post_fence_receipt.valid_until,
                    policy_sha256=evidence.post_fence_receipt.policy_sha256,
                    lease_sha256=evidence.post_fence_receipt.lease_sha256,
                )
                if commit_fence != expected_commit_fence:
                    raise AlpacaPaperLookupConflict(
                        "lookup recovery fence changed before durable append"
                    )
                commit_checked_at = commit_fence.validated_at
                if commit_checked_at < evidence.authenticated_at:
                    raise AlpacaPaperLookupConflict(
                        "lookup commit fence clock regressed behind authentication"
                    )
                receipt = _alpaca_paper_authenticated_lookup_receipt(
                    evidence,
                    commit_checked_at=commit_checked_at,
                    sequence_number=(1 if previous is None else previous.sequence_number + 1),
                    previous_receipt_sha256=(
                        None if previous is None else previous.semantic_sha256
                    ),
                )
                post_fence = _fence_receipt(
                    connection,
                    receipt,
                    phase="post",
                )

                if previous is not None and (
                    evidence.authenticated_at < previous.authenticated_at
                    or commit_checked_at < previous.commit_checked_at
                    or evidence.attempt.events[-1].event_id != previous.terminal_event_id
                    or evidence.attempt.events[-1].semantic_sha256 != previous.terminal_event_sha256
                ):
                    raise AlpacaPaperLookupConflict(
                        "lookup history regressed or changed UNKNOWN identity"
                    )
                _authenticate_durable_sources(connection, receipt)
                values = immutable_alpaca_paper_lookup_observation_values(receipt)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_lookup_observations).values(**values)
                    )
                except IntegrityError as error:
                    raise AlpacaPaperLookupConflict(
                        "Alpaca paper lookup conflicts with durable history"
                    ) from error

                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_alpaca_paper_lookup_observation_heads).values(
                                account_id=receipt.account_id,
                                attempt_id=receipt.attempt_id,
                                terminal_event_id=receipt.terminal_event_id,
                                terminal_event_sha256=(receipt.terminal_event_sha256),
                                last_sequence_number=receipt.sequence_number,
                                last_receipt_sha256=receipt.semantic_sha256,
                                last_authenticated_at=receipt.authenticated_at,
                            )
                        )
                    except IntegrityError as error:
                        raise AlpacaPaperLookupConflict(
                            "Alpaca paper lookup head conflicts with history"
                        ) from error
                else:
                    updated = connection.execute(
                        sa.update(phase4_alpaca_paper_lookup_observation_heads)
                        .where(
                            phase4_alpaca_paper_lookup_observation_heads.c.account_id
                            == previous.account_id,
                            phase4_alpaca_paper_lookup_observation_heads.c.attempt_id
                            == previous.attempt_id,
                            phase4_alpaca_paper_lookup_observation_heads.c.terminal_event_id
                            == previous.terminal_event_id,
                            phase4_alpaca_paper_lookup_observation_heads.c.terminal_event_sha256
                            == previous.terminal_event_sha256,
                            phase4_alpaca_paper_lookup_observation_heads.c.last_sequence_number
                            == previous.sequence_number,
                            phase4_alpaca_paper_lookup_observation_heads.c.last_receipt_sha256
                            == previous.semantic_sha256,
                            phase4_alpaca_paper_lookup_observation_heads.c.last_authenticated_at
                            == previous.authenticated_at,
                        )
                        .values(
                            last_sequence_number=receipt.sequence_number,
                            last_receipt_sha256=receipt.semantic_sha256,
                            last_authenticated_at=receipt.authenticated_at,
                        )
                    )
                    if updated.rowcount != 1:
                        raise AlpacaPaperLookupConflict(
                            "Alpaca paper lookup head changed during append"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_alpaca_paper_lookup_observations).where(
                            phase4_alpaca_paper_lookup_observations.c.receipt_id
                            == receipt.receipt_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = alpaca_paper_lookup_observation_from_row(row)
                if persisted != receipt:
                    raise AlpacaPaperLookupConflict("Alpaca paper lookup failed exact SQL readback")
                assert_immutable(
                    phase4_alpaca_paper_lookup_observations,
                    receipt.receipt_id,
                    row,
                    values,
                )
                persisted_head = _head(
                    connection,
                    account_id=account_id,
                    attempt_id=attempt_id,
                )
                if (
                    persisted_head is None
                    or _terminal_receipt(connection, persisted_head) != receipt
                ):
                    raise AlpacaPaperLookupConflict(
                        "Alpaca paper lookup head failed exact SQL readback"
                    )
                final_commit_fence = self._commit_fence(
                    connection,
                    post_fence.fence,
                )
                expected_final_commit_fence = _account_fence_receipt(
                    fence=post_fence.fence,
                    validated_at=final_commit_fence.validated_at,
                    valid_until=post_fence.valid_until,
                    policy_sha256=post_fence.policy_sha256,
                    lease_sha256=post_fence.lease_sha256,
                )
                if (
                    final_commit_fence.validated_at < commit_checked_at
                    or final_commit_fence != expected_final_commit_fence
                ):
                    raise AlpacaPaperLookupConflict(
                        "lookup recovery fence changed before final durable commit"
                    )
                return persisted
        except AlpacaPaperLookupRuntimeError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperContractError,
            BrokerIngressError,
            BrokerRequestBudgetError,
            ImmutableFactConflict,
            SubmissionAttemptPersistenceError,
        ):
            raise AlpacaPaperLookupConflict(
                "durable Alpaca paper lookup authentication failed"
            ) from None

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt | None:
        """Load one fully authenticated historical lookup receipt."""

        if type(receipt_id) is not str or len(receipt_id) != 36:
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup receipt ID must be a canonical UUID"
            )
        try:
            parsed = UUID(receipt_id)
        except ValueError as error:
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup receipt ID must be a canonical UUID"
            ) from error
        if str(parsed) != receipt_id:
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup receipt ID must be a canonical UUID"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            receipt = _receipt_by_id(connection, receipt_id)
            if receipt is None:
                return None
            history = _history(
                connection,
                account_id=receipt.account_id,
                attempt_id=receipt.attempt_id,
            )
            if receipt not in history:
                raise AlpacaPaperLookupConflict("lookup receipt exists outside its durable head")
            return receipt

    def history(
        self,
        account_id: str,
        attempt_id: str,
    ) -> tuple[AlpacaPaperAuthenticatedLookupReceipt, ...]:
        """Return one authenticated attempt-local observation chain."""

        account_id = _require_identifier(account_id, "account ID")
        attempt_id = _require_identifier(attempt_id, "attempt ID")
        with _repeatable_read_transaction(self._engine) as connection:
            return _history(
                connection,
                account_id=account_id,
                attempt_id=attempt_id,
            )

    def load_by_ingress_receipt_id(
        self,
        ingress_receipt_id: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt | None:
        """Load an authenticated lookup selected by its exact raw-ingress source."""

        if (
            type(ingress_receipt_id) is not str
            or len(ingress_receipt_id) != 64
            or any(character not in "0123456789abcdef" for character in ingress_receipt_id)
        ):
            raise AlpacaPaperLookupConflict(
                "Alpaca paper lookup ingress receipt ID must be a lowercase SHA-256 digest"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            receipt = _receipt_by_ingress_source(
                connection,
                ingress_receipt_id,
            )
            if receipt is None:
                return None
            history = _history(
                connection,
                account_id=receipt.account_id,
                attempt_id=receipt.attempt_id,
            )
            if receipt not in history:
                raise AlpacaPaperLookupConflict(
                    "lookup ingress source exists outside its durable head"
                )
            return receipt


__all__ = [
    "SqlAlpacaPaperLookupObservationRepository",
    "alpaca_paper_lookup_observation_from_row",
    "immutable_alpaca_paper_lookup_observation_values",
    "verify_alpaca_paper_lookup_observation_integrity",
]
