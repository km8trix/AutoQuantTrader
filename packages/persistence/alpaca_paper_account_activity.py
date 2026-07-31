"""Restart-safe persistence for authenticated Alpaca paper order pages."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_CAPABILITIES,
)
from packages.adapters.broker.alpaca_paper_account_activities import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
    AlpacaPaperAccountActivityPageDescription,
    AlpacaPaperAccountActivityPlan,
    PersistedAlpacaPaperAccountActivityPage,
    decode_alpaca_paper_account_activity_page,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION,
    AlpacaPaperAccountActivityConflict,
    AlpacaPaperAccountActivityPagePreparationReceipt,
    AlpacaPaperAccountActivityRuntimeError,
    AlpacaPaperAccountActivityTransportRequest,
    AlpacaPaperAccountActivityTransportResponse,
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPageEvidence,
    AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    AlpacaPaperAuthenticatedAccountActivityPrefix,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
    _alpaca_paper_account_activity_page_preparation_receipt,
    _alpaca_paper_authenticated_account_activity_page_evidence,
    _alpaca_paper_authenticated_account_activity_page_receipt,
    _alpaca_paper_authenticated_account_activity_prefix,
    _alpaca_paper_authenticated_account_activity_traversal_state,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionReceipt,
    _alpaca_paper_account_identity_continuity_receipt,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.broker_ingress import BrokerIngressError, BrokerIngressReceipt
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetError,
    _broker_request_permit_freshness_receipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.models import require_utc
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
    lock_account_capacity_serialization,
)
from packages.persistence.alpaca_paper_account_binding import (
    _authenticate_binding_position,
    _binding_by_id,
    _terminal_binding,
)
from packages.persistence.alpaca_paper_account_binding import (
    _authenticate_durable_sources as _authenticate_account_binding_sources,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_fence_position_at,
)
from packages.persistence.broker_ingress import (
    _authenticate_receipt_position as _authenticate_ingress_position,
)
from packages.persistence.broker_ingress import (
    _receipt_by_id as _ingress_receipt_by_id,
)
from packages.persistence.broker_request_budget import (
    _authenticate_record_position as _authenticate_permit_position,
)
from packages.persistence.broker_request_budget import (
    _PersistedBrokerRequestPermit,
)
from packages.persistence.broker_request_budget import (
    _record_by_id as _permit_record_by_id,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
    same_value,
)
from packages.persistence.schema import (
    phase2_account_leases,
    phase4_alpaca_paper_account_activity_heads,
    phase4_alpaca_paper_account_activity_pages,
    phase4_alpaca_paper_account_activity_plans,
    phase4_alpaca_paper_account_activity_preparations,
    phase4_alpaca_paper_account_bindings,
)

ALPACA_PAPER_ACCOUNT_ACTIVITY_PERSISTENCE_CONTRACT_VERSION = (
    "phase4ae-authenticated-account-activity-persistence-v2"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

AccountActivityRow = Mapping[str, object] | RowMapping


class AlpacaPaperAccountActivityPersistenceError(AlpacaPaperAccountActivityRuntimeError):
    """Durable authenticated account-activity history is unavailable."""


class AlpacaPaperAccountActivityPersistenceConflict(
    AlpacaPaperAccountActivityConflict,
    AlpacaPaperAccountActivityPersistenceError,
):
    """Durable account-activity state conflicts with exact source evidence."""


class SqlAccountFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


class _AccountActivityHeadState(StrEnum):
    ACTIVE = "active"
    CURSOR_EXHAUSTED_UNISOLATED = "cursor_exhausted_unisolated"
    BOUNDED_TRUNCATED = "bounded_truncated"
    STALLED = "stalled"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAccountActivityPersistenceError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAccountActivityPersistenceError(str(error)) from error
    return value


def _required_text(row: AccountActivityRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be text"
        )
    return value


def _optional_text(row: AccountActivityRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be text or null"
        )
    return value


def _required_integer(row: AccountActivityRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be an integer"
        )
    return value


def _optional_integer(
    row: AccountActivityRow,
    field_name: str,
) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be an integer or null"
        )
    return value


def _required_bool(row: AccountActivityRow, field_name: str) -> bool:
    value = row[field_name]
    if type(value) is not bool:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be a boolean"
        )
    return value


def _required_datetime(
    row: AccountActivityRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _optional_datetime(
    row: AccountActivityRow,
    field_name: str,
) -> datetime | None:
    value = row[field_name]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"persisted account activity {field_name} must be a datetime or null"
        )
    return as_aware_utc(value)


def _canonical_uuid(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise AlpacaPaperAccountActivityPersistenceError(f"{field_name} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise AlpacaPaperAccountActivityPersistenceError(
            f"{field_name} must be a canonical UUID"
        ) from error
    if str(parsed) != value:
        raise AlpacaPaperAccountActivityPersistenceError(f"{field_name} must be a canonical UUID")
    return value


def _traversal_profile_sha256(plan: AlpacaPaperAccountActivityPlan) -> str:
    plan.__post_init__()
    return _semantic_sha256(
        (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_PERSISTENCE_CONTRACT_VERSION,
            "traversal_profile",
            ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
            ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            plan.page_size,
            plan.maximum_pages,
            plan.maximum_items,
            "FILL",
            "asc",
            "last_activity_id",
        )
    )


def immutable_alpaca_paper_account_activity_plan_values(
    plan: AlpacaPaperAccountActivityPlan,
    *,
    prepared_at: datetime,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one traversal plan."""

    if type(plan) is not AlpacaPaperAccountActivityPlan:
        raise AlpacaPaperAccountActivityPersistenceError(
            "account activity persistence requires an exact plan"
        )
    plan.__post_init__()
    prepared_at = _require_utc(prepared_at, "account activity plan prepared_at")
    return {
        "capture_id": plan.capture_id,
        "account_id": plan.account_id,
        "capture_idempotency_key": plan.capture_idempotency_key,
        "capability_sha256": ALPACA_PAPER_CAPABILITIES.semantic_sha256,
        "traversal_profile_sha256": _traversal_profile_sha256(plan),
        "page_size": plan.page_size,
        "maximum_pages": plan.maximum_pages,
        "maximum_items": plan.maximum_items,
        "prepared_at": prepared_at,
        "canonical_payload": canonical_json_text(plan._semantic_material()),
        "semantic_sha256": plan.semantic_sha256,
    }


def alpaca_paper_account_activity_plan_from_row(
    row: AccountActivityRow,
) -> AlpacaPaperAccountActivityPlan:
    """Strictly reconstruct one persisted Phase 4AD plan."""

    try:
        plan = AlpacaPaperAccountActivityPlan(
            account_id=_required_text(row, "account_id"),
            capture_idempotency_key=_required_text(
                row,
                "capture_idempotency_key",
            ),
            page_size=_required_integer(row, "page_size"),
            maximum_pages=_required_integer(row, "maximum_pages"),
            maximum_items=_required_integer(row, "maximum_items"),
        )
        if (
            _required_text(row, "capture_id") != plan.capture_id
            or _required_text(row, "capability_sha256") != ALPACA_PAPER_CAPABILITIES.semantic_sha256
            or _required_text(row, "traversal_profile_sha256") != _traversal_profile_sha256(plan)
            or _required_text(row, "canonical_payload")
            != canonical_json_text(plan._semantic_material())
            or _required_text(row, "semantic_sha256") != plan.semantic_sha256
        ):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "persisted account activity plan conflicts with its canonical value"
            )
        _required_datetime(row, "prepared_at")
        return plan
    except AlpacaPaperAccountActivityRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "persisted account activity plan is malformed"
        ) from error


@dataclass(frozen=True, slots=True)
class _AccountActivityHead:
    capture_id: str
    account_id: str
    plan_sha256: str
    committed_page_count: int
    committed_activity_count: int
    last_page_receipt_id: str | None
    last_page_receipt_sha256: str | None
    last_persisted_page_sha256: str | None
    next_page_number: int | None
    next_page_size: int | None
    next_page_token: str | None
    next_previous_page_sha256: str | None
    prepared_description_sha256: str | None
    prepared_prefix_capture_sha256: str | None
    prepared_prefix_page_count: int | None
    prepared_previous_page_receipt_id: str | None
    prepared_previous_page_receipt_sha256: str | None
    preparation_sha256: str | None
    prepared_at: datetime | None
    state: _AccountActivityHeadState
    updated_at: datetime

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_PERSISTENCE_CONTRACT_VERSION,
            "account_activity_head",
            self.capture_id,
            self.account_id,
            self.plan_sha256,
            self.committed_page_count,
            self.committed_activity_count,
            self.last_page_receipt_id,
            self.last_page_receipt_sha256,
            self.last_persisted_page_sha256,
            self.next_page_number,
            self.next_page_size,
            self.next_page_token,
            self.next_previous_page_sha256,
            self.prepared_description_sha256,
            self.prepared_prefix_capture_sha256,
            self.prepared_prefix_page_count,
            self.prepared_previous_page_receipt_id,
            self.prepared_previous_page_receipt_sha256,
            self.preparation_sha256,
            self.prepared_at,
            self.state,
            self.updated_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _head_from_row(row: AccountActivityRow) -> _AccountActivityHead:
    try:
        head = _AccountActivityHead(
            capture_id=_required_text(row, "capture_id"),
            account_id=_required_text(row, "account_id"),
            plan_sha256=_required_text(row, "plan_sha256"),
            committed_page_count=_required_integer(
                row,
                "committed_page_count",
            ),
            committed_activity_count=_required_integer(
                row,
                "committed_activity_count",
            ),
            last_page_receipt_id=_optional_text(
                row,
                "last_page_receipt_id",
            ),
            last_page_receipt_sha256=_optional_text(
                row,
                "last_page_receipt_sha256",
            ),
            last_persisted_page_sha256=_optional_text(
                row,
                "last_persisted_page_sha256",
            ),
            next_page_number=_optional_integer(row, "next_page_number"),
            next_page_size=_optional_integer(row, "next_page_size"),
            next_page_token=_optional_text(row, "next_page_token"),
            next_previous_page_sha256=_optional_text(
                row,
                "next_previous_page_sha256",
            ),
            prepared_description_sha256=_optional_text(
                row,
                "prepared_description_sha256",
            ),
            prepared_prefix_capture_sha256=_optional_text(
                row,
                "prepared_prefix_capture_sha256",
            ),
            prepared_prefix_page_count=_optional_integer(
                row,
                "prepared_prefix_page_count",
            ),
            prepared_previous_page_receipt_id=_optional_text(
                row,
                "prepared_previous_page_receipt_id",
            ),
            prepared_previous_page_receipt_sha256=_optional_text(
                row,
                "prepared_previous_page_receipt_sha256",
            ),
            preparation_sha256=_optional_text(row, "preparation_sha256"),
            prepared_at=_optional_datetime(row, "prepared_at"),
            state=_AccountActivityHeadState(_required_text(row, "state")),
            updated_at=_required_datetime(row, "updated_at"),
        )
        if (
            _required_text(row, "canonical_payload") != head.canonical_json
            or _required_text(row, "semantic_sha256") != head.semantic_sha256
        ):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "persisted account activity head conflicts with its canonical value"
            )
        return head
    except AlpacaPaperAccountActivityRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "persisted account activity head is malformed"
        ) from error


def _head_values(head: _AccountActivityHead) -> dict[str, Any]:
    return {
        field_name: getattr(head, field_name)
        for field_name in _AccountActivityHead.__dataclass_fields__
    } | {
        "state": head.state.value,
        "canonical_payload": head.canonical_json,
        "semantic_sha256": head.semantic_sha256,
    }


def _plan_row(
    connection: Connection,
    capture_id: str,
) -> RowMapping | None:
    return (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_plans).where(
                phase4_alpaca_paper_account_activity_plans.c.capture_id == capture_id
            )
        )
        .mappings()
        .one_or_none()
    )


def immutable_alpaca_paper_account_activity_preparation_values(
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt,
) -> dict[str, Any]:
    """Return the normalized immutable SQL representation of one preparation."""

    if type(preparation) is not AlpacaPaperAccountActivityPagePreparationReceipt:
        raise AlpacaPaperAccountActivityPersistenceError(
            "account activity persistence requires an exact page preparation"
        )
    preparation._validate()
    description = preparation.description
    plan = description.plan
    return {
        "preparation_sha256": preparation.semantic_sha256,
        "capture_id": plan.capture_id,
        "account_id": plan.account_id,
        "page_number": description.page_number,
        "page_size": description.page_size,
        "plan_sha256": plan.semantic_sha256,
        "page_token": description.page_token,
        "description_sha256": description.semantic_sha256,
        "prefix_capture_sha256": preparation.prefix_capture_sha256,
        "prefix_page_count": preparation.prefix_page_count,
        "previous_page_receipt_id": preparation.previous_page_receipt_id,
        "previous_page_receipt_sha256": preparation.previous_page_receipt_sha256,
        "previous_persisted_page_sha256": description.previous_page_sha256,
        "prepared_at": preparation.prepared_at,
    }


def _preparation_fact_from_row(
    row: AccountActivityRow,
    plan: AlpacaPaperAccountActivityPlan,
) -> AlpacaPaperAccountActivityPagePreparationReceipt:
    """Strictly reconstruct one normalized immutable preparation fact."""

    try:
        description = AlpacaPaperAccountActivityPageDescription(
            plan=plan,
            page_number=_required_integer(row, "page_number"),
            page_size=_required_integer(row, "page_size"),
            page_token=_optional_text(row, "page_token"),
            previous_page_sha256=_optional_text(
                row,
                "previous_persisted_page_sha256",
            ),
        )
        preparation = _alpaca_paper_account_activity_page_preparation_receipt(
            description,
            prefix_capture_sha256=_required_text(
                row,
                "prefix_capture_sha256",
            ),
            prefix_page_count=_required_integer(row, "prefix_page_count"),
            previous_page_receipt_id=_optional_text(
                row,
                "previous_page_receipt_id",
            ),
            previous_page_receipt_sha256=_optional_text(
                row,
                "previous_page_receipt_sha256",
            ),
            prepared_at=_required_datetime(row, "prepared_at"),
        )
        if (
            _required_text(row, "capture_id") != plan.capture_id
            or _required_text(row, "account_id") != plan.account_id
            or _required_text(row, "plan_sha256") != plan.semantic_sha256
            or _required_text(row, "description_sha256") != description.semantic_sha256
            or _required_text(row, "preparation_sha256") != preparation.semantic_sha256
        ):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "persisted account activity preparation conflicts with its canonical value"
            )
        return preparation
    except AlpacaPaperAccountActivityRuntimeError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "persisted account activity preparation is malformed"
        ) from error


def _preparation_fact_row(
    connection: Connection,
    *,
    preparation_sha256: str | None = None,
    capture_id: str | None = None,
    page_number: int | None = None,
) -> RowMapping | None:
    if preparation_sha256 is None and (capture_id is None or page_number is None):
        raise AssertionError("preparation fact lookup requires an exact identity")
    statement = sa.select(phase4_alpaca_paper_account_activity_preparations)
    if preparation_sha256 is not None:
        statement = statement.where(
            phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256
            == preparation_sha256
        )
    if capture_id is not None:
        statement = statement.where(
            phase4_alpaca_paper_account_activity_preparations.c.capture_id == capture_id
        )
    if page_number is not None:
        statement = statement.where(
            phase4_alpaca_paper_account_activity_preparations.c.page_number == page_number
        )
    return connection.execute(statement).mappings().one_or_none()


def _load_preparation_fact(
    connection: Connection,
    *,
    plan: AlpacaPaperAccountActivityPlan,
    preparation_sha256: str,
    page_number: int,
) -> AlpacaPaperAccountActivityPagePreparationReceipt:
    row = _preparation_fact_row(
        connection,
        preparation_sha256=preparation_sha256,
        capture_id=plan.capture_id,
        page_number=page_number,
    )
    if row is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation lacks its immutable fact"
        )
    return _preparation_fact_from_row(row, plan)


def _insert_preparation_fact(
    connection: Connection,
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt,
) -> AlpacaPaperAccountActivityPagePreparationReceipt:
    values = immutable_alpaca_paper_account_activity_preparation_values(
        preparation,
    )
    try:
        connection.execute(
            sa.insert(phase4_alpaca_paper_account_activity_preparations).values(**values)
        )
    except IntegrityError as error:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation fact conflicts with durable history"
        ) from error
    row = _preparation_fact_row(
        connection,
        preparation_sha256=preparation.semantic_sha256,
        capture_id=preparation.description.plan.capture_id,
        page_number=preparation.description.page_number,
    )
    if row is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation fact failed exact SQL readback"
        )
    persisted = _preparation_fact_from_row(
        row,
        preparation.description.plan,
    )
    if persisted != preparation:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation fact failed exact reconstruction"
        )
    assert_immutable(
        phase4_alpaca_paper_account_activity_preparations,
        preparation.semantic_sha256,
        row,
        values,
    )
    return persisted


def _head(
    connection: Connection,
    capture_id: str,
) -> _AccountActivityHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_heads).where(
                phase4_alpaca_paper_account_activity_heads.c.capture_id == capture_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _account_binding_source(
    connection: Connection,
    *,
    account_id: str,
    binding_id: str,
    binding_sha256: str,
    expected_provider_account_id: str,
    commit_checked_at: datetime,
) -> AlpacaPaperAuthenticatedAccountBinding:
    binding = _binding_by_id(connection, binding_id)
    if binding is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity references a missing account binding"
        )
    _authenticate_binding_position(connection, binding)
    _authenticate_account_binding_sources(connection, binding)
    successor_before_commit = connection.scalar(
        sa.select(phase4_alpaca_paper_account_bindings.c.binding_id)
        .where(
            phase4_alpaca_paper_account_bindings.c.account_id == binding.account_id,
            phase4_alpaca_paper_account_bindings.c.sequence_number > binding.sequence_number,
            phase4_alpaca_paper_account_bindings.c.qualified_at < commit_checked_at,
        )
        .limit(1)
    )
    if (
        binding.account_id != account_id
        or binding.semantic_sha256 != binding_sha256
        or binding.expected_provider_account_id != expected_provider_account_id
        or successor_before_commit is not None
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity conflicts with its exact account-binding source"
        )
    return binding


def _permit_source(
    connection: Connection,
    *,
    account_id: str,
    permit_id: str,
    permit_sha256: str,
    demand_id: str,
    demand_sha256: str,
    policy_sha256: str,
) -> _PersistedBrokerRequestPermit:
    record = _permit_record_by_id(connection, permit_id)
    if record is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity references a missing request permit"
        )
    _authenticate_permit_position(connection, record)
    if (
        record.permit.account_id != account_id
        or record.permit.semantic_sha256 != permit_sha256
        or record.demand.demand_id != demand_id
        or record.demand.semantic_sha256 != demand_sha256
        or record.policy.semantic_sha256 != policy_sha256
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity conflicts with its exact permit source"
        )
    return record


def _ingress_source(
    connection: Connection,
    *,
    account_id: str,
    receipt_id: str,
    receipt_sha256: str,
    ingress_sequence: int,
) -> BrokerIngressReceipt:
    receipt = _ingress_receipt_by_id(connection, receipt_id)
    if receipt is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity references a missing raw ingress receipt"
        )
    _authenticate_ingress_position(connection, receipt)
    if (
        receipt.account_id != account_id
        or receipt.semantic_sha256 != receipt_sha256
        or receipt.ingress_sequence != ingress_sequence
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity conflicts with its exact raw ingress source"
        )
    return receipt


def _fence_source(
    connection: Connection,
    row: AccountActivityRow,
    *,
    phase: str,
) -> AccountFenceReceipt:
    if phase not in {"pre", "post", "commit"}:
        raise AssertionError("account activity fence phase must be exact")
    lease_sha256 = _required_text(row, f"{phase}_fence_lease_sha256")
    account_id = _required_text(row, "account_id")
    generation = _required_integer(row, "fence_fencing_generation")
    lease_row = (
        connection.execute(
            sa.select(phase2_account_leases).where(
                phase2_account_leases.c.account_id == account_id,
                phase2_account_leases.c.fencing_generation == generation,
                phase2_account_leases.c.lease_sha256 == lease_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if lease_row is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"account activity {phase} fence references a missing lease"
        )
    lease = account_lease_from_row(lease_row)
    validated_at = _required_datetime(
        row,
        f"{phase}_fence_validated_at",
    )
    valid_until = _required_datetime(row, f"{phase}_fence_valid_until")
    receipt = _account_fence_receipt(
        fence=lease.fence,
        validated_at=validated_at,
        valid_until=valid_until,
        policy_sha256=lease.policy_sha256,
        lease_sha256=lease.semantic_sha256,
    )
    if (
        lease.owner_id != _required_text(row, "fence_owner_id")
        or lease.lease_id != _required_text(row, "fence_lease_id")
        or lease.fencing_generation != generation
        or lease.fence.semantic_sha256 != _required_text(row, "fence_sha256")
        or lease.policy_sha256 != _required_text(row, "fence_policy_sha256")
        or valid_until != lease.expires_at
        or receipt.semantic_sha256 != _required_text(row, f"{phase}_fence_receipt_sha256")
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            f"account activity {phase} fence conflicts with its lease source"
        )
    _authenticate_fence_position_at(
        connection,
        receipt,
        checked_at=validated_at,
    )
    return receipt


def _receipt_from_row(
    connection: Connection,
    row: AccountActivityRow,
    plan: AlpacaPaperAccountActivityPlan,
) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
    try:
        page_number = _required_integer(row, "page_number")
        description = AlpacaPaperAccountActivityPageDescription(
            plan=plan,
            page_number=page_number,
            page_size=_required_integer(row, "page_size"),
            page_token=_optional_text(row, "page_token"),
            previous_page_sha256=_optional_text(
                row,
                "previous_persisted_page_sha256",
            ),
        )
        preparation = _alpaca_paper_account_activity_page_preparation_receipt(
            description,
            prefix_capture_sha256=_required_text(
                row,
                "prefix_capture_sha256",
            ),
            prefix_page_count=_required_integer(row, "prefix_page_count"),
            previous_page_receipt_id=_optional_text(
                row,
                "preparation_previous_page_receipt_id",
            ),
            previous_page_receipt_sha256=_optional_text(
                row,
                "preparation_previous_page_receipt_sha256",
            ),
            prepared_at=_required_datetime(row, "prepared_at"),
        )
        preparation_fact = _load_preparation_fact(
            connection,
            plan=plan,
            preparation_sha256=_required_text(
                row,
                "preparation_sha256",
            ),
            page_number=page_number,
        )
        if preparation_fact != preparation:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "account activity page conflicts with its immutable preparation"
            )
        binding = _account_binding_source(
            connection,
            account_id=_required_text(row, "account_id"),
            binding_id=_required_text(row, "account_binding_id"),
            binding_sha256=_required_text(row, "account_binding_sha256"),
            expected_provider_account_id=_required_text(
                row,
                "expected_provider_account_id",
            ),
            commit_checked_at=_required_datetime(
                row,
                "commit_fence_validated_at",
            ),
        )
        reference = AlpacaPaperCredentialReference(
            account_id=binding.account_id,
            expected_provider_account_id=binding.expected_provider_account_id,
            secret_ref=_required_text(row, "secret_ref"),
            secret_version=_required_text(row, "secret_version"),
        )
        credential_receipt = AlpacaPaperCredentialResolutionReceipt(
            reference=reference,
            resolver_id=_required_text(row, "resolver_id"),
            resolver_version=_required_text(row, "resolver_version"),
            started_at=_required_datetime(
                row,
                "credential_resolution_started_at",
            ),
            resolved_at=_required_datetime(row, "resolved_at"),
            valid_until=_required_datetime(
                row,
                "credential_resolution_valid_until",
            ),
        )
        pre_identity = _alpaca_paper_account_identity_continuity_receipt(
            binding,
            checked_at=_required_datetime(
                row,
                "pre_account_identity_checked_at",
            ),
        )
        post_identity = _alpaca_paper_account_identity_continuity_receipt(
            binding,
            checked_at=_required_datetime(
                row,
                "post_account_identity_checked_at",
            ),
        )
        permit_record = _permit_source(
            connection,
            account_id=plan.account_id,
            permit_id=_required_text(row, "permit_id"),
            permit_sha256=_required_text(row, "permit_sha256"),
            demand_id=_required_text(row, "demand_id"),
            demand_sha256=_required_text(row, "demand_sha256"),
            policy_sha256=_required_text(row, "policy_sha256"),
        )
        policy = permit_record.policy
        demand = permit_record.demand
        permit = permit_record.permit
        permit_freshness = _broker_request_permit_freshness_receipt(
            permit=permit,
            policy=policy,
            demand=demand,
            checked_at=_required_datetime(row, "permit_checked_at"),
        )
        pre_fence = _fence_source(connection, row, phase="pre")
        post_fence = _fence_source(connection, row, phase="post")
        commit_fence = _fence_source(connection, row, phase="commit")
        request = AlpacaPaperAccountActivityTransportRequest(
            description=description,
            credential_reference_sha256=reference.semantic_sha256,
            account_binding_sha256=binding.semantic_sha256,
            pre_account_identity_sha256=pre_identity.semantic_sha256,
            preparation_sha256=preparation.semantic_sha256,
            demand_sha256=demand.semantic_sha256,
            permit_sha256=permit.semantic_sha256,
            permit_freshness_sha256=permit_freshness.semantic_sha256,
            fence_receipt_sha256=pre_fence.semantic_sha256,
            started_at=_required_datetime(row, "request_started_at"),
        )
        ingress = _ingress_source(
            connection,
            account_id=plan.account_id,
            receipt_id=_required_text(row, "ingress_receipt_id"),
            receipt_sha256=_required_text(row, "ingress_receipt_sha256"),
            ingress_sequence=_required_integer(row, "ingress_sequence"),
        )
        delivery = ingress.delivery
        provider_request_id = _required_text(row, "provider_request_id")
        response = AlpacaPaperAccountActivityTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID,
            transport_version=ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION,
            http_status=_required_integer(row, "http_status"),
            provider_request_id=provider_request_id,
            media_type=delivery.media_type,
            response_body=delivery.body,
        )
        observation = decode_alpaca_paper_account_activity_page(
            description,
            http_status=response.http_status,
            provider_request_id=provider_request_id,
            response_body=response.response_body,
            received_at=_required_datetime(row, "received_at"),
        )
        persisted_page = PersistedAlpacaPaperAccountActivityPage(
            receipt=ingress,
            observation=observation,
        )
        evidence = _alpaca_paper_authenticated_account_activity_page_evidence(
            reference=reference,
            credential_receipt=credential_receipt,
            account_binding=binding,
            pre_account_identity=pre_identity,
            description=description,
            preparation=preparation,
            policy=policy,
            demand=demand,
            permit=permit,
            permit_freshness=permit_freshness,
            pre_fence_receipt=pre_fence,
            request=request,
            response=response,
            persisted_page=persisted_page,
            post_fence_receipt=post_fence,
            post_account_identity=post_identity,
            authenticated_at=_required_datetime(row, "authenticated_at"),
        )
        receipt = _alpaca_paper_authenticated_account_activity_page_receipt(
            evidence,
            commit_fence_receipt=commit_fence,
            previous_page_receipt_sha256=_optional_text(
                row,
                "previous_page_receipt_sha256",
            ),
        )
        expected_values = immutable_alpaca_paper_account_activity_page_values(receipt)
        if any(
            not same_value(row[field_name], value) for field_name, value in expected_values.items()
        ):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "persisted account activity page conflicts with exact reconstruction"
            )
        return receipt
    except AlpacaPaperAccountActivityRuntimeError:
        raise
    except (
        AccountCoordinatorError,
        BrokerIngressError,
        BrokerRequestBudgetError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "persisted account activity page is malformed"
        ) from error


def immutable_alpaca_paper_account_activity_page_values(
    receipt: AlpacaPaperAuthenticatedAccountActivityPageReceipt,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one page receipt."""

    if type(receipt) is not AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        raise AlpacaPaperAccountActivityPersistenceError(
            "account activity persistence requires an exact page receipt"
        )
    receipt._validate()
    evidence = receipt.evidence
    plan = receipt.plan
    description = receipt.description
    preparation = evidence.preparation
    reference = evidence.reference
    credential = evidence.credential_receipt
    binding = evidence.account_binding
    permit = evidence.permit
    ingress = receipt.persisted_page.receipt
    observation = receipt.persisted_page.observation
    pre_fence = evidence.pre_fence_receipt
    post_fence = evidence.post_fence_receipt
    commit_fence = receipt.commit_fence_receipt
    return {
        "receipt_id": receipt.receipt_id,
        "capture_id": plan.capture_id,
        "account_id": plan.account_id,
        "page_number": description.page_number,
        "page_size": description.page_size,
        "plan_sha256": plan.semantic_sha256,
        "previous_page_receipt_sha256": (receipt.previous_page_receipt_sha256),
        "previous_persisted_page_sha256": (description.previous_page_sha256),
        "description_sha256": description.semantic_sha256,
        "preparation_sha256": preparation.semantic_sha256,
        "prefix_capture_sha256": preparation.prefix_capture_sha256,
        "prefix_page_count": preparation.prefix_page_count,
        "preparation_previous_page_receipt_id": (preparation.previous_page_receipt_id),
        "preparation_previous_page_receipt_sha256": (preparation.previous_page_receipt_sha256),
        "prepared_at": preparation.prepared_at,
        "provider_id": reference.provider_id,
        "environment": reference.environment,
        "capability_sha256": reference.capability_sha256,
        "expected_provider_account_id": (reference.expected_provider_account_id),
        "secret_ref": reference.secret_ref,
        "secret_version": reference.secret_version,
        "credential_reference_sha256": reference.semantic_sha256,
        "credential_resolution_sha256": credential.semantic_sha256,
        "resolver_id": credential.resolver_id,
        "resolver_version": credential.resolver_version,
        "credential_resolution_started_at": credential.started_at,
        "resolved_at": credential.resolved_at,
        "credential_resolution_valid_until": credential.valid_until,
        "account_binding_id": binding.binding_id,
        "account_binding_sha256": binding.semantic_sha256,
        "pre_account_identity_sha256": (evidence.pre_account_identity.semantic_sha256),
        "post_account_identity_sha256": (evidence.post_account_identity.semantic_sha256),
        "pre_account_identity_checked_at": (evidence.pre_account_identity.checked_at),
        "post_account_identity_checked_at": (evidence.post_account_identity.checked_at),
        "policy_sha256": evidence.policy.semantic_sha256,
        "demand_id": evidence.demand.demand_id,
        "demand_sha256": evidence.demand.semantic_sha256,
        "requested_at": evidence.demand.requested_at,
        "permit_id": permit.permit_id,
        "permit_sha256": permit.semantic_sha256,
        "permit_freshness_sha256": (evidence.permit_freshness.semantic_sha256),
        "permit_checked_at": evidence.permit_freshness.checked_at,
        "fence_owner_id": pre_fence.fence.owner_id,
        "fence_lease_id": pre_fence.fence.lease_id,
        "fence_fencing_generation": pre_fence.fence.fencing_generation,
        "fence_sha256": pre_fence.fence.semantic_sha256,
        "fence_policy_sha256": pre_fence.policy_sha256,
        "pre_fence_lease_sha256": pre_fence.lease_sha256,
        "pre_fence_receipt_sha256": pre_fence.semantic_sha256,
        "pre_fence_validated_at": pre_fence.validated_at,
        "pre_fence_valid_until": pre_fence.valid_until,
        "transport_request_sha256": evidence.request.semantic_sha256,
        "transport_response_sha256": evidence.response.semantic_sha256,
        "request_started_at": evidence.request.started_at,
        "http_status": evidence.response.http_status,
        "provider_request_id": evidence.response.provider_request_id,
        "received_at": observation.received_at,
        "ingress_receipt_id": ingress.receipt_id,
        "ingress_receipt_sha256": ingress.semantic_sha256,
        "ingress_sequence": ingress.ingress_sequence,
        "raw_recorded_at": ingress.delivery.recorded_at,
        "observation_sha256": observation.semantic_sha256,
        "persisted_page_sha256": receipt.persisted_page.semantic_sha256,
        "page_token": description.page_token,
        "next_page_token": observation.next_page_token,
        "activity_count": observation.activity_count,
        "terminal_page": observation.terminal_page,
        "bounded_truncation": (
            not observation.terminal_page
            and (
                description.page_number == plan.maximum_pages
                or (
                    (description.page_number - 1) * plan.page_size + observation.activity_count
                    >= plan.maximum_items
                )
            )
        ),
        "post_fence_lease_sha256": post_fence.lease_sha256,
        "post_fence_receipt_sha256": post_fence.semantic_sha256,
        "post_fence_validated_at": post_fence.validated_at,
        "post_fence_valid_until": post_fence.valid_until,
        "authenticated_at": evidence.authenticated_at,
        "evidence_sha256": evidence.semantic_sha256,
        "commit_fence_lease_sha256": commit_fence.lease_sha256,
        "commit_fence_receipt_sha256": commit_fence.semantic_sha256,
        "commit_fence_validated_at": commit_fence.validated_at,
        "commit_fence_valid_until": commit_fence.valid_until,
        "canonical_payload": receipt.canonical_json,
        "semantic_sha256": receipt.semantic_sha256,
    }


def _page_by_evidence(
    connection: Connection,
    evidence_sha256: str,
) -> tuple[RowMapping, AlpacaPaperAuthenticatedAccountActivityPageReceipt] | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_pages).where(
                phase4_alpaca_paper_account_activity_pages.c.evidence_sha256 == evidence_sha256
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    plan_row = _plan_row(connection, _required_text(row, "capture_id"))
    if plan_row is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity page exists without its plan"
        )
    plan = alpaca_paper_account_activity_plan_from_row(plan_row)
    return row, _receipt_from_row(connection, row, plan)


def _history(
    connection: Connection,
    plan: AlpacaPaperAccountActivityPlan,
) -> tuple[AlpacaPaperAuthenticatedAccountActivityPageReceipt, ...]:
    rows = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_pages)
            .where(phase4_alpaca_paper_account_activity_pages.c.capture_id == plan.capture_id)
            .order_by(phase4_alpaca_paper_account_activity_pages.c.page_number)
        )
        .mappings()
        .all()
    )
    receipts = tuple(_receipt_from_row(connection, row, plan) for row in rows)
    prefix = _alpaca_paper_authenticated_account_activity_prefix(
        plan,
        page_receipts=receipts,
    )
    head = _head(connection, plan.capture_id)
    if head is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity plan exists without its durable head"
        )
    _validate_head_against_prefix(connection, head, prefix)
    plan_row = _plan_row(connection, plan.capture_id)
    if plan_row is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity history exists without its durable plan"
        )
    if receipts:
        first_prepared_at = receipts[0].evidence.preparation.prepared_at
    else:
        next_description = prefix.next_page_description
        if next_description is None:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "empty account activity history has no prepared first page"
            )
        first_prepared_at = _preparation_from_head(
            connection,
            head,
            next_description,
        ).prepared_at
    if _required_datetime(plan_row, "prepared_at") != first_prepared_at:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity plan preparation time conflicts with its first claim"
        )
    return receipts


def _preparation_from_head(
    connection: Connection,
    head: _AccountActivityHead,
    description: AlpacaPaperAccountActivityPageDescription,
) -> AlpacaPaperAccountActivityPagePreparationReceipt:
    if (
        head.state is not _AccountActivityHeadState.STALLED
        or head.prepared_prefix_capture_sha256 is None
        or head.prepared_prefix_page_count is None
        or head.preparation_sha256 is None
        or head.prepared_at is None
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity head has no exact prepared-page claim"
        )
    preparation = _load_preparation_fact(
        connection,
        plan=description.plan,
        preparation_sha256=head.preparation_sha256,
        page_number=description.page_number,
    )
    if (
        preparation.description != description
        or preparation.prefix_capture_sha256 != head.prepared_prefix_capture_sha256
        or preparation.prefix_page_count != head.prepared_prefix_page_count
        or preparation.previous_page_receipt_id != head.prepared_previous_page_receipt_id
        or preparation.previous_page_receipt_sha256 != head.prepared_previous_page_receipt_sha256
        or preparation.prepared_at != head.prepared_at
        or head.prepared_description_sha256 != description.semantic_sha256
        or head.preparation_sha256 != preparation.semantic_sha256
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity prepared-page claim conflicts with its head"
        )
    return preparation


def _validate_head_against_prefix(
    connection: Connection,
    head: _AccountActivityHead,
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
) -> None:
    capture = prefix.capture
    previous = None if not prefix.page_receipts else prefix.page_receipts[-1]
    if capture.pagination_exhausted or capture.bounded_truncation:
        if previous is None:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "terminal account activity head has no committed page"
            )
        expected_state = (
            _AccountActivityHeadState.CURSOR_EXHAUSTED_UNISOLATED
            if capture.pagination_exhausted
            else _AccountActivityHeadState.BOUNDED_TRUNCATED
        )
        preparation = None
        updated_at = previous.commit_fence_receipt.validated_at
    elif head.state is _AccountActivityHeadState.STALLED:
        next_description = prefix.next_page_description
        if next_description is None:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "prepared account activity head has no next page"
            )
        preparation = _preparation_from_head(
            connection,
            head,
            next_description,
        )
        if (
            preparation.prefix_capture_sha256 != prefix.capture.semantic_sha256
            or preparation.prefix_page_count != prefix.page_count
        ):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "prepared account activity head conflicts with its prefix"
            )
        expected_state = _AccountActivityHeadState.STALLED
        updated_at = preparation.prepared_at
    elif head.state is _AccountActivityHeadState.ACTIVE:
        if previous is None:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "active account activity head has no committed page"
            )
        expected_state = _AccountActivityHeadState.ACTIVE
        preparation = None
        updated_at = previous.commit_fence_receipt.validated_at
    else:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity head state conflicts with its prefix"
        )
    expected = _head_for_prefix(
        prefix,
        state=expected_state,
        updated_at=updated_at,
        preparation=preparation,
    )
    if head != expected:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity head conflicts with its authenticated prefix"
        )


def _head_for_prefix(
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    *,
    state: _AccountActivityHeadState,
    updated_at: datetime,
    preparation: AlpacaPaperAccountActivityPagePreparationReceipt | None = None,
) -> _AccountActivityHead:
    capture = prefix.capture
    previous = None if not prefix.page_receipts else prefix.page_receipts[-1]
    next_description = prefix.next_page_description
    terminal = capture.pagination_exhausted or capture.bounded_truncation
    return _AccountActivityHead(
        capture_id=prefix.plan.capture_id,
        account_id=prefix.plan.account_id,
        plan_sha256=prefix.plan.semantic_sha256,
        committed_page_count=prefix.page_count,
        committed_activity_count=capture.activity_count,
        last_page_receipt_id=(None if previous is None else previous.receipt_id),
        last_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
        last_persisted_page_sha256=(
            None if previous is None else previous.persisted_page.semantic_sha256
        ),
        next_page_number=(
            None if terminal or next_description is None else next_description.page_number
        ),
        next_page_size=(
            None if terminal or next_description is None else next_description.page_size
        ),
        next_page_token=(
            None if terminal or next_description is None else next_description.page_token
        ),
        next_previous_page_sha256=(
            None if terminal or next_description is None else next_description.previous_page_sha256
        ),
        prepared_description_sha256=(
            None if preparation is None else preparation.description.semantic_sha256
        ),
        prepared_prefix_capture_sha256=(
            None if preparation is None else preparation.prefix_capture_sha256
        ),
        prepared_prefix_page_count=(None if preparation is None else preparation.prefix_page_count),
        prepared_previous_page_receipt_id=(
            None if preparation is None else preparation.previous_page_receipt_id
        ),
        prepared_previous_page_receipt_sha256=(
            None if preparation is None else preparation.previous_page_receipt_sha256
        ),
        preparation_sha256=(None if preparation is None else preparation.semantic_sha256),
        prepared_at=None if preparation is None else preparation.prepared_at,
        state=state,
        updated_at=_require_utc(updated_at, "account activity head updated_at"),
    )


def _authenticate_evidence_sources(
    connection: Connection,
    evidence: AlpacaPaperAuthenticatedAccountActivityPageEvidence,
    *,
    require_terminal_binding: bool,
) -> None:
    binding = _account_binding_source(
        connection,
        account_id=evidence.description.plan.account_id,
        binding_id=evidence.account_binding.binding_id,
        binding_sha256=evidence.account_binding.semantic_sha256,
        expected_provider_account_id=(evidence.reference.expected_provider_account_id),
        commit_checked_at=evidence.authenticated_at,
    )
    head = _authenticate_binding_position(connection, binding)
    if require_terminal_binding and _terminal_binding(connection, head) != binding:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity account binding is no longer terminal"
        )
    if binding != evidence.account_binding:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity account binding changed before commit"
        )
    for identity in (
        evidence.pre_account_identity,
        evidence.post_account_identity,
    ):
        expected = _alpaca_paper_account_identity_continuity_receipt(
            binding,
            checked_at=identity.checked_at,
        )
        if expected != identity:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "account activity account identity conflicts with durable binding"
            )
    permit_record = _permit_source(
        connection,
        account_id=evidence.description.plan.account_id,
        permit_id=evidence.permit.permit_id,
        permit_sha256=evidence.permit.semantic_sha256,
        demand_id=evidence.demand.demand_id,
        demand_sha256=evidence.demand.semantic_sha256,
        policy_sha256=evidence.policy.semantic_sha256,
    )
    if (
        permit_record.policy != evidence.policy
        or permit_record.demand != evidence.demand
        or permit_record.permit != evidence.permit
    ):
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity permit changed before commit"
        )
    ingress = _ingress_source(
        connection,
        account_id=evidence.description.plan.account_id,
        receipt_id=evidence.persisted_page.receipt.receipt_id,
        receipt_sha256=evidence.persisted_page.receipt.semantic_sha256,
        ingress_sequence=evidence.persisted_page.receipt.ingress_sequence,
    )
    if ingress != evidence.persisted_page.receipt:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity raw ingress changed before commit"
        )
    for fence in (
        evidence.pre_fence_receipt,
        evidence.post_fence_receipt,
    ):
        _authenticate_fence_position_at(
            connection,
            fence,
            checked_at=fence.validated_at,
        )


def _verify_alpaca_paper_account_activity_integrity(
    connection: Connection,
) -> None:
    orphan_head = connection.scalar(
        sa.select(phase4_alpaca_paper_account_activity_heads.c.capture_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_plans.c.capture_id
                    == phase4_alpaca_paper_account_activity_heads.c.capture_id
                )
            )
        )
        .limit(1)
    )
    if orphan_head is not None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity heads exist without durable plans"
        )
    orphan_page = connection.scalar(
        sa.select(phase4_alpaca_paper_account_activity_pages.c.receipt_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_heads.c.capture_id
                    == phase4_alpaca_paper_account_activity_pages.c.capture_id
                )
            )
        )
        .limit(1)
    )
    if orphan_page is not None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity pages exist without durable heads"
        )
    orphan_plan = connection.scalar(
        sa.select(phase4_alpaca_paper_account_activity_plans.c.capture_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_heads.c.capture_id
                    == phase4_alpaca_paper_account_activity_plans.c.capture_id
                )
            )
        )
        .limit(1)
    )
    if orphan_plan is not None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity plans exist without durable heads"
        )
    orphan_preparation = connection.scalar(
        sa.select(phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_pages.c.preparation_sha256
                    == phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256
                )
            ),
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_heads.c.preparation_sha256
                    == phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256,
                    phase4_alpaca_paper_account_activity_heads.c.state
                    == _AccountActivityHeadState.STALLED.value,
                )
            ),
        )
        .limit(1)
    )
    if orphan_preparation is not None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation exists outside a page or stalled head"
        )
    multiply_referenced_preparation = connection.scalar(
        sa.select(phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256)
        .where(
            sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_pages.c.preparation_sha256
                    == phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256
                )
            ),
            sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_heads.c.preparation_sha256
                    == phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256
                )
            ),
        )
        .limit(1)
    )
    if multiply_referenced_preparation is not None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation is both completed and stalled"
        )
    preparation_rows = connection.execute(
        sa.select(phase4_alpaca_paper_account_activity_preparations)
        .order_by(
            phase4_alpaca_paper_account_activity_preparations.c.capture_id,
            phase4_alpaca_paper_account_activity_preparations.c.page_number,
        )
        .execution_options(yield_per=64)
    ).mappings()
    for preparation_row in preparation_rows:
        plan_row = _plan_row(
            connection,
            _required_text(preparation_row, "capture_id"),
        )
        if plan_row is None:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "account activity preparation exists without its durable plan"
            )
        plan = alpaca_paper_account_activity_plan_from_row(plan_row)
        _preparation_fact_from_row(preparation_row, plan)
    plan_rows = connection.execute(
        sa.select(phase4_alpaca_paper_account_activity_plans)
        .order_by(phase4_alpaca_paper_account_activity_plans.c.capture_id)
        .execution_options(yield_per=64)
    ).mappings()
    for plan_row in plan_rows:
        plan = alpaca_paper_account_activity_plan_from_row(plan_row)
        _history(connection, plan)


def verify_alpaca_paper_account_activity_integrity(engine: Engine) -> None:
    """Authenticate every durable account-activity prefix in one stable read."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperAccountActivityPersistenceError(
            "account activity verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperAccountActivityPersistenceError(
            f"account activity verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_account_activity_integrity(connection)


def _prepare_alpaca_paper_account_activity_in_transaction(
    connection: Connection,
    description: AlpacaPaperAccountActivityPageDescription,
    *,
    checked_at: datetime,
) -> AlpacaPaperAccountActivityPagePreparationReceipt:
    """Insert one exact preparation under an already-held account lock."""

    plan = description.plan
    plan_row = _plan_row(connection, plan.capture_id)
    if plan_row is None:
        prefix = _alpaca_paper_authenticated_account_activity_prefix(
            plan,
            page_receipts=(),
        )
        if description != prefix.next_page_description:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "account activity preparation is not the first page"
            )
        preparation = _alpaca_paper_account_activity_page_preparation_receipt(
            description,
            prefix_capture_sha256=prefix.capture.semantic_sha256,
            prefix_page_count=0,
            previous_page_receipt_id=None,
            previous_page_receipt_sha256=None,
            prepared_at=checked_at,
        )
        plan_values = immutable_alpaca_paper_account_activity_plan_values(
            plan,
            prepared_at=checked_at,
        )
        initial_head = _head_for_prefix(
            prefix,
            state=_AccountActivityHeadState.STALLED,
            updated_at=checked_at,
            preparation=preparation,
        )
        try:
            connection.execute(
                sa.insert(phase4_alpaca_paper_account_activity_plans).values(**plan_values)
            )
            _insert_preparation_fact(
                connection,
                preparation,
            )
            connection.execute(
                sa.insert(phase4_alpaca_paper_account_activity_heads).values(
                    **_head_values(initial_head)
                )
            )
        except IntegrityError as error:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "account activity preparation conflicts with durable history"
            ) from error
        return preparation

    persisted_plan = alpaca_paper_account_activity_plan_from_row(plan_row)
    if persisted_plan != plan:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity identity conflicts with another plan"
        )
    receipts = _history(connection, plan)
    prefix = _alpaca_paper_authenticated_account_activity_prefix(
        plan,
        page_receipts=receipts,
    )
    current_head = _head(connection, plan.capture_id)
    if current_head is None:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity plan is missing its durable head"
        )
    if description != prefix.next_page_description:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity preparation is not the exact next page"
        )
    if current_head.state is _AccountActivityHeadState.STALLED:
        _preparation_from_head(
            connection,
            current_head,
            description,
        )
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity page already has an unresolved single-use claim"
        )
    if current_head.state is not _AccountActivityHeadState.ACTIVE:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity traversal has no remaining page"
        )
    previous = None if not receipts else receipts[-1]
    preparation = _alpaca_paper_account_activity_page_preparation_receipt(
        description,
        prefix_capture_sha256=prefix.capture.semantic_sha256,
        prefix_page_count=prefix.page_count,
        previous_page_receipt_id=(None if previous is None else previous.receipt_id),
        previous_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
        prepared_at=checked_at,
    )
    updated_head = _head_for_prefix(
        prefix,
        state=_AccountActivityHeadState.STALLED,
        updated_at=checked_at,
        preparation=preparation,
    )
    _insert_preparation_fact(
        connection,
        preparation,
    )
    updated = connection.execute(
        sa.update(phase4_alpaca_paper_account_activity_heads)
        .where(
            phase4_alpaca_paper_account_activity_heads.c.capture_id == plan.capture_id,
            phase4_alpaca_paper_account_activity_heads.c.semantic_sha256
            == current_head.semantic_sha256,
        )
        .values(**_head_values(updated_head))
    )
    if updated.rowcount != 1:
        raise AlpacaPaperAccountActivityPersistenceConflict(
            "account activity head changed during preparation"
        )
    return preparation


class SqlAlpacaPaperAccountActivityRepository:
    """Persist and authenticate one restart-safe bounded page prefix."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperAccountActivityPersistenceError(
                "SQL account activities require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperAccountActivityPersistenceError(
                f"SQL account activities do not support dialect {engine.dialect.name!r}"
            )
        if not callable(
            getattr(
                coordinator,
                "revalidate_for_commit_in_transaction",
                None,
            )
        ):
            raise AlpacaPaperAccountActivityPersistenceError(
                "SQL account activitys require a SQL fence validator"
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
            if receipt.fence != fence:
                raise AccountCoordinatorError("commit fence validator returned another fence")
            return receipt
        except Exception:
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "account activity commit fence validation failed"
            ) from None

    def prepare_next(
        self,
        description: AlpacaPaperAccountActivityPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperAccountActivityPagePreparationReceipt:
        """Durably claim the exact next page before capacity is consumed."""

        if type(description) is not AlpacaPaperAccountActivityPageDescription:
            raise AlpacaPaperAccountActivityPersistenceError(
                "account activity preparation requires an exact description"
            )
        description.__post_init__()
        checked_at = _require_utc(
            checked_at,
            "account activity preparation checked_at",
        )
        plan = description.plan
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    plan.account_id,
                )
                return _prepare_alpaca_paper_account_activity_in_transaction(
                    connection,
                    description,
                    checked_at=checked_at,
                )
        except AlpacaPaperAccountActivityRuntimeError:
            raise
        except (ImmutableFactConflict, IntegrityError):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "durable account activity preparation failed"
            ) from None

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityPageEvidence,
    ) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        """Append one authenticated page under the shared account lock."""

        if type(evidence) is not AlpacaPaperAuthenticatedAccountActivityPageEvidence:
            raise AlpacaPaperAccountActivityPersistenceError(
                "account activity recording requires exact authenticated evidence"
            )
        evidence._validate()
        plan = evidence.description.plan
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    plan.account_id,
                )
                plan_row = _plan_row(connection, plan.capture_id)
                if plan_row is None or (
                    alpaca_paper_account_activity_plan_from_row(plan_row) != plan
                ):
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity page lacks its exact durable plan"
                    )
                receipts = _history(connection, plan)
                prefix = _alpaca_paper_authenticated_account_activity_prefix(
                    plan,
                    page_receipts=receipts,
                )
                existing_pair = _page_by_evidence(
                    connection,
                    evidence.semantic_sha256,
                )
                if existing_pair is not None:
                    _, existing = existing_pair
                    if existing not in receipts:
                        raise AlpacaPaperAccountActivityPersistenceConflict(
                            "account activity evidence exists outside its prefix"
                        )
                    expected = _alpaca_paper_authenticated_account_activity_page_receipt(
                        evidence,
                        commit_fence_receipt=(existing.commit_fence_receipt),
                        previous_page_receipt_sha256=(existing.previous_page_receipt_sha256),
                    )
                    if expected != existing:
                        raise AlpacaPaperAccountActivityPersistenceConflict(
                            "account activity evidence identity conflicts"
                        )
                    _authenticate_evidence_sources(
                        connection,
                        evidence,
                        require_terminal_binding=False,
                    )
                    return existing

                head = _head(connection, plan.capture_id)
                if head is None:
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity plan is missing its durable head"
                    )
                expected_description = prefix.next_page_description
                if (
                    expected_description is None
                    or evidence.description != expected_description
                    or head.state is not _AccountActivityHeadState.STALLED
                    or _preparation_from_head(
                        connection,
                        head,
                        expected_description,
                    )
                    != evidence.preparation
                ):
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity evidence does not match its prepared page"
                    )
                _authenticate_evidence_sources(
                    connection,
                    evidence,
                    require_terminal_binding=True,
                )
                commit_fence = self._commit_fence(
                    connection,
                    evidence.post_fence_receipt.fence,
                )
                if (
                    commit_fence.policy_sha256 != evidence.post_fence_receipt.policy_sha256
                    or commit_fence.lease_sha256 != evidence.post_fence_receipt.lease_sha256
                    or commit_fence.valid_until != evidence.post_fence_receipt.valid_until
                    or commit_fence.validated_at < evidence.authenticated_at
                ):
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity fence changed before durable append"
                    )
                previous = None if not receipts else receipts[-1]
                receipt = _alpaca_paper_authenticated_account_activity_page_receipt(
                    evidence,
                    commit_fence_receipt=commit_fence,
                    previous_page_receipt_sha256=(
                        None if previous is None else previous.semantic_sha256
                    ),
                )
                values = immutable_alpaca_paper_account_activity_page_values(receipt)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_account_activity_pages).values(**values)
                    )
                except IntegrityError as error:
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity page conflicts with durable history"
                    ) from error
                updated_prefix = _alpaca_paper_authenticated_account_activity_prefix(
                    plan,
                    page_receipts=(*receipts, receipt),
                )
                capture = updated_prefix.capture
                state = (
                    _AccountActivityHeadState.CURSOR_EXHAUSTED_UNISOLATED
                    if capture.pagination_exhausted
                    else (
                        _AccountActivityHeadState.BOUNDED_TRUNCATED
                        if capture.bounded_truncation
                        else _AccountActivityHeadState.ACTIVE
                    )
                )
                updated_head = _head_for_prefix(
                    updated_prefix,
                    state=state,
                    updated_at=commit_fence.validated_at,
                )
                updated = connection.execute(
                    sa.update(phase4_alpaca_paper_account_activity_heads)
                    .where(
                        phase4_alpaca_paper_account_activity_heads.c.capture_id == plan.capture_id,
                        phase4_alpaca_paper_account_activity_heads.c.semantic_sha256
                        == head.semantic_sha256,
                    )
                    .values(**_head_values(updated_head))
                )
                if updated.rowcount != 1:
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity head changed during page append"
                    )
                row = (
                    connection.execute(
                        sa.select(phase4_alpaca_paper_account_activity_pages).where(
                            phase4_alpaca_paper_account_activity_pages.c.receipt_id
                            == receipt.receipt_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = _receipt_from_row(connection, row, plan)
                if persisted != receipt:
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity page failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_alpaca_paper_account_activity_pages,
                    receipt.receipt_id,
                    row,
                    values,
                )
                persisted_receipts = _history(connection, plan)
                if persisted_receipts != (*receipts, receipt):
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity prefix failed exact SQL readback"
                    )
                final_fence = self._commit_fence(
                    connection,
                    evidence.post_fence_receipt.fence,
                )
                if (
                    final_fence.validated_at < commit_fence.validated_at
                    or final_fence.policy_sha256 != commit_fence.policy_sha256
                    or final_fence.lease_sha256 != commit_fence.lease_sha256
                    or final_fence.valid_until != commit_fence.valid_until
                ):
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "account activity fence changed before final commit"
                    )
                return persisted
        except AlpacaPaperAccountActivityRuntimeError:
            raise
        except (
            AccountCoordinatorError,
            BrokerIngressError,
            BrokerRequestBudgetError,
            ImmutableFactConflict,
        ):
            raise AlpacaPaperAccountActivityPersistenceConflict(
                "durable account activity authentication failed"
            ) from None

    def load_prefix(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityPrefix:
        """Load one fully authenticated committed page prefix."""

        if type(plan) is not AlpacaPaperAccountActivityPlan:
            raise AlpacaPaperAccountActivityPersistenceError(
                "account activity loading requires an exact plan"
            )
        plan.__post_init__()
        with _repeatable_read_transaction(self._engine) as connection:
            plan_row = _plan_row(connection, plan.capture_id)
            if plan_row is None:
                return _alpaca_paper_authenticated_account_activity_prefix(
                    plan,
                    page_receipts=(),
                )
            if alpaca_paper_account_activity_plan_from_row(plan_row) != plan:
                raise AlpacaPaperAccountActivityPersistenceConflict(
                    "account activity identity conflicts with durable plan"
                )
            receipts = _history(connection, plan)
            return _alpaca_paper_authenticated_account_activity_prefix(
                plan,
                page_receipts=receipts,
            )

    def load_state(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
        """Load the exact durable head meaning and its authenticated prefix."""

        if type(plan) is not AlpacaPaperAccountActivityPlan:
            raise AlpacaPaperAccountActivityPersistenceError(
                "account activity state loading requires an exact plan"
            )
        plan.__post_init__()
        with _repeatable_read_transaction(self._engine) as connection:
            plan_row = _plan_row(connection, plan.capture_id)
            if plan_row is None:
                orphan_page = connection.scalar(
                    sa.select(phase4_alpaca_paper_account_activity_pages.c.receipt_id)
                    .where(
                        phase4_alpaca_paper_account_activity_pages.c.capture_id == plan.capture_id
                    )
                    .limit(1)
                )
                if _head(connection, plan.capture_id) is not None or orphan_page is not None:
                    raise AlpacaPaperAccountActivityPersistenceConflict(
                        "absent account activity plan has orphaned durable state"
                    )
                prefix = _alpaca_paper_authenticated_account_activity_prefix(
                    plan,
                    page_receipts=(),
                )
                return _alpaca_paper_authenticated_account_activity_traversal_state(
                    stage=AlpacaPaperAccountActivityTraversalStage.ABSENT,
                    prefix=prefix,
                    preparation=None,
                    source_head_sha256=None,
                )
            if alpaca_paper_account_activity_plan_from_row(plan_row) != plan:
                raise AlpacaPaperAccountActivityPersistenceConflict(
                    "account activity identity conflicts with durable plan"
                )
            receipts = _history(connection, plan)
            prefix = _alpaca_paper_authenticated_account_activity_prefix(
                plan,
                page_receipts=receipts,
            )
            head = _head(connection, plan.capture_id)
            if head is None:
                raise AlpacaPaperAccountActivityPersistenceConflict(
                    "account activity plan is missing its durable head"
                )
            _validate_head_against_prefix(connection, head, prefix)
            stage = {
                _AccountActivityHeadState.ACTIVE: (AlpacaPaperAccountActivityTraversalStage.ACTIVE),
                _AccountActivityHeadState.STALLED: (
                    AlpacaPaperAccountActivityTraversalStage.STALLED
                ),
                _AccountActivityHeadState.CURSOR_EXHAUSTED_UNISOLATED: (
                    AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED
                ),
                _AccountActivityHeadState.BOUNDED_TRUNCATED: (
                    AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED
                ),
            }[head.state]
            preparation = (
                _preparation_from_head(
                    connection,
                    head,
                    prefix.next_page_description,
                )
                if (
                    head.state is _AccountActivityHeadState.STALLED
                    and prefix.next_page_description is not None
                )
                else None
            )
            return _alpaca_paper_authenticated_account_activity_traversal_state(
                stage=stage,
                prefix=prefix,
                preparation=preparation,
                source_head_sha256=head.semantic_sha256,
            )


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperAccountActivityPersistenceConflict",
    "AlpacaPaperAccountActivityPersistenceError",
    "SqlAlpacaPaperAccountActivityRepository",
    "alpaca_paper_account_activity_plan_from_row",
    "immutable_alpaca_paper_account_activity_page_values",
    "immutable_alpaca_paper_account_activity_plan_values",
    "verify_alpaca_paper_account_activity_integrity",
]
