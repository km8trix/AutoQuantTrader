"""Restart-safe persistence for authenticated Alpaca paper order-view comparisons."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotRuntimeError,
    _alpaca_paper_authenticated_order_snapshot_prefix,
)
from packages.application.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedOrderViewComparisonError,
    AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
    AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
    AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
    _alpaca_paper_authenticated_order_view_comparison_evidence,
    _alpaca_paper_authenticated_order_view_comparison_receipt,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
    lock_account_capacity_serialization,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_fence_position_at,
)
from packages.persistence.alpaca_paper_order_snapshot import (
    _head as _snapshot_head,
)
from packages.persistence.alpaca_paper_order_snapshot import (
    _history as _snapshot_history,
)
from packages.persistence.alpaca_paper_order_snapshot import (
    _plan_row as _snapshot_plan_row,
)
from packages.persistence.alpaca_paper_order_snapshot import (
    alpaca_paper_order_snapshot_plan_from_row,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.schema import (
    phase2_account_leases,
    phase4_alpaca_paper_order_view_comparison_heads,
    phase4_alpaca_paper_order_view_comparisons,
)

ALPACA_PAPER_ORDER_VIEW_COMPARISON_PERSISTENCE_CONTRACT_VERSION = (
    "phase4p-authenticated-order-view-comparison-persistence-v1"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

OrderViewComparisonRow = Mapping[str, object] | RowMapping


class AlpacaPaperOrderViewComparisonPersistenceError(
    AlpacaPaperAuthenticatedOrderViewComparisonError
):
    """Durable authenticated order-view comparison history is unavailable."""


class AlpacaPaperOrderViewComparisonPersistenceConflict(
    AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
    AlpacaPaperOrderViewComparisonPersistenceError,
):
    """Durable comparison history conflicts with exact authenticated sources."""


class SqlAccountFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _required_text(row: OrderViewComparisonRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            f"persisted order-view comparison {field_name} must be nonempty text"
        )
    return value


def _optional_text(
    row: OrderViewComparisonRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            f"persisted order-view comparison {field_name} must be nonempty text or null"
        )
    return value


def _required_integer(row: OrderViewComparisonRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            f"persisted order-view comparison {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: OrderViewComparisonRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            f"persisted order-view comparison {field_name} must be a datetime"
        )
    return as_aware_utc(value)


@dataclass(frozen=True, slots=True)
class _LoadedOrderSnapshotSource:
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix
    head_sha256: str

    @property
    def committed_at(self) -> datetime:
        return self.prefix.page_receipts[-1].commit_fence_receipt.validated_at


def _load_source(
    connection: Connection,
    snapshot_id: str,
) -> _LoadedOrderSnapshotSource:
    try:
        plan_row = _snapshot_plan_row(connection, snapshot_id)
        if plan_row is None:
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison references a missing snapshot plan"
            )
        plan = alpaca_paper_order_snapshot_plan_from_row(plan_row)
        receipts = _snapshot_history(connection, plan)
        prefix = _alpaca_paper_authenticated_order_snapshot_prefix(
            plan,
            page_receipts=receipts,
        )
        head = _snapshot_head(connection, snapshot_id)
        if head is None:
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison source is missing its durable snapshot head"
            )
        capture = prefix.capture
        if (
            prefix.page_count == 0
            or not (capture.pagination_exhausted or capture.bounded_truncation)
            or prefix.next_page_description is not None
        ):
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison source is not an exact terminal snapshot prefix"
            )
        return _LoadedOrderSnapshotSource(
            prefix=prefix,
            head_sha256=head.semantic_sha256,
        )
    except AlpacaPaperOrderViewComparisonPersistenceError:
        raise
    except AlpacaPaperOrderSnapshotRuntimeError:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison source failed durable authentication"
        ) from None


def _fence_source(
    connection: Connection,
    row: OrderViewComparisonRow,
) -> AccountFenceReceipt:
    account_id = _required_text(row, "account_id")
    generation = _required_integer(row, "fence_fencing_generation")
    lease_sha256 = _required_text(row, "commit_fence_lease_sha256")
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
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison commit fence references a missing lease"
        )
    try:
        lease = account_lease_from_row(lease_row)
        validated_at = _required_datetime(row, "commit_fence_validated_at")
        valid_until = _required_datetime(row, "commit_fence_valid_until")
        receipt = _account_fence_receipt(
            fence=lease.fence,
            validated_at=validated_at,
            valid_until=valid_until,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
    except (AccountCoordinatorError, TypeError, ValueError):
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison commit fence source is malformed"
        ) from None
    if (
        lease.owner_id != _required_text(row, "fence_owner_id")
        or lease.lease_id != _required_text(row, "fence_lease_id")
        or lease.fencing_generation != generation
        or lease.fence.semantic_sha256 != _required_text(row, "fence_sha256")
        or lease.policy_sha256 != _required_text(row, "fence_policy_sha256")
        or valid_until != lease.expires_at
        or receipt.semantic_sha256 != _required_text(row, "commit_fence_receipt_sha256")
        or validated_at != _required_datetime(row, "recorded_at")
    ):
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison commit fence conflicts with its exact lease source"
        )
    try:
        _authenticate_fence_position_at(
            connection,
            receipt,
            checked_at=validated_at,
        )
    except Exception:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison commit fence position failed authentication"
        ) from None
    return receipt


def _source_values(
    *,
    phase: str,
    source: _LoadedOrderSnapshotSource,
    receipt: AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
) -> dict[str, object]:
    if phase not in {"earlier", "later"}:
        raise AssertionError("comparison source phase must be exact")
    prefix = source.prefix
    capture = prefix.capture
    terminal = prefix.page_receipts[-1]
    comparison = receipt.evidence.comparison
    return {
        f"{phase}_snapshot_id": prefix.plan.snapshot_id,
        f"{phase}_plan_sha256": prefix.plan.semantic_sha256,
        f"{phase}_head_sha256": (
            receipt.earlier_source_head_sha256
            if phase == "earlier"
            else receipt.later_source_head_sha256
        ),
        f"{phase}_prefix_id": prefix.prefix_id,
        f"{phase}_prefix_sha256": prefix.semantic_sha256,
        f"{phase}_capture_sha256": capture.semantic_sha256,
        f"{phase}_page_count": prefix.page_count,
        f"{phase}_tip_receipt_id": terminal.receipt_id,
        f"{phase}_tip_receipt_sha256": terminal.semantic_sha256,
        f"{phase}_tip_persisted_page_sha256": terminal.persisted_page.semantic_sha256,
        f"{phase}_source_committed_at": source.committed_at,
        f"{phase}_window_started_at": getattr(
            comparison,
            f"{phase}_window_started_at",
        ),
        f"{phase}_window_ended_at": getattr(
            comparison,
            f"{phase}_window_ended_at",
        ),
        f"{phase}_view_sha256": getattr(
            comparison,
            f"{phase}_view_sha256",
        ),
    }


def immutable_alpaca_paper_order_view_comparison_values(
    receipt: AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
    *,
    earlier_source: _LoadedOrderSnapshotSource,
    later_source: _LoadedOrderSnapshotSource,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one receipt."""

    if type(receipt) is not AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        raise AlpacaPaperOrderViewComparisonPersistenceError(
            "order-view comparison persistence requires an exact receipt"
        )
    receipt._validate()
    evidence = receipt.evidence
    comparison = evidence.comparison
    commit_fence = receipt.commit_fence_receipt
    if (
        earlier_source.prefix != evidence.earlier_prefix
        or later_source.prefix != evidence.later_prefix
        or earlier_source.head_sha256 != receipt.earlier_source_head_sha256
        or later_source.head_sha256 != receipt.later_source_head_sha256
    ):
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison receipt conflicts with transactionally loaded sources"
        )
    return {
        "receipt_id": receipt.receipt_id,
        "evidence_id": evidence.evidence_id,
        "comparison_id": comparison.comparison_id,
        "account_id": receipt.account_id,
        "account_sequence": receipt.account_sequence,
        "previous_receipt_sha256": receipt.previous_receipt_sha256,
        "fence_owner_id": commit_fence.fence.owner_id,
        "fence_lease_id": commit_fence.fence.lease_id,
        "fence_fencing_generation": commit_fence.fence.fencing_generation,
        "fence_sha256": commit_fence.fence.semantic_sha256,
        "fence_policy_sha256": commit_fence.policy_sha256,
        "commit_fence_lease_sha256": commit_fence.lease_sha256,
        "commit_fence_receipt_sha256": commit_fence.semantic_sha256,
        "commit_fence_validated_at": commit_fence.validated_at,
        "commit_fence_valid_until": commit_fence.valid_until,
        "authentication_policy_sha256": (
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256
        ),
        "comparison_policy_sha256": (ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256),
        "traversal_profile_sha256": evidence.traversal_profile_sha256,
        **_source_values(
            phase="earlier",
            source=earlier_source,
            receipt=receipt,
        ),
        **_source_values(
            phase="later",
            source=later_source,
            receipt=receipt,
        ),
        "observed_utc_separation_microseconds": str(
            comparison.observed_utc_separation_microseconds
        ),
        "disposition": comparison.disposition.value,
        "added_provider_order_ids_payload": canonical_json_text(
            comparison.added_provider_order_ids
        ),
        "removed_provider_order_ids_payload": canonical_json_text(
            comparison.removed_provider_order_ids
        ),
        "changed_provider_order_ids_payload": canonical_json_text(
            comparison.changed_provider_order_ids
        ),
        "added_count": len(comparison.added_provider_order_ids),
        "removed_count": len(comparison.removed_provider_order_ids),
        "changed_count": len(comparison.changed_provider_order_ids),
        "comparison_sha256": comparison.semantic_sha256,
        "evidence_sha256": evidence.semantic_sha256,
        "recorded_at": receipt.recorded_at,
        "canonical_payload": receipt.canonical_json,
        "semantic_sha256": receipt.semantic_sha256,
    }


def alpaca_paper_order_view_comparison_from_row(
    connection: Connection,
    row: OrderViewComparisonRow,
) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
    """Reconstruct one receipt only from its authenticated durable sources."""

    try:
        earlier_source = _load_source(
            connection,
            _required_text(row, "earlier_snapshot_id"),
        )
        later_source = _load_source(
            connection,
            _required_text(row, "later_snapshot_id"),
        )
        evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
            earlier_prefix=earlier_source.prefix,
            later_prefix=later_source.prefix,
        )
        commit_fence = _fence_source(connection, row)
        receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256=earlier_source.head_sha256,
            later_source_head_sha256=later_source.head_sha256,
            commit_fence_receipt=commit_fence,
            account_sequence=_required_integer(row, "account_sequence"),
            previous_receipt_sha256=_optional_text(
                row,
                "previous_receipt_sha256",
            ),
        )
        expected = immutable_alpaca_paper_order_view_comparison_values(
            receipt,
            earlier_source=earlier_source,
            later_source=later_source,
        )
        assert_immutable(
            phase4_alpaca_paper_order_view_comparisons,
            receipt.receipt_id,
            row,
            expected,
        )
        return receipt
    except AlpacaPaperOrderViewComparisonPersistenceError:
        raise
    except (
        AlpacaPaperAuthenticatedOrderViewComparisonError,
        ImmutableFactConflict,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "persisted order-view comparison failed exact source reconstruction"
        ) from None


@dataclass(frozen=True, slots=True)
class _OrderViewComparisonHead:
    account_id: str
    last_account_sequence: int
    last_receipt_id: str
    last_receipt_sha256: str
    last_recorded_at: datetime

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ORDER_VIEW_COMPARISON_PERSISTENCE_CONTRACT_VERSION,
            "order_view_comparison_head",
            self.account_id,
            self.last_account_sequence,
            self.last_receipt_id,
            self.last_receipt_sha256,
            self.last_recorded_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _head_for_receipt(
    receipt: AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
) -> _OrderViewComparisonHead:
    return _OrderViewComparisonHead(
        account_id=receipt.account_id,
        last_account_sequence=receipt.account_sequence,
        last_receipt_id=receipt.receipt_id,
        last_receipt_sha256=receipt.semantic_sha256,
        last_recorded_at=receipt.recorded_at,
    )


def _head_values(head: _OrderViewComparisonHead) -> dict[str, object]:
    return {
        "account_id": head.account_id,
        "last_account_sequence": head.last_account_sequence,
        "last_receipt_id": head.last_receipt_id,
        "last_receipt_sha256": head.last_receipt_sha256,
        "last_recorded_at": head.last_recorded_at,
        "canonical_payload": head.canonical_json,
        "semantic_sha256": head.semantic_sha256,
    }


def _head_from_row(row: OrderViewComparisonRow) -> _OrderViewComparisonHead:
    try:
        head = _OrderViewComparisonHead(
            account_id=_required_text(row, "account_id"),
            last_account_sequence=_required_integer(
                row,
                "last_account_sequence",
            ),
            last_receipt_id=_required_text(row, "last_receipt_id"),
            last_receipt_sha256=_required_text(
                row,
                "last_receipt_sha256",
            ),
            last_recorded_at=_required_datetime(row, "last_recorded_at"),
        )
        if (
            head.last_account_sequence <= 0
            or _required_text(row, "canonical_payload") != head.canonical_json
            or _required_text(row, "semantic_sha256") != head.semantic_sha256
        ):
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "persisted order-view comparison head conflicts with its canonical value"
            )
        return head
    except AlpacaPaperOrderViewComparisonPersistenceError:
        raise
    except (KeyError, TypeError, ValueError):
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "persisted order-view comparison head is malformed"
        ) from None


def _head(
    connection: Connection,
    account_id: str,
) -> _OrderViewComparisonHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_order_view_comparison_heads).where(
                phase4_alpaca_paper_order_view_comparison_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _receipt_by_id(
    connection: Connection,
    receipt_id: str,
) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_order_view_comparisons).where(
                phase4_alpaca_paper_order_view_comparisons.c.receipt_id == receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_order_view_comparison_from_row(connection, row)


def _existing_receipt(
    connection: Connection,
    evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None:
    predicates = (
        phase4_alpaca_paper_order_view_comparisons.c.evidence_id == evidence.evidence_id,
        phase4_alpaca_paper_order_view_comparisons.c.comparison_id
        == evidence.comparison.comparison_id,
        sa.and_(
            phase4_alpaca_paper_order_view_comparisons.c.earlier_snapshot_id
            == evidence.earlier_plan_id,
            phase4_alpaca_paper_order_view_comparisons.c.later_snapshot_id
            == evidence.later_plan_id,
            phase4_alpaca_paper_order_view_comparisons.c.authentication_policy_sha256
            == ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
        ),
    )
    rows = tuple(
        (
            connection.execute(
                sa.select(phase4_alpaca_paper_order_view_comparisons).where(predicate)
            )
            .mappings()
            .one_or_none()
        )
        for predicate in predicates
    )
    present = tuple(row for row in rows if row is not None)
    if not present:
        return None
    receipt_ids = {_required_text(row, "receipt_id") for row in present}
    if len(present) != len(rows) or len(receipt_ids) != 1:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison identity or source pair was reused"
        )
    receipt = alpaca_paper_order_view_comparison_from_row(
        connection,
        present[0],
    )
    if receipt.evidence != evidence:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison retry conflicts with durable evidence"
        )
    return receipt


def _validate_history(
    connection: Connection,
    *,
    account_id: str,
    rows: tuple[RowMapping, ...],
    head: _OrderViewComparisonHead | None,
) -> tuple[AlpacaPaperAuthenticatedOrderViewComparisonReceipt, ...]:
    result: list[AlpacaPaperAuthenticatedOrderViewComparisonReceipt] = []
    previous: AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        receipt = alpaca_paper_order_view_comparison_from_row(connection, row)
        if (
            receipt.account_id != account_id
            or receipt.account_sequence != expected_sequence
            or receipt.previous_receipt_sha256
            != (None if previous is None else previous.semantic_sha256)
            or (previous is not None and receipt.recorded_at < previous.recorded_at)
        ):
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison account history is discontinuous"
            )
        result.append(receipt)
        previous = receipt
    if previous is None:
        if head is not None:
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison head exists without durable receipts"
            )
        return ()
    expected_head = _head_for_receipt(previous)
    if head != expected_head:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison head conflicts with terminal history"
        )
    return tuple(result)


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[AlpacaPaperAuthenticatedOrderViewComparisonReceipt, ...]:
    rows = tuple(
        connection.execute(
            sa.select(phase4_alpaca_paper_order_view_comparisons)
            .where(phase4_alpaca_paper_order_view_comparisons.c.account_id == account_id)
            .order_by(phase4_alpaca_paper_order_view_comparisons.c.account_sequence)
        )
        .mappings()
        .all()
    )
    return _validate_history(
        connection,
        account_id=account_id,
        rows=rows,
        head=_head(connection, account_id),
    )


def _verify_alpaca_paper_order_view_comparison_integrity(
    connection: Connection,
) -> None:
    comparison_without_head = connection.scalar(
        sa.select(phase4_alpaca_paper_order_view_comparisons.c.receipt_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_order_view_comparison_heads.c.account_id
                    == phase4_alpaca_paper_order_view_comparisons.c.account_id
                )
            )
        )
        .limit(1)
    )
    if comparison_without_head is not None:
        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
            "order-view comparison receipts exist without durable account heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_alpaca_paper_order_view_comparison_heads)
        .order_by(phase4_alpaca_paper_order_view_comparison_heads.c.account_id)
        .execution_options(yield_per=64)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        rows = tuple(
            connection.execute(
                sa.select(phase4_alpaca_paper_order_view_comparisons)
                .where(phase4_alpaca_paper_order_view_comparisons.c.account_id == head.account_id)
                .order_by(phase4_alpaca_paper_order_view_comparisons.c.account_sequence)
                .execution_options(yield_per=64)
            )
            .mappings()
            .all()
        )
        _validate_history(
            connection,
            account_id=head.account_id,
            rows=rows,
            head=head,
        )


def verify_alpaca_paper_order_view_comparison_integrity(
    engine: Engine,
) -> None:
    """Authenticate every durable comparison chain in one stable read."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperOrderViewComparisonPersistenceError(
            "order-view comparison verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperOrderViewComparisonPersistenceError(
            f"order-view comparison verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_order_view_comparison_integrity(connection)


class SqlAlpacaPaperOrderViewComparisonRepository:
    """Append exact authenticated comparisons under the shared account lock."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                "SQL order-view comparisons require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                f"SQL order-view comparisons do not support dialect {engine.dialect.name!r}"
            )
        if not callable(
            getattr(
                coordinator,
                "revalidate_for_commit_in_transaction",
                None,
            )
        ):
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                "SQL order-view comparisons require a SQL fence validator"
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
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison commit fence validation failed"
            ) from None

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        """Append authenticated evidence or return its identical retry."""

        if type(evidence) is not AlpacaPaperAuthenticatedOrderViewComparisonEvidence:
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                "order-view comparison recording requires exact evidence"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                "order-view comparison recording requires an exact account fence"
            )
        evidence._validate()
        fence.__post_init__()
        if fence.account_id != evidence.account_id:
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "order-view comparison fence crosses account identities"
            )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    evidence.account_id,
                )
                history = _history(connection, evidence.account_id)
                previous = None if not history else history[-1]
                earlier_source = _load_source(
                    connection,
                    evidence.earlier_plan_id,
                )
                later_source = _load_source(
                    connection,
                    evidence.later_plan_id,
                )
                expected_evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
                    earlier_prefix=earlier_source.prefix,
                    later_prefix=later_source.prefix,
                )
                if expected_evidence != evidence:
                    raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                        "order-view comparison evidence conflicts with durable sources"
                    )
                commit_fence = self._commit_fence(connection, fence)
                existing = _existing_receipt(connection, expected_evidence)
                if existing is not None:
                    if existing not in history:
                        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                            "order-view comparison retry exists outside account history"
                        )
                    return existing

                receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
                    expected_evidence,
                    earlier_source_head_sha256=earlier_source.head_sha256,
                    later_source_head_sha256=later_source.head_sha256,
                    commit_fence_receipt=commit_fence,
                    account_sequence=(1 if previous is None else previous.account_sequence + 1),
                    previous_receipt_sha256=(
                        None if previous is None else previous.semantic_sha256
                    ),
                )
                if previous is not None and receipt.recorded_at < previous.recorded_at:
                    raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                        "order-view comparison commit clock regressed"
                    )
                if _receipt_by_id(connection, receipt.receipt_id) is not None:
                    raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                        "order-view comparison receipt identity was reused"
                    )
                values = immutable_alpaca_paper_order_view_comparison_values(
                    receipt,
                    earlier_source=earlier_source,
                    later_source=later_source,
                )
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_order_view_comparisons).values(**values)
                    )
                except IntegrityError:
                    raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                        "order-view comparison conflicts with durable history"
                    ) from None

                next_head = _head_for_receipt(receipt)
                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_alpaca_paper_order_view_comparison_heads).values(
                                **_head_values(next_head)
                            )
                        )
                    except IntegrityError:
                        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                            "order-view comparison head conflicts with durable history"
                        ) from None
                else:
                    previous_head = _head_for_receipt(previous)
                    updated = connection.execute(
                        sa.update(phase4_alpaca_paper_order_view_comparison_heads)
                        .where(
                            phase4_alpaca_paper_order_view_comparison_heads.c.account_id
                            == previous_head.account_id,
                            phase4_alpaca_paper_order_view_comparison_heads.c.semantic_sha256
                            == previous_head.semantic_sha256,
                            phase4_alpaca_paper_order_view_comparison_heads.c.last_account_sequence
                            == previous_head.last_account_sequence,
                            phase4_alpaca_paper_order_view_comparison_heads.c.last_receipt_id
                            == previous_head.last_receipt_id,
                            phase4_alpaca_paper_order_view_comparison_heads.c.last_receipt_sha256
                            == previous_head.last_receipt_sha256,
                            phase4_alpaca_paper_order_view_comparison_heads.c.last_recorded_at
                            == previous_head.last_recorded_at,
                        )
                        .values(**_head_values(next_head))
                    )
                    if updated.rowcount != 1:
                        raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                            "order-view comparison head changed during append"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_alpaca_paper_order_view_comparisons).where(
                            phase4_alpaca_paper_order_view_comparisons.c.receipt_id
                            == receipt.receipt_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = alpaca_paper_order_view_comparison_from_row(
                    connection,
                    row,
                )
                if persisted != receipt:
                    raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                        "order-view comparison failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_alpaca_paper_order_view_comparisons,
                    receipt.receipt_id,
                    row,
                    values,
                )
                terminal_history = _history(connection, receipt.account_id)
                if not terminal_history or terminal_history[-1] != receipt:
                    raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                        "order-view comparison head failed exact SQL readback"
                    )
                return persisted
        except AlpacaPaperAuthenticatedOrderViewComparisonError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperOrderSnapshotRuntimeError,
            ImmutableFactConflict,
            IntegrityError,
            SQLAlchemyError,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                "durable order-view comparison append failed"
            ) from None

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None:
        """Load and authenticate one durable comparison receipt."""

        if type(receipt_id) is not str or not receipt_id:
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                "order-view comparison receipt ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            receipt = _receipt_by_id(connection, receipt_id)
            if receipt is None:
                return None
            history = _history(connection, receipt.account_id)
            if receipt not in history:
                raise AlpacaPaperOrderViewComparisonPersistenceConflict(
                    "order-view comparison receipt exists outside its account history"
                )
            return receipt

    def history(
        self,
        account_id: str,
    ) -> tuple[AlpacaPaperAuthenticatedOrderViewComparisonReceipt, ...]:
        """Load one complete authenticated account-local comparison chain."""

        if type(account_id) is not str or not account_id:
            raise AlpacaPaperOrderViewComparisonPersistenceError(
                "order-view comparison account ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            return _history(connection, account_id)


__all__ = [
    "ALPACA_PAPER_ORDER_VIEW_COMPARISON_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperOrderViewComparisonPersistenceConflict",
    "AlpacaPaperOrderViewComparisonPersistenceError",
    "SqlAlpacaPaperOrderViewComparisonRepository",
    "alpaca_paper_order_view_comparison_from_row",
    "immutable_alpaca_paper_order_view_comparison_values",
    "verify_alpaca_paper_order_view_comparison_integrity",
]
