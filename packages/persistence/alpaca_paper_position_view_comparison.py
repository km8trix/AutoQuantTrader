"""Restart-safe persistence for authenticated Alpaca paper position comparisons."""

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

from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotRuntimeError,
)
from packages.application.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedPositionViewComparisonError,
    AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
    AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
    _alpaca_paper_authenticated_position_view_comparison_evidence,
    _alpaca_paper_authenticated_position_view_comparison_receipt,
    create_authenticated_alpaca_paper_position_view_comparison_plan,
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
from packages.persistence.alpaca_paper_position_snapshot import (
    AlpacaPaperPositionSnapshotPersistenceError,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    _plan_and_preparation_from_row as _position_plan_from_row,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    _plan_row as _position_plan_row,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    _receipt_from_row as _position_receipt_from_row,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    _snapshot_row as _position_snapshot_row,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.schema import (
    phase2_account_leases,
    phase4_alpaca_paper_position_view_comparison_heads,
    phase4_alpaca_paper_position_view_comparisons,
)

ALPACA_PAPER_POSITION_VIEW_COMPARISON_PERSISTENCE_CONTRACT_VERSION = (
    "phase4v-authenticated-position-view-comparison-persistence-v1"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

PositionViewComparisonRow = Mapping[str, object] | RowMapping


class AlpacaPaperPositionViewComparisonPersistenceError(
    AlpacaPaperAuthenticatedPositionViewComparisonError
):
    """Durable authenticated position-view comparison history is unavailable."""


class AlpacaPaperPositionViewComparisonPersistenceConflict(
    AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
    AlpacaPaperPositionViewComparisonPersistenceError,
):
    """Durable history conflicts with exact authenticated position sources."""


class SqlPositionViewComparisonFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


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


def _required_text(
    row: PositionViewComparisonRow,
    field_name: str,
) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            f"persisted position-view comparison {field_name} must be nonempty text"
        )
    return value


def _optional_text(
    row: PositionViewComparisonRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            f"persisted position-view comparison {field_name} must be nonempty text or null"
        )
    return value


def _required_integer(
    row: PositionViewComparisonRow,
    field_name: str,
) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            f"persisted position-view comparison {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: PositionViewComparisonRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            f"persisted position-view comparison {field_name} must be a datetime"
        )
    return as_aware_utc(value)


@dataclass(frozen=True, slots=True)
class _LoadedPositionSnapshotSource:
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt

    @property
    def committed_at(self) -> datetime:
        return self.receipt.commit_fence_receipt.validated_at


def _load_source(
    connection: Connection,
    *,
    plan_id: str,
    capture_id: str,
) -> _LoadedPositionSnapshotSource:
    """Reconstruct one complete Phase 4U receipt from all durable sources."""

    try:
        plan_row = _position_plan_row(
            connection,
            plan_id=plan_id,
            capture_id=capture_id,
        )
        snapshot_row = _position_snapshot_row(
            connection,
            plan_id=plan_id,
            capture_id=capture_id,
        )
        if plan_row is None:
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison references a missing snapshot plan"
            )
        if snapshot_row is None:
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison source is not a complete durable snapshot"
            )
        plan, preparation = _position_plan_from_row(connection, plan_row)
        receipt = _position_receipt_from_row(
            connection,
            snapshot_row,
            plan,
            preparation,
        )
        if (
            receipt.plan.plan_id != plan_id
            or receipt.capture_id != capture_id
            or not receipt.durable_authenticated_position_snapshot_established
        ):
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison source failed exact durable authentication"
            )
        return _LoadedPositionSnapshotSource(receipt=receipt)
    except AlpacaPaperPositionViewComparisonPersistenceError:
        raise
    except (
        AlpacaPaperPositionSnapshotPersistenceError,
        AlpacaPaperPositionSnapshotRuntimeError,
    ):
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison source failed durable authentication"
        ) from None


def _fence_source(
    connection: Connection,
    row: PositionViewComparisonRow,
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
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison commit fence references a missing lease"
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
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison commit fence source is malformed"
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
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison commit fence conflicts with its exact lease source"
        )
    try:
        _authenticate_fence_position_at(
            connection,
            receipt,
            checked_at=validated_at,
        )
    except Exception:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison commit fence position failed authentication"
        ) from None
    return receipt


def _source_values(
    *,
    phase: str,
    source: _LoadedPositionSnapshotSource,
    receipt: AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
) -> dict[str, object]:
    if phase not in {"earlier", "later"}:
        raise AssertionError("position-view comparison source phase must be exact")
    source_receipt = source.receipt
    snapshot = source_receipt.persisted_snapshot
    ingress = snapshot.receipt
    comparison = receipt.evidence.comparison
    return {
        f"{phase}_snapshot_receipt_id": source_receipt.receipt_id,
        f"{phase}_snapshot_receipt_sha256": source_receipt.semantic_sha256,
        f"{phase}_plan_id": source_receipt.plan.plan_id,
        f"{phase}_plan_sha256": source_receipt.plan.semantic_sha256,
        f"{phase}_capture_id": source_receipt.capture_id,
        f"{phase}_persisted_snapshot_sha256": snapshot.semantic_sha256,
        f"{phase}_ingress_receipt_id": ingress.receipt_id,
        f"{phase}_ingress_receipt_sha256": ingress.semantic_sha256,
        f"{phase}_ingress_sequence": ingress.ingress_sequence,
        f"{phase}_source_committed_at": source.committed_at,
        f"{phase}_received_at": snapshot.observation.received_at,
        f"{phase}_view_sha256": getattr(
            comparison,
            f"{phase}_view_sha256",
        ),
    }


def immutable_alpaca_paper_position_view_comparison_values(
    receipt: AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
    *,
    earlier_source: _LoadedPositionSnapshotSource,
    later_source: _LoadedPositionSnapshotSource,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one receipt."""

    if type(receipt) is not AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        raise AlpacaPaperPositionViewComparisonPersistenceError(
            "position-view comparison persistence requires an exact receipt"
        )
    receipt._validate()
    evidence = receipt.evidence
    plan = evidence.plan
    comparison = evidence.comparison
    commit_fence = receipt.commit_fence_receipt
    if (
        earlier_source.receipt != evidence.earlier_receipt
        or later_source.receipt != evidence.later_receipt
    ):
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison receipt conflicts with loaded sources"
        )
    return {
        "receipt_id": receipt.receipt_id,
        "evidence_id": evidence.evidence_id,
        "comparison_id": comparison.comparison_id,
        "comparison_plan_id": plan.comparison_plan_id,
        "comparison_plan_sha256": plan.semantic_sha256,
        "account_id": receipt.account_id,
        "expected_provider_account_id": plan.expected_provider_account_id,
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
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256
        ),
        "comparison_policy_sha256": (ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256),
        "capture_profile_sha256": evidence.capture_profile_sha256,
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
        "added_asset_ids_payload": canonical_json_text(comparison.added_asset_ids),
        "removed_asset_ids_payload": canonical_json_text(comparison.removed_asset_ids),
        "changed_asset_ids_payload": canonical_json_text(comparison.changed_asset_ids),
        "added_count": len(comparison.added_asset_ids),
        "removed_count": len(comparison.removed_asset_ids),
        "changed_count": len(comparison.changed_asset_ids),
        "comparison_sha256": comparison.semantic_sha256,
        "evidence_sha256": evidence.semantic_sha256,
        "recorded_at": receipt.recorded_at,
        "canonical_payload": receipt.canonical_json,
        "semantic_sha256": receipt.semantic_sha256,
    }


def alpaca_paper_position_view_comparison_from_row(
    connection: Connection,
    row: PositionViewComparisonRow,
) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
    """Reconstruct one receipt only from fully authenticated durable sources."""

    try:
        earlier_source = _load_source(
            connection,
            plan_id=_required_text(row, "earlier_plan_id"),
            capture_id=_required_text(row, "earlier_capture_id"),
        )
        later_source = _load_source(
            connection,
            plan_id=_required_text(row, "later_plan_id"),
            capture_id=_required_text(row, "later_capture_id"),
        )
        plan = create_authenticated_alpaca_paper_position_view_comparison_plan(
            earlier_plan=earlier_source.receipt.plan,
            later_plan=later_source.receipt.plan,
        )
        evidence = _alpaca_paper_authenticated_position_view_comparison_evidence(
            plan=plan,
            earlier_receipt=earlier_source.receipt,
            later_receipt=later_source.receipt,
        )
        commit_fence = _fence_source(connection, row)
        receipt = _alpaca_paper_authenticated_position_view_comparison_receipt(
            evidence,
            commit_fence_receipt=commit_fence,
            account_sequence=_required_integer(row, "account_sequence"),
            previous_receipt_sha256=_optional_text(
                row,
                "previous_receipt_sha256",
            ),
        )
        expected = immutable_alpaca_paper_position_view_comparison_values(
            receipt,
            earlier_source=earlier_source,
            later_source=later_source,
        )
        assert_immutable(
            phase4_alpaca_paper_position_view_comparisons,
            receipt.receipt_id,
            row,
            expected,
        )
        return receipt
    except AlpacaPaperPositionViewComparisonPersistenceError:
        raise
    except (
        AlpacaPaperAuthenticatedPositionViewComparisonError,
        AlpacaPaperPositionSnapshotPersistenceError,
        AlpacaPaperPositionSnapshotRuntimeError,
        ImmutableFactConflict,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "persisted position-view comparison failed exact source reconstruction"
        ) from None


@dataclass(frozen=True, slots=True)
class _PositionViewComparisonHead:
    account_id: str
    last_account_sequence: int
    last_receipt_id: str
    last_receipt_sha256: str
    last_recorded_at: datetime

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_POSITION_VIEW_COMPARISON_PERSISTENCE_CONTRACT_VERSION,
            "position_view_comparison_head",
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
    receipt: AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
) -> _PositionViewComparisonHead:
    return _PositionViewComparisonHead(
        account_id=receipt.account_id,
        last_account_sequence=receipt.account_sequence,
        last_receipt_id=receipt.receipt_id,
        last_receipt_sha256=receipt.semantic_sha256,
        last_recorded_at=receipt.recorded_at,
    )


def _head_values(
    head: _PositionViewComparisonHead,
) -> dict[str, object]:
    return {
        "account_id": head.account_id,
        "last_account_sequence": head.last_account_sequence,
        "last_receipt_id": head.last_receipt_id,
        "last_receipt_sha256": head.last_receipt_sha256,
        "last_recorded_at": head.last_recorded_at,
        "canonical_payload": head.canonical_json,
        "semantic_sha256": head.semantic_sha256,
    }


def _head_from_row(
    row: PositionViewComparisonRow,
) -> _PositionViewComparisonHead:
    try:
        head = _PositionViewComparisonHead(
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
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "persisted position-view comparison head conflicts with canonical value"
            )
        return head
    except AlpacaPaperPositionViewComparisonPersistenceError:
        raise
    except (KeyError, TypeError, ValueError):
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "persisted position-view comparison head is malformed"
        ) from None


def _head(
    connection: Connection,
    account_id: str,
) -> _PositionViewComparisonHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_position_view_comparison_heads).where(
                phase4_alpaca_paper_position_view_comparison_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _receipt_by_id(
    connection: Connection,
    receipt_id: str,
) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_position_view_comparisons).where(
                phase4_alpaca_paper_position_view_comparisons.c.receipt_id == receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else alpaca_paper_position_view_comparison_from_row(connection, row)


def _existing_receipt(
    connection: Connection,
    evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None:
    table = phase4_alpaca_paper_position_view_comparisons
    predicates = (
        table.c.evidence_id == evidence.evidence_id,
        table.c.comparison_id == evidence.comparison.comparison_id,
        table.c.comparison_plan_id == evidence.plan.comparison_plan_id,
        sa.and_(
            table.c.earlier_plan_id == evidence.plan.earlier_plan.plan_id,
            table.c.later_plan_id == evidence.plan.later_plan.plan_id,
            table.c.authentication_policy_sha256
            == ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
        ),
    )
    rows = tuple(
        (connection.execute(sa.select(table).where(predicate)).mappings().one_or_none())
        for predicate in predicates
    )
    present = tuple(row for row in rows if row is not None)
    if not present:
        return None
    receipt_ids = {_required_text(row, "receipt_id") for row in present}
    if len(present) != len(rows) or len(receipt_ids) != 1:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison identity or source pair was reused"
        )
    receipt = alpaca_paper_position_view_comparison_from_row(
        connection,
        present[0],
    )
    if receipt.evidence != evidence:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison retry conflicts with durable evidence"
        )
    return receipt


def _validate_history(
    connection: Connection,
    *,
    account_id: str,
    rows: tuple[RowMapping, ...],
    head: _PositionViewComparisonHead | None,
) -> tuple[AlpacaPaperAuthenticatedPositionViewComparisonReceipt, ...]:
    result: list[AlpacaPaperAuthenticatedPositionViewComparisonReceipt] = []
    previous: AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        receipt = alpaca_paper_position_view_comparison_from_row(
            connection,
            row,
        )
        if (
            receipt.account_id != account_id
            or receipt.account_sequence != expected_sequence
            or receipt.previous_receipt_sha256
            != (None if previous is None else previous.semantic_sha256)
            or (previous is not None and receipt.recorded_at < previous.recorded_at)
        ):
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison account history is discontinuous"
            )
        result.append(receipt)
        previous = receipt
    if previous is None:
        if head is not None:
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison head exists without durable receipts"
            )
        return ()
    if head != _head_for_receipt(previous):
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison head conflicts with terminal history"
        )
    return tuple(result)


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[AlpacaPaperAuthenticatedPositionViewComparisonReceipt, ...]:
    rows = tuple(
        connection.execute(
            sa.select(phase4_alpaca_paper_position_view_comparisons)
            .where(phase4_alpaca_paper_position_view_comparisons.c.account_id == account_id)
            .order_by(phase4_alpaca_paper_position_view_comparisons.c.account_sequence)
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


def _verify_alpaca_paper_position_view_comparison_integrity(
    connection: Connection,
) -> None:
    receipt_without_head = connection.scalar(
        sa.select(phase4_alpaca_paper_position_view_comparisons.c.receipt_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_position_view_comparison_heads.c.account_id
                    == phase4_alpaca_paper_position_view_comparisons.c.account_id
                )
            )
        )
        .limit(1)
    )
    if receipt_without_head is not None:
        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
            "position-view comparison receipts exist without durable account heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_alpaca_paper_position_view_comparison_heads)
        .order_by(phase4_alpaca_paper_position_view_comparison_heads.c.account_id)
        .execution_options(yield_per=64)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        rows = tuple(
            connection.execute(
                sa.select(phase4_alpaca_paper_position_view_comparisons)
                .where(
                    phase4_alpaca_paper_position_view_comparisons.c.account_id == head.account_id
                )
                .order_by(phase4_alpaca_paper_position_view_comparisons.c.account_sequence)
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


def verify_alpaca_paper_position_view_comparison_integrity(
    engine: Engine,
) -> None:
    """Authenticate every durable comparison chain in one stable read."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperPositionViewComparisonPersistenceError(
            "position-view comparison verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperPositionViewComparisonPersistenceError(
            "position-view comparison verification does not support dialect "
            f"{engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_position_view_comparison_integrity(connection)


class SqlAlpacaPaperPositionViewComparisonRepository:
    """Append exact authenticated comparisons under the shared account lock."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlPositionViewComparisonFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                "SQL position-view comparisons require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                f"SQL position-view comparisons do not support dialect {engine.dialect.name!r}"
            )
        if not callable(
            getattr(
                coordinator,
                "revalidate_for_commit_in_transaction",
                None,
            )
        ):
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                "SQL position-view comparisons require a SQL fence validator"
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
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison current call fence validation failed"
            ) from None

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        """Append evidence or return its historical receipt after fresh checks."""

        if type(evidence) is not AlpacaPaperAuthenticatedPositionViewComparisonEvidence:
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                "position-view comparison recording requires exact evidence"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                "position-view comparison recording requires an exact account fence"
            )
        evidence._validate()
        fence.__post_init__()
        if fence.account_id != evidence.account_id:
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "position-view comparison fence crosses account identities"
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
                    plan_id=evidence.plan.earlier_plan.plan_id,
                    capture_id=(evidence.plan.earlier_plan.description.capture_id),
                )
                later_source = _load_source(
                    connection,
                    plan_id=evidence.plan.later_plan.plan_id,
                    capture_id=evidence.plan.later_plan.description.capture_id,
                )
                expected_plan = create_authenticated_alpaca_paper_position_view_comparison_plan(
                    earlier_plan=earlier_source.receipt.plan,
                    later_plan=later_source.receipt.plan,
                )
                expected_evidence = _alpaca_paper_authenticated_position_view_comparison_evidence(
                    plan=expected_plan,
                    earlier_receipt=earlier_source.receipt,
                    later_receipt=later_source.receipt,
                )
                if expected_evidence != evidence:
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison evidence conflicts with durable sources"
                    )

                # Exact retries still authenticate the current call fence here.
                # The returned historical receipt retains its original fence.
                commit_fence = self._commit_fence(connection, fence)
                existing = _existing_receipt(connection, expected_evidence)
                if existing is not None:
                    if existing not in history:
                        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                            "position-view comparison retry exists outside account history"
                        )
                    return existing

                receipt = _alpaca_paper_authenticated_position_view_comparison_receipt(
                    expected_evidence,
                    commit_fence_receipt=commit_fence,
                    account_sequence=(1 if previous is None else previous.account_sequence + 1),
                    previous_receipt_sha256=(
                        None if previous is None else previous.semantic_sha256
                    ),
                )
                if previous is not None and receipt.recorded_at < previous.recorded_at:
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison commit clock regressed"
                    )
                if _receipt_by_id(connection, receipt.receipt_id) is not None:
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison receipt identity was reused"
                    )
                values = immutable_alpaca_paper_position_view_comparison_values(
                    receipt,
                    earlier_source=earlier_source,
                    later_source=later_source,
                )
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_position_view_comparisons).values(**values)
                    )
                except IntegrityError:
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison conflicts with durable history"
                    ) from None

                next_head = _head_for_receipt(receipt)
                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_alpaca_paper_position_view_comparison_heads).values(
                                **_head_values(next_head)
                            )
                        )
                    except IntegrityError:
                        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                            "position-view comparison head conflicts with durable history"
                        ) from None
                else:
                    previous_head = _head_for_receipt(previous)
                    updated = connection.execute(
                        sa.update(phase4_alpaca_paper_position_view_comparison_heads)
                        .where(
                            phase4_alpaca_paper_position_view_comparison_heads.c.account_id
                            == previous_head.account_id,
                            phase4_alpaca_paper_position_view_comparison_heads.c.semantic_sha256
                            == previous_head.semantic_sha256,
                            phase4_alpaca_paper_position_view_comparison_heads.c.last_account_sequence
                            == previous_head.last_account_sequence,
                            phase4_alpaca_paper_position_view_comparison_heads.c.last_receipt_id
                            == previous_head.last_receipt_id,
                            phase4_alpaca_paper_position_view_comparison_heads.c.last_receipt_sha256
                            == previous_head.last_receipt_sha256,
                            phase4_alpaca_paper_position_view_comparison_heads.c.last_recorded_at
                            == previous_head.last_recorded_at,
                        )
                        .values(**_head_values(next_head))
                    )
                    if updated.rowcount != 1:
                        raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                            "position-view comparison head changed during append"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_alpaca_paper_position_view_comparisons).where(
                            phase4_alpaca_paper_position_view_comparisons.c.receipt_id
                            == receipt.receipt_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = alpaca_paper_position_view_comparison_from_row(
                    connection,
                    row,
                )
                if persisted != receipt:
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_alpaca_paper_position_view_comparisons,
                    receipt.receipt_id,
                    row,
                    values,
                )
                terminal_history = _history(
                    connection,
                    receipt.account_id,
                )
                if not terminal_history or terminal_history[-1] != receipt:
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison head failed exact SQL readback"
                    )
                final_fence = self._commit_fence(connection, fence)
                if not (
                    _same_fence_lease(commit_fence, final_fence)
                    and commit_fence.validated_at
                    <= final_fence.validated_at
                    < final_fence.valid_until
                ):
                    raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                        "position-view comparison fence changed before final commit"
                    )
                return persisted
        except AlpacaPaperAuthenticatedPositionViewComparisonError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperPositionSnapshotPersistenceError,
            AlpacaPaperPositionSnapshotRuntimeError,
            ImmutableFactConflict,
            IntegrityError,
            SQLAlchemyError,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                "durable position-view comparison append failed"
            ) from None

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None:
        """Load and authenticate one receipt and its complete account chain."""

        if type(receipt_id) is not str or not receipt_id:
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                "position-view comparison receipt ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            receipt = _receipt_by_id(connection, receipt_id)
            if receipt is None:
                return None
            history = _history(connection, receipt.account_id)
            if receipt not in history:
                raise AlpacaPaperPositionViewComparisonPersistenceConflict(
                    "position-view comparison receipt exists outside account history"
                )
            return receipt

    def history(
        self,
        account_id: str,
    ) -> tuple[AlpacaPaperAuthenticatedPositionViewComparisonReceipt, ...]:
        """Load one complete authenticated account-local comparison chain."""

        if type(account_id) is not str or not account_id:
            raise AlpacaPaperPositionViewComparisonPersistenceError(
                "position-view comparison account ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            return _history(connection, account_id)


__all__ = [
    "ALPACA_PAPER_POSITION_VIEW_COMPARISON_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperPositionViewComparisonPersistenceConflict",
    "AlpacaPaperPositionViewComparisonPersistenceError",
    "SqlAlpacaPaperPositionViewComparisonRepository",
    "alpaca_paper_position_view_comparison_from_row",
    "immutable_alpaca_paper_position_view_comparison_values",
    "verify_alpaca_paper_position_view_comparison_integrity",
]
