"""Restart-safe persistence for authenticated Alpaca paper activity comparisons."""

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

from packages.adapters.broker.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
    _timedelta_microseconds,
    _utc_separation,
    _view_sha256,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    AlpacaPaperAccountActivityRuntimeError,
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPrefix,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
    _alpaca_paper_authenticated_account_activity_prefix,
    _alpaca_paper_authenticated_account_activity_traversal_state,
)
from packages.application.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedAccountActivityComparisonError,
    AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
    _alpaca_paper_authenticated_account_activity_comparison_evidence,
    _alpaca_paper_authenticated_account_activity_comparison_receipt,
    _AuthenticatedAccountActivityComparisonEvidenceMaterialization,
    _AuthenticatedAccountActivityComparisonReceiptMaterialization,
    _AuthenticatedAccountActivitySourceMaterialization,
    _materialize_authenticated_comparison_evidence,
    _materialize_authenticated_comparison_receipt,
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
from packages.persistence.alpaca_paper_account_activity import (
    AlpacaPaperAccountActivityPersistenceError,
    alpaca_paper_account_activity_plan_from_row,
)
from packages.persistence.alpaca_paper_account_activity import (
    _head as _activity_head,
)
from packages.persistence.alpaca_paper_account_activity import (
    _history as _activity_history,
)
from packages.persistence.alpaca_paper_account_activity import (
    _plan_row as _activity_plan_row,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_fence_position_at,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.schema import (
    phase2_account_leases,
    phase4_alpaca_paper_account_activity_comparison_heads,
    phase4_alpaca_paper_account_activity_comparisons,
)

ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_PERSISTENCE_CONTRACT_VERSION = (
    "phase4ah-authenticated-account-activity-comparison-persistence-v1"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

AccountActivityComparisonRow = Mapping[str, object] | RowMapping


class AlpacaPaperAccountActivityComparisonPersistenceError(
    AlpacaPaperAuthenticatedAccountActivityComparisonError
):
    """Durable authenticated account-activity comparison history is unavailable."""


class AlpacaPaperAccountActivityComparisonPersistenceConflict(
    AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
    AlpacaPaperAccountActivityComparisonPersistenceError,
):
    """Durable comparison history conflicts with exact authenticated sources."""


class SqlAccountActivityComparisonFenceValidator(Protocol):
    """Revalidate the exact account fence inside the append transaction."""

    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _required_text(
    row: AccountActivityComparisonRow,
    field_name: str,
) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            f"persisted account-activity comparison {field_name} must be nonempty text"
        )
    return value


def _optional_text(
    row: AccountActivityComparisonRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            f"persisted account-activity comparison {field_name} must be nonempty text or null"
        )
    return value


def _required_integer(
    row: AccountActivityComparisonRow,
    field_name: str,
) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            f"persisted account-activity comparison {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: AccountActivityComparisonRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            f"persisted account-activity comparison {field_name} must be a datetime"
        )
    return as_aware_utc(value)


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


@dataclass(frozen=True, slots=True)
class _LoadedAccountActivitySource:
    state: AlpacaPaperAuthenticatedAccountActivityTraversalState

    @property
    def prefix(self) -> AlpacaPaperAuthenticatedAccountActivityPrefix:
        return self.state.prefix

    @property
    def head_sha256(self) -> str:
        value = self.state.source_head_sha256
        if type(value) is not str:
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "terminal account-activity source is missing its durable head digest"
            )
        return value

    @property
    def committed_at(self) -> datetime:
        return self.prefix.page_receipts[-1].commit_fence_receipt.validated_at


def _load_source(
    connection: Connection,
    capture_id: str,
) -> _LoadedAccountActivitySource:
    """Reconstruct one complete Phase 4AE prefix and every durable raw source."""

    try:
        plan_row = _activity_plan_row(connection, capture_id)
        if plan_row is None:
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison references a missing traversal plan"
            )
        plan = alpaca_paper_account_activity_plan_from_row(plan_row)
        receipts = _activity_history(connection, plan)
        prefix = _alpaca_paper_authenticated_account_activity_prefix(
            plan,
            page_receipts=receipts,
        )
        head = _activity_head(connection, capture_id)
        if head is None:
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison source is missing its durable head"
            )
        capture = prefix.capture
        if (
            prefix.page_count == 0
            or not (capture.pagination_exhausted or capture.bounded_truncation)
            or prefix.next_page_description is not None
        ):
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison source is not an exact terminal prefix"
            )
        stage = (
            AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED
            if capture.pagination_exhausted
            else AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED
        )
        state = _alpaca_paper_authenticated_account_activity_traversal_state(
            stage=stage,
            prefix=prefix,
            preparation=None,
            source_head_sha256=head.semantic_sha256,
        )
        return _LoadedAccountActivitySource(state=state)
    except AlpacaPaperAccountActivityComparisonPersistenceError:
        raise
    except (
        AlpacaPaperAccountActivityPersistenceError,
        AlpacaPaperAccountActivityRuntimeError,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison source failed durable authentication"
        ) from None


def _fence_source(
    connection: Connection,
    row: AccountActivityComparisonRow,
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
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison commit fence references a missing lease"
        )
    try:
        lease = account_lease_from_row(lease_row)
        validated_at = _required_datetime(
            row,
            "commit_fence_validated_at",
        )
        valid_until = _required_datetime(
            row,
            "commit_fence_valid_until",
        )
        receipt = _account_fence_receipt(
            fence=lease.fence,
            validated_at=validated_at,
            valid_until=valid_until,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
    except (AccountCoordinatorError, TypeError, ValueError):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison commit fence source is malformed"
        ) from None
    if (
        lease.owner_id != _required_text(row, "fence_owner_id")
        or lease.lease_id != _required_text(row, "fence_lease_id")
        or lease.fencing_generation != generation
        or lease.fence.semantic_sha256 != _required_text(row, "fence_sha256")
        or lease.policy_sha256
        != _required_text(
            row,
            "fence_policy_sha256",
        )
        or valid_until != lease.expires_at
        or receipt.semantic_sha256 != _required_text(row, "commit_fence_receipt_sha256")
        or validated_at != _required_datetime(row, "recorded_at")
    ):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison commit fence conflicts with its lease source"
        )
    try:
        _authenticate_fence_position_at(
            connection,
            receipt,
            checked_at=validated_at,
        )
    except Exception:
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison commit fence position failed authentication"
        ) from None
    return receipt


def _source_values(
    *,
    phase: str,
    source: _AuthenticatedAccountActivitySourceMaterialization,
) -> dict[str, object]:
    if phase not in {"earlier", "later"}:
        raise AssertionError("account-activity comparison source phase must be exact")
    capture = source.capture
    first = source.pages[0]
    tip = source.pages[-1]
    return {
        f"{phase}_capture_id": source.capture_id,
        f"{phase}_plan_sha256": source.plan_sha256,
        f"{phase}_head_sha256": source.source_head_sha256,
        f"{phase}_state_sha256": source.state_sha256,
        f"{phase}_prefix_id": source.prefix_id,
        f"{phase}_prefix_sha256": source.prefix_sha256,
        f"{phase}_capture_sha256": source.capture_sha256,
        f"{phase}_page_count": len(source.pages),
        f"{phase}_activity_count": capture.activity_count,
        f"{phase}_first_page_number": 1,
        f"{phase}_first_receipt_id": first.receipt_id,
        f"{phase}_first_receipt_sha256": first.receipt_sha256,
        f"{phase}_first_persisted_page_sha256": first.persisted_page_sha256,
        f"{phase}_first_ingress_receipt_id": first.ingress_receipt_id,
        f"{phase}_first_ingress_receipt_sha256": first.ingress_receipt_sha256,
        f"{phase}_first_ingress_sequence": first.ingress_sequence,
        f"{phase}_tip_receipt_id": tip.receipt_id,
        f"{phase}_tip_receipt_sha256": tip.receipt_sha256,
        f"{phase}_tip_persisted_page_sha256": tip.persisted_page_sha256,
        f"{phase}_tip_ingress_receipt_id": tip.ingress_receipt_id,
        f"{phase}_tip_ingress_receipt_sha256": tip.ingress_receipt_sha256,
        f"{phase}_tip_ingress_sequence": tip.ingress_sequence,
        f"{phase}_source_committed_at": source.committed_at,
        f"{phase}_window_started_at": capture.pages[0].observation.received_at,
        f"{phase}_window_ended_at": capture.pages[-1].observation.received_at,
        f"{phase}_view_sha256": _view_sha256(capture),
    }


def _immutable_alpaca_paper_account_activity_comparison_values(
    receipt: AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    *,
    earlier_source: _LoadedAccountActivitySource,
    later_source: _LoadedAccountActivitySource,
    materialization: _AuthenticatedAccountActivityComparisonReceiptMaterialization,
) -> dict[str, Any]:
    evidence = receipt.evidence
    comparison = evidence.comparison
    commit_fence = receipt.commit_fence_receipt
    if (
        earlier_source.state != evidence.earlier_state
        or later_source.state != evidence.later_state
        or earlier_source.head_sha256 != receipt.earlier_source_head_sha256
        or later_source.head_sha256 != receipt.later_source_head_sha256
    ):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison receipt conflicts with transactionally loaded sources"
        )
    evidence_materialization = materialization.evidence
    earlier_materialization = evidence_materialization.earlier_source
    later_materialization = evidence_materialization.later_source
    observed_utc_separation_microseconds = _timedelta_microseconds(
        _utc_separation(
            earlier_materialization.capture,
            later_materialization.capture,
        )
    )
    return {
        "receipt_id": materialization.receipt_id,
        "evidence_id": evidence_materialization.evidence_id,
        "comparison_id": evidence_materialization.comparison_id,
        "account_id": evidence_materialization.account_id,
        "provider_account_id": evidence_materialization.provider_account_id,
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
            ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256
        ),
        "comparison_policy_sha256": (ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256),
        "traversal_profile_sha256": evidence_materialization.traversal_profile_sha256,
        **_source_values(
            phase="earlier",
            source=earlier_materialization,
        ),
        **_source_values(
            phase="later",
            source=later_materialization,
        ),
        "observed_utc_separation_microseconds": str(observed_utc_separation_microseconds),
        "disposition": comparison.disposition.value,
        "added_provider_activity_ids_payload": canonical_json_text(
            comparison.added_provider_activity_ids
        ),
        "removed_provider_activity_ids_payload": canonical_json_text(
            comparison.removed_provider_activity_ids
        ),
        "changed_provider_activity_ids_payload": canonical_json_text(
            comparison.changed_provider_activity_ids
        ),
        "added_count": len(comparison.added_provider_activity_ids),
        "removed_count": len(comparison.removed_provider_activity_ids),
        "changed_count": len(comparison.changed_provider_activity_ids),
        "comparison_sha256": evidence_materialization.comparison_sha256,
        "evidence_sha256": evidence_materialization.semantic_sha256,
        "recorded_at": commit_fence.validated_at,
        "canonical_payload": materialization.canonical_json,
        "semantic_sha256": materialization.semantic_sha256,
    }


def immutable_alpaca_paper_account_activity_comparison_values(
    receipt: AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    *,
    earlier_source: _LoadedAccountActivitySource,
    later_source: _LoadedAccountActivitySource,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one receipt."""

    if type(receipt) is not AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        raise AlpacaPaperAccountActivityComparisonPersistenceError(
            "account-activity comparison persistence requires an exact receipt"
        )
    materialization = _materialize_authenticated_comparison_receipt(receipt)
    return _immutable_alpaca_paper_account_activity_comparison_values(
        receipt,
        earlier_source=earlier_source,
        later_source=later_source,
        materialization=materialization,
    )


@dataclass(frozen=True, slots=True)
class _LoadedAccountActivityComparisonReceipt:
    receipt: AlpacaPaperAuthenticatedAccountActivityComparisonReceipt
    materialization: _AuthenticatedAccountActivityComparisonReceiptMaterialization


def _alpaca_paper_account_activity_comparison_from_row(
    connection: Connection,
    row: AccountActivityComparisonRow,
) -> _LoadedAccountActivityComparisonReceipt:
    """Reconstruct one receipt from complete authenticated durable sources."""

    try:
        earlier_source = _load_source(
            connection,
            _required_text(row, "earlier_capture_id"),
        )
        later_source = _load_source(
            connection,
            _required_text(row, "later_capture_id"),
        )
        evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
            earlier_state=earlier_source.state,
            later_state=later_source.state,
        )
        commit_fence = _fence_source(connection, row)
        receipt = _alpaca_paper_authenticated_account_activity_comparison_receipt(
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
        materialization = _materialize_authenticated_comparison_receipt(
            receipt,
            authenticate=False,
        )
        expected = _immutable_alpaca_paper_account_activity_comparison_values(
            receipt,
            earlier_source=earlier_source,
            later_source=later_source,
            materialization=materialization,
        )
        assert_immutable(
            phase4_alpaca_paper_account_activity_comparisons,
            materialization.receipt_id,
            row,
            expected,
        )
        return _LoadedAccountActivityComparisonReceipt(
            receipt=receipt,
            materialization=materialization,
        )
    except AlpacaPaperAccountActivityComparisonPersistenceError:
        raise
    except (
        AlpacaPaperAuthenticatedAccountActivityComparisonError,
        AlpacaPaperAccountActivityPersistenceError,
        AlpacaPaperAccountActivityRuntimeError,
        ImmutableFactConflict,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "persisted account-activity comparison failed exact source reconstruction"
        ) from None


def alpaca_paper_account_activity_comparison_from_row(
    connection: Connection,
    row: AccountActivityComparisonRow,
) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
    """Reconstruct one receipt from complete authenticated durable sources."""

    return _alpaca_paper_account_activity_comparison_from_row(
        connection,
        row,
    ).receipt


@dataclass(frozen=True, slots=True)
class _AccountActivityComparisonHead:
    account_id: str
    last_account_sequence: int
    last_receipt_id: str
    last_receipt_sha256: str
    last_recorded_at: datetime

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_PERSISTENCE_CONTRACT_VERSION,
            "account_activity_comparison_head",
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
    receipt: AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    materialization: _AuthenticatedAccountActivityComparisonReceiptMaterialization,
) -> _AccountActivityComparisonHead:
    return _AccountActivityComparisonHead(
        account_id=materialization.evidence.account_id,
        last_account_sequence=receipt.account_sequence,
        last_receipt_id=materialization.receipt_id,
        last_receipt_sha256=materialization.semantic_sha256,
        last_recorded_at=receipt.commit_fence_receipt.validated_at,
    )


def _head_values(
    head: _AccountActivityComparisonHead,
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
    row: AccountActivityComparisonRow,
) -> _AccountActivityComparisonHead:
    try:
        head = _AccountActivityComparisonHead(
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
            last_recorded_at=_required_datetime(
                row,
                "last_recorded_at",
            ),
        )
        if (
            head.last_account_sequence <= 0
            or _required_text(row, "canonical_payload") != head.canonical_json
            or _required_text(row, "semantic_sha256") != head.semantic_sha256
        ):
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "persisted account-activity comparison head conflicts with its canonical value"
            )
        return head
    except AlpacaPaperAccountActivityComparisonPersistenceError:
        raise
    except (KeyError, TypeError, ValueError):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "persisted account-activity comparison head is malformed"
        ) from None


def _head(
    connection: Connection,
    account_id: str,
) -> _AccountActivityComparisonHead | None:
    row = (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_comparison_heads).where(
                phase4_alpaca_paper_account_activity_comparison_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _receipt_row_by_id(
    connection: Connection,
    receipt_id: str,
) -> RowMapping | None:
    return (
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_comparisons).where(
                phase4_alpaca_paper_account_activity_comparisons.c.receipt_id == receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )


def _existing_receipt(
    connection: Connection,
    evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    *,
    evidence_materialization: (_AuthenticatedAccountActivityComparisonEvidenceMaterialization),
    history: tuple[_LoadedAccountActivityComparisonReceipt, ...],
) -> _LoadedAccountActivityComparisonReceipt | None:
    material = evidence_materialization
    table = phase4_alpaca_paper_account_activity_comparisons
    predicates = (
        table.c.evidence_id == material.evidence_id,
        table.c.comparison_id == material.comparison_id,
        sa.and_(
            table.c.earlier_capture_id == material.earlier_source.capture_id,
            table.c.later_capture_id == material.later_source.capture_id,
            table.c.authentication_policy_sha256
            == ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
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
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison identity or ordered source pair was reused"
        )
    receipt_id = next(iter(receipt_ids))
    matches = tuple(loaded for loaded in history if loaded.materialization.receipt_id == receipt_id)
    if len(matches) != 1 or matches[0].receipt.evidence != evidence:
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison retry conflicts with durable evidence"
        )
    return matches[0]


def _validate_history(
    connection: Connection,
    *,
    account_id: str,
    rows: tuple[RowMapping, ...],
    head: _AccountActivityComparisonHead | None,
) -> tuple[_LoadedAccountActivityComparisonReceipt, ...]:
    result: list[_LoadedAccountActivityComparisonReceipt] = []
    previous: _LoadedAccountActivityComparisonReceipt | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        loaded = _alpaca_paper_account_activity_comparison_from_row(
            connection,
            row,
        )
        receipt = loaded.receipt
        materialization = loaded.materialization
        if (
            materialization.evidence.account_id != account_id
            or receipt.account_sequence != expected_sequence
            or receipt.previous_receipt_sha256
            != (None if previous is None else previous.materialization.semantic_sha256)
            or (
                previous is not None
                and receipt.commit_fence_receipt.validated_at
                < previous.receipt.commit_fence_receipt.validated_at
            )
        ):
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison account history is discontinuous"
            )
        result.append(loaded)
        previous = loaded
    if previous is None:
        if head is not None:
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison head exists without durable receipts"
            )
        return ()
    if head != _head_for_receipt(
        previous.receipt,
        previous.materialization,
    ):
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison head conflicts with terminal history"
        )
    return tuple(result)


def _loaded_history(
    connection: Connection,
    account_id: str,
) -> tuple[_LoadedAccountActivityComparisonReceipt, ...]:
    rows = tuple(
        connection.execute(
            sa.select(phase4_alpaca_paper_account_activity_comparisons)
            .where(phase4_alpaca_paper_account_activity_comparisons.c.account_id == account_id)
            .order_by(phase4_alpaca_paper_account_activity_comparisons.c.account_sequence)
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


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[AlpacaPaperAuthenticatedAccountActivityComparisonReceipt, ...]:
    return tuple(
        loaded.receipt
        for loaded in _loaded_history(
            connection,
            account_id,
        )
    )


def _verify_alpaca_paper_account_activity_comparison_integrity(
    connection: Connection,
) -> None:
    receipt_without_head = connection.scalar(
        sa.select(phase4_alpaca_paper_account_activity_comparisons.c.receipt_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_account_activity_comparison_heads.c.account_id
                    == phase4_alpaca_paper_account_activity_comparisons.c.account_id
                )
            )
        )
        .limit(1)
    )
    if receipt_without_head is not None:
        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
            "account-activity comparison receipts exist without durable account heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_alpaca_paper_account_activity_comparison_heads)
        .order_by(phase4_alpaca_paper_account_activity_comparison_heads.c.account_id)
        .execution_options(yield_per=64)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        rows = tuple(
            connection.execute(
                sa.select(phase4_alpaca_paper_account_activity_comparisons)
                .where(
                    phase4_alpaca_paper_account_activity_comparisons.c.account_id == head.account_id
                )
                .order_by(phase4_alpaca_paper_account_activity_comparisons.c.account_sequence)
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


def verify_alpaca_paper_account_activity_comparison_integrity(
    engine: Engine,
) -> None:
    """Authenticate every durable comparison chain in one stable read."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperAccountActivityComparisonPersistenceError(
            "account-activity comparison verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperAccountActivityComparisonPersistenceError(
            "account-activity comparison verification does not support dialect "
            f"{engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_account_activity_comparison_integrity(connection)


class SqlAlpacaPaperAccountActivityComparisonRepository:
    """Append exact Phase 4AG receipts under the shared account lock."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountActivityComparisonFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                "SQL account-activity comparisons require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                f"SQL account-activity comparisons do not support dialect {engine.dialect.name!r}"
            )
        if not callable(
            getattr(
                coordinator,
                "revalidate_for_commit_in_transaction",
                None,
            )
        ):
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                "SQL account-activity comparisons require a SQL fence validator"
            )
        self._engine = engine
        self._coordinator = coordinator

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared engine for process-local composition checks."""

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
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison current call fence validation failed"
            ) from None

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        """Append exact evidence or converge an identical historical retry."""

        if type(evidence) is not AlpacaPaperAuthenticatedAccountActivityComparisonEvidence:
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                "account-activity comparison recording requires exact evidence"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                "account-activity comparison recording requires an exact account fence"
            )
        evidence._validate()
        fence.__post_init__()
        account_id = evidence.comparison.earlier_capture.plan.account_id
        if fence.account_id != account_id:
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "account-activity comparison fence crosses account identities"
            )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    account_id,
                )
                history = _loaded_history(connection, account_id)
                previous = None if not history else history[-1]
                earlier_source = _load_source(
                    connection,
                    evidence.earlier_state.prefix.plan.capture_id,
                )
                later_source = _load_source(
                    connection,
                    evidence.later_state.prefix.plan.capture_id,
                )
                expected_evidence = (
                    _alpaca_paper_authenticated_account_activity_comparison_evidence(
                        earlier_state=earlier_source.state,
                        later_state=later_source.state,
                    )
                )
                if expected_evidence != evidence:
                    raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                        "account-activity comparison evidence conflicts with durable sources"
                    )
                expected_evidence_materialization = _materialize_authenticated_comparison_evidence(
                    expected_evidence,
                    authenticate=False,
                )

                # Exact retries authenticate the current call fence while the
                # returned historical receipt retains its original fence.
                commit_fence = self._commit_fence(connection, fence)
                existing = _existing_receipt(
                    connection,
                    expected_evidence,
                    evidence_materialization=expected_evidence_materialization,
                    history=history,
                )
                if existing is not None:
                    return existing.receipt

                receipt = _alpaca_paper_authenticated_account_activity_comparison_receipt(
                    expected_evidence,
                    earlier_source_head_sha256=(earlier_source.head_sha256),
                    later_source_head_sha256=later_source.head_sha256,
                    commit_fence_receipt=commit_fence,
                    account_sequence=(
                        1 if previous is None else previous.receipt.account_sequence + 1
                    ),
                    previous_receipt_sha256=(
                        None if previous is None else previous.materialization.semantic_sha256
                    ),
                )
                materialization = _materialize_authenticated_comparison_receipt(
                    receipt,
                    authenticate=False,
                )
                if (
                    previous is not None
                    and receipt.commit_fence_receipt.validated_at
                    < previous.receipt.commit_fence_receipt.validated_at
                ):
                    raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                        "account-activity comparison commit clock regressed"
                    )
                if (
                    _receipt_row_by_id(
                        connection,
                        materialization.receipt_id,
                    )
                    is not None
                ):
                    raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                        "account-activity comparison receipt identity was reused"
                    )
                values = _immutable_alpaca_paper_account_activity_comparison_values(
                    receipt,
                    earlier_source=earlier_source,
                    later_source=later_source,
                    materialization=materialization,
                )
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_account_activity_comparisons).values(**values)
                    )
                except IntegrityError:
                    raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                        "account-activity comparison conflicts with durable history"
                    ) from None

                next_head = _head_for_receipt(
                    receipt,
                    materialization,
                )
                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_alpaca_paper_account_activity_comparison_heads).values(
                                **_head_values(next_head)
                            )
                        )
                    except IntegrityError:
                        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                            "account-activity comparison head conflicts with durable history"
                        ) from None
                else:
                    previous_head = _head_for_receipt(
                        previous.receipt,
                        previous.materialization,
                    )
                    updated = connection.execute(
                        sa.update(phase4_alpaca_paper_account_activity_comparison_heads)
                        .where(
                            phase4_alpaca_paper_account_activity_comparison_heads.c.account_id
                            == previous_head.account_id,
                            phase4_alpaca_paper_account_activity_comparison_heads.c.semantic_sha256
                            == previous_head.semantic_sha256,
                            phase4_alpaca_paper_account_activity_comparison_heads.c.last_account_sequence
                            == previous_head.last_account_sequence,
                            phase4_alpaca_paper_account_activity_comparison_heads.c.last_receipt_id
                            == previous_head.last_receipt_id,
                            phase4_alpaca_paper_account_activity_comparison_heads.c.last_receipt_sha256
                            == previous_head.last_receipt_sha256,
                            phase4_alpaca_paper_account_activity_comparison_heads.c.last_recorded_at
                            == previous_head.last_recorded_at,
                        )
                        .values(**_head_values(next_head))
                    )
                    if updated.rowcount != 1:
                        raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                            "account-activity comparison head changed during append"
                        )

                terminal_history = _loaded_history(
                    connection,
                    account_id,
                )
                if (
                    not terminal_history
                    or terminal_history[-1].receipt != receipt
                    or terminal_history[-1].materialization != materialization
                ):
                    raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                        "account-activity comparison head failed exact SQL readback"
                    )
                final_fence = self._commit_fence(connection, fence)
                if not (
                    _same_fence_lease(commit_fence, final_fence)
                    and commit_fence.validated_at
                    <= final_fence.validated_at
                    < final_fence.valid_until
                ):
                    raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                        "account-activity comparison fence changed before final commit"
                    )
                return terminal_history[-1].receipt
        except AlpacaPaperAuthenticatedAccountActivityComparisonError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperAccountActivityPersistenceError,
            AlpacaPaperAccountActivityRuntimeError,
            ImmutableFactConflict,
            IntegrityError,
            SQLAlchemyError,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                "durable account-activity comparison append failed"
            ) from None

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt | None:
        """Load and authenticate one receipt and its complete account chain."""

        if type(receipt_id) is not str or not receipt_id:
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                "account-activity comparison receipt ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _receipt_row_by_id(connection, receipt_id)
            if row is None:
                return None
            history = _loaded_history(
                connection,
                _required_text(row, "account_id"),
            )
            matches = tuple(
                loaded for loaded in history if loaded.materialization.receipt_id == receipt_id
            )
            if len(matches) != 1:
                raise AlpacaPaperAccountActivityComparisonPersistenceConflict(
                    "account-activity comparison receipt exists outside account history"
                )
            return matches[0].receipt

    def history(
        self,
        account_id: str,
    ) -> tuple[
        AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
        ...,
    ]:
        """Load one complete authenticated account-local comparison chain."""

        if type(account_id) is not str or not account_id:
            raise AlpacaPaperAccountActivityComparisonPersistenceError(
                "account-activity comparison account ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            return _history(connection, account_id)


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperAccountActivityComparisonPersistenceConflict",
    "AlpacaPaperAccountActivityComparisonPersistenceError",
    "SqlAlpacaPaperAccountActivityComparisonRepository",
    "alpaca_paper_account_activity_comparison_from_row",
    "immutable_alpaca_paper_account_activity_comparison_values",
    "verify_alpaca_paper_account_activity_comparison_integrity",
]
