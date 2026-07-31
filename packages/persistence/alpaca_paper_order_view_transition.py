"""Durable page admission for one ordered pair of Alpaca paper order views."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, SQLAlchemyError

from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotRuntimeError,
    _alpaca_paper_authenticated_order_snapshot_prefix,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPlan,
)
from packages.application.alpaca_paper_order_view_transition import (
    ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
    ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
    AlpacaPaperOrderViewTransitionClaim,
    AlpacaPaperOrderViewTransitionConflict,
    AlpacaPaperOrderViewTransitionConsumption,
    AlpacaPaperOrderViewTransitionError,
    AlpacaPaperOrderViewTransitionPlan,
    AlpacaPaperOrderViewTransitionRole,
    _alpaca_paper_order_view_transition_claim,
    _alpaca_paper_order_view_transition_consumption,
    create_alpaca_paper_order_view_transition_plan,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
    lock_account_capacity_serialization,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_fence_position_at,
)
from packages.persistence.alpaca_paper_order_snapshot import (
    AlpacaPaperOrderSnapshotPersistenceError,
    _head,
    _history,
    _plan_row,
    _preparation_fact_from_row,
    _preparation_fact_row,
    _prepare_alpaca_paper_order_snapshot_in_transaction,
    _receipt_from_row,
    alpaca_paper_order_snapshot_plan_from_row,
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
    phase4_alpaca_paper_order_snapshot_pages,
    phase4_alpaca_paper_order_snapshot_preparations,
    phase4_alpaca_paper_order_transition_claims,
    phase4_alpaca_paper_order_transition_consumptions,
    phase4_alpaca_paper_order_transition_members,
)

ALPACA_PAPER_ORDER_VIEW_TRANSITION_PERSISTENCE_CONTRACT_VERSION = (
    "phase4aa-durable-order-view-transition-persistence-v1"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

OrderTransitionRow = Mapping[str, object] | RowMapping


class AlpacaPaperOrderViewTransitionPersistenceError(AlpacaPaperOrderViewTransitionError):
    """Durable order-pair page admission state is unavailable."""


class AlpacaPaperOrderViewTransitionPersistenceConflict(
    AlpacaPaperOrderViewTransitionConflict,
    AlpacaPaperOrderViewTransitionPersistenceError,
):
    """Durable pair state conflicts with the requested page transition."""


class SqlOrderViewTransitionFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _required_text(row: OrderTransitionRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            f"persisted order transition {field_name} must be nonempty text"
        )
    return value


def _optional_text(row: OrderTransitionRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            f"persisted order transition {field_name} must be nonempty text or null"
        )
    return value


def _required_integer(row: OrderTransitionRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            f"persisted order transition {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: OrderTransitionRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            f"persisted order transition {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperOrderViewTransitionPersistenceError(str(error)) from error
    return value


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


def _member_material(
    transition: AlpacaPaperOrderViewTransitionPlan,
    role: AlpacaPaperOrderViewTransitionRole,
) -> tuple[str, str, str]:
    plan = transition.selected_plan(role)
    member_id = canonical_id(
        "alpaca-paper-order-view-transition-member",
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
        transition.round_id,
        role,
        plan.snapshot_id,
        plan.semantic_sha256,
    )
    material = (
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
        "transition_member",
        member_id,
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
        transition.round_id,
        transition.semantic_sha256,
        role,
        transition.account_id,
        plan.snapshot_id,
        plan.semantic_sha256,
        plan.page_limit,
        plan.maximum_pages,
        False,
        False,
        False,
        False,
    )
    return member_id, canonical_json_text(material), _semantic_sha256(material)


def immutable_alpaca_paper_order_transition_member_values(
    transition: AlpacaPaperOrderViewTransitionPlan,
    role: AlpacaPaperOrderViewTransitionRole,
) -> dict[str, Any]:
    """Return the immutable registration of one exact pair member."""

    if type(transition) is not AlpacaPaperOrderViewTransitionPlan:
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            "transition membership requires an exact transition plan"
        )
    if type(role) is not AlpacaPaperOrderViewTransitionRole:
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            "transition membership requires an exact role"
        )
    transition.__post_init__()
    plan = transition.selected_plan(role)
    member_id, canonical_payload, semantic_sha256 = _member_material(
        transition,
        role,
    )
    return {
        "member_id": member_id,
        "round_id": transition.round_id,
        "member_role": role.value,
        "transition_plan_sha256": transition.semantic_sha256,
        "account_id": transition.account_id,
        "snapshot_id": plan.snapshot_id,
        "capture_idempotency_key": plan.capture_idempotency_key,
        "page_limit": plan.page_limit,
        "maximum_pages": plan.maximum_pages,
        "plan_canonical_payload": canonical_json_text(plan._semantic_material()),
        "plan_sha256": plan.semantic_sha256,
        "canonical_payload": canonical_payload,
        "semantic_sha256": semantic_sha256,
    }


def _member_rows(
    connection: Connection,
    round_id: str,
) -> tuple[RowMapping, ...]:
    return tuple(
        connection.execute(
            sa.select(phase4_alpaca_paper_order_transition_members)
            .where(phase4_alpaca_paper_order_transition_members.c.round_id == round_id)
            .order_by(phase4_alpaca_paper_order_transition_members.c.member_role)
        )
        .mappings()
        .all()
    )


def _plan_from_member_row(row: OrderTransitionRow) -> AlpacaPaperOrderSnapshotPlan:
    try:
        plan = AlpacaPaperOrderSnapshotPlan(
            account_id=_required_text(row, "account_id"),
            capture_idempotency_key=_required_text(
                row,
                "capture_idempotency_key",
            ),
            page_limit=_required_integer(row, "page_limit"),
            maximum_pages=_required_integer(row, "maximum_pages"),
        )
        expected = {
            "snapshot_id": plan.snapshot_id,
            "plan_canonical_payload": canonical_json_text(plan._semantic_material()),
            "plan_sha256": plan.semantic_sha256,
        }
        if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition member conflicts with exact plan reconstruction"
            )
        return plan
    except AlpacaPaperOrderViewTransitionError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "persisted order transition member plan is malformed"
        ) from error


def _transition_from_member_rows(
    rows: tuple[RowMapping, ...],
) -> AlpacaPaperOrderViewTransitionPlan:
    if len(rows) != 2:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition round must have exactly two members"
        )
    by_role: dict[AlpacaPaperOrderViewTransitionRole, RowMapping] = {}
    for row in rows:
        try:
            role = AlpacaPaperOrderViewTransitionRole(_required_text(row, "member_role"))
        except ValueError:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition member role is invalid"
            ) from None
        if role in by_role:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition member role is duplicated"
            )
        by_role[role] = row
    if set(by_role) != set(AlpacaPaperOrderViewTransitionRole):
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition round lacks an exact ordered pair"
        )
    transition = create_alpaca_paper_order_view_transition_plan(
        earlier_plan=_plan_from_member_row(by_role[AlpacaPaperOrderViewTransitionRole.EARLIER]),
        later_plan=_plan_from_member_row(by_role[AlpacaPaperOrderViewTransitionRole.LATER]),
    )
    for role, row in by_role.items():
        expected = immutable_alpaca_paper_order_transition_member_values(
            transition,
            role,
        )
        if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition member failed exact reconstruction"
            )
    return transition


def _load_transition(
    connection: Connection,
    round_id: str,
) -> AlpacaPaperOrderViewTransitionPlan:
    transition = _transition_from_member_rows(_member_rows(connection, round_id))
    if transition.round_id != round_id:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition round ID conflicts with its members"
        )
    return transition


def _prefix_for_count(
    connection: Connection,
    plan: AlpacaPaperOrderSnapshotPlan,
    page_count: int,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    if page_count < 0 or page_count > plan.maximum_pages:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition prefix count is out of bounds"
        )
    plan_row = _plan_row(connection, plan.snapshot_id)
    if plan_row is None:
        if page_count != 0:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition prefix references a missing snapshot plan"
            )
    elif alpaca_paper_order_snapshot_plan_from_row(plan_row) != plan:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition prefix plan conflicts with durable history"
        )
    rows = (
        connection.execute(
            sa.select(phase4_alpaca_paper_order_snapshot_pages)
            .where(
                phase4_alpaca_paper_order_snapshot_pages.c.snapshot_id == plan.snapshot_id,
                phase4_alpaca_paper_order_snapshot_pages.c.page_number <= page_count,
            )
            .order_by(phase4_alpaca_paper_order_snapshot_pages.c.page_number)
        )
        .mappings()
        .all()
    )
    if len(rows) != page_count:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition prefix is not gap-free"
        )
    receipts = tuple(_receipt_from_row(connection, row, plan) for row in rows)
    return _alpaca_paper_authenticated_order_snapshot_prefix(
        plan,
        page_receipts=receipts,
    )


def _current_prefix(
    connection: Connection,
    plan: AlpacaPaperOrderSnapshotPlan,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    plan_row = _plan_row(connection, plan.snapshot_id)
    if plan_row is None:
        return _prefix_for_count(connection, plan, 0)
    if alpaca_paper_order_snapshot_plan_from_row(plan_row) != plan:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition plan conflicts with durable snapshot history"
        )
    receipts = _history(connection, plan)
    return _alpaca_paper_authenticated_order_snapshot_prefix(
        plan,
        page_receipts=receipts,
    )


def _terminal_earlier_prefix(
    connection: Connection,
    transition: AlpacaPaperOrderViewTransitionPlan,
) -> tuple[AlpacaPaperAuthenticatedOrderSnapshotPrefix, str]:
    prefix = _current_prefix(connection, transition.earlier_plan)
    capture = prefix.capture
    head = _head(connection, transition.earlier_plan.snapshot_id)
    if (
        head is None
        or not prefix.page_receipts
        or not (capture.pagination_exhausted or capture.bounded_truncation)
    ):
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "later transition requires the exact terminal earlier prefix"
        )
    return prefix, head.semantic_sha256


def _fence_from_row(
    connection: Connection,
    row: OrderTransitionRow,
    *,
    validated_at_field: str,
    receipt_sha256_field: str,
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
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition fence references a missing lease"
        )
    lease = account_lease_from_row(lease_row)
    receipt = _account_fence_receipt(
        fence=lease.fence,
        validated_at=_required_datetime(row, validated_at_field),
        valid_until=_required_datetime(row, "commit_fence_valid_until"),
        policy_sha256=lease.policy_sha256,
        lease_sha256=lease.semantic_sha256,
    )
    if (
        lease.owner_id != _required_text(row, "fence_owner_id")
        or lease.lease_id != _required_text(row, "fence_lease_id")
        or lease.fence.semantic_sha256 != _required_text(row, "fence_sha256")
        or lease.policy_sha256 != _required_text(row, "fence_policy_sha256")
        or lease.expires_at != receipt.valid_until
        or receipt.semantic_sha256 != _required_text(row, receipt_sha256_field)
    ):
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition fence conflicts with its lease source"
        )
    _authenticate_fence_position_at(
        connection,
        receipt,
        checked_at=receipt.validated_at,
    )
    return receipt


def _claim_row(
    connection: Connection,
    *,
    claim_id: str | None = None,
    round_id: str | None = None,
    role: AlpacaPaperOrderViewTransitionRole | None = None,
    page_number: int | None = None,
) -> RowMapping | None:
    if claim_id is None and (round_id is None or role is None or page_number is None):
        raise AssertionError("claim lookup requires an ID or exact round page")
    conditions = []
    if claim_id is not None:
        conditions.append(phase4_alpaca_paper_order_transition_claims.c.claim_id == claim_id)
    if round_id is not None:
        conditions.append(phase4_alpaca_paper_order_transition_claims.c.round_id == round_id)
    if role is not None:
        conditions.append(phase4_alpaca_paper_order_transition_claims.c.selected_role == role.value)
    if page_number is not None:
        conditions.append(phase4_alpaca_paper_order_transition_claims.c.page_number == page_number)
    try:
        return (
            connection.execute(
                sa.select(phase4_alpaca_paper_order_transition_claims).where(*conditions)
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition claim identity is not unique"
        ) from None


def _consumption_row(
    connection: Connection,
    *,
    consumption_id: str | None = None,
    claim_id: str | None = None,
) -> RowMapping | None:
    if consumption_id is None and claim_id is None:
        raise AssertionError("consumption lookup requires an ID")
    conditions = []
    if consumption_id is not None:
        conditions.append(
            phase4_alpaca_paper_order_transition_consumptions.c.consumption_id == consumption_id
        )
    if claim_id is not None:
        conditions.append(phase4_alpaca_paper_order_transition_consumptions.c.claim_id == claim_id)
    try:
        return (
            connection.execute(
                sa.select(phase4_alpaca_paper_order_transition_consumptions).where(*conditions)
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition consumption identity is not unique"
        ) from None


def immutable_alpaca_paper_order_transition_claim_values(
    claim: AlpacaPaperOrderViewTransitionClaim,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one page claim."""

    if type(claim) is not AlpacaPaperOrderViewTransitionClaim:
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            "transition persistence requires an exact claim"
        )
    claim._validate()
    transition = claim.plan
    earlier_values = immutable_alpaca_paper_order_transition_member_values(
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    later_values = immutable_alpaca_paper_order_transition_member_values(
        transition,
        AlpacaPaperOrderViewTransitionRole.LATER,
    )
    selected_values = (
        earlier_values
        if claim.selected_role is AlpacaPaperOrderViewTransitionRole.EARLIER
        else later_values
    )
    previous = claim.previous_claim
    prior = claim.prior_earlier_prefix
    prior_tip = None if prior is None else prior.page_receipts[-1]
    fence = claim.commit_fence_receipt
    return {
        "claim_id": claim.claim_id,
        "round_id": transition.round_id,
        "transition_plan_sha256": transition.semantic_sha256,
        "selected_role": claim.selected_role.value,
        "account_id": transition.account_id,
        "earlier_member_id": earlier_values["member_id"],
        "earlier_member_role": AlpacaPaperOrderViewTransitionRole.EARLIER.value,
        "earlier_member_sha256": earlier_values["semantic_sha256"],
        "earlier_snapshot_id": transition.earlier_plan.snapshot_id,
        "earlier_plan_sha256": transition.earlier_plan.semantic_sha256,
        "later_member_id": later_values["member_id"],
        "later_member_role": AlpacaPaperOrderViewTransitionRole.LATER.value,
        "later_member_sha256": later_values["semantic_sha256"],
        "later_snapshot_id": transition.later_plan.snapshot_id,
        "later_plan_sha256": transition.later_plan.semantic_sha256,
        "selected_member_id": selected_values["member_id"],
        "selected_snapshot_id": claim.selected_plan.snapshot_id,
        "selected_plan_sha256": claim.selected_plan.semantic_sha256,
        "page_number": claim.description.page_number,
        "description_sha256": claim.description.semantic_sha256,
        "before_order_id": claim.description.before_order_id,
        "prefix_id": claim.selected_prefix.prefix_id,
        "prefix_sha256": claim.selected_prefix.semantic_sha256,
        "prefix_capture_sha256": claim.selected_prefix.capture.semantic_sha256,
        "prefix_page_count": claim.selected_prefix.page_count,
        "previous_page_receipt_id": claim.previous_page_receipt_id,
        "previous_page_receipt_sha256": claim.previous_page_receipt_sha256,
        "previous_persisted_page_sha256": (claim.previous_persisted_page_sha256),
        "previous_claim_id": None if previous is None else previous.claim_id,
        "previous_claim_sha256": (None if previous is None else previous.semantic_sha256),
        "prior_earlier_prefix_id": None if prior is None else prior.prefix_id,
        "prior_earlier_prefix_sha256": (None if prior is None else prior.semantic_sha256),
        "prior_earlier_source_head_sha256": (claim.prior_earlier_source_head_sha256),
        "prior_earlier_tip_receipt_id": (None if prior_tip is None else prior_tip.receipt_id),
        "prior_earlier_tip_receipt_sha256": (
            None if prior_tip is None else prior_tip.semantic_sha256
        ),
        "prior_earlier_tip_received_at": (
            None if prior_tip is None else prior_tip.persisted_page.observation.received_at
        ),
        "eligible_at": claim.eligible_at,
        "fence_owner_id": fence.fence.owner_id,
        "fence_lease_id": fence.fence.lease_id,
        "fence_fencing_generation": fence.fence.fencing_generation,
        "fence_sha256": fence.fence.semantic_sha256,
        "fence_policy_sha256": fence.policy_sha256,
        "commit_fence_lease_sha256": fence.lease_sha256,
        "commit_fence_receipt_sha256": fence.semantic_sha256,
        "selected_at": claim.selected_at,
        "commit_fence_valid_until": fence.valid_until,
        "transition_policy_sha256": (ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256),
        "canonical_payload": claim.canonical_json,
        "semantic_sha256": claim.semantic_sha256,
    }


def alpaca_paper_order_transition_claim_from_row(
    connection: Connection,
    row: OrderTransitionRow,
) -> AlpacaPaperOrderViewTransitionClaim:
    """Reconstruct one page claim from all immutable durable sources."""

    try:
        transition = _load_transition(
            connection,
            _required_text(row, "round_id"),
        )
        role = AlpacaPaperOrderViewTransitionRole(_required_text(row, "selected_role"))
        prefix = _prefix_for_count(
            connection,
            transition.selected_plan(role),
            _required_integer(row, "prefix_page_count"),
        )
        previous: AlpacaPaperOrderViewTransitionClaim | None = None
        previous_claim_id = _optional_text(row, "previous_claim_id")
        if previous_claim_id is not None:
            previous_row = _claim_row(
                connection,
                claim_id=previous_claim_id,
            )
            if previous_row is None:
                raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                    "order transition claim references a missing predecessor"
                )
            previous = alpaca_paper_order_transition_claim_from_row(
                connection,
                previous_row,
            )
        prior: AlpacaPaperAuthenticatedOrderSnapshotPrefix | None = None
        prior_head_sha256: str | None = None
        if role is AlpacaPaperOrderViewTransitionRole.LATER:
            prior, prior_head_sha256 = _terminal_earlier_prefix(
                connection,
                transition,
            )
        fence = _fence_from_row(
            connection,
            row,
            validated_at_field="selected_at",
            receipt_sha256_field="commit_fence_receipt_sha256",
        )
        claim = _alpaca_paper_order_view_transition_claim(
            plan=transition,
            selected_role=role,
            selected_prefix=prefix,
            previous_claim=previous,
            prior_earlier_prefix=prior,
            prior_earlier_source_head_sha256=prior_head_sha256,
            commit_fence_receipt=fence,
        )
        expected = immutable_alpaca_paper_order_transition_claim_values(claim)
        if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition claim failed exact reconstruction"
            )
        return claim
    except AlpacaPaperOrderViewTransitionError:
        raise
    except (
        AccountCoordinatorError,
        AlpacaPaperOrderSnapshotRuntimeError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "persisted order transition claim is malformed"
        ) from error


def immutable_alpaca_paper_order_transition_consumption_values(
    consumption: AlpacaPaperOrderViewTransitionConsumption,
) -> dict[str, Any]:
    """Return the immutable binding between one claim and one preparation."""

    if type(consumption) is not AlpacaPaperOrderViewTransitionConsumption:
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            "transition persistence requires an exact consumption"
        )
    consumption._validate()
    claim = consumption.claim
    preparation = consumption.preparation
    selected_member = immutable_alpaca_paper_order_transition_member_values(
        claim.plan,
        claim.selected_role,
    )
    claim_fence = claim.commit_fence_receipt
    fence = consumption.commit_fence_receipt
    return {
        "consumption_id": consumption.consumption_id,
        "claim_id": claim.claim_id,
        "claim_sha256": claim.semantic_sha256,
        "round_id": claim.plan.round_id,
        "selected_role": claim.selected_role.value,
        "selected_member_id": selected_member["member_id"],
        "selected_snapshot_id": claim.selected_plan.snapshot_id,
        "selected_plan_sha256": claim.selected_plan.semantic_sha256,
        "account_id": claim.selected_plan.account_id,
        "page_number": claim.description.page_number,
        "description_sha256": claim.description.semantic_sha256,
        "preparation_id": preparation.preparation_id,
        "preparation_sha256": preparation.semantic_sha256,
        "prefix_capture_sha256": preparation.prefix_capture_sha256,
        "prefix_page_count": preparation.prefix_page_count,
        "prepared_at": preparation.prepared_at,
        "fence_owner_id": fence.fence.owner_id,
        "fence_lease_id": fence.fence.lease_id,
        "fence_fencing_generation": fence.fence.fencing_generation,
        "fence_sha256": fence.fence.semantic_sha256,
        "fence_policy_sha256": fence.policy_sha256,
        "commit_fence_lease_sha256": fence.lease_sha256,
        "claim_fence_receipt_sha256": claim_fence.semantic_sha256,
        "claim_selected_at": claim.selected_at,
        "commit_fence_receipt_sha256": fence.semantic_sha256,
        "consumed_at": consumption.consumed_at,
        "commit_fence_valid_until": fence.valid_until,
        "canonical_payload": consumption.canonical_json,
        "semantic_sha256": consumption.semantic_sha256,
    }


def alpaca_paper_order_transition_consumption_from_row(
    connection: Connection,
    row: OrderTransitionRow,
) -> AlpacaPaperOrderViewTransitionConsumption:
    """Reconstruct one consumed claim and its exact unchanged preparation."""

    claim_row = _claim_row(
        connection,
        claim_id=_required_text(row, "claim_id"),
    )
    if claim_row is None:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition consumption references a missing claim"
        )
    claim = alpaca_paper_order_transition_claim_from_row(
        connection,
        claim_row,
    )
    preparation_row = _preparation_fact_row(
        connection,
        preparation_sha256=_required_text(row, "preparation_sha256"),
        snapshot_id=_required_text(row, "selected_snapshot_id"),
        page_number=_required_integer(row, "page_number"),
    )
    if preparation_row is None:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition consumption references a missing preparation"
        )
    preparation = _preparation_fact_from_row(
        preparation_row,
        claim.selected_plan,
    )
    fence = _fence_from_row(
        connection,
        row,
        validated_at_field="consumed_at",
        receipt_sha256_field="commit_fence_receipt_sha256",
    )
    consumption = _alpaca_paper_order_view_transition_consumption(
        claim=claim,
        preparation=preparation,
        commit_fence_receipt=fence,
    )
    expected = immutable_alpaca_paper_order_transition_consumption_values(consumption)
    if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "order transition consumption failed exact reconstruction"
        )
    return consumption


def _verify_alpaca_paper_order_view_transition_integrity(
    connection: Connection,
) -> None:
    member_rounds = tuple(
        connection.scalars(
            sa.select(phase4_alpaca_paper_order_transition_members.c.round_id)
            .distinct()
            .order_by(phase4_alpaca_paper_order_transition_members.c.round_id)
        )
    )
    for round_id in member_rounds:
        transition = _load_transition(connection, round_id)
        first_earlier = _claim_row(
            connection,
            round_id=transition.round_id,
            role=AlpacaPaperOrderViewTransitionRole.EARLIER,
            page_number=1,
        )
        if first_earlier is None:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition members exist without their first earlier claim"
            )

    claims = connection.execute(
        sa.select(phase4_alpaca_paper_order_transition_claims).order_by(
            phase4_alpaca_paper_order_transition_claims.c.round_id,
            phase4_alpaca_paper_order_transition_claims.c.selected_role,
            phase4_alpaca_paper_order_transition_claims.c.page_number,
        )
    ).mappings()
    for row in claims:
        claim = alpaca_paper_order_transition_claim_from_row(connection, row)
        if claim.description.page_number > 1:
            previous = claim.previous_claim
            if previous is None:
                raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                    "continued order transition claim lacks its predecessor"
                )
            previous_consumption = _consumption_row(
                connection,
                claim_id=previous.claim_id,
            )
            if previous_consumption is None:
                raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                    "continued order transition claim lacks predecessor consumption"
                )
            alpaca_paper_order_transition_consumption_from_row(
                connection,
                previous_consumption,
            )
        if claim.selected_role is AlpacaPaperOrderViewTransitionRole.LATER:
            prior = claim.prior_earlier_prefix
            if prior is None:
                raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                    "later order transition claim lacks its earlier prefix"
                )
            earlier_tip_page = prior.page_count
            earlier_claim_row = _claim_row(
                connection,
                round_id=claim.plan.round_id,
                role=AlpacaPaperOrderViewTransitionRole.EARLIER,
                page_number=earlier_tip_page,
            )
            if earlier_claim_row is None:
                raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                    "later order transition claim lacks terminal earlier claim"
                )
            earlier_claim = alpaca_paper_order_transition_claim_from_row(
                connection,
                earlier_claim_row,
            )
            earlier_consumption = _consumption_row(
                connection,
                claim_id=earlier_claim.claim_id,
            )
            if earlier_consumption is None:
                raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                    "later order transition claim lacks terminal earlier consumption"
                )
            alpaca_paper_order_transition_consumption_from_row(
                connection,
                earlier_consumption,
            )

    consumptions = connection.execute(
        sa.select(phase4_alpaca_paper_order_transition_consumptions).order_by(
            phase4_alpaca_paper_order_transition_consumptions.c.consumption_id
        )
    ).mappings()
    for row in consumptions:
        alpaca_paper_order_transition_consumption_from_row(connection, row)

    unconsumed_registered_preparation = connection.scalar(
        sa.select(phase4_alpaca_paper_order_snapshot_preparations.c.preparation_sha256)
        .join(
            phase4_alpaca_paper_order_transition_members,
            phase4_alpaca_paper_order_transition_members.c.snapshot_id
            == phase4_alpaca_paper_order_snapshot_preparations.c.snapshot_id,
        )
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_order_transition_consumptions.c.preparation_sha256
                    == phase4_alpaca_paper_order_snapshot_preparations.c.preparation_sha256
                )
            )
        )
        .limit(1)
    )
    if unconsumed_registered_preparation is not None:
        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
            "registered order transition preparation lacks atomic claim consumption"
        )


def verify_alpaca_paper_order_view_transition_integrity(
    engine: Engine,
) -> None:
    """Authenticate every durable pair member, page claim, and consumption."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            "order transition verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperOrderViewTransitionPersistenceError(
            f"order transition verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_order_view_transition_integrity(connection)


class SqlAlpacaPaperOrderViewTransitionRepository:
    """Register a pair, claim exact next pages, and consume each claim once."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlOrderViewTransitionFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "SQL order transitions require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                f"SQL order transitions do not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(coordinator, "revalidate_for_commit_in_transaction", None)):
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "SQL order transitions require a SQL fence validator"
            )
        self._engine = engine
        self._coordinator = coordinator

    @property
    def runtime_store_identity(self) -> int:
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
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition current call fence validation failed"
            ) from None

    @staticmethod
    def _assert_absent(
        connection: Connection,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> None:
        if _plan_row(connection, plan.snapshot_id) is not None:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition selected an existing stalled or complete source"
            )

    @staticmethod
    def _prior_claim(
        connection: Connection,
        transition: AlpacaPaperOrderViewTransitionPlan,
        role: AlpacaPaperOrderViewTransitionRole,
        page_number: int,
    ) -> AlpacaPaperOrderViewTransitionClaim | None:
        if page_number == 1:
            return None
        row = _claim_row(
            connection,
            round_id=transition.round_id,
            role=role,
            page_number=page_number - 1,
        )
        if row is None:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "continued order transition claim lacks its gap-free predecessor"
            )
        previous = alpaca_paper_order_transition_claim_from_row(
            connection,
            row,
        )
        consumption_row = _consumption_row(
            connection,
            claim_id=previous.claim_id,
        )
        if consumption_row is None:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "continued order transition claim requires predecessor consumption"
            )
        alpaca_paper_order_transition_consumption_from_row(
            connection,
            consumption_row,
        )
        return previous

    @staticmethod
    def _authenticate_terminal_earlier_claim(
        connection: Connection,
        transition: AlpacaPaperOrderViewTransitionPlan,
        prior: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    ) -> None:
        row = _claim_row(
            connection,
            round_id=transition.round_id,
            role=AlpacaPaperOrderViewTransitionRole.EARLIER,
            page_number=prior.page_count,
        )
        if row is None:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "later transition requires a terminal pair-managed earlier page"
            )
        claim = alpaca_paper_order_transition_claim_from_row(connection, row)
        consumption_row = _consumption_row(
            connection,
            claim_id=claim.claim_id,
        )
        if consumption_row is None:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "later transition requires terminal earlier claim consumption"
            )
        alpaca_paper_order_transition_consumption_from_row(
            connection,
            consumption_row,
        )

    def claim(
        self,
        transition: AlpacaPaperOrderViewTransitionPlan,
        *,
        selected_role: AlpacaPaperOrderViewTransitionRole,
        selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
        selected_source_head_sha256: str | None,
        fence: AccountFence,
    ) -> AlpacaPaperOrderViewTransitionClaim:
        """Return an exact retry or durably claim one eligible next page."""

        if type(transition) is not AlpacaPaperOrderViewTransitionPlan:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition claim requires an exact transition plan"
            )
        if type(selected_role) is not AlpacaPaperOrderViewTransitionRole:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition claim requires an exact role"
            )
        if type(selected_prefix) is not AlpacaPaperAuthenticatedOrderSnapshotPrefix:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition claim requires an exact selected prefix"
            )
        if selected_source_head_sha256 is not None and (
            type(selected_source_head_sha256) is not str
            or len(selected_source_head_sha256) != 64
            or any(character not in "0123456789abcdef" for character in selected_source_head_sha256)
        ):
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition selected source head must be a lowercase SHA-256 digest"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition claim requires an exact account fence"
            )
        transition.__post_init__()
        selected_prefix._validate()
        selected_plan = transition.selected_plan(selected_role)
        if selected_prefix.plan != selected_plan:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition selected prefix belongs to another plan"
            )
        fence.__post_init__()
        if fence.account_id != transition.account_id:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "order transition claim fence crosses accounts"
            )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    transition.account_id,
                )
                durable_selected_prefix = _current_prefix(
                    connection,
                    selected_plan,
                )
                selected_head = _head(
                    connection,
                    selected_plan.snapshot_id,
                )
                durable_selected_source_head_sha256 = (
                    None if selected_head is None else selected_head.semantic_sha256
                )
                if (
                    durable_selected_prefix != selected_prefix
                    or durable_selected_source_head_sha256 != selected_source_head_sha256
                ):
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition selected source changed before admission"
                    )
                rows = _member_rows(connection, transition.round_id)
                if not rows:
                    if selected_role is not AlpacaPaperOrderViewTransitionRole.EARLIER:
                        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                            "later transition claim requires registered earlier history"
                        )
                    self._assert_absent(connection, transition.earlier_plan)
                    self._assert_absent(connection, transition.later_plan)
                    for role in AlpacaPaperOrderViewTransitionRole:
                        values = immutable_alpaca_paper_order_transition_member_values(
                            transition,
                            role,
                        )
                        try:
                            connection.execute(
                                sa.insert(phase4_alpaca_paper_order_transition_members).values(
                                    **values
                                )
                            )
                        except IntegrityError:
                            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                                "order transition membership conflicts with durable history"
                            ) from None
                else:
                    durable_transition = _transition_from_member_rows(rows)
                    if durable_transition != transition:
                        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                            "order transition claim conflicts with registered pair"
                        )

                description = selected_prefix.next_page_description
                if description is None:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition traversal has no remaining page"
                    )
                existing_row = _claim_row(
                    connection,
                    round_id=transition.round_id,
                    role=selected_role,
                    page_number=description.page_number,
                )
                if existing_row is not None:
                    existing = alpaca_paper_order_transition_claim_from_row(
                        connection,
                        existing_row,
                    )
                    if existing.plan != transition or existing.selected_prefix != selected_prefix:
                        raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                            "order transition retry conflicts with durable page"
                        )
                    self._commit_fence(connection, fence)
                    return existing

                previous = self._prior_claim(
                    connection,
                    transition,
                    selected_role,
                    description.page_number,
                )
                prior: AlpacaPaperAuthenticatedOrderSnapshotPrefix | None = None
                prior_head_sha256: str | None = None
                if selected_role is AlpacaPaperOrderViewTransitionRole.LATER:
                    prior, prior_head_sha256 = _terminal_earlier_prefix(
                        connection,
                        transition,
                    )
                    self._authenticate_terminal_earlier_claim(
                        connection,
                        transition,
                        prior,
                    )
                    if description.page_number == 1:
                        self._assert_absent(connection, transition.later_plan)

                commit_fence = self._commit_fence(connection, fence)
                claim = _alpaca_paper_order_view_transition_claim(
                    plan=transition,
                    selected_role=selected_role,
                    selected_prefix=selected_prefix,
                    previous_claim=previous,
                    prior_earlier_prefix=prior,
                    prior_earlier_source_head_sha256=prior_head_sha256,
                    commit_fence_receipt=commit_fence,
                )
                values = immutable_alpaca_paper_order_transition_claim_values(claim)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_order_transition_claims).values(**values)
                    )
                except IntegrityError:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition claim conflicts with durable history"
                    ) from None
                row = _claim_row(
                    connection,
                    claim_id=claim.claim_id,
                    round_id=transition.round_id,
                    role=selected_role,
                    page_number=description.page_number,
                )
                if row is None:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition claim failed exact SQL readback"
                    )
                persisted = alpaca_paper_order_transition_claim_from_row(
                    connection,
                    row,
                )
                if persisted != claim:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition claim failed exact reconstruction"
                    )
                assert_immutable(
                    phase4_alpaca_paper_order_transition_claims,
                    claim.claim_id,
                    row,
                    values,
                )
                final_fence = self._commit_fence(connection, fence)
                if not (
                    _same_fence_lease(commit_fence, final_fence)
                    and commit_fence.validated_at
                    <= final_fence.validated_at
                    < final_fence.valid_until
                ):
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition fence changed before claim commit"
                    )
                return persisted
        except AlpacaPaperOrderViewTransitionError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperOrderSnapshotPersistenceError,
            AlpacaPaperOrderSnapshotRuntimeError,
            ImmutableFactConflict,
            IntegrityError,
            SQLAlchemyError,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "durable order transition claim failed"
            ) from None

    def prepare_claimed(
        self,
        claim: AlpacaPaperOrderViewTransitionClaim,
        *,
        checked_at: datetime,
        fence: AccountFence,
    ) -> AlpacaPaperOrderViewTransitionConsumption:
        """Atomically consume one claim with unchanged Phase 4O preparation."""

        if type(claim) is not AlpacaPaperOrderViewTransitionClaim:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "claimed preparation requires an exact transition claim"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "claimed preparation requires an exact account fence"
            )
        claim._validate()
        checked_at = _require_utc(
            checked_at,
            "order transition preparation checked_at",
        )
        fence.__post_init__()
        if fence.account_id != claim.plan.account_id or checked_at < claim.selected_at:
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "claimed preparation conflicts with claim time or account"
            )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    claim.plan.account_id,
                )
                row = _claim_row(connection, claim_id=claim.claim_id)
                if row is None:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "claimed preparation references a missing durable claim"
                    )
                durable_claim = alpaca_paper_order_transition_claim_from_row(
                    connection,
                    row,
                )
                if durable_claim != claim:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "claimed preparation conflicts with durable claim"
                    )
                if (
                    _consumption_row(
                        connection,
                        claim_id=claim.claim_id,
                    )
                    is not None
                ):
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition claim was already consumed"
                    )
                commit_fence = self._commit_fence(connection, fence)
                if not (
                    _same_fence_lease(
                        claim.commit_fence_receipt,
                        commit_fence,
                    )
                    and claim.selected_at
                    <= checked_at
                    <= commit_fence.validated_at
                    < commit_fence.valid_until
                ):
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition claim lease changed before consumption"
                    )
                preparation = _prepare_alpaca_paper_order_snapshot_in_transaction(
                    connection,
                    claim.description,
                    checked_at=checked_at,
                    admitted_transition_round_id=claim.plan.round_id,
                )
                consumption = _alpaca_paper_order_view_transition_consumption(
                    claim=claim,
                    preparation=preparation,
                    commit_fence_receipt=commit_fence,
                )
                values = immutable_alpaca_paper_order_transition_consumption_values(consumption)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_order_transition_consumptions).values(
                            **values
                        )
                    )
                except IntegrityError:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition consumption conflicts with durable history"
                    ) from None
                persisted_row = _consumption_row(
                    connection,
                    consumption_id=consumption.consumption_id,
                    claim_id=claim.claim_id,
                )
                if persisted_row is None:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition consumption failed exact SQL readback"
                    )
                persisted = alpaca_paper_order_transition_consumption_from_row(
                    connection,
                    persisted_row,
                )
                if persisted != consumption:
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition consumption failed exact reconstruction"
                    )
                assert_immutable(
                    phase4_alpaca_paper_order_transition_consumptions,
                    consumption.consumption_id,
                    persisted_row,
                    values,
                )
                final_fence = self._commit_fence(connection, fence)
                if not (
                    _same_fence_lease(commit_fence, final_fence)
                    and commit_fence.validated_at
                    <= final_fence.validated_at
                    < final_fence.valid_until
                ):
                    raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                        "order transition fence changed before consumption commit"
                    )
                return persisted
        except AlpacaPaperOrderViewTransitionError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperOrderSnapshotPersistenceError,
            AlpacaPaperOrderSnapshotRuntimeError,
            ImmutableFactConflict,
            IntegrityError,
            SQLAlchemyError,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperOrderViewTransitionPersistenceConflict(
                "durable order transition consumption failed"
            ) from None

    def load_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperOrderViewTransitionClaim | None:
        if type(claim_id) is not str or not claim_id:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition claim ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _claim_row(connection, claim_id=claim_id)
            if row is None:
                return None
            return alpaca_paper_order_transition_claim_from_row(
                connection,
                row,
            )

    def load_consumption(
        self,
        consumption_id: str,
    ) -> AlpacaPaperOrderViewTransitionConsumption | None:
        if type(consumption_id) is not str or not consumption_id:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition consumption ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _consumption_row(
                connection,
                consumption_id=consumption_id,
            )
            if row is None:
                return None
            return alpaca_paper_order_transition_consumption_from_row(
                connection,
                row,
            )

    def load_consumption_for_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperOrderViewTransitionConsumption | None:
        if type(claim_id) is not str or not claim_id:
            raise AlpacaPaperOrderViewTransitionPersistenceError(
                "order transition claim ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _consumption_row(connection, claim_id=claim_id)
            if row is None:
                return None
            return alpaca_paper_order_transition_consumption_from_row(
                connection,
                row,
            )


__all__ = [
    "ALPACA_PAPER_ORDER_VIEW_TRANSITION_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperOrderViewTransitionPersistenceConflict",
    "AlpacaPaperOrderViewTransitionPersistenceError",
    "SqlAlpacaPaperOrderViewTransitionRepository",
    "alpaca_paper_order_transition_claim_from_row",
    "alpaca_paper_order_transition_consumption_from_row",
    "immutable_alpaca_paper_order_transition_claim_values",
    "immutable_alpaca_paper_order_transition_consumption_values",
    "immutable_alpaca_paper_order_transition_member_values",
    "verify_alpaca_paper_order_view_transition_integrity",
]
