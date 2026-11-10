"""Durable pair admission for single-use Alpaca paper position captures."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, SQLAlchemyError

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotRuntimeError,
    AlpacaPaperPositionSnapshotRuntimePlan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_view_transition import (
    ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
    ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
    AlpacaPaperPositionViewTransitionClaim,
    AlpacaPaperPositionViewTransitionConflict,
    AlpacaPaperPositionViewTransitionConsumption,
    AlpacaPaperPositionViewTransitionError,
    AlpacaPaperPositionViewTransitionPlan,
    AlpacaPaperPositionViewTransitionRole,
    _alpaca_paper_position_view_transition_claim,
    _alpaca_paper_position_view_transition_consumption,
    create_alpaca_paper_position_view_transition_plan,
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
from packages.persistence.alpaca_paper_account_binding import _binding_by_id
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_fence_position_at,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    AlpacaPaperPositionSnapshotPersistenceError,
    _binding_source,
    _plan_and_preparation_from_row,
    _plan_row,
    _prepare_alpaca_paper_position_snapshot_in_transaction,
    _receipt_from_row,
    _snapshot_row,
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
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_position_transition_claims,
    phase4_alpaca_paper_position_transition_consumptions,
    phase4_alpaca_paper_position_transition_members,
)

ALPACA_PAPER_POSITION_VIEW_TRANSITION_PERSISTENCE_CONTRACT_VERSION = (
    "phase4x-durable-position-view-transition-persistence-v1"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

PositionTransitionRow = Mapping[str, object] | RowMapping


class AlpacaPaperPositionViewTransitionPersistenceError(AlpacaPaperPositionViewTransitionError):
    """Durable position-pair admission state is unavailable."""


class AlpacaPaperPositionViewTransitionPersistenceConflict(
    AlpacaPaperPositionViewTransitionConflict,
    AlpacaPaperPositionViewTransitionPersistenceError,
):
    """Durable pair state conflicts with the requested transition."""


class SqlPositionViewTransitionFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _required_text(row: PositionTransitionRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            f"persisted position transition {field_name} must be nonempty text"
        )
    return value


def _optional_text(
    row: PositionTransitionRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            f"persisted position transition {field_name} must be nonempty text or null"
        )
    return value


def _required_integer(row: PositionTransitionRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            f"persisted position transition {field_name} must be an integer"
        )
    return value


def _optional_integer(
    row: PositionTransitionRow,
    field_name: str,
) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            f"persisted position transition {field_name} must be an integer or null"
        )
    return value


def _required_datetime(
    row: PositionTransitionRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            f"persisted position transition {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _optional_datetime(
    row: PositionTransitionRow,
    field_name: str,
) -> datetime | None:
    value = row[field_name]
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            f"persisted position transition {field_name} must be a datetime or null"
        )
    return as_aware_utc(value)


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperPositionViewTransitionPersistenceError(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperPositionViewTransitionPersistenceError(str(error)) from error
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
    transition: AlpacaPaperPositionViewTransitionPlan,
    role: AlpacaPaperPositionViewTransitionRole,
) -> tuple[str, str, str]:
    plan = transition.selected_plan(role)
    member_id = canonical_id(
        "alpaca-paper-position-view-transition-member",
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
        transition.round_id,
        role,
        plan.plan_id,
        plan.semantic_sha256,
    )
    material = (
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
        "transition_member",
        member_id,
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
        transition.round_id,
        transition.semantic_sha256,
        role,
        transition.account_id,
        transition.expected_provider_account_id,
        plan.plan_id,
        plan.semantic_sha256,
        plan.description.capture_id,
        False,
        False,
        False,
        False,
    )
    return member_id, canonical_json_text(material), _semantic_sha256(material)


def immutable_alpaca_paper_position_transition_member_values(
    transition: AlpacaPaperPositionViewTransitionPlan,
    role: AlpacaPaperPositionViewTransitionRole,
) -> dict[str, Any]:
    """Return the immutable registration of one exact pair member."""

    if type(transition) is not AlpacaPaperPositionViewTransitionPlan:
        raise AlpacaPaperPositionViewTransitionPersistenceError(
            "transition membership requires an exact transition plan"
        )
    if type(role) is not AlpacaPaperPositionViewTransitionRole:
        raise AlpacaPaperPositionViewTransitionPersistenceError(
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
        "expected_provider_account_id": transition.expected_provider_account_id,
        "plan_id": plan.plan_id,
        "capture_id": plan.description.capture_id,
        "capture_idempotency_key": plan.description.capture_idempotency_key,
        "description_sha256": plan.description.semantic_sha256,
        "provider_id": plan.reference.provider_id,
        "environment": plan.reference.environment,
        "capability_sha256": plan.reference.capability_sha256,
        "secret_ref": plan.reference.secret_ref,
        "secret_version": plan.reference.secret_version,
        "credential_reference_sha256": plan.reference.semantic_sha256,
        "account_binding_id": plan.account_binding.binding_id,
        "account_binding_sha256": plan.account_binding.semantic_sha256,
        "account_binding_sequence": plan.account_binding.sequence_number,
        "plan_canonical_payload": plan.canonical_json,
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
            sa.select(phase4_alpaca_paper_position_transition_members)
            .where(phase4_alpaca_paper_position_transition_members.c.round_id == round_id)
            .order_by(phase4_alpaca_paper_position_transition_members.c.member_role)
        )
        .mappings()
        .all()
    )


def _plan_from_member_row(
    connection: Connection,
    row: PositionTransitionRow,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    binding = _binding_by_id(connection, _required_text(row, "account_binding_id"))
    if binding is None:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition member references a missing account binding"
        )
    binding = _binding_source(
        connection,
        account_id=_required_text(row, "account_id"),
        binding_id=binding.binding_id,
        binding_sha256=_required_text(row, "account_binding_sha256"),
        expected_provider_account_id=_required_text(
            row,
            "expected_provider_account_id",
        ),
        checked_at=binding.qualified_at,
        require_terminal=False,
    )
    reference = AlpacaPaperCredentialReference(
        account_id=binding.account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=_required_text(row, "secret_ref"),
        secret_version=_required_text(row, "secret_version"),
    )
    description = create_alpaca_paper_position_snapshot_description(
        account_id=binding.account_id,
        capture_idempotency_key=_required_text(
            row,
            "capture_idempotency_key",
        ),
    )
    plan = AlpacaPaperPositionSnapshotRuntimePlan(
        description=description,
        reference=reference,
        account_binding=binding,
    )
    expected = {
        "account_id": plan.description.account_id,
        "expected_provider_account_id": plan.reference.expected_provider_account_id,
        "plan_id": plan.plan_id,
        "capture_id": plan.description.capture_id,
        "description_sha256": plan.description.semantic_sha256,
        "provider_id": plan.reference.provider_id,
        "environment": plan.reference.environment,
        "capability_sha256": plan.reference.capability_sha256,
        "credential_reference_sha256": plan.reference.semantic_sha256,
        "account_binding_sequence": plan.account_binding.sequence_number,
        "plan_canonical_payload": plan.canonical_json,
        "plan_sha256": plan.semantic_sha256,
    }
    if any(
        not same_value(row[field_name], expected_value)
        for field_name, expected_value in expected.items()
    ):
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition member conflicts with exact plan reconstruction"
        )
    return plan


def _transition_from_member_rows(
    connection: Connection,
    rows: tuple[RowMapping, ...],
) -> AlpacaPaperPositionViewTransitionPlan:
    if len(rows) != 2:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition round must have exactly two members"
        )
    by_role: dict[AlpacaPaperPositionViewTransitionRole, RowMapping] = {}
    for row in rows:
        try:
            role = AlpacaPaperPositionViewTransitionRole(_required_text(row, "member_role"))
        except ValueError:
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition member role is invalid"
            ) from None
        if role in by_role:
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition member role is duplicated"
            )
        by_role[role] = row
    if set(by_role) != set(AlpacaPaperPositionViewTransitionRole):
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition round lacks an exact ordered pair"
        )
    transition = create_alpaca_paper_position_view_transition_plan(
        earlier_plan=_plan_from_member_row(
            connection,
            by_role[AlpacaPaperPositionViewTransitionRole.EARLIER],
        ),
        later_plan=_plan_from_member_row(
            connection,
            by_role[AlpacaPaperPositionViewTransitionRole.LATER],
        ),
    )
    for role, row in by_role.items():
        expected = immutable_alpaca_paper_position_transition_member_values(
            transition,
            role,
        )
        if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition member failed exact reconstruction"
            )
    return transition


def _load_transition(
    connection: Connection,
    round_id: str,
) -> AlpacaPaperPositionViewTransitionPlan:
    transition = _transition_from_member_rows(
        connection,
        _member_rows(connection, round_id),
    )
    if transition.round_id != round_id:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition round ID conflicts with its members"
        )
    return transition


def _load_complete_receipt(
    connection: Connection,
    *,
    plan_id: str,
    capture_id: str,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    plan_row = _plan_row(
        connection,
        plan_id=plan_id,
        capture_id=capture_id,
    )
    snapshot_row = _snapshot_row(
        connection,
        plan_id=plan_id,
        capture_id=capture_id,
    )
    if plan_row is None or snapshot_row is None:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition requires one complete earlier snapshot"
        )
    plan, preparation = _plan_and_preparation_from_row(connection, plan_row)
    if plan.plan_id != plan_id or plan.description.capture_id != capture_id:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition earlier plan failed exact identity reconstruction"
        )
    receipt = _receipt_from_row(
        connection,
        snapshot_row,
        plan,
        preparation,
    )
    if not receipt.durable_authenticated_position_snapshot_established:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition earlier snapshot is not authenticated"
        )
    return receipt


def _fence_from_row(
    connection: Connection,
    row: PositionTransitionRow,
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
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition fence references a missing lease"
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
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition fence conflicts with its lease source"
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
    role: AlpacaPaperPositionViewTransitionRole | None = None,
) -> RowMapping | None:
    if claim_id is None and (round_id is None or role is None):
        raise AssertionError("claim lookup requires an ID or exact round role")
    conditions = []
    if claim_id is not None:
        conditions.append(phase4_alpaca_paper_position_transition_claims.c.claim_id == claim_id)
    if round_id is not None:
        conditions.append(phase4_alpaca_paper_position_transition_claims.c.round_id == round_id)
    if role is not None:
        conditions.append(
            phase4_alpaca_paper_position_transition_claims.c.selected_role == role.value
        )
    try:
        return (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_transition_claims).where(*conditions)
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition claim identity is not unique"
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
            phase4_alpaca_paper_position_transition_consumptions.c.consumption_id == consumption_id
        )
    if claim_id is not None:
        conditions.append(
            phase4_alpaca_paper_position_transition_consumptions.c.claim_id == claim_id
        )
    try:
        return (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_transition_consumptions).where(*conditions)
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition consumption identity is not unique"
        ) from None


def _source_values(
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None,
) -> dict[str, object]:
    if receipt is None:
        return {
            "prior_snapshot_receipt_id": None,
            "prior_snapshot_receipt_sha256": None,
            "prior_plan_id": None,
            "prior_capture_id": None,
            "prior_plan_sha256": None,
            "prior_persisted_snapshot_sha256": None,
            "prior_ingress_receipt_id": None,
            "prior_ingress_receipt_sha256": None,
            "prior_ingress_sequence": None,
            "prior_source_committed_at": None,
        }
    persisted = receipt.persisted_snapshot
    ingress = persisted.receipt
    return {
        "prior_snapshot_receipt_id": receipt.receipt_id,
        "prior_snapshot_receipt_sha256": receipt.semantic_sha256,
        "prior_plan_id": receipt.plan.plan_id,
        "prior_capture_id": receipt.capture_id,
        "prior_plan_sha256": receipt.plan.semantic_sha256,
        "prior_persisted_snapshot_sha256": persisted.semantic_sha256,
        "prior_ingress_receipt_id": ingress.receipt_id,
        "prior_ingress_receipt_sha256": ingress.semantic_sha256,
        "prior_ingress_sequence": ingress.ingress_sequence,
        "prior_source_committed_at": receipt.commit_fence_receipt.validated_at,
    }


def immutable_alpaca_paper_position_transition_claim_values(
    claim: AlpacaPaperPositionViewTransitionClaim,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one role claim."""

    if type(claim) is not AlpacaPaperPositionViewTransitionClaim:
        raise AlpacaPaperPositionViewTransitionPersistenceError(
            "transition persistence requires an exact claim"
        )
    claim._validate()
    transition = claim.plan
    earlier_values = immutable_alpaca_paper_position_transition_member_values(
        transition,
        AlpacaPaperPositionViewTransitionRole.EARLIER,
    )
    later_values = immutable_alpaca_paper_position_transition_member_values(
        transition,
        AlpacaPaperPositionViewTransitionRole.LATER,
    )
    selected_values = (
        earlier_values
        if claim.selected_role is AlpacaPaperPositionViewTransitionRole.EARLIER
        else later_values
    )
    fence = claim.commit_fence_receipt
    values: dict[str, Any] = {
        "claim_id": claim.claim_id,
        "round_id": transition.round_id,
        "transition_plan_sha256": transition.semantic_sha256,
        "selected_role": claim.selected_role.value,
        "account_id": transition.account_id,
        "expected_provider_account_id": transition.expected_provider_account_id,
        "earlier_member_id": earlier_values["member_id"],
        "earlier_member_role": AlpacaPaperPositionViewTransitionRole.EARLIER.value,
        "earlier_member_sha256": earlier_values["semantic_sha256"],
        "earlier_plan_id": transition.earlier_plan.plan_id,
        "earlier_capture_id": transition.earlier_plan.description.capture_id,
        "earlier_plan_sha256": transition.earlier_plan.semantic_sha256,
        "later_member_id": later_values["member_id"],
        "later_member_role": AlpacaPaperPositionViewTransitionRole.LATER.value,
        "later_member_sha256": later_values["semantic_sha256"],
        "later_plan_id": transition.later_plan.plan_id,
        "later_capture_id": transition.later_plan.description.capture_id,
        "later_plan_sha256": transition.later_plan.semantic_sha256,
        "selected_member_id": selected_values["member_id"],
        "selected_plan_id": claim.selected_plan.plan_id,
        "selected_capture_id": claim.selected_plan.description.capture_id,
        "selected_plan_sha256": claim.selected_plan.semantic_sha256,
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
        "transition_policy_sha256": (ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256),
        "canonical_payload": claim.canonical_json,
        "semantic_sha256": claim.semantic_sha256,
    }
    values.update(_source_values(claim.prior_earlier_receipt))
    return values


def alpaca_paper_position_transition_claim_from_row(
    connection: Connection,
    row: PositionTransitionRow,
) -> AlpacaPaperPositionViewTransitionClaim:
    """Reconstruct one claim from its complete immutable sources."""

    try:
        transition = _load_transition(
            connection,
            _required_text(row, "round_id"),
        )
        role = AlpacaPaperPositionViewTransitionRole(_required_text(row, "selected_role"))
        prior: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None = None
        if role is AlpacaPaperPositionViewTransitionRole.LATER:
            prior_plan_id = _optional_text(row, "prior_plan_id")
            prior_capture_id = _optional_text(row, "prior_capture_id")
            if prior_plan_id is None or prior_capture_id is None:
                raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                    "later transition claim lacks its exact earlier source"
                )
            prior = _load_complete_receipt(
                connection,
                plan_id=prior_plan_id,
                capture_id=prior_capture_id,
            )
        fence = _fence_from_row(
            connection,
            row,
            validated_at_field="selected_at",
            receipt_sha256_field="commit_fence_receipt_sha256",
        )
        claim = _alpaca_paper_position_view_transition_claim(
            plan=transition,
            selected_role=role,
            prior_earlier_receipt=prior,
            commit_fence_receipt=fence,
        )
        expected = immutable_alpaca_paper_position_transition_claim_values(claim)
        if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition claim failed exact reconstruction"
            )
        return claim
    except AlpacaPaperPositionViewTransitionError:
        raise
    except (
        AccountCoordinatorError,
        AlpacaPaperPositionSnapshotRuntimeError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "persisted position transition claim is malformed"
        ) from error


def immutable_alpaca_paper_position_transition_consumption_values(
    consumption: AlpacaPaperPositionViewTransitionConsumption,
) -> dict[str, Any]:
    """Return the immutable binding between one claim and one U preparation."""

    if type(consumption) is not AlpacaPaperPositionViewTransitionConsumption:
        raise AlpacaPaperPositionViewTransitionPersistenceError(
            "transition persistence requires an exact consumption"
        )
    consumption._validate()
    claim = consumption.claim
    preparation = consumption.preparation
    selected_member = immutable_alpaca_paper_position_transition_member_values(
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
        "selected_plan_id": preparation.plan.plan_id,
        "selected_capture_id": preparation.plan.description.capture_id,
        "selected_plan_sha256": preparation.plan.semantic_sha256,
        "account_id": preparation.plan.description.account_id,
        "preparation_id": preparation.preparation_id,
        "preparation_sha256": preparation.semantic_sha256,
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


def alpaca_paper_position_transition_consumption_from_row(
    connection: Connection,
    row: PositionTransitionRow,
) -> AlpacaPaperPositionViewTransitionConsumption:
    """Reconstruct one consumed claim and its exact unchanged U preparation."""

    claim_row = _claim_row(
        connection,
        claim_id=_required_text(row, "claim_id"),
    )
    if claim_row is None:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition consumption references a missing claim"
        )
    claim = alpaca_paper_position_transition_claim_from_row(
        connection,
        claim_row,
    )
    plan_row = _plan_row(
        connection,
        plan_id=_required_text(row, "selected_plan_id"),
        capture_id=_required_text(row, "selected_capture_id"),
    )
    if plan_row is None:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition consumption references a missing U plan"
        )
    _, preparation = _plan_and_preparation_from_row(connection, plan_row)
    fence = _fence_from_row(
        connection,
        row,
        validated_at_field="consumed_at",
        receipt_sha256_field="commit_fence_receipt_sha256",
    )
    consumption = _alpaca_paper_position_view_transition_consumption(
        claim=claim,
        preparation=preparation,
        commit_fence_receipt=fence,
    )
    expected = immutable_alpaca_paper_position_transition_consumption_values(consumption)
    if any(not same_value(row[field_name], value) for field_name, value in expected.items()):
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "position transition consumption failed exact reconstruction"
        )
    return consumption


def _verify_alpaca_paper_position_view_transition_integrity(
    connection: Connection,
) -> None:
    member_rounds = tuple(
        connection.scalars(
            sa.select(phase4_alpaca_paper_position_transition_members.c.round_id)
            .distinct()
            .order_by(phase4_alpaca_paper_position_transition_members.c.round_id)
        )
    )
    for round_id in member_rounds:
        transition = _load_transition(connection, round_id)
        earlier_claim_row = _claim_row(
            connection,
            round_id=transition.round_id,
            role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        )
        if earlier_claim_row is None:
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition members exist without their earlier claim"
            )

    claims = connection.execute(
        sa.select(phase4_alpaca_paper_position_transition_claims).order_by(
            phase4_alpaca_paper_position_transition_claims.c.claim_id
        )
    ).mappings()
    for row in claims:
        claim = alpaca_paper_position_transition_claim_from_row(connection, row)
        if claim.selected_role is AlpacaPaperPositionViewTransitionRole.LATER:
            earlier_row = _claim_row(
                connection,
                round_id=claim.plan.round_id,
                role=AlpacaPaperPositionViewTransitionRole.EARLIER,
            )
            if earlier_row is None:
                raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                    "later transition claim lacks its earlier claim"
                )
            earlier_claim = alpaca_paper_position_transition_claim_from_row(
                connection,
                earlier_row,
            )
            earlier_consumption = _consumption_row(
                connection,
                claim_id=earlier_claim.claim_id,
            )
            if earlier_consumption is None:
                raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                    "later transition claim lacks earlier claim consumption"
                )
            alpaca_paper_position_transition_consumption_from_row(
                connection,
                earlier_consumption,
            )

    consumptions = connection.execute(
        sa.select(phase4_alpaca_paper_position_transition_consumptions).order_by(
            phase4_alpaca_paper_position_transition_consumptions.c.consumption_id
        )
    ).mappings()
    for row in consumptions:
        alpaca_paper_position_transition_consumption_from_row(connection, row)

    unconsumed_registered_plan = connection.scalar(
        sa.select(phase4_alpaca_paper_position_snapshot_plans.c.plan_id)
        .join(
            phase4_alpaca_paper_position_transition_members,
            phase4_alpaca_paper_position_transition_members.c.plan_id
            == phase4_alpaca_paper_position_snapshot_plans.c.plan_id,
        )
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_position_transition_consumptions.c.selected_plan_id
                    == phase4_alpaca_paper_position_snapshot_plans.c.plan_id
                )
            )
        )
        .limit(1)
    )
    if unconsumed_registered_plan is not None:
        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
            "registered U plan exists without atomic claim consumption"
        )


def verify_alpaca_paper_position_view_transition_integrity(
    engine: Engine,
) -> None:
    """Authenticate every durable pair member, claim, and consumption."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperPositionViewTransitionPersistenceError(
            "position transition verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperPositionViewTransitionPersistenceError(
            f"position transition verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_position_view_transition_integrity(connection)


class SqlAlpacaPaperPositionViewTransitionRepository:
    """Register pair members, claim one role, and consume it exactly once."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlPositionViewTransitionFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "SQL position transitions require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                f"SQL position transitions do not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(coordinator, "revalidate_for_commit_in_transaction", None)):
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "SQL position transitions require a SQL fence validator"
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
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition current call fence validation failed"
            ) from None

    @staticmethod
    def _assert_absent(
        connection: Connection,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> None:
        if (
            _plan_row(
                connection,
                plan_id=plan.plan_id,
                capture_id=plan.description.capture_id,
            )
            is not None
            or _snapshot_row(
                connection,
                plan_id=plan.plan_id,
                capture_id=plan.description.capture_id,
            )
            is not None
        ):
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition selected an existing stalled or complete source"
            )

    def claim(
        self,
        transition: AlpacaPaperPositionViewTransitionPlan,
        *,
        selected_role: AlpacaPaperPositionViewTransitionRole,
        fence: AccountFence,
    ) -> AlpacaPaperPositionViewTransitionClaim:
        """Return an exact retry or durably claim one eligible pair role."""

        if type(transition) is not AlpacaPaperPositionViewTransitionPlan:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "position transition claim requires an exact transition plan"
            )
        if type(selected_role) is not AlpacaPaperPositionViewTransitionRole:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "position transition claim requires an exact role"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "position transition claim requires an exact account fence"
            )
        transition.__post_init__()
        fence.__post_init__()
        if fence.account_id != transition.account_id:
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "position transition claim fence crosses accounts"
            )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    transition.account_id,
                )
                existing_row = _claim_row(
                    connection,
                    round_id=transition.round_id,
                    role=selected_role,
                )
                if existing_row is not None:
                    existing = alpaca_paper_position_transition_claim_from_row(
                        connection,
                        existing_row,
                    )
                    if existing.plan != transition:
                        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                            "position transition retry conflicts with durable pair"
                        )
                    # Exact retry reauthenticates the current call but preserves
                    # the immutable historical claim and its original fence.
                    self._commit_fence(connection, fence)
                    return existing

                prior: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None = None
                if selected_role is AlpacaPaperPositionViewTransitionRole.EARLIER:
                    if _member_rows(connection, transition.round_id):
                        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                            "position transition members exist without exact claim history"
                        )
                    self._assert_absent(connection, transition.earlier_plan)
                    self._assert_absent(connection, transition.later_plan)
                    for role in AlpacaPaperPositionViewTransitionRole:
                        values = immutable_alpaca_paper_position_transition_member_values(
                            transition,
                            role,
                        )
                        try:
                            connection.execute(
                                sa.insert(phase4_alpaca_paper_position_transition_members).values(
                                    **values
                                )
                            )
                        except IntegrityError:
                            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                                "position transition membership conflicts with durable history"
                            ) from None
                else:
                    durable_transition = _load_transition(
                        connection,
                        transition.round_id,
                    )
                    if durable_transition != transition:
                        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                            "later transition claim conflicts with registered pair"
                        )
                    earlier_row = _claim_row(
                        connection,
                        round_id=transition.round_id,
                        role=AlpacaPaperPositionViewTransitionRole.EARLIER,
                    )
                    if earlier_row is None:
                        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                            "later transition claim requires its earlier claim"
                        )
                    earlier_claim = alpaca_paper_position_transition_claim_from_row(
                        connection,
                        earlier_row,
                    )
                    earlier_consumption = _consumption_row(
                        connection,
                        claim_id=earlier_claim.claim_id,
                    )
                    if earlier_consumption is None:
                        raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                            "later transition claim requires earlier claim consumption"
                        )
                    alpaca_paper_position_transition_consumption_from_row(
                        connection,
                        earlier_consumption,
                    )
                    prior = _load_complete_receipt(
                        connection,
                        plan_id=transition.earlier_plan.plan_id,
                        capture_id=transition.earlier_plan.description.capture_id,
                    )
                    self._assert_absent(connection, transition.later_plan)

                commit_fence = self._commit_fence(connection, fence)
                claim = _alpaca_paper_position_view_transition_claim(
                    plan=transition,
                    selected_role=selected_role,
                    prior_earlier_receipt=prior,
                    commit_fence_receipt=commit_fence,
                )
                values = immutable_alpaca_paper_position_transition_claim_values(claim)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_position_transition_claims).values(**values)
                    )
                except IntegrityError:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition claim conflicts with durable history"
                    ) from None
                row = _claim_row(
                    connection,
                    claim_id=claim.claim_id,
                    round_id=transition.round_id,
                    role=selected_role,
                )
                if row is None:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition claim failed exact SQL readback"
                    )
                persisted = alpaca_paper_position_transition_claim_from_row(
                    connection,
                    row,
                )
                if persisted != claim:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition claim failed exact reconstruction"
                    )
                assert_immutable(
                    phase4_alpaca_paper_position_transition_claims,
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
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition fence changed before claim commit"
                    )
                return persisted
        except AlpacaPaperPositionViewTransitionError:
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
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "durable position transition claim failed"
            ) from None

    def prepare_claimed(
        self,
        claim: AlpacaPaperPositionViewTransitionClaim,
        *,
        checked_at: datetime,
        fence: AccountFence,
    ) -> AlpacaPaperPositionViewTransitionConsumption:
        """Atomically consume one claim with the unchanged Phase 4U preparation."""

        if type(claim) is not AlpacaPaperPositionViewTransitionClaim:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "claimed preparation requires an exact transition claim"
            )
        if type(fence) is not AccountFence:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "claimed preparation requires an exact account fence"
            )
        claim._validate()
        checked_at = _require_utc(
            checked_at,
            "position transition preparation checked_at",
        )
        fence.__post_init__()
        if fence.account_id != claim.plan.account_id or checked_at < claim.selected_at:
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
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
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "claimed preparation references a missing durable claim"
                    )
                durable_claim = alpaca_paper_position_transition_claim_from_row(
                    connection,
                    row,
                )
                if durable_claim != claim:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "claimed preparation conflicts with durable claim"
                    )
                if _consumption_row(connection, claim_id=claim.claim_id) is not None:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition claim was already consumed"
                    )
                self._assert_absent(connection, claim.selected_plan)
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
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition claim lease changed before consumption"
                    )
                preparation = _prepare_alpaca_paper_position_snapshot_in_transaction(
                    connection,
                    claim.selected_plan,
                    checked_at=checked_at,
                    admitted_transition_round_id=claim.plan.round_id,
                )
                consumption = _alpaca_paper_position_view_transition_consumption(
                    claim=claim,
                    preparation=preparation,
                    commit_fence_receipt=commit_fence,
                )
                values = immutable_alpaca_paper_position_transition_consumption_values(consumption)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_position_transition_consumptions).values(
                            **values
                        )
                    )
                except IntegrityError:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition consumption conflicts with durable history"
                    ) from None
                persisted_row = _consumption_row(
                    connection,
                    consumption_id=consumption.consumption_id,
                    claim_id=claim.claim_id,
                )
                if persisted_row is None:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition consumption failed exact SQL readback"
                    )
                persisted = alpaca_paper_position_transition_consumption_from_row(
                    connection,
                    persisted_row,
                )
                if persisted != consumption:
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition consumption failed exact reconstruction"
                    )
                assert_immutable(
                    phase4_alpaca_paper_position_transition_consumptions,
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
                    raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                        "position transition fence changed before consumption commit"
                    )
                return persisted
        except AlpacaPaperPositionViewTransitionError:
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
            raise AlpacaPaperPositionViewTransitionPersistenceConflict(
                "durable position transition consumption failed"
            ) from None

    def load_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperPositionViewTransitionClaim | None:
        if type(claim_id) is not str or not claim_id:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "position transition claim ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _claim_row(connection, claim_id=claim_id)
            if row is None:
                return None
            return alpaca_paper_position_transition_claim_from_row(connection, row)

    def load_consumption(
        self,
        consumption_id: str,
    ) -> AlpacaPaperPositionViewTransitionConsumption | None:
        if type(consumption_id) is not str or not consumption_id:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "position transition consumption ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _consumption_row(
                connection,
                consumption_id=consumption_id,
            )
            if row is None:
                return None
            return alpaca_paper_position_transition_consumption_from_row(
                connection,
                row,
            )

    def load_consumption_for_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperPositionViewTransitionConsumption | None:
        """Load the sole consumption for one exact claim, when present."""

        if type(claim_id) is not str or not claim_id:
            raise AlpacaPaperPositionViewTransitionPersistenceError(
                "position transition claim ID must be nonempty text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = _consumption_row(
                connection,
                claim_id=claim_id,
            )
            if row is None:
                return None
            return alpaca_paper_position_transition_consumption_from_row(
                connection,
                row,
            )


__all__ = [
    "ALPACA_PAPER_POSITION_VIEW_TRANSITION_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperPositionViewTransitionPersistenceConflict",
    "AlpacaPaperPositionViewTransitionPersistenceError",
    "SqlAlpacaPaperPositionViewTransitionRepository",
    "alpaca_paper_position_transition_claim_from_row",
    "alpaca_paper_position_transition_consumption_from_row",
    "immutable_alpaca_paper_position_transition_claim_values",
    "immutable_alpaca_paper_position_transition_consumption_values",
    "immutable_alpaca_paper_position_transition_member_values",
    "verify_alpaca_paper_position_view_transition_integrity",
]
