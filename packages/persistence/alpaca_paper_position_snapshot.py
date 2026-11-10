"""Single-use SQL persistence for authenticated Alpaca paper positions."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, MultipleResultsFound

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    AlpacaPaperCredentialResolutionReceipt,
    _alpaca_paper_account_identity_continuity_receipt,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID,
    ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimeError,
    AlpacaPaperPositionSnapshotRuntimePlan,
    AlpacaPaperPositionSnapshotTransportRequest,
    AlpacaPaperPositionSnapshotTransportResponse,
    _alpaca_paper_authenticated_position_snapshot_evidence,
    _alpaca_paper_authenticated_position_snapshot_receipt,
    _alpaca_paper_position_snapshot_preparation_receipt,
)
from packages.adapters.broker.alpaca_paper_positions import (
    PersistedAlpacaPaperPositionSnapshot,
    create_alpaca_paper_position_snapshot_description,
    decode_alpaca_paper_position_snapshot_response,
)
from packages.application.alpaca_paper_position_view_supervisor import (
    AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    AlpacaPaperPositionSnapshotSupervisorSourceStage,
    _alpaca_paper_authenticated_position_snapshot_supervisor_state,
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
    phase4_alpaca_paper_account_bindings,
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_position_snapshots,
    phase4_alpaca_paper_position_transition_members,
)

ALPACA_PAPER_POSITION_SNAPSHOT_PERSISTENCE_CONTRACT_VERSION = (
    "phase4u-single-use-position-snapshot-persistence-v1"
)
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

PositionSnapshotRow = Mapping[str, object] | RowMapping


class AlpacaPaperPositionSnapshotPersistenceError(AlpacaPaperPositionSnapshotRuntimeError):
    """Durable authenticated position-snapshot history is unavailable."""


class AlpacaPaperPositionSnapshotPersistenceConflict(
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotPersistenceError,
):
    """Durable position-snapshot state conflicts with exact source evidence."""


class SqlPositionSnapshotFenceValidator(Protocol):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt: ...


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperPositionSnapshotPersistenceError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperPositionSnapshotPersistenceError(str(error)) from error
    return value


def _required_text(row: PositionSnapshotRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            f"persisted position snapshot {field_name} must be text"
        )
    return value


def _required_integer(row: PositionSnapshotRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            f"persisted position snapshot {field_name} must be an integer"
        )
    return value


def _required_datetime(
    row: PositionSnapshotRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            f"persisted position snapshot {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _plan_row(
    connection: Connection,
    *,
    plan_id: str,
    capture_id: str,
) -> RowMapping | None:
    try:
        by_plan = (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_snapshot_plans).where(
                    phase4_alpaca_paper_position_snapshot_plans.c.plan_id == plan_id
                )
            )
            .mappings()
            .one_or_none()
        )
        by_capture = (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_snapshot_plans).where(
                    phase4_alpaca_paper_position_snapshot_plans.c.capture_id == capture_id
                )
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot claim identity is not unique"
        ) from None
    if by_plan is None and by_capture is None:
        return None
    if (
        by_plan is None
        or by_capture is None
        or by_plan["plan_id"] != by_capture["plan_id"]
        or by_plan["capture_id"] != by_capture["capture_id"]
    ):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot plan ID and capture ID disagree"
        )
    return by_plan


def _snapshot_row(
    connection: Connection,
    *,
    plan_id: str,
    capture_id: str,
) -> RowMapping | None:
    try:
        by_plan = (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_snapshots).where(
                    phase4_alpaca_paper_position_snapshots.c.plan_id == plan_id
                )
            )
            .mappings()
            .one_or_none()
        )
        by_capture = (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_snapshots).where(
                    phase4_alpaca_paper_position_snapshots.c.capture_id == capture_id
                )
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot receipt identity is not unique"
        ) from None
    if by_plan is None and by_capture is None:
        return None
    if (
        by_plan is None
        or by_capture is None
        or by_plan["receipt_id"] != by_capture["receipt_id"]
        or by_plan["plan_id"] != by_capture["plan_id"]
        or by_plan["capture_id"] != by_capture["capture_id"]
    ):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot receipt plan ID and capture ID disagree"
        )
    return by_plan


def _binding_source(
    connection: Connection,
    *,
    account_id: str,
    binding_id: str,
    binding_sha256: str,
    expected_provider_account_id: str,
    checked_at: datetime,
    require_terminal: bool,
) -> AlpacaPaperAuthenticatedAccountBinding:
    binding = _binding_by_id(connection, binding_id)
    if binding is None:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot references a missing account binding"
        )
    head = _authenticate_binding_position(connection, binding)
    _authenticate_account_binding_sources(connection, binding)
    successor_before_check = connection.scalar(
        sa.select(phase4_alpaca_paper_account_bindings.c.binding_id)
        .where(
            phase4_alpaca_paper_account_bindings.c.account_id == binding.account_id,
            phase4_alpaca_paper_account_bindings.c.sequence_number > binding.sequence_number,
            phase4_alpaca_paper_account_bindings.c.qualified_at < checked_at,
        )
        .limit(1)
    )
    if (
        binding.account_id != account_id
        or binding.semantic_sha256 != binding_sha256
        or binding.expected_provider_account_id != expected_provider_account_id
        or checked_at < binding.qualified_at
        or successor_before_check is not None
    ):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot conflicts with its exact account-binding source"
        )
    if require_terminal and _terminal_binding(connection, head) != binding:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot account binding is no longer terminal"
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
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot references a missing request permit"
        )
    _authenticate_permit_position(connection, record)
    if (
        record.permit.account_id != account_id
        or record.permit.semantic_sha256 != permit_sha256
        or record.demand.demand_id != demand_id
        or record.demand.semantic_sha256 != demand_sha256
        or record.policy.semantic_sha256 != policy_sha256
    ):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot conflicts with its exact permit source"
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
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot references a missing raw ingress receipt"
        )
    _authenticate_ingress_position(connection, receipt)
    if (
        receipt.account_id != account_id
        or receipt.semantic_sha256 != receipt_sha256
        or receipt.ingress_sequence != ingress_sequence
    ):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot conflicts with its exact raw ingress source"
        )
    return receipt


def _fence_source(
    connection: Connection,
    row: PositionSnapshotRow,
    *,
    phase: str,
) -> AccountFenceReceipt:
    if phase not in {"pre", "post", "final", "commit"}:
        raise AssertionError("position snapshot fence phase must be exact")
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
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            f"position snapshot {phase} fence references a missing lease"
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
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            f"position snapshot {phase} fence conflicts with its lease source"
        )
    _authenticate_fence_position_at(
        connection,
        receipt,
        checked_at=validated_at,
    )
    return receipt


def immutable_alpaca_paper_position_snapshot_plan_values(
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
) -> dict[str, Any]:
    """Return the complete immutable SQL representation of one fresh claim."""

    if type(preparation) is not AlpacaPaperPositionSnapshotPreparationReceipt:
        raise AlpacaPaperPositionSnapshotPersistenceError(
            "position snapshot persistence requires an exact preparation"
        )
    preparation._validate()
    plan = preparation.plan
    description = plan.description
    reference = plan.reference
    binding = plan.account_binding
    return {
        "plan_id": plan.plan_id,
        "capture_id": description.capture_id,
        "account_id": description.account_id,
        "capture_idempotency_key": description.capture_idempotency_key,
        "description_sha256": description.semantic_sha256,
        "provider_id": reference.provider_id,
        "environment": reference.environment,
        "capability_sha256": reference.capability_sha256,
        "expected_provider_account_id": (reference.expected_provider_account_id),
        "secret_ref": reference.secret_ref,
        "secret_version": reference.secret_version,
        "credential_reference_sha256": reference.semantic_sha256,
        "account_binding_id": binding.binding_id,
        "account_binding_sha256": binding.semantic_sha256,
        "account_binding_sequence": binding.sequence_number,
        "prepared_at": preparation.prepared_at,
        "preparation_id": preparation.preparation_id,
        "preparation_sha256": preparation.semantic_sha256,
        "plan_canonical_payload": plan.canonical_json,
        "preparation_canonical_payload": preparation.canonical_json,
        "semantic_sha256": plan.semantic_sha256,
    }


def _plan_and_preparation_from_row(
    connection: Connection,
    row: PositionSnapshotRow,
) -> tuple[
    AlpacaPaperPositionSnapshotRuntimePlan,
    AlpacaPaperPositionSnapshotPreparationReceipt,
]:
    try:
        prepared_at = _required_datetime(row, "prepared_at")
        binding = _binding_source(
            connection,
            account_id=_required_text(row, "account_id"),
            binding_id=_required_text(row, "account_binding_id"),
            binding_sha256=_required_text(row, "account_binding_sha256"),
            expected_provider_account_id=_required_text(
                row,
                "expected_provider_account_id",
            ),
            checked_at=prepared_at,
            require_terminal=False,
        )
        if binding.sequence_number != _required_integer(
            row,
            "account_binding_sequence",
        ):
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "position snapshot plan conflicts with its binding sequence"
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
        preparation = _alpaca_paper_position_snapshot_preparation_receipt(
            plan,
            prepared_at=prepared_at,
        )
        expected_values = immutable_alpaca_paper_position_snapshot_plan_values(preparation)
        if any(
            not same_value(row[field_name], value) for field_name, value in expected_values.items()
        ):
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "persisted position snapshot plan conflicts with exact reconstruction"
            )
        return plan, preparation
    except AlpacaPaperPositionSnapshotRuntimeError:
        raise
    except (
        AccountCoordinatorError,
        BrokerIngressError,
        BrokerRequestBudgetError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "persisted position snapshot plan is malformed"
        ) from error


def immutable_alpaca_paper_position_snapshot_values(
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one receipt."""

    if type(receipt) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        raise AlpacaPaperPositionSnapshotPersistenceError(
            "position snapshot persistence requires an exact receipt"
        )
    receipt._validate()
    evidence = receipt.evidence
    plan = evidence.plan
    preparation = evidence.preparation
    credential = evidence.credential_receipt
    permit = evidence.permit
    ingress = evidence.persisted_snapshot.receipt
    observation = evidence.persisted_snapshot.observation
    pre_fence = evidence.pre_fence_receipt
    post_fence = evidence.post_fence_receipt
    final_fence = evidence.final_fence_receipt
    commit_fence = receipt.commit_fence_receipt
    return {
        "receipt_id": receipt.receipt_id,
        "evidence_id": evidence.evidence_id,
        "plan_id": plan.plan_id,
        "capture_id": plan.description.capture_id,
        "account_id": plan.description.account_id,
        "plan_sha256": plan.semantic_sha256,
        "preparation_sha256": preparation.semantic_sha256,
        "credential_resolution_sha256": credential.semantic_sha256,
        "resolver_id": credential.resolver_id,
        "resolver_version": credential.resolver_version,
        "credential_resolution_started_at": credential.started_at,
        "resolved_at": credential.resolved_at,
        "credential_resolution_valid_until": credential.valid_until,
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
        "permit_freshness_sha256": evidence.permit_freshness.semantic_sha256,
        "permit_issued_at": permit.issued_at,
        "permit_checked_at": evidence.permit_freshness.checked_at,
        "permit_expires_at": permit.expires_at,
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
        "response_size_bytes": observation.response_size_bytes,
        "response_body_sha256": observation.response_sha256,
        "position_count": observation.position_count,
        "observation_sha256": observation.semantic_sha256,
        "persisted_snapshot_sha256": (evidence.persisted_snapshot.semantic_sha256),
        "post_fence_lease_sha256": post_fence.lease_sha256,
        "post_fence_receipt_sha256": post_fence.semantic_sha256,
        "post_fence_validated_at": post_fence.validated_at,
        "post_fence_valid_until": post_fence.valid_until,
        "final_fence_lease_sha256": final_fence.lease_sha256,
        "final_fence_receipt_sha256": final_fence.semantic_sha256,
        "final_fence_validated_at": final_fence.validated_at,
        "final_fence_valid_until": final_fence.valid_until,
        "authenticated_at": evidence.authenticated_at,
        "evidence_sha256": evidence.semantic_sha256,
        "commit_fence_lease_sha256": commit_fence.lease_sha256,
        "commit_fence_receipt_sha256": commit_fence.semantic_sha256,
        "commit_fence_validated_at": commit_fence.validated_at,
        "commit_fence_valid_until": commit_fence.valid_until,
        "canonical_payload": receipt.canonical_json,
        "semantic_sha256": receipt.semantic_sha256,
    }


def _receipt_from_row(
    connection: Connection,
    row: PositionSnapshotRow,
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    try:
        commit_checked_at = _required_datetime(
            row,
            "commit_fence_validated_at",
        )
        commit_binding = _binding_source(
            connection,
            account_id=plan.description.account_id,
            binding_id=plan.account_binding.binding_id,
            binding_sha256=plan.account_binding.semantic_sha256,
            expected_provider_account_id=(plan.reference.expected_provider_account_id),
            checked_at=commit_checked_at,
            require_terminal=False,
        )
        if commit_binding != plan.account_binding:
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "position snapshot commit conflicts with its historical account-binding source"
            )
        credential = AlpacaPaperCredentialResolutionReceipt(
            reference=plan.reference,
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
            plan.account_binding,
            checked_at=_required_datetime(
                row,
                "pre_account_identity_checked_at",
            ),
        )
        post_identity = _alpaca_paper_account_identity_continuity_receipt(
            plan.account_binding,
            checked_at=_required_datetime(
                row,
                "post_account_identity_checked_at",
            ),
        )
        permit_record = _permit_source(
            connection,
            account_id=plan.description.account_id,
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
        final_fence = _fence_source(connection, row, phase="final")
        commit_fence = _fence_source(connection, row, phase="commit")
        request = AlpacaPaperPositionSnapshotTransportRequest(
            plan=plan,
            preparation_sha256=preparation.semantic_sha256,
            pre_account_identity_sha256=pre_identity.semantic_sha256,
            demand_sha256=demand.semantic_sha256,
            permit_sha256=permit.semantic_sha256,
            permit_freshness_sha256=permit_freshness.semantic_sha256,
            pre_fence_receipt_sha256=pre_fence.semantic_sha256,
            started_at=_required_datetime(row, "request_started_at"),
        )
        ingress = _ingress_source(
            connection,
            account_id=plan.description.account_id,
            receipt_id=_required_text(row, "ingress_receipt_id"),
            receipt_sha256=_required_text(row, "ingress_receipt_sha256"),
            ingress_sequence=_required_integer(row, "ingress_sequence"),
        )
        delivery = ingress.delivery
        provider_request_id = _required_text(row, "provider_request_id")
        response = AlpacaPaperPositionSnapshotTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID,
            transport_version=ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION,
            http_status=_required_integer(row, "http_status"),
            provider_request_id=provider_request_id,
            media_type=delivery.media_type,
            response_body=delivery.body,
        )
        observation = decode_alpaca_paper_position_snapshot_response(
            plan.description,
            http_status=response.http_status,
            provider_request_id=provider_request_id,
            response_body=response.response_body,
            received_at=_required_datetime(row, "received_at"),
        )
        persisted_snapshot = PersistedAlpacaPaperPositionSnapshot(
            receipt=ingress,
            observation=observation,
        )
        evidence = _alpaca_paper_authenticated_position_snapshot_evidence(
            plan=plan,
            preparation=preparation,
            credential_receipt=credential,
            pre_account_identity=pre_identity,
            policy=policy,
            demand=demand,
            permit=permit,
            permit_freshness=permit_freshness,
            pre_fence_receipt=pre_fence,
            request=request,
            response=response,
            persisted_snapshot=persisted_snapshot,
            post_fence_receipt=post_fence,
            post_account_identity=post_identity,
            final_fence_receipt=final_fence,
            authenticated_at=_required_datetime(row, "authenticated_at"),
        )
        receipt = _alpaca_paper_authenticated_position_snapshot_receipt(
            evidence,
            commit_fence_receipt=commit_fence,
        )
        expected_values = immutable_alpaca_paper_position_snapshot_values(receipt)
        if any(
            not same_value(row[field_name], value) for field_name, value in expected_values.items()
        ):
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "persisted position snapshot conflicts with exact reconstruction"
            )
        return receipt
    except AlpacaPaperPositionSnapshotRuntimeError:
        raise
    except (
        AccountCoordinatorError,
        BrokerIngressError,
        BrokerRequestBudgetError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "persisted position snapshot is malformed"
        ) from error


def _authenticate_evidence_sources(
    connection: Connection,
    evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
) -> None:
    binding = _binding_source(
        connection,
        account_id=evidence.plan.description.account_id,
        binding_id=evidence.plan.account_binding.binding_id,
        binding_sha256=evidence.plan.account_binding.semantic_sha256,
        expected_provider_account_id=(evidence.plan.reference.expected_provider_account_id),
        checked_at=evidence.authenticated_at,
        require_terminal=True,
    )
    if binding != evidence.plan.account_binding:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot account binding changed before commit"
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
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "position snapshot account identity conflicts with durable binding"
            )
    permit_record = _permit_source(
        connection,
        account_id=evidence.plan.description.account_id,
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
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot permit changed before commit"
        )
    ingress = _ingress_source(
        connection,
        account_id=evidence.plan.description.account_id,
        receipt_id=evidence.persisted_snapshot.receipt.receipt_id,
        receipt_sha256=evidence.persisted_snapshot.receipt.semantic_sha256,
        ingress_sequence=evidence.persisted_snapshot.receipt.ingress_sequence,
    )
    if ingress != evidence.persisted_snapshot.receipt:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot raw ingress changed before commit"
        )
    for fence in (
        evidence.pre_fence_receipt,
        evidence.post_fence_receipt,
        evidence.final_fence_receipt,
    ):
        _authenticate_fence_position_at(
            connection,
            fence,
            checked_at=fence.validated_at,
        )


def _verify_alpaca_paper_position_snapshot_integrity(
    connection: Connection,
) -> None:
    orphan = connection.scalar(
        sa.select(phase4_alpaca_paper_position_snapshots.c.receipt_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_alpaca_paper_position_snapshot_plans.c.plan_id
                    == phase4_alpaca_paper_position_snapshots.c.plan_id
                )
            )
        )
        .limit(1)
    )
    if orphan is not None:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshots exist without durable single-use claims"
        )
    plan_rows = connection.execute(
        sa.select(phase4_alpaca_paper_position_snapshot_plans)
        .order_by(phase4_alpaca_paper_position_snapshot_plans.c.plan_id)
        .execution_options(yield_per=64)
    ).mappings()
    for plan_row in plan_rows:
        plan, preparation = _plan_and_preparation_from_row(
            connection,
            plan_row,
        )
        row = _snapshot_row(
            connection,
            plan_id=plan.plan_id,
            capture_id=plan.description.capture_id,
        )
        if row is not None:
            _receipt_from_row(connection, row, plan, preparation)


def verify_alpaca_paper_position_snapshot_integrity(engine: Engine) -> None:
    """Authenticate every durable claim and committed position snapshot."""

    if not isinstance(engine, Engine):
        raise AlpacaPaperPositionSnapshotPersistenceError(
            "position snapshot verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AlpacaPaperPositionSnapshotPersistenceError(
            f"position snapshot verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_alpaca_paper_position_snapshot_integrity(connection)


def _position_transition_member_row(
    connection: Connection,
    *,
    plan_id: str,
    capture_id: str,
) -> RowMapping | None:
    """Resolve one globally unique Phase 4X member without trusting one key alone."""

    try:
        by_plan = (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_transition_members).where(
                    phase4_alpaca_paper_position_transition_members.c.plan_id == plan_id
                )
            )
            .mappings()
            .one_or_none()
        )
        by_capture = (
            connection.execute(
                sa.select(phase4_alpaca_paper_position_transition_members).where(
                    phase4_alpaca_paper_position_transition_members.c.capture_id == capture_id
                )
            )
            .mappings()
            .one_or_none()
        )
    except MultipleResultsFound:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position transition membership identity is not unique"
        ) from None
    if by_plan is None and by_capture is None:
        return None
    if (
        by_plan is None
        or by_capture is None
        or by_plan["member_id"] != by_capture["member_id"]
        or by_plan["plan_id"] != by_capture["plan_id"]
        or by_plan["capture_id"] != by_capture["capture_id"]
    ):
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position transition plan ID and capture ID disagree"
        )
    return by_plan


def _prepare_alpaca_paper_position_snapshot_in_transaction(
    connection: Connection,
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    checked_at: datetime,
    admitted_transition_round_id: str | None,
) -> AlpacaPaperPositionSnapshotPreparationReceipt:
    """Insert one unchanged U plan under an already-held account lock."""

    preparation = _alpaca_paper_position_snapshot_preparation_receipt(
        plan,
        prepared_at=checked_at,
    )
    member = _position_transition_member_row(
        connection,
        plan_id=plan.plan_id,
        capture_id=plan.description.capture_id,
    )
    if member is None:
        if admitted_transition_round_id is not None:
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "pair-aware position snapshot preparation lacks its membership"
            )
    elif admitted_transition_round_id is None:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "registered position-view transition members require pair-aware preparation"
        )
    else:
        expected_member_plan_values: dict[str, object] = {
            "round_id": admitted_transition_round_id,
            "account_id": plan.description.account_id,
            "expected_provider_account_id": (plan.reference.expected_provider_account_id),
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
        }
        if any(
            not same_value(member[field_name], expected)
            for field_name, expected in expected_member_plan_values.items()
        ):
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "pair-aware position snapshot preparation conflicts with membership"
            )
    existing = _plan_row(
        connection,
        plan_id=plan.plan_id,
        capture_id=plan.description.capture_id,
    )
    existing_snapshot = _snapshot_row(
        connection,
        plan_id=plan.plan_id,
        capture_id=plan.description.capture_id,
    )
    if existing is not None or existing_snapshot is not None:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot capture already has a stalled or complete single-use claim"
        )
    binding = _binding_source(
        connection,
        account_id=plan.description.account_id,
        binding_id=plan.account_binding.binding_id,
        binding_sha256=plan.account_binding.semantic_sha256,
        expected_provider_account_id=plan.reference.expected_provider_account_id,
        checked_at=checked_at,
        require_terminal=True,
    )
    if binding != plan.account_binding:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot plan binding changed before preparation"
        )
    values = immutable_alpaca_paper_position_snapshot_plan_values(preparation)
    try:
        connection.execute(sa.insert(phase4_alpaca_paper_position_snapshot_plans).values(**values))
    except IntegrityError as error:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot preparation conflicts with durable history"
        ) from error
    row = _plan_row(
        connection,
        plan_id=plan.plan_id,
        capture_id=plan.description.capture_id,
    )
    if row is None:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot preparation failed exact SQL readback"
        )
    persisted_plan, persisted_preparation = _plan_and_preparation_from_row(
        connection,
        row,
    )
    if persisted_plan != plan or persisted_preparation != preparation:
        raise AlpacaPaperPositionSnapshotPersistenceConflict(
            "position snapshot preparation failed exact SQL readback"
        )
    assert_immutable(
        phase4_alpaca_paper_position_snapshot_plans,
        plan.plan_id,
        row,
        values,
    )
    return persisted_preparation


class SqlAlpacaPaperPositionSnapshotRepository:
    """Persist one non-retryable authenticated position capture."""

    __slots__ = ("_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlPositionSnapshotFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AlpacaPaperPositionSnapshotPersistenceError(
                "SQL position snapshots require an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AlpacaPaperPositionSnapshotPersistenceError(
                f"SQL position snapshots do not support dialect {engine.dialect.name!r}"
            )
        if not callable(
            getattr(
                coordinator,
                "revalidate_for_commit_in_transaction",
                None,
            )
        ):
            raise AlpacaPaperPositionSnapshotPersistenceError(
                "SQL position snapshots require a SQL fence validator"
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
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "position snapshot commit fence validation failed"
            ) from None

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt:
        """Persist a fresh plan-as-claim; every existing capture conflicts."""

        if type(plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
            raise AlpacaPaperPositionSnapshotPersistenceError(
                "position snapshot preparation requires an exact runtime plan"
            )
        plan.__post_init__()
        checked_at = _require_utc(
            checked_at,
            "position snapshot preparation checked_at",
        )
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    plan.description.account_id,
                )
                return _prepare_alpaca_paper_position_snapshot_in_transaction(
                    connection,
                    plan,
                    checked_at=checked_at,
                    admitted_transition_round_id=None,
                )
        except AlpacaPaperPositionSnapshotRuntimeError:
            raise
        except (
            AccountCoordinatorError,
            BrokerIngressError,
            BrokerRequestBudgetError,
            ImmutableFactConflict,
            IntegrityError,
        ):
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "durable position snapshot preparation failed"
            ) from None

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        """Commit one exact authenticated capture under the account lock."""

        if type(evidence) is not AlpacaPaperAuthenticatedPositionSnapshotEvidence:
            raise AlpacaPaperPositionSnapshotPersistenceError(
                "position snapshot recording requires exact authenticated evidence"
            )
        evidence._validate()
        plan = evidence.plan
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    plan.description.account_id,
                )
                plan_row = _plan_row(
                    connection,
                    plan_id=plan.plan_id,
                    capture_id=plan.description.capture_id,
                )
                if plan_row is None:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot evidence lacks its fresh durable claim"
                    )
                persisted_plan, preparation = _plan_and_preparation_from_row(
                    connection,
                    plan_row,
                )
                if persisted_plan != plan or preparation != evidence.preparation:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot evidence conflicts with its durable claim"
                    )
                if (
                    _snapshot_row(
                        connection,
                        plan_id=plan.plan_id,
                        capture_id=plan.description.capture_id,
                    )
                    is not None
                ):
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot capture is already complete and cannot retry"
                    )
                _authenticate_evidence_sources(connection, evidence)
                commit_fence = self._commit_fence(
                    connection,
                    evidence.final_fence_receipt.fence,
                )
                if (
                    commit_fence.fence != evidence.final_fence_receipt.fence
                    or commit_fence.policy_sha256 != evidence.final_fence_receipt.policy_sha256
                    or commit_fence.lease_sha256 != evidence.final_fence_receipt.lease_sha256
                    or commit_fence.valid_until != evidence.final_fence_receipt.valid_until
                    or commit_fence.validated_at < evidence.authenticated_at
                    or commit_fence.validated_at >= commit_fence.valid_until
                ):
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot fence changed before durable commit"
                    )
                receipt = _alpaca_paper_authenticated_position_snapshot_receipt(
                    evidence,
                    commit_fence_receipt=commit_fence,
                )
                values = immutable_alpaca_paper_position_snapshot_values(receipt)
                try:
                    connection.execute(
                        sa.insert(phase4_alpaca_paper_position_snapshots).values(**values)
                    )
                except IntegrityError as error:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot receipt conflicts with durable history"
                    ) from error
                row = _snapshot_row(
                    connection,
                    plan_id=plan.plan_id,
                    capture_id=plan.description.capture_id,
                )
                if row is None:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot receipt failed exact SQL readback"
                    )
                persisted = _receipt_from_row(
                    connection,
                    row,
                    plan,
                    preparation,
                )
                if persisted != receipt:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot receipt failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_alpaca_paper_position_snapshots,
                    receipt.receipt_id,
                    row,
                    values,
                )
                final_fence = self._commit_fence(
                    connection,
                    evidence.final_fence_receipt.fence,
                )
                if (
                    final_fence.validated_at < commit_fence.validated_at
                    or final_fence.fence != commit_fence.fence
                    or final_fence.policy_sha256 != commit_fence.policy_sha256
                    or final_fence.lease_sha256 != commit_fence.lease_sha256
                    or final_fence.valid_until != commit_fence.valid_until
                    or final_fence.validated_at >= final_fence.valid_until
                ):
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot fence changed before final commit"
                    )
                return persisted
        except AlpacaPaperPositionSnapshotRuntimeError:
            raise
        except (
            AccountCoordinatorError,
            BrokerIngressError,
            BrokerRequestBudgetError,
            ImmutableFactConflict,
            IntegrityError,
        ):
            raise AlpacaPaperPositionSnapshotPersistenceConflict(
                "durable position snapshot authentication failed"
            ) from None

    def load_state(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
        """Load the exact unclaimed, stalled, or complete Phase 4U state."""

        if type(plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
            raise AlpacaPaperPositionSnapshotPersistenceError(
                "position snapshot state loading requires an exact runtime plan"
            )
        plan.__post_init__()
        with _repeatable_read_transaction(self._engine) as connection:
            plan_row = _plan_row(
                connection,
                plan_id=plan.plan_id,
                capture_id=plan.description.capture_id,
            )
            snapshot_row = _snapshot_row(
                connection,
                plan_id=plan.plan_id,
                capture_id=plan.description.capture_id,
            )
            if plan_row is None:
                if snapshot_row is not None:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "absent position snapshot plan has an orphaned receipt"
                    )
                return _alpaca_paper_authenticated_position_snapshot_supervisor_state(
                    stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT,
                    plan=plan,
                    preparation=None,
                    receipt=None,
                )
            persisted_plan, preparation = _plan_and_preparation_from_row(
                connection,
                plan_row,
            )
            if persisted_plan != plan:
                raise AlpacaPaperPositionSnapshotPersistenceConflict(
                    "position snapshot state conflicts with durable plan identity"
                )
            if snapshot_row is None:
                return _alpaca_paper_authenticated_position_snapshot_supervisor_state(
                    stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED,
                    plan=persisted_plan,
                    preparation=preparation,
                    receipt=None,
                )
            receipt = _receipt_from_row(
                connection,
                snapshot_row,
                persisted_plan,
                preparation,
            )
            return _alpaca_paper_authenticated_position_snapshot_supervisor_state(
                stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE,
                plan=persisted_plan,
                preparation=preparation,
                receipt=receipt,
            )

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        """Load one exact committed receipt; valid absence or stall returns None."""

        if type(plan) is not AlpacaPaperPositionSnapshotRuntimePlan:
            raise AlpacaPaperPositionSnapshotPersistenceError(
                "position snapshot loading requires an exact runtime plan"
            )
        plan.__post_init__()
        with _repeatable_read_transaction(self._engine) as connection:
            plan_row = _plan_row(
                connection,
                plan_id=plan.plan_id,
                capture_id=plan.description.capture_id,
            )
            snapshot_row = _snapshot_row(
                connection,
                plan_id=plan.plan_id,
                capture_id=plan.description.capture_id,
            )
            if plan_row is None:
                if snapshot_row is not None:
                    raise AlpacaPaperPositionSnapshotPersistenceConflict(
                        "position snapshot receipt exists without its durable claim"
                    )
                return None
            persisted_plan, preparation = _plan_and_preparation_from_row(
                connection,
                plan_row,
            )
            if persisted_plan != plan:
                raise AlpacaPaperPositionSnapshotPersistenceConflict(
                    "position snapshot capture identity conflicts with durable plan"
                )
            if snapshot_row is None:
                return None
            return _receipt_from_row(
                connection,
                snapshot_row,
                persisted_plan,
                preparation,
            )


__all__ = [
    "ALPACA_PAPER_POSITION_SNAPSHOT_PERSISTENCE_CONTRACT_VERSION",
    "AlpacaPaperPositionSnapshotPersistenceConflict",
    "AlpacaPaperPositionSnapshotPersistenceError",
    "SqlAlpacaPaperPositionSnapshotRepository",
    "immutable_alpaca_paper_position_snapshot_plan_values",
    "immutable_alpaca_paper_position_snapshot_values",
    "verify_alpaca_paper_position_snapshot_integrity",
]
