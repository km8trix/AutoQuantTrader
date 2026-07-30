"""Durable Phase 5B policy registration, assignment, and assessment evidence.

This base repository authenticates the fixed policy definition, the separate
runtime assignment, and complete policy-assessment evidence under the shared
account lease-head lock.  The post-cutover atomic assessment, operational
enforcement, unchanged Phase 2 decision, and admission sidecar are composed by
``packages.persistence.advanced_batch_risk`` in its caller-owned transaction.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.advanced_risk import (
    AdvancedRiskEvidenceSource,
    AdvancedRiskObservationCompleteness,
)
from packages.domain.advanced_risk_admission import AdvancedRiskAssessmentReference
from packages.domain.advanced_risk_assignment import (
    AdvancedRiskAssignmentCommand,
    AdvancedRiskAssignmentConflict,
    AdvancedRiskAssignmentError,
    AdvancedRiskPolicyAssignment,
    assign_advanced_risk_policy,
)
from packages.domain.advanced_risk_policy import (
    ADVANCED_RISK_POLICY_CONTRACT_VERSION,
    MODERATE_ADVANCED_RISK_POLICY,
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyAssessment,
    AdvancedRiskPolicyError,
    AdvancedRiskPolicyObservation,
    ModerateAdvancedRiskPolicy,
    ModerateAdvancedRiskRuleId,
    advanced_risk_policy_source_set_sha256,
    assess_moderate_advanced_risk,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.operational_control import (
    OperationalControlError,
    OperationalControlState,
    OperationalControlTransition,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.operational_control import (
    load_operational_control_head_in_transaction,
)
from packages.persistence.schema import (
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_assignment_heads,
    phase5_advanced_risk_assignments,
    phase5_advanced_risk_evidence,
    phase5_advanced_risk_evidence_sources,
    phase5_advanced_risk_policies,
    phase5_operational_control_transitions,
)

ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION = "phase5b-advanced-risk-persistence-v1"
_SCOPE_PROFILE_ID = "paper-us-equities-rth-long-only-dia-iwm-qqq-spy-v1"
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

AdvancedRiskRow = Mapping[str, object] | RowMapping


class AdvancedRiskPersistenceError(RuntimeError):
    """Persisted advanced-risk state is malformed, unavailable, or unsafe."""


class AdvancedRiskPersistenceConflict(AdvancedRiskPersistenceError):
    """An immutable advanced-risk identity has conflicting durable content."""


class SqlAccountFenceValidator(Protocol):
    """Narrow account-coordinator surface required by this repository."""

    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


@dataclass(frozen=True, slots=True)
class RegisteredAdvancedRiskPolicy:
    """The fixed policy plus non-authenticating owner-direction provenance."""

    policy: ModerateAdvancedRiskPolicy
    approval_evidence_sha256: str
    approved_at: datetime
    registry_sha256: str


@dataclass(frozen=True, slots=True)
class AdvancedRiskSourceSet:
    """A bounded exact source membership set for one policy observation."""

    members: tuple[AdvancedRiskEvidenceSource, ...]
    source_count: int

    def __post_init__(self) -> None:
        if type(self.members) is not tuple or any(
            type(member) is not AdvancedRiskEvidenceSource for member in self.members
        ):
            raise AdvancedRiskPersistenceError(
                "advanced-risk source members must be an exact tuple"
            )
        if len(self.members) > 2_048:
            raise AdvancedRiskPersistenceError(
                "advanced-risk source membership exceeds its durable bound"
            )
        for member in self.members:
            member.__post_init__()
        expected = tuple(
            sorted(
                self.members,
                key=lambda member: (member.source_kind, member.source_id),
            )
        )
        if self.members != expected:
            raise AdvancedRiskPersistenceError(
                "advanced-risk source members must be canonically ordered"
            )
        identities = tuple((member.source_kind, member.source_id) for member in self.members)
        if len(identities) != len(set(identities)):
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk source membership repeats an identity"
            )
        if (
            type(self.source_count) is not int
            or self.source_count < len(self.members)
            or self.source_count > (1 << 63) - 1
        ):
            raise AdvancedRiskPersistenceError(
                "advanced-risk source_count is outside its durable bound"
            )

    @property
    def semantic_sha256(self) -> str:
        try:
            return advanced_risk_policy_source_set_sha256(
                self.members,
                source_count=self.source_count,
            )
        except AdvancedRiskPolicyError as error:
            raise AdvancedRiskPersistenceError(str(error)) from error


@dataclass(frozen=True, slots=True)
class AuthenticatedAdvancedRiskAssignment:
    """One assignment plus its authenticated persistence-envelope bindings."""

    assignment: AdvancedRiskPolicyAssignment
    envelope_sha256: str
    fence_sha256: str
    lease_sha256: str
    operational_transition_id: str
    operational_transition_sha256: str


@dataclass(frozen=True, slots=True)
class _PersistedAssignment:
    command: AdvancedRiskAssignmentCommand
    assignment: AdvancedRiskPolicyAssignment
    envelope_sha256: str
    fence_sha256: str
    lease_sha256: str
    operational_transition_id: str
    operational_transition_sha256: str


@dataclass(frozen=True, slots=True)
class _PersistedEvidence:
    observation: AdvancedRiskPolicyObservation
    source_set: AdvancedRiskSourceSet
    observation_sequence: int
    envelope_sha256: str
    assignment_id: str
    policy_sha256: str


@dataclass(frozen=True, slots=True)
class _PersistedAssessment:
    assessment: AdvancedRiskPolicyAssessment
    required_instrument_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    sequence_number: int
    envelope_sha256: str
    evidence_context_sha256: str | None
    valid_through: datetime


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    row: AdvancedRiskRow,
    field_name: str,
) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AdvancedRiskPersistenceError(f"persisted advanced-risk {field_name} must be a string")
    return value


def _optional_text(
    row: AdvancedRiskRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk {field_name} must be a string or null"
        )
    return value


def _require_int(row: AdvancedRiskRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk {field_name} must be an integer"
        )
    return value


def _optional_decimal(
    row: AdvancedRiskRow,
    field_name: str,
) -> Decimal | None:
    value = row[field_name]
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except Exception as error:
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk {field_name} must be a Decimal or null"
        ) from error


def _require_datetime(row: AdvancedRiskRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise AdvancedRiskPersistenceError(f"{field_name} must be UTC")
    return value


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AdvancedRiskPersistenceError(f"{field_name} must be a lowercase SHA-256 digest")


def _decode_canonical_node(node: object) -> object:
    if not isinstance(node, dict):
        raise AdvancedRiskPersistenceError("persisted advanced-risk canonical payload is malformed")
    typed = cast(dict[str, object], node)
    node_type = typed.get("type")
    value = typed.get("value")
    if node_type == "null":
        return None
    if node_type == "string":
        if type(value) is not str:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical string is malformed"
            )
        return value
    if node_type == "int":
        if type(value) is not str:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical integer is malformed"
            )
        try:
            return int(value)
        except ValueError as error:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical integer is malformed"
            ) from error
    if node_type == "bool":
        if type(value) is not bool:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical bool is malformed"
            )
        return value
    if node_type == "decimal":
        if type(value) is not str:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical decimal is malformed"
            )
        try:
            return Decimal(value)
        except Exception as error:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical decimal is malformed"
            ) from error
    if node_type == "datetime":
        if type(value) is not str or not value.endswith("Z"):
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical datetime is malformed"
            )
        try:
            return datetime.fromisoformat(f"{value[:-1]}+00:00").astimezone(UTC)
        except ValueError as error:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical datetime is malformed"
            ) from error
    if node_type == "tuple":
        if type(value) is not list:
            raise AdvancedRiskPersistenceError(
                "persisted advanced-risk canonical tuple is malformed"
            )
        return tuple(_decode_canonical_node(item) for item in value)
    raise AdvancedRiskPersistenceError(
        "persisted advanced-risk canonical payload uses an unsupported node"
    )


def _decode_canonical_tuple(payload: str, *, kind: str, size: int) -> tuple[object, ...]:
    try:
        node: object = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk canonical payload is not valid JSON"
        ) from error
    decoded = _decode_canonical_node(node)
    if type(decoded) is not tuple or len(decoded) != size:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk canonical envelope has the wrong shape"
        )
    if decoded[0] != ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION or decoded[1] != kind:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk canonical envelope has the wrong contract"
        )
    return decoded


def _assert_immutable(
    table: sa.Table,
    identifier: str,
    row: AdvancedRiskRow,
    expected: Mapping[str, object],
) -> None:
    try:
        assert_immutable(table, identifier, row, expected)
    except ImmutableFactConflict as error:
        raise AdvancedRiskPersistenceConflict(
            f"persisted advanced-risk fact {identifier!r} conflicts"
        ) from error


def _policy_scope_sha256(policy: ModerateAdvancedRiskPolicy) -> str:
    return _sha256(
        (
            ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
            "policy_scope",
            policy.instruments,
            policy.market_session,
            policy.position_scope,
        )
    )


def _policy_registry_material(
    policy: ModerateAdvancedRiskPolicy,
    *,
    approval_evidence_sha256: str,
    approved_at: datetime,
) -> tuple[object, ...]:
    return (
        ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
        "policy_registry",
        policy.canonical_json,
        policy.semantic_sha256,
        approval_evidence_sha256,
        approved_at,
        "owner_direction_provenance_not_actor_authentication",
    )


def _policy_values(
    policy: ModerateAdvancedRiskPolicy,
    *,
    approval_evidence_sha256: str,
    approved_at: datetime,
) -> dict[str, object]:
    material = _policy_registry_material(
        policy,
        approval_evidence_sha256=approval_evidence_sha256,
        approved_at=approved_at,
    )
    pretrade_count = sum(rule.pretrade_reject_threshold is not None for rule in policy.rules)
    runtime_count = sum(rule.runtime_pause_threshold is not None for rule in policy.rules)
    return {
        "policy_sha256": policy.semantic_sha256,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "environment": policy.environment,
        "scope_profile_id": _SCOPE_PROFILE_ID,
        "scope_profile_sha256": _policy_scope_sha256(policy),
        "rule_count": len(policy.rules),
        "pretrade_new_exposure_rule_count": pretrade_count,
        "runtime_rule_count": runtime_count,
        "none_disposition_count": sum(
            rule.pretrade_reject_threshold is None and rule.runtime_pause_threshold is None
            for rule in policy.rules
        ),
        "reject_disposition_count": pretrade_count,
        "pause_disposition_count": runtime_count,
        "halt_disposition_count": sum(
            rule.runtime_halt_threshold is not None for rule in policy.rules
        ),
        "rules_payload": canonical_json_text(
            tuple((rule.rule_id.value, rule.semantic_sha256) for rule in policy.rules)
        ),
        "approval_evidence_sha256": approval_evidence_sha256,
        "approved_at": approved_at,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def _registered_policy_from_row(row: AdvancedRiskRow) -> RegisteredAdvancedRiskPolicy:
    policy = MODERATE_ADVANCED_RISK_POLICY
    approval_evidence_sha256 = _require_text(row, "approval_evidence_sha256")
    approved_at = _require_datetime(row, "approved_at")
    expected = _policy_values(
        policy,
        approval_evidence_sha256=approval_evidence_sha256,
        approved_at=approved_at,
    )
    _assert_immutable(
        phase5_advanced_risk_policies,
        _require_text(row, "policy_sha256"),
        row,
        expected,
    )
    return RegisteredAdvancedRiskPolicy(
        policy=policy,
        approval_evidence_sha256=approval_evidence_sha256,
        approved_at=approved_at,
        registry_sha256=cast(str, expected["semantic_sha256"]),
    )


def _registered_policy_in_transaction(
    connection: Connection,
    policy_sha256: str = MODERATE_ADVANCED_RISK_POLICY_SHA256,
) -> RegisteredAdvancedRiskPolicy | None:
    row = (
        connection.execute(
            sa.select(phase5_advanced_risk_policies).where(
                phase5_advanced_risk_policies.c.policy_sha256 == policy_sha256
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _registered_policy_from_row(row)


def _assignment_material(
    *,
    assignment: AdvancedRiskPolicyAssignment,
    command: AdvancedRiskAssignmentCommand,
    registry_sha256: str,
    previous_envelope_sha256: str | None,
    fence_sha256: str,
    lease_sha256: str,
    operational_transition_id: str,
    operational_transition_sha256: str,
) -> tuple[object, ...]:
    return (
        ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
        "assignment_envelope",
        assignment.canonical_json,
        assignment.semantic_sha256,
        command.canonical_json,
        command.idempotency_key,
        command.requested_at,
        command.approval_evidence_sha256,
        command.expected_assignment_sequence_number,
        command.expected_assignment_sha256,
        registry_sha256,
        previous_envelope_sha256,
        fence_sha256,
        lease_sha256,
        operational_transition_id,
        operational_transition_sha256,
    )


def _assignment_values(
    *,
    assignment: AdvancedRiskPolicyAssignment,
    command: AdvancedRiskAssignmentCommand,
    registered: RegisteredAdvancedRiskPolicy,
    previous: _PersistedAssignment | None,
    fencing_generation: int,
    lease_sha256: str,
    fence_sha256: str,
    operational_transition_id: str,
    operational_transition_sha256: str,
) -> dict[str, object]:
    previous_envelope = None if previous is None else previous.envelope_sha256
    material = _assignment_material(
        assignment=assignment,
        command=command,
        registry_sha256=registered.registry_sha256,
        previous_envelope_sha256=previous_envelope,
        fence_sha256=fence_sha256,
        lease_sha256=lease_sha256,
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
    )
    return {
        "assignment_id": assignment.assignment_id,
        "account_id": assignment.account_id,
        "sequence_number": assignment.sequence_number,
        "previous_sequence_number": (
            None if previous is None else previous.assignment.sequence_number
        ),
        "previous_assignment_id": (None if previous is None else previous.assignment.assignment_id),
        "previous_assignment_sha256": previous_envelope,
        "policy_sha256": assignment.policy_sha256,
        "policy_id": assignment.policy_id,
        "policy_semantic_sha256": registered.registry_sha256,
        "environment": assignment.environment,
        "command_id": assignment.command_id,
        "command_sha256": assignment.command_sha256,
        "actor_id": assignment.actor_id,
        "actor_authority_sha256": assignment.actor_authority_sha256,
        "actor_authenticated_at": assignment.actor_authenticated_at,
        "fencing_generation": fencing_generation,
        "lease_sha256": lease_sha256,
        "fence_sha256": fence_sha256,
        "operational_transition_id": operational_transition_id,
        "operational_transition_sha256": operational_transition_sha256,
        "assigned_at": assignment.assigned_at,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def _assignment_head_material(record: _PersistedAssignment) -> tuple[object, ...]:
    assignment = record.assignment
    return (
        ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
        "assignment_head",
        assignment.account_id,
        assignment.sequence_number,
        assignment.assignment_id,
        record.envelope_sha256,
        assignment.policy_sha256,
        assignment.environment,
        assignment.assigned_at,
    )


def _assignment_head_values(record: _PersistedAssignment) -> dict[str, object]:
    material = _assignment_head_material(record)
    assignment = record.assignment
    return {
        "account_id": assignment.account_id,
        "sequence_number": assignment.sequence_number,
        "assignment_id": assignment.assignment_id,
        "assignment_sha256": record.envelope_sha256,
        "policy_sha256": assignment.policy_sha256,
        "environment": assignment.environment,
        "assigned_at": assignment.assigned_at,
        "updated_at": assignment.assigned_at,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def _control_bindings(
    connection: Connection,
    account_id: str,
) -> tuple[OperationalControlTransition | None, dict[str, str]]:
    current = load_operational_control_head_in_transaction(connection, account_id)
    rows = connection.execute(
        sa.select(
            phase5_operational_control_transitions.c.transition_id,
            phase5_operational_control_transitions.c.semantic_sha256,
        ).where(phase5_operational_control_transitions.c.account_id == account_id)
    ).mappings()
    bindings = {
        _require_text(row, "transition_id"): _require_text(row, "semantic_sha256") for row in rows
    }
    if current is None:
        if bindings:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk control history has no authenticated head"
            )
        return None, bindings
    if bindings.get(current.transition_id) != current.semantic_sha256:
        raise AdvancedRiskPersistenceConflict("advanced-risk current control binding conflicts")
    return current, bindings


def _decoded_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk envelope {field_name} must be text"
        )
    return value


def _decoded_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _decoded_text(value, field_name)


def _decoded_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk envelope {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _assignment_from_row(
    row: AdvancedRiskRow,
    *,
    current_domain: AdvancedRiskPolicyAssignment | None,
    previous: _PersistedAssignment | None,
    registered: RegisteredAdvancedRiskPolicy,
    control_bindings: Mapping[str, str],
) -> _PersistedAssignment:
    canonical_payload = _require_text(row, "canonical_payload")
    material = _decode_canonical_tuple(
        canonical_payload,
        kind="assignment_envelope",
        size=16,
    )
    idempotency_key = _decoded_text(material[5], "idempotency_key")
    requested_at = _decoded_datetime(material[6], "requested_at")
    approval_evidence_sha256 = _decoded_text(
        material[7],
        "approval_evidence_sha256",
    )
    expected_assignment_sequence_number = material[8]
    if type(expected_assignment_sequence_number) is not int:
        raise AdvancedRiskPersistenceError(
            "persisted assignment expected head sequence is malformed"
        )
    expected_assignment_sha256 = _decoded_optional_text(
        material[9],
        "expected_assignment_sha256",
    )
    command = AdvancedRiskAssignmentCommand(
        account_id=_require_text(row, "account_id"),
        environment=_require_text(row, "environment"),
        idempotency_key=idempotency_key,
        policy_id=_require_text(row, "policy_id"),
        policy_sha256=_require_text(row, "policy_sha256"),
        actor_id=_require_text(row, "actor_id"),
        actor_authority_sha256=_require_text(row, "actor_authority_sha256"),
        actor_authenticated_at=_require_datetime(row, "actor_authenticated_at"),
        requested_at=requested_at,
        approval_evidence_sha256=approval_evidence_sha256,
        expected_assignment_sequence_number=expected_assignment_sequence_number,
        expected_assignment_sha256=expected_assignment_sha256,
    )
    assignment = assign_advanced_risk_policy(
        current_domain,
        command,
        assigned_at=_require_datetime(row, "assigned_at"),
    )
    if (
        assignment.assignment_id != _require_text(row, "assignment_id")
        or assignment.command_id != _require_text(row, "command_id")
        or assignment.command_sha256 != _require_text(row, "command_sha256")
    ):
        raise AdvancedRiskPersistenceConflict(
            "persisted advanced-risk assignment identity conflicts"
        )
    if approval_evidence_sha256 != registered.approval_evidence_sha256:
        raise AdvancedRiskPersistenceConflict(
            "persisted assignment approval evidence conflicts with policy registration"
        )
    operational_transition_id = _require_text(row, "operational_transition_id")
    operational_transition_sha256 = _require_text(
        row,
        "operational_transition_sha256",
    )
    if control_bindings.get(operational_transition_id) != operational_transition_sha256:
        raise AdvancedRiskPersistenceConflict(
            "persisted assignment control transition is not authenticated"
        )
    expected = _assignment_values(
        assignment=assignment,
        command=command,
        registered=registered,
        previous=previous,
        fencing_generation=_require_int(row, "fencing_generation"),
        lease_sha256=_require_text(row, "lease_sha256"),
        fence_sha256=_require_text(row, "fence_sha256"),
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
    )
    _assert_immutable(
        phase5_advanced_risk_assignments,
        assignment.assignment_id,
        row,
        expected,
    )
    if (
        material[2] != assignment.canonical_json
        or material[3] != assignment.semantic_sha256
        or material[4] != command.canonical_json
        or material[10] != registered.registry_sha256
        or material[11] != (None if previous is None else previous.envelope_sha256)
    ):
        raise AdvancedRiskPersistenceConflict("persisted assignment canonical envelope conflicts")
    return _PersistedAssignment(
        command=command,
        assignment=assignment,
        envelope_sha256=cast(str, expected["semantic_sha256"]),
        fence_sha256=_require_text(row, "fence_sha256"),
        lease_sha256=_require_text(row, "lease_sha256"),
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
    )


def _verified_assignment_history(
    connection: Connection,
    account_id: str,
) -> tuple[_PersistedAssignment, ...]:
    registered = _registered_policy_in_transaction(connection)
    rows = tuple(
        connection.execute(
            sa.select(phase5_advanced_risk_assignments)
            .where(phase5_advanced_risk_assignments.c.account_id == account_id)
            .order_by(phase5_advanced_risk_assignments.c.sequence_number)
        ).mappings()
    )
    head_row = (
        connection.execute(
            sa.select(phase5_advanced_risk_assignment_heads).where(
                phase5_advanced_risk_assignment_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if not rows:
        if head_row is not None:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assignment head exists without history"
            )
        return ()
    if registered is None:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk assignment history has no registered policy"
        )
    _, control_bindings = _control_bindings(connection, account_id)
    records: list[_PersistedAssignment] = []
    current_domain: AdvancedRiskPolicyAssignment | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        if _require_int(row, "sequence_number") != expected_sequence:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assignment history is not gap-free"
            )
        previous = None if not records else records[-1]
        record = _assignment_from_row(
            row,
            current_domain=current_domain,
            previous=previous,
            registered=registered,
            control_bindings=control_bindings,
        )
        records.append(record)
        current_domain = record.assignment
    if head_row is None:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk assignment history has no durable head"
        )
    expected_head = _assignment_head_values(records[-1])
    _assert_immutable(
        phase5_advanced_risk_assignment_heads,
        account_id,
        head_row,
        expected_head,
    )
    return tuple(records)


_RULES_BY_ID = {rule.rule_id: rule for rule in MODERATE_ADVANCED_RISK_POLICY.rules}


def _validate_source_set_for_observation(
    observation: AdvancedRiskPolicyObservation,
    source_set: AdvancedRiskSourceSet,
) -> None:
    source_set.__post_init__()
    completeness = observation.completeness
    if completeness is AdvancedRiskObservationCompleteness.OVERFLOWED:
        if len(source_set.members) != 2_048 or source_set.source_count <= 2_048:
            raise AdvancedRiskPersistenceError(
                "overflowed advanced-risk evidence requires a bounded 2,048-member prefix"
            )
    elif source_set.source_count != len(source_set.members):
        raise AdvancedRiskPersistenceError(
            "non-overflowed advanced-risk source_count must be exact"
        )
    if completeness is AdvancedRiskObservationCompleteness.COMPLETE and not source_set.members:
        raise AdvancedRiskPersistenceError(
            "complete advanced-risk evidence requires retained source membership"
        )
    if observation.source_set_sha256 != source_set.semantic_sha256:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk observation source-set digest does not authenticate "
            "its exact retained membership"
        )
    for member in source_set.members:
        if not (
            observation.window_started_at <= member.effective_at <= observation.window_ended_at
            and member.available_at <= observation.observed_at
        ):
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk source membership lies outside its causal window"
            )


def _evidence_material(
    *,
    observation: AdvancedRiskPolicyObservation,
    source_set: AdvancedRiskSourceSet,
    assignment_sha256: str,
    mode: AdvancedRiskEvaluationMode,
    disposition: AdvancedRiskDisposition,
    previous_envelope_sha256: str | None,
    fence_sha256: str,
    lease_sha256: str,
    operational_transition_id: str,
    operational_transition_sha256: str,
) -> tuple[object, ...]:
    return (
        ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
        "evidence_envelope",
        observation.canonical_json,
        observation.semantic_sha256,
        assignment_sha256,
        MODERATE_ADVANCED_RISK_POLICY_SHA256,
        mode.value,
        disposition.value,
        source_set.source_count,
        tuple(member.semantic_sha256 for member in source_set.members),
        observation.qualifying_count,
        previous_envelope_sha256,
        fence_sha256,
        lease_sha256,
        operational_transition_id,
        operational_transition_sha256,
    )


def _evidence_values(
    *,
    observation: AdvancedRiskPolicyObservation,
    source_set: AdvancedRiskSourceSet,
    assignment: _PersistedAssignment,
    observation_sequence: int,
    previous: _PersistedEvidence | None,
    mode: AdvancedRiskEvaluationMode,
    disposition: AdvancedRiskDisposition,
    fencing_generation: int,
    lease_sha256: str,
    fence_sha256: str,
    operational_transition_id: str,
    operational_transition_sha256: str,
) -> dict[str, object]:
    rule = _RULES_BY_ID[observation.rule_id]
    previous_envelope = None if previous is None else previous.envelope_sha256
    material = _evidence_material(
        observation=observation,
        source_set=source_set,
        assignment_sha256=assignment.envelope_sha256,
        mode=mode,
        disposition=disposition,
        previous_envelope_sha256=previous_envelope,
        fence_sha256=fence_sha256,
        lease_sha256=lease_sha256,
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
    )
    return {
        "evidence_id": observation.observation_id,
        "account_id": observation.account_id,
        "observation_sequence": observation_sequence,
        "previous_observation_sequence": (
            None if previous is None else previous.observation_sequence
        ),
        "previous_evidence_id": (None if previous is None else previous.observation.observation_id),
        "previous_evidence_sha256": previous_envelope,
        "assignment_id": assignment.assignment.assignment_id,
        "assignment_sequence_number": assignment.assignment.sequence_number,
        "assignment_sha256": assignment.envelope_sha256,
        "policy_sha256": observation_policy_sha256(observation),
        "environment": observation.environment,
        "idempotency_key": observation.observation_id,
        "rule_id": observation.rule_id.value,
        "rule_kind": rule.kind.value,
        "subject_id": observation.subject_id,
        "rule_sha256": rule.semantic_sha256,
        "evaluation_mode": mode.value,
        "breach_disposition": disposition.value,
        "producer_id": rule.producer_authority_id,
        "producer_version": ADVANCED_RISK_POLICY_CONTRACT_VERSION,
        "producer_authority_sha256": observation.producer_authority_sha256,
        "source_authority_sha256": observation.source_authority_sha256,
        "window_started_at": observation.window_started_at,
        "window_ended_at": observation.window_ended_at,
        "observed_at": observation.observed_at,
        "recorded_at": observation.recorded_at,
        "completeness": observation.completeness.value,
        "value": observation.value,
        "incomplete_reason": observation.incomplete_reason,
        "sample_count": observation.sample_count,
        # The schema predates nullable qualifying counts.  The authenticated
        # envelope retains None exactly; zero is only the SQL projection.
        "qualifying_count": (
            0 if observation.qualifying_count is None else observation.qualifying_count
        ),
        "source_count": source_set.source_count,
        "retained_source_count": len(source_set.members),
        "source_set_sha256": observation.source_set_sha256,
        "evidence_sha256": observation.evidence_sha256,
        "fencing_generation": fencing_generation,
        "lease_sha256": lease_sha256,
        "fence_sha256": fence_sha256,
        "operational_transition_id": operational_transition_id,
        "operational_transition_sha256": operational_transition_sha256,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def observation_policy_sha256(
    observation: AdvancedRiskPolicyObservation,
) -> str:
    """Return the only policy digest accepted for a fixed-policy observation."""

    observation.__post_init__()
    return MODERATE_ADVANCED_RISK_POLICY_SHA256


def _source_values(
    *,
    evidence_id: str,
    account_id: str,
    evidence_sha256: str,
    ordinal: int,
    source: AdvancedRiskEvidenceSource,
) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "ordinal": ordinal,
        "account_id": account_id,
        "evidence_sha256": evidence_sha256,
        "source_kind": source.source_kind,
        "source_id": source.source_id,
        "source_sha256": source.source_sha256,
        "effective_at": source.effective_at,
        "available_at": source.available_at,
        "canonical_payload": source.canonical_json,
        "semantic_sha256": source.semantic_sha256,
    }


def _source_set_from_rows(
    rows: tuple[RowMapping, ...],
    *,
    evidence_id: str,
    account_id: str,
    evidence_sha256: str,
    source_count: int,
) -> AdvancedRiskSourceSet:
    members: list[AdvancedRiskEvidenceSource] = []
    for expected_ordinal, row in enumerate(rows):
        if _require_int(row, "ordinal") != expected_ordinal:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk evidence source ordinals are not contiguous"
            )
        source = AdvancedRiskEvidenceSource(
            source_kind=_require_text(row, "source_kind"),
            source_id=_require_text(row, "source_id"),
            source_sha256=_require_text(row, "source_sha256"),
            effective_at=_require_datetime(row, "effective_at"),
            available_at=_require_datetime(row, "available_at"),
        )
        expected = _source_values(
            evidence_id=evidence_id,
            account_id=account_id,
            evidence_sha256=evidence_sha256,
            ordinal=expected_ordinal,
            source=source,
        )
        _assert_immutable(
            phase5_advanced_risk_evidence_sources,
            f"{evidence_id}:{expected_ordinal}",
            row,
            expected,
        )
        members.append(source)
    return AdvancedRiskSourceSet(
        members=tuple(members),
        source_count=source_count,
    )


def _evidence_from_row(
    connection: Connection,
    row: AdvancedRiskRow,
    *,
    previous: _PersistedEvidence | None,
    assignments: Mapping[str, _PersistedAssignment],
    control_bindings: Mapping[str, str],
) -> _PersistedEvidence:
    canonical_payload = _require_text(row, "canonical_payload")
    material = _decode_canonical_tuple(
        canonical_payload,
        kind="evidence_envelope",
        size=16,
    )
    assignment_id = _require_text(row, "assignment_id")
    assignment = assignments.get(assignment_id)
    if assignment is None:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk evidence assignment is not authenticated"
        )
    operational_transition_id = _require_text(row, "operational_transition_id")
    operational_transition_sha256 = _require_text(
        row,
        "operational_transition_sha256",
    )
    if control_bindings.get(operational_transition_id) != operational_transition_sha256:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk evidence control transition is not authenticated"
        )
    try:
        rule_id = ModerateAdvancedRiskRuleId(_require_text(row, "rule_id"))
        completeness = AdvancedRiskObservationCompleteness(_require_text(row, "completeness"))
        mode = AdvancedRiskEvaluationMode(_require_text(row, "evaluation_mode"))
        disposition = AdvancedRiskDisposition(_require_text(row, "breach_disposition"))
    except ValueError as error:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk evidence uses an unsupported enum"
        ) from error
    qualifying_material = material[10]
    if qualifying_material is not None and type(qualifying_material) is not int:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk qualifying_count marker is malformed"
        )
    qualifying_count = qualifying_material
    observation = AdvancedRiskPolicyObservation(
        account_id=_require_text(row, "account_id"),
        environment=_require_text(row, "environment"),
        rule_id=rule_id,
        subject_id=_require_text(row, "subject_id"),
        completeness=completeness,
        value=_optional_decimal(row, "value"),
        sample_count=_require_int(row, "sample_count"),
        qualifying_count=qualifying_count,
        producer_authority_sha256=_require_text(
            row,
            "producer_authority_sha256",
        ),
        source_authority_sha256=_require_text(
            row,
            "source_authority_sha256",
        ),
        source_set_sha256=_require_text(row, "source_set_sha256"),
        evidence_sha256=_require_text(row, "evidence_sha256"),
        window_started_at=_require_datetime(row, "window_started_at"),
        window_ended_at=_require_datetime(row, "window_ended_at"),
        observed_at=_require_datetime(row, "observed_at"),
        recorded_at=_require_datetime(row, "recorded_at"),
        incomplete_reason=_optional_text(row, "incomplete_reason"),
    )
    evidence_id = _require_text(row, "evidence_id")
    evidence_envelope_sha256 = _require_text(row, "semantic_sha256")
    source_rows = tuple(
        connection.execute(
            sa.select(phase5_advanced_risk_evidence_sources)
            .where(phase5_advanced_risk_evidence_sources.c.evidence_id == evidence_id)
            .order_by(phase5_advanced_risk_evidence_sources.c.ordinal)
        ).mappings()
    )
    source_set = _source_set_from_rows(
        source_rows,
        evidence_id=evidence_id,
        account_id=observation.account_id,
        evidence_sha256=evidence_envelope_sha256,
        source_count=_require_int(row, "source_count"),
    )
    _validate_source_set_for_observation(observation, source_set)
    expected = _evidence_values(
        observation=observation,
        source_set=source_set,
        assignment=assignment,
        observation_sequence=_require_int(row, "observation_sequence"),
        previous=previous,
        mode=mode,
        disposition=disposition,
        fencing_generation=_require_int(row, "fencing_generation"),
        lease_sha256=_require_text(row, "lease_sha256"),
        fence_sha256=_require_text(row, "fence_sha256"),
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
    )
    _assert_immutable(
        phase5_advanced_risk_evidence,
        evidence_id,
        row,
        expected,
    )
    expected_member_sha256s = tuple(member.semantic_sha256 for member in source_set.members)
    if (
        material[2] != observation.canonical_json
        or material[3] != observation.semantic_sha256
        or material[4] != assignment.envelope_sha256
        or material[5] != MODERATE_ADVANCED_RISK_POLICY_SHA256
        or material[8] != source_set.source_count
        or material[9] != expected_member_sha256s
        or material[11] != (None if previous is None else previous.envelope_sha256)
    ):
        raise AdvancedRiskPersistenceConflict("persisted advanced-risk evidence envelope conflicts")
    return _PersistedEvidence(
        observation=observation,
        source_set=source_set,
        observation_sequence=_require_int(row, "observation_sequence"),
        envelope_sha256=evidence_envelope_sha256,
        assignment_id=assignment_id,
        policy_sha256=_require_text(row, "policy_sha256"),
    )


def _verified_evidence_history(
    connection: Connection,
    account_id: str,
    assignments: tuple[_PersistedAssignment, ...],
) -> tuple[_PersistedEvidence, ...]:
    rows = tuple(
        connection.execute(
            sa.select(phase5_advanced_risk_evidence)
            .where(phase5_advanced_risk_evidence.c.account_id == account_id)
            .order_by(phase5_advanced_risk_evidence.c.observation_sequence)
        ).mappings()
    )
    _, control_bindings = _control_bindings(connection, account_id)
    assignment_by_id = {record.assignment.assignment_id: record for record in assignments}
    records: list[_PersistedEvidence] = []
    for expected_sequence, row in enumerate(rows, start=1):
        if _require_int(row, "observation_sequence") != expected_sequence:
            raise AdvancedRiskPersistenceConflict("advanced-risk evidence history is not gap-free")
        previous = None if not records else records[-1]
        records.append(
            _evidence_from_row(
                connection,
                row,
                previous=previous,
                assignments=assignment_by_id,
                control_bindings=control_bindings,
            )
        )
    source_account_ids = set(
        connection.scalars(
            sa.select(phase5_advanced_risk_evidence_sources.c.account_id).where(
                phase5_advanced_risk_evidence_sources.c.account_id == account_id
            )
        )
    )
    if not records and source_account_ids:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk source membership exists without evidence"
        )
    return tuple(records)


def _assessment_results_material(
    *,
    assessment: AdvancedRiskPolicyAssessment,
    required_instrument_ids: tuple[str, ...],
    evidence_records: tuple[_PersistedEvidence, ...],
) -> tuple[object, ...]:
    return (
        ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
        "assessment_results",
        assessment.canonical_json,
        assessment.semantic_sha256,
        required_instrument_ids,
        tuple((item.canonical_json, item.semantic_sha256) for item in assessment.rule_assessments),
        tuple(
            (record.observation.observation_id, record.envelope_sha256)
            for record in evidence_records
        ),
    )


def _assessment_material(
    *,
    assessment: AdvancedRiskPolicyAssessment,
    results_sha256: str,
    assignment_sha256: str,
    required_instrument_ids: tuple[str, ...],
    evidence_records: tuple[_PersistedEvidence, ...],
    evidence_context_sha256: str | None,
    previous_envelope_sha256: str | None,
    fence_sha256: str,
    lease_sha256: str,
    operational_transition_id: str,
    operational_transition_sha256: str,
    valid_through: datetime,
) -> tuple[object, ...]:
    return (
        ADVANCED_RISK_PERSISTENCE_CONTRACT_VERSION,
        "assessment_envelope",
        assessment.canonical_json,
        assessment.semantic_sha256,
        results_sha256,
        assignment_sha256,
        required_instrument_ids,
        tuple(
            (record.observation.observation_id, record.envelope_sha256)
            for record in evidence_records
        ),
        evidence_context_sha256,
        previous_envelope_sha256,
        fence_sha256,
        lease_sha256,
        operational_transition_id,
        operational_transition_sha256,
        valid_through,
    )


def _assessment_values(
    *,
    assessment: AdvancedRiskPolicyAssessment,
    required_instrument_ids: tuple[str, ...],
    evidence_records: tuple[_PersistedEvidence, ...],
    watermark: _PersistedEvidence,
    assignment: _PersistedAssignment,
    evidence_context_sha256: str | None,
    sequence_number: int,
    previous: _PersistedAssessment | None,
    fencing_generation: int,
    lease_sha256: str,
    fence_sha256: str,
    operational_transition_id: str,
    operational_transition_sha256: str,
    valid_through: datetime,
) -> dict[str, object]:
    results_material = _assessment_results_material(
        assessment=assessment,
        required_instrument_ids=required_instrument_ids,
        evidence_records=evidence_records,
    )
    results_payload = canonical_json_text(results_material)
    results_sha256 = _sha256(results_material)
    previous_envelope = None if previous is None else previous.envelope_sha256
    material = _assessment_material(
        assessment=assessment,
        results_sha256=results_sha256,
        assignment_sha256=assignment.envelope_sha256,
        required_instrument_ids=required_instrument_ids,
        evidence_records=evidence_records,
        evidence_context_sha256=evidence_context_sha256,
        previous_envelope_sha256=previous_envelope,
        fence_sha256=fence_sha256,
        lease_sha256=lease_sha256,
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
        valid_through=valid_through,
    )
    complete_count = sum(
        item.effective_completeness is AdvancedRiskObservationCompleteness.COMPLETE
        for item in assessment.rule_assessments
    )
    breached_count = sum(
        item.reason_code.endswith("limit_breached") for item in assessment.rule_assessments
    )
    return {
        "assessment_id": assessment.assessment_id,
        "account_id": assessment.account_id,
        "sequence_number": sequence_number,
        "previous_sequence_number": (None if previous is None else previous.sequence_number),
        "previous_assessment_id": (None if previous is None else previous.assessment.assessment_id),
        "previous_assessment_sha256": previous_envelope,
        "idempotency_key": assessment.assessment_id,
        "assignment_id": assignment.assignment.assignment_id,
        "assignment_sequence_number": assignment.assignment.sequence_number,
        "assignment_sha256": assignment.envelope_sha256,
        "policy_sha256": assessment.policy_sha256,
        "environment": assessment.environment,
        "observation_watermark_sequence": watermark.observation_sequence,
        "watermark_evidence_id": watermark.observation.observation_id,
        "watermark_evidence_sha256": watermark.envelope_sha256,
        "evaluation_mode": assessment.mode.value,
        "disposition": assessment.disposition.value,
        "result_count": len(assessment.rule_assessments),
        "complete_result_count": complete_count,
        "incomplete_result_count": (len(assessment.rule_assessments) - complete_count),
        "breached_rule_count": breached_count,
        "results_payload": results_payload,
        "results_sha256": results_sha256,
        "fencing_generation": fencing_generation,
        "lease_sha256": lease_sha256,
        "fence_sha256": fence_sha256,
        "operational_transition_id": operational_transition_id,
        "operational_transition_sha256": operational_transition_sha256,
        "assessed_at": assessment.assessed_at,
        "valid_through": valid_through,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def _decoded_string_tuple(
    value: object,
    field_name: str,
) -> tuple[str, ...]:
    if type(value) is not tuple or any(type(item) is not str for item in value):
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk {field_name} must be an exact string tuple"
        )
    return cast(tuple[str, ...], value)


def _decoded_pair_tuple(
    value: object,
    field_name: str,
) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple:
        raise AdvancedRiskPersistenceError(
            f"persisted advanced-risk {field_name} must be an exact pair tuple"
        )
    pairs: list[tuple[str, str]] = []
    for item in value:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
        ):
            raise AdvancedRiskPersistenceError(
                f"persisted advanced-risk {field_name} contains a malformed pair"
            )
        pairs.append((item[0], item[1]))
    return tuple(pairs)


def _assessment_from_row(
    row: AdvancedRiskRow,
    *,
    previous: _PersistedAssessment | None,
    assignments: Mapping[str, _PersistedAssignment],
    evidence: Mapping[str, _PersistedEvidence],
    control_bindings: Mapping[str, str],
) -> _PersistedAssessment:
    results_payload = _require_text(row, "results_payload")
    results_material = _decode_canonical_tuple(
        results_payload,
        kind="assessment_results",
        size=7,
    )
    required_instrument_ids = _decoded_string_tuple(
        results_material[4],
        "required instrument IDs",
    )
    expected_rule_pairs = _decoded_pair_tuple(
        results_material[5],
        "rule assessment identities",
    )
    evidence_pairs = _decoded_pair_tuple(
        results_material[6],
        "assessment evidence identities",
    )
    canonical_payload = _require_text(row, "canonical_payload")
    material = _decode_canonical_tuple(
        canonical_payload,
        kind="assessment_envelope",
        size=15,
    )
    evidence_context_sha256 = _decoded_optional_text(
        material[8],
        "evidence_context_sha256",
    )
    if evidence_context_sha256 is not None:
        _require_sha256(
            evidence_context_sha256,
            "advanced-risk evidence_context_sha256",
        )
    evidence_records: list[_PersistedEvidence] = []
    for evidence_id, envelope_sha256 in evidence_pairs:
        record = evidence.get(evidence_id)
        if record is None or record.envelope_sha256 != envelope_sha256:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assessment references unauthenticated evidence"
            )
        evidence_records.append(record)
    observations = tuple(record.observation for record in evidence_records)
    try:
        mode = AdvancedRiskEvaluationMode(_require_text(row, "evaluation_mode"))
    except ValueError as error:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk assessment mode is unsupported"
        ) from error
    assessment = assess_moderate_advanced_risk(
        observations,
        mode=mode,
        required_instrument_ids=required_instrument_ids,
        assessed_at=_require_datetime(row, "assessed_at"),
    )
    if assessment.assessment_id != _require_text(row, "assessment_id"):
        raise AdvancedRiskPersistenceConflict(
            "persisted advanced-risk assessment identity conflicts"
        )
    actual_rule_pairs = tuple(
        (item.canonical_json, item.semantic_sha256) for item in assessment.rule_assessments
    )
    if (
        results_material[2] != assessment.canonical_json
        or results_material[3] != assessment.semantic_sha256
        or expected_rule_pairs != actual_rule_pairs
    ):
        raise AdvancedRiskPersistenceConflict("persisted advanced-risk assessment results conflict")
    assignment_id = _require_text(row, "assignment_id")
    assignment = assignments.get(assignment_id)
    if assignment is None:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk assessment assignment is not authenticated"
        )
    operational_transition_id = _require_text(row, "operational_transition_id")
    operational_transition_sha256 = _require_text(
        row,
        "operational_transition_sha256",
    )
    if control_bindings.get(operational_transition_id) != operational_transition_sha256:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk assessment control transition is not authenticated"
        )
    watermark_id = _require_text(row, "watermark_evidence_id")
    watermark = evidence.get(watermark_id)
    if (
        watermark is None
        or watermark.observation_sequence != _require_int(row, "observation_watermark_sequence")
        or watermark.envelope_sha256 != _require_text(row, "watermark_evidence_sha256")
    ):
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk assessment watermark is not authenticated"
        )
    valid_through = _require_datetime(row, "valid_through")
    expected = _assessment_values(
        assessment=assessment,
        required_instrument_ids=required_instrument_ids,
        evidence_records=tuple(evidence_records),
        watermark=watermark,
        assignment=assignment,
        evidence_context_sha256=evidence_context_sha256,
        sequence_number=_require_int(row, "sequence_number"),
        previous=previous,
        fencing_generation=_require_int(row, "fencing_generation"),
        lease_sha256=_require_text(row, "lease_sha256"),
        fence_sha256=_require_text(row, "fence_sha256"),
        operational_transition_id=operational_transition_id,
        operational_transition_sha256=operational_transition_sha256,
        valid_through=valid_through,
    )
    _assert_immutable(
        phase5_advanced_risk_assessments,
        assessment.assessment_id,
        row,
        expected,
    )
    if (
        material[2] != assessment.canonical_json
        or material[3] != assessment.semantic_sha256
        or material[4] != expected["results_sha256"]
        or material[5] != assignment.envelope_sha256
        or material[6] != required_instrument_ids
        or material[7] != evidence_pairs
        or material[9] != (None if previous is None else previous.envelope_sha256)
        or material[14] != valid_through
    ):
        raise AdvancedRiskPersistenceConflict(
            "persisted advanced-risk assessment envelope conflicts"
        )
    return _PersistedAssessment(
        assessment=assessment,
        required_instrument_ids=required_instrument_ids,
        evidence_ids=tuple(item[0] for item in evidence_pairs),
        sequence_number=_require_int(row, "sequence_number"),
        envelope_sha256=_require_text(row, "semantic_sha256"),
        evidence_context_sha256=evidence_context_sha256,
        valid_through=valid_through,
    )


def _verified_assessment_history(
    connection: Connection,
    account_id: str,
    assignments: tuple[_PersistedAssignment, ...],
    evidence_records: tuple[_PersistedEvidence, ...],
) -> tuple[_PersistedAssessment, ...]:
    rows = tuple(
        connection.execute(
            sa.select(phase5_advanced_risk_assessments)
            .where(phase5_advanced_risk_assessments.c.account_id == account_id)
            .order_by(phase5_advanced_risk_assessments.c.sequence_number)
        ).mappings()
    )
    _, control_bindings = _control_bindings(connection, account_id)
    assignment_by_id = {record.assignment.assignment_id: record for record in assignments}
    evidence_by_id = {record.observation.observation_id: record for record in evidence_records}
    records: list[_PersistedAssessment] = []
    for expected_sequence, row in enumerate(rows, start=1):
        if _require_int(row, "sequence_number") != expected_sequence:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assessment history is not gap-free"
            )
        previous = None if not records else records[-1]
        records.append(
            _assessment_from_row(
                row,
                previous=previous,
                assignments=assignment_by_id,
                evidence=evidence_by_id,
                control_bindings=control_bindings,
            )
        )
    referenced_evidence = {evidence_id for record in records for evidence_id in record.evidence_ids}
    if set(evidence_by_id) != referenced_evidence:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk evidence history contains an orphan or missing assessment reference"
        )
    return tuple(records)


def _validate_receipt(
    receipt: AccountFenceReceipt,
    *,
    fence: AccountFence,
    checked_at: datetime,
) -> None:
    if type(receipt) is not AccountFenceReceipt:
        raise AdvancedRiskPersistenceError(
            "advanced-risk fence validator returned a non-canonical receipt"
        )
    receipt._validate()
    if receipt.fence != fence or receipt.validated_at != checked_at:
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk fence receipt does not bind the requested fence and instant"
        )


def _authenticated_assignment(
    record: _PersistedAssignment,
) -> AuthenticatedAdvancedRiskAssignment:
    return AuthenticatedAdvancedRiskAssignment(
        assignment=record.assignment,
        envelope_sha256=record.envelope_sha256,
        fence_sha256=record.fence_sha256,
        lease_sha256=record.lease_sha256,
        operational_transition_id=record.operational_transition_id,
        operational_transition_sha256=record.operational_transition_sha256,
    )


def load_current_advanced_risk_assignment_in_transaction(
    connection: Connection,
    account_id: str,
) -> AuthenticatedAdvancedRiskAssignment | None:
    """Authenticate the assignment chain and return its exact current envelope."""

    if not isinstance(connection, Connection):
        raise AdvancedRiskPersistenceError("transactional assignment load requires a Connection")
    if type(account_id) is not str or not account_id or account_id != account_id.strip():
        raise AdvancedRiskPersistenceError(
            "advanced-risk account ID must be non-empty trimmed text"
        )
    records = _verified_assignment_history(connection, account_id)
    return None if not records else _authenticated_assignment(records[-1])


def load_authenticated_advanced_risk_assignment_in_transaction(
    connection: Connection,
    assignment_id: str,
) -> AuthenticatedAdvancedRiskAssignment | None:
    """Load one assignment only through its complete authenticated history."""

    if not isinstance(connection, Connection):
        raise AdvancedRiskPersistenceError("transactional assignment load requires a Connection")
    if (
        type(assignment_id) is not str
        or not assignment_id
        or assignment_id != assignment_id.strip()
    ):
        raise AdvancedRiskPersistenceError(
            "advanced-risk assignment ID must be non-empty trimmed text"
        )
    account_id = connection.scalar(
        sa.select(phase5_advanced_risk_assignments.c.account_id).where(
            phase5_advanced_risk_assignments.c.assignment_id == assignment_id
        )
    )
    if account_id is None:
        return None
    if type(account_id) is not str:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk assignment account is malformed"
        )
    records = _verified_assignment_history(connection, account_id)
    record = next(
        (item for item in records if item.assignment.assignment_id == assignment_id),
        None,
    )
    return None if record is None else _authenticated_assignment(record)


def load_advanced_risk_control_bindings_in_transaction(
    connection: Connection,
    account_id: str,
) -> tuple[OperationalControlTransition | None, Mapping[str, str]]:
    """Authenticate operational history used by advanced-risk envelope readers."""

    if not isinstance(connection, Connection):
        raise AdvancedRiskPersistenceError(
            "transactional control binding load requires a Connection"
        )
    return _control_bindings(connection, account_id)


def load_advanced_risk_assessment_reference_in_transaction(
    connection: Connection,
    assessment_id: str,
) -> AdvancedRiskAssessmentReference | None:
    """Load one assessment only through the complete exact account verifier."""

    if not isinstance(connection, Connection):
        raise AdvancedRiskPersistenceError("transactional assessment load requires a Connection")
    if (
        type(assessment_id) is not str
        or not assessment_id
        or assessment_id != assessment_id.strip()
    ):
        raise AdvancedRiskPersistenceError(
            "advanced-risk assessment ID must be non-empty trimmed text"
        )
    account_id = connection.scalar(
        sa.select(phase5_advanced_risk_assessments.c.account_id).where(
            phase5_advanced_risk_assessments.c.assessment_id == assessment_id
        )
    )
    if account_id is None:
        return None
    if type(account_id) is not str:
        raise AdvancedRiskPersistenceError(
            "persisted advanced-risk assessment account is malformed"
        )
    assignments = _verified_assignment_history(connection, account_id)
    evidence = _verified_evidence_history(connection, account_id, assignments)
    records = _verified_assessment_history(
        connection,
        account_id,
        assignments,
        evidence,
    )
    record = next(
        (item for item in records if item.assessment.assessment_id == assessment_id),
        None,
    )
    if record is None:  # pragma: no cover - account selected by assessment ID
        raise AdvancedRiskPersistenceConflict(
            "advanced-risk assessment disappeared during authenticated load"
        )
    row = (
        connection.execute(
            sa.select(phase5_advanced_risk_assessments).where(
                phase5_advanced_risk_assessments.c.assessment_id == assessment_id
            )
        )
        .mappings()
        .one()
    )
    return AdvancedRiskAssessmentReference(
        account_id=account_id,
        assessment_id=assessment_id,
        assessment_sha256=record.envelope_sha256,
        policy_sha256=record.assessment.policy_sha256,
        mode=record.assessment.mode,
        disposition=record.assessment.disposition,
        assignment_id=_require_text(row, "assignment_id"),
        assignment_sequence_number=_require_int(
            row,
            "assignment_sequence_number",
        ),
        assignment_sha256=_require_text(row, "assignment_sha256"),
        observation_watermark_sequence=_require_int(
            row,
            "observation_watermark_sequence",
        ),
        watermark_evidence_id=_require_text(row, "watermark_evidence_id"),
        watermark_evidence_sha256=_require_text(
            row,
            "watermark_evidence_sha256",
        ),
        operational_transition_id=_require_text(
            row,
            "operational_transition_id",
        ),
        operational_transition_sha256=_require_text(
            row,
            "operational_transition_sha256",
        ),
        evidence_context_sha256=record.evidence_context_sha256,
        assessed_at=record.assessment.assessed_at,
        valid_through=record.valid_through,
    )


def authenticate_advanced_risk_assessment_evidence_in_transaction(
    connection: Connection,
    assessment: AdvancedRiskPolicyAssessment,
    *,
    observations: tuple[AdvancedRiskPolicyObservation, ...],
    source_sets: tuple[AdvancedRiskSourceSet, ...],
    required_instrument_ids: tuple[str, ...],
    valid_through: datetime,
    evidence_context_sha256: str | None,
) -> AdvancedRiskAssessmentReference:
    """Authenticate an exact retained assessment without replaying a write.

    Historical batch retries use this read-only path after a runtime trip has
    intentionally changed the operational-control head.  It verifies the full
    assessment, observation, and retained source membership rather than
    treating the assessment identifier as sufficient evidence.
    """

    if not isinstance(connection, Connection):
        raise AdvancedRiskPersistenceError(
            "transactional assessment authentication requires a Connection"
        )
    if type(assessment) is not AdvancedRiskPolicyAssessment:
        raise AdvancedRiskPersistenceError(
            "assessment authentication requires an exact policy assessment"
        )
    assessment.__post_init__()
    if type(observations) is not tuple or any(
        type(item) is not AdvancedRiskPolicyObservation for item in observations
    ):
        raise AdvancedRiskPersistenceError(
            "assessment authentication observations must be an exact tuple"
        )
    if (
        type(source_sets) is not tuple
        or len(source_sets) != len(observations)
        or any(type(item) is not AdvancedRiskSourceSet for item in source_sets)
    ):
        raise AdvancedRiskPersistenceError(
            "assessment authentication source sets must exactly align"
        )
    for observation, source_set in zip(observations, source_sets, strict=True):
        observation.__post_init__()
        _validate_source_set_for_observation(observation, source_set)
    expected_assessment = assess_moderate_advanced_risk(
        observations,
        mode=assessment.mode,
        required_instrument_ids=required_instrument_ids,
        assessed_at=assessment.assessed_at,
    )
    if expected_assessment != assessment:
        raise AdvancedRiskPersistenceConflict(
            "retained advanced-risk assessment conflicts with full policy coverage"
        )
    valid_through = _require_utc(
        valid_through,
        "retained advanced-risk assessment valid_through",
    )
    if valid_through <= assessment.assessed_at:
        raise AdvancedRiskPersistenceError(
            "retained advanced-risk assessment validity must follow assessment time"
        )
    if evidence_context_sha256 is not None:
        _require_sha256(
            evidence_context_sha256,
            "retained advanced-risk evidence_context_sha256",
        )

    assignments = _verified_assignment_history(connection, assessment.account_id)
    evidence = _verified_evidence_history(
        connection,
        assessment.account_id,
        assignments,
    )
    assessments = _verified_assessment_history(
        connection,
        assessment.account_id,
        assignments,
        evidence,
    )
    record = next(
        (item for item in assessments if item.assessment.assessment_id == assessment.assessment_id),
        None,
    )
    if record is None:
        raise AdvancedRiskPersistenceError("advanced-risk assessment is not durably retained")
    expected_evidence_ids = tuple(observation.observation_id for observation in observations)
    evidence_by_id = {item.observation.observation_id: item for item in evidence}
    if (
        record.assessment != assessment
        or record.required_instrument_ids != required_instrument_ids
        or record.evidence_ids != expected_evidence_ids
        or record.evidence_context_sha256 != evidence_context_sha256
        or record.valid_through != valid_through
        or any(
            evidence_by_id.get(observation.observation_id) is None
            or evidence_by_id[observation.observation_id].observation != observation
            or evidence_by_id[observation.observation_id].source_set != source_set
            for observation, source_set in zip(
                observations,
                source_sets,
                strict=True,
            )
        )
    ):
        raise AdvancedRiskPersistenceConflict(
            "retained advanced-risk assessment evidence conflicts"
        )
    reference = load_advanced_risk_assessment_reference_in_transaction(
        connection,
        assessment.assessment_id,
    )
    if reference is None:  # pragma: no cover - authenticated immediately above
        raise AdvancedRiskPersistenceConflict(
            "retained advanced-risk assessment reference disappeared"
        )
    return reference


class SqlAdvancedRiskRepository:
    """Persist the fixed policy, authenticated assignments, and assessments."""

    __slots__ = ("_clock", "_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
        clock: Clock,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AdvancedRiskPersistenceError("advanced-risk repository requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AdvancedRiskPersistenceError(
                f"advanced-risk repository does not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise AdvancedRiskPersistenceError(
                "advanced-risk repository requires a SQL fence validator"
            )
        if not callable(getattr(clock, "now", None)):
            raise AdvancedRiskPersistenceError("advanced-risk repository requires a trusted clock")
        self._engine = engine
        self._coordinator = coordinator
        self._clock = clock

    def _trusted_now(self) -> datetime:
        value = self._clock.now()
        return _require_utc(value, "advanced-risk trusted clock instant")

    def register_moderate_policy(
        self,
        *,
        approval_evidence_sha256: str,
        approved_at: datetime,
    ) -> RegisteredAdvancedRiskPolicy:
        """Register the one fixed policy or return its byte-exact retry."""

        _require_sha256(
            approval_evidence_sha256,
            "advanced-risk approval_evidence_sha256",
        )
        approved_at = _require_utc(approved_at, "advanced-risk approved_at")
        values = _policy_values(
            MODERATE_ADVANCED_RISK_POLICY,
            approval_evidence_sha256=approval_evidence_sha256,
            approved_at=approved_at,
        )
        try:
            with _write_transaction(self._engine) as connection:
                existing = _registered_policy_in_transaction(connection)
                if existing is not None:
                    if (
                        existing.approval_evidence_sha256 != approval_evidence_sha256
                        or existing.approved_at != approved_at
                    ):
                        raise AdvancedRiskPersistenceConflict(
                            "advanced-risk policy registration conflicts"
                        )
                    return existing
                try:
                    connection.execute(sa.insert(phase5_advanced_risk_policies).values(**values))
                except IntegrityError as error:
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk policy registration conflicts"
                    ) from error
                registered = _registered_policy_in_transaction(connection)
                if registered is None:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk policy registration was not durable"
                    )
                return registered
        except AdvancedRiskPersistenceError:
            raise
        except (AdvancedRiskPolicyError, ImmutableFactConflict) as error:
            raise AdvancedRiskPersistenceConflict(str(error)) from error

    def load_registered_policy(self) -> RegisteredAdvancedRiskPolicy | None:
        """Load and authenticate the fixed policy registry row."""

        with _repeatable_read_transaction(self._engine) as connection:
            return _registered_policy_in_transaction(connection)

    def assign(
        self,
        command: AdvancedRiskAssignmentCommand,
        fence: AccountFence,
    ) -> AdvancedRiskPolicyAssignment:
        """Append one authenticated assignment under the account lease-head lock."""

        if type(command) is not AdvancedRiskAssignmentCommand:
            raise AdvancedRiskPersistenceError("advanced-risk assignment requires an exact command")
        command.__post_init__()
        if type(fence) is not AccountFence:
            raise AdvancedRiskPersistenceError(
                "advanced-risk assignment requires an exact account fence"
            )
        fence.__post_init__()
        if command.account_id != fence.account_id:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assignment command and fence accounts differ"
            )
        assigned_at = self._trusted_now()
        try:
            with _write_transaction(self._engine) as connection:
                receipt = self._coordinator.revalidate_in_transaction(
                    connection,
                    fence,
                    checked_at=assigned_at,
                )
                _validate_receipt(receipt, fence=fence, checked_at=assigned_at)
                registered = _registered_policy_in_transaction(
                    connection,
                    command.policy_sha256,
                )
                if registered is None:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assignment requires registered policy"
                    )
                records = _verified_assignment_history(
                    connection,
                    command.account_id,
                )
                existing = next(
                    (
                        record
                        for record in records
                        if record.assignment.command_id == command.command_id
                    ),
                    None,
                )
                if existing is not None:
                    if (
                        existing.command != command
                        or existing.fence_sha256 != fence.semantic_sha256
                    ):
                        raise AdvancedRiskPersistenceConflict(
                            "advanced-risk assignment command identity conflicts"
                        )
                    return existing.assignment
                if (
                    command.policy_id != registered.policy.policy_id
                    or command.policy_sha256 != registered.policy.semantic_sha256
                    or command.environment != registered.policy.environment
                    or command.approval_evidence_sha256 != registered.approval_evidence_sha256
                ):
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk assignment conflicts with registered policy"
                    )
                current_control, _ = _control_bindings(
                    connection,
                    command.account_id,
                )
                if current_control is None:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assignment requires operational control"
                    )
                if current_control.effective_state is OperationalControlState.RUNNING:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk policy cannot be assigned while control is RUNNING"
                    )
                previous = None if not records else records[-1]
                assignment = assign_advanced_risk_policy(
                    None if previous is None else previous.assignment,
                    command,
                    assigned_at=assigned_at,
                )
                values = _assignment_values(
                    assignment=assignment,
                    command=command,
                    registered=registered,
                    previous=previous,
                    fencing_generation=fence.fencing_generation,
                    lease_sha256=receipt.lease_sha256,
                    fence_sha256=fence.semantic_sha256,
                    operational_transition_id=current_control.transition_id,
                    operational_transition_sha256=current_control.semantic_sha256,
                )
                try:
                    connection.execute(sa.insert(phase5_advanced_risk_assignments).values(**values))
                except IntegrityError as error:
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk assignment append conflicts"
                    ) from error
                record = _PersistedAssignment(
                    command=command,
                    assignment=assignment,
                    envelope_sha256=cast(str, values["semantic_sha256"]),
                    fence_sha256=fence.semantic_sha256,
                    lease_sha256=receipt.lease_sha256,
                    operational_transition_id=current_control.transition_id,
                    operational_transition_sha256=current_control.semantic_sha256,
                )
                head_values = _assignment_head_values(record)
                if previous is None:
                    connection.execute(
                        sa.insert(phase5_advanced_risk_assignment_heads).values(**head_values)
                    )
                else:
                    updated = connection.execute(
                        sa.update(phase5_advanced_risk_assignment_heads)
                        .where(
                            phase5_advanced_risk_assignment_heads.c.account_id
                            == command.account_id,
                            phase5_advanced_risk_assignment_heads.c.sequence_number
                            == previous.assignment.sequence_number,
                            phase5_advanced_risk_assignment_heads.c.assignment_sha256
                            == previous.envelope_sha256,
                        )
                        .values(**head_values)
                    )
                    if updated.rowcount != 1:
                        raise AdvancedRiskPersistenceConflict(
                            "advanced-risk assignment head compare-and-set lost"
                        )
                verified = _verified_assignment_history(
                    connection,
                    command.account_id,
                )
                if not verified or verified[-1].assignment != assignment:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assignment append was not durable"
                    )
                return assignment
        except AdvancedRiskPersistenceError:
            raise
        except AdvancedRiskAssignmentConflict as error:
            raise AdvancedRiskPersistenceConflict(str(error)) from error
        except (
            AccountCoordinatorError,
            AdvancedRiskAssignmentError,
            AdvancedRiskPolicyError,
            ImmutableFactConflict,
            OperationalControlError,
        ) as error:
            raise AdvancedRiskPersistenceError(str(error)) from error

    def current_assignment(
        self,
        account_id: str,
    ) -> AdvancedRiskPolicyAssignment | None:
        """Load the exact authenticated assignment head."""

        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise AdvancedRiskPersistenceError(
                "advanced-risk account ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            records = _verified_assignment_history(connection, account_id)
            return None if not records else records[-1].assignment

    def assignment_history(
        self,
        account_id: str,
    ) -> tuple[AdvancedRiskPolicyAssignment, ...]:
        """Load the authenticated gap-free assignment history."""

        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise AdvancedRiskPersistenceError(
                "advanced-risk account ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            return tuple(
                record.assignment for record in _verified_assignment_history(connection, account_id)
            )

    def load_assignment(
        self,
        assignment_id: str,
    ) -> AdvancedRiskPolicyAssignment | None:
        """Load one assignment only through its authenticated account history."""

        if (
            type(assignment_id) is not str
            or not assignment_id
            or assignment_id != assignment_id.strip()
        ):
            raise AdvancedRiskPersistenceError(
                "advanced-risk assignment ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            account_id = connection.scalar(
                sa.select(phase5_advanced_risk_assignments.c.account_id).where(
                    phase5_advanced_risk_assignments.c.assignment_id == assignment_id
                )
            )
            if account_id is None:
                return None
            if type(account_id) is not str:
                raise AdvancedRiskPersistenceError(
                    "persisted advanced-risk assignment account is malformed"
                )
            records = _verified_assignment_history(connection, account_id)
            return next(
                (
                    record.assignment
                    for record in records
                    if record.assignment.assignment_id == assignment_id
                ),
                None,
            )

    def record_assessment(
        self,
        assessment: AdvancedRiskPolicyAssessment,
        *,
        observations: tuple[AdvancedRiskPolicyObservation, ...],
        source_sets: tuple[AdvancedRiskSourceSet, ...],
        required_instrument_ids: tuple[str, ...],
        fence: AccountFence,
        valid_through: datetime,
        evidence_context_sha256: str | None = None,
        _connection: Connection | None = None,
        _receipt: AccountFenceReceipt | None = None,
        _committed_at: datetime | None = None,
        _expected_assignment: AuthenticatedAdvancedRiskAssignment | None = None,
        _expected_control: OperationalControlTransition | None = None,
    ) -> AdvancedRiskPolicyAssessment:
        """Atomically retain full policy coverage and its exact source membership."""

        if type(assessment) is not AdvancedRiskPolicyAssessment:
            raise AdvancedRiskPersistenceError(
                "advanced-risk persistence requires an exact policy assessment"
            )
        assessment.__post_init__()
        if type(observations) is not tuple or any(
            type(item) is not AdvancedRiskPolicyObservation for item in observations
        ):
            raise AdvancedRiskPersistenceError("advanced-risk observations must be an exact tuple")
        if (
            type(source_sets) is not tuple
            or len(source_sets) != len(observations)
            or any(type(item) is not AdvancedRiskSourceSet for item in source_sets)
        ):
            raise AdvancedRiskPersistenceError(
                "advanced-risk source sets must exactly align with observations"
            )
        for observation, source_set in zip(observations, source_sets, strict=True):
            observation.__post_init__()
            _validate_source_set_for_observation(observation, source_set)
        expected_assessment = assess_moderate_advanced_risk(
            observations,
            mode=assessment.mode,
            required_instrument_ids=required_instrument_ids,
            assessed_at=assessment.assessed_at,
        )
        if expected_assessment != assessment:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assessment conflicts with full policy coverage"
            )
        if type(fence) is not AccountFence:
            raise AdvancedRiskPersistenceError(
                "advanced-risk assessment requires an exact account fence"
            )
        fence.__post_init__()
        if assessment.account_id != fence.account_id:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk assessment and fence accounts differ"
            )
        valid_through = _require_utc(
            valid_through,
            "advanced-risk assessment valid_through",
        )
        if valid_through <= assessment.assessed_at:
            raise AdvancedRiskPersistenceError(
                "advanced-risk assessment validity must follow assessment time"
            )
        if evidence_context_sha256 is not None:
            _require_sha256(
                evidence_context_sha256,
                "advanced-risk evidence_context_sha256",
            )
        if _connection is not None and not isinstance(_connection, Connection):
            raise AdvancedRiskPersistenceError(
                "advanced-risk caller-owned transaction requires a Connection"
            )
        committed_at = (
            self._trusted_now()
            if _committed_at is None
            else _require_utc(
                _committed_at,
                "advanced-risk caller-owned committed_at",
            )
        )
        if committed_at < assessment.assessed_at or committed_at >= valid_through:
            raise AdvancedRiskPersistenceError(
                "advanced-risk assessment must be current at durable commit"
            )
        try:
            transaction = (
                _write_transaction(self._engine)
                if _connection is None
                else nullcontext(_connection)
            )
            with transaction as connection:
                receipt = _receipt
                if receipt is None:
                    receipt = self._coordinator.revalidate_in_transaction(
                        connection,
                        fence,
                        checked_at=committed_at,
                    )
                _validate_receipt(
                    receipt,
                    fence=fence,
                    checked_at=committed_at,
                )
                registered = _registered_policy_in_transaction(
                    connection,
                    assessment.policy_sha256,
                )
                if registered is None:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assessment requires registered policy"
                    )
                assignments = _verified_assignment_history(
                    connection,
                    assessment.account_id,
                )
                if not assignments:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assessment requires current assignment"
                    )
                current_assignment = assignments[-1]
                if _expected_assignment is not None and (
                    current_assignment.assignment != _expected_assignment.assignment
                    or current_assignment.envelope_sha256 != _expected_assignment.envelope_sha256
                ):
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk current assignment changed during composition"
                    )
                if (
                    current_assignment.assignment.policy_id != assessment.policy_id
                    or current_assignment.assignment.policy_sha256 != assessment.policy_sha256
                    or current_assignment.assignment.environment != assessment.environment
                    or current_assignment.assignment.assigned_at > assessment.assessed_at
                ):
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk assessment conflicts with current assignment"
                    )
                current_control, _ = _control_bindings(
                    connection,
                    assessment.account_id,
                )
                if current_control is None:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assessment requires operational control"
                    )
                if _expected_control is not None and current_control != _expected_control:
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk control head changed during composition"
                    )
                evidence_records = list(
                    _verified_evidence_history(
                        connection,
                        assessment.account_id,
                        assignments,
                    )
                )
                assessment_records = list(
                    _verified_assessment_history(
                        connection,
                        assessment.account_id,
                        assignments,
                        tuple(evidence_records),
                    )
                )
                existing_assessment = next(
                    (
                        record
                        for record in assessment_records
                        if record.assessment.assessment_id == assessment.assessment_id
                    ),
                    None,
                )
                if existing_assessment is not None:
                    expected_sources = {
                        record.observation.observation_id: record.source_set
                        for record in evidence_records
                    }
                    if (
                        existing_assessment.assessment != assessment
                        or existing_assessment.required_instrument_ids != required_instrument_ids
                        or existing_assessment.evidence_context_sha256 != evidence_context_sha256
                        or existing_assessment.valid_through != valid_through
                        or any(
                            expected_sources.get(observation.observation_id) != source_set
                            for observation, source_set in zip(
                                observations,
                                source_sets,
                                strict=True,
                            )
                        )
                    ):
                        raise AdvancedRiskPersistenceConflict(
                            "advanced-risk assessment identity conflicts"
                        )
                    return existing_assessment.assessment
                evidence_by_id = {
                    record.observation.observation_id: record for record in evidence_records
                }
                rule_assessment_by_identity = {
                    (item.rule_id, item.subject_id): item for item in assessment.rule_assessments
                }
                selected_records: list[_PersistedEvidence] = []
                for observation, source_set in zip(
                    observations,
                    source_sets,
                    strict=True,
                ):
                    existing_evidence = evidence_by_id.get(observation.observation_id)
                    if existing_evidence is not None:
                        if (
                            existing_evidence.observation != observation
                            or existing_evidence.source_set != source_set
                            or existing_evidence.assignment_id
                            != current_assignment.assignment.assignment_id
                        ):
                            raise AdvancedRiskPersistenceConflict(
                                "advanced-risk observation identity conflicts"
                            )
                        selected_records.append(existing_evidence)
                        continue
                    previous_evidence = None if not evidence_records else evidence_records[-1]
                    rule_assessment = rule_assessment_by_identity[
                        (observation.rule_id, observation.subject_id)
                    ]
                    observation_sequence = len(evidence_records) + 1
                    evidence_values = _evidence_values(
                        observation=observation,
                        source_set=source_set,
                        assignment=current_assignment,
                        observation_sequence=observation_sequence,
                        previous=previous_evidence,
                        mode=assessment.mode,
                        disposition=rule_assessment.disposition,
                        fencing_generation=fence.fencing_generation,
                        lease_sha256=receipt.lease_sha256,
                        fence_sha256=fence.semantic_sha256,
                        operational_transition_id=current_control.transition_id,
                        operational_transition_sha256=current_control.semantic_sha256,
                    )
                    try:
                        connection.execute(
                            sa.insert(phase5_advanced_risk_evidence).values(**evidence_values)
                        )
                        source_values = [
                            _source_values(
                                evidence_id=observation.observation_id,
                                account_id=observation.account_id,
                                evidence_sha256=cast(
                                    str,
                                    evidence_values["semantic_sha256"],
                                ),
                                ordinal=ordinal,
                                source=source,
                            )
                            for ordinal, source in enumerate(source_set.members)
                        ]
                        if source_values:
                            connection.execute(
                                sa.insert(phase5_advanced_risk_evidence_sources),
                                source_values,
                            )
                    except IntegrityError as error:
                        raise AdvancedRiskPersistenceConflict(
                            "advanced-risk evidence append conflicts"
                        ) from error
                    persisted_evidence = _PersistedEvidence(
                        observation=observation,
                        source_set=source_set,
                        observation_sequence=observation_sequence,
                        envelope_sha256=cast(
                            str,
                            evidence_values["semantic_sha256"],
                        ),
                        assignment_id=current_assignment.assignment.assignment_id,
                        policy_sha256=assessment.policy_sha256,
                    )
                    evidence_records.append(persisted_evidence)
                    evidence_by_id[observation.observation_id] = persisted_evidence
                    selected_records.append(persisted_evidence)
                if not evidence_records:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assessment has no durable evidence watermark"
                    )
                previous_assessment = None if not assessment_records else assessment_records[-1]
                assessment_values = _assessment_values(
                    assessment=assessment,
                    required_instrument_ids=required_instrument_ids,
                    evidence_records=tuple(selected_records),
                    watermark=evidence_records[-1],
                    assignment=current_assignment,
                    evidence_context_sha256=evidence_context_sha256,
                    sequence_number=len(assessment_records) + 1,
                    previous=previous_assessment,
                    fencing_generation=fence.fencing_generation,
                    lease_sha256=receipt.lease_sha256,
                    fence_sha256=fence.semantic_sha256,
                    operational_transition_id=current_control.transition_id,
                    operational_transition_sha256=current_control.semantic_sha256,
                    valid_through=valid_through,
                )
                try:
                    connection.execute(
                        sa.insert(phase5_advanced_risk_assessments).values(**assessment_values)
                    )
                except IntegrityError as error:
                    raise AdvancedRiskPersistenceConflict(
                        "advanced-risk assessment append conflicts"
                    ) from error
                verified_evidence = _verified_evidence_history(
                    connection,
                    assessment.account_id,
                    assignments,
                )
                verified_assessments = _verified_assessment_history(
                    connection,
                    assessment.account_id,
                    assignments,
                    verified_evidence,
                )
                if not verified_assessments or verified_assessments[-1].assessment != assessment:
                    raise AdvancedRiskPersistenceError(
                        "advanced-risk assessment append was not durable"
                    )
                return assessment
        except AdvancedRiskPersistenceError:
            raise
        except (
            AccountCoordinatorError,
            AdvancedRiskAssignmentError,
            AdvancedRiskPolicyError,
            ImmutableFactConflict,
            OperationalControlError,
        ) as error:
            raise AdvancedRiskPersistenceError(str(error)) from error

    def record_assessment_in_transaction(
        self,
        connection: Connection,
        assessment: AdvancedRiskPolicyAssessment,
        *,
        observations: tuple[AdvancedRiskPolicyObservation, ...],
        source_sets: tuple[AdvancedRiskSourceSet, ...],
        required_instrument_ids: tuple[str, ...],
        fence: AccountFence,
        receipt: AccountFenceReceipt,
        committed_at: datetime,
        valid_through: datetime,
        evidence_context_sha256: str | None,
        expected_assignment: AuthenticatedAdvancedRiskAssignment,
        expected_control: OperationalControlTransition,
    ) -> AdvancedRiskAssessmentReference:
        """Persist and reload an assessment inside a caller-owned transaction."""

        if not isinstance(connection, Connection) or connection.engine is not self._engine:
            raise AdvancedRiskPersistenceError(
                "advanced-risk caller-owned transaction uses a different SQL store"
            )
        self.record_assessment(
            assessment,
            observations=observations,
            source_sets=source_sets,
            required_instrument_ids=required_instrument_ids,
            fence=fence,
            valid_through=valid_through,
            evidence_context_sha256=evidence_context_sha256,
            _connection=connection,
            _receipt=receipt,
            _committed_at=committed_at,
            _expected_assignment=expected_assignment,
            _expected_control=expected_control,
        )
        reference = load_advanced_risk_assessment_reference_in_transaction(
            connection,
            assessment.assessment_id,
        )
        if reference is None:  # pragma: no cover - inserted immediately above
            raise AdvancedRiskPersistenceError("advanced-risk assessment reference was not durable")
        return reference

    def assessment_history(
        self,
        account_id: str,
    ) -> tuple[AdvancedRiskPolicyAssessment, ...]:
        """Load every authenticated assessment for an account."""

        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise AdvancedRiskPersistenceError(
                "advanced-risk account ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            assignments = _verified_assignment_history(connection, account_id)
            evidence = _verified_evidence_history(
                connection,
                account_id,
                assignments,
            )
            return tuple(
                record.assessment
                for record in _verified_assessment_history(
                    connection,
                    account_id,
                    assignments,
                    evidence,
                )
            )

    def load_assessment(
        self,
        assessment_id: str,
    ) -> AdvancedRiskPolicyAssessment | None:
        """Load one assessment through its complete account integrity chain."""

        if (
            type(assessment_id) is not str
            or not assessment_id
            or assessment_id != assessment_id.strip()
        ):
            raise AdvancedRiskPersistenceError(
                "advanced-risk assessment ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            account_id = connection.scalar(
                sa.select(phase5_advanced_risk_assessments.c.account_id).where(
                    phase5_advanced_risk_assessments.c.assessment_id == assessment_id
                )
            )
            if account_id is None:
                return None
            if type(account_id) is not str:
                raise AdvancedRiskPersistenceError(
                    "persisted advanced-risk assessment account is malformed"
                )
            assignments = _verified_assignment_history(connection, account_id)
            evidence = _verified_evidence_history(
                connection,
                account_id,
                assignments,
            )
            records = _verified_assessment_history(
                connection,
                account_id,
                assignments,
                evidence,
            )
            return next(
                (
                    record.assessment
                    for record in records
                    if record.assessment.assessment_id == assessment_id
                ),
                None,
            )

    def verify_integrity(self) -> None:
        """Authenticate all registered policy, assignment, and assessment state."""

        verify_advanced_risk_integrity(self._engine)


def verify_advanced_risk_integrity(engine: Engine) -> None:
    """Authenticate the complete Phase 5B repository in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise AdvancedRiskPersistenceError(
            "advanced-risk integrity verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise AdvancedRiskPersistenceError(
            f"advanced-risk integrity verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        policy_rows = tuple(connection.execute(sa.select(phase5_advanced_risk_policies)).mappings())
        if len(policy_rows) > 1:
            raise AdvancedRiskPersistenceConflict(
                "advanced-risk registry contains unsupported policy rows"
            )
        for row in policy_rows:
            _registered_policy_from_row(row)
        account_ids = {
            str(value)
            for value in connection.scalars(
                sa.select(phase5_advanced_risk_assignments.c.account_id)
            )
        }
        account_ids.update(
            str(value)
            for value in connection.scalars(
                sa.select(phase5_advanced_risk_assignment_heads.c.account_id)
            )
        )
        account_ids.update(
            str(value)
            for value in connection.scalars(sa.select(phase5_advanced_risk_evidence.c.account_id))
        )
        account_ids.update(
            str(value)
            for value in connection.scalars(
                sa.select(phase5_advanced_risk_evidence_sources.c.account_id)
            )
        )
        account_ids.update(
            str(value)
            for value in connection.scalars(
                sa.select(phase5_advanced_risk_assessments.c.account_id)
            )
        )
        for account_id in sorted(account_ids):
            assignments = _verified_assignment_history(connection, account_id)
            evidence = _verified_evidence_history(
                connection,
                account_id,
                assignments,
            )
            _verified_assessment_history(
                connection,
                account_id,
                assignments,
                evidence,
            )
