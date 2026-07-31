from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TypeVar

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection

from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLeasePolicy,
)
from packages.domain.advanced_risk import (
    AdvancedRiskEvidenceSource,
    AdvancedRiskObservationCompleteness,
)
from packages.domain.advanced_risk_admission import (
    AdvancedRiskCutoverQuiescenceFacts,
)
from packages.domain.advanced_risk_assignment import AdvancedRiskAssignmentCommand
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_POLICY,
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyObservation,
    ModerateAdvancedRiskRuleId,
    assess_moderate_advanced_risk,
)
from packages.domain.advanced_risk_sources import (
    AdvancedRiskExposureEvidence,
    ProposedBatchBuyExposureSet,
    derive_advanced_risk_exposure_evidence,
    proposed_batch_buy_exposure_from_phase2,
)
from packages.domain.batch_risk import (
    ActiveCapacityReservationState,
    ActiveCapacityUniverse,
    BatchRiskAuthority,
    BatchRiskDecisionStatus,
    BatchRiskFactConflict,
    VersionedBatchRiskSnapshot,
)
from packages.domain.models import OrderIntentBatch, TargetPortfolio
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlIncidentDisposition,
    OperationalControlState,
    OperationalControlTransition,
    _operational_control_rearm_evidence,
    apply_operational_control_command,
)
from packages.domain.portfolio import target_to_intent_batch
from packages.domain.submission_attempt import (
    SubmissionAttemptState,
    create_broker_submission_request,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    _write_transaction,
)
from packages.persistence.advanced_batch_risk import (
    AdvancedBatchRiskPersistenceError,
    AdvancedRiskAssessmentEvidence,
    AdvancedRiskTransactionalEvidence,
    AdvancedRiskTransactionalEvidenceContext,
    AdvancedRiskTransactionalEvidenceProducer,
    AdvancedRiskTransactionalReader,
    SqlAdvancedBatchRiskRepository,
    _verify_advanced_batch_risk_integrity,
    authenticate_advanced_risk_admission_for_dispatch_in_transaction,
)
from packages.persistence.advanced_risk import (
    AdvancedRiskSourceSet,
    AuthenticatedAdvancedRiskAssignment,
    SqlAdvancedRiskRepository,
)
from packages.persistence.batch_risk import SqlBatchRiskRepository
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
    _head_values,
    _PersistedTransition,
    _transition_values,
)
from packages.persistence.schema import (
    metadata,
    phase2_batch_authorizations,
    phase2_batch_decisions,
    phase2_batch_reservations,
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_batch_admissions,
    phase5_advanced_risk_batch_outcomes,
    phase5_advanced_risk_enforcement_heads,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from packages.persistence.submission_attempt import SqlSubmissionAttemptRepository
from tests.unit.test_advanced_risk_sources import (
    authorization,
    reservation,
    risk_snapshot,
    universe,
)
from tests.unit.test_batch_risk import (
    EVALUATED_AT,
    MutableClock,
    limits,
    make_batch,
)

ResultT = TypeVar("ResultT")
ACCOUNT_ID = "batch-risk-account"
CUTOVER_AT = EVALUATED_AT - timedelta(seconds=2)
REARMED_AT = EVALUATED_AT - timedelta(seconds=1)
APPROVAL_SHA256 = "a" * 64

_INSTRUMENT_RULES = frozenset(
    {
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO,
        ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
        ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS,
    }
)
_EXPOSURE_RULES = frozenset(
    {
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
        ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
        ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
    }
)


@dataclass(frozen=True, slots=True)
class _Snapshots:
    snapshot: VersionedBatchRiskSnapshot

    def current(self) -> VersionedBatchRiskSnapshot:
        return self.snapshot

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], ResultT],
    ) -> ResultT:
        return operation(self.snapshot)


@dataclass(slots=True)
class _CutoverVerifier:
    mode: str = "exact"
    last_facts: AdvancedRiskCutoverQuiescenceFacts | None = None

    def verify_in_transaction(
        self,
        connection: Connection,
        *,
        receipt: AccountFenceReceipt,
        assignment: AuthenticatedAdvancedRiskAssignment,
        control: OperationalControlTransition,
        checked_at: datetime,
    ) -> AdvancedRiskCutoverQuiescenceFacts | None:
        assert isinstance(connection, Connection)
        if self.mode == "absent":
            return None
        facts = AdvancedRiskCutoverQuiescenceFacts(
            account_id=receipt.fence.account_id,
            fencing_generation=receipt.fence.fencing_generation,
            fence_sha256=receipt.fence.semantic_sha256,
            assignment_id=assignment.assignment.assignment_id,
            assignment_sequence_number=assignment.assignment.sequence_number,
            assignment_sha256=assignment.envelope_sha256,
            operational_transition_id=control.transition_id,
            operational_transition_sha256=control.semantic_sha256,
            checked_at=checked_at,
            expires_at=checked_at + timedelta(seconds=5),
            reconciliation_source_id="authoritative-paper-reconciliation",
            reconciliation_sha256=_digest("clean-reconciliation"),
            reconciliation_clean=True,
            working_order_ids=(),
            unknown_order_ids=(),
            pending_cancel_order_ids=(),
            strategy_activity_source_id="durable-strategy-activity-head",
            strategy_activity_sha256=_digest("no-active-strategy-invocation"),
            active_strategy_invocation_ids=(),
        )
        if self.mode == "stale":
            facts = replace(
                facts,
                checked_at=checked_at - timedelta(seconds=1),
            )
        elif self.mode == "mismatched":
            facts = replace(facts, fence_sha256="0" * 64)
        elif self.mode == "dirty_reconciliation":
            facts = replace(facts, reconciliation_clean=False)
        elif self.mode == "active_strategy":
            facts = replace(
                facts,
                active_strategy_invocation_ids=("active-invocation",),
            )
        self.last_facts = facts
        return facts


@dataclass(slots=True)
class _EvidenceProducer:
    runtime_values: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] = field(
        default_factory=dict
    )
    pretrade_values: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] = field(
        default_factory=dict
    )
    corrupt_pretrade: bool = False
    assignment_sha256_override: str | None = None
    runtime_exposure_override: AdvancedRiskExposureEvidence | None = None
    pretrade_exposure_override: AdvancedRiskExposureEvidence | None = None
    last_context: AdvancedRiskTransactionalEvidenceContext | None = None
    last_snapshot: VersionedBatchRiskSnapshot | None = None
    last_capacity: ActiveCapacityUniverse | None = None
    last_proposed: ProposedBatchBuyExposureSet | None = None
    last_runtime_exposure: AdvancedRiskExposureEvidence | None = None
    last_pretrade_exposure: AdvancedRiskExposureEvidence | None = None

    def reset_authorization(
        self,
        *,
        runtime_values: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] | None = None,
        pretrade_values: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] | None = None,
        corrupt_pretrade: bool = False,
    ) -> None:
        self.runtime_values = {} if runtime_values is None else runtime_values
        self.pretrade_values = {} if pretrade_values is None else pretrade_values
        self.corrupt_pretrade = corrupt_pretrade
        self.assignment_sha256_override = None
        self.runtime_exposure_override = None
        self.pretrade_exposure_override = None

    def derive_in_transaction(
        self,
        reader: AdvancedRiskTransactionalReader,
        *,
        context: AdvancedRiskTransactionalEvidenceContext,
        snapshot: VersionedBatchRiskSnapshot,
        active_capacity: ActiveCapacityUniverse,
        batch: OrderIntentBatch | None,
        target: TargetPortfolio | None,
        proposed: ProposedBatchBuyExposureSet | None,
    ) -> AdvancedRiskTransactionalEvidence:
        assert isinstance(reader, AdvancedRiskTransactionalReader)
        assignment, control = reader.read_current_heads(context=context)
        assert assignment.assignment.assignment_id == context.assignment_id
        assert control.transition_id == context.operational_transition_id
        exact_batch_target = reader.read_batch_target(context=context)
        assert (exact_batch_target is None) is (batch is None)
        if exact_batch_target is not None:
            assert exact_batch_target == (batch, target)
        assert (batch is None) is (target is None)
        runtime_exposure = self.runtime_exposure_override or derive_advanced_risk_exposure_evidence(
            snapshot=snapshot,
            active_capacity=active_capacity,
            proposed=None,
            fence_token=context.fencing_generation,
            fence_sha256=context.fence_sha256,
            observed_at=context.evaluated_at,
            recorded_at=context.evaluated_at,
        )
        pretrade_exposure = (
            None
            if proposed is None
            else (
                self.pretrade_exposure_override
                or derive_advanced_risk_exposure_evidence(
                    snapshot=snapshot,
                    active_capacity=active_capacity,
                    proposed=proposed,
                    fence_token=context.fencing_generation,
                    fence_sha256=context.fence_sha256,
                    observed_at=context.evaluated_at,
                    recorded_at=context.evaluated_at,
                )
            )
        )
        runtime = _assessment_evidence(
            assessed_at=context.evaluated_at,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            instrument_ids=context.runtime_instrument_ids,
            value_overrides=self.runtime_values,
            exposure=runtime_exposure,
        )
        pretrade = (
            None
            if pretrade_exposure is None
            else _assessment_evidence(
                assessed_at=context.evaluated_at,
                mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
                instrument_ids=context.pretrade_instrument_ids,
                value_overrides=self.pretrade_values,
                corrupt_first_source_set=self.corrupt_pretrade,
                exposure=pretrade_exposure,
            )
        )
        self.last_context = context
        self.last_snapshot = snapshot
        self.last_capacity = active_capacity
        self.last_proposed = proposed
        self.last_runtime_exposure = runtime_exposure
        self.last_pretrade_exposure = pretrade_exposure
        return AdvancedRiskTransactionalEvidence(
            context=(
                context
                if self.assignment_sha256_override is None
                else replace(
                    context,
                    assignment_sha256=self.assignment_sha256_override,
                )
            ),
            runtime=runtime,
            pretrade=pretrade,
        )


@dataclass(slots=True)
class _AdversarialEvidenceProducer:
    attribute: str | None = None
    statement: object | None = None
    substituted_context_field: str | None = None
    invoked: bool = False

    def derive_in_transaction(
        self,
        reader: AdvancedRiskTransactionalReader,
        *,
        context: AdvancedRiskTransactionalEvidenceContext,
        snapshot: VersionedBatchRiskSnapshot,
        active_capacity: ActiveCapacityUniverse,
        batch: OrderIntentBatch | None,
        target: TargetPortfolio | None,
        proposed: ProposedBatchBuyExposureSet | None,
    ) -> AdvancedRiskTransactionalEvidence:
        del snapshot, active_capacity, batch, target, proposed
        self.invoked = True
        assert isinstance(reader, AdvancedRiskTransactionalReader)
        assert not hasattr(reader, "__dict__")
        assert not any(
            isinstance(value, Connection)
            for value in (
                reader.context,
                reader.assignment,
                reader.control,
                reader.batch,
                reader.target,
            )
        )
        if self.attribute is not None:
            capability = getattr(reader, self.attribute)
            if self.statement is None:
                capability()
            else:
                capability(self.statement)
        if self.substituted_context_field == "control":
            substituted = replace(
                context,
                operational_transition_sha256="0" * 64,
            )
        elif self.substituted_context_field == "target":
            substituted = replace(
                context,
                target_id="substituted-target",
                target_sha256="0" * 64,
            )
            reader.read_batch_target(context=substituted)
        else:
            raise AssertionError("adversarial producer requires an attack")
        reader.read_current_heads(context=substituted)
        raise AssertionError("substituted context was accepted")


@dataclass(frozen=True, slots=True)
class _System:
    engine: Engine
    clock: MutableClock
    coordinator: SqlAccountCoordinator
    fence: AccountFence
    advanced: SqlAdvancedRiskRepository
    atomic: SqlAdvancedBatchRiskRepository
    cutover_verifier: _CutoverVerifier
    evidence_producer: _EvidenceProducer
    legacy: SqlBatchRiskRepository
    initial_command: OperationalControlCommand
    initial_control: OperationalControlTransition
    target: TargetPortfolio
    batch: OrderIntentBatch
    snapshot: VersionedBatchRiskSnapshot


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _actor(
    *,
    actor_id: str,
    kind: OperationalControlActorKind,
    authenticated_at: datetime | None,
) -> OperationalControlActor:
    return OperationalControlActor(
        actor_id=actor_id,
        kind=kind,
        authority_sha256=_digest(f"{actor_id}-authority"),
        authenticated_at=authenticated_at,
    )


def _system(path: Path) -> _System:
    snapshot = risk_snapshot(
        positions={
            "US-ETF-IWM": Decimal("10"),
            "US-ETF-SPY": Decimal("2"),
        },
        prices={
            "US-ETF-DIA": Decimal("100"),
            "US-ETF-IWM": Decimal("50"),
            "US-ETF-QQQ": Decimal("100"),
            "US-ETF-SPY": Decimal("100"),
        },
        equity=Decimal("10000"),
    )
    target, batch = make_batch(
        snapshot.portfolio_snapshot,
        desired={
            "US-ETF-IWM": Decimal("6"),
            "US-ETF-SPY": Decimal("5"),
        },
    )
    assert snapshot.account_id == ACCOUNT_ID
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    clock = MutableClock(CUTOVER_AT)
    coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase5b-atomic-tests",
                policy_version="1",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    lease = coordinator.acquire("phase5b-atomic-worker")
    initial_command = OperationalControlCommand(
        scope_id=ACCOUNT_ID,
        idempotency_key="initialize-0001",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=_actor(
            actor_id="startup",
            kind=OperationalControlActorKind.SYSTEM,
            authenticated_at=None,
        ),
        reason_code="startup",
        reason_evidence_sha256="b" * 64,
        requested_at=CUTOVER_AT,
    )
    control = SqlOperationalControlRepository(engine=engine, clock=clock)
    initial = control.apply(initial_command)
    advanced = SqlAdvancedRiskRepository(
        engine=engine,
        coordinator=coordinator,
        clock=clock,
    )
    advanced.register_moderate_policy(
        approval_evidence_sha256=APPROVAL_SHA256,
        approved_at=CUTOVER_AT,
    )
    advanced.assign(
        AdvancedRiskAssignmentCommand(
            account_id=ACCOUNT_ID,
            environment="paper",
            idempotency_key="assignment-0001",
            policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
            policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
            actor_id="risk-owner",
            actor_authority_sha256="c" * 64,
            actor_authenticated_at=CUTOVER_AT,
            requested_at=CUTOVER_AT,
            approval_evidence_sha256=APPROVAL_SHA256,
            expected_assignment_sequence_number=0,
            expected_assignment_sha256=None,
        ),
        lease.fence,
    )
    authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=_Snapshots(snapshot),
        evaluation_clock=clock,
        consumption_clock=clock,
    )
    cutover_verifier = _CutoverVerifier()
    evidence_producer = _EvidenceProducer()
    return _System(
        engine=engine,
        clock=clock,
        coordinator=coordinator,
        fence=lease.fence,
        advanced=advanced,
        atomic=SqlAdvancedBatchRiskRepository(
            engine=engine,
            authority=authority,
            coordinator=coordinator,
            clock=clock,
            cutover_verifier=cutover_verifier,
            evidence_producer=evidence_producer,
        ),
        cutover_verifier=cutover_verifier,
        evidence_producer=evidence_producer,
        legacy=SqlBatchRiskRepository(
            engine=engine,
            authority=authority,
            coordinator=coordinator,
        ),
        initial_command=initial_command,
        initial_control=initial,
        target=target,
        batch=batch,
        snapshot=snapshot,
    )


def _assessment_evidence(
    *,
    assessed_at: datetime,
    mode: AdvancedRiskEvaluationMode,
    instrument_ids: tuple[str, ...],
    value_overrides: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] | None = None,
    corrupt_first_source_set: bool = False,
    exposure: AdvancedRiskExposureEvidence | None = None,
) -> AdvancedRiskAssessmentEvidence:
    values = value_overrides or {}
    observations: list[AdvancedRiskPolicyObservation] = []
    source_sets: list[AdvancedRiskSourceSet] = []
    for rule in MODERATE_ADVANCED_RISK_POLICY.rules:
        applicable = (
            rule.runtime_pause_threshold is not None
            if mode is AdvancedRiskEvaluationMode.RUNTIME
            else rule.pretrade_reject_threshold is not None
        )
        if not applicable:
            continue
        if exposure is not None and rule.rule_id in _EXPOSURE_RULES:
            continue
        subjects = instrument_ids if rule.rule_id in _INSTRUMENT_RULES else (ACCOUNT_ID,)
        for subject_id in subjects:
            identity = f"{mode.value}-{rule.rule_id.value}-{subject_id}-{assessed_at.isoformat()}"
            source = AdvancedRiskEvidenceSource(
                source_kind="canonical_test_fact",
                source_id=f"{identity}-source",
                source_sha256=_digest(f"{identity}-source"),
                effective_at=assessed_at - timedelta(seconds=20),
                available_at=assessed_at - timedelta(seconds=10),
            )
            source_set = AdvancedRiskSourceSet(members=(source,), source_count=1)
            source_set_sha256 = source_set.semantic_sha256
            if corrupt_first_source_set and not observations:
                source_set_sha256 = "f" * 64
            observation = AdvancedRiskPolicyObservation(
                account_id=ACCOUNT_ID,
                environment="paper",
                rule_id=rule.rule_id,
                subject_id=subject_id,
                completeness=AdvancedRiskObservationCompleteness.COMPLETE,
                value=values.get((rule.rule_id, subject_id), Decimal(0)),
                sample_count=rule.minimum_complete_samples,
                qualifying_count=(
                    0
                    if rule.rule_id is ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO
                    else None
                ),
                producer_authority_sha256=rule.producer_authority_sha256,
                source_authority_sha256=rule.source_authority_sha256,
                source_set_sha256=source_set_sha256,
                evidence_sha256=_digest(f"{identity}-evidence"),
                window_started_at=assessed_at - timedelta(minutes=1),
                window_ended_at=assessed_at - timedelta(seconds=2),
                observed_at=assessed_at - timedelta(seconds=1),
                recorded_at=assessed_at,
            )
            observations.append(observation)
            source_sets.append(source_set)
    if exposure is not None:
        exposure_source_set = AdvancedRiskSourceSet(
            members=exposure.source_members,
            source_count=len(exposure.source_members),
        )
        for observation in exposure.observations:
            if (
                observation.rule_id is ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO
                and observation.subject_id not in instrument_ids
            ):
                continue
            observations.append(observation)
            source_sets.append(exposure_source_set)
    ordered = tuple(sorted(observations, key=lambda item: (item.rule_id.value, item.subject_id)))
    sources = {
        observation.observation_id: source_set
        for observation, source_set in zip(observations, source_sets, strict=True)
    }
    assessment = assess_moderate_advanced_risk(
        ordered,
        mode=mode,
        required_instrument_ids=instrument_ids,
        assessed_at=assessed_at,
    )
    return AdvancedRiskAssessmentEvidence(
        assessment=assessment,
        observations=ordered,
        source_sets=tuple(sources[item.observation_id] for item in ordered),
        required_instrument_ids=instrument_ids,
        valid_through=assessed_at + timedelta(seconds=45),
    )


def _cutover(system: _System) -> None:
    system.evidence_producer.reset_authorization()
    head = system.atomic.enable_enforcement(fence=system.fence)
    assert head.enforcement_enabled
    assert system.cutover_verifier.last_facts is not None
    assert head.quiescence_facts_sha256 == system.cutover_verifier.last_facts.semantic_sha256
    assert system.atomic.enable_enforcement(fence=system.fence) == head


def _rearm(system: _System) -> OperationalControlTransition:
    human = _actor(
        actor_id="rearm-operator",
        kind=OperationalControlActorKind.HUMAN,
        authenticated_at=CUTOVER_AT,
    )
    dispositions = tuple(
        OperationalControlIncidentDisposition(
            event_id=event.event_id,
            event_sha256=event.semantic_sha256,
            resolution_code="reviewed",
            resolution_evidence_sha256="d" * 64,
            resolved_at=REARMED_AT,
        )
        for event in system.initial_control.blocking_events
    )
    evidence = _operational_control_rearm_evidence(
        scope_id=ACCOUNT_ID,
        current_transition_id=system.initial_control.transition_id,
        current_transition_sha256=system.initial_control.semantic_sha256,
        current_state=system.initial_control.effective_state,
        current_state_epoch_id=system.initial_control.state_epoch_id,
        actor=human,
        checked_at=REARMED_AT,
        expires_at=REARMED_AT + timedelta(seconds=30),
        readiness_sha256="e" * 64,
        reconciliation_sha256="1" * 64,
        incident_register_sha256="2" * 64,
        reconciliation_clean=True,
        data_healthy=True,
        clock_healthy=True,
        working_order_ids=(),
        unknown_order_ids=(),
        pending_cancel_order_ids=(),
        incident_dispositions=dispositions,
    )
    command = OperationalControlCommand(
        scope_id=ACCOUNT_ID,
        idempotency_key="verified-rearm-0001",
        kind=OperationalControlCommandKind.REARM,
        target_state=OperationalControlState.RUNNING,
        actor=human,
        reason_code="verified_rearm",
        reason_evidence_sha256="3" * 64,
        requested_at=REARMED_AT,
        rearm_evidence_sha256=evidence.semantic_sha256,
    )
    rearmed = apply_operational_control_command(
        system.initial_control,
        command,
        decided_at=REARMED_AT,
        rearm_evidence=evidence,
    )
    previous = _PersistedTransition(
        command=system.initial_command,
        transition=system.initial_control,
    )
    record = _PersistedTransition(command=command, transition=rearmed)
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(phase5_operational_control_transitions).values(
                **_transition_values(
                    command=command,
                    transition=rearmed,
                    previous=previous,
                )
            )
        )
        updated = connection.execute(
            sa.update(phase5_operational_control_heads)
            .where(
                phase5_operational_control_heads.c.account_id == ACCOUNT_ID,
                phase5_operational_control_heads.c.transition_id
                == system.initial_control.transition_id,
                phase5_operational_control_heads.c.transition_sha256
                == system.initial_control.semantic_sha256,
            )
            .values(**_head_values(record))
        )
        assert updated.rowcount == 1
    system.clock.instant = EVALUATED_AT
    return rearmed


def _authorization_evidence(
    system: _System,
    *,
    runtime_values: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] | None = None,
    pretrade_values: dict[tuple[ModerateAdvancedRiskRuleId, str], Decimal] | None = None,
    corrupt_pretrade: bool = False,
) -> None:
    system.evidence_producer.reset_authorization(
        runtime_values=runtime_values,
        pretrade_values=pretrade_values,
        corrupt_pretrade=corrupt_pretrade,
    )


def _repository_with_producer(
    system: _System,
    producer: AdvancedRiskTransactionalEvidenceProducer,
) -> SqlAdvancedBatchRiskRepository:
    return SqlAdvancedBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=_Snapshots(system.snapshot),
            evaluation_clock=system.clock,
            consumption_clock=system.clock,
        ),
        coordinator=system.coordinator,
        clock=system.clock,
        evidence_producer=producer,
    )


def _assert_authorization_has_no_effects(system: _System) -> None:
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_batch_admissions)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_batch_outcomes)
            )
            == 0
        )
        assert (
            connection.scalar(sa.select(phase5_operational_control_heads.c.effective_state))
            == OperationalControlState.RUNNING.value
        )


@pytest.mark.parametrize(
    ("attribute", "statement"),
    (
        (
            "execute",
            sa.update(phase5_operational_control_heads).values(
                effective_state=OperationalControlState.HALTED.value
            ),
        ),
        ("execute", sa.delete(phase5_operational_control_heads)),
        (
            "execute",
            sa.insert(phase5_operational_control_heads).values(account_id="producer-write"),
        ),
        ("execute", sa.text("CREATE TABLE producer_write (value TEXT)")),
        ("execute", sa.text("COMMIT")),
        ("execute", sa.text("ROLLBACK")),
        ("execute", sa.select(sa.func.random())),
        (
            "execute",
            sa.select(phase5_operational_control_heads).with_for_update(),
        ),
        (
            "execute",
            sa.select(sa.text("*")).select_from(sa.text("phase5_operational_control_heads")),
        ),
        ("commit", None),
        ("rollback", None),
        ("connection", None),
    ),
)
def test_transactional_evidence_reader_exposes_no_sql_or_transaction_authority(
    tmp_path: Path,
    attribute: str,
    statement: object | None,
) -> None:
    system = _system(tmp_path / f"producer-capability-{attribute}-{id(statement)}.sqlite")
    _cutover(system)
    _rearm(system)
    producer = _AdversarialEvidenceProducer(
        attribute=attribute,
        statement=statement,
    )

    with pytest.raises(AttributeError, match=attribute):
        _repository_with_producer(system, producer).authorize(
            system.batch,
            system.target,
            system.fence,
        )

    assert producer.invoked
    _assert_authorization_has_no_effects(system)
    assert "producer_write" not in sa.inspect(system.engine).get_table_names()


def test_cutover_producer_has_no_writable_connection_and_leaves_no_effects(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "cutover-producer-capability.sqlite")
    producer = _AdversarialEvidenceProducer(
        attribute="execute",
        statement=sa.update(phase5_operational_control_heads).values(
            effective_state=OperationalControlState.RUNNING.value
        ),
    )
    repository = SqlAdvancedBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=_Snapshots(system.snapshot),
            evaluation_clock=system.clock,
            consumption_clock=system.clock,
        ),
        coordinator=system.coordinator,
        clock=system.clock,
        cutover_verifier=system.cutover_verifier,
        evidence_producer=producer,
    )

    with pytest.raises(AttributeError, match="execute"):
        repository.enable_enforcement(fence=system.fence)

    assert producer.invoked
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_enforcement_heads)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 0
        )
        assert (
            connection.scalar(sa.select(phase5_operational_control_heads.c.effective_state))
            == OperationalControlState.HALTED.value
        )


@pytest.mark.parametrize("substituted_context_field", ("control", "target"))
def test_transactional_evidence_reader_rejects_context_substitution_without_effects(
    tmp_path: Path,
    substituted_context_field: str,
) -> None:
    system = _system(tmp_path / f"producer-substitution-{substituted_context_field}.sqlite")
    _cutover(system)
    _rearm(system)
    producer = _AdversarialEvidenceProducer(
        substituted_context_field=substituted_context_field,
    )

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="rejects substituted context",
    ):
        _repository_with_producer(system, producer).authorize(
            system.batch,
            system.target,
            system.fence,
        )

    assert producer.invoked
    _assert_authorization_has_no_effects(system)


@pytest.mark.parametrize(
    ("mode", "message"),
    (
        ("absent", "requires authoritative quiescence facts"),
        ("stale", "facts are stale"),
        ("mismatched", "do not bind the exact current heads"),
        (
            "dirty_reconciliation",
            "reconciliation or strategy activity is not quiescent",
        ),
        (
            "active_strategy",
            "reconciliation or strategy activity is not quiescent",
        ),
    ),
)
def test_cutover_requires_fresh_exact_authoritative_quiescence_proofs(
    tmp_path: Path,
    mode: str,
    message: str,
) -> None:
    system = _system(tmp_path / f"cutover-proof-{mode}.sqlite")
    system.cutover_verifier.mode = mode

    with pytest.raises(AdvancedBatchRiskPersistenceError, match=message):
        system.atomic.enable_enforcement(fence=system.fence)

    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_enforcement_heads)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 0
        )


def test_cutover_is_disabled_without_a_transactional_evidence_producer(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "cutover-missing-producer.sqlite")
    disabled = SqlAdvancedBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(),
            snapshots=_Snapshots(system.snapshot),
            evaluation_clock=system.clock,
            consumption_clock=system.clock,
        ),
        coordinator=system.coordinator,
        clock=system.clock,
        cutover_verifier=system.cutover_verifier,
    )

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="requires a transactional evidence producer",
    ):
        disabled.enable_enforcement(fence=system.fence)

    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_enforcement_heads)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 0
        )


def test_cutover_rejects_replayed_snapshot_exposure_before_writing_a_head(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "cutover-replayed-exposure.sqlite")
    replayed_snapshot = risk_snapshot(
        positions={
            "US-ETF-IWM": Decimal("10"),
            "US-ETF-SPY": Decimal("2"),
        },
        prices={
            "US-ETF-DIA": Decimal("100"),
            "US-ETF-IWM": Decimal("50"),
            "US-ETF-QQQ": Decimal("100"),
            "US-ETF-SPY": Decimal("100"),
        },
        equity=Decimal("10001"),
    )
    system.evidence_producer.runtime_exposure_override = derive_advanced_risk_exposure_evidence(
        snapshot=replayed_snapshot,
        active_capacity=universe(),
        proposed=None,
        fence_token=system.fence.fencing_generation,
        fence_sha256=system.fence.semantic_sha256,
        observed_at=CUTOVER_AT,
        recorded_at=CUTOVER_AT,
    )

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="does not derive from the exact snapshot, capacity, proposed batch, and fence",
    ):
        system.atomic.enable_enforcement(fence=system.fence)

    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_enforcement_heads)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 0
        )


def test_cutover_locks_legacy_writer_and_atomic_path_admits_exact_retry(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "atomic-admission.sqlite")
    _cutover(system)
    with pytest.raises(
        BatchRiskFactConflict,
        match="legacy batch-risk authorization is disabled",
    ):
        system.legacy.authorize(system.batch, system.target, system.fence)
    running = _rearm(system)
    _authorization_evidence(system)

    outcome = system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )
    assert outcome.phase2_decision is not None
    assert outcome.phase2_decision.status is BatchRiskDecisionStatus.APPROVED
    assert outcome.admission is not None and outcome.admission.admitted
    assert outcome.final_control_transition_id == running.transition_id
    context = system.evidence_producer.last_context
    runtime_exposure = system.evidence_producer.last_runtime_exposure
    pretrade_exposure = system.evidence_producer.last_pretrade_exposure
    assert context is not None
    assert runtime_exposure is not None
    assert pretrade_exposure is not None
    assert (
        context.snapshot_sha256
        == runtime_exposure.watermark.snapshot_sha256
        == outcome.watermark.snapshot_sha256
    )
    assert (
        context.active_capacity_sha256
        == runtime_exposure.watermark.active_capacity_sha256
        == outcome.watermark.active_capacity_sha256
    )
    assert runtime_exposure.watermark.proposed_batch_sha256 is None
    assert pretrade_exposure.watermark.proposed_batch_sha256 == system.batch.semantic_sha256
    assert pretrade_exposure.watermark.fence_sha256 == outcome.watermark.fence_sha256
    assert (
        system.atomic.authorize(
            system.batch,
            system.target,
            system.fence,
        )
        == outcome
    )
    with system.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_reservations))
            == 1
        )
        assert connection.scalar(
            sa.select(sa.func.count()).select_from(phase2_batch_authorizations)
        ) == len(outcome.phase2_decision.authorizations)
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_batch_admissions)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_enforcement_heads)
            )
            == 1
        )


@pytest.mark.parametrize(
    "replay_kind",
    ("snapshot", "capacity", "batch", "fence"),
)
def test_replayed_exposure_inputs_are_rejected_before_any_authorization_effect(
    tmp_path: Path,
    replay_kind: str,
) -> None:
    system = _system(tmp_path / f"advanced-replayed-{replay_kind}.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    capacity = system.evidence_producer.last_capacity
    assert capacity is not None

    if replay_kind == "snapshot":
        replayed_snapshot = risk_snapshot(
            positions={
                "US-ETF-IWM": Decimal("10"),
                "US-ETF-SPY": Decimal("2"),
            },
            prices={
                "US-ETF-DIA": Decimal("100"),
                "US-ETF-IWM": Decimal("50"),
                "US-ETF-QQQ": Decimal("100"),
                "US-ETF-SPY": Decimal("100"),
            },
            equity=Decimal("10001"),
        )
        system.evidence_producer.runtime_exposure_override = derive_advanced_risk_exposure_evidence(
            snapshot=replayed_snapshot,
            active_capacity=capacity,
            proposed=None,
            fence_token=system.fence.fencing_generation,
            fence_sha256=system.fence.semantic_sha256,
            observed_at=EVALUATED_AT,
            recorded_at=EVALUATED_AT,
        )
    elif replay_kind == "capacity":
        replayed_capacity = universe(
            reservation(
                "replayed-capacity",
                ActiveCapacityReservationState.ACTIVE,
                authorization("replayed-capacity", "US-ETF-IWM"),
            )
        )
        system.evidence_producer.runtime_exposure_override = derive_advanced_risk_exposure_evidence(
            snapshot=system.snapshot,
            active_capacity=replayed_capacity,
            proposed=None,
            fence_token=system.fence.fencing_generation,
            fence_sha256=system.fence.semantic_sha256,
            observed_at=EVALUATED_AT,
            recorded_at=EVALUATED_AT,
        )
    elif replay_kind == "batch":
        replayed_target, replayed_batch = make_batch(
            system.snapshot.portfolio_snapshot,
            desired={
                "US-ETF-IWM": Decimal("6"),
                "US-ETF-SPY": Decimal("6"),
            },
            target_id="replayed-target",
        )
        replayed_proposed = proposed_batch_buy_exposure_from_phase2(
            batch=replayed_batch,
            target=replayed_target,
            snapshot=system.snapshot,
            limits=limits(),
            evaluated_at=EVALUATED_AT,
        )
        system.evidence_producer.pretrade_exposure_override = (
            derive_advanced_risk_exposure_evidence(
                snapshot=system.snapshot,
                active_capacity=capacity,
                proposed=replayed_proposed,
                fence_token=system.fence.fencing_generation,
                fence_sha256=system.fence.semantic_sha256,
                observed_at=EVALUATED_AT,
                recorded_at=EVALUATED_AT,
            )
        )
    else:
        system.evidence_producer.runtime_exposure_override = derive_advanced_risk_exposure_evidence(
            snapshot=system.snapshot,
            active_capacity=capacity,
            proposed=None,
            fence_token=system.fence.fencing_generation,
            fence_sha256="0" * 64,
            observed_at=EVALUATED_AT,
            recorded_at=EVALUATED_AT,
        )

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="does not derive from the exact snapshot, capacity, proposed batch, and fence",
    ):
        system.atomic.authorize(
            system.batch,
            system.target,
            system.fence,
        )

    _assert_authorization_has_no_effects(system)


def test_replayed_assignment_context_is_rejected_before_any_authorization_effect(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-replayed-assignment.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    system.evidence_producer.assignment_sha256_override = "0" * 64

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="replayed a different transaction context",
    ):
        system.atomic.authorize(
            system.batch,
            system.target,
            system.fence,
        )

    _assert_authorization_has_no_effects(system)


def test_no_action_persists_only_the_exact_null_assessment_sidecar(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-no-action.sqlite")
    _cutover(system)
    _rearm(system)
    current_quantities = {
        position.instrument_id: position.quantity
        for position in system.snapshot.portfolio_snapshot.positions
    }
    no_action_target = replace(
        system.target,
        targets=tuple(
            replace(
                target,
                quantity=current_quantities[target.instrument_id],
            )
            for target in system.target.targets
        ),
    )
    empty_batch = target_to_intent_batch(
        no_action_target,
        system.snapshot.portfolio_snapshot,
    )
    _authorization_evidence(system)

    outcome = system.atomic.authorize(
        empty_batch,
        no_action_target,
        system.fence,
    )

    assert outcome.phase2_decision is not None
    assert outcome.phase2_decision.status is BatchRiskDecisionStatus.NO_ACTION
    assert outcome.pretrade_assessment is None
    assert outcome.admission is not None
    assert outcome.admission.assessment is None
    assert not outcome.admission.admitted
    with system.engine.connect() as connection:
        row = connection.execute(sa.select(phase5_advanced_risk_batch_admissions)).mappings().one()
    assert {
        row[column]
        for column in (
            "assessment_id",
            "assessment_sha256",
            "assignment_id",
            "assignment_sequence_number",
            "assignment_sha256",
            "policy_sha256",
            "observation_watermark_sequence",
            "watermark_evidence_id",
            "watermark_evidence_sha256",
            "assessment_mode",
            "assessment_disposition",
        )
    } == {None}


def test_post_cutover_cas_reassignment_is_bound_without_legacy_fallback(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-reassignment.sqlite")
    _cutover(system)
    prior = system.advanced.current_assignment(ACCOUNT_ID)
    assert prior is not None
    reassigned = system.advanced.assign(
        AdvancedRiskAssignmentCommand(
            account_id=ACCOUNT_ID,
            environment="paper",
            idempotency_key="assignment-0002",
            policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
            policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
            actor_id="risk-owner",
            actor_authority_sha256="c" * 64,
            actor_authenticated_at=CUTOVER_AT,
            requested_at=CUTOVER_AT,
            approval_evidence_sha256=APPROVAL_SHA256,
            expected_assignment_sequence_number=prior.sequence_number,
            expected_assignment_sha256=prior.semantic_sha256,
        ),
        system.fence,
    )
    assert reassigned.sequence_number == 2
    _rearm(system)
    _authorization_evidence(system)

    outcome = system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )

    assert outcome.assignment_id == reassigned.assignment_id
    assert outcome.assignment_sequence_number == reassigned.sequence_number
    assert (
        outcome.admission is not None
        and outcome.admission.assessment is not None
        and outcome.admission.assessment.assignment_id == reassigned.assignment_id
    )
    with pytest.raises(
        BatchRiskFactConflict,
        match="legacy batch-risk authorization is disabled",
    ):
        system.legacy.authorize(system.batch, system.target, system.fence)


def test_pretrade_reject_commits_assessments_without_phase2_or_holds(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-reject.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(
        system,
        pretrade_values={
            (
                ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS,
                "US-ETF-SPY",
            ): Decimal("26")
        },
    )
    outcome = system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )

    assert (
        outcome.pretrade_assessment is not None
        and outcome.pretrade_assessment.disposition is AdvancedRiskDisposition.REJECT
    )
    assert outcome.phase2_decision is None
    assert outcome.admission is None
    with system.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_reservations))
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_batch_admissions)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 3
        )


def test_phase2_reject_keeps_nonadmitted_advanced_sidecar_without_holds(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-phase2-reject.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    rejected = SqlAdvancedBatchRiskRepository(
        engine=system.engine,
        authority=BatchRiskAuthority(
            limits=limits(max_order_quantity=Decimal("1")),
            snapshots=_Snapshots(system.snapshot),
            evaluation_clock=system.clock,
            consumption_clock=system.clock,
        ),
        coordinator=system.coordinator,
        clock=system.clock,
        evidence_producer=system.evidence_producer,
    )

    outcome = rejected.authorize(
        system.batch,
        system.target,
        system.fence,
    )

    assert outcome.phase2_decision is not None
    assert outcome.phase2_decision.status is BatchRiskDecisionStatus.REJECTED
    assert outcome.admission is not None
    assert not outcome.admission.admitted
    assert (
        outcome.admission.assessment is not None
        and outcome.admission.assessment.disposition is AdvancedRiskDisposition.NONE
    )
    with system.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_reservations))
            == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_authorizations))
            == 0
        )


@pytest.mark.parametrize(
    ("session_loss", "expected_state"),
    (
        (Decimal("0.021"), OperationalControlState.PAUSED),
        (Decimal("0.031"), OperationalControlState.HALTED),
    ),
)
def test_runtime_trip_commits_control_and_assessments_without_phase2(
    tmp_path: Path,
    session_loss: Decimal,
    expected_state: OperationalControlState,
) -> None:
    system = _system(tmp_path / f"advanced-{expected_state.value}-trip.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(
        system,
        runtime_values={
            (
                ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO,
                ACCOUNT_ID,
            ): session_loss
        },
    )

    outcome = system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )

    assert outcome.final_control_state is expected_state
    assert outcome.phase2_decision is None
    assert outcome.admission is None
    with system.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(phase5_operational_control_heads.c.effective_state))
            == expected_state.value
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_batch_admissions)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 3
        )


def test_invalid_pretrade_evidence_rolls_back_runtime_append(tmp_path: Path) -> None:
    system = _system(tmp_path / "advanced-rollback.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system, corrupt_pretrade=True)

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="does not authenticate",
    ):
        system.atomic.authorize(
            system.batch,
            system.target,
            system.fence,
        )
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 0
        )


def test_late_admission_insert_failure_rolls_back_the_atomic_authorization(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-late-admission-failure.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    tables = (
        phase5_advanced_risk_assessments,
        phase2_batch_decisions,
        phase2_batch_reservations,
        phase2_batch_authorizations,
        phase5_advanced_risk_batch_admissions,
        phase5_advanced_risk_batch_outcomes,
        phase5_operational_control_transitions,
    )

    def row_counts() -> tuple[int, ...]:
        with system.engine.connect() as connection:
            return tuple(
                int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
                for table in tables
            )

    before = row_counts()
    with system.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER reject_phase5_advanced_risk_admission "
            "BEFORE INSERT ON phase5_advanced_risk_batch_admissions "
            "BEGIN SELECT RAISE(ABORT, 'forced admission failure'); END"
        )

    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="advanced-risk admission conflicts",
    ):
        system.atomic.authorize(
            system.batch,
            system.target,
            system.fence,
        )

    assert row_counts() == before


def test_dispatch_authentication_rejects_missing_expired_and_tampered_sidecar(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-dispatch.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    outcome = system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )
    assert outcome.phase2_decision is not None
    assert outcome.admission is not None
    with _write_transaction(system.engine) as connection:
        receipt = system.coordinator.revalidate_in_transaction(
            connection,
            system.fence,
            checked_at=EVALUATED_AT,
        )
        assert (
            authenticate_advanced_risk_admission_for_dispatch_in_transaction(
                connection,
                decision=outcome.phase2_decision,
                receipt=receipt,
                checked_at=EVALUATED_AT,
            )
            == outcome.admission
        )
    with _write_transaction(system.engine) as connection:
        receipt = system.coordinator.revalidate_in_transaction(
            connection,
            system.fence,
            checked_at=outcome.admission.expires_at,
        )
        with pytest.raises(
            AdvancedBatchRiskPersistenceError,
            match="stale, non-admitted, or no longer exact",
        ):
            authenticate_advanced_risk_admission_for_dispatch_in_transaction(
                connection,
                decision=outcome.phase2_decision,
                receipt=receipt,
                checked_at=outcome.admission.expires_at,
            )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_advanced_risk_batch_admissions).values(canonical_payload="[]")
        )
    with _write_transaction(system.engine) as connection:
        receipt = system.coordinator.revalidate_in_transaction(
            connection,
            system.fence,
            checked_at=EVALUATED_AT,
        )
        with pytest.raises(ImmutableFactConflict):
            authenticate_advanced_risk_admission_for_dispatch_in_transaction(
                connection,
                decision=outcome.phase2_decision,
                receipt=receipt,
                checked_at=EVALUATED_AT,
            )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_advanced_risk_batch_admissions).values(
                canonical_payload=outcome.admission.canonical_json
            )
        )
        connection.execute(sa.delete(phase5_advanced_risk_batch_outcomes))
        connection.execute(sa.delete(phase5_advanced_risk_batch_admissions))
    with _write_transaction(system.engine) as connection:
        receipt = system.coordinator.revalidate_in_transaction(
            connection,
            system.fence,
            checked_at=EVALUATED_AT,
        )
        with pytest.raises(
            AdvancedBatchRiskPersistenceError,
            match="requires an advanced-risk admission sidecar",
        ):
            authenticate_advanced_risk_admission_for_dispatch_in_transaction(
                connection,
                decision=outcome.phase2_decision,
                receipt=receipt,
                checked_at=EVALUATED_AT,
            )


def test_startup_integrity_authenticates_every_atomic_outcome(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-startup-integrity.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )

    with system.engine.begin() as connection:
        connection.execute(
            sa.text("CREATE TABLE alembic_version (version_num VARCHAR(64) NOT NULL PRIMARY KEY)")
        )
        connection.execute(
            sa.text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": EXPECTED_SCHEMA_REVISION},
        )
    with system.engine.connect() as connection:
        _verify_advanced_batch_risk_integrity(connection)
    verify_operational_schema(system.engine, require_phase_zero_facts=False)
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_advanced_risk_batch_outcomes).values(canonical_payload="[]")
        )
    with (
        system.engine.connect() as connection,
        pytest.raises(
            AdvancedBatchRiskPersistenceError,
            match="persisted advanced-risk outcome conflicts",
        ),
    ):
        _verify_advanced_batch_risk_integrity(connection)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="Phase 5 advanced-risk outcome integrity verification failed",
    ):
        verify_operational_schema(system.engine, require_phase_zero_facts=False)


def test_mark_in_flight_reauthenticates_atomic_outcome(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "advanced-final-dispatch-gate.sqlite")
    _cutover(system)
    _rearm(system)
    _authorization_evidence(system)
    outcome = system.atomic.authorize(
        system.batch,
        system.target,
        system.fence,
    )
    assert outcome.phase2_decision is not None
    intent = system.batch.intents[0]
    submissions = SqlSubmissionAttemptRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    request = create_broker_submission_request(
        intent=intent,
        adapter_id="phase5b-integration-broker",
        adapter_version="1.0.0",
        operation="submit_order",
        payload={
            "quantity": intent.quantity,
            "side": intent.side.value,
            "symbol": intent.symbol,
        },
    )
    pending = submissions.prepare(
        intent=intent,
        risk_decision=outcome.phase2_decision,
        fence=system.fence,
        request=request,
        prepared_at=EVALUATED_AT,
        recorded_at=EVALUATED_AT,
    )
    assert pending.state is SubmissionAttemptState.PENDING

    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_advanced_risk_batch_outcomes).values(canonical_payload="[]")
        )
    dispatch_at = EVALUATED_AT + timedelta(milliseconds=1)
    with pytest.raises(
        AdvancedBatchRiskPersistenceError,
        match="persisted advanced-risk outcome conflicts",
    ):
        submissions.mark_in_flight(
            pending.attempt_id,
            fence=system.fence,
            occurred_at=dispatch_at,
            recorded_at=dispatch_at,
        )
    persisted = submissions.get(pending.attempt_id)
    assert persisted is not None
    assert persisted.state is SubmissionAttemptState.PENDING
