from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from threading import Barrier

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.domain.account_coordinator import AccountFence, AccountLeasePolicy
from packages.domain.advanced_risk import (
    AdvancedRiskEvidenceSource,
    AdvancedRiskObservationCompleteness,
)
from packages.domain.advanced_risk_assignment import (
    AdvancedRiskAssignmentCommand,
    AdvancedRiskPolicyAssignment,
)
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_POLICY,
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyAssessment,
    AdvancedRiskPolicyObservation,
    ModerateAdvancedRiskRuleId,
    assess_moderate_advanced_risk,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.advanced_risk import (
    AdvancedRiskPersistenceConflict,
    AdvancedRiskSourceSet,
    SqlAdvancedRiskRepository,
    verify_advanced_risk_integrity,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import (
    metadata,
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_assignments,
    phase5_advanced_risk_evidence,
    phase5_advanced_risk_evidence_sources,
)

ACCOUNT_ID = "phase5b-paper-account"
REQUIRED_INSTRUMENT_IDS = ("US-ETF-SPY",)
BASE = datetime(2026, 7, 28, 18, 0, tzinfo=UTC)
APPROVAL_SHA256 = "a" * 64

_INSTRUMENT_RULES = frozenset(
    {
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO,
        ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
        ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS,
    }
)


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(frozen=True, slots=True)
class _TestSystem:
    engine: Engine
    clock: MutableClock
    coordinator: SqlAccountCoordinator
    repository: SqlAdvancedRiskRepository
    fence: AccountFence


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _system(path: Path) -> _TestSystem:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    clock = MutableClock(BASE)
    coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase5b-advanced-risk-tests",
                policy_version="1",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )
    lease = coordinator.acquire("phase5b-worker")
    control = SqlOperationalControlRepository(engine=engine, clock=clock)
    control.apply(
        OperationalControlCommand(
            scope_id=ACCOUNT_ID,
            idempotency_key="initialize-0001",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=OperationalControlActor(
                actor_id="startup",
                kind=OperationalControlActorKind.SYSTEM,
                authority_sha256="b" * 64,
                authenticated_at=None,
            ),
            reason_code="startup",
            reason_evidence_sha256="c" * 64,
            requested_at=BASE,
        )
    )
    repository = SqlAdvancedRiskRepository(
        engine=engine,
        coordinator=coordinator,
        clock=clock,
    )
    return _TestSystem(
        engine=engine,
        clock=clock,
        coordinator=coordinator,
        repository=repository,
        fence=lease.fence,
    )


def _command(
    key: str,
    *,
    actor_id: str = "risk-owner",
    expected_sequence_number: int = 0,
    expected_assignment_sha256: str | None = None,
) -> AdvancedRiskAssignmentCommand:
    return AdvancedRiskAssignmentCommand(
        account_id=ACCOUNT_ID,
        environment="paper",
        idempotency_key=key,
        policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
        policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
        actor_id=actor_id,
        actor_authority_sha256=_digest(f"{actor_id}-authority"),
        actor_authenticated_at=BASE,
        requested_at=BASE,
        approval_evidence_sha256=APPROVAL_SHA256,
        expected_assignment_sequence_number=expected_sequence_number,
        expected_assignment_sha256=expected_assignment_sha256,
    )


def _register_and_assign(system: _TestSystem) -> None:
    system.repository.register_moderate_policy(
        approval_evidence_sha256=APPROVAL_SHA256,
        approved_at=BASE,
    )
    system.repository.assign(_command("assignment-0001"), system.fence)


def _pretrade_observations() -> tuple[
    tuple[AdvancedRiskPolicyObservation, ...],
    tuple[AdvancedRiskSourceSet, ...],
]:
    observations: list[AdvancedRiskPolicyObservation] = []
    source_sets: list[AdvancedRiskSourceSet] = []
    for rule in MODERATE_ADVANCED_RISK_POLICY.rules:
        if rule.pretrade_reject_threshold is None:
            continue
        subjects = REQUIRED_INSTRUMENT_IDS if rule.rule_id in _INSTRUMENT_RULES else (ACCOUNT_ID,)
        for subject_id in subjects:
            source_identity = f"{rule.rule_id.value}-{subject_id}"
            source = AdvancedRiskEvidenceSource(
                source_kind="canonical_test_fact",
                source_id=f"{source_identity}-source",
                source_sha256=_digest(f"{source_identity}-source"),
                effective_at=BASE - timedelta(minutes=1),
                available_at=BASE - timedelta(seconds=20),
            )
            source_set = AdvancedRiskSourceSet(members=(source,), source_count=1)
            observation = AdvancedRiskPolicyObservation(
                account_id=ACCOUNT_ID,
                environment="paper",
                rule_id=rule.rule_id,
                subject_id=subject_id,
                completeness=AdvancedRiskObservationCompleteness.COMPLETE,
                value=Decimal(0),
                sample_count=rule.minimum_complete_samples,
                qualifying_count=None,
                producer_authority_sha256=rule.producer_authority_sha256,
                source_authority_sha256=rule.source_authority_sha256,
                source_set_sha256=source_set.semantic_sha256,
                evidence_sha256=_digest(f"{source_identity}-evidence"),
                window_started_at=BASE - timedelta(minutes=2),
                window_ended_at=BASE - timedelta(seconds=30),
                observed_at=BASE - timedelta(seconds=10),
                recorded_at=BASE,
            )
            observations.append(observation)
            source_sets.append(source_set)
    ordered = tuple(sorted(observations, key=lambda item: (item.rule_id.value, item.subject_id)))
    source_by_observation = {
        observation.observation_id: source_set
        for observation, source_set in zip(observations, source_sets, strict=True)
    }
    return ordered, tuple(
        source_by_observation[observation.observation_id] for observation in ordered
    )


def _assessment(
    observations: tuple[AdvancedRiskPolicyObservation, ...],
    *,
    assessed_at: datetime,
) -> AdvancedRiskPolicyAssessment:
    return assess_moderate_advanced_risk(
        observations,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        required_instrument_ids=REQUIRED_INSTRUMENT_IDS,
        assessed_at=assessed_at,
    )


def test_policy_registration_assignment_retry_and_concurrent_gap_free_chain(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "assignment.sqlite")
    first_registration = system.repository.register_moderate_policy(
        approval_evidence_sha256=APPROVAL_SHA256,
        approved_at=BASE,
    )
    assert (
        system.repository.register_moderate_policy(
            approval_evidence_sha256=APPROVAL_SHA256,
            approved_at=BASE,
        )
        == first_registration
    )
    with pytest.raises(
        AdvancedRiskPersistenceConflict,
        match="registration conflicts",
    ):
        system.repository.register_moderate_policy(
            approval_evidence_sha256="d" * 64,
            approved_at=BASE,
        )

    shared_command = _command("assignment-0001")
    barrier = Barrier(2)

    def assign_retry(_: int) -> object:
        barrier.wait(timeout=10)
        return system.repository.assign(shared_command, system.fence)

    with ThreadPoolExecutor(max_workers=2) as executor:
        retries = tuple(executor.map(assign_retry, range(2)))
    assert retries[0] == retries[1]
    first_assignment = retries[0]
    assert isinstance(first_assignment, AdvancedRiskPolicyAssignment)

    commands = (
        _command(
            "assignment-0002",
            actor_id="risk-owner-2",
            expected_sequence_number=first_assignment.sequence_number,
            expected_assignment_sha256=first_assignment.semantic_sha256,
        ),
        _command(
            "assignment-0003",
            actor_id="risk-owner-3",
            expected_sequence_number=first_assignment.sequence_number,
            expected_assignment_sha256=first_assignment.semantic_sha256,
        ),
    )
    barrier = Barrier(2)

    def assign_distinct(
        command: AdvancedRiskAssignmentCommand,
    ) -> tuple[str, AdvancedRiskAssignmentCommand, object | None]:
        barrier.wait(timeout=10)
        try:
            return (
                "appended",
                command,
                system.repository.assign(command, system.fence),
            )
        except AdvancedRiskPersistenceConflict:
            return ("stale", command, None)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(assign_distinct, commands))
    assert tuple(sorted(result[0] for result in results)) == ("appended", "stale")
    winner = next(result for result in results if result[0] == "appended")
    assert system.repository.assign(winner[1], system.fence) == winner[2]
    assert system.repository.assign(shared_command, system.fence) == first_assignment

    history = system.repository.assignment_history(ACCOUNT_ID)
    assert tuple(item.sequence_number for item in history) == (1, 2)
    assert system.repository.current_assignment(ACCOUNT_ID) == history[-1]
    assert system.repository.load_assignment(history[0].assignment_id) == history[0]
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assignments)
            )
            == 2
        )
    verify_advanced_risk_integrity(system.engine)


def test_full_coverage_assessment_is_atomic_idempotent_and_strictly_loaded(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "assessment.sqlite")
    _register_and_assign(system)
    assessed_at = BASE + timedelta(seconds=1)
    valid_through = BASE + timedelta(seconds=30)
    observations, source_sets = _pretrade_observations()
    assessment = _assessment(observations, assessed_at=assessed_at)
    system.clock.instant = assessed_at

    retained = system.repository.record_assessment(
        assessment,
        observations=observations,
        source_sets=source_sets,
        required_instrument_ids=REQUIRED_INSTRUMENT_IDS,
        fence=system.fence,
        valid_through=valid_through,
    )
    assert retained == assessment
    assert system.repository.load_assessment(assessment.assessment_id) == assessment
    assert system.repository.assessment_history(ACCOUNT_ID) == (assessment,)
    assert (
        system.repository.record_assessment(
            assessment,
            observations=observations,
            source_sets=source_sets,
            required_instrument_ids=REQUIRED_INSTRUMENT_IDS,
            fence=system.fence,
            valid_through=valid_through,
        )
        == assessment
    )
    with pytest.raises(
        AdvancedRiskPersistenceConflict,
        match="identity conflicts",
    ):
        system.repository.record_assessment(
            assessment,
            observations=observations,
            source_sets=source_sets,
            required_instrument_ids=REQUIRED_INSTRUMENT_IDS,
            fence=system.fence,
            valid_through=valid_through + timedelta(seconds=1),
        )
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 1
        )
        assert connection.scalar(
            sa.select(sa.func.count()).select_from(phase5_advanced_risk_evidence)
        ) == len(observations)
        assert connection.scalar(
            sa.select(sa.func.count()).select_from(phase5_advanced_risk_evidence_sources)
        ) == len(observations)
    system.repository.verify_integrity()


def test_claimed_source_set_digest_must_authenticate_members_before_insert(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "source-set-mismatch.sqlite")
    _register_and_assign(system)
    assessed_at = BASE + timedelta(seconds=1)
    observations, source_sets = _pretrade_observations()
    mismatched = list(observations)
    mismatched[0] = replace(mismatched[0], source_set_sha256="f" * 64)
    mismatched_observations = tuple(mismatched)
    assessment = _assessment(mismatched_observations, assessed_at=assessed_at)
    system.clock.instant = assessed_at

    with pytest.raises(
        AdvancedRiskPersistenceConflict,
        match="does not authenticate",
    ):
        system.repository.record_assessment(
            assessment,
            observations=mismatched_observations,
            source_sets=source_sets,
            required_instrument_ids=REQUIRED_INSTRUMENT_IDS,
            fence=system.fence,
            valid_through=BASE + timedelta(seconds=30),
        )

    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_assessments)
            )
            == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase5_advanced_risk_evidence))
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_advanced_risk_evidence_sources)
            )
            == 0
        )


def test_tampered_source_member_fails_all_strict_read_paths(tmp_path: Path) -> None:
    system = _system(tmp_path / "tamper.sqlite")
    _register_and_assign(system)
    assessed_at = BASE + timedelta(seconds=1)
    observations, source_sets = _pretrade_observations()
    assessment = _assessment(observations, assessed_at=assessed_at)
    system.clock.instant = assessed_at
    system.repository.record_assessment(
        assessment,
        observations=observations,
        source_sets=source_sets,
        required_instrument_ids=REQUIRED_INSTRUMENT_IDS,
        fence=system.fence,
        valid_through=BASE + timedelta(seconds=30),
    )
    with system.engine.begin() as connection:
        connection.execute(
            sa.update(phase5_advanced_risk_evidence_sources)
            .where(
                phase5_advanced_risk_evidence_sources.c.evidence_id
                == observations[0].observation_id
            )
            .values(source_sha256="f" * 64)
        )

    with pytest.raises(
        AdvancedRiskPersistenceConflict,
        match="persisted advanced-risk fact",
    ):
        system.repository.load_assessment(assessment.assessment_id)
    with pytest.raises(AdvancedRiskPersistenceConflict):
        system.repository.assessment_history(ACCOUNT_ID)
    with pytest.raises(AdvancedRiskPersistenceConflict):
        verify_advanced_risk_integrity(system.engine)
