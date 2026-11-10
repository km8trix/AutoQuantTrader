from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import (
    MAX_OPERATIONAL_CONTROL_BLOCKERS,
    MAX_OPERATIONAL_CONTROL_RESIDUAL_POSITIONS,
    OPERATIONAL_CONTROL_POLICY_SHA256,
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlCompletionOutcome,
    OperationalControlConflict,
    OperationalControlIncidentDisposition,
    OperationalControlRearmRejected,
    OperationalControlResidualFacts,
    OperationalControlResidualPosition,
    OperationalControlState,
    OperationalControlTransition,
    _operational_control_rearm_evidence,
    apply_operational_control_command,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
    _head_values,
    _json_list,
    _PersistedTransition,
    _position_payload,
    _transition_values,
    verify_operational_control_integrity,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)

ACCOUNT_ID = "phase5-paper-account"
BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


def _engine(path: Path, account_id: str = ACCOUNT_ID) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=account_id,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=BASE,
            )
        )
    return engine


def _actor(
    kind: OperationalControlActorKind,
    *,
    actor_id: str,
    authenticated_at: datetime | None = None,
) -> OperationalControlActor:
    return OperationalControlActor(
        actor_id=actor_id,
        kind=kind,
        authority_sha256="a" * 64,
        authenticated_at=authenticated_at,
    )


_TARGETS = {
    OperationalControlCommandKind.INITIALIZE_HALTED: OperationalControlState.HALTED,
    OperationalControlCommandKind.PAUSE: OperationalControlState.PAUSED,
    OperationalControlCommandKind.DRAIN: OperationalControlState.DRAINING,
    OperationalControlCommandKind.FLATTEN: OperationalControlState.FLATTENING,
    OperationalControlCommandKind.HALT: OperationalControlState.HALTED,
}


def _command(
    kind: OperationalControlCommandKind,
    *,
    key: str,
    instant: datetime,
    actor: OperationalControlActor | None = None,
    reason: str | None = None,
    target: OperationalControlState | None = None,
    rearm_sha256: str | None = None,
) -> OperationalControlCommand:
    selected_actor = actor
    if selected_actor is None:
        selected_actor = (
            _actor(
                OperationalControlActorKind.SYSTEM,
                actor_id="bootstrap-system",
            )
            if kind is OperationalControlCommandKind.INITIALIZE_HALTED
            else _actor(
                OperationalControlActorKind.HUMAN,
                actor_id="operator-1",
                authenticated_at=BASE,
            )
        )
    trip = kind is OperationalControlCommandKind.TRIP
    return OperationalControlCommand(
        scope_id=ACCOUNT_ID,
        idempotency_key=key,
        kind=kind,
        target_state=(
            OperationalControlState.RUNNING
            if kind is OperationalControlCommandKind.REARM
            else _TARGETS[kind]
            if target is None
            else target
        ),
        actor=selected_actor,
        reason_code=reason or f"reason-{kind.value}",
        reason_evidence_sha256="b" * 64,
        requested_at=instant,
        rearm_evidence_sha256=rearm_sha256,
        trip_rule_id="market-data-stale" if trip else None,
        trip_policy_sha256="c" * 64 if trip else None,
        trip_observation_sha256="d" * 64 if trip else None,
    )


def _repository(
    engine: Engine,
    *,
    instant: datetime = BASE,
) -> tuple[SqlOperationalControlRepository, MutableClock]:
    clock = MutableClock(instant)
    return SqlOperationalControlRepository(engine=engine, clock=clock), clock


def _initialize(
    repository: SqlOperationalControlRepository,
) -> tuple[OperationalControlCommand, OperationalControlTransition]:
    command = _command(
        OperationalControlCommandKind.INITIALIZE_HALTED,
        key="initialize-0001",
        instant=BASE,
    )
    return command, repository.apply(command)


def _seed_authenticated_rearm(
    engine: Engine,
    *,
    initial_command: OperationalControlCommand,
    initial: OperationalControlTransition,
) -> OperationalControlTransition:
    """Install a future-verifier receipt without exposing a repository bypass."""

    checked_at = BASE + timedelta(seconds=1)
    human = _actor(
        OperationalControlActorKind.HUMAN,
        actor_id="rearm-operator",
        authenticated_at=BASE,
    )
    dispositions = tuple(
        sorted(
            (
                OperationalControlIncidentDisposition(
                    event_id=event.event_id,
                    event_sha256=event.semantic_sha256,
                    resolution_code="reviewed",
                    resolution_evidence_sha256="e" * 64,
                    resolved_at=checked_at,
                )
                for event in initial.blocking_events
            ),
            key=lambda value: value.event_id,
        )
    )
    evidence = _operational_control_rearm_evidence(
        scope_id=ACCOUNT_ID,
        current_transition_id=initial.transition_id,
        current_transition_sha256=initial.semantic_sha256,
        current_state=initial.effective_state,
        current_state_epoch_id=initial.state_epoch_id,
        actor=human,
        checked_at=checked_at,
        expires_at=checked_at + timedelta(seconds=30),
        readiness_sha256="f" * 64,
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
    rearm_command = _command(
        OperationalControlCommandKind.REARM,
        key="verified-rearm-0001",
        instant=checked_at,
        actor=human,
        rearm_sha256=evidence.semantic_sha256,
    )
    rearmed = apply_operational_control_command(
        initial,
        rearm_command,
        decided_at=checked_at,
        rearm_evidence=evidence,
    )
    prior_record = _PersistedTransition(
        command=initial_command,
        transition=initial,
    )
    rearm_record = _PersistedTransition(
        command=rearm_command,
        transition=rearmed,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase5_operational_control_transitions).values(
                **_transition_values(
                    command=rearm_command,
                    transition=rearmed,
                    previous=prior_record,
                )
            )
        )
        updated = connection.execute(
            sa.update(phase5_operational_control_heads)
            .where(
                phase5_operational_control_heads.c.account_id == ACCOUNT_ID,
                phase5_operational_control_heads.c.transition_id == initial.transition_id,
                phase5_operational_control_heads.c.transition_sha256 == initial.semantic_sha256,
            )
            .values(**_head_values(rearm_record))
        )
        assert updated.rowcount == 1
    return rearmed


def _running_repository(
    engine: Engine,
) -> tuple[SqlOperationalControlRepository, MutableClock, OperationalControlTransition]:
    repository, clock = _repository(engine)
    initial_command, initial = _initialize(repository)
    running = _seed_authenticated_rearm(
        engine,
        initial_command=initial_command,
        initial=initial,
    )
    clock.instant = BASE + timedelta(seconds=2)
    assert repository.load(ACCOUNT_ID) == running
    return repository, clock, running


def _residuals(
    *,
    working: tuple[str, ...] = (),
    unknown: tuple[str, ...] = (),
    pending_cancel: tuple[str, ...] = (),
    positions: tuple[OperationalControlResidualPosition, ...] = (),
    clean: bool = True,
) -> OperationalControlResidualFacts:
    return OperationalControlResidualFacts(
        terminal_order_count=3,
        working_order_ids=working,
        unknown_order_ids=unknown,
        pending_cancel_order_ids=pending_cancel,
        positions=positions,
        reconciliation_clean=clean,
        source_evidence_sha256="9" * 64,
    )


def test_absent_load_initial_append_and_actor_scoped_historical_retry(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "control.sqlite")
    repository, clock = _repository(engine)
    assert repository.load(ACCOUNT_ID) is None

    initial_command, initial = _initialize(repository)
    clock.instant = BASE + timedelta(seconds=1)
    noop = repository.apply(
        _command(
            OperationalControlCommandKind.HALT,
            key="halt-noop-0001",
            instant=clock.instant,
        )
    )
    assert noop.sequence_number == 2
    assert repository.apply(initial_command) == initial
    assert repository.load(ACCOUNT_ID) == noop

    drift = _command(
        OperationalControlCommandKind.INITIALIZE_HALTED,
        key=initial_command.idempotency_key,
        instant=initial_command.requested_at,
        actor=initial_command.actor,
        reason="different-reason",
    )
    with pytest.raises(OperationalControlConflict, match="idempotency"):
        repository.apply(drift)

    other_actor = _actor(
        OperationalControlActorKind.HUMAN,
        actor_id="operator-2",
        authenticated_at=BASE,
    )
    clock.instant += timedelta(seconds=1)
    actor_scoped = repository.apply(
        _command(
            OperationalControlCommandKind.HALT,
            key="halt-noop-0001",
            instant=clock.instant,
            actor=other_actor,
        )
    )
    assert actor_scoped.sequence_number == 3
    assert tuple(value.sequence_number for value in repository.history(ACCOUNT_ID)) == (
        1,
        2,
        3,
    )
    verify_operational_control_integrity(engine)


def test_public_repository_rejects_rearm_without_any_write(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "rearm.sqlite")
    repository, _ = _repository(engine)
    _, initial = _initialize(repository)
    human = _actor(
        OperationalControlActorKind.HUMAN,
        actor_id="operator-rearm",
        authenticated_at=BASE,
    )
    rearm = _command(
        OperationalControlCommandKind.REARM,
        key="rearm-rejected-0001",
        instant=BASE + timedelta(seconds=1),
        actor=human,
        rearm_sha256="f" * 64,
    )
    with pytest.raises(OperationalControlRearmRejected, match="rejects REARM"):
        repository.apply(rearm)
    assert repository.history(ACCOUNT_ID) == (initial,)


def test_sqlite_account_lock_serializes_concurrent_severity_winner(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "concurrent.sqlite")
    repository, clock, _ = _running_repository(engine)
    commands = (
        _command(
            kind,
            key=f"concurrent-{kind.value}-0001",
            instant=clock.instant,
            actor=_actor(
                OperationalControlActorKind.SYSTEM,
                actor_id=f"system-{kind.value}",
            ),
        )
        for kind in (
            OperationalControlCommandKind.PAUSE,
            OperationalControlCommandKind.HALT,
        )
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(repository.apply, commands))
    assert sorted(result.sequence_number for result in results) == [3, 4]
    assert tuple(value.sequence_number for value in repository.history(ACCOUNT_ID)) == (
        1,
        2,
        3,
        4,
    )
    head = repository.load(ACCOUNT_ID)
    assert head is not None
    assert head.effective_state is OperationalControlState.HALTED


def test_drain_escalates_to_flatten_without_a_drain_completion(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "escalation.sqlite")
    repository, clock, _ = _running_repository(engine)
    drain = repository.apply(
        _command(
            OperationalControlCommandKind.DRAIN,
            key="drain-0001",
            instant=clock.instant,
        )
    )
    assert drain.active_operation is not None
    clock.instant += timedelta(seconds=1)
    flatten = repository.apply(
        _command(
            OperationalControlCommandKind.FLATTEN,
            key="flatten-escalation-0001",
            instant=clock.instant,
        )
    )
    assert flatten.effective_state is OperationalControlState.FLATTENING
    assert flatten.active_operation is not None
    assert flatten.active_operation.attempt_id != drain.active_operation.attempt_id
    verify_operational_control_integrity(engine)


def test_completion_exact_retry_and_incomplete_flatten_retry(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "completion.sqlite")
    repository, clock, _ = _running_repository(engine)
    flatten = repository.apply(
        _command(
            OperationalControlCommandKind.FLATTEN,
            key="flatten-0001",
            instant=clock.instant,
        )
    )
    assert flatten.active_operation is not None
    first_attempt_id = flatten.active_operation.attempt_id
    residuals = _residuals(
        pending_cancel=("broker-order-1",),
        positions=(
            OperationalControlResidualPosition(
                instrument_id="US-ETF-SPY",
                quantity=Decimal("2"),
                gross_exposure=Decimal("1200.50"),
            ),
        ),
        clean=False,
    )
    clock.instant += timedelta(seconds=1)
    completion = repository.record_completion(
        account_id=ACCOUNT_ID,
        idempotency_key="flatten-completion-0001",
        outcome=OperationalControlCompletionOutcome.INCOMPLETE,
        evidence_sha256="8" * 64,
        residual_facts=residuals,
        incomplete_reason="market_closed",
    )
    assert repository.load_completion(completion.completion_id) == completion
    assert repository.load_completion("missing-completion-id") is None
    clock.instant += timedelta(seconds=10)
    noop = repository.apply(
        _command(
            OperationalControlCommandKind.PAUSE,
            key="pause-after-flatten-completion",
            instant=clock.instant,
        )
    )
    assert noop.active_operation == flatten.active_operation
    clock.instant += timedelta(seconds=1)
    assert (
        repository.record_completion(
            account_id=ACCOUNT_ID,
            idempotency_key="flatten-completion-0001",
            outcome=OperationalControlCompletionOutcome.INCOMPLETE,
            evidence_sha256="8" * 64,
            residual_facts=residuals,
            incomplete_reason="market_closed",
        )
        == completion
    )
    with pytest.raises(OperationalControlConflict, match="idempotency"):
        repository.record_completion(
            account_id=ACCOUNT_ID,
            idempotency_key="flatten-completion-0001",
            outcome=OperationalControlCompletionOutcome.INCOMPLETE,
            evidence_sha256="7" * 64,
            residual_facts=residuals,
            incomplete_reason="market_closed",
        )

    retry = repository.apply(
        _command(
            OperationalControlCommandKind.FLATTEN,
            key="flatten-retry-0002",
            instant=clock.instant,
        )
    )
    assert not retry.state_changed
    assert retry.state_epoch_id == flatten.state_epoch_id
    assert retry.active_operation is not None
    assert retry.active_operation.attempt_id != first_attempt_id
    verify_operational_control_integrity(engine)


def test_strict_replay_catches_transition_and_head_corruption(tmp_path: Path) -> None:
    transition_engine = _engine(tmp_path / "transition-corrupt.sqlite")
    repository, clock = _repository(transition_engine)
    _, initial = _initialize(repository)
    clock.instant += timedelta(seconds=1)
    second = repository.apply(
        _command(
            OperationalControlCommandKind.HALT,
            key="halt-corrupt-0001",
            instant=clock.instant,
        )
    )
    with transition_engine.begin() as connection:
        connection.execute(
            sa.update(phase5_operational_control_transitions)
            .where(phase5_operational_control_transitions.c.transition_id == second.transition_id)
            .values(canonical_payload=initial.canonical_json)
        )
    with pytest.raises(OperationalControlConflict, match=r"conflicts|payload"):
        verify_operational_control_integrity(transition_engine)

    head_engine = _engine(tmp_path / "head-corrupt.sqlite")
    head_repository, _ = _repository(head_engine)
    _initialize(head_repository)
    with head_engine.begin() as connection:
        connection.execute(
            sa.update(phase5_operational_control_heads)
            .where(phase5_operational_control_heads.c.account_id == ACCOUNT_ID)
            .values(canonical_payload="{}")
        )
    with pytest.raises(OperationalControlConflict, match="conflicts"):
        head_repository.load(ACCOUNT_ID)


def test_completion_corruption_is_detected(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "completion-corrupt.sqlite")
    repository, clock, _ = _running_repository(engine)
    flatten = repository.apply(
        _command(
            OperationalControlCommandKind.FLATTEN,
            key="flatten-corrupt-0001",
            instant=clock.instant,
        )
    )
    clock.instant += timedelta(seconds=1)
    completion = repository.record_completion(
        account_id=ACCOUNT_ID,
        idempotency_key="flatten-corrupt-completion",
        outcome=OperationalControlCompletionOutcome.DEADLINE_EXCEEDED,
        evidence_sha256="6" * 64,
        residual_facts=_residuals(unknown=("client-order-1",), clean=False),
        incomplete_reason="deadline",
        deadline_at=flatten.decided_at,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase5_operational_control_completions)
            .where(
                phase5_operational_control_completions.c.completion_id == completion.completion_id
            )
            .values(canonical_payload="{}")
        )
    with pytest.raises(OperationalControlConflict, match="duplicated fields"):
        verify_operational_control_integrity(engine)


def test_maximum_blocker_projection_roundtrips_one_exact_sql_row(
    tmp_path: Path,
) -> None:
    """Exercise the declared payload bound without an O(n²) repository append loop."""

    engine = _engine(tmp_path / "maximum-blockers.sqlite")
    repository, _ = _repository(engine)
    initial_command, initial = _initialize(repository)
    command = _command(
        OperationalControlCommandKind.HALT,
        key="halt-max-blockers",
        instant=BASE + timedelta(seconds=1),
    )
    events = tuple(
        OperationalControlBlockingEvent(
            scope_id=ACCOUNT_ID,
            sequence_number=sequence,
            command_id=(
                command.command_id
                if sequence == MAX_OPERATIONAL_CONTROL_BLOCKERS
                else canonical_id("max-blocker-command", ACCOUNT_ID, sequence)
            ),
            command_sha256=(
                command.semantic_sha256
                if sequence == MAX_OPERATIONAL_CONTROL_BLOCKERS
                else f"{sequence:064x}"
            ),
            state=OperationalControlState.HALTED,
            occurred_at=BASE + timedelta(microseconds=sequence),
        )
        for sequence in range(1, MAX_OPERATIONAL_CONTROL_BLOCKERS + 1)
    )
    transition_id = canonical_id(
        "operational-control-transition",
        OPERATIONAL_CONTROL_POLICY_SHA256,
        ACCOUNT_ID,
        MAX_OPERATIONAL_CONTROL_BLOCKERS,
        command.command_id,
    )
    maximum = OperationalControlTransition(
        transition_id=transition_id,
        scope_id=ACCOUNT_ID,
        sequence_number=MAX_OPERATIONAL_CONTROL_BLOCKERS,
        previous_transition_sha256="f" * 64,
        command_id=command.command_id,
        command_sha256=command.semantic_sha256,
        prior_state=OperationalControlState.HALTED,
        effective_state=OperationalControlState.HALTED,
        state_changed=False,
        state_epoch_id=initial.state_epoch_id,
        blocking_events=events,
        blocker_overflowed=False,
        active_operation=None,
        decided_at=command.requested_at,
    )
    values = _transition_values(
        command=command,
        transition=maximum,
        previous=_PersistedTransition(
            command=initial_command,
            transition=initial,
        ),
    )
    assert len(str(values["canonical_payload"])) < 2 * 1024 * 1024
    assert len(str(values["blocking_event_ids_payload"])) < 262_144

    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        with connection.begin():
            connection.execute(sa.insert(phase5_operational_control_transitions).values(**values))
            row = (
                connection.execute(
                    sa.select(phase5_operational_control_transitions).where(
                        phase5_operational_control_transitions.c.transition_id
                        == maximum.transition_id
                    )
                )
                .mappings()
                .one()
            )
            assert row["canonical_payload"] == maximum.canonical_json
            assert row["blocking_event_count"] == MAX_OPERATIONAL_CONTROL_BLOCKERS


def test_unicode_residual_payload_caps_cover_every_domain_member() -> None:
    astral = "\U0001f4a5"
    order_ids = tuple(
        f"{index:08d}{astral * 120}" for index in range(MAX_OPERATIONAL_CONTROL_BLOCKERS)
    )
    positions = tuple(
        OperationalControlResidualPosition(
            instrument_id=f"{index:08d}{astral * 120}",
            quantity=Decimal("1"),
            gross_exposure=Decimal("1"),
        )
        for index in range(MAX_OPERATIONAL_CONTROL_RESIDUAL_POSITIONS)
    )
    residuals = OperationalControlResidualFacts(
        terminal_order_count=0,
        working_order_ids=order_ids,
        unknown_order_ids=(),
        pending_cancel_order_ids=(),
        positions=positions,
        reconciliation_clean=False,
        source_evidence_sha256="a" * 64,
    )

    order_payload = _json_list(residuals.working_order_ids)
    position_payload = _position_payload(residuals.positions)
    assert 262_144 < len(order_payload) < 4_194_304
    assert 262_144 < len(position_payload) < 2_097_152
