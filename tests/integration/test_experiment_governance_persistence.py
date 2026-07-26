from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine

from packages.domain.experiment_governance import (
    ExperimentAttemptStatus,
    ExperimentGovernanceFamily,
    ExperimentGovernanceSnapshot,
    ExperimentSegmentEvidence,
    GovernedSegmentEvaluationReceipt,
    NonExecutableTerminalEvidence,
)
from packages.domain.experiment_governance import (
    TestSegmentCommitment as HoldoutCommitment,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.feature_target import CertifiedFeatureTargetReplay
from packages.persistence.backtest_workflow import SqlBacktestWorkflow
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    _repeatable_read_transaction,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.experiment_governance import (
    ExperimentGovernanceConflict,
    ExperimentGovernanceError,
    SqlExperimentGovernance,
)
from packages.persistence.schema import (
    phase2_backtest_jobs,
    phase3_experiment_attempt_events,
    phase3_experiment_attempts,
    phase3_experiment_audit_events,
    phase3_experiment_tape_claims,
    phase3_experiment_tape_policies,
    phase3_holdout_reveals,
)
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _fixture,
    _request,
    _scoped_certification,
    _segment,
    _target_certification,
)

ROOT = Path(__file__).resolve().parents[2]


def _migrated_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/experiment-governance.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def _registered_repository(
    tmp_path: Path,
    fixture: GovernanceFixture,
) -> tuple[Engine, SqlExperimentGovernance, ExperimentGovernanceSnapshot]:
    engine = _migrated_engine(tmp_path)
    SqlBacktestWorkflow(engine).register_strategy(
        version=fixture.family.strategy_version,
        configuration=fixture.configuration,
        display_name=fixture.family.family_name,
        parameter_schema_payload=fixture.schema_payload,
    )
    repository = SqlExperimentGovernance(engine)
    initial = repository.register_family(
        fixture.family,
        actor_id=fixture.family.owner_id,
        idempotency_key="register-phase3c-family",
        registered_at=fixture.family.created_at,
    )
    return engine, repository, initial


def _persist_attempt(
    repository: SqlExperimentGovernance,
    previous: ExperimentGovernanceSnapshot,
    proposed: ExperimentGovernanceSnapshot,
    *,
    key: str,
) -> ExperimentGovernanceSnapshot:
    attempt = proposed.attempts[-1]
    return repository.record_attempt(
        proposed,
        expected_registry_sha256=previous.semantic_sha256,
        actor_id=attempt.requested_by,
        idempotency_key=key,
        occurred_at=attempt.requested_at,
    )


def test_postgresql_repeatable_read_is_configured_before_transaction_begin() -> None:
    engine = MagicMock(spec=Engine)
    connection = MagicMock()
    connection.dialect.name = "postgresql"
    engine.connect.return_value.__enter__.return_value = connection
    calls: list[object] = []

    def configure(**options: object) -> Connection:
        calls.append(("execution_options", options))
        return connection

    connection.execution_options.side_effect = configure
    connection.begin.side_effect = lambda: calls.append("begin")
    connection.rollback.side_effect = lambda: calls.append("rollback")

    with _repeatable_read_transaction(engine) as yielded:
        assert yielded is connection

    assert calls == [
        ("execution_options", {"isolation_level": "REPEATABLE READ"}),
        "begin",
        "rollback",
    ]


def test_governance_reads_and_readiness_use_one_explicit_sqlite_snapshot(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    statements: list[str] = []

    def capture_statement(
        _connection: Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(statement.strip().upper())

    sa.event.listen(engine, "before_cursor_execute", capture_statement)
    try:
        statements.clear()
        assert repository.get(initial.family_id) == initial
        assert statements[0] == "BEGIN"

        statements.clear()
        assert repository.families() == (initial,)
        assert statements[0] == "BEGIN"

        statements.clear()
        verify_operational_schema(engine, require_phase_zero_facts=False)
        assert statements[0] == "BEGIN"
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture_statement)


def test_family_registration_retry_requires_the_same_normalized_time(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    equivalent_time = fixture.family.created_at.astimezone(timezone(timedelta(hours=-5)))

    assert (
        repository.register_family(
            fixture.family,
            actor_id=fixture.family.owner_id,
            idempotency_key="register-phase3c-family",
            registered_at=equivalent_time,
        )
        == initial
    )
    with pytest.raises(ExperimentGovernanceConflict, match="different experiment command"):
        repository.register_family(
            fixture.family,
            actor_id=fixture.family.owner_id,
            idempotency_key="register-phase3c-family",
            registered_at=equivalent_time + timedelta(microseconds=1),
        )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_audit_events)
            )
            == 1
        )


def _persist_transition(
    repository: SqlExperimentGovernance,
    previous: ExperimentGovernanceSnapshot,
    proposed: ExperimentGovernanceSnapshot,
    *,
    key: str,
    certification: CertifiedFeatureTargetReplay | None = None,
) -> ExperimentGovernanceSnapshot:
    event = proposed.lifecycle_events[-1]
    return repository.transition_attempt(
        proposed,
        expected_registry_sha256=previous.semantic_sha256,
        actor_id=event.actor_id,
        idempotency_key=key,
        occurred_at=event.occurred_at,
        certification=certification,
    )


def _complete_latest(
    repository: SqlExperimentGovernance,
    snapshot: ExperimentGovernanceSnapshot,
    fixture: GovernanceFixture,
    *,
    prefix: str,
) -> ExperimentGovernanceSnapshot:
    attempt = snapshot.attempts[-1]
    started_at = snapshot.lifecycle_events[-1].occurred_at + timedelta(minutes=1)
    running = _start_latest(
        repository,
        snapshot,
        prefix=prefix,
        started_at=started_at,
    )
    feature_certification = {
        EvaluationSegmentKind.TRAIN: fixture.train_certification,
        EvaluationSegmentKind.VALIDATION: fixture.validation_certification,
        EvaluationSegmentKind.TEST: fixture.test_certification,
    }[attempt.segment_kind]
    certification = _target_certification(feature_certification, attempt.configuration)
    completed = running.complete_attempt(
        attempt.attempt_id,
        certification,
        completed_at=started_at + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    return _persist_transition(
        repository,
        running,
        completed,
        key=f"{prefix}-completed",
        certification=certification,
    )


def _start_latest(
    repository: SqlExperimentGovernance,
    snapshot: ExperimentGovernanceSnapshot,
    *,
    prefix: str,
    started_at: datetime,
    worker_id: str = "phase3c-worker",
) -> ExperimentGovernanceSnapshot:
    attempt = snapshot.attempts[-1]
    running = snapshot.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=started_at,
        actor_id=worker_id,
    )
    return _persist_transition(
        repository,
        snapshot,
        running,
        key=f"{prefix}-running",
    )


def _family_with_distinct_test_tape(
    fixture: GovernanceFixture,
    *,
    family_name: str,
    start_index: int,
    created_offset: timedelta,
) -> ExperimentGovernanceFamily:
    certification = _scoped_certification(start_index)
    test_segment = _segment(EvaluationSegmentKind.TEST, certification)
    return replace(
        fixture.family,
        family_name=family_name,
        created_at=fixture.family.created_at + created_offset,
        segments=(*fixture.family.segments[:2], test_segment),
        test_commitment=HoldoutCommitment.from_certification(
            test_segment,
            certification,
        ),
    )


def _family_whose_train_is_original_test(
    fixture: GovernanceFixture,
) -> ExperimentGovernanceFamily:
    train_certification = fixture.test_certification
    validation_certification = _scoped_certification(30)
    test_certification = _scoped_certification(40)
    train = _segment(EvaluationSegmentKind.TRAIN, train_certification)
    validation = _segment(EvaluationSegmentKind.VALIDATION, validation_certification)
    test = _segment(EvaluationSegmentKind.TEST, test_certification)
    return replace(
        fixture.family,
        family_name="phase3c-cross-role-family",
        created_at=fixture.family.created_at + timedelta(minutes=1),
        segments=(train, validation, test),
        train_evidence=ExperimentSegmentEvidence.from_certification(
            train,
            train_certification,
        ),
        validation_evidence=ExperimentSegmentEvidence.from_certification(
            validation,
            validation_certification,
        ),
        test_commitment=HoldoutCommitment.from_certification(
            test,
            test_certification,
        ),
    )


def test_full_reveal_and_final_test_history_round_trips_without_phase2_jobs(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    validation_queued = _request(
        initial,
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )
    validation_queued = _persist_attempt(
        repository,
        initial,
        validation_queued,
        key="validation-attempt",
    )
    validation_completed = _complete_latest(
        repository,
        validation_queued,
        fixture,
        prefix="validation",
    )
    authorization = validation_completed.create_holdout_authorization(
        selected_configuration_sha256=fixture.configuration.semantic_sha256,
        authorized_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
        authorized_by="holdout-custodian",
        access_reason="Run the single selected final confirmation.",
    )
    revealed = validation_completed.reveal_holdout(
        authorization,
        fixture.test_certification,
    )
    reveal = revealed.holdout_reveal
    assert reveal is not None
    revealed = repository.reveal_holdout(
        revealed,
        expected_registry_sha256=validation_completed.semantic_sha256,
        actor_id=reveal.revealed_by,
        idempotency_key="reveal-final-holdout",
        occurred_at=reveal.revealed_at,
    )
    test_queued = _request(
        revealed,
        fixture,
        kind=EvaluationSegmentKind.TEST,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
    )
    test_queued = _persist_attempt(
        repository,
        revealed,
        test_queued,
        key="final-test-attempt",
    )
    completed = _complete_latest(repository, test_queued, fixture, prefix="final-test")

    assert repository.get(fixture.family.family_id) == completed
    assert repository.families() == (completed,)
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(phase2_backtest_jobs)) == 0
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_experiment_attempts))
            == 2
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_attempt_events)
            )
            == 6
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_holdout_reveals)) == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_audit_events)
            )
            == 8
        )
    verify_operational_schema(engine, require_phase_zero_facts=False)

    historical_retry = repository.record_attempt(
        validation_queued,
        expected_registry_sha256=initial.semantic_sha256,
        actor_id=validation_queued.attempts[-1].requested_by,
        idempotency_key="validation-attempt",
        occurred_at=FIRST_ATTEMPT_AT.astimezone(timezone(timedelta(hours=-5))),
    )
    assert historical_retry == validation_queued
    assert historical_retry != completed
    with pytest.raises(ExperimentGovernanceConflict, match="different experiment command"):
        repository.record_attempt(
            validation_queued,
            expected_registry_sha256=initial.semantic_sha256,
            actor_id=validation_queued.attempts[-1].requested_by,
            idempotency_key="validation-attempt",
            occurred_at=FIRST_ATTEMPT_AT + timedelta(microseconds=1),
        )


def test_governed_evaluation_receipt_round_trips_and_retries_exactly(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _persist_attempt(
        repository,
        initial,
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.VALIDATION,
            requested_at=FIRST_ATTEMPT_AT,
        ),
        key="receipt-roundtrip-attempt",
    )
    started_at = FIRST_ATTEMPT_AT + timedelta(minutes=1)
    running = _start_latest(
        repository,
        queued,
        prefix="receipt-roundtrip",
        started_at=started_at,
        worker_id="phase3d-worker-a",
    )
    attempt = running.attempts[-1]
    certification = _target_certification(
        fixture.validation_certification,
        attempt.configuration,
    )
    completed = running.complete_attempt(
        attempt.attempt_id,
        certification,
        completed_at=started_at + timedelta(minutes=1),
        actor_id="phase3d-worker-a",
    )
    receipt = completed.lifecycle_events[-1].terminal_evidence
    assert type(receipt) is GovernedSegmentEvaluationReceipt
    completed = _persist_transition(
        repository,
        running,
        completed,
        key="receipt-roundtrip-completed",
        certification=certification,
    )

    reconstructed = repository.get(initial.family_id)
    terminal = reconstructed.lifecycle_events[-1].terminal_evidence
    assert reconstructed == completed
    assert type(terminal) is GovernedSegmentEvaluationReceipt
    assert terminal == receipt
    with engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(phase3_experiment_attempt_events).where(
                    phase3_experiment_attempt_events.c.event_sha256
                    == completed.lifecycle_events[-1].semantic_sha256
                )
            )
            .mappings()
            .one()
        )
    assert row["terminal_evidence_sha256"] == receipt.semantic_sha256
    assert '"$type":"GovernedSegmentEvaluationReceipt"' in row["terminal_evidence_payload"]

    later = _persist_attempt(
        repository,
        completed,
        _request(
            completed,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=receipt.completed_at + timedelta(minutes=1),
        ),
        key="receipt-roundtrip-later-attempt",
    )
    exact_retry = repository.transition_attempt(
        completed,
        expected_registry_sha256=running.semantic_sha256,
        actor_id=receipt.evaluated_by,
        idempotency_key="receipt-roundtrip-completed",
        occurred_at=receipt.completed_at,
        certification=certification,
    )
    assert exact_retry == completed
    assert repository.get(initial.family_id) == later

    with pytest.raises(
        ExperimentGovernanceConflict,
        match="different experiment command",
    ):
        repository.transition_attempt(
            completed,
            expected_registry_sha256=running.semantic_sha256,
            actor_id=receipt.evaluated_by,
            idempotency_key="receipt-roundtrip-completed",
            occurred_at=receipt.completed_at + timedelta(microseconds=1),
            certification=certification,
        )
    with pytest.raises(
        ExperimentGovernanceConflict,
        match="requires exact target certification",
    ):
        repository.transition_attempt(
            completed,
            expected_registry_sha256=running.semantic_sha256,
            actor_id=receipt.evaluated_by,
            idempotency_key="receipt-roundtrip-completed",
            occurred_at=receipt.completed_at,
        )
    with pytest.raises(
        ExperimentGovernanceConflict,
        match="does not match its exact target certification",
    ):
        repository.transition_attempt(
            completed,
            expected_registry_sha256=running.semantic_sha256,
            actor_id=receipt.evaluated_by,
            idempotency_key="receipt-roundtrip-completed",
            occurred_at=receipt.completed_at,
            certification=_target_certification(
                fixture.train_certification,
                attempt.configuration,
            ),
        )

    failed_evidence = NonExecutableTerminalEvidence.unsuccessful(
        attempt,
        status=ExperimentAttemptStatus.FAILED,
        reason_code="bounded_evaluation_failure",
        detail="A changed terminal command must not reuse completion idempotency.",
    )
    failed = running.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.FAILED,
        occurred_at=receipt.completed_at + timedelta(seconds=1),
        actor_id=receipt.evaluated_by,
        terminal_evidence=failed_evidence,
    )
    with pytest.raises(
        ExperimentGovernanceConflict,
        match="different experiment command",
    ):
        repository.transition_attempt(
            failed,
            expected_registry_sha256=running.semantic_sha256,
            actor_id=receipt.evaluated_by,
            idempotency_key="receipt-roundtrip-completed",
            occurred_at=failed.lifecycle_events[-1].occurred_at,
        )


def test_completion_persistence_requires_exact_transient_certification(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    _, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _persist_attempt(
        repository,
        initial,
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.VALIDATION,
            requested_at=FIRST_ATTEMPT_AT,
        ),
        key="certification-bound-attempt",
    )
    attempt = queued.attempts[-1]
    certification = _target_certification(
        fixture.validation_certification,
        attempt.configuration,
    )
    started_at = FIRST_ATTEMPT_AT + timedelta(minutes=1)
    proposed_running = queued.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=started_at,
        actor_id="phase3d-worker-a",
    )
    with pytest.raises(
        ExperimentGovernanceConflict,
        match="non-completed attempt transition",
    ):
        repository.transition_attempt(
            proposed_running,
            expected_registry_sha256=queued.semantic_sha256,
            actor_id="phase3d-worker-a",
            idempotency_key="certification-on-running",
            occurred_at=started_at,
            certification=certification,
        )
    running = _persist_transition(
        repository,
        queued,
        proposed_running,
        key="certification-bound-running",
    )
    completed_at = started_at + timedelta(minutes=1)
    completed = running.complete_attempt(
        attempt.attempt_id,
        certification,
        completed_at=completed_at,
        actor_id="phase3d-worker-a",
    )

    with pytest.raises(
        ExperimentGovernanceConflict,
        match="requires exact target certification",
    ):
        repository.transition_attempt(
            completed,
            expected_registry_sha256=running.semantic_sha256,
            actor_id="phase3d-worker-a",
            idempotency_key="completion-without-certification",
            occurred_at=completed_at,
        )

    receipt = completed.lifecycle_events[-1].terminal_evidence
    assert type(receipt) is GovernedSegmentEvaluationReceipt
    restore = cast(Any, GovernedSegmentEvaluationReceipt._restore)
    forged_fields = (
        "target_runtime_pin_sha256",
        "target_certification_sha256",
        "batch_result_sha256",
        "incremental_result_sha256",
        "target_parity_receipt_sha256",
        "target_transcript_sha256",
        "step_count",
        "target_count",
    )
    for index, field_name in enumerate(forged_fields):
        values = {
            field.name: getattr(receipt, field.name)
            for field in fields(receipt)
            if field.name not in {"evidence_kind", "receipt_sha256"}
        }
        current_value = values[field_name]
        if field_name == "step_count":
            values[field_name] = cast(int, current_value) + 1
        elif field_name == "target_count":
            values[field_name] = 0 if current_value != 0 else 1
        else:
            values[field_name] = "f" * 64 if current_value != "f" * 64 else "e" * 64
        forged_receipt = restore(**values)
        forged_event = replace(
            completed.lifecycle_events[-1],
            terminal_evidence=forged_receipt,
        )
        forged = replace(
            completed,
            lifecycle_events=(*completed.lifecycle_events[:-1], forged_event),
        )
        with pytest.raises(
            ExperimentGovernanceConflict,
            match="does not match its exact target certification",
        ):
            repository.transition_attempt(
                forged,
                expected_registry_sha256=running.semantic_sha256,
                actor_id="phase3d-worker-a",
                idempotency_key=f"forged-completion-{index}",
                occurred_at=completed_at,
                certification=certification,
            )
        assert repository.get(initial.family_id) == running

    persisted = repository.transition_attempt(
        completed,
        expected_registry_sha256=running.semantic_sha256,
        actor_id="phase3d-worker-a",
        idempotency_key="certification-bound-completed",
        occurred_at=completed_at,
        certification=certification,
    )
    assert persisted == completed


def test_governed_completion_retains_the_recorded_running_actor_identifier(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    _, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _persist_attempt(
        repository,
        initial,
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT,
        ),
        key="worker-continuity-attempt",
    )
    running = _start_latest(
        repository,
        queued,
        prefix="worker-continuity",
        started_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        worker_id="phase3d-worker-a",
    )
    attempt = running.attempts[-1]
    certification = _target_certification(
        fixture.train_certification,
        attempt.configuration,
    )

    with pytest.raises(
        ValueError,
        match="recorded running actor identifier",
    ):
        running.complete_attempt(
            attempt.attempt_id,
            certification,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id="phase3d-worker-b",
        )
    assert repository.get(initial.family_id) == running


def test_family_lock_allows_one_terminal_result_for_a_running_evaluation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _persist_attempt(
        repository,
        initial,
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT,
        ),
        key="terminal-race-attempt",
    )
    running = _start_latest(
        repository,
        queued,
        prefix="terminal-race",
        started_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        worker_id="phase3d-worker-a",
    )
    attempt = running.attempts[-1]
    completed_at = FIRST_ATTEMPT_AT + timedelta(minutes=2)
    certification = _target_certification(
        fixture.train_certification,
        attempt.configuration,
    )
    completed = running.complete_attempt(
        attempt.attempt_id,
        certification,
        completed_at=completed_at,
        actor_id="phase3d-worker-a",
    )
    failed_evidence = NonExecutableTerminalEvidence.unsuccessful(
        attempt,
        status=ExperimentAttemptStatus.FAILED,
        reason_code="bounded_evaluation_failure",
        detail="Only one terminal result may extend the running attempt.",
    )
    failed = running.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.FAILED,
        occurred_at=completed_at + timedelta(microseconds=1),
        actor_id="phase3d-worker-a",
        terminal_evidence=failed_evidence,
    )
    candidates = (completed, failed)

    def submit(index: int) -> ExperimentGovernanceSnapshot | ExperimentGovernanceConflict:
        candidate = candidates[index]
        event = candidate.lifecycle_events[-1]
        try:
            return repository.transition_attempt(
                candidate,
                expected_registry_sha256=running.semantic_sha256,
                actor_id=event.actor_id,
                idempotency_key=f"terminal-race-result-{index}",
                occurred_at=event.occurred_at,
                certification=certification if index == 0 else None,
            )
        except ExperimentGovernanceConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(submit, range(2)))

    winners = tuple(result for result in results if type(result) is ExperimentGovernanceSnapshot)
    conflicts = tuple(result for result in results if type(result) is ExperimentGovernanceConflict)
    assert len(winners) == len(conflicts) == 1
    assert repository.get(initial.family_id) == winners[0]
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_attempt_events)
            )
            == 3
        )


@pytest.mark.parametrize(
    "corruption",
    ["evidence-kind", "receipt-digest", "terminal-digest-column"],
)
def test_governed_evaluation_receipt_corruption_breaks_reads_and_readiness(
    tmp_path: Path,
    corruption: str,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _persist_attempt(
        repository,
        initial,
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.VALIDATION,
            requested_at=FIRST_ATTEMPT_AT,
        ),
        key="corrupt-receipt-attempt",
    )
    completed = _complete_latest(
        repository,
        queued,
        fixture,
        prefix="corrupt-receipt",
    )
    event = completed.lifecycle_events[-1]

    with engine.begin() as connection:
        row = (
            connection.execute(
                sa.select(phase3_experiment_attempt_events).where(
                    phase3_experiment_attempt_events.c.event_sha256 == event.semantic_sha256
                )
            )
            .mappings()
            .one()
        )
        if corruption == "terminal-digest-column":
            connection.execute(
                sa.update(phase3_experiment_attempt_events)
                .where(phase3_experiment_attempt_events.c.event_sha256 == event.semantic_sha256)
                .values(terminal_evidence_sha256="f" * 64)
            )
        else:
            canonical = json.loads(row["canonical_payload"])
            terminal_payload = json.loads(row["terminal_evidence_payload"])
            canonical_receipt_fields = canonical["fields"]["terminal_evidence"]["fields"]
            terminal_receipt_fields = terminal_payload["fields"]
            if corruption == "evidence-kind":
                canonical_receipt_fields["evidence_kind"] = "unsupported_evaluation"
                terminal_receipt_fields["evidence_kind"] = "unsupported_evaluation"
            else:
                canonical_receipt_fields["receipt_sha256"] = "f" * 64
                terminal_receipt_fields["receipt_sha256"] = "f" * 64
            connection.execute(
                sa.update(phase3_experiment_attempt_events)
                .where(phase3_experiment_attempt_events.c.event_sha256 == event.semantic_sha256)
                .values(
                    canonical_payload=json.dumps(
                        canonical,
                        ensure_ascii=True,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    terminal_evidence_payload=json.dumps(
                        terminal_payload,
                        ensure_ascii=True,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
            )

    with pytest.raises(ExperimentGovernanceError):
        repository.get(initial.family_id)
    with pytest.raises(DatabaseSchemaNotReady, match="Phase 3"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_compare_and_swap_idempotency_and_audit_identity_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    _, repository, initial = _registered_repository(tmp_path, fixture)
    first = _request(
        initial,
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=FIRST_ATTEMPT_AT,
    )

    with pytest.raises(ExperimentGovernanceConflict, match="actor/time"):
        repository.record_attempt(
            first,
            expected_registry_sha256=initial.semantic_sha256,
            actor_id="forged-actor",
            idempotency_key="forged-attempt-actor",
            occurred_at=FIRST_ATTEMPT_AT,
        )
    with pytest.raises(ExperimentGovernanceConflict, match="actor/time"):
        repository.record_attempt(
            first,
            expected_registry_sha256=initial.semantic_sha256,
            actor_id=first.attempts[-1].requested_by,
            idempotency_key="forged-attempt-time",
            occurred_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
        )
    assert repository.get(initial.family_id) == initial

    persisted = _persist_attempt(repository, initial, first, key="first-cas-attempt")
    changed = _request(
        initial,
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
    )
    with pytest.raises(ExperimentGovernanceConflict, match="head changed"):
        _persist_attempt(repository, initial, changed, key="stale-cas-attempt")
    with pytest.raises(ExperimentGovernanceConflict, match="different experiment command"):
        repository.record_attempt(
            first,
            expected_registry_sha256=persisted.semantic_sha256,
            actor_id=first.attempts[-1].requested_by,
            idempotency_key="first-cas-attempt",
            occurred_at=FIRST_ATTEMPT_AT,
        )
    assert repository.get(initial.family_id) == persisted


def test_family_lock_allows_exactly_one_concurrent_compare_and_swap(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    candidates = (
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT,
        ),
        _request(
            initial,
            fixture,
            kind=EvaluationSegmentKind.VALIDATION,
            requested_at=FIRST_ATTEMPT_AT + timedelta(seconds=1),
        ),
    )

    def submit(index: int) -> ExperimentGovernanceSnapshot | ExperimentGovernanceConflict:
        candidate = candidates[index]
        try:
            return repository.record_attempt(
                candidate,
                expected_registry_sha256=initial.semantic_sha256,
                actor_id=candidate.attempts[-1].requested_by,
                idempotency_key=f"concurrent-cas-attempt-{index}",
                occurred_at=candidate.attempts[-1].requested_at,
            )
        except ExperimentGovernanceConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(submit, range(2)))

    winners = tuple(result for result in results if type(result) is ExperimentGovernanceSnapshot)
    conflicts = tuple(result for result in results if type(result) is ExperimentGovernanceConflict)
    assert len(winners) == len(conflicts) == 1
    assert repository.get(initial.family_id) == winners[0]
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_experiment_attempts))
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_attempt_events)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_audit_events)
            )
            == 2
        )


def test_holdout_tape_content_commitment_is_globally_one_use(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    _, repository, initial = _registered_repository(tmp_path, fixture)
    changed_test = replace(
        fixture.family.segments[-1],
        purge_before=timedelta(minutes=1),
    )
    changed_commitment = HoldoutCommitment.from_certification(
        changed_test,
        fixture.test_certification,
    )
    changed_family = replace(
        fixture.family,
        family_name="same-holdout-new-wrapper",
        segments=(*fixture.family.segments[:2], changed_test),
        test_commitment=changed_commitment,
    )

    assert changed_family.family_id != initial.family_id
    assert changed_commitment.semantic_sha256 != (fixture.family.test_commitment.semantic_sha256)
    assert changed_commitment.content_commitment_sha256 == (
        fixture.family.test_commitment.content_commitment_sha256
    )
    with pytest.raises(ExperimentGovernanceConflict):
        repository.register_family(
            changed_family,
            actor_id=changed_family.owner_id,
            idempotency_key="reuse-holdout-content",
            registered_at=changed_family.created_at,
        )
    assert repository.families() == (initial,)


@pytest.mark.parametrize(
    "holdout_registered_first",
    [True, False],
    ids=["holdout-then-exploratory", "exploratory-then-holdout"],
)
def test_source_tape_cannot_cross_the_exploratory_holdout_boundary(
    tmp_path: Path,
    holdout_registered_first: bool,
) -> None:
    fixture = _fixture()
    original = fixture.family
    exploratory = _family_whose_train_is_original_test(fixture)
    assert exploratory.train_evidence.source_tape_sha256 == (
        original.test_commitment.source_tape_sha256
    )
    first, conflicting = (
        (original, exploratory) if holdout_registered_first else (exploratory, original)
    )
    engine = _migrated_engine(tmp_path)
    SqlBacktestWorkflow(engine).register_strategy(
        version=fixture.family.strategy_version,
        configuration=fixture.configuration,
        display_name=fixture.family.family_name,
        parameter_schema_payload=fixture.schema_payload,
    )
    repository = SqlExperimentGovernance(engine)
    persisted = repository.register_family(
        first,
        actor_id=first.owner_id,
        idempotency_key="register-first-tape-role",
        registered_at=first.created_at,
    )

    with pytest.raises(ExperimentGovernanceConflict):
        repository.register_family(
            conflicting,
            actor_id=conflicting.owner_id,
            idempotency_key="register-conflicting-tape-role",
            registered_at=conflicting.created_at,
        )

    assert repository.families() == (persisted,)
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_experiment_tape_claims))
            == 3
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_tape_policies)
            )
            == 3
        )


@pytest.mark.parametrize(
    "corruption",
    [
        "missing-claim",
        "tampered-claim",
        "tampered-policy",
        "orphan-claim",
        "orphan-policy",
    ],
)
def test_tape_claim_corruption_breaks_reads_or_global_readiness(
    tmp_path: Path,
    corruption: str,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    if corruption == "orphan-claim":
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.execute(
                sa.insert(phase3_experiment_tape_claims).values(
                    claim_sha256="a" * 64,
                    family_id="b" * 64,
                    segment_kind="train",
                    segment_sha256="c" * 64,
                    source_tape_sha256="d" * 64,
                    tape_content_sha256="e" * 64,
                    usage_class="exploratory",
                    canonical_payload="{}",
                    semantic_sha256="a" * 64,
                )
            )
            connection.commit()
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    else:
        with engine.begin() as connection:
            if corruption == "missing-claim":
                connection.execute(
                    sa.delete(phase3_experiment_tape_claims).where(
                        phase3_experiment_tape_claims.c.family_id == initial.family_id,
                        phase3_experiment_tape_claims.c.segment_kind == "validation",
                    )
                )
            elif corruption == "tampered-claim":
                connection.execute(
                    sa.update(phase3_experiment_tape_claims)
                    .where(
                        phase3_experiment_tape_claims.c.family_id == initial.family_id,
                        phase3_experiment_tape_claims.c.segment_kind == "train",
                    )
                    .values(canonical_payload="{}")
                )
            elif corruption == "tampered-policy":
                connection.execute(
                    sa.update(phase3_experiment_tape_policies)
                    .where(phase3_experiment_tape_policies.c.usage_class == "holdout")
                    .values(canonical_payload="{}")
                )
            else:
                connection.execute(
                    sa.insert(phase3_experiment_tape_policies).values(
                        tape_content_sha256="d" * 64,
                        source_tape_sha256="e" * 64,
                        usage_class="exploratory",
                        holdout_family_id=None,
                        canonical_payload="{}",
                        semantic_sha256="f" * 64,
                    )
                )

    if corruption in {"orphan-claim", "orphan-policy"}:
        assert repository.get(initial.family_id) == initial
    else:
        with pytest.raises(ExperimentGovernanceError):
            repository.get(initial.family_id)
    with pytest.raises(DatabaseSchemaNotReady, match="Phase 3"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_missing_audit_fact_breaks_queries_and_database_readiness(tmp_path: Path) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _request(
        initial,
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=FIRST_ATTEMPT_AT,
    )
    queued = _persist_attempt(repository, initial, queued, key="audited-attempt")
    failed_evidence = NonExecutableTerminalEvidence.unsuccessful(
        queued.attempts[-1],
        status=ExperimentAttemptStatus.FAILED,
        reason_code="bounded_fixture_failure",
        detail="The unsuccessful stable attempt must remain durable.",
    )
    failed = queued.transition_attempt(
        queued.attempts[-1].attempt_id,
        status=ExperimentAttemptStatus.FAILED,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
        terminal_evidence=failed_evidence,
    )
    failed = _persist_transition(
        repository,
        queued,
        failed,
        key="audited-failure",
    )
    assert repository.get(failed.family_id) == failed

    with engine.begin() as connection:
        connection.execute(
            sa.delete(phase3_experiment_audit_events).where(
                phase3_experiment_audit_events.c.resource_sha256
                == failed.lifecycle_events[-1].semantic_sha256
            )
        )
    with pytest.raises(ExperimentGovernanceError, match="audit coverage"):
        repository.get(failed.family_id)
    with pytest.raises(DatabaseSchemaNotReady, match="Phase 3"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


@pytest.mark.parametrize("corruption", ["canonical_payload", "deleted_event"])
def test_lifecycle_corruption_breaks_queries_and_database_readiness(
    tmp_path: Path,
    corruption: str,
) -> None:
    fixture = _fixture()
    engine, repository, initial = _registered_repository(tmp_path, fixture)
    queued = _request(
        initial,
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=FIRST_ATTEMPT_AT,
    )
    queued = _persist_attempt(repository, initial, queued, key="corruptible-attempt")
    event_sha256 = queued.lifecycle_events[-1].semantic_sha256

    with engine.begin() as connection:
        if corruption == "canonical_payload":
            connection.execute(
                sa.update(phase3_experiment_attempt_events)
                .where(phase3_experiment_attempt_events.c.event_sha256 == event_sha256)
                .values(canonical_payload="{}")
            )
        else:
            connection.execute(
                sa.delete(phase3_experiment_attempt_events).where(
                    phase3_experiment_attempt_events.c.event_sha256 == event_sha256
                )
            )
    with pytest.raises(ExperimentGovernanceError):
        repository.get(queued.family_id)
    with pytest.raises(DatabaseSchemaNotReady, match="Phase 3"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_family_queries_have_deterministic_order_and_strict_bounds(tmp_path: Path) -> None:
    fixture = _fixture()
    engine, repository, original = _registered_repository(tmp_path, fixture)
    tied_a = _family_with_distinct_test_tape(
        fixture,
        family_name="tied-a",
        start_index=30,
        created_offset=timedelta(minutes=10),
    )
    tied_b = _family_with_distinct_test_tape(
        fixture,
        family_name="tied-b",
        start_index=40,
        created_offset=timedelta(minutes=10),
    )
    registered_tied = []
    for index, family in enumerate((tied_a, tied_b), start=1):
        registered_tied.append(
            repository.register_family(
                family,
                actor_id=family.owner_id,
                idempotency_key=f"register-tied-family-{index}",
                registered_at=family.created_at,
            )
        )

    expected_tied = sorted(registered_tied, key=lambda snapshot: snapshot.family_id)
    assert repository.families(limit=2) == tuple(expected_tied)
    assert repository.families(limit=3) == (*expected_tied, original)
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase3_experiment_tape_claims))
            == 9
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase3_experiment_tape_policies)
            )
            == 5
        )
    for invalid in (0, 501, True):
        with pytest.raises(ExperimentGovernanceError, match="between 1 and 500"):
            repository.families(limit=invalid)  # type: ignore[arg-type]
