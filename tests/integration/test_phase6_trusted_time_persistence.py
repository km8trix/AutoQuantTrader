from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

import packages.persistence.trusted_time as trusted_time_persistence
from packages.application.durable_trusted_time_monitor import (
    DurableTrustedTimeEpochSession,
    PersistedTrustedTimeProbe,
    run_durable_trusted_time_probe_once,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION,
    AuthenticatedTrustedTimeHeadTransition,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
    TrustedTimeSourceReading,
    run_trusted_time_probe,
)
from packages.domain.trusted_time import TRUSTED_TIME_POLICY, TrustedTimeHealth, TrustedTimeReason
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import (
    SqlTrustedTimeRepository,
    TrustedTimePersistenceConflict,
    TrustedTimePersistenceError,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 7, 31, 14, 0, tzinfo=UTC)
AUTHORITY = "a" * 64
DEPLOYMENT_IDENTITY = "c" * 64
RUNTIME_DATABASE_IDENTITY = "d" * 64
ANCHOR_PROJECT_IDENTITY = "e" * 64
ANCHOR_PROJECT_REF = "abcdefghijklmnopqrst"
ANCHOR_PRINCIPAL_ID = "11111111-1111-4111-8111-111111111111"


class SequenceClock:
    def __init__(self, *values: object) -> None:
        self._values = list(values)

    def __call__(self) -> object:
        if not self._values:
            raise RuntimeError("clock exhausted")
        return self._values.pop(0)


class Source:
    def __init__(
        self,
        reading: object = None,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.reading = reading
        self.failure = failure
        self.calls = 0

    def read_trusted_time(self, *, deadline_monotonic_ns: int) -> object:
        self.calls += 1
        assert deadline_monotonic_ns >= 1_000_000_000
        if self.failure is not None:
            raise self.failure
        return self.reading


@dataclass(frozen=True, slots=True)
class System:
    database_path: Path
    engine: Engine
    repository: SqlTrustedTimeRepository


def _config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def system(tmp_path: Path) -> Iterator[System]:
    database_path = tmp_path / "phase6-trusted-time.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    command.upgrade(_config(database_url), "head")
    engine = create_database_engine(database_url)
    value = System(
        database_path=database_path,
        engine=engine,
        repository=SqlTrustedTimeRepository(engine),
    )
    yield value
    engine.dispose()


def _register(
    repository: SqlTrustedTimeRepository,
    *,
    host_id: str = "paper-host-1",
    recorded_at: datetime = BASE,
) -> DurableTrustedTimeEpochSession:
    return repository.register_new_epoch(
        source_id="trusted-source-1",
        source_authority_sha256=AUTHORITY,
        host_id=host_id,
        recorded_at=recorded_at,
    )


def _reading(
    session: DurableTrustedTimeEpochSession,
    *,
    instant: datetime,
    offset: timedelta = timedelta(0),
    source_id: str | None = None,
    observed_monotonic_ns: int | None = None,
    uncertainty_milliseconds: Decimal = Decimal("0"),
) -> TrustedTimeSourceReading:
    elapsed = instant - BASE
    default_monotonic_ns = (
        elapsed.days * 86_400 + elapsed.seconds
    ) * 1_000_000_000 + elapsed.microseconds * 1_000
    return TrustedTimeSourceReading(
        source_id=session.binding.source_id if source_id is None else source_id,
        source_authority_sha256=session.binding.source_authority_sha256,
        local_observed_at_utc=instant,
        trusted_at_utc=instant + offset,
        observed_at_monotonic_ns=(
            default_monotonic_ns if observed_monotonic_ns is None else observed_monotonic_ns
        ),
        source_uncertainty_milliseconds=uncertainty_milliseconds,
        source_evidence_sha256="b" * 64,
    )


def _run_once(
    system: System,
    session: DurableTrustedTimeEpochSession,
    *,
    instant: datetime,
    monotonic_ns: int,
    source: Source,
) -> PersistedTrustedTimeProbe:
    return run_durable_trusted_time_probe_once(
        session,
        repository=system.repository,
        source=source,  # type: ignore[arg-type]
        utc_clock=SequenceClock(instant, instant),  # type: ignore[arg-type]
        monotonic_clock=SequenceClock(monotonic_ns, monotonic_ns),  # type: ignore[arg-type]
    )


def _evaluate_without_append(
    session: DurableTrustedTimeEpochSession,
    *,
    prior: Any,
    instant: datetime,
    monotonic_ns: int,
) -> TrustedTimeMonitorResult:
    return run_trusted_time_probe(
        prior,
        binding=session.binding,
        source=Source(_reading(session, instant=instant)),  # type: ignore[arg-type]
        utc_clock=SequenceClock(instant, instant),  # type: ignore[arg-type]
        monotonic_clock=SequenceClock(monotonic_ns, monotonic_ns),  # type: ignore[arg-type]
    )


def _raw_corrupt(database_path: Path, statement: str, parameters: tuple[object, ...]) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(statement, parameters)


def _seed_probe_evaluations(
    system: System,
    session: DurableTrustedTimeEpochSession,
    *,
    count: int,
) -> str:
    with system.engine.begin() as connection:
        epoch_row = (
            connection.execute(
                sa.select(phase6_trusted_time_epoch_registrations).where(
                    phase6_trusted_time_epoch_registrations.c.monitor_epoch_id
                    == session.binding.monitor_epoch_id
                )
            )
            .mappings()
            .one()
        )
        epoch = trusted_time_persistence._epoch_from_row(epoch_row)
        previous = None
        prior = None
        for index in range(count):
            instant = BASE + timedelta(seconds=20 * index)
            result = _evaluate_without_append(
                session,
                prior=prior,
                instant=instant,
                monotonic_ns=20_000_000_000 * index,
            )
            evaluation_id = str(uuid.uuid4())
            values = trusted_time_persistence._evaluation_values(
                evaluation_id=evaluation_id,
                epoch=epoch,
                evaluation_sequence=index + 1,
                previous_evaluation_id=(None if previous is None else previous.evaluation_id),
                previous_evaluation_sha256=(None if previous is None else previous.semantic_sha256),
                result=result,
            )
            connection.execute(sa.insert(phase6_trusted_time_probe_evaluations).values(**values))
            previous = trusted_time_persistence._EvaluationRecord(
                evaluation_id=evaluation_id,
                evaluation_sequence=index + 1,
                previous_evaluation_id=(None if previous is None else previous.evaluation_id),
                previous_evaluation_sha256=(None if previous is None else previous.semantic_sha256),
                semantic_sha256=str(values["semantic_sha256"]),
                result=result,
            )
            prior = result.state
        head = trusted_time_persistence._new_head(epoch, previous)
        updated = connection.execute(
            sa.update(phase6_trusted_time_host_heads)
            .where(phase6_trusted_time_host_heads.c.host_id == session.binding.host_id)
            .values(**trusted_time_persistence._head_values(head))
        )
        assert updated.rowcount == 1
    return head.semantic_sha256


def _read_authenticated_head_transitions(
    repository: SqlTrustedTimeRepository,
    *,
    host_id: str = "paper-host-1",
) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    return repository.read_authenticated_head_transitions(
        host_id=host_id,
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=ANCHOR_PRINCIPAL_ID,
    )


def test_recorded_and_unavailable_attempts_replay_exactly_after_restart(
    system: System,
) -> None:
    session = _register(system.repository)
    first = _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(
            _reading(
                session,
                instant=BASE,
                uncertainty_milliseconds=Decimal("12.5"),
            )
        ),
    )
    unavailable_source = Source(failure=RuntimeError("secret source endpoint"))
    second = _run_once(
        system,
        session,
        instant=BASE + timedelta(seconds=30),
        monotonic_ns=30_000_000_000,
        source=unavailable_source,
    )

    assert first.evaluation_sequence == 1
    assert first.result.status is TrustedTimeProbeStatus.RECORDED
    assert second.evaluation_sequence == 2
    assert second.result.status is TrustedTimeProbeStatus.SOURCE_UNAVAILABLE
    assert second.result.state.latest_sample == first.result.state.latest_sample
    assert unavailable_source.calls == 1
    with system.engine.connect() as connection:
        rows = (
            connection.execute(
                sa.select(phase6_trusted_time_probe_evaluations).order_by(
                    phase6_trusted_time_probe_evaluations.c.evaluation_sequence
                )
            )
            .mappings()
            .all()
        )
    assert [row["probe_status"] for row in rows] == [
        "recorded",
        "source_unavailable",
    ]
    assert rows[0]["sample_sequence"] == 1
    assert rows[0]["source_uncertainty_milliseconds"] == Decimal("12.5")
    for field_name in (
        "sample_sequence",
        "source_evidence_sha256",
        "probe_started_at_utc",
        "probe_completed_at_utc",
        "trusted_at_utc",
        "source_uncertainty_milliseconds",
        "probe_started_monotonic_ns",
        "probe_completed_monotonic_ns",
        "sample_canonical_payload",
        "sample_sha256",
    ):
        assert rows[1][field_name] is None

    restarted_repository = SqlTrustedTimeRepository(system.engine)
    restarted_repository.verify_integrity()
    verify_operational_schema(system.engine, require_phase_zero_facts=False)
    with pytest.raises(TrustedTimePersistenceConflict, match="not active"):
        restarted_repository.prepare_probe(session)
    prepared = system.repository.prepare_probe(session)
    assert prepared.next_evaluation_sequence == 3
    assert prepared.prior == second.result.state


@pytest.mark.parametrize(
    ("reading", "expected_status"),
    [
        ("identity_mismatch", TrustedTimeProbeStatus.SOURCE_IDENTITY_MISMATCH),
        ("invalid", TrustedTimeProbeStatus.INVALID_READING),
    ],
)
def test_sample_free_failure_classes_are_durably_accounted(
    system: System,
    reading: str,
    expected_status: TrustedTimeProbeStatus,
) -> None:
    session = _register(system.repository)
    source_value: object
    if reading == "identity_mismatch":
        source_value = _reading(
            session,
            instant=BASE,
            source_id="unapproved-source",
        )
    else:
        source_value = {"trusted_at": BASE.isoformat()}

    persisted = _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(source_value),
    )

    assert persisted.result.status is expected_status
    with system.engine.connect() as connection:
        row = connection.execute(sa.select(phase6_trusted_time_probe_evaluations)).mappings().one()
    assert row["probe_status"] == expected_status.value
    assert row["sample_sha256"] is None
    assert row["sample_canonical_payload"] is None
    system.repository.verify_integrity()


def test_registration_translates_invalid_binding_without_writing(
    system: System,
) -> None:
    with pytest.raises(
        TrustedTimePersistenceError,
        match="epoch registration failed",
    ):
        system.repository.register_new_epoch(
            source_id=" untrimmed-source",
            source_authority_sha256=AUTHORITY,
            host_id="paper-host-1",
            recorded_at=BASE,
        )

    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_epoch_registrations)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_host_heads)
            )
            == 0
        )


def test_epoch_rotation_fences_stale_session_and_resets_monotonic_state(
    system: System,
) -> None:
    first_session = _register(system.repository)
    first = _run_once(
        system,
        first_session,
        instant=BASE,
        monotonic_ns=50_000_000_000,
        source=Source(
            _reading(
                first_session,
                instant=BASE,
                offset=timedelta(seconds=2),
                observed_monotonic_ns=50_000_000_000,
            )
        ),
    )
    assert first.result.state.hard_failure_latched is True

    second_session = _register(
        system.repository,
        recorded_at=BASE + timedelta(seconds=1),
    )
    with pytest.raises(TrustedTimePersistenceConflict, match="not active"):
        system.repository.prepare_probe(first_session)
    prepared = system.repository.prepare_probe(second_session)
    assert prepared.prior is None
    assert prepared.next_evaluation_sequence == 1
    fresh = _run_once(
        system,
        second_session,
        instant=BASE + timedelta(seconds=1),
        monotonic_ns=0,
        source=Source(
            _reading(
                second_session,
                instant=BASE + timedelta(seconds=1),
                observed_monotonic_ns=0,
            )
        ),
    )
    assert fresh.result.state.hard_failure_latched is False
    assert fresh.result.state.health is TrustedTimeHealth.HEALTHY
    with system.engine.connect() as connection:
        epochs = (
            connection.execute(
                sa.select(
                    phase6_trusted_time_epoch_registrations.c.epoch_sequence,
                    phase6_trusted_time_epoch_registrations.c.previous_host_head_sha256,
                ).order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence)
            )
            .mappings()
            .all()
        )
    assert [row["epoch_sequence"] for row in epochs] == [1, 2]
    assert epochs[0]["previous_host_head_sha256"] is None
    assert epochs[1]["previous_host_head_sha256"] == first.host_head_sha256


def test_hard_latch_and_exact_sixty_second_recovery_remain_non_authorizing(
    system: System,
) -> None:
    session = _register(system.repository)
    hard = _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(session, instant=BASE, offset=timedelta(milliseconds=1001))),
    )
    assert hard.result.state.reason is TrustedTimeReason.HARD_OFFSET

    recovered: PersistedTrustedTimeProbe | None = None
    for seconds in (1, 31, 61):
        recovered = _run_once(
            system,
            session,
            instant=BASE + timedelta(seconds=seconds),
            monotonic_ns=seconds * 1_000_000_000,
            source=Source(
                _reading(
                    session,
                    instant=BASE + timedelta(seconds=seconds),
                )
            ),
        )
    assert recovered is not None
    assert recovered.result.state.clock_recovery_qualified is True
    assert recovered.result.state.hard_failure_latched is True
    assert recovered.result.state.health is TrustedTimeHealth.BLOCKED
    assert recovered.result.state.reason is TrustedTimeReason.HARD_OFFSET_LATCHED
    assert recovered.new_exposure_authorized is False
    assert recovered.automatic_rearm_authorized is False
    system.repository.verify_integrity()


def test_concurrent_preparations_allow_only_one_exact_cas_append(
    system: System,
) -> None:
    session = _register(system.repository)
    first_preparation = system.repository.prepare_probe(session)
    second_preparation = system.repository.prepare_probe(session)
    first_result = _evaluate_without_append(
        session,
        prior=first_preparation.prior,
        instant=BASE,
        monotonic_ns=0,
    )
    second_result = _evaluate_without_append(
        session,
        prior=second_preparation.prior,
        instant=BASE,
        monotonic_ns=0,
    )

    persisted = system.repository.append_probe(
        session,
        prepared=first_preparation,
        result=first_result,
    )
    with pytest.raises(TrustedTimePersistenceConflict, match="head changed"):
        system.repository.append_probe(
            session,
            prepared=second_preparation,
            result=second_result,
        )

    assert persisted.evaluation_sequence == 1
    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_probe_evaluations)
            )
            == 1
        )


def test_append_failure_rolls_back_insert_and_head_advance(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _register(system.repository)
    prepared = system.repository.prepare_probe(session)
    result = _evaluate_without_append(
        session,
        prior=prepared.prior,
        instant=BASE,
        monotonic_ns=0,
    )
    original_head_values = trusted_time_persistence._head_values
    calls = 0

    def fail_after_insert(
        head: trusted_time_persistence._HostHead,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TrustedTimePersistenceError("injected head write failure")
        return original_head_values(head)

    monkeypatch.setattr(
        trusted_time_persistence,
        "_head_values",
        fail_after_insert,
    )
    with pytest.raises(TrustedTimePersistenceError, match="injected"):
        system.repository.append_probe(
            session,
            prepared=prepared,
            result=result,
        )
    monkeypatch.setattr(
        trusted_time_persistence,
        "_head_values",
        original_head_values,
    )

    with system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_probe_evaluations)
            )
            == 0
        )
        assert (
            connection.scalar(sa.select(phase6_trusted_time_host_heads.c.evaluation_sequence)) == 0
        )
    system.repository.verify_integrity()


@pytest.mark.parametrize(
    ("statement", "parameters"),
    [
        (
            "UPDATE phase6_trusted_time_probe_evaluations SET canonical_payload = ?",
            ("{}",),
        ),
        (
            "UPDATE phase6_trusted_time_probe_evaluations SET reason = ?",
            ("warning_offset",),
        ),
        (
            "UPDATE phase6_trusted_time_probe_evaluations SET policy_sha256 = ?",
            ("f" * 64,),
        ),
        (
            "UPDATE phase6_trusted_time_probe_evaluations SET source_uncertainty_milliseconds = ?",
            ("1.0000000000",),
        ),
        (
            "UPDATE phase6_trusted_time_host_heads SET semantic_sha256 = ?",
            ("e" * 64,),
        ),
    ],
)
def test_canonical_policy_projection_and_head_tampering_fail_closed(
    system: System,
    statement: str,
    parameters: tuple[object, ...],
) -> None:
    session = _register(system.repository)
    _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(session, instant=BASE)),
    )
    _raw_corrupt(system.database_path, statement, parameters)

    with pytest.raises((TrustedTimePersistenceError, TrustedTimePersistenceConflict)):
        system.repository.verify_integrity()
    with pytest.raises(DatabaseSchemaNotReady, match="trusted-time integrity"):
        verify_operational_schema(
            system.engine,
            require_phase_zero_facts=False,
        )


def test_predecessor_tampering_and_deleted_tail_fail_closed(
    system: System,
) -> None:
    session = _register(system.repository)
    first = _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(session, instant=BASE)),
    )
    second = _run_once(
        system,
        session,
        instant=BASE + timedelta(seconds=30),
        monotonic_ns=30_000_000_000,
        source=Source(_reading(session, instant=BASE + timedelta(seconds=30))),
    )
    assert second.evaluation_sequence == 2
    _raw_corrupt(
        system.database_path,
        "UPDATE phase6_trusted_time_probe_evaluations "
        "SET previous_evaluation_sha256 = ? WHERE evaluation_sequence = 2",
        ("f" * 64,),
    )
    with pytest.raises((TrustedTimePersistenceError, TrustedTimePersistenceConflict)):
        system.repository.verify_integrity()

    # A coherent database transaction could never leave this shape, but an
    # administrator with constraints disabled must still be detected.
    _raw_corrupt(
        system.database_path,
        "UPDATE phase6_trusted_time_probe_evaluations "
        "SET previous_evaluation_sha256 = ? WHERE evaluation_sequence = 2",
        (first.record_sha256,),
    )
    _raw_corrupt(
        system.database_path,
        "DELETE FROM phase6_trusted_time_probe_evaluations WHERE evaluation_sequence = 2",
        (),
    )
    with pytest.raises((TrustedTimePersistenceError, TrustedTimePersistenceConflict)):
        system.repository.verify_integrity()


def test_authenticated_head_transition_export_replays_every_zero_and_evaluated_head(
    system: System,
) -> None:
    first_session = _register(system.repository)
    first = _run_once(
        system,
        first_session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(first_session, instant=BASE)),
    )
    second = _run_once(
        system,
        first_session,
        instant=BASE + timedelta(seconds=30),
        monotonic_ns=30_000_000_000,
        source=Source(failure=RuntimeError("source unavailable")),
    )
    second_session = _register(
        system.repository,
        recorded_at=BASE + timedelta(seconds=31),
    )
    third = _run_once(
        system,
        second_session,
        instant=BASE + timedelta(seconds=31),
        monotonic_ns=0,
        source=Source(
            _reading(
                second_session,
                instant=BASE + timedelta(seconds=31),
                observed_monotonic_ns=0,
            )
        ),
    )

    transitions = _read_authenticated_head_transitions(system.repository)

    assert [(item.epoch_sequence, item.evaluation_sequence) for item in transitions] == [
        (1, 0),
        (1, 1),
        (1, 2),
        (2, 0),
        (2, 1),
    ]
    assert all(item.deployment_identity_sha256 == DEPLOYMENT_IDENTITY for item in transitions)
    assert all(
        item.runtime_database_identity_sha256 == RUNTIME_DATABASE_IDENTITY for item in transitions
    )
    assert all(
        item.anchor_project_identity_sha256 == ANCHOR_PROJECT_IDENTITY for item in transitions
    )
    assert all(item.anchor_project_ref == ANCHOR_PROJECT_REF for item in transitions)
    assert all(item.bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME for item in transitions)
    assert all(item.principal_id == ANCHOR_PRINCIPAL_ID for item in transitions)
    assert all(item.host_id == "paper-host-1" for item in transitions)
    assert all(item.policy_sha256 == TRUSTED_TIME_POLICY.semantic_sha256 for item in transitions)
    assert all(
        item.persistence_contract_version == TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION
        for item in transitions
    )
    assert [item.previous_host_head_sha256 for item in transitions] == [
        None,
        transitions[0].current_host_head_sha256,
        first.host_head_sha256,
        second.host_head_sha256,
        transitions[3].current_host_head_sha256,
    ]
    assert transitions[1].current_host_head_sha256 == first.host_head_sha256
    assert transitions[2].current_host_head_sha256 == second.host_head_sha256
    assert transitions[4].current_host_head_sha256 == third.host_head_sha256
    assert [item.head_authenticated_at_utc for item in transitions] == [
        BASE,
        first.result.state.evaluated_at_utc,
        second.result.state.evaluated_at_utc,
        BASE + timedelta(seconds=31),
        third.result.state.evaluated_at_utc,
    ]

    for zero in (transitions[0], transitions[3]):
        assert zero.evaluation_id is None
        assert zero.evaluation_record_sha256 is None
        assert zero.state_sha256 is None
        assert zero.probe_status is None
        assert zero.health is None
        assert zero.reason is None
        assert zero.hard_failure_latched is None
        assert zero.clock_recovery_qualified is None
        assert zero.evaluated_at_utc is None
        assert zero.evaluated_at_monotonic_ns is None

    with system.engine.connect() as connection:
        epoch_rows = (
            connection.execute(
                sa.select(
                    phase6_trusted_time_epoch_registrations.c.monitor_epoch_id,
                    phase6_trusted_time_epoch_registrations.c.semantic_sha256,
                    phase6_trusted_time_epoch_registrations.c.source_id,
                    phase6_trusted_time_epoch_registrations.c.source_authority_sha256,
                ).order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence)
            )
            .mappings()
            .all()
        )
        evaluation_rows = (
            connection.execute(
                sa.select(
                    phase6_trusted_time_probe_evaluations.c.monitor_epoch_id,
                    phase6_trusted_time_probe_evaluations.c.evaluation_sequence,
                    phase6_trusted_time_probe_evaluations.c.evaluation_id,
                ).order_by(
                    phase6_trusted_time_probe_evaluations.c.evaluated_at_utc,
                    phase6_trusted_time_probe_evaluations.c.evaluation_sequence,
                )
            )
            .mappings()
            .all()
        )
    for transition, row in zip((transitions[0], transitions[3]), epoch_rows, strict=True):
        assert transition.monitor_epoch_id == row["monitor_epoch_id"]
        assert transition.epoch_sha256 == row["semantic_sha256"]
        assert transition.source_id == row["source_id"]
        assert transition.source_authority_sha256 == row["source_authority_sha256"]
    for transition, row, persisted in zip(
        (transitions[1], transitions[2], transitions[4]),
        evaluation_rows,
        (first, second, third),
        strict=True,
    ):
        assert transition.monitor_epoch_id == row["monitor_epoch_id"]
        assert transition.evaluation_id == row["evaluation_id"]
        assert transition.evaluation_record_sha256 == persisted.record_sha256
        assert transition.state_sha256 == persisted.result.state.semantic_sha256
        assert transition.probe_status is persisted.result.status
        assert transition.health is persisted.result.state.health
        assert transition.reason is persisted.result.state.reason
        assert transition.hard_failure_latched is persisted.result.state.hard_failure_latched
        assert (
            transition.clock_recovery_qualified is persisted.result.state.clock_recovery_qualified
        )
        assert (
            transition.evaluated_at_monotonic_ns == persisted.result.state.evaluated_at_monotonic_ns
        )


def test_authenticated_head_transition_export_validates_identity_even_when_absent(
    system: System,
) -> None:
    assert (
        _read_authenticated_head_transitions(
            system.repository,
            host_id="absent-paper-host",
        )
        == ()
    )

    with pytest.raises(TrustedTimePersistenceError, match="deployment identity"):
        system.repository.read_authenticated_head_transitions(
            host_id="absent-paper-host",
            deployment_identity_sha256="not-a-digest",
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            principal_id=ANCHOR_PRINCIPAL_ID,
        )


def test_authenticated_head_transition_export_fails_closed_on_replay_tampering(
    system: System,
) -> None:
    session = _register(system.repository)
    _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(session, instant=BASE)),
    )
    _raw_corrupt(
        system.database_path,
        "UPDATE phase6_trusted_time_probe_evaluations SET canonical_payload = ?",
        ("{}",),
    )

    with pytest.raises((TrustedTimePersistenceError, TrustedTimePersistenceConflict)):
        _read_authenticated_head_transitions(system.repository)


def test_authenticated_head_transition_export_preserves_regressing_utc_evidence(
    system: System,
) -> None:
    first_session = _register(system.repository)
    _run_once(
        system,
        first_session,
        instant=BASE + timedelta(seconds=10),
        monotonic_ns=10_000_000_000,
        source=Source(_reading(first_session, instant=BASE + timedelta(seconds=10))),
    )
    _register(
        system.repository,
        recorded_at=BASE + timedelta(seconds=9),
    )

    transitions = _read_authenticated_head_transitions(system.repository)

    assert [(item.epoch_sequence, item.evaluation_sequence) for item in transitions] == [
        (1, 0),
        (1, 1),
        (2, 0),
    ]
    assert transitions[-1].head_authenticated_at_utc < (transitions[-2].head_authenticated_at_utc)
    assert transitions[-1].previous_host_head_sha256 == (transitions[-2].current_host_head_sha256)


def test_active_probe_path_does_not_replay_the_authenticated_prefix(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _register(system.repository)

    def reject_full_replay(*args: object, **kwargs: object) -> None:
        raise AssertionError("active probe path attempted a full history replay")

    monkeypatch.setattr(trusted_time_persistence, "_verified_host", reject_full_replay)

    persisted = _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(session, instant=BASE)),
    )

    assert persisted.evaluation_sequence == 1


def test_authenticated_head_snapshot_compacts_and_refreshes_only_the_suffix(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _register(system.repository)
    first = _run_once(
        system,
        session,
        instant=BASE,
        monotonic_ns=0,
        source=Source(_reading(session, instant=BASE)),
    )
    startup = system.repository.load_authenticated_head_startup_snapshot(
        host_id="paper-host-1",
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=ANCHOR_PRINCIPAL_ID,
    )

    assert startup.complete_replay is True
    assert startup.transition_count == 2
    assert startup.local_transitions == ()
    assert startup.current_host_head_sha256 == first.host_head_sha256
    proof = startup.full_replay_proof
    assert proof is not None
    assert proof.transition_count == 2
    assert proof.first_transition.evaluation_sequence == 0
    assert proof.current_transition.evaluation_sequence == 1
    assert proof.current_host_head_sha256 == first.host_head_sha256

    compact = system.repository.compact_authenticated_head_snapshot(startup)
    assert compact.complete_replay is False
    assert compact.local_transitions == ()
    assert compact.full_replay_proof is None
    with pytest.raises(TrustedTimePersistenceConflict, match="stale or foreign"):
        system.repository.discard_authenticated_head_full_replay_proof(proof)
    assert system.repository.refresh_authenticated_head_snapshot(compact) is compact
    with pytest.raises(TrustedTimePersistenceConflict, match="stale or foreign"):
        system.repository.refresh_authenticated_head_snapshot(startup)

    second = _run_once(
        system,
        session,
        instant=BASE + timedelta(seconds=30),
        monotonic_ns=30_000_000_000,
        source=Source(failure=RuntimeError("source unavailable")),
    )

    def reject_full_replay(*args: object, **kwargs: object) -> None:
        raise AssertionError("snapshot refresh attempted a full history replay")

    monkeypatch.setattr(trusted_time_persistence, "_verified_host", reject_full_replay)
    refreshed = system.repository.refresh_authenticated_head_snapshot(compact)

    assert refreshed is not compact
    assert refreshed.complete_replay is False
    assert refreshed.transition_count == 3
    assert len(refreshed.local_transitions) == 1
    assert refreshed.local_transitions[0].previous_host_head_sha256 == first.host_head_sha256
    assert refreshed.current_host_head_sha256 == second.host_head_sha256

    released = system.repository.compact_authenticated_head_snapshot(refreshed)
    assert released.local_transitions == ()
    assert released.transition_count == 3
    system.repository.discard_authenticated_head_snapshot(released)
    with pytest.raises(TrustedTimePersistenceConflict, match="stale or foreign"):
        system.repository.refresh_authenticated_head_snapshot(released)


def test_large_full_replay_keeps_raw_and_projected_pages_bounded(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _register(system.repository)
    terminal_head_sha256 = _seed_probe_evaluations(system, session, count=600)
    original_epoch_page = trusted_time_persistence._trusted_time_epoch_replay_page
    original_evaluation_page = trusted_time_persistence._trusted_time_evaluation_replay_page
    raw_epoch_page_lengths: list[int] = []
    raw_evaluation_page_lengths: list[int] = []
    replay_connection_ids: set[int] = set()
    replay_connection: Any = None

    def record_epoch_page(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        nonlocal replay_connection
        connection = args[0]
        assert connection.in_transaction()
        replay_connection = connection
        replay_connection_ids.add(id(connection))
        page = original_epoch_page(*args, **kwargs)
        raw_epoch_page_lengths.append(len(page))
        return page

    def record_evaluation_page(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        nonlocal replay_connection
        connection = args[0]
        assert connection.in_transaction()
        replay_connection = connection
        replay_connection_ids.add(id(connection))
        page = original_evaluation_page(*args, **kwargs)
        raw_evaluation_page_lengths.append(len(page))
        return page

    monkeypatch.setattr(
        trusted_time_persistence,
        "_trusted_time_epoch_replay_page",
        record_epoch_page,
    )
    monkeypatch.setattr(
        trusted_time_persistence,
        "_trusted_time_evaluation_replay_page",
        record_evaluation_page,
    )

    startup = system.repository.load_authenticated_head_startup_snapshot(
        host_id="paper-host-1",
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=ANCHOR_PRINCIPAL_ID,
    )

    assert startup.local_transitions == ()
    assert startup.transition_count == 601
    assert startup.current_host_head_sha256 == terminal_head_sha256
    assert startup.full_replay_proof is not None
    assert startup.full_replay_proof.transition_count == 601
    assert max(raw_epoch_page_lengths) <= 256
    assert max(raw_evaluation_page_lengths) <= 256
    assert sum(length > 0 for length in raw_evaluation_page_lengths) == 3
    assert len(replay_connection_ids) == 1

    system.repository.discard_authenticated_head_snapshot(startup)
    raw_epoch_page_lengths.clear()
    raw_evaluation_page_lengths.clear()
    replay_connection_ids.clear()
    replay_connection = None
    projected_page_lengths: list[int] = []
    projected_transition_count = 0

    def consume_page(
        page: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> None:
        nonlocal projected_transition_count
        assert replay_connection is not None
        assert replay_connection.in_transaction()
        projected_page_lengths.append(len(page))
        projected_transition_count += len(page)

    proof = system.repository.consume_authenticated_head_full_replay(
        host_id="paper-host-1",
        deployment_identity_sha256=DEPLOYMENT_IDENTITY,
        runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
        anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
        anchor_project_ref=ANCHOR_PROJECT_REF,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=ANCHOR_PRINCIPAL_ID,
        page_consumer=consume_page,
        page_size=37,
    )

    assert projected_transition_count == 601
    assert proof.transition_count == 601
    assert proof.first_transition.evaluation_sequence == 0
    assert proof.current_transition.evaluation_sequence == 600
    assert proof.current_host_head_sha256 == terminal_head_sha256
    assert max(projected_page_lengths) <= 37
    assert len(projected_page_lengths) > 1
    assert max(raw_epoch_page_lengths) <= 37
    assert max(raw_evaluation_page_lengths) <= 37
    assert sum(length > 0 for length in raw_evaluation_page_lengths) == 17
    assert len(replay_connection_ids) == 1
    system.repository.discard_authenticated_head_full_replay_proof(proof)


@pytest.mark.parametrize("page_fault", ["gap", "fork"])
def test_full_replay_rejects_evaluation_page_drift_and_forks(
    system: System,
    monkeypatch: pytest.MonkeyPatch,
    page_fault: str,
) -> None:
    session = _register(system.repository)
    _seed_probe_evaluations(system, session, count=6)
    original_page = trusted_time_persistence._trusted_time_evaluation_replay_page
    prior_page_terminal: Any = None
    nonempty_page_number = 0

    def drifted_page(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        nonlocal nonempty_page_number
        nonlocal prior_page_terminal
        page = original_page(*args, **kwargs)
        if not page:
            return page
        nonempty_page_number += 1
        if nonempty_page_number == 1:
            prior_page_terminal = page[-1]
            return page
        if nonempty_page_number == 2:
            if page_fault == "gap":
                return page[1:]
            assert prior_page_terminal is not None
            return (prior_page_terminal, *page[1:])
        return page

    monkeypatch.setattr(
        trusted_time_persistence,
        "_trusted_time_evaluation_replay_page",
        drifted_page,
    )
    proof_count_before = len(system.repository._authenticated_head_replay_proofs)

    with pytest.raises(
        (TrustedTimePersistenceError, TrustedTimePersistenceConflict),
    ):
        system.repository.consume_authenticated_head_full_replay(
            host_id="paper-host-1",
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            principal_id=ANCHOR_PRINCIPAL_ID,
            page_consumer=lambda _page: None,
            page_size=2,
        )

    assert len(system.repository._authenticated_head_replay_proofs) == proof_count_before


def test_full_replay_callback_failure_prevents_proof_issuance(system: System) -> None:
    _register(system.repository)
    proof_count_before = len(system.repository._authenticated_head_replay_proofs)

    def reject_page(
        _page: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> None:
        raise RuntimeError("consumer rejected provisional replay page")

    with pytest.raises(RuntimeError, match="consumer rejected"):
        system.repository.consume_authenticated_head_full_replay(
            host_id="paper-host-1",
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            principal_id=ANCHOR_PRINCIPAL_ID,
            page_consumer=reject_page,
            page_size=1,
        )

    assert len(system.repository._authenticated_head_replay_proofs) == proof_count_before


@pytest.mark.parametrize("journal_fault", ["deleted_tail", "foreign_epoch"])
def test_full_replay_requires_complete_non_orphaned_journal_before_proof(
    system: System,
    journal_fault: str,
) -> None:
    session = _register(system.repository)
    _seed_probe_evaluations(system, session, count=6)
    if journal_fault == "deleted_tail":
        _raw_corrupt(
            system.database_path,
            "DELETE FROM phase6_trusted_time_probe_evaluations WHERE evaluation_sequence = 6",
            (),
        )
    else:
        _raw_corrupt(
            system.database_path,
            "UPDATE phase6_trusted_time_probe_evaluations "
            "SET monitor_epoch_id = ? WHERE evaluation_sequence = 6",
            (str(uuid.uuid4()),),
        )
    provisional_transition_count = 0
    proof_count_before = len(system.repository._authenticated_head_replay_proofs)

    def consume_provisional_page(
        page: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> None:
        nonlocal provisional_transition_count
        provisional_transition_count += len(page)

    with pytest.raises(
        (TrustedTimePersistenceError, TrustedTimePersistenceConflict),
    ):
        system.repository.consume_authenticated_head_full_replay(
            host_id="paper-host-1",
            deployment_identity_sha256=DEPLOYMENT_IDENTITY,
            runtime_database_identity_sha256=RUNTIME_DATABASE_IDENTITY,
            anchor_project_identity_sha256=ANCHOR_PROJECT_IDENTITY,
            anchor_project_ref=ANCHOR_PROJECT_REF,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            principal_id=ANCHOR_PRINCIPAL_ID,
            page_consumer=consume_provisional_page,
            page_size=2,
        )

    assert provisional_transition_count > 0
    assert len(system.repository._authenticated_head_replay_proofs) == proof_count_before
