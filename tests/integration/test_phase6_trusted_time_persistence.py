from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
    TrustedTimeSourceReading,
    run_trusted_time_probe,
)
from packages.domain.trusted_time import TrustedTimeHealth, TrustedTimeReason
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
def system(tmp_path: Path) -> System:
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
) -> TrustedTimeSourceReading:
    return TrustedTimeSourceReading(
        source_id=session.binding.source_id if source_id is None else source_id,
        source_authority_sha256=session.binding.source_authority_sha256,
        trusted_at_utc=instant + offset,
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


def test_recorded_and_unavailable_attempts_replay_exactly_after_restart(
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
    for field_name in (
        "sample_sequence",
        "source_evidence_sha256",
        "probe_started_at_utc",
        "probe_completed_at_utc",
        "trusted_at_utc",
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
        source=Source(_reading(second_session, instant=BASE + timedelta(seconds=1))),
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
