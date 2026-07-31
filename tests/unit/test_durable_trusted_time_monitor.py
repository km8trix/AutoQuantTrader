from __future__ import annotations

from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.application.durable_trusted_time_monitor import (
    DURABLE_TRUSTED_TIME_MONITOR_CONTRACT_VERSION,
    DurableTrustedTimeEpochSession,
    DurableTrustedTimeMonitorError,
    PersistedTrustedTimeProbe,
    PreparedTrustedTimeProbe,
    _new_durable_trusted_time_epoch_session,
    run_durable_trusted_time_probe_once,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorBinding,
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
    TrustedTimeSourceReading,
)
from packages.domain.trusted_time import TrustedTimeHealth, TrustedTimeReason

BASE = datetime(2026, 7, 31, 14, 0, tzinfo=UTC)
AUTHORITY = "a" * 64
REGISTRATION = "b" * 64
EXPECTED_HEAD = "c" * 64
RECORD = "d" * 64
NEW_HEAD = "e" * 64


class SequenceClock:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        if not self.values:
            raise RuntimeError("clock exhausted")
        return self.values.pop(0)


class Source:
    def __init__(
        self,
        trace: list[str],
        *,
        failure: Exception | None = None,
    ) -> None:
        self.trace = trace
        self.failure = failure
        self.calls = 0

    def read_trusted_time(self, *, deadline_monotonic_ns: int) -> TrustedTimeSourceReading:
        self.calls += 1
        self.trace.append("source")
        assert deadline_monotonic_ns == 1_000_000_100
        if self.failure is not None:
            raise self.failure
        return TrustedTimeSourceReading(
            source_id="trusted-source-1",
            source_authority_sha256=AUTHORITY,
            trusted_at_utc=BASE + timedelta(milliseconds=10),
            source_evidence_sha256="f" * 64,
        )


class Repository:
    def __init__(
        self,
        prepared: object,
        trace: list[str],
        *,
        prepare_failure: Exception | None = None,
        append_failure: Exception | None = None,
        persisted: object | None = None,
    ) -> None:
        self.prepared = prepared
        self.trace = trace
        self.prepare_failure = prepare_failure
        self.append_failure = append_failure
        self.persisted = persisted
        self.prepare_calls = 0
        self.append_calls = 0
        self.appended_result: TrustedTimeMonitorResult | None = None

    def prepare_probe(self, session: DurableTrustedTimeEpochSession) -> object:
        self.prepare_calls += 1
        self.trace.append("prepare")
        if self.prepare_failure is not None:
            raise self.prepare_failure
        return self.prepared

    def append_probe(
        self,
        session: DurableTrustedTimeEpochSession,
        *,
        prepared: PreparedTrustedTimeProbe,
        result: TrustedTimeMonitorResult,
    ) -> object:
        self.append_calls += 1
        self.trace.append("append")
        self.appended_result = result
        if self.append_failure is not None:
            raise self.append_failure
        if self.persisted is not None:
            return self.persisted
        return PersistedTrustedTimeProbe(
            result=result,
            evaluation_sequence=prepared.next_evaluation_sequence,
            record_sha256=RECORD,
            host_head_sha256=NEW_HEAD,
        )


class ExplodingRepositoryPort:
    def __getattribute__(self, name: str) -> object:
        if name in {"prepare_probe", "append_probe"}:
            raise RuntimeError("secret repository port detail")
        return super().__getattribute__(name)


def _binding(*, epoch_id: str = "monitor-epoch-1") -> TrustedTimeMonitorBinding:
    return TrustedTimeMonitorBinding(
        source_id="trusted-source-1",
        source_authority_sha256=AUTHORITY,
        host_id="paper-trader-1",
        monitor_epoch_id=epoch_id,
    )


def _session(
    *,
    binding: TrustedTimeMonitorBinding | None = None,
    registration: str = REGISTRATION,
) -> DurableTrustedTimeEpochSession:
    return _new_durable_trusted_time_epoch_session(
        binding=_binding() if binding is None else binding,
        epoch_registration_sha256=registration,
    )


def _prepared(
    *,
    binding: TrustedTimeMonitorBinding | None = None,
    registration: str = REGISTRATION,
) -> PreparedTrustedTimeProbe:
    return PreparedTrustedTimeProbe(
        binding=_binding() if binding is None else binding,
        prior=None,
        expected_host_head_sha256=EXPECTED_HEAD,
        epoch_registration_sha256=registration,
        next_evaluation_sequence=1,
    )


def _run(
    repository: object,
    source: Source,
    *,
    session: DurableTrustedTimeEpochSession | None = None,
) -> PersistedTrustedTimeProbe:
    return run_durable_trusted_time_probe_once(
        _session() if session is None else session,
        repository=repository,  # type: ignore[arg-type]
        source=source,
        utc_clock=SequenceClock(BASE, BASE + timedelta(milliseconds=20)),  # type: ignore[arg-type]
        monotonic_clock=SequenceClock(100, 20_000_100),  # type: ignore[arg-type]
    )


def test_one_shot_prepares_probes_once_then_cas_appends_once() -> None:
    trace: list[str] = []
    source = Source(trace)
    repository = Repository(_prepared(), trace)

    persisted = _run(repository, source)

    assert trace == ["prepare", "source", "append"]
    assert repository.prepare_calls == 1
    assert source.calls == 1
    assert repository.append_calls == 1
    assert persisted.result.status is TrustedTimeProbeStatus.RECORDED
    assert persisted.result.state.health is TrustedTimeHealth.HEALTHY
    assert persisted.result.state.reason is TrustedTimeReason.STARTUP_QUALIFYING
    assert persisted.evaluation_sequence == 1
    assert persisted.record_sha256 == RECORD
    assert persisted.host_head_sha256 == NEW_HEAD


def test_source_failure_is_persisted_as_blocked_evidence_without_retry() -> None:
    trace: list[str] = []
    source = Source(trace, failure=RuntimeError("secret source endpoint"))
    repository = Repository(_prepared(), trace)

    persisted = _run(repository, source)

    assert trace == ["prepare", "source", "append"]
    assert source.calls == 1
    assert repository.append_calls == 1
    assert persisted.result.status is TrustedTimeProbeStatus.SOURCE_UNAVAILABLE
    assert persisted.result.state.health is TrustedTimeHealth.BLOCKED
    assert "secret" not in repr(persisted)


def test_prepare_failure_is_sanitized_before_source_or_append() -> None:
    trace: list[str] = []
    source = Source(trace)
    repository = Repository(
        _prepared(),
        trace,
        prepare_failure=RuntimeError("secret database detail"),
    )

    with pytest.raises(
        DurableTrustedTimeMonitorError,
        match="preparation failed",
    ) as captured:
        _run(repository, source)

    assert "secret" not in str(captured.value)
    assert trace == ["prepare"]
    assert source.calls == 0
    assert repository.append_calls == 0


@pytest.mark.parametrize(
    "prepared",
    [
        _prepared(binding=_binding(epoch_id="monitor-epoch-2")),
        _prepared(registration="9" * 64),
        {"prior": None},
    ],
)
def test_substituted_preparation_fails_before_source_or_append(
    prepared: object,
) -> None:
    trace: list[str] = []
    source = Source(trace)
    repository = Repository(prepared, trace)

    with pytest.raises(
        DurableTrustedTimeMonitorError,
        match=r"preparation|epoch identity",
    ):
        _run(repository, source)

    assert trace == ["prepare"]
    assert source.calls == 0
    assert repository.append_calls == 0


def test_append_conflict_is_sanitized_and_never_retries_probe_or_cas() -> None:
    trace: list[str] = []
    source = Source(trace)
    repository = Repository(
        _prepared(),
        trace,
        append_failure=RuntimeError("secret CAS winner"),
    )

    with pytest.raises(
        DurableTrustedTimeMonitorError,
        match="append failed",
    ) as captured:
        _run(repository, source)

    assert "secret" not in str(captured.value)
    assert trace == ["prepare", "source", "append"]
    assert source.calls == 1
    assert repository.append_calls == 1


def test_substituted_persisted_result_is_rejected_without_another_effect() -> None:
    trace: list[str] = []
    source = Source(trace)
    repository = Repository(_prepared(), trace)
    first = _run(repository, source)
    substituted = replace(first, evaluation_sequence=2)
    second_trace: list[str] = []
    second_source = Source(second_trace)
    substituting_repository = Repository(
        _prepared(),
        second_trace,
        persisted=substituted,
    )

    with pytest.raises(DurableTrustedTimeMonitorError, match="substituted"):
        _run(substituting_repository, second_source)

    assert second_trace == ["prepare", "source", "append"]
    assert second_source.calls == 1
    assert substituting_repository.append_calls == 1


def test_repository_attribute_failure_is_sanitized_before_any_probe_effect() -> None:
    source = Source([])

    with pytest.raises(
        DurableTrustedTimeMonitorError,
        match="repository port is unavailable",
    ) as captured:
        _run(ExplodingRepositoryPort(), source)

    assert "secret" not in str(captured.value)
    assert source.calls == 0


def test_session_is_init_disabled_and_persisted_result_has_no_authority() -> None:
    assert DURABLE_TRUSTED_TIME_MONITOR_CONTRACT_VERSION == (
        "phase6a-durable-trusted-time-persistence-v1"
    )
    with pytest.raises(TypeError, match="issued by"):
        DurableTrustedTimeEpochSession()

    persisted = _run(Repository(_prepared(), []), Source([]))

    assert tuple(field.name for field in fields(PersistedTrustedTimeProbe)) == (
        "result",
        "evaluation_sequence",
        "record_sha256",
        "host_head_sha256",
    )
    assert persisted.operational_control_authorized is False
    assert persisted.readiness_authorized is False
    assert persisted.arming_authorized is False
    assert persisted.new_exposure_authorized is False
    assert persisted.broker_action_authorized is False
    assert persisted.automatic_rearm_authorized is False
    assert persisted.automatic_resume_authorized is False


def test_prepared_sequence_one_cannot_resume_a_persisted_prior() -> None:
    trace: list[str] = []
    first = _run(Repository(_prepared(), trace), Source(trace))

    with pytest.raises(DurableTrustedTimeMonitorError, match="sequence conflicts"):
        PreparedTrustedTimeProbe(
            binding=_binding(),
            prior=first.result.state,
            expected_host_head_sha256=NEW_HEAD,
            epoch_registration_sha256=REGISTRATION,
            next_evaluation_sequence=1,
        )
