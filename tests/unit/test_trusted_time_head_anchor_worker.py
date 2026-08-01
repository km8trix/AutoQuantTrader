from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from apps.trusted_time_supervisor.head_anchor_worker import (
    TrustedTimeHeadAnchorBackgroundWorker,
    TrustedTimeHeadAnchorBackgroundWorkerError,
)
from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_worker import (
    TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS,
    TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS,
    TRUSTED_TIME_HEAD_ANCHOR_WORKER_STALE_AFTER_NS,
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorTransientFailure,
    TrustedTimeHeadAnchorWorkerCore,
    TrustedTimeHeadAnchorWorkerStatus,
    TrustedTimeHeadAnchorWorkRequest,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.domain.trusted_time import (
    TrustedTimeSample,
    TrustedTimeState,
    evaluate_trusted_time,
)

BASE = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
SECOND_NS = 1_000_000_000


def _attempt_result(
    request: TrustedTimeHeadAnchorWorkRequest,
    *,
    at_utc: datetime = BASE,
    candidate: bool = True,
) -> TrustedTimeHeadAnchorAttemptResult:
    return TrustedTimeHeadAnchorAttemptResult(
        request_sequence=request.request_sequence,
        checkpoint_reason=request.checkpoint_reason,
        current_host_head_sha256="a" * 64,
        current_anchor_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        completed_at_utc=at_utc,
        full_audit_completed=request.full_audit,
        pending_intent_recovered=False,
        candidate_remote_readback_sha256="d" * 64 if candidate else None,
        receipt_semantic_sha256="e" * 64 if candidate else None,
    )


def _sample(
    *,
    second: int,
    sequence: int,
    offset_microseconds: int = 0,
) -> TrustedTimeSample:
    instant = BASE + timedelta(seconds=second)
    return TrustedTimeSample(
        source_id="source",
        source_authority_sha256="1" * 64,
        host_id="host",
        monitor_epoch_id="epoch",
        sequence=sequence,
        source_evidence_sha256="2" * 64,
        probe_started_at_utc=instant,
        probe_completed_at_utc=instant,
        trusted_at_utc=instant + timedelta(microseconds=offset_microseconds),
        source_uncertainty_milliseconds=Decimal("0"),
        probe_started_monotonic_ns=second * SECOND_NS,
        probe_completed_monotonic_ns=second * SECOND_NS,
    )


def _persisted(
    prior: TrustedTimeState | None,
    sample: TrustedTimeSample | None,
    *,
    second: int,
    sequence: int,
) -> tuple[PersistedTrustedTimeProbe, TrustedTimeState]:
    evaluation = evaluate_trusted_time(
        prior,
        sample,
        evaluated_at_utc=BASE + timedelta(seconds=second),
        evaluated_at_monotonic_ns=second * SECOND_NS,
    )
    status = (
        TrustedTimeProbeStatus.SOURCE_UNAVAILABLE
        if sample is None
        else TrustedTimeProbeStatus.RECORDED
    )
    return (
        PersistedTrustedTimeProbe(
            result=TrustedTimeMonitorResult(status=status, evaluation=evaluation),
            evaluation_sequence=sequence,
            record_sha256=f"{sequence % 10}" * 64,
            host_head_sha256=f"{(sequence + 1) % 10}" * 64,
        ),
        evaluation.state,
    )


def _complete_startup(
    core: TrustedTimeHeadAnchorWorkerCore,
    *,
    at: int,
) -> TrustedTimeHeadAnchorWorkRequest:
    request = core.take_work(observed_at_monotonic_ns=at)
    assert request is not None
    assert request.full_audit is True
    core.record_success(
        request,
        _attempt_result(request),
        observed_at_monotonic_ns=at,
    )
    return request


def test_startup_is_one_full_audit_and_evidence_stales_at_exact_bound() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=100)

    request = _complete_startup(core, at=100)

    assert request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
    fresh = core.evidence(
        observed_at_monotonic_ns=100 + TRUSTED_TIME_HEAD_ANCHOR_WORKER_STALE_AFTER_NS - 1
    )
    stale = core.evidence(
        observed_at_monotonic_ns=100 + TRUSTED_TIME_HEAD_ANCHOR_WORKER_STALE_AFTER_NS
    )
    assert fresh.status is TrustedTimeHeadAnchorWorkerStatus.CURRENT
    assert fresh.external_head_anchor_evidence is True
    assert stale.status is TrustedTimeHeadAnchorWorkerStatus.UNAVAILABLE
    assert stale.external_head_anchor_evidence is False
    for field_name in (
        "operational_control_authorized",
        "readiness_authorized",
        "arming_authorized",
        "new_exposure_authorized",
        "broker_action_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "alert_delivery_authorized",
        "exposure_authorized",
        "paper_trading_authorized",
        "live_trading_authorized",
    ):
        assert getattr(fresh, field_name) is False


def test_explicit_enrollment_is_the_exact_one_shot_startup_reason() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(
        started_at_monotonic_ns=0,
        allow_enrollment=True,
    )

    request = core.take_work(observed_at_monotonic_ns=0)

    assert request is not None
    assert request.full_audit is True
    assert request.allow_enrollment is True
    assert request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT


def test_on_demand_is_an_explicit_full_audit_but_never_reopens_enrollment() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(
        started_at_monotonic_ns=0,
        allow_enrollment=True,
    )
    _complete_startup(core, at=0)
    core.request_on_demand(observed_at_monotonic_ns=1)

    request = core.take_work(observed_at_monotonic_ns=1)

    assert request is not None
    assert request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ON_DEMAND
    assert request.full_audit is True
    assert request.allow_enrollment is False


def test_periodic_deadlines_remain_on_absolute_grid_and_skip_catch_up() -> None:
    start = 1_000
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=start)
    _complete_startup(core, at=start)

    assert (
        core.take_work(
            observed_at_monotonic_ns=(start + TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS - 1)
        )
        is None
    )
    late = start + 3 * TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS + 7
    periodic = core.take_work(observed_at_monotonic_ns=late)
    assert periodic is not None
    assert periodic.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.PERIODIC
    assert periodic.scheduled_monotonic_ns == (start + TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS)
    core.record_success(
        periodic,
        _attempt_result(periodic),
        observed_at_monotonic_ns=late,
    )
    assert (
        core.take_work(
            observed_at_monotonic_ns=(start + 4 * TRUSTED_TIME_HEAD_ANCHOR_WORKER_INTERVAL_NS - 1)
        )
        is None
    )


def test_success_rejects_checkpoint_reason_substitution() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    request = core.take_work(observed_at_monotonic_ns=0)
    assert request is not None
    substituted = TrustedTimeHeadAnchorAttemptResult(
        request_sequence=request.request_sequence,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ON_DEMAND,
        current_host_head_sha256="a" * 64,
        current_anchor_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        completed_at_utc=BASE,
        full_audit_completed=True,
        pending_intent_recovered=False,
        candidate_remote_readback_sha256=None,
        receipt_semantic_sha256=None,
    )

    with pytest.raises(Exception, match="conflicts with its request"):
        core.record_success(request, substituted, observed_at_monotonic_ns=0)


def test_transient_startup_failure_latches_false_and_retries_before_later_events() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    startup = core.take_work(observed_at_monotonic_ns=0)
    assert startup is not None
    core.record_transient_failure(startup, observed_at_monotonic_ns=1)
    core.request_epoch_rotation(observed_at_monotonic_ns=2)

    unavailable = core.evidence(observed_at_monotonic_ns=2)
    assert unavailable.status is TrustedTimeHeadAnchorWorkerStatus.UNAVAILABLE
    assert unavailable.external_head_anchor_evidence is False
    assert (
        core.take_work(
            observed_at_monotonic_ns=(1 + TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS - 1)
        )
        is None
    )

    retried = core.take_work(
        observed_at_monotonic_ns=1 + TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS
    )
    assert retried is not None
    assert retried.full_audit is True
    assert retried.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
    core.record_success(
        retried,
        _attempt_result(retried),
        observed_at_monotonic_ns=1 + TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS,
    )
    duplicate_epoch = core.take_work(
        observed_at_monotonic_ns=1 + TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS
    )
    assert duplicate_epoch is None


def test_probe_notifications_select_hard_health_and_recovery_transitions() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    _complete_startup(core, at=0)
    blocked, blocked_state = _persisted(None, None, second=0, sequence=1)
    core.observe_persisted_probe(blocked, observed_at_monotonic_ns=1)
    assert core.take_work(observed_at_monotonic_ns=1) is None

    hard, _hard_state = _persisted(
        blocked_state,
        _sample(second=30, sequence=1, offset_microseconds=1_100_000),
        second=30,
        sequence=2,
    )
    core.observe_persisted_probe(hard, observed_at_monotonic_ns=2)
    hard_request = core.take_work(observed_at_monotonic_ns=2)
    assert hard_request is not None
    assert hard_request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.HARD_FAILURE
    core.record_success(
        hard_request,
        _attempt_result(hard_request),
        observed_at_monotonic_ns=2,
    )

    # A fresh epoch can recover from blocked through warning/healthy states.
    warning, warning_state = _persisted(
        None,
        _sample(second=60, sequence=1, offset_microseconds=300_000),
        second=60,
        sequence=1,
    )
    core.observe_persisted_probe(warning, observed_at_monotonic_ns=3)
    health_request = core.take_work(observed_at_monotonic_ns=3)
    assert health_request is not None
    assert health_request.checkpoint_reason is (
        TrustedTimeHeadAnchorCheckpointReason.HEALTH_TRANSITION
    )
    core.record_success(
        health_request,
        _attempt_result(health_request),
        observed_at_monotonic_ns=3,
    )

    healthy_one, healthy_state = _persisted(
        warning_state,
        _sample(second=90, sequence=2),
        second=90,
        sequence=2,
    )
    core.observe_persisted_probe(healthy_one, observed_at_monotonic_ns=4)
    transition = core.take_work(observed_at_monotonic_ns=4)
    assert transition is not None
    assert transition.checkpoint_reason is (TrustedTimeHeadAnchorCheckpointReason.HEALTH_TRANSITION)
    core.record_success(
        transition,
        _attempt_result(transition),
        observed_at_monotonic_ns=4,
    )

    prior = healthy_state
    for index, second in enumerate((120, 150, 180, 210), start=3):
        persisted, prior = _persisted(
            prior,
            _sample(second=second, sequence=index),
            second=second,
            sequence=index,
        )
        core.observe_persisted_probe(
            persisted,
            observed_at_monotonic_ns=second,
        )
    recovery = core.take_work(observed_at_monotonic_ns=210)
    assert recovery is not None
    assert recovery.checkpoint_reason is (TrustedTimeHeadAnchorCheckpointReason.RECOVERY_TRANSITION)


def test_clean_stop_is_one_terminal_attempt_and_transient_failure_does_not_retry() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    _complete_startup(core, at=0)
    core.request_epoch_rotation(observed_at_monotonic_ns=1)
    core.request_clean_stop(observed_at_monotonic_ns=2)

    clean = core.take_work(observed_at_monotonic_ns=2)
    assert clean is not None
    assert clean.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
    core.record_transient_failure(clean, observed_at_monotonic_ns=3)

    evidence = core.evidence(observed_at_monotonic_ns=3)
    assert evidence.status is TrustedTimeHeadAnchorWorkerStatus.STOPPED
    assert evidence.clean_shutdown_completed is False
    assert evidence.external_head_anchor_evidence is False
    assert core.take_work(observed_at_monotonic_ns=10**12) is None


class _Clock:
    def __init__(self) -> None:
        self.value = 0
        self._lock = threading.Lock()

    def __call__(self) -> int:
        with self._lock:
            return self.value

    def advance(self, value: int) -> None:
        with self._lock:
            self.value = value


def test_background_notification_never_waits_for_inflight_external_attempt() -> None:
    clock = _Clock()
    attempt_started = threading.Event()
    release_attempt = threading.Event()
    attempt_finished = threading.Event()

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        attempt_started.set()
        assert release_attempt.wait(timeout=2)
        attempt_finished.set()
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=lambda: None,
    )
    worker.start()
    assert attempt_started.wait(timeout=1)
    persisted, _ = _persisted(None, None, second=0, sequence=1)

    notified = threading.Event()

    def notify() -> None:
        worker.notify_persisted_probe(persisted)
        notified.set()

    notifier = threading.Thread(target=notify)
    notifier.start()
    assert notified.wait(timeout=0.2)
    assert attempt_finished.is_set() is False
    release_attempt.set()
    notifier.join(timeout=1)
    assert worker.close(timeout_seconds=1, clean_stop=False) is True


def test_background_start_requires_explicit_local_prime_when_primer_is_bound() -> None:
    clock = _Clock()
    attempt_started = threading.Event()
    primed: list[str] = []

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        attempt_started.set()
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=lambda: None,
        startup_primer=lambda: primed.append("local_sql_authenticated"),
    )

    with pytest.raises(TrustedTimeHeadAnchorBackgroundWorkerError, match="not primed"):
        worker.start()
    assert attempt_started.is_set() is False

    worker.prime_startup()
    assert primed == ["local_sql_authenticated"]
    assert attempt_started.is_set() is False
    worker.start()
    assert attempt_started.wait(timeout=1)
    assert worker.close(timeout_seconds=1, clean_stop=False) is True


def test_background_primer_failure_latches_fatal_before_thread_or_remote_attempt() -> None:
    fatal = threading.Event()
    attempt_called = False

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        nonlocal attempt_called
        attempt_called = True
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=lambda: 0,
        on_fatal=fatal.set,
        startup_primer=lambda: (_ for _ in ()).throw(RuntimeError("local detail")),
    )

    with pytest.raises(
        TrustedTimeHeadAnchorBackgroundWorkerError,
        match="startup authentication failed",
    ):
        worker.prime_startup()
    assert fatal.is_set() is True
    assert worker.fatal_error_latched is True
    assert attempt_called is False


def test_background_worker_is_single_flight_and_orders_startup_before_on_demand() -> None:
    clock = _Clock()
    first_started = threading.Event()
    release_first = threading.Event()
    second_finished = threading.Event()
    requests: list[TrustedTimeHeadAnchorWorkRequest] = []
    concurrent = 0
    maximum_concurrent = 0
    lock = threading.Lock()

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        nonlocal concurrent, maximum_concurrent
        with lock:
            requests.append(request)
            concurrent += 1
            maximum_concurrent = max(maximum_concurrent, concurrent)
        if len(requests) == 1:
            first_started.set()
            assert release_first.wait(timeout=2)
        with lock:
            concurrent -= 1
        if len(requests) >= 2:
            second_finished.set()
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=lambda: None,
    )
    worker.start()
    assert first_started.wait(timeout=1)
    worker.request_on_demand()
    worker.request_on_demand()
    release_first.set()
    assert second_finished.wait(timeout=1)
    assert [request.checkpoint_reason for request in requests[:2]] == [
        TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        TrustedTimeHeadAnchorCheckpointReason.ON_DEMAND,
    ]
    assert requests[0].full_audit is True
    assert requests[1].full_audit is True
    assert maximum_concurrent == 1
    assert worker.close(timeout_seconds=1, clean_stop=False) is True


def test_background_transient_failure_retries_without_fatal_callback() -> None:
    clock = _Clock()
    first_failed = threading.Event()
    second_finished = threading.Event()
    fatal = threading.Event()
    attempts = 0

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            first_failed.set()
            raise TrustedTimeHeadAnchorTransientFailure("sanitized outage")
        second_finished.set()
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=fatal.set,
    )
    worker.start()
    assert first_failed.wait(timeout=1)
    clock.advance(TRUSTED_TIME_HEAD_ANCHOR_WORKER_RETRY_INTERVAL_NS)
    worker.request_on_demand()
    assert second_finished.wait(timeout=1)
    assert fatal.is_set() is False
    assert worker.fatal_error_latched is False
    assert worker.close(timeout_seconds=1, clean_stop=False) is True


@pytest.mark.parametrize(
    "failure",
    [TrustedTimeHeadAnchorFatalFailure("fork"), RuntimeError("unknown")],
)
def test_background_integrity_or_unknown_failure_latches_fatal(
    failure: Exception,
) -> None:
    clock = _Clock()
    fatal = threading.Event()

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        del request
        raise failure

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=fatal.set,
    )
    worker.start()
    assert fatal.wait(timeout=1)
    assert worker.fatal_error_latched is True
    evidence = worker.evidence()
    assert evidence.status is TrustedTimeHeadAnchorWorkerStatus.FATAL
    assert evidence.external_head_anchor_evidence is False
    assert worker.close(timeout_seconds=1) is False


def test_background_shutdown_returns_at_bound_while_attempt_is_blocked() -> None:
    clock = _Clock()
    started = threading.Event()
    release = threading.Event()

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        started.set()
        assert release.wait(timeout=2)
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=lambda: None,
    )
    worker.start()
    assert started.wait(timeout=1)
    assert worker.close(timeout_seconds=0) is False
    release.set()
    assert worker.close(timeout_seconds=1, clean_stop=False) is True


def test_background_monotonic_regression_latches_but_keeps_fatal_evidence_readable() -> None:
    clock = _Clock()
    clock.advance(100)
    started = threading.Event()
    release = threading.Event()
    fatal = threading.Event()

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        started.set()
        assert release.wait(timeout=2)
        return _attempt_result(request)

    worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=clock,
        on_fatal=fatal.set,
    )
    worker.start()
    assert started.wait(timeout=1)
    clock.advance(50)

    evidence = worker.evidence()

    assert fatal.wait(timeout=1)
    assert evidence.status is TrustedTimeHeadAnchorWorkerStatus.FATAL
    assert evidence.observed_at_monotonic_ns == 100
    assert evidence.external_head_anchor_evidence is False
    release.set()
    assert worker.close(timeout_seconds=1, clean_stop=False) is True
