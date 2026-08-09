from __future__ import annotations

import json
import os
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from apps.trusted_time_supervisor.config import (
    DATABASE_CA_PATH,
    TrustedTimeDeploymentAuthority,
    TrustedTimeSupervisorConfigurationError,
    decode_trusted_time_authority,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorRuntimeConfiguration,
)
from apps.trusted_time_supervisor.head_anchor_worker import (
    TrustedTimeHeadAnchorBackgroundWorker,
    TrustedTimeHeadAnchorBackgroundWorkerError,
)
from apps.trusted_time_supervisor.main import (
    StopAwareBoottimeWaiter,
    _chrony_authority,
    _create_supervisor_database_engine,
    _probe_payload,
    _record_database_secret_consumed,
    _require_fixed_runtime_paths,
    main,
    run_service,
    run_service_with_production_head_anchor,
)
from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorEnrollmentNotApprovedFailure,
    TrustedTimeHeadAnchorFatalReason,
    TrustedTimeHeadAnchorWorkRequest,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.application.trusted_time_supervisor import TrustedTimeSupervisorResult
from packages.domain.trusted_time import evaluate_trusted_time

ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 7, 31, 18, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _released_post_enrollment_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep existing service tests focused beyond the separately tested barrier."""

    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.wait_for_post_enrollment_start_release",
        lambda: None,
    )


def _authority() -> TrustedTimeDeploymentAuthority:
    return decode_trusted_time_authority(
        (ROOT / "infra" / "trusted-time" / "source-authority.json").read_bytes(),
        chrony_config_payload=(ROOT / "infra" / "trusted-time" / "chrony.conf").read_bytes(),
        database_ca_payload=(
            ROOT / "packages" / "persistence" / "certs" / "supabase-prod-ca-2021.crt"
        ).read_bytes(),
    )


def _persisted() -> PersistedTrustedTimeProbe:
    return PersistedTrustedTimeProbe(
        result=TrustedTimeMonitorResult(
            status=TrustedTimeProbeStatus.SOURCE_UNAVAILABLE,
            evaluation=evaluate_trusted_time(
                None,
                None,
                evaluated_at_utc=BASE,
                evaluated_at_monotonic_ns=10,
            ),
        ),
        evaluation_sequence=1,
        record_sha256="a" * 64,
        host_head_sha256="b" * 64,
    )


def test_composition_builds_exact_no_retry_unix_socket_authority() -> None:
    authority = _chrony_authority(_authority())

    assert authority.argv == (
        "/usr/local/bin/chronyc",
        "-h",
        "/run/chrony/chronyd.sock",
        "-c",
        "-N",
        "-e",
        "-m",
        "retries 0",
        "tracking",
        "selectdata -a",
        "authdata -a",
        "ntpdata",
    )
    assert authority.ordered_source_names == (
        "time.cloudflare.com",
        "virginia.time.system76.com",
    )
    assert authority.ordered_ntp_ports == (123, 123)


def test_public_probe_payload_is_bounded_evidence_and_never_authority() -> None:
    payload = _probe_payload(
        _persisted(),
        authority=_authority(),
        monitor_epoch_id="epoch-1",
    )

    assert payload["status"] == "evidence_persisted"
    assert payload["health"] == "blocked"
    assert payload["probe_status"] == "source_unavailable"
    assert payload["sample_sequence"] is None
    for field_name in (
        "alert_delivery_authorized",
        "automatic_rearm_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
    ):
        assert payload[field_name] is False
    assert "database_url" not in payload


def test_waiter_returns_on_due_deadline_or_preexisting_stop_without_sleep() -> None:
    event = threading.Event()
    waiter = StopAwareBoottimeWaiter(stop_event=event, clock=lambda: 100)
    waiter(deadline_monotonic_ns=100)

    event.set()
    calls = 0

    def forbidden_clock() -> int:
        nonlocal calls
        calls += 1
        return 0

    StopAwareBoottimeWaiter(stop_event=event, clock=forbidden_clock)(deadline_monotonic_ns=200)
    assert calls == 0


def test_runtime_paths_reject_environment_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AQT_TRUSTED_TIME_AUTHORITY_PATH", "/tmp/substituted.json")

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="path differs"):
        _require_fixed_runtime_paths()


def test_supervisor_database_engine_bounds_connect_pool_statement_and_lock_waits() -> None:
    engine = Mock()
    database_url = "postgresql+psycopg://user:secret@db.invalid/autoquant?sslmode=verify-full"

    with patch(
        "apps.trusted_time_supervisor.main.create_engine",
        return_value=engine,
    ) as create:
        result = _create_supervisor_database_engine(database_url)

    assert result is engine
    create.assert_called_once_with(
        database_url,
        connect_args={
            "connect_timeout": 3,
            "sslmode": "verify-full",
            "sslrootcert": str(DATABASE_CA_PATH),
            "options": "-c statement_timeout=3000 -c lock_timeout=1000",
        },
        max_overflow=0,
        pool_pre_ping=True,
        pool_size=1,
        pool_timeout=3.0,
    )


def test_service_registers_fresh_epoch_runs_one_durable_probe_and_disposes() -> None:
    authority = _authority()
    engine = Mock()
    repository = Mock()
    session = SimpleNamespace(binding=SimpleNamespace(monitor_epoch_id="fresh-runtime-epoch"))
    repository.register_new_epoch.return_value = session
    source = object()
    persisted = _persisted()
    emitted: list[dict[str, object]] = []

    def fake_scheduler(**dependencies: object) -> TrustedTimeSupervisorResult:
        durable_probe = dependencies["durable_probe"]
        assert callable(durable_probe)
        assert durable_probe() == persisted
        return TrustedTimeSupervisorResult(probe_count=0, last_event=None)

    with (
        patch("apps.trusted_time_supervisor.main.verify_operational_schema") as verify_schema,
        patch(
            "apps.trusted_time_supervisor.main.SqlTrustedTimeRepository",
            return_value=repository,
        ),
        patch(
            "apps.trusted_time_supervisor.main.ChronyNtsTrustedTimeSource",
            return_value=source,
        ) as source_factory,
        patch(
            "apps.trusted_time_supervisor.main.run_durable_trusted_time_probe_once",
            return_value=persisted,
        ) as durable_probe,
        patch(
            "apps.trusted_time_supervisor.main.run_trusted_time_supervisor",
            side_effect=fake_scheduler,
        ),
    ):
        result = run_service(
            authority=authority,
            database_url="postgresql+psycopg://user:secret@db.invalid/autoquant",
            utc_clock=lambda: BASE,
            monotonic_clock=lambda: 10,
            stop_event=threading.Event(),
            emit=emitted.append,
            engine_factory=lambda _: engine,
        )

    assert result == TrustedTimeSupervisorResult(probe_count=0, last_event=None)
    verify_schema.assert_called_once_with(engine, require_phase_zero_facts=False)
    repository.verify_integrity.assert_called_once_with()
    repository.register_new_epoch.assert_called_once_with(
        source_id=authority.source_id,
        source_authority_sha256=authority.source_authority_sha256,
        host_id=authority.host_id,
        recorded_at=BASE,
    )
    source_factory.assert_called_once()
    durable_probe.assert_called_once()
    assert emitted[0]["monitor_epoch_id"] == "fresh-runtime-epoch"
    engine.dispose.assert_called_once_with()


def test_service_starts_anchor_after_epoch_notifies_without_external_io_and_clean_stops() -> None:
    authority = _authority()
    engine = Mock()
    repository = Mock()
    session = SimpleNamespace(binding=SimpleNamespace(monitor_epoch_id="fresh-runtime-epoch"))
    repository.register_new_epoch.return_value = session
    persisted = _persisted()
    requests: list[TrustedTimeHeadAnchorWorkRequest] = []

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        requests.append(request)
        return TrustedTimeHeadAnchorAttemptResult(
            request_sequence=request.request_sequence,
            checkpoint_reason=request.checkpoint_reason,
            current_host_head_sha256="a" * 64,
            current_anchor_sha256="b" * 64,
            current_anchor_semantic_sha256="c" * 64,
            completed_at_utc=BASE,
            full_audit_completed=request.full_audit,
            pending_intent_recovered=False,
            candidate_remote_readback_sha256="d" * 64,
            receipt_semantic_sha256="e" * 64,
        )

    anchor_worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=lambda: 10,
        on_fatal=lambda: None,
    )

    def fake_scheduler(**dependencies: object) -> TrustedTimeSupervisorResult:
        durable_probe = dependencies["durable_probe"]
        assert callable(durable_probe)
        assert durable_probe() == persisted
        return TrustedTimeSupervisorResult(probe_count=0, last_event=None)

    with (
        patch("apps.trusted_time_supervisor.main.verify_operational_schema"),
        patch(
            "apps.trusted_time_supervisor.main.SqlTrustedTimeRepository",
            return_value=repository,
        ),
        patch("apps.trusted_time_supervisor.main.ChronyNtsTrustedTimeSource"),
        patch(
            "apps.trusted_time_supervisor.main.run_durable_trusted_time_probe_once",
            return_value=persisted,
        ),
        patch(
            "apps.trusted_time_supervisor.main.run_trusted_time_supervisor",
            side_effect=fake_scheduler,
        ),
    ):
        run_service(
            authority=authority,
            database_url="postgresql+psycopg://user:secret@db.invalid/autoquant",
            utc_clock=lambda: BASE,
            monotonic_clock=lambda: 10,
            stop_event=threading.Event(),
            emit=lambda _: None,
            engine_factory=lambda _: engine,
            head_anchor_worker=anchor_worker,
        )

    assert [request.checkpoint_reason for request in requests] == [
        TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
    ]
    assert requests[0].full_audit is True
    assert requests[1].full_audit is False
    engine.dispose.assert_called_once_with()


def test_service_cleans_partially_started_anchor_worker_when_start_raises() -> None:
    authority = _authority()
    engine = Mock()
    repository = Mock()
    repository.register_new_epoch.return_value = SimpleNamespace(
        binding=SimpleNamespace(monitor_epoch_id="fresh-runtime-epoch")
    )

    def unused_attempt(
        request: TrustedTimeHeadAnchorWorkRequest,
    ) -> TrustedTimeHeadAnchorAttemptResult:
        return TrustedTimeHeadAnchorAttemptResult(
            request_sequence=request.request_sequence,
            checkpoint_reason=request.checkpoint_reason,
            current_host_head_sha256="a" * 64,
            current_anchor_sha256="b" * 64,
            current_anchor_semantic_sha256="c" * 64,
            completed_at_utc=BASE,
            full_audit_completed=request.full_audit,
            pending_intent_recovered=False,
            candidate_remote_readback_sha256=None,
            receipt_semantic_sha256=None,
        )

    anchor_worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=unused_attempt,
        monotonic_clock=lambda: 10,
        on_fatal=lambda: None,
    )
    with (
        patch("apps.trusted_time_supervisor.main.verify_operational_schema"),
        patch(
            "apps.trusted_time_supervisor.main.SqlTrustedTimeRepository",
            return_value=repository,
        ),
        patch.object(
            TrustedTimeHeadAnchorBackgroundWorker,
            "start",
            side_effect=TrustedTimeHeadAnchorBackgroundWorkerError("start failed"),
        ),
        patch.object(
            TrustedTimeHeadAnchorBackgroundWorker,
            "close",
            return_value=True,
        ) as close,
        pytest.raises(TrustedTimeHeadAnchorBackgroundWorkerError, match="start failed"),
    ):
        run_service(
            authority=authority,
            database_url="postgresql+psycopg://user:secret@db.invalid/autoquant",
            utc_clock=lambda: BASE,
            monotonic_clock=lambda: 10,
            stop_event=threading.Event(),
            emit=lambda _: None,
            engine_factory=lambda _: engine,
            head_anchor_worker=anchor_worker,
        )

    close.assert_called_once_with(clean_stop=False)
    engine.dispose.assert_called_once_with()


def test_service_surfaces_only_typed_unapproved_enrollment_failure() -> None:
    authority = _authority()
    engine = Mock()
    repository = Mock()
    repository.register_new_epoch.return_value = SimpleNamespace(
        binding=SimpleNamespace(monitor_epoch_id="fresh-runtime-epoch")
    )
    fatal = threading.Event()

    def attempt(request: TrustedTimeHeadAnchorWorkRequest) -> TrustedTimeHeadAnchorAttemptResult:
        del request
        raise TrustedTimeHeadAnchorEnrollmentNotApprovedFailure(
            "secret provider response must not cross the service boundary"
        )

    anchor_worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=attempt,
        monotonic_clock=lambda: 10,
        on_fatal=fatal.set,
    )

    def fake_scheduler(**dependencies: object) -> TrustedTimeSupervisorResult:
        del dependencies
        assert fatal.wait(timeout=1)
        return TrustedTimeSupervisorResult(probe_count=0, last_event=None)

    with (
        patch("apps.trusted_time_supervisor.main.verify_operational_schema"),
        patch(
            "apps.trusted_time_supervisor.main.SqlTrustedTimeRepository",
            return_value=repository,
        ),
        patch("apps.trusted_time_supervisor.main.ChronyNtsTrustedTimeSource"),
        patch(
            "apps.trusted_time_supervisor.main.run_trusted_time_supervisor",
            side_effect=fake_scheduler,
        ),
        pytest.raises(TrustedTimeHeadAnchorEnrollmentNotApprovedFailure) as captured,
    ):
        run_service(
            authority=authority,
            database_url="postgresql+psycopg://user:secret@db.invalid/autoquant",
            utc_clock=lambda: BASE,
            monotonic_clock=lambda: 10,
            stop_event=threading.Event(),
            emit=lambda _: None,
            engine_factory=lambda _: engine,
            head_anchor_worker=anchor_worker,
        )

    assert str(captured.value) == (
        "trusted-time remote anchor history is absent and enrollment is not approved"
    )
    assert "provider response" not in str(captured.value)
    assert anchor_worker.fatal_reason is (
        TrustedTimeHeadAnchorFatalReason.REMOTE_HISTORY_ABSENT_ENROLLMENT_NOT_APPROVED
    )
    engine.dispose.assert_called_once_with()


def test_service_preserves_typed_failure_that_latches_during_clean_close() -> None:
    authority = _authority()
    engine = Mock()
    repository = Mock()
    repository.register_new_epoch.return_value = SimpleNamespace(
        binding=SimpleNamespace(monitor_epoch_id="fresh-runtime-epoch")
    )

    def unused_attempt(
        request: TrustedTimeHeadAnchorWorkRequest,
    ) -> TrustedTimeHeadAnchorAttemptResult:
        raise AssertionError(request)

    anchor_worker = TrustedTimeHeadAnchorBackgroundWorker(
        attempt=unused_attempt,
        monotonic_clock=lambda: 10,
        on_fatal=lambda: None,
    )

    def latch_during_close(*_: object, **__: object) -> bool:
        anchor_worker._fatal_reason = (
            TrustedTimeHeadAnchorFatalReason.REMOTE_HISTORY_ABSENT_ENROLLMENT_NOT_APPROVED
        )
        anchor_worker._fatal_event.set()
        return False

    with (
        patch("apps.trusted_time_supervisor.main.verify_operational_schema"),
        patch(
            "apps.trusted_time_supervisor.main.SqlTrustedTimeRepository",
            return_value=repository,
        ),
        patch("apps.trusted_time_supervisor.main.ChronyNtsTrustedTimeSource"),
        patch(
            "apps.trusted_time_supervisor.main.run_trusted_time_supervisor",
            return_value=TrustedTimeSupervisorResult(probe_count=0, last_event=None),
        ),
        patch.object(TrustedTimeHeadAnchorBackgroundWorker, "prime_startup"),
        patch.object(TrustedTimeHeadAnchorBackgroundWorker, "start"),
        patch.object(
            TrustedTimeHeadAnchorBackgroundWorker,
            "close",
            side_effect=latch_during_close,
        ) as close,
        pytest.raises(TrustedTimeHeadAnchorEnrollmentNotApprovedFailure),
    ):
        run_service(
            authority=authority,
            database_url="postgresql+psycopg://user:secret@db.invalid/autoquant",
            utc_clock=lambda: BASE,
            monotonic_clock=lambda: 10,
            stop_event=threading.Event(),
            emit=lambda _: None,
            engine_factory=lambda _: engine,
            head_anchor_worker=anchor_worker,
        )

    close.assert_called_once_with(clean_stop=True)
    engine.dispose.assert_called_once_with()


def test_production_head_anchor_uses_separate_resources_and_closes_after_join() -> None:
    authority = _authority()
    anchor_authority = SimpleNamespace(
        anchor_authority_sha256="a" * 64,
        host_id=authority.host_id,
        signing_key_id="trusted-time-anchor-key-v1",
        signing_public_key_sha256="b" * 64,
        source_authority_sha256=authority.source_authority_sha256,
    )
    configuration = object.__new__(TrustedTimeHeadAnchorRuntimeConfiguration)
    object.__setattr__(configuration, "authority", anchor_authority)
    object.__setattr__(configuration, "credentials", object())
    object.__setattr__(configuration, "signer", object())
    object.__setattr__(configuration, "verifier", object())
    anchor_engine = Mock(name="head-anchor-engine")
    anchor_repository = Mock(name="head-anchor-repository")
    provider = Mock(name="head-anchor-provider")
    attempt = Mock(name="head-anchor-attempt")
    worker = Mock(name="head-anchor-worker")
    worker.close.return_value = True
    result = TrustedTimeSupervisorResult(probe_count=0, last_event=None)
    stop_event = threading.Event()
    cleanup = Mock()
    cleanup.attach_mock(worker.close, "worker_close")
    cleanup.attach_mock(attempt.close, "attempt_close")
    cleanup.attach_mock(provider.close, "provider_close")
    cleanup.attach_mock(anchor_engine.dispose, "engine_dispose")

    with (
        patch("apps.trusted_time_supervisor.main.verify_operational_schema") as verify_schema,
        patch(
            "apps.trusted_time_supervisor.main.SqlTrustedTimeHeadAnchorRepository",
            return_value=anchor_repository,
        ) as anchor_factory,
        patch(
            "apps.trusted_time_supervisor.main.SupabaseStorageTrustedTimeAnchorProvider",
            return_value=provider,
        ) as provider_factory,
        patch(
            "apps.trusted_time_supervisor.main.RepositoryBackedTrustedTimeHeadAnchorAttempt",
            return_value=attempt,
        ) as attempt_factory,
        patch(
            "apps.trusted_time_supervisor.main.TrustedTimeHeadAnchorBackgroundWorker",
            return_value=worker,
        ) as worker_factory,
        patch(
            "apps.trusted_time_supervisor.main.run_service",
            return_value=result,
        ) as local_service,
    ):
        actual = run_service_with_production_head_anchor(
            authority=authority,
            database_url="postgresql+psycopg://user:secret@db.invalid/autoquant",
            head_anchor_configuration=configuration,
            utc_clock=lambda: BASE,
            monotonic_clock=lambda: 10,
            stop_event=stop_event,
            emit=lambda _: None,
            anchor_engine_factory=lambda _: anchor_engine,
        )

    assert actual == result
    verify_schema.assert_called_once_with(
        anchor_engine,
        require_phase_zero_facts=False,
    )
    anchor_factory.assert_called_once_with(
        anchor_engine,
        verifier=configuration.verifier,
        anchor_authority_sha256="a" * 64,
        signing_key_id="trusted-time-anchor-key-v1",
        signing_public_key_sha256="b" * 64,
    )
    provider_factory.assert_called_once_with(credentials=configuration.credentials)
    attempt_factory.assert_called_once_with(
        anchor_repository=anchor_repository,
        provider=provider,
        signer=configuration.signer,
        verifier=configuration.verifier,
        authority=anchor_authority,
        utc_clock=local_service.call_args.kwargs["utc_clock"],
    )
    assert worker_factory.call_args.kwargs["allow_enrollment"] is False
    assert worker_factory.call_args.kwargs["startup_primer"] is attempt.prime_startup
    fatal_callback = worker_factory.call_args.kwargs["on_fatal"]
    assert callable(fatal_callback)
    fatal_callback()
    assert stop_event.is_set() is True
    assert local_service.call_args.kwargs["head_anchor_worker"] is worker
    assert cleanup.mock_calls == [
        call.worker_close(timeout_seconds=0, clean_stop=False),
        call.attempt_close(),
        call.provider_close(),
        call.engine_dispose(),
    ]


def test_main_sanitizes_configuration_failure_without_echoing_detail(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch(
            "apps.trusted_time_supervisor.main.load_trusted_time_authority",
            side_effect=TrustedTimeSupervisorConfigurationError(
                "secret database and socket detail"
            ),
        ),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert payload["status"] == "fatal"
    assert payload["reason"] == "configuration_rejected"
    assert "secret" not in output.out
    assert output.err == ""


def test_main_waits_after_input_consumption_and_before_runtime_composition(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority = _authority()
    configuration = object.__new__(TrustedTimeHeadAnchorRuntimeConfiguration)
    events: list[str] = []
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main._require_fixed_runtime_paths",
        lambda: events.append("fixed_paths"),
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.load_trusted_time_authority",
        lambda: events.append("authority") or authority,
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.load_database_url_secret",
        lambda: events.append("database_secret") or "postgresql+psycopg://db/runtime",
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.load_trusted_time_head_anchor_runtime_configuration",
        lambda **_: events.append("anchor_inputs") or configuration,
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main._record_database_secret_consumed",
        lambda: events.append("inputs_consumed"),
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.wait_for_post_enrollment_start_release",
        lambda: events.append("release"),
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main._install_stop_handlers",
        lambda _: events.append("handlers") or {},
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.run_service_with_production_head_anchor",
        lambda **_: (
            events.append("runtime") or TrustedTimeSupervisorResult(probe_count=0, last_event=None)
        ),
    )

    main()

    assert events == [
        "fixed_paths",
        "authority",
        "database_secret",
        "anchor_inputs",
        "inputs_consumed",
        "release",
        "handlers",
        "runtime",
    ]
    assert json.loads(capsys.readouterr().out)["status"] == "stopped"


def test_release_failure_prevents_every_runtime_mutation_and_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority = _authority()
    configuration = object.__new__(TrustedTimeHeadAnchorRuntimeConfiguration)
    consumed = Mock()
    runtime = Mock(side_effect=AssertionError("runtime crossed release barrier"))
    handlers = Mock(side_effect=AssertionError("handlers installed before release"))
    monkeypatch.setattr("apps.trusted_time_supervisor.main._require_fixed_runtime_paths", Mock())
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.load_trusted_time_authority",
        Mock(return_value=authority),
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.load_database_url_secret",
        Mock(return_value="postgresql+psycopg://db/runtime"),
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.load_trusted_time_head_anchor_runtime_configuration",
        Mock(return_value=configuration),
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main._record_database_secret_consumed",
        consumed,
    )
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.wait_for_post_enrollment_start_release",
        Mock(side_effect=TrustedTimeSupervisorConfigurationError("secret marker tamper detail")),
    )
    monkeypatch.setattr("apps.trusted_time_supervisor.main._install_stop_handlers", handlers)
    monkeypatch.setattr(
        "apps.trusted_time_supervisor.main.run_service_with_production_head_anchor",
        runtime,
    )

    with pytest.raises(SystemExit) as captured:
        main()

    assert captured.value.code == 2
    consumed.assert_called_once_with()
    handlers.assert_not_called()
    runtime.assert_not_called()
    output = capsys.readouterr()
    assert json.loads(output.out)["reason"] == "configuration_rejected"
    assert "secret" not in output.out
    assert output.err == ""


@pytest.mark.parametrize(
    ("failure", "expected_reason"),
    [
        (
            TrustedTimeHeadAnchorEnrollmentNotApprovedFailure(
                "secret provider response must not reach the terminal payload"
            ),
            "head_anchor_remote_history_absent_enrollment_not_approved",
        ),
        (RuntimeError("secret unclassified runtime detail"), "supervision_failed"),
    ],
)
def test_main_emits_only_fixed_supervision_failure_reasons(
    failure: Exception,
    expected_reason: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority = _authority()
    configuration = object.__new__(TrustedTimeHeadAnchorRuntimeConfiguration)
    with (
        patch("apps.trusted_time_supervisor.main._require_fixed_runtime_paths"),
        patch(
            "apps.trusted_time_supervisor.main.load_trusted_time_authority",
            return_value=authority,
        ),
        patch(
            "apps.trusted_time_supervisor.main.load_database_url_secret",
            return_value="postgresql+psycopg://runtime.example/database",
        ),
        patch(
            "apps.trusted_time_supervisor.main.load_trusted_time_head_anchor_runtime_configuration",
            return_value=configuration,
        ),
        patch("apps.trusted_time_supervisor.main._record_database_secret_consumed"),
        patch("apps.trusted_time_supervisor.main._install_stop_handlers", return_value={}),
        patch(
            "apps.trusted_time_supervisor.main.run_service_with_production_head_anchor",
            side_effect=failure,
        ),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert payload["status"] == "fatal"
    assert payload["reason"] == expected_reason
    assert payload["operational_control_authorized"] is False
    assert payload["new_exposure_authorized"] is False
    assert payload["live_trading_authorized"] is False
    assert "secret" not in output.out
    assert output.err == ""


def test_main_requires_runtime_uid_for_all_file_backed_head_anchor_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority = _authority()
    configuration = object.__new__(TrustedTimeHeadAnchorRuntimeConfiguration)
    with (
        patch("apps.trusted_time_supervisor.main._require_fixed_runtime_paths"),
        patch(
            "apps.trusted_time_supervisor.main.load_trusted_time_authority",
            return_value=authority,
        ),
        patch(
            "apps.trusted_time_supervisor.main.load_database_url_secret",
            return_value="postgresql+psycopg://runtime.example/database",
        ),
        patch(
            "apps.trusted_time_supervisor.main.load_trusted_time_head_anchor_runtime_configuration",
            return_value=configuration,
        ) as load_head_anchor,
        patch("apps.trusted_time_supervisor.main._record_database_secret_consumed"),
        patch("apps.trusted_time_supervisor.main._install_stop_handlers", return_value={}),
        patch(
            "apps.trusted_time_supervisor.main.run_service_with_production_head_anchor",
            return_value=TrustedTimeSupervisorResult(probe_count=0, last_event=None),
        ),
    ):
        main()

    load_head_anchor.assert_called_once_with(
        database_url="postgresql+psycopg://runtime.example/database",
        expected_host_id=authority.host_id,
        expected_source_authority_sha256=authority.source_authority_sha256,
        authority_owner_uid=os.geteuid(),
        secret_owner_uid=os.geteuid(),
    )
    assert json.loads(capsys.readouterr().out)["status"] == "stopped"


def test_database_secret_consumption_marker_is_exact_owner_only_and_one_shot(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "database-secret-consumed"
    with patch(
        "apps.trusted_time_supervisor.main.DATABASE_SECRET_CONSUMED_PATH",
        str(marker),
    ):
        _record_database_secret_consumed()
        with pytest.raises(
            TrustedTimeSupervisorConfigurationError,
            match="consumption marker failed",
        ):
            _record_database_secret_consumed()

    assert marker.read_bytes() == b"phase6c-database-secret-consumed-v1\n"
    assert marker.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(marker.stat().st_mode) == 0o400
