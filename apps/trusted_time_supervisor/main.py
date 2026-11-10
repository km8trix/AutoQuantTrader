"""Evidence-only local Chrony/NTS trusted-time persistence supervisor."""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from types import FrameType
from typing import cast

from sqlalchemy import Engine, create_engine

from apps.trusted_time_supervisor.config import (
    AUTHORITY_PATH,
    CHRONY_CONFIG_PATH,
    DATABASE_CA_PATH,
    DATABASE_URL_EXPECTED_SHA256_ENVIRONMENT,
    DATABASE_URL_SECRET_PATH,
    TrustedTimeDeploymentAuthority,
    TrustedTimeSupervisorConfigurationError,
    load_database_url_secret,
    load_trusted_time_authority,
)
from apps.trusted_time_supervisor.head_anchor_attempt import (
    DeadlineBoundTrustedTimeHeadAnchorProvider,
    RepositoryBackedTrustedTimeHeadAnchorAttempt,
    TrustedTimeHeadAnchorStartupEffectDeadlineGuard,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_EXPECTED_SHA256_ENVIRONMENT,
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_PATH,
    TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_EXPECTED_SHA256_ENVIRONMENT,
    TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH,
    TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_EXPECTED_SHA256_ENVIRONMENT,
    TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_PATH,
    TrustedTimeHeadAnchorRuntimeConfiguration,
    load_trusted_time_head_anchor_runtime_configuration,
)
from apps.trusted_time_supervisor.head_anchor_worker import (
    TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS,
    TrustedTimeHeadAnchorBackgroundWorker,
    TrustedTimeHeadAnchorBackgroundWorkerError,
)
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS,
    read_exact_post_enrollment_start_sequence_two_deadline,
    wait_for_post_enrollment_start_release,
)
from apps.trusted_time_supervisor.post_enrollment_sequence_two_ready import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_NANOSECONDS,
    write_post_enrollment_start_sequence_two_ready,
)
from packages.adapters.trusted_time import (
    ChronyNtsAuthority,
    ChronyNtsTrustedTimeSource,
    SupabaseStorageTrustedTimeAnchorProvider,
)
from packages.application.durable_trusted_time_monitor import (
    PersistedTrustedTimeProbe,
    run_durable_trusted_time_probe_once,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorEnrollmentNotApprovedFailure,
    TrustedTimeHeadAnchorFatalReason,
)
from packages.application.trusted_time_supervisor import (
    TRUSTED_TIME_SUPERVISOR_INTERVAL_NS,
    TrustedTimeSupervisorError,
    TrustedTimeSupervisorResult,
    run_trusted_time_supervisor,
)
from packages.persistence.database import verify_operational_schema
from packages.persistence.trusted_time import SqlTrustedTimeRepository
from packages.persistence.trusted_time_head_anchor import (
    SqlTrustedTimeHeadAnchorRepository,
)

_PATH_ENVIRONMENT = {
    "AQT_TRUSTED_TIME_AUTHORITY_PATH": AUTHORITY_PATH,
    "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH": CHRONY_CONFIG_PATH,
    "AQT_TRUSTED_TIME_DATABASE_URL_FILE": DATABASE_URL_SECRET_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH": (TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH),
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE": (TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_PATH),
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE": (
        TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_PATH
    ),
}
_WAIT_POLL_SECONDS = 1.0
_DATABASE_CONNECT_TIMEOUT_SECONDS = 3
_DATABASE_POOL_SIZE = 1
_DATABASE_MAX_OVERFLOW = 0
_DATABASE_POOL_TIMEOUT_SECONDS = 3.0
_DATABASE_STATEMENT_TIMEOUT_MILLISECONDS = 3_000
_DATABASE_LOCK_TIMEOUT_MILLISECONDS = 1_000
DATABASE_SECRET_CONSUMED_PATH = "/tmp/database-secret-consumed"
DATABASE_SECRET_CONSUMED_BYTES = b"phase6c-database-secret-consumed-v1\n"
_EXPECTED_STAGED_INPUT_SHA256_ENVIRONMENT = (
    DATABASE_URL_EXPECTED_SHA256_ENVIRONMENT,
    TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_EXPECTED_SHA256_ENVIRONMENT,
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_EXPECTED_SHA256_ENVIRONMENT,
    TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_EXPECTED_SHA256_ENVIRONMENT,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _create_supervisor_database_engine(database_url: str) -> Engine:
    """Create the PostgreSQL engine with hard per-operation wait bounds."""

    return create_engine(
        database_url,
        connect_args={
            "connect_timeout": _DATABASE_CONNECT_TIMEOUT_SECONDS,
            "sslmode": "verify-full",
            "sslrootcert": str(DATABASE_CA_PATH),
            "options": (
                f"-c statement_timeout={_DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                f"-c lock_timeout={_DATABASE_LOCK_TIMEOUT_MILLISECONDS}"
            ),
        },
        max_overflow=_DATABASE_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_size=_DATABASE_POOL_SIZE,
        pool_timeout=_DATABASE_POOL_TIMEOUT_SECONDS,
    )


def _create_head_anchor_database_engine(database_url: str) -> Engine:
    """Create a distinct bounded pool reserved for the anchor worker."""

    return _create_supervisor_database_engine(database_url)


def _boottime_monotonic_ns() -> int:
    """Read Linux CLOCK_BOOTTIME so host/container suspension counts as a gap."""

    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if type(clock_id) is not int:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time suspend-aware monotonic clock is unavailable"
        )
    try:
        value = time.clock_gettime_ns(clock_id)
    except (OSError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time suspend-aware monotonic clock is unavailable"
        ) from None
    if type(value) is not int or value < 0:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time suspend-aware monotonic clock is invalid"
        )
    return value


class StopAwareBoottimeWaiter:
    """Wait in short chunks so a laptop resume is observed within one second."""

    __slots__ = ("_clock", "_stop_event")

    def __init__(
        self,
        *,
        stop_event: threading.Event,
        clock: Callable[[], int],
    ) -> None:
        if type(stop_event) is not threading.Event or not callable(clock):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time wait dependencies are invalid"
            )
        self._stop_event = stop_event
        self._clock = clock

    def __call__(self, *, deadline_monotonic_ns: int) -> None:
        if type(deadline_monotonic_ns) is not int or deadline_monotonic_ns < 0:
            raise TrustedTimeSupervisorConfigurationError("trusted-time wait deadline is invalid")
        while not self._stop_event.is_set():
            observed = self._clock()
            if type(observed) is not int or observed < 0:
                raise TrustedTimeSupervisorConfigurationError("trusted-time wait clock is invalid")
            remaining_ns = deadline_monotonic_ns - observed
            if remaining_ns <= 0:
                return
            self._stop_event.wait(min(_WAIT_POLL_SECONDS, remaining_ns / 1_000_000_000))


def _require_fixed_runtime_paths() -> None:
    for variable, expected in _PATH_ENVIRONMENT.items():
        value = os.getenv(variable, str(expected))
        if value != str(expected):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime path differs from the reviewed image contract"
            )


def _expected_staged_input_sha256s(
    environment: Mapping[str, str] = os.environ,
) -> tuple[str, str, str, str]:
    """Read only the four private post-enrollment input bindings."""

    values = tuple(environment.get(name) for name in _EXPECTED_STAGED_INPUT_SHA256_ENVIRONMENT)
    if any(
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in values
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time staged-input digest environment is invalid"
        )
    return cast(tuple[str, str, str, str], values)


def _record_database_secret_consumed() -> None:
    """Publish a nonsecret one-shot marker after the DSN is resident in memory."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            DATABASE_SECRET_CONSUMED_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        view = memoryview(DATABASE_SECRET_CONSUMED_BYTES)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret consumption marker failed"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _chrony_authority(
    authority: TrustedTimeDeploymentAuthority,
) -> ChronyNtsAuthority:
    return ChronyNtsAuthority(
        source_id=authority.source_id,
        source_authority_sha256=authority.source_authority_sha256,
        chronyc_path=str(authority.chronyc_path),
        socket_path=str(authority.chrony_socket_path),
        chrony_version=authority.chrony_version,
        ordered_source_names=authority.ordered_source_names,
        ordered_ntp_ports=authority.ordered_ntp_ports,
        maximum_reference_age_seconds=authority.maximum_reference_age_seconds,
    )


def _probe_payload(
    persisted: PersistedTrustedTimeProbe,
    *,
    authority: TrustedTimeDeploymentAuthority,
    monitor_epoch_id: str,
) -> dict[str, object]:
    state = persisted.result.evaluation.state
    sample = persisted.result.evaluation.sample
    return {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "clock_recovery_evidence_qualified": state.clock_recovery_qualified,
        "evaluation_sequence": persisted.evaluation_sequence,
        "external_head_anchor": False,
        "health": state.health.value,
        "host_head_sha256": persisted.host_head_sha256,
        "host_id": authority.host_id,
        "live_trading_authorized": False,
        "monitor_epoch_id": monitor_epoch_id,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "probe_status": persisted.result.status.value,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "exposure_authorized": False,
        "reason": state.reason.value,
        "record_sha256": persisted.record_sha256,
        "sample_sequence": None if sample is None else sample.sequence,
        "service": "trusted-time-supervisor",
        "source_authority_sha256": authority.source_authority_sha256,
        "source_id": authority.source_id,
        "state_sha256": state.semantic_sha256,
        "status": "evidence_persisted",
    }


def _print_payload(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def _install_stop_handlers(
    stop_event: threading.Event,
) -> dict[signal.Signals, signal._HANDLER]:
    previous: dict[signal.Signals, signal._HANDLER] = {}

    def request_stop(_: int, __: FrameType | None) -> None:
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    return previous


def _restore_stop_handlers(previous: dict[signal.Signals, signal._HANDLER]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _raise_if_head_anchor_failed(
    worker: TrustedTimeHeadAnchorBackgroundWorker,
) -> None:
    if not worker.fatal_error_latched:
        return
    if worker.fatal_reason is (
        TrustedTimeHeadAnchorFatalReason.REMOTE_HISTORY_ABSENT_ENROLLMENT_NOT_APPROVED
    ):
        raise TrustedTimeHeadAnchorEnrollmentNotApprovedFailure(
            "trusted-time remote anchor history is absent and enrollment is not approved"
        )
    raise TrustedTimeSupervisorError("trusted-time head-anchor worker failed closed")


def run_service(
    *,
    authority: TrustedTimeDeploymentAuthority,
    database_url: str,
    utc_clock: Callable[[], datetime] = _utc_now,
    monotonic_clock: Callable[[], int] = _boottime_monotonic_ns,
    stop_event: threading.Event | None = None,
    emit: Callable[[dict[str, object]], None] = _print_payload,
    engine_factory: Callable[[str], Engine] = _create_supervisor_database_engine,
    head_anchor_worker: TrustedTimeHeadAnchorBackgroundWorker | None = None,
    require_head_anchor_startup_terminal: bool = False,
    head_anchor_startup_terminal_publisher: Callable[[], None] | None = None,
) -> TrustedTimeSupervisorResult:
    """Create one fresh epoch and supervise exact durable probes until stopped.

    When supplied, the head-anchor worker starts only after the epoch commit;
    its first full-audit request therefore represents that epoch rotation.  A
    durable probe merely posts an in-process notification to the worker.  All
    database, signing, and external-provider work remains on its single
    background thread.
    """

    if authority.cadence_ns != TRUSTED_TIME_SUPERVISOR_INTERVAL_NS:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time scheduler interval differs from deployment authority"
        )
    event = threading.Event() if stop_event is None else stop_event
    if type(event) is not threading.Event or not callable(emit):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime dependencies are invalid"
        )
    if head_anchor_worker is not None and type(head_anchor_worker) is not (
        TrustedTimeHeadAnchorBackgroundWorker
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor worker dependency is invalid"
        )
    if (
        type(require_head_anchor_startup_terminal) is not bool
        or (
            require_head_anchor_startup_terminal
            and (head_anchor_worker is None or not callable(head_anchor_startup_terminal_publisher))
        )
        or (
            not require_head_anchor_startup_terminal
            and head_anchor_startup_terminal_publisher is not None
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor startup-terminal composition is invalid"
        )
    engine = engine_factory(database_url)
    worker_started = False
    worker_closed = False
    try:
        verify_operational_schema(engine, require_phase_zero_facts=False)
        repository = SqlTrustedTimeRepository(engine)
        repository.verify_integrity()
        session = repository.register_new_epoch(
            source_id=authority.source_id,
            source_authority_sha256=authority.source_authority_sha256,
            host_id=authority.host_id,
            recorded_at=utc_clock(),
        )
        if head_anchor_worker is not None:
            worker_started = True
            head_anchor_worker.prime_startup()
            head_anchor_worker.start()
            if require_head_anchor_startup_terminal:
                try:
                    head_anchor_worker.wait_for_startup_terminal(
                        timeout_seconds=(TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS),
                        publish_startup_terminal=(head_anchor_startup_terminal_publisher),
                    )
                except TrustedTimeHeadAnchorBackgroundWorkerError:
                    _raise_if_head_anchor_failed(head_anchor_worker)
                    raise
                _raise_if_head_anchor_failed(head_anchor_worker)
        source = ChronyNtsTrustedTimeSource(
            authority=_chrony_authority(authority),
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
        )

        def durable_probe() -> PersistedTrustedTimeProbe:
            persisted = run_durable_trusted_time_probe_once(
                session,
                repository=repository,
                source=source,
                utc_clock=utc_clock,
                monotonic_clock=monotonic_clock,
            )
            emit(
                _probe_payload(
                    persisted,
                    authority=authority,
                    monitor_epoch_id=session.binding.monitor_epoch_id,
                )
            )
            if head_anchor_worker is not None:
                head_anchor_worker.notify_persisted_probe(persisted)
                _raise_if_head_anchor_failed(head_anchor_worker)
            return persisted

        result = run_trusted_time_supervisor(
            durable_probe=durable_probe,
            monotonic_clock=monotonic_clock,
            waiter=StopAwareBoottimeWaiter(stop_event=event, clock=monotonic_clock),
            stop_requested=event.is_set,
        )
        if head_anchor_worker is not None:
            _raise_if_head_anchor_failed(head_anchor_worker)
            clean_stop_confirmed = head_anchor_worker.close(clean_stop=True)
            worker_closed = True
            _raise_if_head_anchor_failed(head_anchor_worker)
            if not clean_stop_confirmed:
                raise TrustedTimeSupervisorError(
                    "trusted-time head-anchor clean stop was not confirmed"
                )
        return result
    finally:
        if head_anchor_worker is not None and worker_started and not worker_closed:
            head_anchor_worker.close(clean_stop=False)
        engine.dispose()


def _fatal_payload(reason: str) -> dict[str, object]:
    return {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "exposure_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "reason": reason,
        "service": "trusted-time-supervisor",
        "status": "fatal",
    }


def run_service_with_production_head_anchor(
    *,
    authority: TrustedTimeDeploymentAuthority,
    database_url: str,
    head_anchor_configuration: TrustedTimeHeadAnchorRuntimeConfiguration,
    sequence_two_deadline_monotonic_ns: int,
    utc_clock: Callable[[], datetime] = _utc_now,
    monotonic_clock: Callable[[], int] = _boottime_monotonic_ns,
    stop_event: threading.Event | None = None,
    emit: Callable[[dict[str, object]], None] = _print_payload,
    anchor_engine_factory: Callable[[str], Engine] = (_create_head_anchor_database_engine),
) -> TrustedTimeSupervisorResult:
    """Compose the separate bounded anchor resources around the local service."""

    event = threading.Event() if stop_event is None else stop_event
    if (
        type(event) is not threading.Event
        or type(head_anchor_configuration) is not TrustedTimeHeadAnchorRuntimeConfiguration
        or type(sequence_two_deadline_monotonic_ns) is not int
        or sequence_two_deadline_monotonic_ns
        < POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor runtime dependencies are invalid"
        )
    try:
        observed_at_composition = monotonic_clock()
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor sequence-two deadline clock failed"
        ) from None
    sequence_two_issued_at = (
        sequence_two_deadline_monotonic_ns
        - POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
    )
    if (
        type(observed_at_composition) is not int
        or observed_at_composition < sequence_two_issued_at
        or observed_at_composition >= sequence_two_deadline_monotonic_ns
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor sequence-two deadline is invalid"
        )
    if (
        head_anchor_configuration.authority.host_id != authority.host_id
        or head_anchor_configuration.authority.source_authority_sha256
        != authority.source_authority_sha256
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor runtime crosses source deployment identity"
        )
    anchor_engine = anchor_engine_factory(database_url)
    provider: SupabaseStorageTrustedTimeAnchorProvider | None = None
    startup_effect_guard: TrustedTimeHeadAnchorStartupEffectDeadlineGuard | None = None
    attempt: RepositoryBackedTrustedTimeHeadAnchorAttempt | None = None
    worker: TrustedTimeHeadAnchorBackgroundWorker | None = None
    try:
        verify_operational_schema(anchor_engine, require_phase_zero_facts=False)
        anchor_authority = head_anchor_configuration.authority
        anchor_repository = SqlTrustedTimeHeadAnchorRepository(
            anchor_engine,
            verifier=head_anchor_configuration.verifier,
            anchor_authority_sha256=anchor_authority.anchor_authority_sha256,
            signing_key_id=anchor_authority.signing_key_id,
            signing_public_key_sha256=(anchor_authority.signing_public_key_sha256),
        )
        provider = SupabaseStorageTrustedTimeAnchorProvider(
            credentials=head_anchor_configuration.credentials
        )
        startup_effect_guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
            deadline_monotonic_ns=sequence_two_deadline_monotonic_ns,
            monotonic_clock=monotonic_clock,
        )
        deadline_bound_provider = DeadlineBoundTrustedTimeHeadAnchorProvider(
            provider=provider,
            startup_effect_guard=startup_effect_guard,
        )
        attempt = RepositoryBackedTrustedTimeHeadAnchorAttempt(
            anchor_repository=anchor_repository,
            provider=deadline_bound_provider,
            signer=head_anchor_configuration.signer,
            verifier=head_anchor_configuration.verifier,
            authority=anchor_authority,
            utc_clock=utc_clock,
            startup_effect_guard=startup_effect_guard,
        )
        worker = TrustedTimeHeadAnchorBackgroundWorker(
            attempt=attempt,
            monotonic_clock=monotonic_clock,
            on_fatal=event.set,
            allow_enrollment=False,
            startup_primer=attempt.prime_startup,
            require_startup_terminal=True,
            startup_terminal_deadline_monotonic_ns=(
                sequence_two_deadline_monotonic_ns
                - POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_NANOSECONDS
            ),
            startup_terminal_publication_deadline_monotonic_ns=(sequence_two_deadline_monotonic_ns),
        )

        def publish_startup_terminal() -> None:
            write_post_enrollment_start_sequence_two_ready(
                publication_deadline_monotonic_ns=(sequence_two_deadline_monotonic_ns),
                monotonic_clock=monotonic_clock,
            )
            if startup_effect_guard is None:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time startup effect guard is unavailable"
                )
            startup_effect_guard.release_after_startup_terminal()

        return run_service(
            authority=authority,
            database_url=database_url,
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
            stop_event=event,
            emit=emit,
            head_anchor_worker=worker,
            require_head_anchor_startup_terminal=True,
            head_anchor_startup_terminal_publisher=publish_startup_terminal,
        )
    finally:
        joined = worker is None or worker.close(
            timeout_seconds=0,
            clean_stop=False,
        )
        # Never tear resources out from beneath an alive daemon thread.  A
        # fatal process exit reclaims them after the bounded join fails.
        if joined:
            try:
                if attempt is not None:
                    attempt.close()
            finally:
                try:
                    if provider is not None:
                        provider.close()
                finally:
                    anchor_engine.dispose()


def main() -> None:
    stop_event = threading.Event()
    previous_handlers: dict[signal.Signals, signal._HANDLER] = {}
    try:
        _require_fixed_runtime_paths()
        staged_input_sha256s = _expected_staged_input_sha256s()
        authority = load_trusted_time_authority()
        database_url = load_database_url_secret(expected_sha256=staged_input_sha256s[0])
        head_anchor_configuration = load_trusted_time_head_anchor_runtime_configuration(
            database_url=database_url,
            expected_host_id=authority.host_id,
            expected_source_authority_sha256=(authority.source_authority_sha256),
            authority_owner_uid=os.geteuid(),
            secret_owner_uid=os.geteuid(),
            expected_authority_sha256=staged_input_sha256s[1],
            expected_auth_secret_sha256=staged_input_sha256s[2],
            expected_signing_key_sha256=staged_input_sha256s[3],
        )
        _record_database_secret_consumed()
        wait_for_post_enrollment_start_release()
        sequence_two_deadline_monotonic_ns = (
            read_exact_post_enrollment_start_sequence_two_deadline()
        )
        previous_handlers = _install_stop_handlers(stop_event)
        result = run_service_with_production_head_anchor(
            authority=authority,
            database_url=database_url,
            head_anchor_configuration=head_anchor_configuration,
            sequence_two_deadline_monotonic_ns=(sequence_two_deadline_monotonic_ns),
            stop_event=stop_event,
        )
        _print_payload(
            {
                "alert_delivery_authorized": False,
                "arming_authorized": False,
                "automatic_rearm_authorized": False,
                "automatic_resume_authorized": False,
                "broker_action_authorized": False,
                "exposure_authorized": False,
                "live_trading_authorized": False,
                "new_exposure_authorized": False,
                "operational_control_authorized": False,
                "probe_count": result.probe_count,
                "paper_trading_authorized": False,
                "readiness_authorized": False,
                "rearm_authorized": False,
                "service": "trusted-time-supervisor",
                "status": "stopped",
            }
        )
    except TrustedTimeSupervisorConfigurationError:
        _print_payload(_fatal_payload("configuration_rejected"))
        raise SystemExit(2) from None
    except TrustedTimeHeadAnchorEnrollmentNotApprovedFailure:
        _print_payload(
            _fatal_payload(
                TrustedTimeHeadAnchorFatalReason.REMOTE_HISTORY_ABSENT_ENROLLMENT_NOT_APPROVED.value
            )
        )
        raise SystemExit(2) from None
    except Exception:
        _print_payload(_fatal_payload("supervision_failed"))
        raise SystemExit(2) from None
    finally:
        if previous_handlers:
            _restore_stop_handlers(previous_handlers)


if __name__ == "__main__":
    main()
