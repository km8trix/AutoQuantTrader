"""Single-flight background runtime for external trusted-head checkpoints."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from contextlib import suppress

from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_clean_stop import (
    TrustedTimeHeadAnchorCleanStopTerminalResult,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorAttempt,
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorEnrollmentNotApprovedFailure,
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorFatalReason,
    TrustedTimeHeadAnchorTransientFailure,
    TrustedTimeHeadAnchorWorkerCore,
    TrustedTimeHeadAnchorWorkerError,
    TrustedTimeHeadAnchorWorkerEvidence,
    TrustedTimeHeadAnchorWorkRequest,
)

TRUSTED_TIME_HEAD_ANCHOR_BACKGROUND_WORKER_CONTRACT_VERSION = (
    "phase6d-background-trusted-head-anchor-runtime-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_SHUTDOWN_TIMEOUT_SECONDS = 30.0
# The read-only cross-process marker waiter owns the enclosing 120-second
# bound. This worker must fail closed first and preserve its exact 5-second
# teardown/observation margin.
TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS = 115.0
_TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_POLL_SECONDS = 1.0
_TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS = 5_000_000_000


class TrustedTimeHeadAnchorBackgroundWorkerError(RuntimeError):
    """The background thread could not preserve its fail-closed contract."""


class TrustedTimeHeadAnchorBackgroundWorker:
    """Own exactly one daemon thread and at most one external attempt.

    Notification methods acquire only an in-process condition, update bounded
    scheduling state, and return.  The injected attempt is invoked exclusively
    by the background thread and may own a separate bounded database engine and
    provider session.
    """

    __slots__ = (
        "_abort_requested",
        "_allow_enrollment",
        "_attempt",
        "_condition",
        "_configured_startup_terminal_deadline_monotonic_ns",
        "_configured_startup_terminal_publication_deadline_monotonic_ns",
        "_core",
        "_fatal_event",
        "_fatal_reason",
        "_last_observed_monotonic_ns",
        "_monotonic_clock",
        "_on_fatal",
        "_require_startup_terminal",
        "_runtime_fatal",
        "_started_event",
        "_startup_primed",
        "_startup_primer",
        "_startup_started_at_monotonic_ns",
        "_startup_started_at_wall_monotonic_ns",
        "_startup_terminal_completed_at_monotonic_ns",
        "_startup_terminal_completed_at_wall_monotonic_ns",
        "_startup_terminal_deadline_monotonic_ns",
        "_startup_terminal_deadline_wall_monotonic_ns",
        "_startup_terminal_publication_deadline_monotonic_ns",
        "_startup_terminal_publication_deadline_wall_monotonic_ns",
        "_startup_terminal_released",
        "_thread",
    )

    def __init__(
        self,
        *,
        attempt: TrustedTimeHeadAnchorAttempt,
        monotonic_clock: Callable[[], int],
        on_fatal: Callable[[], object],
        allow_enrollment: bool = False,
        startup_primer: Callable[[], None] | None = None,
        require_startup_terminal: bool = False,
        startup_terminal_deadline_monotonic_ns: int | None = None,
        startup_terminal_publication_deadline_monotonic_ns: int | None = None,
    ) -> None:
        if (
            not callable(attempt)
            or not callable(monotonic_clock)
            or not callable(on_fatal)
            or (startup_primer is not None and not callable(startup_primer))
        ):
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background dependencies are unavailable"
            )
        if (
            type(allow_enrollment) is not bool
            or type(require_startup_terminal) is not bool
            or (allow_enrollment and require_startup_terminal)
            or (
                startup_terminal_deadline_monotonic_ns is not None
                and (
                    type(startup_terminal_deadline_monotonic_ns) is not int
                    or startup_terminal_deadline_monotonic_ns < 0
                    or not require_startup_terminal
                )
            )
            or (
                startup_terminal_publication_deadline_monotonic_ns is not None
                and (
                    type(startup_terminal_publication_deadline_monotonic_ns) is not int
                    or startup_terminal_deadline_monotonic_ns is None
                    or startup_terminal_publication_deadline_monotonic_ns
                    - startup_terminal_deadline_monotonic_ns
                    != _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS
                )
            )
        ):
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background startup mode is invalid"
            )
        self._attempt = attempt
        self._monotonic_clock = monotonic_clock
        self._on_fatal = on_fatal
        self._allow_enrollment = allow_enrollment
        self._require_startup_terminal = require_startup_terminal
        self._startup_primer = startup_primer
        self._configured_startup_terminal_deadline_monotonic_ns = (
            startup_terminal_deadline_monotonic_ns
        )
        self._configured_startup_terminal_publication_deadline_monotonic_ns = (
            startup_terminal_publication_deadline_monotonic_ns
        )
        self._condition = threading.Condition(threading.Lock())
        self._started_event = threading.Event()
        self._fatal_event = threading.Event()
        self._fatal_reason: TrustedTimeHeadAnchorFatalReason | None = None
        self._abort_requested = False
        self._runtime_fatal = False
        self._startup_primed = False
        self._startup_started_at_monotonic_ns: int | None = None
        self._startup_started_at_wall_monotonic_ns: int | None = None
        self._startup_terminal_deadline_monotonic_ns: int | None = None
        self._startup_terminal_deadline_wall_monotonic_ns: int | None = None
        self._startup_terminal_publication_deadline_monotonic_ns: int | None = None
        self._startup_terminal_publication_deadline_wall_monotonic_ns: int | None = None
        self._startup_terminal_completed_at_monotonic_ns: int | None = None
        self._startup_terminal_completed_at_wall_monotonic_ns: int | None = None
        self._startup_terminal_released = False
        self._last_observed_monotonic_ns = 0
        self._core: TrustedTimeHeadAnchorWorkerCore | None = None
        self._thread: threading.Thread | None = None

    def prime_startup(self) -> None:
        """Authenticate local durable tips before probes may begin appending.

        The optional primer is a local SQL-only operation.  It must not call a
        signer or provider.  Running it synchronously after epoch registration
        closes the otherwise unavoidable race between that fresh epoch and the
        first scheduled durable probe; the first remote audit still runs only
        on the background thread.
        """

        with self._condition:
            if self._thread is not None or self._startup_primed:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor background startup was already primed"
                )
            if self._runtime_fatal:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor background startup is fatal"
                )
            primer = self._startup_primer
        try:
            if primer is not None:
                primer()
        except Exception:
            with self._condition:
                callback = self._latch_runtime_fatal_locked()
            self._invoke_fatal_callback(callback)
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background startup authentication failed"
            ) from None
        with self._condition:
            if self._runtime_fatal:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor background startup is fatal"
                )
            self._startup_primed = True

    def _read_monotonic_ns(self) -> int:
        try:
            value = self._monotonic_clock()
        except Exception:
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background monotonic clock failed"
            ) from None
        if type(value) is not int or value < 0:
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background monotonic clock is invalid"
            )
        if value < self._last_observed_monotonic_ns:
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background monotonic clock regressed"
            )
        self._last_observed_monotonic_ns = value
        return value

    def _core_locked(self) -> TrustedTimeHeadAnchorWorkerCore:
        core = self._core
        if core is None:
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background worker is not started"
            )
        return core

    def _latch_runtime_fatal_locked(
        self,
        *,
        reason: TrustedTimeHeadAnchorFatalReason | None = None,
    ) -> Callable[[], object] | None:
        if self._runtime_fatal:
            return None
        self._runtime_fatal = True
        self._abort_requested = True
        self._fatal_reason = reason
        core = self._core
        if core is not None and not core.fatal_error_latched:
            with suppress(Exception):
                core.record_fatal_failure(
                    None,
                    observed_at_monotonic_ns=self._last_observed_monotonic_ns,
                )
        self._fatal_event.set()
        self._condition.notify_all()
        return self._on_fatal

    @staticmethod
    def _invoke_fatal_callback(callback: Callable[[], object] | None) -> None:
        if callback is None:
            return
        try:
            callback()
        except Exception:
            # Failure reporting cannot weaken or clear the already-latched
            # fatal state and must never expose callback details.
            return

    def start(self) -> None:
        """Start the thread; return before its first database/network attempt."""

        with self._condition:
            if self._thread is not None:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor background worker was already started"
                )
            if self._startup_primer is not None and not self._startup_primed:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor background startup was not primed"
                )
            if not self._startup_primed:
                self._startup_primed = True
            if self._runtime_fatal:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor background startup is fatal"
                )
            started_at = self._read_monotonic_ns()
            self._startup_started_at_monotonic_ns = started_at
            self._startup_started_at_wall_monotonic_ns = time.monotonic_ns()
            startup_timeout_ns = int(
                TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS * 1_000_000_000
            )
            self._startup_terminal_deadline_monotonic_ns = (
                self._configured_startup_terminal_deadline_monotonic_ns
                if self._configured_startup_terminal_deadline_monotonic_ns is not None
                else started_at + startup_timeout_ns
            )
            remaining_ns = max(
                0,
                self._startup_terminal_deadline_monotonic_ns - started_at,
            )
            self._startup_terminal_deadline_wall_monotonic_ns = (
                self._startup_started_at_wall_monotonic_ns + min(startup_timeout_ns, remaining_ns)
            )
            self._startup_terminal_publication_deadline_monotonic_ns = (
                self._configured_startup_terminal_publication_deadline_monotonic_ns
                if self._configured_startup_terminal_publication_deadline_monotonic_ns is not None
                else self._startup_terminal_deadline_monotonic_ns
                + _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS
            )
            publication_remaining_ns = max(
                0,
                self._startup_terminal_publication_deadline_monotonic_ns - started_at,
            )
            self._startup_terminal_publication_deadline_wall_monotonic_ns = (
                self._startup_started_at_wall_monotonic_ns
                + min(
                    startup_timeout_ns
                    + _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS,
                    publication_remaining_ns,
                )
            )
            self._core = TrustedTimeHeadAnchorWorkerCore(
                started_at_monotonic_ns=started_at,
                allow_enrollment=self._allow_enrollment,
            )
            self._thread = threading.Thread(
                target=self._run,
                name="trusted-time-head-anchor",
                daemon=True,
            )
            self._thread.start()
        if not self._started_event.wait(timeout=1.0):
            callback: Callable[[], object] | None
            with self._condition:
                self._abort_requested = True
                callback = self._latch_runtime_fatal_locked()
                self._condition.notify_all()
            self._invoke_fatal_callback(callback)
            thread = self._thread
            if thread is not None:
                thread.join(timeout=1.0)
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background thread did not start"
            )

    def _run(self) -> None:
        callback: Callable[[], object] | None = None
        self._started_event.set()
        while True:
            request: TrustedTimeHeadAnchorWorkRequest | None = None
            with self._condition:
                if self._abort_requested or self._runtime_fatal:
                    return
                if (
                    self._require_startup_terminal
                    and self._startup_terminal_completed_at_monotonic_ns is not None
                    and not self._startup_terminal_released
                ):
                    self._condition.wait()
                    continue
                core = self._core_locked()
                if core.fatal_error_latched or core.stopped:
                    return
                try:
                    observed = self._read_monotonic_ns()
                    if self._startup_terminal_deadline_expired_locked(observed):
                        callback = self._latch_runtime_fatal_locked()
                    else:
                        request = core.take_work(observed_at_monotonic_ns=observed)
                    if request is None and callback is None:
                        deadline = core.next_wake_monotonic_ns()
                        timeout = None
                        if deadline is not None:
                            timeout = max(0.0, (deadline - observed) / 1_000_000_000)
                        self._condition.wait(timeout=timeout)
                        continue
                except Exception:
                    callback = self._latch_runtime_fatal_locked()
            if request is None:
                self._invoke_fatal_callback(callback)
                return

            result: TrustedTimeHeadAnchorAttemptResult | None = None
            transient = False
            fatal = False
            fatal_reason: TrustedTimeHeadAnchorFatalReason | None = None
            try:
                attempted = self._attempt(request)
                if type(attempted) is not TrustedTimeHeadAnchorAttemptResult:
                    raise TrustedTimeHeadAnchorFatalFailure(
                        "trusted-time anchor attempt returned a noncanonical result"
                    )
                attempted.__post_init__()
                result = attempted
            except TrustedTimeHeadAnchorTransientFailure:
                transient = True
            except TrustedTimeHeadAnchorEnrollmentNotApprovedFailure:
                fatal = True
                fatal_reason = (
                    TrustedTimeHeadAnchorFatalReason.REMOTE_HISTORY_ABSENT_ENROLLMENT_NOT_APPROVED
                )
            except TrustedTimeHeadAnchorFatalFailure:
                fatal = True
            except Exception:
                # Unknown failures default fatal.  Only a positively classified
                # external outage may use the transient exception above.
                fatal = True

            callback = None
            with self._condition:
                if self._abort_requested or self._fatal_event.is_set():
                    self._condition.notify_all()
                    return
                core = self._core_locked()
                try:
                    completed = self._read_monotonic_ns()
                    if result is not None:
                        core.record_success(
                            request,
                            result,
                            observed_at_monotonic_ns=completed,
                        )
                        if (
                            request.full_audit
                            and not request.allow_enrollment
                            and request.checkpoint_reason
                            is TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
                        ):
                            self._startup_terminal_completed_at_monotonic_ns = completed
                            self._startup_terminal_completed_at_wall_monotonic_ns = (
                                time.monotonic_ns()
                            )
                    elif transient:
                        core.record_transient_failure(
                            request,
                            observed_at_monotonic_ns=completed,
                        )
                    elif fatal:
                        core.record_fatal_failure(
                            request,
                            observed_at_monotonic_ns=completed,
                        )
                        callback = self._latch_runtime_fatal_locked(reason=fatal_reason)
                    else:  # pragma: no cover - defensive exhaustiveness
                        core.record_fatal_failure(
                            request,
                            observed_at_monotonic_ns=completed,
                        )
                        callback = self._latch_runtime_fatal_locked()
                except TrustedTimeHeadAnchorWorkerError:
                    callback = self._latch_runtime_fatal_locked()
                except Exception:
                    callback = self._latch_runtime_fatal_locked()
                self._condition.notify_all()
            self._invoke_fatal_callback(callback)
            if callback is not None:
                return

    def _startup_terminal_deadline_expired_locked(
        self,
        observed_at_monotonic_ns: int,
    ) -> bool:
        if (
            not self._require_startup_terminal
            or self._startup_terminal_completed_at_monotonic_ns is not None
        ):
            return False
        logical_deadline = self._startup_terminal_deadline_monotonic_ns
        wall_deadline = self._startup_terminal_deadline_wall_monotonic_ns
        return (
            logical_deadline is None
            or wall_deadline is None
            or observed_at_monotonic_ns >= logical_deadline
            or time.monotonic_ns() >= wall_deadline
        )

    def wait_for_startup_terminal(
        self,
        *,
        timeout_seconds: float = (TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS),
        publish_startup_terminal: Callable[[], None] | None = None,
    ) -> TrustedTimeHeadAnchorWorkerEvidence:
        """Require the first normal full-audit epoch rotation within one bound.

        Transient failures may use the core's existing retry schedule only
        while both the suspend-aware runtime bound and an independent wall
        bound remain open. Expiry irreversibly aborts the worker and latches
        fatal state, so a delayed retry cannot cross into long-lived probing.
        """

        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0
            < float(timeout_seconds)
            <= TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS
            or (publish_startup_terminal is not None and not callable(publish_startup_terminal))
        ):
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor startup-terminal bound is invalid"
            )
        timeout_ns = int(float(timeout_seconds) * 1_000_000_000)
        callback: Callable[[], object] | None = None
        evidence: TrustedTimeHeadAnchorWorkerEvidence | None = None
        failure: str | None = None
        publication_failure: BaseException | None = None
        with self._condition:
            if self._thread is None:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor startup-terminal worker is not started"
                )
            if self._allow_enrollment:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor startup terminal requires normal supervision"
                )
            logical_started_at = self._startup_started_at_monotonic_ns
            wall_started_at = self._startup_started_at_wall_monotonic_ns
            if logical_started_at is None or wall_started_at is None:
                raise TrustedTimeHeadAnchorBackgroundWorkerError(
                    "trusted-time anchor startup terminal has no start instant"
                )
            requested_logical_deadline = logical_started_at + timeout_ns
            requested_wall_deadline = wall_started_at + timeout_ns
            current_logical_deadline = self._startup_terminal_deadline_monotonic_ns
            current_wall_deadline = self._startup_terminal_deadline_wall_monotonic_ns
            logical_deadline = min(
                requested_logical_deadline,
                current_logical_deadline
                if current_logical_deadline is not None
                else requested_logical_deadline,
            )
            wall_deadline = min(
                requested_wall_deadline,
                current_wall_deadline
                if current_wall_deadline is not None
                else requested_wall_deadline,
            )
            self._startup_terminal_deadline_monotonic_ns = logical_deadline
            self._startup_terminal_deadline_wall_monotonic_ns = wall_deadline
            configured_publication_deadline = (
                self._startup_terminal_publication_deadline_monotonic_ns
            )
            configured_publication_wall_deadline = (
                self._startup_terminal_publication_deadline_wall_monotonic_ns
            )
            self._startup_terminal_publication_deadline_monotonic_ns = min(
                logical_deadline
                + _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS,
                configured_publication_deadline
                if configured_publication_deadline is not None
                else logical_deadline
                + _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS,
            )
            self._startup_terminal_publication_deadline_wall_monotonic_ns = min(
                wall_deadline + _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS,
                configured_publication_wall_deadline
                if configured_publication_wall_deadline is not None
                else wall_deadline
                + _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_PUBLICATION_RESERVE_NANOSECONDS,
            )
            while True:
                if self._runtime_fatal:
                    failure = "trusted-time anchor startup terminal failed closed"
                    break
                try:
                    logical_now = self._read_monotonic_ns()
                except Exception:
                    self._abort_requested = True
                    callback = self._latch_runtime_fatal_locked()
                    failure = "trusted-time anchor startup terminal clock failed"
                    break
                wall_now = time.monotonic_ns()
                terminal_at = self._startup_terminal_completed_at_monotonic_ns
                terminal_wall_at = self._startup_terminal_completed_at_wall_monotonic_ns
                if logical_now >= logical_deadline or wall_now >= wall_deadline:
                    self._abort_requested = True
                    callback = self._latch_runtime_fatal_locked()
                    failure = "trusted-time anchor startup terminal was not confirmed"
                    break
                if terminal_at is not None and terminal_wall_at is not None:
                    if terminal_at > logical_deadline or terminal_wall_at > wall_deadline:
                        self._abort_requested = True
                        callback = self._latch_runtime_fatal_locked()
                        failure = "trusted-time anchor startup terminal was not confirmed"
                        break
                    try:
                        if (
                            publish_startup_terminal is not None
                            and publish_startup_terminal() is not None
                        ):
                            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                                "trusted-time anchor startup-terminal publisher is invalid"
                            )
                    except BaseException as error:
                        self._abort_requested = True
                        callback = self._latch_runtime_fatal_locked()
                        publication_failure = error
                        failure = "trusted-time anchor startup terminal publication failed"
                        break
                    try:
                        published_at = self._read_monotonic_ns()
                    except Exception:
                        self._abort_requested = True
                        callback = self._latch_runtime_fatal_locked()
                        failure = "trusted-time anchor startup terminal publication failed"
                        break
                    publication_deadline = self._startup_terminal_publication_deadline_monotonic_ns
                    publication_wall_deadline = (
                        self._startup_terminal_publication_deadline_wall_monotonic_ns
                    )
                    if (
                        publication_deadline is None
                        or publication_wall_deadline is None
                        or published_at >= publication_deadline
                        or time.monotonic_ns() >= publication_wall_deadline
                    ):
                        self._abort_requested = True
                        callback = self._latch_runtime_fatal_locked()
                        failure = "trusted-time anchor startup terminal publication failed"
                        break
                    try:
                        evidence = self._core_locked().evidence(
                            observed_at_monotonic_ns=self._last_observed_monotonic_ns
                        )
                    except Exception:
                        self._abort_requested = True
                        failure = "trusted-time anchor startup terminal is invalid"
                    if (
                        evidence is None
                        or not evidence.startup_full_audit_completed
                        or evidence.fatal_error_latched
                    ):
                        self._abort_requested = True
                        callback = self._latch_runtime_fatal_locked()
                        failure = "trusted-time anchor startup terminal is invalid"
                    else:
                        self._startup_terminal_released = True
                        self._condition.notify_all()
                    break
                if terminal_at is not None or terminal_wall_at is not None:
                    self._abort_requested = True
                    callback = self._latch_runtime_fatal_locked()
                    failure = "trusted-time anchor startup terminal is invalid"
                    break
                # Recompute the worker's retry deadline against the same
                # suspend-aware clock after each bounded wall-clock poll.
                self._condition.notify_all()
                self._condition.wait(
                    timeout=min(
                        _TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_POLL_SECONDS,
                        (logical_deadline - logical_now) / 1_000_000_000,
                        (wall_deadline - wall_now) / 1_000_000_000,
                    )
                )
        self._invoke_fatal_callback(callback)
        if publication_failure is not None:
            raise publication_failure
        if failure is not None or evidence is None:
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                failure or "trusted-time anchor startup terminal failed closed"
            )
        return evidence

    def _notify(self, operation: Callable[[TrustedTimeHeadAnchorWorkerCore, int], None]) -> None:
        callback: Callable[[], object] | None = None
        with self._condition:
            if self._runtime_fatal or self._abort_requested:
                return
            try:
                observed = self._read_monotonic_ns()
                operation(self._core_locked(), observed)
            except Exception:
                callback = self._latch_runtime_fatal_locked()
            self._condition.notify_all()
        self._invoke_fatal_callback(callback)

    def notify_epoch_rotation(self) -> None:
        self._notify(
            lambda core, observed: core.request_epoch_rotation(observed_at_monotonic_ns=observed)
        )

    def notify_persisted_probe(self, persisted_probe: PersistedTrustedTimeProbe) -> None:
        """Bounded local notification; never performs database or external I/O."""

        self._notify(
            lambda core, observed: core.observe_persisted_probe(
                persisted_probe,
                observed_at_monotonic_ns=observed,
            )
        )

    def request_on_demand(self) -> None:
        self._notify(
            lambda core, observed: core.request_on_demand(observed_at_monotonic_ns=observed)
        )

    def evidence(self) -> TrustedTimeHeadAnchorWorkerEvidence:
        callback: Callable[[], object] | None = None
        with self._condition:
            try:
                observed = (
                    self._last_observed_monotonic_ns
                    if self._runtime_fatal
                    else self._read_monotonic_ns()
                )
                evidence = self._core_locked().evidence(observed_at_monotonic_ns=observed)
            except Exception:
                callback = self._latch_runtime_fatal_locked()
                evidence = self._core_locked().evidence(
                    observed_at_monotonic_ns=self._last_observed_monotonic_ns
                )
        self._invoke_fatal_callback(callback)
        return evidence

    @property
    def fatal_error_latched(self) -> bool:
        return self._fatal_event.is_set()

    @property
    def fatal_reason(self) -> TrustedTimeHeadAnchorFatalReason | None:
        with self._condition:
            return self._fatal_reason

    def close(
        self,
        *,
        timeout_seconds: float = TRUSTED_TIME_HEAD_ANCHOR_SHUTDOWN_TIMEOUT_SECONDS,
        clean_stop: bool = True,
    ) -> bool:
        """Request at most one clean-stop attempt and join for a hard bound.

        The return value is true only when the worker reached a terminal state
        within the bound.  A timed-out thread is marked for termination after
        its already-bounded in-flight dependency call returns; it is never
        joined without a deadline.
        """

        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not 0 <= float(timeout_seconds) <= 60.0
            or type(clean_stop) is not bool
        ):
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background shutdown bound is invalid"
            )
        thread: threading.Thread | None
        callback: Callable[[], object] | None = None
        with self._condition:
            thread = self._thread
            if thread is None:
                return True
            if clean_stop and not self._runtime_fatal:
                try:
                    observed = self._read_monotonic_ns()
                    self._core_locked().request_clean_stop(observed_at_monotonic_ns=observed)
                except Exception:
                    callback = self._latch_runtime_fatal_locked()
            elif not clean_stop:
                self._abort_requested = True
            self._condition.notify_all()
        self._invoke_fatal_callback(callback)
        thread.join(timeout=float(timeout_seconds))
        if thread.is_alive():
            with self._condition:
                self._abort_requested = True
                self._condition.notify_all()
            return False
        if not clean_stop:
            return True
        with self._condition:
            return self._core_locked().clean_shutdown_completed

    def close_with_clean_stop_terminal_result(
        self,
        *,
        timeout_seconds: float = TRUSTED_TIME_HEAD_ANCHOR_SHUTDOWN_TIMEOUT_SECONDS,
    ) -> TrustedTimeHeadAnchorCleanStopTerminalResult | None:
        """Close within the existing bound and return only exact new-record evidence.

        ``None`` means that no sealed current-request terminal result was
        accepted.  It never represents an unchanged-head or no-new-record
        success and grants no stop, signal, admission, or teardown authority.
        """

        with self._condition:
            if self._thread is None:
                return None
        if not self.close(timeout_seconds=timeout_seconds, clean_stop=True):
            return None
        callback: Callable[[], object] | None = None
        with self._condition:
            try:
                result = self._core_locked().clean_stop_terminal_result
                if type(result) is not TrustedTimeHeadAnchorCleanStopTerminalResult:
                    return None
                result.__post_init__()
            except Exception:
                callback = self._latch_runtime_fatal_locked()
                result = None
        self._invoke_fatal_callback(callback)
        return result


def system_monotonic_ns() -> int:
    """Default process monotonic clock for isolated tests and compositions."""

    return time.monotonic_ns()


__all__ = [
    "TRUSTED_TIME_HEAD_ANCHOR_BACKGROUND_WORKER_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_SHUTDOWN_TIMEOUT_SECONDS",
    "TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS",
    "TrustedTimeHeadAnchorBackgroundWorker",
    "TrustedTimeHeadAnchorBackgroundWorkerError",
    "system_monotonic_ns",
]
