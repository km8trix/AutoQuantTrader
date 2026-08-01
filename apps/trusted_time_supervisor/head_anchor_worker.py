"""Single-flight background runtime for external trusted-head checkpoints."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from contextlib import suppress

from packages.application.durable_trusted_time_monitor import PersistedTrustedTimeProbe
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorAttempt,
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorFatalFailure,
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
        "_core",
        "_fatal_event",
        "_last_observed_monotonic_ns",
        "_monotonic_clock",
        "_on_fatal",
        "_runtime_fatal",
        "_started_event",
        "_startup_primed",
        "_startup_primer",
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
        if type(allow_enrollment) is not bool:
            raise TrustedTimeHeadAnchorBackgroundWorkerError(
                "trusted-time anchor background enrollment flag is invalid"
            )
        self._attempt = attempt
        self._monotonic_clock = monotonic_clock
        self._on_fatal = on_fatal
        self._allow_enrollment = allow_enrollment
        self._startup_primer = startup_primer
        self._condition = threading.Condition(threading.Lock())
        self._started_event = threading.Event()
        self._fatal_event = threading.Event()
        self._abort_requested = False
        self._runtime_fatal = False
        self._startup_primed = False
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

    def _latch_runtime_fatal_locked(self) -> Callable[[], object] | None:
        if self._runtime_fatal:
            return None
        self._runtime_fatal = True
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
                core = self._core_locked()
                if core.fatal_error_latched or core.stopped:
                    return
                try:
                    observed = self._read_monotonic_ns()
                    request = core.take_work(observed_at_monotonic_ns=observed)
                    if request is None:
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
            except TrustedTimeHeadAnchorFatalFailure:
                fatal = True
            except Exception:
                # Unknown failures default fatal.  Only a positively classified
                # external outage may use the transient exception above.
                fatal = True

            callback = None
            with self._condition:
                core = self._core_locked()
                try:
                    completed = self._read_monotonic_ns()
                    if result is not None:
                        core.record_success(
                            request,
                            result,
                            observed_at_monotonic_ns=completed,
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
                        callback = self._latch_runtime_fatal_locked()
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


def system_monotonic_ns() -> int:
    """Default process monotonic clock for isolated tests and compositions."""

    return time.monotonic_ns()


__all__ = [
    "TRUSTED_TIME_HEAD_ANCHOR_BACKGROUND_WORKER_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_SHUTDOWN_TIMEOUT_SECONDS",
    "TrustedTimeHeadAnchorBackgroundWorker",
    "TrustedTimeHeadAnchorBackgroundWorkerError",
    "system_monotonic_ns",
]
