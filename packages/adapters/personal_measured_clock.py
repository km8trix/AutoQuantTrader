"""Own fresh StandardClock history and its original Chrony conversions.

Sampling explicitly invokes the supplied source and local callbacks. Construction
and historical verification invoke neither. These process-local records establish
which original inputs produced a health snapshot, not qualified host time,
currentness, capture admission, a runtime profile, or permission to re-arm.
The ownership boundary assumes cooperating Python code, not a hostile sandbox.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields
from datetime import datetime
from threading import Lock
from weakref import ReferenceType, WeakValueDictionary, finalize, ref

from packages.adapters import standard_clock as standard
from packages.adapters import standard_clock_chrony as chrony
from packages.adapters.trusted_time.chrony_nts import ChronyNtsAuthority
from packages.application.personal_runtime import ClockHealthSnapshot

_CONFIGURATION_FIELDS = (
    "_utc_now",
    "_monotonic_now_ns",
    "_epoch_provider",
    "_source",
    "_simulated_health",
)
_HISTORY_FIELDS = ("_previous", "_source_id", "_healthy_since")
_CLOCK_FIELDS = frozenset(
    (*_CONFIGURATION_FIELDS, *_HISTORY_FIELDS, "_latched_reasons", "_sequence")
)
_SNAPSHOT_FIELDS = tuple(item.name for item in fields(ClockHealthSnapshot))
_AUTHORITY_FIELDS = tuple(item.name for item in fields(ChronyNtsAuthority))
_HANDLERS = ("_utc", "_monotonic", "_epoch", "_measurement")


class MeasuredClockError(ValueError):
    """Fixed diagnostics; no callback exception or private source output."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SampledMeasuredHealth:
    """Original historical health, possibly with a successful source read.

    A later local-clock failure can discard a successful measurement and produce
    an unavailable snapshot. Retaining that read does not upgrade the snapshot.
    """

    snapshot: ClockHealthSnapshot = field(repr=False)
    source_observation: chrony.ChronyStandardObservation | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class _History:
    values: tuple[object, ...]
    reasons: set[str]
    reason_values: frozenset[str]
    sequence: int


@dataclass(frozen=True, slots=True)
class _OriginalHealth:
    owner: ReferenceType[PersonalMeasuredClock]
    snapshot: ClockHealthSnapshot
    snapshot_values: tuple[object, ...]
    source_observation: chrony.ChronyStandardObservation | None


def _same_objects(current: tuple[object, ...], original: tuple[object, ...]) -> bool:
    return len(current) == len(original) and all(
        actual is expected for actual, expected in zip(current, original, strict=True)
    )


def _policy() -> tuple[object, ...]:
    return (
        standard.STANDARD_CLOCK_POLICY_VERSION,
        standard.WARNING_NS,
        standard.BLOCK_NS,
        standard.MAX_SAMPLE_AGE_NS,
        standard.MAX_SAMPLING_DURATION_NS,
        standard.HEALTHY_RECOVERY_NS,
    )


def _owner(identity: ReferenceType[PersonalMeasuredClock]) -> PersonalMeasuredClock:
    owner = identity()
    if owner is None:
        raise MeasuredClockError("MEASURED_CLOCK_OWNER_REQUIRED")
    return owner


class PersonalMeasuredClock:
    """One fresh private reducer; supplied UTC/monotonic callbacks match its source."""

    def __init__(
        self,
        *,
        source: chrony.ChronyStandardTimeSource,
        utc_now: Callable[[], datetime],
        monotonic_now_ns: Callable[[], int],
        epoch_provider: Callable[[], str],
    ) -> None:
        if (
            type(source) is not chrony.ChronyStandardTimeSource
            or utc_now is not source.source.utc_clock
            or monotonic_now_ns is not source.source.monotonic_clock
            or not all(
                callable(callback) for callback in (utc_now, monotonic_now_ns, epoch_provider)
            )
        ):
            raise MeasuredClockError("MEASURED_CLOCK_CONFIGURATION_INVALID")
        self._source = source
        self._utc_now = utc_now
        self._monotonic_now_ns = monotonic_now_ns
        self._epoch_provider = epoch_provider
        identity = ref(self)
        self._identity = identity
        self._lock = Lock()
        self._sampling = False
        self._invalid = False
        self._source_calls = 0
        self._pending: chrony.ChronyStandardObservation | None = None
        utc_call = PersonalMeasuredClock._utc
        monotonic_call = PersonalMeasuredClock._monotonic
        epoch_call = PersonalMeasuredClock._epoch
        measurement_call = PersonalMeasuredClock._measurement
        self._clock = standard.StandardClock(
            utc_now=lambda: utc_call(_owner(identity)),
            monotonic_now_ns=lambda: monotonic_call(_owner(identity)),
            epoch_provider=lambda: epoch_call(_owner(identity)),
            source=lambda at, mono: measurement_call(_owner(identity), at, mono),
        )
        self._original_configuration = self._configuration()
        self._original_policy = _policy()
        self._expected = self._history()
        self._owned: WeakValueDictionary[int, SampledMeasuredHealth] = WeakValueDictionary()
        self._original: dict[int, _OriginalHealth] = {}

    def _configuration(self) -> tuple[object, ...]:
        if (
            type(self._clock) is not standard.StandardClock
            or set(vars(self._clock)) != _CLOCK_FIELDS
            or self._clock._simulated_health is not False
            or type(self._source) is not chrony.ChronyStandardTimeSource
            or type(self._source.source.authority) is not ChronyNtsAuthority
            or any(name in vars(self) for name in _HANDLERS)
        ):
            raise MeasuredClockError("MEASURED_CLOCK_OWNERSHIP_CHANGED")
        callbacks = (self._utc_now, self._monotonic_now_ns, self._epoch_provider)
        return (
            self._clock,
            self._source,
            *callbacks,
            *(type(callback).__call__ for callback in callbacks),
            *(getattr(PersonalMeasuredClock, name) for name in _HANDLERS),
            *(getattr(self._clock, name) for name in _CONFIGURATION_FIELDS),
            standard.StandardClock.health_snapshot,
            standard.StandardClock.now,
            standard.StandardClock.monotonic_ns,
            chrony.ChronyStandardTimeSource.read_observation,
            chrony.ChronyStandardTimeSource.require_original_observation,
            chrony.ChronyStandardTimeSource._read_measurement,
            self._source._authority_binding,
            self._source._measurement_source_id,
            *chrony._source_owners(self._source.source),
            *(getattr(self._source.source.authority, name) for name in _AUTHORITY_FIELDS),
        )

    def _history(self) -> _History:
        clock = self._clock
        if (
            type(clock._sequence) is not int
            or clock._sequence < 0
            or type(clock._latched_reasons) is not set
            or len(clock._latched_reasons) > 64
            or any(type(reason) is not str for reason in clock._latched_reasons)
        ):
            raise MeasuredClockError("MEASURED_CLOCK_HISTORY_CHANGED")
        return _History(
            tuple(getattr(clock, name) for name in _HISTORY_FIELDS),
            clock._latched_reasons,
            frozenset(clock._latched_reasons),
            clock._sequence,
        )

    def _require_state(self, *, active: bool) -> None:
        try:
            history = self._history()
            if (
                self._identity() is not self
                or self._invalid
                or self._sampling is not active
                or not _same_objects(self._configuration(), self._original_configuration)
                or _policy() != self._original_policy
                or not _same_objects(history.values, self._expected.values)
                or history.reasons is not self._expected.reasons
                or history.reason_values != self._expected.reason_values
                or history.sequence != self._expected.sequence + int(active)
            ):
                raise ValueError("original history required")
        except Exception:
            self._invalid = True
            raise MeasuredClockError("MEASURED_CLOCK_OWNERSHIP_CHANGED") from None

    def _utc(self) -> datetime:
        self._require_state(active=True)
        pending, calls = self._pending, self._source_calls
        try:
            return self._utc_now()
        finally:
            self._require_callback_exit(pending, calls)

    def _monotonic(self) -> int:
        self._require_state(active=True)
        pending, calls = self._pending, self._source_calls
        try:
            return self._monotonic_now_ns()
        finally:
            self._require_callback_exit(pending, calls)

    def _epoch(self) -> str:
        self._require_state(active=True)
        pending, calls = self._pending, self._source_calls
        try:
            return self._epoch_provider()
        finally:
            self._require_callback_exit(pending, calls)

    def _require_callback_exit(
        self, pending: chrony.ChronyStandardObservation | None, calls: int
    ) -> None:
        self._require_state(active=True)
        if self._pending is not pending or self._source_calls is not calls:
            self._invalid = True
            raise MeasuredClockError("MEASURED_CLOCK_SOURCE_PROGRESS_CHANGED")

    def _measurement(self, at: datetime, monotonic_ns: int) -> standard.TimeSourceMeasurement:
        self._require_state(active=True)
        try:
            if self._source_calls != 0 or self._pending is not None:
                self._invalid = True
                raise MeasuredClockError("MEASURED_CLOCK_DUPLICATE_SOURCE_READ")
            self._source_calls = 1
            try:
                observed = self._source.read_observation(at, monotonic_ns)
            finally:
                self._require_callback_exit(None, 1)
            self._source.require_original_observation(observed)
            self._pending = observed
            return observed.measurement
        finally:
            self._require_state(active=True)

    def _acquire(self) -> None:
        if self._identity() is not self:
            raise MeasuredClockError("MEASURED_CLOCK_OWNER_REQUIRED")
        if not self._lock.acquire(blocking=False):
            raise MeasuredClockError("MEASURED_CLOCK_BUSY")

    def _reduce_once(self) -> ClockHealthSnapshot:
        self._pending = None
        self._source_calls = 0
        self._sampling = True
        return self._clock.health_snapshot()

    def sample_health(self) -> SampledMeasuredHealth:
        """Take one original reducer step; failures keep StandardClock's semantics."""
        self._acquire()
        try:
            self._require_state(active=False)
            snapshot = self._reduce_once()
            if (
                self._invalid
                or not _same_objects(self._configuration(), self._original_configuration)
                or _policy() != self._original_policy
                or type(snapshot) is not ClockHealthSnapshot
                or snapshot.sequence != self._expected.sequence + 1
                or self._clock._sequence != snapshot.sequence
                or self._clock._latched_reasons is not self._expected.reasons
            ):
                raise MeasuredClockError("MEASURED_CLOCK_OWNERSHIP_CHANGED")
            observation = self._pending
            if observation is not None:
                self._source.require_original_observation(observation)
            if snapshot.evidence_class == "host-measurement":
                if observation is None or not _same_objects(
                    (
                        snapshot.source_id,
                        snapshot.source_observed_at_utc,
                        snapshot.source_observed_monotonic_ns,
                        snapshot.offset_ns,
                        snapshot.uncertainty_ns,
                    ),
                    chrony._measurement_fields(observation.measurement),
                ):
                    raise MeasuredClockError("MEASURED_CLOCK_CONVERSION_CHANGED")
            elif snapshot.evidence_class != "unavailable":
                raise MeasuredClockError("MEASURED_CLOCK_EVIDENCE_INVALID")
            self._expected = self._history()
            result = SampledMeasuredHealth(snapshot, observation)
            self._owned[id(result)] = result
            self._original[id(result)] = _OriginalHealth(
                ref(self),
                snapshot,
                tuple(getattr(snapshot, name) for name in _SNAPSHOT_FIELDS),
                observation,
            )
            finalize(result, self._original.pop, id(result), None)
            return result
        except Exception:
            self._invalid = True
            raise MeasuredClockError("MEASURED_CLOCK_OWNERSHIP_CHANGED") from None
        finally:
            self._sampling = False
            self._pending = None
            self._lock.release()

    def require_original_health(self, sample: SampledMeasuredHealth) -> None:
        """Verify historical ownership only; never sample, renew, or assert freshness."""
        self._acquire()
        try:
            self._require_state(active=False)
            if (
                type(sample) is not SampledMeasuredHealth
                or self._owned.get(id(sample)) is not sample
            ):
                raise ValueError("original sample required")
            original = self._original[id(sample)]
            if (
                original.owner() is not self
                or sample.snapshot is not original.snapshot
                or sample.source_observation is not original.source_observation
                or not _same_objects(
                    tuple(getattr(sample.snapshot, name) for name in _SNAPSHOT_FIELDS),
                    original.snapshot_values,
                )
            ):
                raise ValueError("original sample changed")
            if sample.source_observation is not None:
                self._source.require_original_observation(sample.source_observation)
        except Exception:
            raise MeasuredClockError("MEASURED_CLOCK_HEALTH_INVALID") from None
        finally:
            self._lock.release()
