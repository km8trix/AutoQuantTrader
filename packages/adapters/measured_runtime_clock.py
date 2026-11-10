"""Unwired projection of original measured-clock health into pure domain records.

These process-local tokens confer no host, account, persistence or runtime-profile
authority. Currentness delegates to the original owner without refreshing a source.
The finite ownership checks assume cooperating Python, not a hostile-code sandbox.
"""

from __future__ import annotations

from _thread import LockType
from dataclasses import dataclass, field, fields
from threading import Lock
from typing import Literal, cast
from weakref import ReferenceType, WeakValueDictionary, finalize, ref

from packages.adapters import personal_measured_clock as measured
from packages.adapters import standard_clock as standard
from packages.adapters import standard_clock_chrony as chrony
from packages.adapters.trusted_time.chrony_nts import (
    ChronyNtsAuthority,
    ChronyNtsTrustedTimeSource,
)
from packages.application.personal_runtime import ClockHealthSnapshot, ClockHealthStatus
from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.measured_runtime_clock_contracts import (
    MEASURED_CLOCK_BRIDGE_VERSION,
    MEASURED_CLOCK_PROFILE,
    MeasuredClockSourceAssociation,
    MeasuredRuntimeClockObservation,
)
from packages.domain.personal_contracts import ContractRecord, VersionPin, content_digest
from packages.domain.runtime_operating_contracts import CLOCK_POLICY

_MEASURED_HANDLERS = (
    "sample_health",
    "require_original_health",
    "require_current_health",
    "_acquire",
    "_configuration",
    "_history",
    "_require_state",
    "_reduce_once",
    "_utc",
    "_monotonic",
    "_epoch",
    "_measurement",
    "_require_callback_exit",
    "_require_current_state",
    "_require_current_sample",
    "_current_callback",
    "_current_elapsed",
)
_BRIDGE_HANDLERS = ("read_observation", "require_original_observation", "_read_measurement")
_CONFIGURATION_FIELDS = (
    "_utc_now",
    "_monotonic_now_ns",
    "_epoch_provider",
    "_source",
    "_simulated_health",
)
_REDUCER_HANDLERS = ("_utc", "_monotonic", "_epoch", "_measurement")
_SCOPE_FIELDS = tuple(item.name for item in fields(ContinuousAccountScope))
_POLICY_FIELDS = tuple(item.name for item in fields(VersionPin))
_AUTHORITY_FIELDS = tuple(item.name for item in fields(ChronyNtsAuthority))
_OBSERVATION_FIELDS = tuple(item.name for item in fields(MeasuredRuntimeClockObservation))
_ASSOCIATION_FIELDS = tuple(item.name for item in fields(MeasuredClockSourceAssociation))
_SNAPSHOT_FIELDS = tuple(item.name for item in fields(ClockHealthSnapshot))
_READING_FIELDS = tuple(item.name for item in fields(TrustedTimeSourceReading))
_MEASUREMENT_FIELDS = tuple(item.name for item in fields(standard.TimeSourceMeasurement))
_MEASURED_ERRORS = frozenset(
    {
        "MEASURED_CLOCK_CONFIGURATION_INVALID",
        "MEASURED_CLOCK_OWNER_REQUIRED",
        "MEASURED_CLOCK_BUSY",
        "MEASURED_CLOCK_OWNERSHIP_CHANGED",
        "MEASURED_CLOCK_HISTORY_CHANGED",
        "MEASURED_CLOCK_SOURCE_PROGRESS_CHANGED",
        "MEASURED_CLOCK_DUPLICATE_SOURCE_READ",
        "MEASURED_CLOCK_CONVERSION_CHANGED",
        "MEASURED_CLOCK_EVIDENCE_INVALID",
        "MEASURED_CLOCK_HEALTH_INVALID",
        "MEASURED_CLOCK_CURRENT_INVALID",
    }
)
_ADAPTER_ERRORS = frozenset(
    {
        "MEASURED_RUNTIME_CLOCK_CONFIGURATION_INVALID",
        "MEASURED_RUNTIME_CLOCK_OWNER_REQUIRED",
        "MEASURED_RUNTIME_CLOCK_BUSY",
        "MEASURED_RUNTIME_CLOCK_SAMPLE_REQUIRED",
        "MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED",
        "MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED",
        "MEASURED_RUNTIME_CLOCK_FAILED",
    }
)


class MeasuredRuntimeClockError(ValueError):
    """Fixed diagnostics only; no callback output or private source details."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SampledMeasuredRuntimeClock:
    observation: MeasuredRuntimeClockObservation = field(repr=False)


@dataclass(frozen=True, slots=True)
class _OriginalSample:
    owner: ReferenceType[MeasuredRuntimeClockSampler]
    observation: MeasuredRuntimeClockObservation
    health: measured.SampledMeasuredHealth
    values: tuple[object, ...]


def _same_objects(actual: tuple[object, ...], expected: tuple[object, ...]) -> bool:
    return len(actual) == len(expected) and all(
        left is right for left, right in zip(actual, expected, strict=True)
    )


def _safe_error(error: BaseException) -> BaseException:
    if (
        type(error) is measured.MeasuredClockError or type(error) is MeasuredRuntimeClockError
    ) and (
        type(error.args) is tuple
        and len(error.args) == 1
        and type(error.args[0]) is str
        and (
            (type(error) is measured.MeasuredClockError and error.args[0] in _MEASURED_ERRORS)
            or (type(error) is MeasuredRuntimeClockError and error.args[0] in _ADAPTER_ERRORS)
        )
    ):
        return error
    return MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_FAILED")


def _require_functions() -> None:
    if any(getattr(owner, name) is not original for owner, name, original in _FUNCTIONS):
        raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED")


def _owner_configuration(owner: measured.PersonalMeasuredClock) -> tuple[object, ...]:
    """Read the original finite configuration shape without invoking its helpers."""
    bridge = owner._source
    source = bridge.source
    callbacks = (owner._utc_now, owner._monotonic_now_ns, owner._epoch_provider)
    source_callbacks = (source.utc_clock, source.monotonic_clock, source.runner)
    return (
        owner._clock,
        bridge,
        *callbacks,
        *(type(callback).__call__ for callback in callbacks),
        *(getattr(measured.PersonalMeasuredClock, name) for name in _REDUCER_HANDLERS),
        *(getattr(owner._clock, name) for name in _CONFIGURATION_FIELDS),
        standard.StandardClock.health_snapshot,
        standard.StandardClock.now,
        standard.StandardClock.monotonic_ns,
        chrony.ChronyStandardTimeSource.read_observation,
        chrony.ChronyStandardTimeSource.require_original_observation,
        chrony.ChronyStandardTimeSource._read_measurement,
        bridge._authority_binding,
        bridge._measurement_source_id,
        source,
        source.authority,
        type(source).read_trusted_time,
        type(source).__post_init__,
        type(source.authority).__post_init__,
        type(source.authority).semantic_sha256,
        type(source.authority).argv,
        *source_callbacks,
        *(type(callback).__call__ for callback in source_callbacks),
        *(getattr(source.authority, name) for name in _AUTHORITY_FIELDS),
    )


def _values(
    observation: MeasuredRuntimeClockObservation, health: measured.SampledMeasuredHealth
) -> tuple[object, ...]:
    if (
        type(observation) is not MeasuredRuntimeClockObservation
        or type(observation.scope) is not ContinuousAccountScope
        or type(observation.policy) is not VersionPin
        or type(health) is not measured.SampledMeasuredHealth
        or type(health.snapshot) is not ClockHealthSnapshot
        or (
            observation.source is not None
            and type(observation.source) is not MeasuredClockSourceAssociation
        )
    ):
        raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED")
    source_values: tuple[object, ...] = ()
    if health.source_observation is not None:
        original = health.source_observation
        if (
            type(original) is not chrony.ChronyStandardObservation
            or type(original.reading) is not TrustedTimeSourceReading
            or type(original.measurement) is not standard.TimeSourceMeasurement
        ):
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED")
        source_values = (
            original.reading,
            original.measurement,
            *(getattr(original.reading, name) for name in _READING_FIELDS),
            *(getattr(original.measurement, name) for name in _MEASUREMENT_FIELDS),
        )
    return (
        health,
        *(getattr(observation, name) for name in _OBSERVATION_FIELDS),
        *(getattr(observation.scope, name) for name in _SCOPE_FIELDS),
        *(getattr(observation.policy, name) for name in _POLICY_FIELDS),
        *(
            getattr(observation.source, name)
            for name in _ASSOCIATION_FIELDS
            if observation.source is not None
        ),
        health.snapshot,
        health.source_observation,
        *(getattr(health.snapshot, name) for name in _SNAPSHOT_FIELDS),
        *source_values,
    )


class MeasuredRuntimeClockSampler:
    """One unwired owned projection, with currentness retained by the measured owner."""

    def __init__(
        self, *, scope: ContinuousAccountScope, measured_clock: measured.PersonalMeasuredClock
    ) -> None:
        try:
            _require_functions()
            if (
                type(self) is not MeasuredRuntimeClockSampler
                or type(scope) is not ContinuousAccountScope
                or type(measured_clock) is not measured.PersonalMeasuredClock
                or type(measured_clock._identity) is not ReferenceType
                or measured_clock._identity() is not measured_clock
            ):
                raise ValueError("original owner and scope required")
            ContinuousAccountScope.__post_init__(scope)
            VersionPin.__post_init__(CLOCK_POLICY)
            if CLOCK_POLICY.version != standard.STANDARD_CLOCK_POLICY_VERSION or (
                CLOCK_POLICY.sha256
                != content_digest(
                    (
                        standard.WARNING_NS,
                        standard.BLOCK_NS,
                        standard.MAX_SAMPLE_AGE_NS,
                        standard.MAX_SAMPLING_DURATION_NS,
                        standard.HEALTHY_RECOVERY_NS,
                    )
                )
            ):
                raise ValueError("original clock policy required")
            self.scope = scope
            self._measured_clock = measured_clock
            self._identity = ref(self)
            self._lock = Lock()
            self._invalid = False
            self._owned: WeakValueDictionary[int, SampledMeasuredRuntimeClock] = (
                WeakValueDictionary()
            )
            self._original: dict[int, _OriginalSample] = {}
            self._binding_values = _BINDINGS(self)
            _CHECK(self)
        except BaseException:
            raise MeasuredRuntimeClockError(
                "MEASURED_RUNTIME_CLOCK_CONFIGURATION_INVALID"
            ) from None

    def _bindings(self) -> tuple[object, ...]:
        owner = self._measured_clock
        if (
            type(MEASURED_CLOCK_BRIDGE_VERSION) is not str
            or MEASURED_CLOCK_BRIDGE_VERSION != "personal-chrony-standard-clock/1"
            or type(chrony.CHRONY_STANDARD_BRIDGE_VERSION) is not str
            or chrony.CHRONY_STANDARD_BRIDGE_VERSION != MEASURED_CLOCK_BRIDGE_VERSION
            or type(self.scope) is not ContinuousAccountScope
            or type(owner) is not measured.PersonalMeasuredClock
            or type(owner._identity) is not ReferenceType
            or owner._identity() is not owner
            or type(owner._lock) is not LockType
            or type(owner._clock) is not standard.StandardClock
            or type(owner._source) is not chrony.ChronyStandardTimeSource
            or type(owner._source.source) is not ChronyNtsTrustedTimeSource
            or type(owner._source.source.authority) is not ChronyNtsAuthority
            or type(owner._original_configuration) is not tuple
            or type(owner._original_policy) is not tuple
            or type(owner._current_methods) is not tuple
            or any(name in vars(owner) for name in _MEASURED_HANDLERS)
            or not _same_objects(_owner_configuration(owner), owner._original_configuration)
            or not _same_objects(
                owner._original_policy,
                (
                    standard.STANDARD_CLOCK_POLICY_VERSION,
                    standard.WARNING_NS,
                    standard.BLOCK_NS,
                    standard.MAX_SAMPLE_AGE_NS,
                    standard.MAX_SAMPLING_DURATION_NS,
                    standard.HEALTHY_RECOVERY_NS,
                ),
            )
            or not _same_objects(
                tuple(
                    getattr(measured.PersonalMeasuredClock, name)
                    for name in measured._CURRENT_HANDLERS
                ),
                owner._current_methods,
            )
        ):
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED")
        bridge = owner._source
        return (
            self.scope,
            *(getattr(self.scope, name) for name in _SCOPE_FIELDS),
            CLOCK_POLICY,
            *(getattr(CLOCK_POLICY, name) for name in _POLICY_FIELDS),
            self._identity,
            self._lock,
            self._owned,
            self._original,
            owner,
            owner._identity,
            owner._lock,
            owner._owned,
            owner._original,
            owner._original_configuration,
            owner._original_policy,
            owner._current_methods,
            *_owner_configuration(owner),
            bridge._owned,
            bridge._original,
            MeasuredClockSourceAssociation.contract_version,
            MeasuredRuntimeClockObservation.contract_version,
            ContinuousAccountScope.contract_version,
            VersionPin.contract_version,
            MEASURED_CLOCK_PROFILE,
            MEASURED_CLOCK_BRIDGE_VERSION,
            chrony.CHRONY_STANDARD_BRIDGE_VERSION,
            standard.STANDARD_CLOCK_POLICY_VERSION,
            standard.WARNING_NS,
            standard.BLOCK_NS,
            standard.MAX_SAMPLE_AGE_NS,
            standard.MAX_SAMPLING_DURATION_NS,
            standard.HEALTHY_RECOVERY_NS,
        )

    def _require_bindings(self) -> None:
        try:
            _require_functions()
            if (
                type(self) is not MeasuredRuntimeClockSampler
                or type(self._identity) is not ReferenceType
                or self._identity() is not self
                or self._invalid is not False
                or any(name in vars(self) for name in _HANDLERS)
                or not _same_objects(_BINDINGS(self), self._binding_values)
            ):
                raise ValueError("original adapter bindings required")
        except BaseException:
            self._invalid = True
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED") from None

    def _acquire(self) -> LockType:
        try:
            if (
                type(self) is not MeasuredRuntimeClockSampler
                or type(self._identity) is not ReferenceType
                or self._identity() is not self
                or type(self._lock) is not LockType
            ):
                raise ValueError("original adapter required")
        except BaseException:
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_OWNER_REQUIRED") from None
        lock = self._lock
        if not lock.acquire(blocking=False):
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_BUSY")
        return lock

    def _lookup(self, token: SampledMeasuredRuntimeClock | None) -> _OriginalSample:
        if type(token) is not SampledMeasuredRuntimeClock:
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_REQUIRED")
        if type(self._owned) is not WeakValueDictionary or type(self._original) is not dict:
            self._invalid = True
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED")
        if self._owned.get(id(token)) is not token:
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_REQUIRED")
        original = self._original.get(id(token))
        if (
            type(original) is not _OriginalSample
            or type(original.owner) is not ReferenceType
            or original.owner() is not self
        ):
            self._invalid = True
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED")
        return original

    def _require_token(
        self,
        token: SampledMeasuredRuntimeClock,
        original: _OriginalSample,
        *,
        registered: bool = True,
    ) -> None:
        try:
            if (
                (
                    registered
                    and (
                        self._owned.get(id(token)) is not token
                        or self._original.get(id(token)) is not original
                    )
                )
                or type(original.owner) is not ReferenceType
                or original.owner() is not self
                or token.observation is not original.observation
                or not _same_objects(
                    _values(original.observation, original.health), original.values
                )
            ):
                raise ValueError("original sampled fields required")
            MeasuredRuntimeClockObservation.__post_init__(original.observation)
            if not _same_objects(_values(original.observation, original.health), original.values):
                raise ValueError("sampled fields changed during validation")
        except BaseException:
            self._invalid = True
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED") from None

    def _project(self, health: measured.SampledMeasuredHealth) -> MeasuredRuntimeClockObservation:
        snapshot = health.snapshot
        association = None
        if health.source_observation is not None:
            source = health.source_observation
            reading, conversion = source.reading, source.measurement
            binding = self._measured_clock._source._authority_binding
            association = MeasuredClockSourceAssociation(
                source_id=reading.source_id,
                source_authority_sha256=reading.source_authority_sha256,
                authority_semantic_sha256=binding[2],
                bridge_version="personal-chrony-standard-clock/1",
                measurement_source_id=conversion.source_id,
                local_observed_at_utc=reading.local_observed_at_utc,
                trusted_at_utc=reading.trusted_at_utc,
                observed_at_monotonic_ns=reading.observed_at_monotonic_ns,
                source_uncertainty_milliseconds=reading.source_uncertainty_milliseconds,
                source_evidence_sha256=reading.source_evidence_sha256,
            )
            if (
                reading.source_id != binding[0]
                or reading.source_authority_sha256 != binding[1]
                or conversion.source_id != self._measured_clock._source._measurement_source_id
                or association.offset_ns != conversion.offset_ns
                or association.uncertainty_ns != conversion.uncertainty_ns
            ):
                raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED")
        if type(snapshot.status) is not ClockHealthStatus:
            raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED")
        return MeasuredRuntimeClockObservation(
            scope=self.scope,
            profile="personal_chrony_measured/1",
            policy=CLOCK_POLICY,
            status=snapshot.status.value,
            reasons=snapshot.reasons,
            evidence_class=cast(
                Literal["unavailable", "host-measurement"], snapshot.evidence_class
            ),
            source_id=snapshot.source_id,
            observed_at_utc=snapshot.observed_at_utc,
            observed_monotonic_ns=snapshot.observed_monotonic_ns,
            source_observed_at_utc=snapshot.source_observed_at_utc,
            source_observed_monotonic_ns=snapshot.source_observed_monotonic_ns,
            epoch=snapshot.epoch,
            sequence=snapshot.sequence,
            offset_ns=snapshot.offset_ns,
            uncertainty_ns=snapshot.uncertainty_ns,
            sampling_duration_ns=snapshot.sampling_duration_ns,
            sample_age_ns=snapshot.sample_age_ns,
            recovery_ready=snapshot.recovery_ready,
            rearm_required=snapshot.rearm_required,
            source=association,
        )

    def _run(
        self,
        operation: Literal["sample", "history", "current"],
        token: SampledMeasuredRuntimeClock | None,
    ) -> SampledMeasuredRuntimeClock | None:
        lock = _ACQUIRE(self)
        try:
            original = None if operation == "sample" else _LOOKUP(self, token)
            health = None if original is None else original.health
            result = token
            _CHECK(self)
            if original is not None:
                _TOKEN(self, cast(SampledMeasuredRuntimeClock, result), original)
            primary = None
            try:
                if operation == "sample":
                    health = _SAMPLE(self._measured_clock)
                    _CHECK(self)
                if health is None:
                    raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_SAMPLE_REQUIRED")
                _HISTORY(self._measured_clock, health)
                _CHECK(self)
                if operation == "sample":
                    observation = _PROJECT(self, health)
                    original = _OriginalSample(
                        ref(self), observation, health, _values(observation, health)
                    )
                    result = SampledMeasuredRuntimeClock(observation)
                elif operation == "current":
                    _CURRENT(self._measured_clock, health)
            except BaseException as error:
                primary = _safe_error(error)
            secondary = None
            try:
                _CHECK(self)
                if result is not None and original is not None:
                    _TOKEN(self, result, original, registered=operation != "sample")
                if health is not None:
                    _HISTORY(self._measured_clock, health)
                    _CHECK(self)
                    if result is not None and original is not None:
                        _TOKEN(self, result, original, registered=operation != "sample")
            except BaseException as error:
                secondary = _safe_error(error)
            if primary is not None and secondary is not None:
                raise BaseExceptionGroup(
                    "MEASURED_RUNTIME_CLOCK_OPERATION_AND_CHECK_FAILED", [primary, secondary]
                ) from None
            if primary is not None:
                raise primary from None
            if secondary is not None:
                raise secondary from None
            if operation == "sample":
                if result is None or original is None:
                    raise MeasuredRuntimeClockError("MEASURED_RUNTIME_CLOCK_FAILED")
                finalize(result, self._original.pop, id(result), None)
                self._original[id(result)] = original
                self._owned[id(result)] = result
                return result
            return None
        finally:
            lock.release()

    def sample(self) -> SampledMeasuredRuntimeClock:
        """Invoke one original step; an early local failure can precede its source read."""
        return cast(SampledMeasuredRuntimeClock, _RUN(self, "sample", None))

    def require_sample(self, token: SampledMeasuredRuntimeClock) -> None:
        """Check historical ownership without local clock or source callbacks."""
        _RUN(self, "history", token)

    def require_current(self, token: SampledMeasuredRuntimeClock) -> None:
        """Delegate one currentness check; no new source read or healthy permit."""
        _RUN(self, "current", token)


_HANDLERS = (
    "__init__",
    "_bindings",
    "_require_bindings",
    "_acquire",
    "_lookup",
    "_require_token",
    "_project",
    "_run",
    "sample",
    "require_sample",
    "require_current",
)
_FUNCTIONS = (
    *(
        (measured.PersonalMeasuredClock, name, getattr(measured.PersonalMeasuredClock, name))
        for name in _MEASURED_HANDLERS
    ),
    *(
        (chrony.ChronyStandardTimeSource, name, getattr(chrony.ChronyStandardTimeSource, name))
        for name in _BRIDGE_HANDLERS
    ),
    *(
        (MeasuredRuntimeClockSampler, name, getattr(MeasuredRuntimeClockSampler, name))
        for name in _HANDLERS
    ),
    *(
        (owner, name, getattr(owner, name))
        for owner, names in (
            (
                MeasuredClockSourceAssociation,
                ("__init__", "__post_init__", "offset_ns", "uncertainty_ns"),
            ),
            (MeasuredRuntimeClockObservation, ("__init__", "__post_init__")),
            (SampledMeasuredRuntimeClock, ("__init__",)),
            (ContinuousAccountScope, ("__post_init__",)),
            (VersionPin, ("__post_init__",)),
            (ContractRecord, ("__post_init__",)),
        )
        for name in names
    ),
)
_BINDINGS = MeasuredRuntimeClockSampler._bindings
_CHECK = MeasuredRuntimeClockSampler._require_bindings
_ACQUIRE = MeasuredRuntimeClockSampler._acquire
_LOOKUP = MeasuredRuntimeClockSampler._lookup
_TOKEN = MeasuredRuntimeClockSampler._require_token
_PROJECT = MeasuredRuntimeClockSampler._project
_RUN = MeasuredRuntimeClockSampler._run
_SAMPLE = measured.PersonalMeasuredClock.sample_health
_HISTORY = measured.PersonalMeasuredClock.require_original_health
_CURRENT = measured.PersonalMeasuredClock.require_current_health
