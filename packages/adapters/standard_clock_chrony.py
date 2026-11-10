"""Opt-in mechanical Chrony measurement bridge; no host/capture attestation.

The caller supplies an existing source and the same UTC/monotonic clock domain
used by StandardClock. Construction does not query or configure a time service.
The source's process runner requires separate qualification before actual use;
this adapter does not admit runtime profiles, re-arm, or issue capture evidence.
Authority identity is retained in the measurement ID; per-reading evidence must
be authenticated separately by a future resolver, not inferred from that ID.
The optional owned observation retains a reading-to-measurement association;
it does not establish health history, currentness or host qualification.
Ownership assumes the cooperating Python implementation, not a hostile-code sandbox.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from weakref import ReferenceType, WeakValueDictionary, finalize, ref

from packages.adapters.standard_clock import MAX_SAMPLING_DURATION_NS, TimeSourceMeasurement
from packages.adapters.trusted_time.chrony_nts import ChronyNtsTrustedTimeSource
from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from packages.domain.canonical import canonical_json_bytes

CHRONY_STANDARD_BRIDGE_VERSION = "personal-chrony-standard-clock/1"


class ChronyStandardTimeError(ValueError):
    """Fixed diagnostics only; never include source exceptions or command output."""


def _binding(source: ChronyNtsTrustedTimeSource) -> tuple[str, str, str]:
    if type(source) is not ChronyNtsTrustedTimeSource:
        raise ValueError("exact source required")
    source.__post_init__()
    authority = source.authority
    return (
        authority.source_id,
        authority.source_authority_sha256,
        authority.semantic_sha256,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ChronyStandardObservation:
    """Mechanical conversion evidence; only its producing owner can verify it."""

    reading: TrustedTimeSourceReading = field(repr=False)
    measurement: TimeSourceMeasurement = field(repr=False)


@dataclass(frozen=True, slots=True)
class _OriginalObservation:
    owner: ReferenceType[ChronyStandardTimeSource]
    reading: TrustedTimeSourceReading
    measurement: TimeSourceMeasurement
    reading_fields: tuple[object, ...]
    measurement_fields: tuple[object, ...]
    source_owners: tuple[object, ...]
    authority_binding: tuple[str, str, str]
    measurement_source_id: str


def _reading_fields(reading: TrustedTimeSourceReading) -> tuple[object, ...]:
    return (
        reading.source_id,
        reading.source_authority_sha256,
        reading.local_observed_at_utc,
        reading.trusted_at_utc,
        reading.observed_at_monotonic_ns,
        reading.source_uncertainty_milliseconds,
        reading.source_evidence_sha256,
    )


def _measurement_fields(measurement: TimeSourceMeasurement) -> tuple[object, ...]:
    return (
        measurement.source_id,
        measurement.observed_at_utc,
        measurement.observed_monotonic_ns,
        measurement.offset_ns,
        measurement.uncertainty_ns,
    )


def _source_owners(source: ChronyNtsTrustedTimeSource) -> tuple[object, ...]:
    if type(source) is not ChronyNtsTrustedTimeSource:
        raise ValueError("exact source required")
    callbacks = (source.utc_clock, source.monotonic_clock, source.runner)
    return (
        source,
        source.authority,
        type(source).read_trusted_time,
        type(source).__post_init__,
        type(source.authority).__post_init__,
        type(source.authority).semantic_sha256,
        type(source.authority).argv,
        *callbacks,
        *(type(callback).__call__ for callback in callbacks),
    )


def _same_objects(current: tuple[object, ...], original: tuple[object, ...]) -> bool:
    return len(current) == len(original) and all(
        actual is expected for actual, expected in zip(current, original, strict=True)
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ChronyStandardTimeSource:
    """One original-deadline attempt; StandardClock owns health classification."""

    source: ChronyNtsTrustedTimeSource
    _authority_binding: tuple[str, str, str] = field(init=False, repr=False)
    _measurement_source_id: str = field(init=False, repr=False)
    _owned: WeakValueDictionary[int, ChronyStandardObservation] = field(
        default_factory=WeakValueDictionary, init=False, repr=False, compare=False
    )
    _original: dict[int, _OriginalObservation] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        try:
            binding = _binding(self.source)
            identity = hashlib.sha256(
                canonical_json_bytes((CHRONY_STANDARD_BRIDGE_VERSION, binding))
            ).hexdigest()
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_SOURCE_INVALID") from None
        object.__setattr__(self, "_authority_binding", binding)
        object.__setattr__(self, "_measurement_source_id", f"chrony-standard:{identity}")

    def __call__(
        self, started_at_utc: datetime, started_monotonic_ns: int
    ) -> TimeSourceMeasurement:
        return self._read_measurement(started_at_utc, started_monotonic_ns)[1]

    def _read_measurement(
        self, started_at_utc: datetime, started_monotonic_ns: int
    ) -> tuple[TrustedTimeSourceReading, TimeSourceMeasurement]:
        try:
            if (
                type(started_at_utc) is not datetime
                or started_at_utc.tzinfo is None
                or started_at_utc.utcoffset() != timedelta(0)
                or type(started_monotonic_ns) is not int
                or started_monotonic_ns < 0
            ):
                raise ValueError("invalid callback clock")
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_CALL_INVALID") from None
        try:
            if _binding(self.source) != self._authority_binding:
                raise ValueError("authority changed")
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_AUTHORITY_CHANGED") from None
        try:
            reading = self.source.read_trusted_time(
                deadline_monotonic_ns=started_monotonic_ns + MAX_SAMPLING_DURATION_NS
            )
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_READ_UNAVAILABLE") from None
        try:
            if _binding(self.source) != self._authority_binding:
                raise ValueError("authority changed")
            if type(reading) is not TrustedTimeSourceReading:
                raise ValueError("exact reading required")
            reading.__post_init__()
            if (
                reading.source_id != self._authority_binding[0]
                or reading.source_authority_sha256 != self._authority_binding[1]
            ):
                raise ValueError("reading authority differs")
            delta = reading.trusted_at_utc - reading.local_observed_at_utc
            offset_ns = (delta.days * 86_400 + delta.seconds) * 1_000_000_000
            offset_ns += delta.microseconds * 1_000
            numerator, denominator = reading.source_uncertainty_milliseconds.as_integer_ratio()
            uncertainty_ns = -(-(numerator * 1_000_000) // denominator)
            measurement = TimeSourceMeasurement(
                source_id=self._measurement_source_id,
                observed_at_utc=reading.local_observed_at_utc,
                observed_monotonic_ns=reading.observed_at_monotonic_ns,
                offset_ns=offset_ns,
                uncertainty_ns=uncertainty_ns,
            )
            return reading, measurement
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_READING_INVALID") from None

    def read_observation(
        self, started_at_utc: datetime, started_monotonic_ns: int
    ) -> ChronyStandardObservation:
        """Opt in to retaining one original conversion, with the same single read.

        A source may use an injected test runner. Ownership proves only which
        objects participated, never that the runner or actual host is qualified.
        """
        try:
            owners = _source_owners(self.source)
            authority_binding = self._authority_binding
            measurement_source_id = self._measurement_source_id
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_OBSERVATION_INVALID") from None
        reading, measurement = self._read_measurement(started_at_utc, started_monotonic_ns)
        try:
            if (
                not _same_objects(_source_owners(self.source), owners)
                or self._authority_binding is not authority_binding
                or self._measurement_source_id is not measurement_source_id
            ):
                raise ValueError("source owners changed during read")
            result = ChronyStandardObservation(reading, measurement)
            original = _OriginalObservation(
                ref(self),
                reading,
                measurement,
                _reading_fields(reading),
                _measurement_fields(measurement),
                owners,
                authority_binding,
                measurement_source_id,
            )
            self._owned[id(result)] = result
            self._original[id(result)] = original
            finalize(result, self._original.pop, id(result), None)
            return result
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_OBSERVATION_INVALID") from None

    def require_original_observation(self, observation: ChronyStandardObservation) -> None:
        """Check original objects without reading a source or sampling any clock.

        This deliberately grants no currentness or health claim: an unchanged
        historical observation stays verifiable without renewing its timestamps.
        """
        try:
            if (
                type(observation) is not ChronyStandardObservation
                or self._owned.get(id(observation)) is not observation
            ):
                raise ValueError("original observation required")
            original = self._original[id(observation)]
            if (
                original.owner() is not self
                or observation.reading is not original.reading
                or observation.measurement is not original.measurement
                or not _same_objects(_reading_fields(observation.reading), original.reading_fields)
                or not _same_objects(
                    _measurement_fields(observation.measurement), original.measurement_fields
                )
                or not _same_objects(_source_owners(self.source), original.source_owners)
                or self._authority_binding is not original.authority_binding
                or self._measurement_source_id is not original.measurement_source_id
                or _binding(self.source) != original.authority_binding
            ):
                raise ValueError("original conversion or source changed")
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_OBSERVATION_INVALID") from None
