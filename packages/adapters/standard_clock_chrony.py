"""Opt-in mechanical Chrony measurement bridge; no host/capture attestation.

The caller supplies an existing source and the same UTC/monotonic clock domain
used by StandardClock. Construction does not query or configure a time service.
The source's process runner requires separate qualification before actual use;
this adapter does not admit runtime profiles, re-arm, or issue capture evidence.
Authority identity is retained in the measurement ID; per-reading evidence must
be authenticated separately by a future resolver, not inferred from that ID.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta

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


@dataclass(frozen=True, slots=True)
class ChronyStandardTimeSource:
    """One original-deadline attempt; StandardClock owns health classification."""

    source: ChronyNtsTrustedTimeSource
    _authority_binding: tuple[str, str, str] = field(init=False, repr=False)
    _measurement_source_id: str = field(init=False, repr=False)

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
            return TimeSourceMeasurement(
                source_id=self._measurement_source_id,
                observed_at_utc=reading.local_observed_at_utc,
                observed_monotonic_ns=reading.observed_at_monotonic_ns,
                offset_ns=offset_ns,
                uncertainty_ns=uncertainty_ns,
            )
        except Exception:
            raise ChronyStandardTimeError("CHRONY_STANDARD_READING_INVALID") from None
