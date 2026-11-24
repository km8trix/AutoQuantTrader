"""Owned StandardClock observations; host defaults remain unqualified."""

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from uuid import uuid4
from weakref import WeakValueDictionary, finalize

from packages.adapters import standard_clock as standard
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.personal_contracts import content_digest
from packages.domain.runtime_operating_contracts import (
    CLOCK_POLICY,
    ClockProfile,
    RuntimeClockObservation,
)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SampledRuntimeClock:
    observation: RuntimeClockObservation


class RuntimeClockSampler:
    """The default source measures local clocks but cannot establish UTC accuracy.

    The explicit model constructor is confined to stateful simulation. Neither
    healthy model output nor these in-process tokens qualifies the actual host.
    """

    def __init__(self, *, scope: ContinuousAccountScope) -> None:
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
            raise ValueError("retained clock policy differs from the actual StandardClock")
        self.scope = scope
        self.profile: ClockProfile = "host_unqualified"
        process = uuid4().hex
        self._epoch_provider: Callable[[], str] = lambda: f"{process}:{os.getpid()}"
        self._clock = standard.StandardClock(epoch_provider=self._epoch_provider)
        self._owned: WeakValueDictionary[int, SampledRuntimeClock] = WeakValueDictionary()
        self._original: dict[int, tuple[RuntimeClockObservation, str]] = {}

    @classmethod
    def simulation_model(
        cls,
        *,
        scope: ContinuousAccountScope,
        utc_now: Callable[[], datetime],
        monotonic_now_ns: Callable[[], int],
        epoch_provider: Callable[[], str],
    ) -> "RuntimeClockSampler":
        result = cls(scope=scope)
        result.profile = "explicit_simulation_time_model"
        result._epoch_provider = epoch_provider
        result._clock = standard.StandardClock(
            utc_now=utc_now,
            monotonic_now_ns=monotonic_now_ns,
            epoch_provider=epoch_provider,
            simulated_health=True,
        )
        return result

    def sample(self) -> SampledRuntimeClock:
        observed = self._clock.health_snapshot()
        fields = {
            name: getattr(observed, name)
            for name in RuntimeClockObservation.__dataclass_fields__
            if name not in ("contract_version", "scope", "profile", "policy", "status")
        }
        record = RuntimeClockObservation(
            scope=self.scope,
            profile=self.profile,
            policy=CLOCK_POLICY,
            status=cast(Any, observed.status.value),
            **fields,
        )
        result = SampledRuntimeClock(record)
        self._owned[id(result)] = result
        self._original[id(result)] = (record, record.semantic_sha256)
        finalize(result, self._original.pop, id(result), None)
        return result

    def require_sample(self, sample: SampledRuntimeClock) -> None:
        if type(sample) is not SampledRuntimeClock or self._owned.get(id(sample)) is not sample:
            raise ValueError("original sampler-produced clock observation required")
        original = self._original[id(sample)]
        if (
            sample.observation is not original[0]
            or sample.observation.semantic_sha256 != original[1]
        ):
            raise ValueError("original sampled clock observation changed")

    def require_current(self, observation: RuntimeClockObservation) -> None:
        """Read local clock scalars only; never refresh an original source deadline."""
        before = self._clock.monotonic_ns()
        instant = self._clock.now()
        epoch = self._epoch_provider()
        mono = self._clock.monotonic_ns()
        if (
            observation.scope != self.scope
            or observation.profile != self.profile
            or observation.profile != "explicit_simulation_time_model"
            or observation.status != "healthy"
            or not observation.recovery_ready
            or observation.epoch != epoch
            or not 0 <= mono - before < standard.MAX_SAMPLING_DURATION_NS
        ):
            raise ValueError("original clock scope, health or epoch is not current")
        for at, original_mono in (
            (observation.observed_at_utc, observation.observed_monotonic_ns),
            (observation.source_observed_at_utc, observation.source_observed_monotonic_ns),
        ):
            if at is None or original_mono is None:
                raise ValueError("original clock observation is incomplete")
            elapsed = instant - at
            wall = (
                elapsed.days * 86400 + elapsed.seconds
            ) * 1_000_000_000 + elapsed.microseconds * 1000
            monotonic = mono - original_mono
            if (
                not 0 <= wall < standard.MAX_SAMPLE_AGE_NS
                or not 0 <= monotonic < standard.MAX_SAMPLE_AGE_NS
                or abs(wall - monotonic) >= standard.WARNING_NS
            ):
                raise ValueError("original clock deadline elapsed or clocks disagree")
