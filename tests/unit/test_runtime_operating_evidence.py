"""Explicit simulation clock observations never qualify the actual host."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.application.personal_codec import decode_record, encode_record
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.runtime_operating_contracts import RuntimeClockObservation


class ModelClock:
    def __init__(self, at=None):
        self.at = at or datetime(2025, 2, 4, 14, tzinfo=UTC)
        self.mono = 1_000_000_000
        self.epoch = "explicit-test-epoch"

    def advance(self, seconds):
        self.at += timedelta(seconds=seconds)
        self.mono += int(seconds * 1_000_000_000)

    def sampler(self, scope):
        return RuntimeClockSampler.simulation_model(
            scope=scope,
            utc_now=lambda: self.at,
            monotonic_now_ns=lambda: self.mono,
            epoch_provider=lambda: self.epoch,
        )


def healthy_sampler(scope=None, at=None):
    scope = scope or ContinuousAccountScope("test-account", "a" * 64, "test-stream")
    clock = ModelClock(None if at is None else at - timedelta(seconds=60))
    sampler = clock.sampler(scope)
    values = [sampler.sample()]
    for _ in range(3):
        clock.advance(20)
        values.append(sampler.sample())
    return clock, sampler, values[-1]


def test_actual_standard_sampler_retains_original_qualification_and_model_class():
    clock, sampler, sample = healthy_sampler()
    observation = sample.observation
    assert observation.status == "healthy" and observation.recovery_ready
    assert observation.profile == "explicit_simulation_time_model"
    assert observation.evidence_class == "simulated"
    assert observation.sequence == 4 and observation.rearm_required
    assert observation.observed_at_utc == clock.at
    assert observation.observed_monotonic_ns == clock.mono
    assert decode_record(encode_record(observation), RuntimeClockObservation) == observation
    sampler.require_sample(sample)
    sampler.require_current(observation)
    with pytest.raises(ValueError, match="original sampler"):
        sampler.require_sample(replace(sample))


def test_default_actual_host_sampler_is_explicitly_unavailable():
    sampler = RuntimeClockSampler(scope=ContinuousAccountScope("host", "a" * 64, "host"))
    observation = sampler.sample().observation
    assert observation.profile == "host_unqualified" and observation.status == "blocked"
    assert observation.evidence_class == "unavailable" and observation.offset_ns is None
    with pytest.raises(ValueError, match="not current"):
        sampler.require_current(observation)


@pytest.mark.parametrize("change", ["utc_regression", "mono_regression", "epoch", "stale", "drift"])
def test_current_guard_never_refreshes_original_clock_or_ignores_monotonic(change):
    clock, sampler, sample = healthy_sampler()
    original = encode_record(sample.observation)
    if change == "utc_regression":
        clock.at -= timedelta(microseconds=1)
    elif change == "mono_regression":
        clock.mono -= 1
    elif change == "epoch":
        clock.epoch = "changed"
    elif change == "stale":
        clock.advance(30)
    else:
        clock.mono += 250_000_000
    with pytest.raises(ValueError):
        sampler.require_current(sample.observation)
    assert encode_record(sample.observation) == original


def test_just_before_original_deadline_remains_current_and_clock_fault_latches():
    clock, sampler, sample = healthy_sampler()
    clock.advance(29.999999)
    sampler.require_current(sample.observation)
    clock.epoch = "new-epoch"
    blocked = sampler.sample().observation
    assert blocked.status == "blocked" and "epoch_changed" in blocked.reasons
    for _ in range(4):
        clock.advance(20)
        blocked = sampler.sample().observation
    assert blocked.status == "blocked" and blocked.rearm_required
    assert "fault_latched_rearm_required" in blocked.reasons


@pytest.mark.parametrize("change", ["outer", "clock", "scope"])
def test_same_instance_sample_mutation_cannot_rewrite_original_observation(change):
    _clock, sampler, sample = healthy_sampler()
    if change == "outer":
        object.__setattr__(sample, "observation", replace(sample.observation, sequence=5))
    elif change == "clock":
        object.__setattr__(sample.observation, "observed_monotonic_ns", 0)
    else:
        object.__setattr__(sample.observation.scope, "account_id", "changed-account")
    with pytest.raises(ValueError, match="original sampled"):
        sampler.require_sample(sample)
