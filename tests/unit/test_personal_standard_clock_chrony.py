"""Offline personal bridge tests; original Chrony parser fixtures remain synthetic."""

import copy
import gc
import pickle
import weakref
from dataclasses import fields, replace
from datetime import datetime, timedelta, tzinfo
from decimal import Decimal, Inexact, localcontext

import pytest

from packages.adapters.standard_clock import StandardClock
from packages.adapters.standard_clock_chrony import (
    ChronyStandardObservation,
    ChronyStandardTimeError,
    ChronyStandardTimeSource,
)
from packages.adapters.trusted_time import chrony_nts
from packages.adapters.trusted_time.chrony_nts import ChronyNtsTrustedTimeSource
from packages.application.personal_runtime import ClockHealthStatus
from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from tests.unit.test_chrony_nts import BASE, _authority, _source


@pytest.fixture(autouse=True)
def forbid_real_process(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("real process forbidden in bridge qualification")

    monkeypatch.setattr(chrony_nts.subprocess, "Popen", forbidden)


def reading(**overrides: object) -> TrustedTimeSourceReading:
    values: dict[str, object] = {
        "source_id": _authority().source_id,
        "source_authority_sha256": _authority().source_authority_sha256,
        "local_observed_at_utc": BASE,
        "trusted_at_utc": BASE + timedelta(microseconds=2_001),
        "observed_at_monotonic_ns": 10_000_000_000,
        "source_uncertainty_milliseconds": Decimal("0.0000011"),
        "source_evidence_sha256": "b" * 64,
    }
    values.update(overrides)
    return TrustedTimeSourceReading(**values)  # type: ignore[arg-type]


def stub_read(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> tuple[ChronyStandardTimeSource, list[int]]:
    source, _ = _source()
    calls: list[int] = []

    def read(self: ChronyNtsTrustedTimeSource, *, deadline_monotonic_ns: int) -> object:
        assert self is source
        calls.append(deadline_monotonic_ns)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    return ChronyStandardTimeSource(source), calls


@pytest.mark.parametrize("microseconds", [2_001, -2_001, 0])
def test_signed_offset_and_original_timestamps(
    monkeypatch: pytest.MonkeyPatch, microseconds: int
) -> None:
    original = reading(trusted_at_utc=BASE + timedelta(microseconds=microseconds))
    bridge, calls = stub_read(monkeypatch, original)
    measurement = bridge(BASE + timedelta(milliseconds=5), 10_005_000_000)
    assert measurement.observed_at_utc is original.local_observed_at_utc
    assert measurement.observed_monotonic_ns == original.observed_at_monotonic_ns
    assert measurement.offset_ns == microseconds * 1_000
    assert calls == [11_005_000_000]


@pytest.mark.parametrize(
    ("milliseconds", "expected_ns"),
    [("0", 0), ("0.000001", 1), ("0.0000011", 2), ("99.9999999", 100_000_000)],
)
def test_uncertainty_rounds_up_without_decimal_context_rounding(
    monkeypatch: pytest.MonkeyPatch, milliseconds: str, expected_ns: int
) -> None:
    bridge, _ = stub_read(
        monkeypatch, reading(source_uncertainty_milliseconds=Decimal(milliseconds))
    )
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        assert bridge(BASE, 10_000_000_000).uncertainty_ns == expected_ns


def test_source_identity_binds_authority_configuration_not_per_reading_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = reading()
    bridge, _ = stub_read(monkeypatch, original)
    identity = bridge(BASE, 10_000_000_000).source_id
    object.__setattr__(original, "source_evidence_sha256", "c" * 64)
    assert bridge(BASE, 10_000_000_000).source_id == identity
    assert len(identity) <= 128
    altered = replace(bridge.source, authority=_authority(socket_path="/run/chrony/other.sock"))
    other = ChronyStandardTimeSource(altered)
    assert other._measurement_source_id != identity


@pytest.mark.parametrize("field", ["source_id", "source_authority_sha256"])
def test_reading_authority_mismatch_rejected(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    value = "other-source" if field == "source_id" else "d" * 64
    bridge, calls = stub_read(monkeypatch, reading(**{field: value}))
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READING_INVALID$"):
        bridge(BASE, 10_000_000_000)
    assert calls == [11_000_000_000]


def test_changed_authority_rejected_before_read(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge, calls = stub_read(monkeypatch, reading())
    object.__setattr__(bridge.source, "authority", _authority(socket_path="/run/changed.sock"))
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_AUTHORITY_CHANGED$"):
        bridge(BASE, 10_000_000_000)
    assert calls == []


def test_changed_authority_during_read_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    source, _ = _source()
    bridge = ChronyStandardTimeSource(source)
    calls = []

    def read(self: ChronyNtsTrustedTimeSource, *, deadline_monotonic_ns: int) -> object:
        calls.append(deadline_monotonic_ns)
        object.__setattr__(self, "authority", _authority(socket_path="/run/changed.sock"))
        return reading()

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READING_INVALID$"):
        bridge(BASE, 10_000_000_000)
    assert calls == [11_000_000_000]


@pytest.mark.parametrize("value", [None, object(), {"source_id": "fake"}])
def test_nonexact_reading_rejected(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    bridge, _ = stub_read(monkeypatch, value)
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READING_INVALID$"):
        bridge(BASE, 10_000_000_000)


@pytest.mark.parametrize("value", [None, object()])
def test_nonexact_source_rejected(value: object) -> None:
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_SOURCE_INVALID$"):
        ChronyStandardTimeSource(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("at", "mono"),
    [(datetime(2026, 7, 31), 0), (BASE, -1), (BASE, True), ("private-clock-value", 0)],
)
def test_invalid_call_has_static_diagnostic_and_no_read(
    monkeypatch: pytest.MonkeyPatch, at: object, mono: object
) -> None:
    bridge, calls = stub_read(monkeypatch, reading())
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_CALL_INVALID$"):
        bridge(at, mono)  # type: ignore[arg-type]
    assert calls == []


def test_raising_timezone_is_sanitized_before_source_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenTimezone(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta | None:
            raise RuntimeError("private timezone diagnostic")

    bridge, calls = stub_read(monkeypatch, reading())
    at = datetime(2026, 7, 31, tzinfo=BrokenTimezone())
    with pytest.raises(ChronyStandardTimeError) as error:
        bridge(at, 10_000_000_000)
    assert str(error.value) == "CHRONY_STANDARD_CALL_INVALID"
    assert error.value.__suppress_context__
    assert calls == []


def test_source_failure_is_static_unavailable_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge, calls = stub_read(monkeypatch, RuntimeError("private provider diagnostic"))
    with pytest.raises(ChronyStandardTimeError) as error:
        bridge(BASE, 10_000_000_000)
    assert str(error.value) == "CHRONY_STANDARD_READ_UNAVAILABLE"
    assert error.value.__suppress_context__
    assert calls == [11_000_000_000]
    snapshot = StandardClock(
        utc_now=lambda: BASE,
        monotonic_now_ns=lambda: 10_000_000_000,
        source=bridge,
    ).health_snapshot()
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert snapshot.evidence_class == "unavailable"
    assert snapshot.offset_ns is snapshot.uncertainty_ns is None
    assert "clock_or_source_unavailable" in snapshot.reasons
    assert calls == [11_000_000_000, 11_000_000_000]


@pytest.mark.parametrize(
    ("age_ns", "reason"), [(30_000_000_000, "sample_stale"), (-1_000, "future_sample")]
)
def test_original_observation_age_is_not_refreshed(
    monkeypatch: pytest.MonkeyPatch, age_ns: int, reason: str
) -> None:
    bridge, _ = stub_read(
        monkeypatch,
        reading(
            local_observed_at_utc=BASE - timedelta(microseconds=age_ns // 1_000),
            observed_at_monotonic_ns=100_000_000_000 - age_ns,
        ),
    )
    snapshot = StandardClock(
        utc_now=lambda: BASE, monotonic_now_ns=lambda: 100_000_000_000, source=bridge
    ).health_snapshot()
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert reason in snapshot.reasons


def test_real_chrony_parser_fixture_through_bridge_to_standard_clock() -> None:
    source, runner = _source()
    clock = StandardClock(
        utc_now=iter((BASE, BASE + timedelta(milliseconds=20))).__next__,
        monotonic_now_ns=iter((1_000, 20_001_000)).__next__,
        epoch_provider=lambda: "synthetic-process-epoch",
        source=ChronyStandardTimeSource(source),
    )
    snapshot = clock.health_snapshot()
    assert runner.calls == 1
    assert runner.deadline_monotonic_ns == 1_000_001_000
    assert snapshot.status is ClockHealthStatus.BLOCKED
    assert snapshot.reasons == ("startup_qualifying",)
    assert snapshot.offset_ns == 2_000_000
    assert snapshot.uncertainty_ns == 30_000_000
    assert snapshot.source_observed_at_utc == BASE + timedelta(milliseconds=10)
    assert snapshot.source_observed_monotonic_ns == 10_001_000
    assert snapshot.sample_age_ns == 10_000_000
    assert not snapshot.recovery_ready
    assert snapshot.rearm_required


def test_expired_original_deadline_never_runs_chronyc() -> None:
    source, runner = _source(monotonic_values=(1_000_000_000,))
    bridge = ChronyStandardTimeSource(source)
    with pytest.raises(ChronyStandardTimeError, match=r"^CHRONY_STANDARD_READ_UNAVAILABLE$"):
        bridge(BASE, 0)
    assert runner.calls == 0


@pytest.mark.parametrize("elapsed_ns", [999_999_000, 1_000_000_000])
def test_complete_callback_sampling_duration_keeps_strict_original_limit(
    monkeypatch: pytest.MonkeyPatch, elapsed_ns: int
) -> None:
    bridge, calls = stub_read(monkeypatch, reading())
    clock = StandardClock(
        utc_now=iter((BASE, BASE + timedelta(microseconds=elapsed_ns // 1_000))).__next__,
        monotonic_now_ns=iter((10_000_000_000, 10_000_000_000 + elapsed_ns)).__next__,
        source=bridge,
    )
    snapshot = clock.health_snapshot()
    assert calls == [11_000_000_000]
    assert snapshot.sampling_duration_ns == elapsed_ns
    assert ("sampling_timeout" in snapshot.reasons) == (elapsed_ns == 1_000_000_000)
    assert snapshot.status is ClockHealthStatus.BLOCKED


def test_bridge_does_not_skip_startup_or_clear_a_latched_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _ = _source()
    elapsed = 0
    offset = 0
    calls: list[int] = []

    def read(self: ChronyNtsTrustedTimeSource, *, deadline_monotonic_ns: int) -> object:
        assert self is source
        calls.append(deadline_monotonic_ns)
        return reading(
            local_observed_at_utc=BASE + timedelta(seconds=elapsed),
            trusted_at_utc=BASE + timedelta(seconds=elapsed, microseconds=offset),
            observed_at_monotonic_ns=10_000_000_000 + elapsed * 1_000_000_000,
            source_uncertainty_milliseconds=Decimal(0),
        )

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    clock = StandardClock(
        utc_now=lambda: BASE + timedelta(seconds=elapsed),
        monotonic_now_ns=lambda: 10_000_000_000 + elapsed * 1_000_000_000,
        epoch_provider=lambda: "synthetic-process-epoch",
        source=ChronyStandardTimeSource(source),
    )
    for sample_elapsed in (0, 10, 20, 30, 40, 50):
        elapsed = sample_elapsed
        snapshot = clock.health_snapshot()
        assert snapshot.reasons == ("startup_qualifying",)
        assert not snapshot.recovery_ready
    elapsed = 60
    assert clock.health_snapshot().status is ClockHealthStatus.HEALTHY
    elapsed, offset = 61, 1_000_000
    assert "offset_blocked" in clock.health_snapshot().reasons
    elapsed, offset = 62, 0
    recovered = clock.health_snapshot()
    assert recovered.status is ClockHealthStatus.BLOCKED
    assert "fault_latched_rearm_required" in recovered.reasons
    assert recovered.rearm_required
    assert calls == [
        (11 + second) * 1_000_000_000 for second in (0, 10, 20, 30, 40, 50, 60, 61, 62)
    ]


def test_opt_in_observation_retains_exact_reading_and_unchanged_conversion(monkeypatch):
    original = reading()
    bridge, calls = stub_read(monkeypatch, original)
    assert calls == []
    observation = bridge.read_observation(BASE, 10_000_000_000)
    assert observation.reading is original
    assert observation.reading.source_evidence_sha256 == "b" * 64
    assert observation.measurement == bridge(BASE, 10_000_000_000)
    assert calls == [11_000_000_000, 11_000_000_000]
    assert len(bridge._owned) == len(bridge._original) == 1
    bridge.require_original_observation(observation)
    assert calls == [11_000_000_000, 11_000_000_000]


def test_legacy_call_does_not_register_or_inspect_opt_in_owners(monkeypatch):
    from packages.adapters import standard_clock_chrony as module

    bridge, calls = stub_read(monkeypatch, reading())

    def forbidden(*args):
        pytest.fail("legacy conversion must not inspect opt-in owners")

    monkeypatch.setattr(module, "_source_owners", forbidden)
    result = bridge(BASE, 10_000_000_000)
    assert result.offset_ns == 2_001_000 and result.uncertainty_ns == 2
    assert calls == [11_000_000_000]
    assert not bridge._owned and not bridge._original


def test_parser_fixture_observation_matches_legacy_output_without_extra_read():
    source, runner = _source()
    legacy_source, legacy_runner = _source()
    bridge = ChronyStandardTimeSource(source)
    assert runner.calls == 0
    observation = bridge.read_observation(BASE, 1_000)
    expected = ChronyStandardTimeSource(legacy_source)(BASE, 1_000)
    assert observation.measurement == expected
    assert observation.reading.local_observed_at_utc == expected.observed_at_utc
    assert observation.reading.observed_at_monotonic_ns == expected.observed_monotonic_ns
    assert len(observation.reading.source_evidence_sha256) == 64
    bridge.require_original_observation(observation)
    assert runner.calls == legacy_runner.calls == 1
    assert runner.deadline_monotonic_ns == legacy_runner.deadline_monotonic_ns == 1_000_001_000


def test_registry_preserves_dataclass_construction_repr_equality_and_hash(monkeypatch):
    bridge, calls = stub_read(monkeypatch, reading())
    other = replace(bridge)
    before_repr, before_hash = repr(bridge), hash(bridge)
    assert bridge == other
    assert [item.name for item in fields(bridge) if item.init] == ["source"]
    observation = bridge.read_observation(BASE, 10_000_000_000)
    assert bridge == other and hash(bridge) == hash(other) == before_hash
    assert repr(bridge) == before_repr
    assert "_owned" not in before_repr and "_original" not in before_repr
    assert repr(observation) == "ChronyStandardObservation()"
    assert calls == [11_000_000_000]
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        other.require_original_observation(observation)


@pytest.mark.parametrize(
    "clone",
    [
        copy.copy,
        copy.deepcopy,
        replace,
        lambda observation: pickle.loads(pickle.dumps(observation)),
        lambda observation: ChronyStandardObservation(observation.reading, observation.measurement),
        lambda observation: object(),
    ],
)
def test_only_original_registered_observation_is_accepted(monkeypatch, clone):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(clone(observation))
    bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


@pytest.mark.parametrize("clone", [copy.copy, replace])
def test_copied_owner_cannot_verify_original_observation(monkeypatch, clone):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    copied_owner = clone(bridge)
    assert copied_owner == bridge
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        copied_owner.require_original_observation(observation)
    bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


def test_copied_registry_cannot_outlive_and_replace_original_owner(monkeypatch):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    copied_owner = copy.copy(bridge)
    original_owner = weakref.ref(bridge)
    del bridge
    gc.collect()
    assert original_owner() is None
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        copied_owner.require_original_observation(observation)
    assert calls == [11_000_000_000]
    del observation
    gc.collect()
    assert not copied_owner._owned and not copied_owner._original


@pytest.mark.parametrize("member", ["reading", "measurement"])
def test_equal_reconstructed_nested_record_is_not_original(monkeypatch, member):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    object.__setattr__(observation, member, replace(getattr(observation, member)))
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


@pytest.mark.parametrize("member", ["reading", "measurement"])
def test_each_original_record_field_is_bound_without_rehash_or_clock_reads(monkeypatch, member):
    from packages.adapters import standard_clock_chrony as module

    for record_field in fields(
        TrustedTimeSourceReading if member == "reading" else module.TimeSourceMeasurement
    ):
        bridge, calls = stub_read(monkeypatch, reading())
        observation = bridge.read_observation(BASE, 10_000_000_000)
        object.__setattr__(getattr(observation, member), record_field.name, object())
        with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
            bridge.require_original_observation(observation)
        assert calls == [11_000_000_000]


@pytest.mark.parametrize("name", ["source", "authority", "utc_clock", "monotonic_clock", "runner"])
def test_equal_source_or_authority_and_callback_substitution_are_rejected(monkeypatch, name):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    if name == "source":
        object.__setattr__(bridge, name, replace(bridge.source))
    elif name == "authority":
        object.__setattr__(bridge.source, name, replace(bridge.source.authority))
    else:
        object.__setattr__(bridge.source, name, lambda *args, **kwargs: pytest.fail("no effects"))
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


def test_source_read_method_rebinding_is_rejected_without_calling_it(monkeypatch):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)

    def forbidden(*args, **kwargs):
        pytest.fail("verification cannot perform another source read")

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", forbidden)
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


@pytest.mark.parametrize("owner", [ChronyNtsTrustedTimeSource, chrony_nts.ChronyNtsAuthority])
def test_source_validation_rebinding_is_rejected_before_callback(monkeypatch, owner):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)

    def forbidden(*args, **kwargs):
        pytest.fail("verification cannot invoke substituted source validation")

    monkeypatch.setattr(owner, "__post_init__", forbidden)
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


def test_callback_behavior_rebinding_is_rejected_without_invoking_it(monkeypatch):
    source, runner = _source()
    bridge = ChronyStandardTimeSource(source)
    observation = bridge.read_observation(BASE, 1_000)

    def forbidden(*args, **kwargs):
        pytest.fail("verification cannot invoke a runner")

    monkeypatch.setattr(type(runner), "__call__", forbidden)
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert runner.calls == 1


@pytest.mark.parametrize("name", ["semantic_sha256", "argv"])
def test_authority_descriptor_rebinding_is_rejected_before_invocation(monkeypatch, name):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)

    def forbidden(*args, **kwargs):
        pytest.fail("verification cannot invoke a substituted authority descriptor")

    monkeypatch.setattr(chrony_nts.ChronyNtsAuthority, name, property(forbidden))
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


def test_source_owner_change_during_read_never_registers_observation(monkeypatch):
    source, _ = _source()
    bridge = ChronyStandardTimeSource(source)
    calls = []

    def read(self, *, deadline_monotonic_ns):
        calls.append(deadline_monotonic_ns)
        object.__setattr__(self, "authority", replace(self.authority))
        return reading()

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.read_observation(BASE, 10_000_000_000)
    assert calls == [11_000_000_000]
    assert not bridge._owned and not bridge._original


@pytest.mark.parametrize("field", ["_authority_binding", "_measurement_source_id"])
@pytest.mark.parametrize("during_read", [False, True])
def test_bridge_binding_replacement_cannot_become_original(monkeypatch, field, during_read):
    source, _ = _source()
    bridge = ChronyStandardTimeSource(source)
    calls = []

    def replace_binding():
        value = (
            tuple(list(bridge._authority_binding))
            if field == "_authority_binding"
            else "chrony-standard:substituted"
        )
        object.__setattr__(bridge, field, value)

    def read(self, *, deadline_monotonic_ns):
        calls.append(deadline_monotonic_ns)
        if during_read:
            replace_binding()
        return reading()

    monkeypatch.setattr(ChronyNtsTrustedTimeSource, "read_trusted_time", read)
    if during_read:
        with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
            bridge.read_observation(BASE, 10_000_000_000)
        assert not bridge._owned and not bridge._original
    else:
        observation = bridge.read_observation(BASE, 10_000_000_000)
        replace_binding()
        with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
            bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


def test_owned_source_authority_value_mutation_is_rejected(monkeypatch):
    bridge, calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    object.__setattr__(bridge.source.authority, "socket_path", "/run/chrony/changed.sock")
    with pytest.raises(ChronyStandardTimeError, match="CHRONY_STANDARD_OBSERVATION_INVALID"):
        bridge.require_original_observation(observation)
    assert calls == [11_000_000_000]


def test_observation_verification_has_no_freshness_or_health_claim(monkeypatch):
    original = reading(
        local_observed_at_utc=BASE - timedelta(days=1),
        trusted_at_utc=BASE - timedelta(days=1),
        observed_at_monotonic_ns=0,
    )
    bridge, calls = stub_read(monkeypatch, original)
    observation = bridge.read_observation(BASE, 10_000_000_000)
    bridge.require_original_observation(observation)
    assert observation.reading is original
    assert observation.measurement.observed_at_utc == BASE - timedelta(days=1)
    assert observation.measurement.observed_monotonic_ns == 0
    assert not hasattr(observation, "status") and not hasattr(observation, "valid_until")
    assert calls == [11_000_000_000]


def test_observation_collection_releases_registry_and_retained_records(monkeypatch):
    bridge, _calls = stub_read(monkeypatch, reading())
    observation = bridge.read_observation(BASE, 10_000_000_000)
    retained = bridge.read_observation(BASE, 10_000_000_000)
    reference = weakref.ref(observation)
    assert len(bridge._owned) == len(bridge._original) == 2
    del observation
    gc.collect()
    assert reference() is None
    assert len(bridge._owned) == len(bridge._original) == 1
    bridge.require_original_observation(retained)
    del retained
    gc.collect()
    assert not bridge._owned and not bridge._original


@pytest.mark.parametrize(
    ("value", "at", "mono", "error", "expected_calls"),
    [
        (reading(), BASE, -1, "CHRONY_STANDARD_CALL_INVALID", []),
        (
            RuntimeError("private process detail"),
            BASE,
            0,
            "CHRONY_STANDARD_READ_UNAVAILABLE",
            [1_000_000_000],
        ),
        (None, BASE, 0, "CHRONY_STANDARD_READING_INVALID", [1_000_000_000]),
    ],
)
def test_opt_in_read_preserves_original_errors_and_deadlines(
    monkeypatch, value, at, mono, error, expected_calls
):
    bridge, calls = stub_read(monkeypatch, value)
    with pytest.raises(ChronyStandardTimeError, match=f"^{error}$") as raised:
        bridge.read_observation(at, mono)
    assert raised.value.__suppress_context__
    assert calls == expected_calls
    assert not bridge._owned and not bridge._original
