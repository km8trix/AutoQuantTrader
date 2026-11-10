"""Pure measured values and original fixture conversions; no wire or host admission."""

import hashlib
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta
from decimal import ROUND_UP, Decimal, Inexact, Rounded, localcontext

import pytest

from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import (
    MAX_RECORD_BYTES,
    JournalHead,
    JournalKey,
    JournalReceipt,
    empty_head,
)
from packages.domain.measured_runtime_clock_contracts import (
    MEASURED_CLOCK_BRIDGE_VERSION,
    MEASURED_CLOCK_PROFILE,
    MEASURED_CLOCK_REFERENCE_SCHEMA,
    MEASURED_CLOCK_SCHEMA,
    MEASURED_CLOCK_SOURCE_SCHEMA,
    MeasuredClockSourceAssociation,
    MeasuredRuntimeClockObservation,
    MeasuredRuntimeClockReference,
)
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.runtime_operating_contracts import CLOCK_POLICY, RuntimeClockObservation
from tests.unit.test_chrony_nts import BASE
from tests.unit.test_personal_measured_clock import factory as factory


def _scope():
    return ContinuousAccountScope("measured-fixture", "a" * 64, "measured-fixture:clock")


def _measurement_id(source_id, authority_sha, semantic_sha):
    # Independent reproduction of the established bridge's public identity equation.
    payload = canonical_json_bytes(
        ("personal-chrony-standard-clock/1", (source_id, authority_sha, semantic_sha))
    )
    return "chrony-standard:" + hashlib.sha256(payload).hexdigest()


def _association(**changes):
    values = {
        "source_id": "chrony-fixture",
        "source_authority_sha256": "b" * 64,
        "authority_semantic_sha256": "c" * 64,
        "bridge_version": "personal-chrony-standard-clock/1",
        "local_observed_at_utc": BASE,
        "trusted_at_utc": BASE,
        "observed_at_monotonic_ns": 10_000_000_000,
        "source_uncertainty_milliseconds": Decimal("0.0000000001"),
        "source_evidence_sha256": "d" * 64,
    }
    values.update(changes)
    if "measurement_source_id" not in values:
        values["measurement_source_id"] = _measurement_id(
            values["source_id"],
            values["source_authority_sha256"],
            values["authority_semantic_sha256"],
        )
    return MeasuredClockSourceAssociation(**values)


def _observation(**changes):
    source = _association()
    values = {
        "scope": _scope(),
        "profile": "personal_chrony_measured/1",
        "policy": replace(CLOCK_POLICY),
        "status": "healthy",
        "reasons": ("within_limit",),
        "evidence_class": "host-measurement",
        "source_id": source.measurement_source_id,
        "observed_at_utc": BASE + timedelta(milliseconds=1),
        "observed_monotonic_ns": 10_001_000_000,
        "source_observed_at_utc": source.local_observed_at_utc,
        "source_observed_monotonic_ns": source.observed_at_monotonic_ns,
        "epoch": "modeled-fixture-epoch",
        "sequence": 7,
        "offset_ns": 0,
        "uncertainty_ns": 1,
        "sampling_duration_ns": 1_000,
        "sample_age_ns": 1_000_000,
        "recovery_ready": True,
        "rearm_required": True,
        "source": source,
    }
    values.update(changes)
    return MeasuredRuntimeClockObservation(**values)


def _unavailable(**changes):
    values = {
        "status": "blocked",
        "reasons": ("clock_or_source_unavailable",),
        "evidence_class": "unavailable",
        "source_id": None,
        "observed_at_utc": None,
        "observed_monotonic_ns": None,
        "source_observed_at_utc": None,
        "source_observed_monotonic_ns": None,
        "offset_ns": None,
        "uncertainty_ns": None,
        "sampling_duration_ns": None,
        "sample_age_ns": None,
        "recovery_ready": False,
    }
    values.update(changes)
    return _observation(**values)


def _reference_parts(*, byte_count=256):
    # These are claimed reference values, never evidence of an actual append or encoding.
    key = JournalKey(
        namespace="coordinator",
        stream_id="measured-fixture:clock",
        account_scope="measured-fixture",
        source_provider="measured-fixture",
        source_environment="synthetic",
        source_scope_sha256="a" * 64,
    )
    record = ContinuousEvidenceRef(
        "runtime-measured-clock-observation/1",
        ObjectRef("b" * 64, byte_count),
        "c" * 64,
    )
    receipt = JournalReceipt(
        command_id="measured-fixture:append",
        command_sha256="d" * 64,
        append_sha256="e" * 64,
        previous_head=empty_head(key),
        committed_head=JournalHead(key.semantic_sha256, 1, "f" * 64),
        record_ids=(record.semantic_sha256,),
        record_hashes=(record.object_ref.object_sha256,),
    )
    return key, receipt, record


def test_additive_record_fields_versions_and_frozen_values_do_not_extend_v1():
    assert MEASURED_CLOCK_SOURCE_SCHEMA == "measured-clock-source-association/1"
    assert MEASURED_CLOCK_SCHEMA == "runtime-measured-clock-observation/1"
    assert MEASURED_CLOCK_REFERENCE_SCHEMA == "runtime-measured-clock-reference/1"
    assert MEASURED_CLOCK_PROFILE == "personal_chrony_measured/1"
    assert MEASURED_CLOCK_BRIDGE_VERSION == "personal-chrony-standard-clock/1"
    source = _association()
    observed = _observation()
    key, receipt, record = _reference_parts()
    reference = MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)
    assert [item.name for item in fields(source)] == [
        "source_id",
        "source_authority_sha256",
        "authority_semantic_sha256",
        "bridge_version",
        "measurement_source_id",
        "local_observed_at_utc",
        "trusted_at_utc",
        "observed_at_monotonic_ns",
        "source_uncertainty_milliseconds",
        "source_evidence_sha256",
    ]
    assert [item.name for item in fields(observed)] == [
        *[item.name for item in fields(RuntimeClockObservation)],
        "source",
    ]
    assert [item.name for item in fields(reference)] == ["key", "receipt", "record"]
    for value, schema in (
        (source, MEASURED_CLOCK_SOURCE_SCHEMA),
        (observed, MEASURED_CLOCK_SCHEMA),
        (reference, MEASURED_CLOCK_REFERENCE_SCHEMA),
    ):
        assert value.contract_version == schema
        assert not hasattr(value, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(value, fields(value)[0].name, None)
    assert not isinstance(observed, RuntimeClockObservation)
    old_fields = {
        item.name: getattr(observed, item.name) for item in fields(RuntimeClockObservation)
    }
    with pytest.raises(ValueError):
        RuntimeClockObservation(**old_fields)
    old_fields["profile"] = "host_unqualified"
    old = RuntimeClockObservation(**old_fields)
    assert old.contract_version == "runtime-clock-observation/1"
    assert type(old) is RuntimeClockObservation


@pytest.mark.parametrize("offset_ns", [-123_456_000, 0, 123_456_000])
@pytest.mark.parametrize(
    ("uncertainty_ms", "scenario_ns", "expected_ns"),
    [("0", 0, 0), ("0.0000000001", Decimal("0.0001"), 1), ("100", 100_000_000, 100_000_000)],
)
def test_association_matches_original_owned_bridge_conversion_with_independent_literals(
    factory, offset_ns, uncertainty_ms, scenario_ns, expected_ns
):
    owner, scenario, bridge = factory()
    scenario.offset_ns = offset_ns
    scenario.uncertainty_ns = scenario_ns
    token = owner.sample_health()
    owner.require_original_health(token)
    original = token.source_observation
    assert original is not None
    bridge.require_original_observation(original)
    reading, measurement = original.reading, original.measurement
    authority = bridge.source.authority
    association = _association(
        source_id=reading.source_id,
        source_authority_sha256=reading.source_authority_sha256,
        authority_semantic_sha256=authority.semantic_sha256,
        measurement_source_id=measurement.source_id,
        local_observed_at_utc=reading.local_observed_at_utc,
        trusted_at_utc=reading.trusted_at_utc,
        observed_at_monotonic_ns=reading.observed_at_monotonic_ns,
        source_uncertainty_milliseconds=reading.source_uncertainty_milliseconds,
        source_evidence_sha256=reading.source_evidence_sha256,
    )
    assert measurement.source_id == _measurement_id(
        reading.source_id, reading.source_authority_sha256, authority.semantic_sha256
    )
    assert reading.source_uncertainty_milliseconds == Decimal(uncertainty_ms)
    assert association.offset_ns == measurement.offset_ns == offset_ns
    assert association.uncertainty_ns == measurement.uncertainty_ns == expected_ns
    assert association.source_uncertainty_milliseconds.as_tuple() == (
        reading.source_uncertainty_milliseconds.as_tuple()
    )
    assert scenario.calls.count("source") == 1
    actual = {
        item.name: getattr(token.snapshot, item.name)
        for item in fields(RuntimeClockObservation)
        if item.name not in ("scope", "profile", "policy")
    }
    actual["status"] = token.snapshot.status.value
    observed = _observation(**actual, source=association)
    assert observed.status == "blocked"
    assert observed.reasons == ("startup_qualifying",)
    assert observed.source is association
    assert observed.rearm_required is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", ""),
        ("source_id", "x" * 129),
        ("source_id", "unsafe source"),
        ("source_authority_sha256", "A" * 64),
        ("authority_semantic_sha256", "g" * 64),
        ("source_evidence_sha256", "d" * 63),
        ("bridge_version", "personal-chrony-standard-clock/2"),
        ("local_observed_at_utc", datetime(2026, 7, 31, 14)),
        ("observed_at_monotonic_ns", True),
        ("observed_at_monotonic_ns", -1),
        ("source_uncertainty_milliseconds", 0.1),
        ("source_uncertainty_milliseconds", Decimal("NaN")),
        ("source_uncertainty_milliseconds", Decimal("-0.0000000001")),
        ("source_uncertainty_milliseconds", Decimal("100.0000000001")),
        ("source_uncertainty_milliseconds", Decimal("0.00000000001")),
    ],
)
def test_association_rejects_single_native_or_original_numeric_bound_violation(field, value):
    assert _association().uncertainty_ns == 1
    with pytest.raises(ValueError):
        _association(**{field: value})


@pytest.mark.parametrize(
    "field", ["source_id", "source_authority_sha256", "authority_semantic_sha256"]
)
def test_association_identity_binds_all_three_original_authority_coordinates(field):
    original = _association()
    changed = "different-source" if field == "source_id" else "e" * 64
    with pytest.raises(ValueError):
        replace(original, **{field: changed})
    rebound = _association(**{field: changed})
    assert rebound.measurement_source_id != original.measurement_source_id


@pytest.mark.parametrize(
    ("representation", "equivalent", "expected_ns"),
    [
        ("0.0100", "0.01", 10_000),
        ("-0", "0", 0),
        ("100.0", "1E+2", 100_000_000),
        ("1E-10", "0.0000000001", 1),
    ],
)
def test_semantic_identity_is_context_free_without_normalizing_original_decimal_or_wire_bytes(
    representation, equivalent, expected_ns
):
    amount = Decimal(representation)
    original_tuple = amount.as_tuple()
    ordinary = _association(source_uncertainty_milliseconds=amount)
    expected_hash = ordinary.semantic_sha256
    assert ordinary.uncertainty_ns == expected_ns
    assert _association(source_uncertainty_milliseconds=Decimal(equivalent)).semantic_sha256 == (
        expected_hash
    )
    for capitals in (0, 1):
        with localcontext() as context:
            context.prec = 1
            context.rounding = ROUND_UP
            context.capitals = capitals
            context.traps[Inexact] = True
            context.traps[Rounded] = True
            hostile = _association(source_uncertainty_milliseconds=amount)
            assert hostile.source_uncertainty_milliseconds.as_tuple() == original_tuple
            assert hostile.source_uncertainty_milliseconds is amount
            assert hostile.uncertainty_ns == expected_ns
            assert hostile.semantic_sha256 == expected_hash
    assert amount.as_tuple() == original_tuple


@pytest.mark.parametrize("after_source", [False, True])
def test_unavailable_values_preserve_original_failed_step_and_optional_successful_read(
    factory, after_source
):
    owner, scenario, bridge = factory()
    if after_source:
        scenario.utc_error_number = 2
    else:
        scenario.source_error = True
    token = owner.sample_health()
    owner.require_original_health(token)
    assert token.snapshot.evidence_class == "unavailable"
    assert token.snapshot.status.value == "blocked"
    assert token.snapshot.recovery_ready is False
    association = None
    if after_source:
        assert token.source_observation is not None
        reading = token.source_observation.reading
        association = _association(
            source_id=reading.source_id,
            source_authority_sha256=reading.source_authority_sha256,
            authority_semantic_sha256=bridge.source.authority.semantic_sha256,
            measurement_source_id=token.source_observation.measurement.source_id,
            local_observed_at_utc=reading.local_observed_at_utc,
            trusted_at_utc=reading.trusted_at_utc,
            observed_at_monotonic_ns=reading.observed_at_monotonic_ns,
            source_uncertainty_milliseconds=reading.source_uncertainty_milliseconds,
            source_evidence_sha256=reading.source_evidence_sha256,
        )
    else:
        assert token.source_observation is None
    actual = {
        item.name: getattr(token.snapshot, item.name)
        for item in fields(RuntimeClockObservation)
        if item.name not in ("scope", "profile", "policy")
    }
    actual["status"] = token.snapshot.status.value
    observed = _observation(**actual, source=association)
    assert observed.source is association
    for field, expected in actual.items():
        assert getattr(observed, field) == expected
    assert all(
        getattr(observed, field) is None
        for field in (
            "source_id",
            "source_observed_at_utc",
            "source_observed_monotonic_ns",
            "offset_ns",
            "uncertainty_ns",
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "healthy"),
        ("recovery_ready", True),
        ("source_id", "unexpected-source"),
        ("source_observed_at_utc", BASE),
        ("source_observed_monotonic_ns", 0),
        ("offset_ns", 0),
        ("uncertainty_ns", 0),
    ],
)
def test_unavailable_successful_association_never_fills_or_upgrades_snapshot(field, value):
    original = _unavailable()
    assert original.source is not None
    assert original.status == "blocked" and original.recovery_ready is False
    with pytest.raises(ValueError):
        replace(original, **{field: value})
    assert _unavailable(source=None).source is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", None),
        ("source_id", "wrong-measurement"),
        ("source_observed_at_utc", BASE + timedelta(microseconds=1)),
        ("source_observed_monotonic_ns", 10_000_000_001),
        ("offset_ns", 1),
        ("uncertainty_ns", 2),
    ],
)
def test_host_snapshot_requires_exact_association_and_integer_conversion(field, value):
    original = _observation()
    assert original.offset_ns == 0 and original.uncertainty_ns == 1
    with pytest.raises(ValueError):
        replace(original, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sequence", True),
        ("sequence", 0),
        ("sequence", 2**63),
        ("epoch", ""),
        ("epoch", "x" * 129),
        ("reasons", ["within_limit"]),
        ("reasons", ("within_limit", "within_limit")),
        ("reasons", ("z", "a")),
        ("reasons", ("x" * 2049,)),
        ("reasons", tuple(f"r{n:02}" for n in range(65))),
        ("recovery_ready", 1),
        ("rearm_required", 1),
        ("sampling_duration_ns", True),
        ("sample_age_ns", True),
        ("observed_monotonic_ns", True),
        ("observed_monotonic_ns", -1),
        ("evidence_class", "simulated"),
        ("profile", "host_unqualified"),
    ],
)
def test_observation_native_bounds_and_new_literal_profile_are_closed(field, value):
    original = _observation()
    with pytest.raises(ValueError):
        replace(original, **{field: value})


def test_observation_preserves_signed_failure_diagnostics_and_exact_sequence_boundaries():
    for sequence in (1, 2**63 - 1):
        observed = _observation(
            sequence=sequence,
            status="blocked",
            reasons=("future_sample", "monotonic_regression"),
            recovery_ready=False,
            observed_at_utc=BASE - timedelta(microseconds=1),
            observed_monotonic_ns=9_999_999_000,
            sampling_duration_ns=-1,
            sample_age_ns=-1_000,
        )
        assert observed.sequence == sequence
        assert observed.sampling_duration_ns == -1 and observed.sample_age_ns == -1_000
        assert observed.rearm_required is True


def test_observation_accepts_original_inclusive_reason_epoch_and_sequence_bounds():
    reasons = tuple(f"r{number:02}" for number in range(64))
    observed = _observation(
        sequence=2**63 - 1,
        epoch="e" * 128,
        reasons=reasons,
        status="blocked",
        recovery_ready=False,
    )
    assert observed.sequence == 2**63 - 1
    assert observed.epoch == "e" * 128
    assert observed.reasons == reasons and len(observed.reasons) == 64


@pytest.mark.parametrize("nested", ["scope", "policy", "source"])
def test_observation_freshly_revalidates_exact_nested_records(nested):
    original = _observation()
    if nested == "scope":
        target, field, changed = original.scope, "account_id", ""
    elif nested == "policy":
        target, field, changed = original.policy, "sha256", "NOT-A-DIGEST"
    else:
        target, field, changed = original.source, "source_uncertainty_milliseconds", Decimal("101")
    assert target is not None
    object.__setattr__(target, field, changed)
    assert getattr(target, field) == changed
    with pytest.raises(ValueError):
        replace(original)


@pytest.mark.parametrize(
    ("byte_count", "admitted"), [(1, True), (256 * 1024, True), (256 * 1024 + 1, False)]
)
def test_reference_claimed_bytes_obey_narrow_journal_limit_without_claiming_encoded_fit(
    byte_count, admitted
):
    assert MAX_RECORD_BYTES == 256 * 1024
    key, receipt, record = _reference_parts(byte_count=byte_count)
    # All three claims fit their original generic value contracts, even the final adverse.
    key.__post_init__()
    receipt.__post_init__()
    record.__post_init__()
    if admitted:
        reference = MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)
        assert reference.record.object_ref.byte_count == byte_count
        assert receipt.record_ids == (record.semantic_sha256,)
        assert receipt.record_hashes == (record.object_ref.object_sha256,)
        assert record.semantic_sha256 != record.object_ref.object_sha256
    else:
        with pytest.raises(ValueError):
            MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)


@pytest.mark.parametrize("mismatch", ["key", "schema", "semantic", "raw"])
def test_reference_joins_schema_key_semantic_id_and_distinct_raw_receipt_hash(mismatch):
    key, receipt, record = _reference_parts()
    assert record.semantic_sha256 != record.object_ref.object_sha256
    MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)
    if mismatch == "key":
        key = replace(key, stream_id="another-valid-stream")
    elif mismatch == "schema":
        record = replace(record, schema_id="runtime-clock-observation/1")
    elif mismatch == "semantic":
        record = replace(record, semantic_sha256="1" * 64)
    else:
        record = replace(record, object_ref=replace(record.object_ref, object_sha256="2" * 64))
    with pytest.raises(ValueError):
        MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)


@pytest.mark.parametrize(
    "nested", ["key", "receipt", "previous_head", "committed_head", "object", "record"]
)
def test_reference_revalidates_every_nested_original_value_before_binding(nested):
    key, receipt, record = _reference_parts()
    MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)
    target, field, changed = {
        "key": (key, "namespace", "unknown"),
        "receipt": (receipt, "record_hashes", ("not-a-digest",)),
        "previous_head": (receipt.previous_head, "sequence", False),
        "committed_head": (receipt.committed_head, "sequence", True),
        "object": (record.object_ref, "byte_count", True),
        "record": (record, "schema_id", ""),
    }[nested]
    object.__setattr__(target, field, changed)
    assert getattr(target, field) == changed
    with pytest.raises(ValueError):
        MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)


def test_reference_rejects_a_valid_original_multi_record_receipt():
    key, receipt, record = _reference_parts()
    two_records = replace(
        receipt,
        committed_head=replace(receipt.committed_head, sequence=2),
        record_ids=(record.semantic_sha256, "1" * 64),
        record_hashes=(record.object_ref.object_sha256, "2" * 64),
    )
    two_records.__post_init__()
    assert two_records.committed_head.sequence == two_records.previous_head.sequence + 2
    with pytest.raises(ValueError, match="requires one exact journal record"):
        MeasuredRuntimeClockReference(key=key, receipt=two_records, record=record)


@pytest.mark.parametrize("leaf", ["previous_sequence", "committed_sequence", "object_bytes"])
def test_reference_native_leaf_admission_precedes_any_mutated_value_operators(leaf):
    calls = []

    class OperatorTrap:
        def operate(self, *_args):
            calls.append("mutated leaf operator")
            raise AssertionError("native admission must precede every value operation")

        __add__ = operate
        __radd__ = operate
        __eq__ = operate
        __ne__ = operate
        __lt__ = operate
        __le__ = operate
        __gt__ = operate
        __ge__ = operate
        __bool__ = operate

    key, receipt, record = _reference_parts()
    MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)
    if leaf == "previous_sequence":
        target, field = receipt.previous_head, "sequence"
    elif leaf == "committed_sequence":
        target, field = receipt.committed_head, "sequence"
    else:
        target, field = record.object_ref, "byte_count"
    trap = OperatorTrap()
    object.__setattr__(target, field, trap)
    assert getattr(target, field) is trap
    with pytest.raises(ValueError, match=rf"^{field} has an unsupported value type$"):
        MeasuredRuntimeClockReference(key=key, receipt=receipt, record=record)
    assert calls == []
