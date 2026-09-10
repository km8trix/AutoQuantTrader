"""Stored research values must retain types, invariants and exact economics."""

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from packages.application.causal_engine import run_causal_engine
from packages.application.personal_codec import decode_record, encode_record
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.run_report import build_report_artifact, build_run_report
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.engine_contracts import EngineInputs
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.report_contracts import ReportArtifact, ReportConventions


@pytest.fixture(scope="module")
def inputs():
    names = (
        "engine",
        "source",
        "dependency_lock",
        "tzdata",
        "availability",
        "actions",
        "numeric",
        "benchmark",
        "report",
        "dirty_patch",
    )
    pins = tuple(
        VersionPin(
            name,
            ReportConventions().version if name == "report" else "unit-test-only/1",
            content_digest(name),
        )
        for name in sorted(names)
    )
    return synthetic_engine_inputs(fixture="flat", pins=pins, session_count=8, warmup_count=3)


def test_real_inputs_and_report_reconstruct_with_exact_types_and_financial_identities(inputs):
    restored = decode_record(encode_record(inputs), EngineInputs)
    assert restored == inputs
    result = run_causal_engine(
        restored, accounting=PersonalAccounting(), strategy=ReferenceStrategy()
    )
    artifact = build_report_artifact(
        build_run_report(result, ReportConventions()),
        attempt_id="codec-test",
        generated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    payload = encode_record(artifact)
    actual = decode_record(payload, ReportArtifact)
    assert actual == artifact
    assert actual.semantic_sha256 == artifact.semantic_sha256
    assert encode_record(actual) == payload
    assert actual.report.source.journal_entries
    assert type(actual.report.source.final_snapshot.nav) is Decimal


@pytest.mark.parametrize("mutation", ["wrong_type", "extra", "bool_count", "bad_digest"])
def test_wire_edits_cannot_bypass_declared_types_or_constructor_invariants(inputs, mutation):
    value = json.loads(encode_record(inputs))
    spec = value["value"]["fields"]["spec"]
    if mutation == "wrong_type":
        spec["$record"] = "os.system"
    elif mutation == "extra":
        spec["fields"]["unrecognized"] = "x"
    elif mutation == "bool_count":
        spec["fields"]["max_events"] = True
    else:
        spec["fields"]["events_sha256"] = "invalid"
    with pytest.raises(ValueError):
        decode_record(json.dumps(value).encode(), EngineInputs)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"codec":"personal-record/1","codec":"personal-record/1","value":null}',
        b'{"codec":"personal-record/1","value":1.25}',
        b'{"codec":"personal-record/1","value":NaN}',
        b'{"codec":"personal-record/1","value":{"$decimal":"Infinity"}}',
        b'{"codec":"unknown","value":null}',
    ],
)
def test_ambiguous_nonfinite_or_unknown_wire_values_reject(payload):
    with pytest.raises(ValueError):
        decode_record(payload, Decimal)


def test_record_is_canonical_and_expected_root_is_mandatory(inputs):
    payload = encode_record(inputs)
    with pytest.raises(ValueError):
        decode_record(payload, ReportArtifact)
    with pytest.raises(ValueError):
        decode_record(payload + b" ", EngineInputs)
    assert decode_record(encode_record(Decimal("1.234567890123456789")), Decimal) == Decimal(
        "1.234567890123456789"
    )
