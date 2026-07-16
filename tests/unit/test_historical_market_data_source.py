from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from packages.adapters.market_data.recorded import (
    RecordedHistoricalBarSource,
    RecordedJsonlBarSource,
)
from packages.adapters.market_data.reference_fixture import admission_profile, reference_fixture
from packages.market_data import HistoricalBarSource, SourceKind


def test_recorded_fixture_implements_historical_source_port_and_loads_immutable_bundle() -> None:
    fixture = reference_fixture()
    source = RecordedHistoricalBarSource(
        Path("tests/fixtures/market_data/phase1_bars.jsonl"),
        profile=admission_profile(),
        security_master=fixture.security_master,
        calendar=fixture.calendar,
        corporate_actions=fixture.corporate_actions,
        entitlement=fixture.entitlement,
    )

    assert isinstance(source, HistoricalBarSource)
    bundle = source.load()
    assert bundle.profile.kind is SourceKind.SYNTHETIC_FIXTURE
    assert bundle.profile.licensed is False
    assert bundle.profile.adapter_type == "recorded_jsonl"
    assert bundle.profile.identifier_authority == "autoquant-synthetic-v1"
    assert bundle.profile.required_symbols == ("SPY",)
    assert len(bundle.records) == 5
    with pytest.raises(FrozenInstanceError):
        bundle.source_checksum = "0" * 64  # type: ignore[misc]


def test_fixture_profile_cannot_claim_a_licensed_entitlement() -> None:
    with pytest.raises(ValueError, match="cannot claim a licensed entitlement"):
        replace(admission_profile(), licensed=True)


def test_recorded_bundle_hashes_and_parses_one_byte_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original = RecordedJsonlBarSource.bytes

    def counted_bytes(source: RecordedJsonlBarSource) -> bytes:
        nonlocal calls
        calls += 1
        return original(source)

    monkeypatch.setattr(RecordedJsonlBarSource, "bytes", counted_bytes)
    fixture = reference_fixture()
    source = RecordedHistoricalBarSource(
        Path("tests/fixtures/market_data/phase1_bars.jsonl"),
        profile=admission_profile(),
        security_master=fixture.security_master,
        calendar=fixture.calendar,
        corporate_actions=fixture.corporate_actions,
        entitlement=fixture.entitlement,
    )

    source.load()

    assert calls == 1
