"""Canonical ContractRecord identity; these value fixtures grant no authority."""

from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from hashlib import sha256

import pytest

from packages.domain import personal_contracts
from packages.domain.accounting_contracts import AccountingCommand, ControlCommand
from packages.domain.canonical import canonical_json_bytes
from packages.domain.durable_journal_contracts import JournalAppend, JournalHead, JournalRecord
from packages.domain.order_reducer import BrokerOrderEvent, BrokerOrderEventKind
from packages.domain.personal_contracts import CausalMark, VersionPin, semantic_value

AT = datetime(2025, 3, 4, 14, 30, 0, 123456, tzinfo=UTC)
GOLDENS = {
    "pin": "0f4ea7639c7459731016579248374b26161a2178c487616f5530ef82fc828a50",
    "mark": "12702382166d94d095c2cf87be9ebedcc2e68f7e9d18e486642c330649f35cb9",
    "append": "f5dcc9062f4e1d58187ed9320b8a2f3820d5a42e1d8d1137f5abeb7f552ec00e",
    "broker_event": "bb51e4b7f63d8bce6e1ce89a5144d8207523c91e8ec0235048eee7d0cc01767b",
    "control": "ce229d40b7054fcd1b92da8590e23980def8843c67588b996526624f947de9d3",
}


def record_for(kind):
    if kind == "pin":
        return VersionPin("semantic-fixture", "1", "a" * 64)
    if kind == "mark":
        return CausalMark(
            "mark", "instrument", "SPY", Decimal("123.4500"), date(2025, 3, 4), AT, AT, "b" * 64
        )
    if kind == "append":
        return JournalAppend(
            "append",
            "c" * 64,
            JournalHead("a" * 64, 0, "b" * 64),
            (
                JournalRecord("record-one", "fixture/1", b"\x00record-one\n"),
                JournalRecord("record-two", "fixture/1", b"record-two"),
            ),
        )
    if kind == "broker_event":
        return AccountingCommand(
            "observe",
            BrokerOrderEvent("event", "order", "broker", 1, AT, AT, BrokerOrderEventKind.ACCEPTED),
        )
    assert kind == "control"
    return AccountingCommand("halt", ControlCommand(True, "fixture halt"))


def legacy_bytes(record):
    """Preserve the pre-optimization expression as the independent oracle."""
    return canonical_json_bytes(semantic_value((record.contract_version, semantic_value(record))))


@pytest.mark.parametrize("kind", GOLDENS)
def test_actual_property_retains_exact_legacy_canonical_bytes_and_golden_hash(kind, monkeypatch):
    record = record_for(kind)
    expected = legacy_bytes(record)
    assert sha256(expected).hexdigest() == GOLDENS[kind]
    actual_bytes = []

    def capture(value):
        payload = canonical_json_bytes(value)
        actual_bytes.append(payload)
        return payload

    monkeypatch.setattr(personal_contracts, "canonical_json_bytes", capture)
    assert record.semantic_sha256 == GOLDENS[kind]
    assert actual_bytes == [expected]


def test_nested_class_versions_keep_existing_outer_only_behavior(monkeypatch):
    parent = record_for("append")
    child = parent.records[0]
    child_hash = child.semantic_sha256
    parent_hash = parent.semantic_sha256
    monkeypatch.setattr(JournalRecord, "contract_version", "semantic-test-child/2")
    assert child.semantic_sha256 != child_hash
    # A nested ClassVar is not a dataclass field; its own property is not used.
    assert parent.semantic_sha256 == parent_hash == GOLDENS["append"]
    monkeypatch.setattr(JournalAppend, "contract_version", "semantic-test-parent/2")
    assert parent.semantic_sha256 != parent_hash
    assert parent.semantic_sha256 == sha256(legacy_bytes(parent)).hexdigest()


@pytest.mark.parametrize("nested", [False, True])
def test_same_instance_mutation_between_calls_is_rehashed_without_a_cache(nested):
    record = record_for("append" if nested else "pin")
    target, field, changed = (
        (record.records[0], "payload", b"changed payload") if nested else (record, "version", "2")
    )
    original = getattr(target, field)
    before = record.semantic_sha256
    object.__setattr__(target, field, changed)
    after = record.semantic_sha256
    assert after != before
    assert after == sha256(legacy_bytes(record)).hexdigest()
    object.__setattr__(target, field, original)
    assert record.semantic_sha256 == before


@pytest.mark.parametrize(
    "kind,field,value,error",
    [
        ("mark", "price", 1.25, TypeError),
        ("mark", "price", Decimal("Infinity"), ValueError),
        ("mark", "knowledge_at", AT.replace(tzinfo=None), ValueError),
        ("append", "records", (object(),), TypeError),
        ("append", "records", (JournalRecord,), TypeError),
    ],
)
def test_unsupported_corrupted_values_retain_legacy_failure(kind, field, value, error):
    record = record_for(kind)
    # Deliberately bypass frozen fields to model corruption after construction.
    # Hashing must not silently accept a formerly rejected canonical value.
    object.__setattr__(record, field, value)
    with pytest.raises(error) as expected:
        legacy_bytes(record)
    with pytest.raises(error) as actual:
        _ = record.semantic_sha256
    assert str(actual.value) == str(expected.value)


@pytest.mark.parametrize("fault", ["float", "naive_time", "mutable_records"])
def test_hash_changes_do_not_replace_exact_constructor_type_admission(fault):
    with pytest.raises(ValueError):
        if fault == "float":
            replace(record_for("mark"), price=1.25)
        elif fault == "naive_time":
            replace(record_for("mark"), knowledge_at=AT.replace(tzinfo=None))
        else:
            append = record_for("append")
            replace(append, records=list(append.records))
