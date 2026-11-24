"""Finite pure reference compatibility; these unowned values grant no authority.

The oracle retains complete old detachment and semantic normalization. Ordinary
stable reads are observed; arbitrary Python hooks, races, cycles and interpreter
resource thresholds are outside this finite compatibility claim.
"""

from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from typing import ClassVar
from uuid import UUID

import pytest

from packages.domain import personal_contracts
from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.durable_journal_contracts import JournalHead, JournalKey, JournalReceipt
from packages.persistence import continuous_account as account
from packages.persistence import detached_journal_capture as detached
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    ResolvedJournalRead,
    _ReceiptRows,
)

TRACE = []


@dataclass(frozen=True)
class Record:
    label: str
    payload: object
    children: tuple = ()
    _owner: object = None
    _validated_values: object = None
    contract_version: ClassVar[str] = "not-a-dataclass-field/1"

    def __getattribute__(self, name):
        if name in {"label", "payload", "children", "_owner", "_validated_values"}:
            TRACE.append(("field", name))
        return object.__getattribute__(self, name)


class ReadMapping(dict):
    def items(self):
        TRACE.append(("mapping", tuple(self.keys())))
        return super().items()


class OrdinaryEnum(Enum):
    RETAINED = "retained"


class BytesSubclass(bytes):
    pass


class TupleSubclass(tuple):
    pass


def material(leaf=None, *, parent=False, source_lease=False, empty=False):
    """All nine actual metadata dataclass types, but no store ownership or SQL."""
    scope = ContinuousAccountScope("synthetic-account", "a" * 64, "stream")
    key = JournalKey("coordinator", "stream", "account", "fixture", "synthetic", "a" * 64)
    before = JournalHead("b" * 64, 0, "c" * 64)
    after = JournalHead("b" * 64, 1, "d" * 64)
    receipt = JournalReceipt("original", "e" * 64, "f" * 64, before, after, ("r1",), ("a" * 64,))
    row = ReadMapping(sequence=1, payload=b"original-row", nullable=None, leaf=leaf)
    shared = MappingProxyType(row)
    rows = _ReceiptRows(shared, (shared,), None)
    raw = JournalReadSnapshot(
        key,
        None if empty else "original",
        shared,
        None if empty else shared,
        None if empty else rows,
        None if empty else rows,
        False,
        False,
        object(),
    )
    journal = ResolvedJournalRead(
        raw, before if empty else after, None if empty else receipt, object(), (object(),)
    )
    lease = ReadMapping(owner_id="original-owner", expires_at="2026-09-13T00:01:00Z")
    index = account.ContinuousIndexSnapshot(scope, shared)
    snapshot = account.ContinuousReferenceSnapshot(
        index,
        lease,
        raw,
        index if parent else None,
        lease if parent else None,
        raw if parent else None,
        "f" * 64 if source_lease else None,
        MappingProxyType(dict(lease)) if source_lease else None,
    )
    return (snapshot, journal, journal if parent else None), row, lease


def legacy_fingerprint(snapshot, journal, prior_journal):
    return personal_contracts.content_digest(
        detached.detached_journal_value((snapshot, journal, prior_journal))
    )


def captured_call(function, values, monkeypatch):
    encoded = []
    TRACE.clear()

    def encode(value):
        result = canonical_json_bytes(value)
        encoded.append(result)
        return result

    def byte_hash(payload):
        TRACE.append(("bytes", payload))
        return sha256(payload)

    with monkeypatch.context() as guard:
        guard.setattr(personal_contracts, "canonical_json_bytes", encode)
        guard.setattr(account, "canonical_json_bytes", encode)
        guard.setattr(detached, "sha256", byte_hash)
        try:
            result = ("return", function(*values))
        except Exception as error:
            result = ("error", type(error), str(error), error.__cause__)
    return result, tuple(encoded), tuple(TRACE)


def assert_legacy_equivalent(values, monkeypatch):
    old = captured_call(legacy_fingerprint, values, monkeypatch)
    new = captured_call(account._reference_fingerprint, values, monkeypatch)
    assert new == old
    if new[0][0] == "return":
        assert len(new[1]) == 1
        assert new[0][1] == sha256(new[1][0]).hexdigest()
    return new


@pytest.mark.parametrize("shape", ["genesis", "empty", "parent", "source-lease"])
def test_actual_metadata_types_exact_legacy_bytes_and_hash(shape, monkeypatch):
    values, _, _ = material(
        parent=shape in {"parent", "source-lease"},
        source_lease=shape == "source-lease",
        empty=shape == "empty",
    )
    result = assert_legacy_equivalent(values, monkeypatch)
    assert result[0][0] == "return"


def test_full_read_order_alias_visits_bytes_tags_and_exclusions(monkeypatch):
    leaf = Record(
        "retained-é",
        b"original-leaf",
        (
            None,
            True,
            False,
            0,
            -7,
            "text",
            Decimal("12.3400"),
            datetime(2026, 9, 13, tzinfo=UTC),
            date(2026, 9, 13),
            OrdinaryEnum.RETAINED,
            UUID(int=7),
        ),
        object(),
        object(),
    )
    values, _, _ = material(leaf, parent=True, source_lease=True)
    result = assert_legacy_equivalent(values, monkeypatch)
    counts = Counter(result[2])
    assert counts[("bytes", b"original-row")] > 1
    assert counts[("bytes", b"original-leaf")] == counts[("field", "payload")]
    assert counts[("bytes", b"original-leaf")] > 1
    assert ("field", "_owner") not in counts
    assert ("field", "_validated_values") not in counts
    assert b"not-a-dataclass-field/1" not in result[1][0]
    assert result[2][0] == ("mapping", ("sequence", "payload", "nullable", "leaf"))


def test_aliases_equal_copies_and_each_between_call_mutation(monkeypatch):
    leaf = Record("original", b"same", (Decimal("7.00"),))
    values, row, lease = material(leaf, parent=True)
    baseline = assert_legacy_equivalent(values, monkeypatch)[0]
    copied = replace(values[0], current=replace(values[0].current, row=MappingProxyType(dict(row))))
    assert assert_legacy_equivalent((copied, *values[1:]), monkeypatch)[0] == baseline
    for target, name, replacement in (
        (leaf, "label", "changed"),
        (leaf, "payload", b"changed"),
        (leaf, "children", (Decimal("8"),)),
        (values[1].head, "sequence", 2),
    ):
        original = getattr(target, name)
        object.__setattr__(target, name, replacement)
        try:
            assert assert_legacy_equivalent(values, monkeypatch)[0] != baseline
        finally:
            object.__setattr__(target, name, original)
        assert assert_legacy_equivalent(values, monkeypatch)[0] == baseline
    for target, name, replacement in (
        (row, "payload", b"changed-row"),
        (lease, "owner_id", "changed-owner"),
    ):
        original = target[name]
        target[name] = replacement
        try:
            assert assert_legacy_equivalent(values, monkeypatch)[0] != baseline
        finally:
            target[name] = original
        assert assert_legacy_equivalent(values, monkeypatch)[0] == baseline


@pytest.mark.parametrize(
    "leaf",
    [
        None,
        (),
        [None, 1, "list"],
        {1, 2},
        frozenset({"a", "b"}),
        MappingProxyType({2: "second", 1: "first"}),
    ],
)
def test_existing_nonadmitted_container_behavior(leaf, monkeypatch):
    assert assert_legacy_equivalent(material(leaf)[0], monkeypatch)[0][0] == "return"


@pytest.mark.parametrize(
    "leaf",
    [
        1.5,
        object(),
        Record,
        BytesSubclass(b"bytes"),
        TupleSubclass((1,)),
        Decimal("NaN"),
        Decimal("Infinity"),
        datetime(2026, 9, 13),
        [Record("hidden", b"payload")],
        {Record("hidden", b"payload")},
    ],
)
def test_ordinary_corrupt_leaf_errors_match_without_new_admission(leaf, monkeypatch):
    assert assert_legacy_equivalent(material(leaf)[0], monkeypatch)[0][0] == "error"


@pytest.mark.parametrize("error_type", [ValueError, TypeError, KeyError, UnicodeError])
def test_original_read_failure_order_and_exception_identity(error_type, monkeypatch):
    error = error_type("original-read-failure")

    class FailingMapping(dict):
        def items(self):
            TRACE.append(("failing-items",))
            raise error

    values = material(FailingMapping())[0]
    for function in (legacy_fingerprint, account._reference_fingerprint):
        TRACE.clear()
        with pytest.raises(error_type) as raised:
            function(*values)
        assert raised.value is error
        assert TRACE[-1] == ("failing-items",)
    assert_legacy_equivalent(values, monkeypatch)
