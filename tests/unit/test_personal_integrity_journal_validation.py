"""Real journal integrity decisions over finite captures, without a database.

Only the SQL capture/transaction boundary is supplied by the fixture. Resolution,
typed validation, object inspection and the fresh raw-row recheck remain real.
These tests grant no concurrency, performance, complete-restore or trading proof.
"""

from contextlib import contextmanager
from dataclasses import dataclass, replace
from types import MappingProxyType, SimpleNamespace

import pytest

from packages.application import personal_codec
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalEntry,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.persistence import continuous_integrity as integrity
from packages.persistence.database import ContinuousIntegritySnapshot
from packages.persistence.durable_journal import (
    JournalConflict,
    JournalReadSnapshot,
    SqlDurableJournal,
    _ReceiptRows,
)
from packages.persistence.durable_journal_schema import (
    journal_appends,
    journal_entries,
    journal_streams,
)


@dataclass(frozen=True, slots=True)
class Observation(ContractRecord):
    number: int


def _forbidden(*_args, **_kwargs):
    raise AssertionError("SQL/process/artifact I/O is outside this fixture")


def _copy_row(row):
    return None if row is None else MappingProxyType(dict(row))


def _copy_receipt(rows):
    if rows is None:
        return None
    return _ReceiptRows(
        _copy_row(rows.append),
        tuple(_copy_row(row) for row in rows.entries),
        _copy_row(rows.previous),
    )


def _fresh_capture(snapshot):
    return replace(
        snapshot,
        stream=_copy_row(snapshot.stream),
        head_anchor=_copy_row(snapshot.head_anchor),
        head_receipt=_copy_receipt(snapshot.head_receipt),
        requested_receipt=_copy_receipt(snapshot.requested_receipt),
    )


def _append_rows(key, previous, number, previous_row):
    record = JournalRecord(
        f"record-{number}", "observation/1", personal_codec.encode_record(Observation(number))
    )
    request = JournalAppend(f"command-{number}", content_digest(number), previous, (record,))
    entry = JournalEntry(
        key.semantic_sha256,
        previous.sequence + 1,
        request.command_id,
        record,
        previous.entry_sha256,
    )
    receipt = JournalReceipt(
        request.command_id,
        request.command_sha256,
        request.semantic_sha256,
        previous,
        entry.head,
        (record.record_id,),
        (record.payload_sha256,),
    )
    row = MappingProxyType(
        {
            "key_sha256": entry.key_sha256,
            "sequence": entry.sequence,
            "command_id": entry.command_id,
            "record_id": record.record_id,
            "schema_id": record.schema_id,
            "payload": record.payload,
            "payload_sha256": record.payload_sha256,
            "previous_entry_sha256": entry.previous_entry_sha256,
            "entry_sha256": entry.semantic_sha256,
        }
    )
    append = MappingProxyType(
        {
            "key_sha256": entry.key_sha256,
            "command_id": request.command_id,
            "command_sha256": request.command_sha256,
            "append_sha256": request.semantic_sha256,
            "previous_sequence": previous.sequence,
            "previous_entry_sha256": previous.entry_sha256,
            "last_sequence": entry.sequence,
            "last_entry_sha256": entry.semantic_sha256,
            "receipt_sha256": receipt.semantic_sha256,
        }
    )
    return entry, _ReceiptRows(append, (row,), previous_row)


class _Codec:
    """Record boundary events while delegating every codec operation unchanged."""

    def __init__(self, events, in_transaction):
        self.events = events
        self.in_transaction = in_transaction

    def encode_record(self, value):
        assert not self.in_transaction(), "codec encoding moved inside the transaction"
        return personal_codec.encode_record(value)

    def decode_record(self, payload, expected):
        assert not self.in_transaction(), "codec decoding moved inside the transaction"
        value = personal_codec.decode_record(payload, expected)
        self.events.append(("decode", expected.__name__, getattr(value, "number", None)))
        return value


class _Objects(integrity._OriginalObjects):
    def __init__(self, account, events):
        super().__init__(account)
        self.events = events

    def inspect(self, value):
        super().inspect(value)
        self.events.append(("inspect", value.number))


class _JournalFixture:
    def __init__(self, monkeypatch):
        self.events = []
        self.position = 0
        self.returned = {}
        self.active = False
        self.engine = object()  # Identity token only; never an Engine.
        self.connection = SimpleNamespace(
            engine=self.engine,
            dialect=SimpleNamespace(name="sqlite"),
            connection=SimpleNamespace(driver_connection=SimpleNamespace(in_transaction=False)),
            in_transaction=lambda: self.active,
            execute=_forbidden,
            exec_driver_sql=_forbidden,
        )
        self.codec = _Codec(self.events, lambda: self.active)
        self.account = SimpleNamespace(codec=self.codec, artifacts=SimpleNamespace(read=_forbidden))
        # Bypass effectful constructors, not any method under characterization.
        self.journal = object.__new__(SqlDurableJournal)
        self.journal._engine = self.engine
        self.journal._codec = self.codec
        self.journal._types = MappingProxyType({"observation/1": Observation})
        self.journal._preparation_owner = object()
        self.reader = object.__new__(integrity.SqlContinuousIntegrityReader)
        self.reader.engine = self.engine
        self.reader.account = self.account
        self.reader.journals = (self.journal,)
        self.objects = _Objects(self.account, self.events)
        self.key = JournalKey(
            "capture", "integrity-fixture", "fixture-account", "fixture", "synthetic", "a" * 64
        )
        first, rows1 = _append_rows(self.key, empty_head(self.key), 1, None)
        second, rows2 = _append_rows(self.key, first.head, 2, rows1.entries[0])
        self.entries = (first, second)
        self.receipts = (rows1, rows2)
        self.streams = tuple(
            MappingProxyType(
                {
                    "key_sha256": self.key.semantic_sha256,
                    "key_payload": personal_codec.encode_record(self.key),
                    "last_sequence": entry.sequence,
                    "last_entry_sha256": entry.semantic_sha256,
                }
            )
            for entry in self.entries
        )
        self.original = ContinuousIntegritySnapshot(
            "synthetic-journal-method-slice",
            MappingProxyType(
                {
                    journal_streams.name: (self.streams[1],),
                    journal_appends.name: tuple(rows.append for rows in self.receipts),
                    journal_entries.name: tuple(rows.entries[0] for rows in self.receipts),
                }
            ),
        )
        self.reads = [
            ("head", None, self.snapshot()),
            ("request-1", "command-1", self.snapshot("command-1")),
            ("recheck-1", "command-1", self.snapshot("command-1")),
            ("request-2", "command-2", self.snapshot("command-2")),
            ("recheck-2", "command-2", self.snapshot("command-2")),
        ]
        monkeypatch.setattr(self.journal, "capture_in_transaction", self.capture)
        monkeypatch.setattr(integrity, "_repeatable_read_transaction", self.transaction)

    def snapshot(self, command=None, *, head=1):
        requested = None if command is None else self.receipts[int(command[-1]) - 1]
        return JournalReadSnapshot(
            self.key,
            command,
            self.streams[head],
            self.receipts[head].entries[0],
            self.receipts[head],
            requested,
            False,
            False,
            self.journal._preparation_owner,
        )

    @contextmanager
    def transaction(self, engine):
        assert engine is self.engine and not self.active
        self.active = True
        self.connection.connection.driver_connection.in_transaction = True
        try:
            yield self.connection
        finally:
            self.active = False
            self.connection.connection.driver_connection.in_transaction = False

    def capture(self, connection, key, *, command_id=None):
        # Keep the real connection/engine/physical-transaction guards, without SQL.
        self.journal._read_connection(connection)
        assert connection is self.connection and key == self.key
        assert self.position < len(self.reads), "unexpected extra capture/retry"
        label, expected, result = self.reads[self.position]
        assert command_id == expected
        self.position += 1
        self.events.append(("capture", label, command_id))
        if isinstance(result, BaseException):
            raise result
        fresh = _fresh_capture(result)
        self.returned[label] = fresh
        return fresh

    def run(self):
        return self.reader._validate_journals(self.original, self.objects)

    def captures(self):
        return [event[1] for event in self.events if event[0] == "capture"]


@pytest.fixture
def journal_fixture(monkeypatch):
    return _JournalFixture(monkeypatch)


def test_integrity_journal_complete_chain_inspects_then_resolves_and_freshly_rechecks(
    journal_fixture,
):
    rig = journal_fixture

    assert rig.run() is None

    assert rig.captures() == ["head", "request-1", "recheck-1", "request-2", "recheck-2"]
    first_capture = next(i for i, event in enumerate(rig.events) if event[0] == "capture")
    assert [event for event in rig.events[:first_capture] if event[0] == "inspect"] == [
        ("inspect", 1),
        ("inspect", 2),
    ]
    assert not any(event[0] == "inspect" for event in rig.events[first_capture:])
    for number in (1, 2):
        requested = rig.returned[f"request-{number}"]
        rechecked = rig.returned[f"recheck-{number}"]
        assert requested == rechecked and requested is not rechecked
        assert requested.requested_receipt is not rechecked.requested_receipt
        assert requested.requested_receipt.append is not rechecked.requested_receipt.append
        begin = rig.events.index(("capture", f"request-{number}", f"command-{number}"))
        end = rig.events.index(("capture", f"recheck-{number}", f"command-{number}"))
        assert any(event[:2] == ("decode", "Observation") for event in rig.events[begin:end])
    # The real current-head recheck compares rows; it does not re-run the codec.
    begin = rig.events.index(("capture", "recheck-1", "command-1"))
    end = rig.events.index(("capture", "request-2", "command-2"))
    assert not any(event[0] == "decode" for event in rig.events[begin:end])
    assert not rig.active and rig.objects.references == {}


def test_integrity_journal_changed_raw_recheck_rejects_before_next_append(journal_fixture):
    rig = journal_fixture
    snapshot = rig.snapshot("command-1")
    before = snapshot.requested_receipt
    fields = dict(before.append)
    old = fields["receipt_sha256"]
    fields["receipt_sha256"] = ("0" if old[0] != "0" else "1") + old[1:]
    changed = replace(before, append=MappingProxyType(fields))
    rig.reads[2] = ("recheck-1", "command-1", replace(snapshot, requested_receipt=changed))

    with pytest.raises(JournalConflict, match=r"^JOURNAL_READ_CHANGED$"):
        rig.run()

    assert rig.captures() == ["head", "request-1", "recheck-1"]
    assert rig.events[-1] == ("capture", "recheck-1", "command-1")
    assert not rig.active


def test_integrity_journal_changed_head_rejects_before_receipt_recheck(journal_fixture):
    rig = journal_fixture
    rig.reads[1] = ("request-1", "command-1", rig.snapshot("command-1", head=0))

    with pytest.raises(
        integrity.ContinuousIntegrityError, match=r"^COMPLETE_JOURNAL_APPEND_CHAIN_DIFFERS$"
    ):
        rig.run()

    assert rig.captures() == ["head", "request-1"]
    assert not rig.active


def test_integrity_journal_missing_first_append_rejects_broken_previous_chain(journal_fixture):
    rig = journal_fixture
    tables = dict(rig.original.tables)
    tables[journal_appends.name] = (rig.receipts[1].append,)
    rig.original = replace(rig.original, tables=MappingProxyType(tables))
    rig.reads[1] = ("request-2", "command-2", rig.snapshot("command-2"))

    with pytest.raises(
        integrity.ContinuousIntegrityError, match=r"^COMPLETE_JOURNAL_APPEND_CHAIN_DIFFERS$"
    ):
        rig.run()

    assert rig.captures() == ["head", "request-2"]
    assert not rig.active


def test_integrity_journal_missing_latest_inventory_rejects_after_first_recheck(journal_fixture):
    rig = journal_fixture
    tables = dict(rig.original.tables)
    tables[journal_appends.name] = (rig.receipts[0].append,)
    rig.original = replace(rig.original, tables=MappingProxyType(tables))

    with pytest.raises(
        integrity.ContinuousIntegrityError, match=r"^COMPLETE_JOURNAL_INVENTORY_DIFFERS$"
    ):
        rig.run()

    assert rig.captures() == ["head", "request-1", "recheck-1"]
    assert not rig.active


def test_integrity_journal_recheck_capture_fault_keeps_identity_and_stops_chain(journal_fixture):
    rig = journal_fixture
    fault = RuntimeError("synthetic fresh-capture boundary failure")
    rig.reads[2] = ("recheck-1", "command-1", fault)

    with pytest.raises(RuntimeError) as caught:
        rig.run()

    assert caught.value is fault
    assert rig.captures() == ["head", "request-1", "recheck-1"]
    assert rig.events[-1] == ("capture", "recheck-1", "command-1")
    assert not rig.active
