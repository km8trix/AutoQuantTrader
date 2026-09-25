"""Bounded append-journal values, without account or execution authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import ClassVar, Literal

from packages.domain.personal_contracts import ContractRecord, content_digest, require_digest

MAX_APPEND_RECORDS = 64
MAX_RECORD_BYTES = 256 * 1024
MAX_APPEND_BYTES = 1024 * 1024
MAX_PAGE_RECORDS = 256
MAX_PAGE_BYTES = MAX_PAGE_RECORDS * MAX_RECORD_BYTES
MAX_SEQUENCE = 2**63 - 1


def journal_identifier(value: str) -> None:
    if type(value) is not str or not value or value != value.strip() or len(value) > 128:
        raise ValueError("journal identity requires bounded nonempty text")


class JournalValue(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-durable-journal/1"


@dataclass(frozen=True, slots=True)
class JournalKey(JournalValue):
    namespace: Literal["capture", "venue", "coordinator"]
    stream_id: str
    account_scope: str
    source_provider: str
    source_environment: Literal["production", "sandbox", "synthetic"]
    source_scope_sha256: str
    runtime_environment: Literal["stateful_simulation"] = "stateful_simulation"

    def __post_init__(self) -> None:
        super(JournalKey, self).__post_init__()
        for name in ("stream_id", "account_scope", "source_provider"):
            journal_identifier(getattr(self, name))
        require_digest(self.source_scope_sha256, "journal source scope")


@dataclass(frozen=True, slots=True)
class JournalHead(JournalValue):
    key_sha256: str
    sequence: int
    entry_sha256: str

    def __post_init__(self) -> None:
        super(JournalHead, self).__post_init__()
        require_digest(self.key_sha256, "journal key")
        require_digest(self.entry_sha256, "journal entry")
        if not 0 <= self.sequence <= MAX_SEQUENCE:
            raise ValueError("journal sequence is outside its range")


def empty_head(key: JournalKey) -> JournalHead:
    return JournalHead(key.semantic_sha256, 0, content_digest(("journal-empty/1", key)))


@dataclass(frozen=True, slots=True)
class JournalRecord(JournalValue):
    record_id: str
    schema_id: str
    payload: bytes

    def __post_init__(self) -> None:
        super(JournalRecord, self).__post_init__()
        journal_identifier(self.record_id)
        journal_identifier(self.schema_id)
        if not 0 < len(self.payload) <= MAX_RECORD_BYTES:
            raise ValueError("journal record exceeds its byte bound")

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True, slots=True)
class JournalAppend(JournalValue):
    command_id: str
    command_sha256: str
    expected_head: JournalHead
    records: tuple[JournalRecord, ...]

    def __post_init__(self) -> None:
        super(JournalAppend, self).__post_init__()
        journal_identifier(self.command_id)
        require_digest(self.command_sha256, "journal command")
        if not 1 <= len(self.records) <= MAX_APPEND_RECORDS:
            raise ValueError("append requires 1..64 records")
        if sum(len(record.payload) for record in self.records) > MAX_APPEND_BYTES:
            raise ValueError("append exceeds its aggregate byte bound")
        if len({record.record_id for record in self.records}) != len(self.records):
            raise ValueError("append record IDs must be unique")
        if self.expected_head.sequence + len(self.records) > MAX_SEQUENCE:
            raise ValueError("append exceeds journal sequence range")


@dataclass(frozen=True, slots=True)
class JournalEntry(JournalValue):
    key_sha256: str
    sequence: int
    command_id: str
    record: JournalRecord
    previous_entry_sha256: str

    def __post_init__(self) -> None:
        super(JournalEntry, self).__post_init__()
        require_digest(self.key_sha256, "entry key")
        require_digest(self.previous_entry_sha256, "entry predecessor")
        journal_identifier(self.command_id)
        if not 1 <= self.sequence <= MAX_SEQUENCE:
            raise ValueError("entry sequence is outside its range")

    @property
    def head(self) -> JournalHead:
        return JournalHead(self.key_sha256, self.sequence, self.semantic_sha256)


@dataclass(frozen=True, slots=True)
class JournalReceipt(JournalValue):
    command_id: str
    command_sha256: str
    append_sha256: str
    previous_head: JournalHead
    committed_head: JournalHead
    record_ids: tuple[str, ...]
    record_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        super(JournalReceipt, self).__post_init__()
        journal_identifier(self.command_id)
        require_digest(self.command_sha256, "receipt command")
        require_digest(self.append_sha256, "receipt append")
        if not 1 <= len(self.record_ids) <= MAX_APPEND_RECORDS:
            raise ValueError("receipt record inventory is outside bounds")
        if len(set(self.record_ids)) != len(self.record_ids) or len(self.record_ids) != len(
            self.record_hashes
        ):
            raise ValueError("receipt inventory differs")
        for value in self.record_ids:
            journal_identifier(value)
        for value in self.record_hashes:
            require_digest(value, "receipt record hash")
        if (
            self.previous_head.key_sha256 != self.committed_head.key_sha256
            or self.committed_head.sequence != self.previous_head.sequence + len(self.record_ids)
        ):
            raise ValueError("receipt heads differ from ordered inventory")


@dataclass(frozen=True, slots=True)
class JournalPage(JournalValue):
    key: JournalKey
    through_head: JournalHead
    previous_head: JournalHead
    entries: tuple[JournalEntry, ...]
    next_head: JournalHead
    complete: bool

    def __post_init__(self) -> None:
        super(JournalPage, self).__post_init__()
        if len(self.entries) > MAX_PAGE_RECORDS:
            raise ValueError("page exceeds record bound")
        previous = self.previous_head
        if previous.key_sha256 != self.key.semantic_sha256:
            raise ValueError("page key differs")
        for entry in self.entries:
            if (
                entry.key_sha256 != previous.key_sha256
                or entry.sequence != previous.sequence + 1
                or entry.previous_entry_sha256 != previous.entry_sha256
            ):
                raise ValueError("page chain is not contiguous")
            previous = entry.head
        if (
            previous != self.next_head
            or self.through_head.key_sha256 != previous.key_sha256
            or previous.sequence > self.through_head.sequence
            or self.complete != (previous == self.through_head)
        ):
            raise ValueError("page boundary differs")
