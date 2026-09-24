"""Bound and intern a complete detached journal graph before further capture.

Rows remain exactly as issued by the common journal's public transaction read;
this helper adds no decoding, authority, SQL access or mutable journal history.
"""

from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from hashlib import sha256
from typing import Any, overload

from packages.persistence.durable_journal import JournalReadSnapshot


class DetachedJournalCaptureError(ValueError):
    """Static exact-row or aggregate transfer limit violation."""


class DetachedJournalCapture:
    """Intern repeated head/neighbor rows and bound the complete detached graph."""

    def __init__(self, *, max_bytes: int, max_metadata_bytes: int) -> None:
        if (
            type(max_bytes) is not int
            or type(max_metadata_bytes) is not int
            or min(max_bytes, max_metadata_bytes) <= 0
        ):
            raise DetachedJournalCaptureError("JOURNAL_CAPTURE_BUDGET_INVALID")
        self.max_bytes, self.max_metadata_bytes = max_bytes, max_metadata_bytes
        self.rows: dict[tuple[object, ...], Mapping[str, Any]] = {}
        self.byte_count = 0
        self.metadata_bytes = 0

    @overload
    def row(self, kind: str, row: None) -> None: ...

    @overload
    def row(self, kind: str, row: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def row(self, kind: str, row: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
        if row is None:
            return None
        identity = (
            kind,
            row["key_sha256"],
            row.get("command_id") if kind == "append" else row.get("sequence"),
        )
        old = self.rows.get(identity)
        if old is not None:
            if old != row:
                raise DetachedJournalCaptureError("JOURNAL_CAPTURE_ROW_CHANGED")
            return old
        for value in row.values():
            if type(value) is bytes:
                self.byte_count += len(value)
            elif type(value) is str:
                self.metadata_bytes += len(value.encode("utf-8"))
            elif type(value) is int:
                self.metadata_bytes += 8
            else:
                raise DetachedJournalCaptureError("JOURNAL_CAPTURE_METADATA_INVALID")
        if self.byte_count > self.max_bytes or self.metadata_bytes > self.max_metadata_bytes:
            raise DetachedJournalCaptureError("JOURNAL_CAPTURE_AGGREGATE_LIMIT")
        self.rows[identity] = row
        return row

    def capture(self, snapshot: JournalReadSnapshot) -> JournalReadSnapshot:
        receipts = []
        for value in (snapshot.head_receipt, snapshot.requested_receipt):
            receipts.append(
                None
                if value is None
                else replace(
                    value,
                    append=self.row("append", value.append),
                    entries=tuple(self.row("entry", row) for row in value.entries),
                    previous=self.row("entry", value.previous),
                )
            )
        return replace(
            snapshot,
            stream=self.row("stream", snapshot.stream),
            head_anchor=self.row("entry", snapshot.head_anchor),
            head_receipt=receipts[0],
            requested_receipt=receipts[1],
        )


def detached_journal_value(value: object) -> object:
    if type(value) is bytes:
        return ("bytes", len(value), sha256(value).hexdigest())
    if isinstance(value, Mapping):
        return tuple(
            (str(key), detached_journal_value(item)) for key, item in sorted(value.items())
        )
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__qualname__,
            tuple(
                (f.name, detached_journal_value(getattr(value, f.name)))
                for f in fields(value)
                if f.name not in {"_owner", "_validated_values"}
            ),
        )
    if type(value) is tuple:
        return tuple(detached_journal_value(item) for item in value)
    return value
