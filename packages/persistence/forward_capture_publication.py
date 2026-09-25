"""Mechanical synthetic capture publication; no provider source authority.

Encoding and storage finish before SQL. Original bounded fields, append rows
and local deadline denial are checked immediately before actual outer COMMIT.
The final check and physical COMMIT are not atomic with passage of time.
"""

from typing import Any
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Engine

from packages.application.personal_forward_capture import (
    ForwardCaptureError,
    _capture_publication_inputs,
    _method_identity,
    _recheck_capture_episode,
)
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    CapturePublication,
    ForwardCaptureRecord,
)
from packages.persistence.durable_journal import SqlDurableJournal

_PUBLISHERS: WeakValueDictionary[int, "SqlForwardCapturePublication"] = WeakValueDictionary()
_BINDINGS: dict[int, tuple[object, ...]] = {}
_METHODS: dict[int, tuple[tuple[str, object], ...]] = {}


class SqlForwardCapturePublication:
    """Exact original SQL graph, not a rights/clock/quota verifier."""

    def __init__(self, engine: Engine, *, journal: SqlDurableJournal) -> None:
        if (
            not isinstance(engine, Engine)
            or engine.dialect.name not in ("sqlite", "postgresql")
            or type(journal) is not SqlDurableJournal
            or journal._engine is not engine
            or journal._types.get(CAPTURE_SCHEMA) is not ForwardCaptureRecord
        ):
            raise ForwardCaptureError("CAPTURE_EXACT_SQL_JOURNAL_REQUIRED")
        self.engine, self.journal = engine, journal
        _PUBLISHERS[id(self)] = self
        _BINDINGS[id(self)] = self._bindings()
        _METHODS[id(self)] = tuple(
            (name, _method_identity(getattr(journal, name)))
            for name in (
                "prepare_append",
                "append_in_transaction",
                "recheck_prepared_append_in_transaction",
            )
        )
        finalize(self, _BINDINGS.pop, id(self), None)
        finalize(self, _METHODS.pop, id(self), None)

    def _bindings(self) -> tuple[object, ...]:
        return (
            self.engine,
            self.journal,
            type(self.journal),
            self.journal._engine,
            self.journal._codec,
            self.journal._types,
            self.journal._preparation_owner,
            self.journal._prepared_appends,
            self.journal._prepared_readbacks,
        )

    def require_original(self) -> None:
        if type(self) is not SqlForwardCapturePublication or _PUBLISHERS.get(id(self)) is not self:
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PUBLISHER_REQUIRED")
        if any(
            actual is not original
            for actual, original in zip(self._bindings(), _BINDINGS[id(self)], strict=True)
        ):
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PUBLISHER_CHANGED")
        if any(
            _method_identity(getattr(self.journal, name)) != original
            for name, original in _METHODS[id(self)]
        ):
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PUBLISHER_CHANGED")

    def publish(self, episode: object) -> CapturePublication:
        self.require_original()
        key, append, publication = _capture_publication_inputs(episode, publisher=self, claim=True)
        _recheck_capture_episode(episode, publisher=self)
        prepared = self.journal.prepare_append(key, append)
        if prepared.receipt != publication.journal_receipt:
            raise ForwardCaptureError("CAPTURE_JOURNAL_BINDING_DIFFERS")
        _recheck_capture_episode(episode, publisher=self)
        with self.engine.connect() as connection:
            if connection.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection = connection.execution_options(isolation_level="REPEATABLE READ")
                connection.begin()
            try:
                _recheck_capture_episode(episode, publisher=self)
                receipt = self.journal.append_in_transaction(connection, prepared)
                if receipt != prepared.receipt:
                    raise ForwardCaptureError("CAPTURE_JOURNAL_BINDING_DIFFERS")
                self.journal.recheck_prepared_append_in_transaction(connection, prepared)
                _recheck_capture_episode(episode, publisher=self)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        # This exact value was constructed, encoded and verified before SQL.
        return publication

    def __reduce__(self) -> Any:
        raise TypeError("capture publisher is process-local")
