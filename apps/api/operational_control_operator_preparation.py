"""Private E/F/G preparation; no SQL, lifecycle or accepted resolution.

Clock samples are configured inputs, not host qualification or a physical-return
expiry guarantee. Current use authenticates again without re-reading evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, cast
from weakref import WeakValueDictionary, finalize

from apps.api import operational_control_operator_authentication as authentication
from apps.api.operational_control_operator_authentication import (
    LocalOperationalControlOperatorStatementAuthenticator,
)
from apps.trader import operational_control_operator_evidence as evidence
from apps.trader.operational_control_operator_evidence import OperatorStatementEvidenceReader
from packages.application import operational_control_operator_preparation as prepared_values
from packages.application.operational_control_operator_authentication import (
    AuthenticatedOperationalControlOperatorStatement,
)
from packages.application.operational_control_operator_preparation import (
    PreparedOperationalControlOperatorStatementRecord,
)
from packages.application.operational_rearm import UtcClock
from packages.domain import operational_control_operator_record as records
from packages.domain import operational_control_operator_statement as statements
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
)
from packages.domain.operational_control_operator_record import (
    OperationalControlOperatorStatementRecord,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)
from packages.domain.research_job_contracts import ObjectRef

_INVALID = "OPERATOR_STATEMENT_PREPARATION_INVALID"
_CHANGED = "OPERATOR_STATEMENT_PREPARATION_BINDING_CHANGED"
_ORIGINAL = "ORIGINAL_OPERATOR_STATEMENT_PREPARATION_REQUIRED"
_ISSUER = LocalOperationalControlOperatorStatementAuthenticator
_READER = OperatorStatementEvidenceReader
_AUTHENTICATED = AuthenticatedOperationalControlOperatorStatement
_PREPARED = PreparedOperationalControlOperatorStatementRecord
_RECORD = OperationalControlOperatorStatementRecord
_STATEMENT = OperationalControlOperatorStatement
_REFERENCE = ObjectRef
_E_ENTRY = authentication._ENTRY
_E_REQUIRE = LocalOperationalControlOperatorStatementAuthenticator.require_authenticated
_F_ENTRY = evidence._ENTRY
_F_READ = OperatorStatementEvidenceReader.read
_D_COPY = statements.copy_operational_control_operator_statement
_G_COPY = records.copy_operational_control_operator_statement_record
_SHA256 = sha256

type _Graph = tuple[tuple[object | None, type[object], tuple[tuple[str, object], ...]], ...]
type _Baseline = tuple[_Graph, str]


def _bindings() -> None:
    for module, name, expected in _REFERENCES:
        if vars(module).get(name) is not expected:
            raise ValueError(_CHANGED)
    for owner, name, expected in _METHODS:
        if vars(owner).get(name) is not expected:
            raise ValueError(_CHANGED)
    for name, expected in _HELPERS:
        if globals().get(name) is not expected:
            raise ValueError(_CHANGED)


def _entry(owner: OperatorStatementRecordPreparer) -> None:
    if _BINDINGS is not _bindings:
        raise ValueError(_CHANGED)
    _BINDINGS()
    if type(owner) is not _PREPARER or owner._self is not owner:
        raise ValueError(_ORIGINAL)
    issuer, reader, clock, original = owner.issuer, owner.reader, owner.clock, owner._configuration
    if (
        type(original) is not tuple
        or len(original) != 6
        or type(issuer) is not _ISSUER
        or type(reader) is not _READER
        or issuer is not original[0]
        or reader is not original[1]
        or clock is not original[2]
        or owner._seal is not original[3]
        or owner._owned is not original[4]
        or owner._original is not original[5]
    ):
        raise ValueError(_CHANGED)
    _E_ENTRY(issuer)
    _F_ENTRY(reader)


def _arguments(session_cookie: str | None, csrf_token: str) -> None:
    if (
        (
            session_cookie is not None
            and (type(session_cookie) is not str or len(session_cookie) > 2048)
        )
        or type(csrf_token) is not str
        or len(csrf_token) > 128
    ):
        raise ValueError(_INVALID)


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError(_INVALID)
    return value


def _sample(owner: OperatorStatementRecordPreparer) -> datetime:
    sampled = _UTC(owner.clock())
    _ENTRY(owner)
    return sampled


def _native_reference(digest: object, count: object, codec: object) -> bool:
    return type(digest) is str and type(count) is int and type(codec) is str


def _input_record(
    authenticated: AuthenticatedOperationalControlOperatorStatement,
    reference: ObjectRef,
) -> OperationalControlOperatorStatementRecord:
    if type(authenticated) is not _AUTHENTICATED or type(reference) is not _REFERENCE:
        raise ValueError(_INVALID)
    statement, expiry, seal = (
        authenticated.statement,
        authenticated.session_expires_at,
        authenticated.seal,
    )
    digest, count, codec = reference.object_sha256, reference.byte_count, reference.codec_version
    if (
        type(statement) is not _STATEMENT
        or not _NATIVE_REFERENCE(digest, count, codec)
        or type(seal) is not object
    ):
        raise ValueError(_INVALID)
    expiry = _UTC(expiry)
    copied_statement = _D_COPY(statement)
    copied_reference = _REFERENCE(digest, count, codec)
    return _RECORD(
        statement=copied_statement,
        evidence=copied_reference,
        session_expires_at=expiry,
    )


def _statement_nodes(statement: OperationalControlOperatorStatement) -> tuple[object, ...]:
    if type(statement) is not _STATEMENT:
        raise ValueError(_INVALID)
    blocker, actor, claim = statement.blocking_event, statement.actor, statement.resolution_claim
    if (
        type(blocker) is not OperationalControlBlockingEvent
        or type(actor) is not OperationalControlActor
        or type(claim) is not OperationalControlIncidentDisposition
    ):
        raise ValueError(_INVALID)
    return statement, blocker, actor, claim


def _capture_graph(
    record: OperationalControlOperatorStatementRecord,
    authenticated: AuthenticatedOperationalControlOperatorStatement,
    prepared: PreparedOperationalControlOperatorStatementRecord | None = None,
) -> _Graph:
    if type(record) is not _RECORD or type(authenticated) is not _AUTHENTICATED:
        raise ValueError(_INVALID)
    if type(record.evidence) is not _REFERENCE:
        raise ValueError(_INVALID)
    nodes = (
        record,
        record.evidence,
        *_STATEMENT_NODES(record.statement),
        authenticated,
        *_STATEMENT_NODES(authenticated.statement),
    )
    graph: _Graph = tuple(
        (
            node,
            type(node),
            tuple(
                (field.name, object.__getattribute__(node, field.name))
                for field in fields(cast(Any, node))
            ),
        )
        for node in nodes
    )
    if prepared is None:
        return graph
    if type(prepared) is not _PREPARED:
        raise ValueError(_INVALID)
    # Never retain the weakly owned prepared root through its identity graph.
    return (
        *graph,
        (
            None,
            _PREPARED,
            tuple(
                (field.name, object.__getattribute__(prepared, field.name))
                for field in fields(_PREPARED)
            ),
        ),
    )


def _same_graph(
    graph: _Graph, root: PreparedOperationalControlOperatorStatementRecord | None = None
) -> None:
    for node, original_type, originals in graph:
        node = root if node is None else node
        if type(node) is not original_type or any(
            object.__getattribute__(node, name) is not original for name, original in originals
        ):
            raise ValueError(_ORIGINAL)


def _owned(
    owner: OperatorStatementRecordPreparer,
    value: PreparedOperationalControlOperatorStatementRecord,
) -> tuple[OperationalControlOperatorStatementRecord, datetime]:
    _ENTRY(owner)
    if type(value) is not _PREPARED:
        raise ValueError(_ORIGINAL)
    record, authenticated, before, checked, seal = (
        value.record,
        value.authenticated,
        value.before_read_at,
        value.checked_at,
        value.seal,
    )
    if (
        type(record) is not _RECORD
        or type(authenticated) is not _AUTHENTICATED
        or seal is not owner._seal
        or owner._owned.get(id(value)) is not value
    ):
        raise ValueError(_ORIGINAL)
    before, checked = _UTC(before), _UTC(checked)
    baseline = owner._original.get(id(value))
    if baseline is None:
        raise ValueError(_ORIGINAL)
    _SAME_GRAPH(baseline[0], value)
    copied = _G_COPY(record)
    if copied.semantic_sha256 != baseline[1] or not (
        copied.statement.authentication_checked_at <= before <= checked < copied.session_expires_at
    ):
        raise ValueError(_ORIGINAL)
    _ENTRY(owner)
    _SAME_GRAPH(baseline[0], value)
    return copied, checked


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False, repr=False)
class OperatorStatementAdmission:
    prepared: PreparedOperationalControlOperatorStatementRecord
    checked_at: datetime
    expires_at: datetime
    clock: object


class OperatorStatementRecordPreparer:
    """Own prepared inputs after actual current authentication and a past read."""

    __slots__ = (
        "_admission_fields",
        "_admission_registry",
        "_admissions",
        "_configuration",
        "_original",
        "_owned",
        "_seal",
        "_self",
        "clock",
        "issuer",
        "reader",
    )

    def __init__(
        self,
        issuer: LocalOperationalControlOperatorStatementAuthenticator,
        reader: OperatorStatementEvidenceReader,
        *,
        clock: UtcClock,
    ) -> None:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        if (
            type(self) is not _PREPARER
            or type(issuer) is not _ISSUER
            or type(reader) is not _READER
        ):
            raise ValueError(_INVALID)
        if not callable(clock):
            raise ValueError(_INVALID)
        _E_ENTRY(issuer)
        _F_ENTRY(reader)
        self.issuer, self.reader, self.clock = issuer, reader, clock
        self._self, self._seal = self, object()
        self._owned: WeakValueDictionary[int, PreparedOperationalControlOperatorStatementRecord] = (
            WeakValueDictionary()
        )
        self._original: dict[int, _Baseline] = {}
        self._admissions: WeakValueDictionary[int, OperatorStatementAdmission] = (
            WeakValueDictionary()
        )
        self._admission_fields: dict[int, tuple[object, ...]] = {}
        self._admission_registry = (self._admissions, self._admission_fields)
        self._configuration = (issuer, reader, clock, self._seal, self._owned, self._original)
        _ENTRY(self)

    def prepare(
        self,
        authenticated: AuthenticatedOperationalControlOperatorStatement,
        reference: ObjectRef,
        *,
        session_cookie: str | None,
        csrf_token: str,
    ) -> PreparedOperationalControlOperatorStatementRecord:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        _ENTRY(self)
        _ARGUMENTS(session_cookie, csrf_token)
        record = _INPUT_RECORD(authenticated, reference)
        graph = _CAPTURE_GRAPH(record, authenticated)
        original_digest = record.semantic_sha256
        original_expiry = record.session_expires_at
        before = _SAMPLE(self)
        _SAME_GRAPH(graph)
        if not record.statement.authentication_checked_at <= before < record.session_expires_at:
            raise ValueError(_INVALID)
        _E_REQUIRE(
            self.issuer,
            authenticated,
            session_cookie=session_cookie,
            csrf_token=csrf_token,
            now=before,
        )
        _ENTRY(self)
        _SAME_GRAPH(graph)
        returned = _F_READ(self.reader, record.statement, record.evidence)
        _ENTRY(self)
        _SAME_GRAPH(graph)
        if type(returned) is not tuple or len(returned) != 3:
            raise ValueError(_INVALID)
        statement, evidence_ref, payload = returned
        if (
            type(statement) is not _STATEMENT
            or type(evidence_ref) is not _REFERENCE
            or type(payload) is not bytes
        ):
            raise ValueError(_INVALID)
        digest, count, codec = (
            evidence_ref.object_sha256,
            evidence_ref.byte_count,
            evidence_ref.codec_version,
        )
        if not _NATIVE_REFERENCE(digest, count, codec):
            raise ValueError(_INVALID)
        copied_statement = _D_COPY(statement)
        copied_reference = _REFERENCE(digest, count, codec)
        returned_record = _RECORD(
            statement=copied_statement,
            evidence=copied_reference,
            session_expires_at=original_expiry,
        )
        if (
            returned_record.semantic_sha256 != original_digest
            or len(payload) != returned_record.evidence.byte_count
            or _SHA256(payload).hexdigest() != returned_record.evidence.object_sha256
        ):
            raise ValueError(_INVALID)
        returned_graph = _CAPTURE_GRAPH(returned_record, authenticated)
        del returned, payload
        after = _SAMPLE(self)
        _SAME_GRAPH(graph)
        _SAME_GRAPH(returned_graph)
        if not before <= after < original_expiry:
            raise ValueError(_INVALID)
        _E_REQUIRE(
            self.issuer,
            authenticated,
            session_cookie=session_cookie,
            csrf_token=csrf_token,
            now=after,
        )
        _ENTRY(self)
        _SAME_GRAPH(graph)
        _SAME_GRAPH(returned_graph)
        seal = self._seal
        value = _PREPARED(returned_record, authenticated, before, after, seal)
        _ENTRY(self)
        _SAME_GRAPH(graph)
        _SAME_GRAPH(returned_graph)
        if type(value) is not _PREPARED or (
            value.record is not returned_record
            or value.authenticated is not authenticated
            or value.before_read_at is not before
            or value.checked_at is not after
            or value.seal is not seal
        ):
            raise ValueError(_ORIGINAL)
        self._owned[id(value)] = value
        self._original[id(value)] = (
            _CAPTURE_GRAPH(returned_record, authenticated, value),
            original_digest,
        )
        finalize(value, self._original.pop, id(value), None)
        _OWNED(self, value)
        return value

    def require_prepared(
        self,
        prepared: PreparedOperationalControlOperatorStatementRecord,
        *,
        session_cookie: str | None,
        csrf_token: str,
    ) -> None:
        if _BINDINGS is not _bindings:
            raise ValueError(_CHANGED)
        _BINDINGS()
        _ENTRY(self)
        _ARGUMENTS(session_cookie, csrf_token)
        record, checked = _OWNED(self, prepared)
        authenticated = prepared.authenticated
        now = _SAMPLE(self)
        _OWNED(self, prepared)
        if not checked <= now < record.session_expires_at:
            raise ValueError(_ORIGINAL)
        _E_REQUIRE(
            self.issuer,
            authenticated,
            session_cookie=session_cookie,
            csrf_token=csrf_token,
            now=now,
        )
        _OWNED(self, prepared)

    def observe_prepared(
        self,
        prepared: PreparedOperationalControlOperatorStatementRecord,
        *,
        session_cookie: str | None,
        csrf_token: str,
    ) -> OperatorStatementAdmission:
        """Return the actual current authentication sample, without changing old API."""
        if (
            self._admissions is not self._admission_registry[0]
            or self._admission_fields is not self._admission_registry[1]
        ):
            raise ValueError(_CHANGED)
        _ENTRY(self)
        _ARGUMENTS(session_cookie, csrf_token)
        record, checked = _OWNED(self, prepared)
        now = _SAMPLE(self)
        _OWNED(self, prepared)
        if not checked <= now < record.session_expires_at:
            raise ValueError(_ORIGINAL)
        _E_REQUIRE(
            self.issuer,
            prepared.authenticated,
            session_cookie=session_cookie,
            csrf_token=csrf_token,
            now=now,
        )
        _OWNED(self, prepared)
        observation = OperatorStatementAdmission(
            prepared, now, record.session_expires_at, self.clock
        )
        self._admissions[id(observation)] = observation
        self._admission_fields[id(observation)] = (
            prepared,
            now,
            record.session_expires_at,
            self.clock,
        )
        finalize(observation, self._admission_fields.pop, id(observation), None)
        return observation

    def consume_admission(self, observation: OperatorStatementAdmission) -> None:
        """One use of this issuer's exact unchanged observation; no clock or SQL."""
        if (
            self._admissions is not self._admission_registry[0]
            or self._admission_fields is not self._admission_registry[1]
        ):
            raise ValueError(_CHANGED)
        _ENTRY(self)
        if type(observation) is not OperatorStatementAdmission:
            raise ValueError(_ORIGINAL)
        if self._admissions.pop(id(observation), None) is not observation:
            raise ValueError(_ORIGINAL)
        original = self._admission_fields.pop(id(observation), None)
        actual = (
            observation.prepared,
            observation.checked_at,
            observation.expires_at,
            observation.clock,
        )
        if original is None or any(a is not b for a, b in zip(actual, original, strict=True)):
            raise ValueError(_ORIGINAL)
        _OWNED(self, observation.prepared)


_PREPARER = OperatorStatementRecordPreparer
_BINDINGS = _bindings
_ENTRY = _entry
_ARGUMENTS = _arguments
_UTC = _utc
_SAMPLE = _sample
_NATIVE_REFERENCE = _native_reference
_INPUT_RECORD = _input_record
_STATEMENT_NODES = _statement_nodes
_CAPTURE_GRAPH = _capture_graph
_SAME_GRAPH = _same_graph
_OWNED = _owned
_METHODS = (
    (_ISSUER, "require_authenticated", _E_REQUIRE),
    (_READER, "read", _F_READ),
    (_PREPARED, "__init__", _PREPARED.__init__),
    (_RECORD, "__init__", _RECORD.__init__),
    (_RECORD, "__post_init__", _RECORD.__post_init__),
    (_RECORD, "record_id", vars(_RECORD)["record_id"]),
    (_RECORD, "semantic_sha256", vars(_RECORD)["semantic_sha256"]),
    (_REFERENCE, "__init__", _REFERENCE.__init__),
    (_REFERENCE, "__post_init__", _REFERENCE.__post_init__),
    (_PREPARER, "prepare", _PREPARER.prepare),
    (_PREPARER, "require_prepared", _PREPARER.require_prepared),
)
_REFERENCES = (
    (authentication, "LocalOperationalControlOperatorStatementAuthenticator", _ISSUER),
    (authentication, "_ENTRY", _E_ENTRY),
    (evidence, "OperatorStatementEvidenceReader", _READER),
    (evidence, "_ENTRY", _F_ENTRY),
    (prepared_values, "PreparedOperationalControlOperatorStatementRecord", _PREPARED),
    *(
        (records, name, vars(records)[name])
        for name in (
            "OperationalControlOperatorStatementRecord",
            "copy_operational_control_operator_statement_record",
            "_validated_values",
            "_native_fields",
            "content_digest",
            "ObjectRef",
            "UTC",
            "datetime",
            "_VERSION",
        )
    ),
    (statements, "copy_operational_control_operator_statement", _D_COPY),
)
_HELPERS = tuple(
    (name, globals()[name])
    for name in (
        "_bindings",
        "_BINDINGS",
        "_entry",
        "_ENTRY",
        "_arguments",
        "_ARGUMENTS",
        "_utc",
        "_UTC",
        "_sample",
        "_SAMPLE",
        "_native_reference",
        "_NATIVE_REFERENCE",
        "_input_record",
        "_INPUT_RECORD",
        "_statement_nodes",
        "_STATEMENT_NODES",
        "_capture_graph",
        "_CAPTURE_GRAPH",
        "_same_graph",
        "_SAME_GRAPH",
        "_owned",
        "_OWNED",
        "_ISSUER",
        "_READER",
        "_AUTHENTICATED",
        "_PREPARED",
        "_RECORD",
        "_STATEMENT",
        "_REFERENCE",
        "_E_ENTRY",
        "_E_REQUIRE",
        "_F_ENTRY",
        "_F_READ",
        "_D_COPY",
        "_G_COPY",
        "_SHA256",
        "_PREPARER",
        "fields",
        "cast",
        "UTC",
        "datetime",
        "WeakValueDictionary",
        "finalize",
    )
)
